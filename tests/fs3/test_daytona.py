"""Hosted qualification is fail closed; fakes never constitute hosted evidence."""
import copy
import unittest
from daytona import validate_provider, deletion_permitted


def proof():
    sha='a'*64
    return {'provider':{'name':'daytona','sandbox_id':'owned-worker','execution':'remote-ssh','architecture':'x86_64','snapshot':'daytona-medium','version':'0.9.0','provenance':'provider.json'},
            'package':{'manifest_sha256':sha,'archive_sha256':sha,'expected_binary_sha256':sha,'executed_binary_sha256':sha,'platform':'x86_64-unknown-linux-gnu','verified':True},
            'mount':{'kernel_mounted':True,'ordinary_io':True,'workload_uid':1002,'control_uid':0,'workload_sudo_denied':True,'control_credentials_unreadable':True,'provenance':'mount.json'},
            'cases':{k:{'passed':True,'provenance':k+'.json'} for k in ('scope','readonly','private-history','api-bypass','revoked-reconnect','cold-warm-range')},
            'save':{'operation':'op','revision':'rev','receipt':'receipt','sha256':sha,'ack_certain':True,'sequence':10},
            'recovery_before':{'independent':True,'sandbox_disk_used':False,'revision':'rev','sha256':sha,'sequence':11,'provenance':'before.json'},
            'unmount':{'normal':True,'kernel_absent':True,'helpers_stopped':True,'sequence':12},
            'deletion':{'owned':True,'sandbox_id':'owned-worker','confirmed_absent':True,'sequence':13},
            'recovery_after':{'independent':True,'sandbox_disk_used':False,'revision':'rev','sha256':sha,'sequence':14,'provenance':'after.json'},
            'cleanup':{'unresolved':[]}}


class ProviderValidationTests(unittest.TestCase):
    def test_complete_schema(self):
        self.assertEqual(validate_provider(proof()),[])

    def test_absent_real_mount(self):
        p=proof();p['mount']['kernel_mounted']=False
        self.assertIn('actual ordinary provider mount missing',validate_provider(p))

    def test_local_substitution(self):
        p=proof();p['provider']['execution']='local-docker'
        self.assertIn('actual Daytona execution missing',validate_provider(p))

    def test_unknown_package_hash(self):
        p=proof();p['package']['executed_binary_sha256']='b'*64
        self.assertIn('exact package binding missing',validate_provider(p))

    def test_independent_recovery_required_before_delete(self):
        p=proof();p['recovery_before']['independent']=False
        self.assertFalse(deletion_permitted(p))
        self.assertIn('independent pre-deletion recovery missing',validate_provider(p))

    def test_delete_after_receipt(self):
        p=proof();p['deletion']['sequence']=9
        self.assertIn('unsafe deletion ordering',validate_provider(p))

    def test_revoked_reconnect_must_fail(self):
        p=proof();p['cases']['revoked-reconnect']['passed']=False
        self.assertIn('hosted assertion missing: revoked-reconnect',validate_provider(p))

    def test_unresolved_resources(self):
        p=proof();p['cleanup']['unresolved']=['owned-worker']
        self.assertIn('provider resources unresolved',validate_provider(p))

    def test_uncertain_ack_prevents_delete(self):
        p=proof();p['save']['ack_certain']=False
        self.assertFalse(deletion_permitted(p))

    def test_unprivileged_workload(self):
        p=proof();p['mount']['workload_sudo_denied']=False
        self.assertIn('workload/control separation missing',validate_provider(p))

    def test_recovery_exact_bytes_and_revision(self):
        for when in ('recovery_before','recovery_after'):
            for key in ('sha256','revision'):
                p=proof();p[when][key]='wrong'
                self.assertTrue(validate_provider(p))



class PreflightTests(unittest.TestCase):
    def test_read_only_missing_configuration_is_blocked(self):
        import daytona
        result=daytona.preflight({},None)
        self.assertEqual(result['status'],'blocked')
        self.assertFalse(result['executed'])
        self.assertEqual(result['resources_created'],[])

    def test_unresolved_capability_resource_cannot_pass(self):
        import daytona
        result=daytona.preflight({'capability_evidence':{'normal_unmount':False,'sandbox_id':'owned','removed':False}},None)
        self.assertEqual(result['status'],'failed')
        self.assertFalse(result['cleanup']['ok'])

if __name__=='__main__':unittest.main()
