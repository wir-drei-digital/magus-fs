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

def disposable():
    p=proof();p['lifecycle']='disposable-daytona'
    p['run_id']='run';p['owned_sandbox_id']='owned-worker'
    p['unmount']={'normal':False,'kernel_absent':False,'helpers_stopped':False}
    sha='a'*64
    p['freeze']={'run_id':'run','sandbox_id':'owned-worker','dispatch_disabled':True,
        'writers_reaped':True,'unknown_writers':[],'writers_before':[],'writers_after':[],
        'generation_before':7,'generation_after':7,'manifest_before':sha,'manifest_after':sha,
        'sequence':9,'recheck_sequence':12,'provenance':sha}
    p['accounting']={'complete':True,'replicas':['replica'],'work':[{
        'id':'candidate','replica':'replica','intended':True,'unique':True,
        'disposition':'included','revision':'rev','ack_certain':True}],
        'exclusions':[],'provenance':sha}
    p['save'].update(receipt='private-id',replica='replica',original_view='view',original_head='base',
        private_receipt={'receipt':'private-id','submitted_revision':'rev','replica':'replica','original_view':'view','original_head':'base'},
        integration={'candidate_receipt':'private-id'},
        shared_receipt={'submitted_revision':'rev','head':'head'},shared_head='head',
        server_confirmed=True,manifest_sha256=sha,provenance=sha)
    for when in ('recovery_before','recovery_after'):
        p[when].update(service_only=True,whole_fixture=True,manifest_sha256=sha,
            private_closure_verified=True,state_id=when,run_id='run',sandbox_id='owned-worker',provenance=sha)
    p['deletion'].update(ssh_unusable=True,terminal=True,provenance=sha)
    return p


class DisposableTests(unittest.TestCase):
    def test_predelete_guard_does_not_require_postdelete_proof(self):
        import daytona
        p=disposable();del p['recovery_after'];del p['deletion']
        self.assertTrue(hasattr(daytona,'completion_failures'))
        self.assertEqual(daytona.completion_failures(p),[])
        self.assertTrue(deletion_permitted(p))

    def test_complete_disposable_never_claims_normal_unmount(self):
        p=disposable();self.assertEqual(validate_provider(p),[])
        self.assertFalse(p['unmount']['normal'])

    def test_uncertain_freeze_blocks(self):
        for key,value in [('dispatch_disabled',False),('writers_reaped',False),
            ('unknown_writers',['unknown']),('writers_after',[42]),
            ('generation_after',8),('manifest_after','b'*64),('sandbox_id','other')]:
            with self.subTest(key=key):
                p=disposable();p['freeze'][key]=value;self.assertFalse(deletion_permitted(p))

    def test_unaccounted_unique_work_and_unacked_intended_candidate_block(self):
        for change in ({'disposition':'pending'},{'ack_certain':False},{'revision':'other'}):
            p=disposable();p['accounting']['work'][0].update(change)
            self.assertFalse(deletion_permitted(p))

    def test_historical_superseded_failure_has_explicit_coverage(self):
        p=disposable();p['accounting']['work'].append({'id':'old','replica':'replica',
            'intended':True,'unique':False,'disposition':'superseded','covered_by':'candidate'})
        self.assertTrue(deletion_permitted(p))
        p['accounting']['work'][-1]['covered_by']='missing';self.assertFalse(deletion_permitted(p))

    def test_synthetic_exclusion_requires_reproducible_external_input(self):
        p=disposable();p['accounting']['exclusions']=[{'id':'negative','input_sha256':'b'*64,
            'reason':'intentional scope denial','denial_provenance':'c'*64,
            'local_recovery_provenance':'d'*64,'disposition':'synthetic-abandonment',
            'external_input_sha256':'b'*64,'external_provenance':'e'*64}]
        self.assertTrue(deletion_permitted(p))
        p['accounting']['exclusions'][0]['external_input_sha256']='c'*64
        self.assertFalse(deletion_permitted(p))

    def test_private_receipt_is_not_shared_or_server_confirmation(self):
        for change in ({'shared_receipt':{}},{'server_confirmed':False},
            {'integration':{}},{'replica':'wrong'},{'manifest_sha256':'b'*64}):
            p=disposable();p['save'].update(change);self.assertFalse(deletion_permitted(p))

    def test_copied_disk_wrong_metadata_or_absent_recovery_block(self):
        for change in ({'sandbox_disk_used':True},{'service_only':False},
            {'manifest_sha256':'b'*64},{'whole_fixture':False},{'private_closure_verified':False}):
            p=disposable();p['recovery_before'].update(change);self.assertFalse(deletion_permitted(p))
        p=disposable();del p['recovery_before'];self.assertFalse(deletion_permitted(p))

    def test_owned_identity_and_terminal_absence_required(self):
        p=disposable();p['owned_sandbox_id']='wrong';self.assertFalse(deletion_permitted(p))
        for change in ({'terminal':False},{'confirmed_absent':False},{'ssh_unusable':False}):
            p=disposable();p['deletion'].update(change);self.assertTrue(validate_provider(p))

    def test_after_recovery_is_fresh_and_required_only_by_final_validator(self):
        p=disposable();p['recovery_after']['state_id']='recovery_before'
        self.assertTrue(validate_provider(p));self.assertTrue(deletion_permitted(p))

if __name__=='__main__':unittest.main()


class HostedDriverTests(unittest.TestCase):
    def test_missing_owned_inputs_cannot_mutate_or_claim_cleanup(self):
        import daytona,tempfile
        from pathlib import Path
        self.assertTrue(hasattr(daytona,'run_hosted'))
        with tempfile.TemporaryDirectory() as directory:
            result=daytona.run_hosted({},None,Path(directory))
        self.assertNotEqual(result['status'],'passed')
        self.assertFalse(result['executed'])
        self.assertEqual(result['resources_created'],[])

class EvidenceRetentionTests(unittest.TestCase):
    def test_current_ledger_not_startup_snapshot_and_no_duplicate_ids(self):
        import daytona,tempfile,json
        from pathlib import Path
        self.assertTrue(hasattr(daytona,'current_ledger'))
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'commands.json').write_text(json.dumps([{'log':'command-0.log'},{'log':'command-1.log'}]))
            self.assertEqual(len(daytona.current_ledger(p)),2)
            (p/'commands.json').write_text(json.dumps([{'log':'command-0.log'},{'log':'command-0.log'}]))
            with self.assertRaises(ValueError):daytona.current_ledger(p)

    def test_revoked_stat_denial_cannot_hide_kernel_mount(self):
        import daytona
        self.assertTrue(hasattr(daytona,'retained_mount'))
        row={'stat_ismount':False,'mountinfo':'2446 51875 0:525 / /shared/a2 rw - fuse magus-fs1 rw\n',
             'pid':272,'expected_pid':272,'binary_sha256':'a'*64,'expected_binary_sha256':'a'*64,
             'command':['/opt/fs3-task4/bin/magus-fs','mount','--state','/private/a2/state','--mountpoint','/shared/a2']}
        self.assertTrue(daytona.retained_mount(row,'a2'))
        row['mountinfo']='1 0 0:1 / / rw - overlay overlay rw\n'
        self.assertFalse(daytona.retained_mount(row,'a2'))

class FreezeDispatchTests(unittest.TestCase):
    def test_persisted_freeze_blocks_a_fresh_remote_launcher(self):
        import daytona,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'freeze-dispatch.json').write_text('{}')
            r=daytona.RemoteMount(SimpleNamespace(i=SimpleNamespace(output=p)),{},p)
            with self.assertRaisesRegex(RuntimeError,'frozen'):
                r.execute('raise AssertionError("must never dispatch")',user='1002:1002')

class HostedFailureRetentionTests(unittest.TestCase):
    def test_actual_failure_preserves_partial_evidence_and_never_cleans_up(self):
        import daytona,tempfile,json
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);partial=out/'partial.json';partial.write_text('{"actual":true}')
            config={k:'owned' for k in ('sandbox_id','owned_name','ssh_config','ssh_host','owned_service_dir','service_url','daytona_env_file')}
            with patch.object(daytona,'execute_hosted',side_effect=RuntimeError('guard uncertain')),patch.object(daytona,'cleanup_hosted') as cleanup:
                result=daytona.run_hosted(config,Path('/manifest'),out)
            cleanup.assert_not_called()
            self.assertEqual(result['status'],'failed')
            self.assertFalse(result['cleanup']['ok'])
            self.assertEqual(json.loads(partial.read_text()),{'actual':True})
            self.assertTrue((out/'failure.log').exists())
