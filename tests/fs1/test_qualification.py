"""Fail closed on incomplete or contradictory combined evidence."""
import copy
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import ordinary_io
from qualification import aggregate, validate_profile


def profile(platform='macos', journey=1):
    cases={f'V{i}': {'state':'passed','assertions':[{'name':'direct','observed':1,'expected':1,'passed':True}], 'evidence':['native.json']} for i in range(1,13)}
    return {'platform':platform,'journey':journey,'cases':cases,'source_hashes':{'src/lib.rs':'a'*64},
            'binary_sha256':'b'*64,'fault_binary_sha256':'c'*64,'closure_verified':True,
            'warm_body_delta':0,'checkpoint_revision':'sha256:new','recovered_revision':'sha256:new',
            'cleanup':{'verified':True,'remaining_mounts':[],'remaining_containers':[],'remaining_pids':[]},
            'interrupted':False,'native_exit':0,'cli_exit':0,'archive_exit':0,'retention_exit':0}

class Qualification(unittest.TestCase):
    def test_recovered_ack_requires_metadata_and_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,data in [('offline-new',b'ACK survives daemon loss'),('uncached',b'full offline replacement'),('new',b'new generation')]:
                (root/name).write_bytes(data)
            (root/'new').chmod(0o644)
            with patch.object(ordinary_io,'ROOT',root):
                with self.assertRaises(AssertionError):ordinary_io.run('recovered')
                (root/'new').chmod(0o640);(root/'moved').mkdir()
                with self.assertRaises(AssertionError):ordinary_io.run('recovered')
                (root/'moved').rmdir();(root/'unlink-parent').mkdir();(root/'unlink-parent/no-write').touch()
                with self.assertRaises(AssertionError):ordinary_io.run('recovered')
                (root/'unlink-parent/no-write').unlink()
                self.assertEqual(ordinary_io.run('recovered')['modes']['new'],'0640')

    def test_complete_matrix(self):
        self.assertEqual(aggregate([profile(p,j) for p in ['macos','linux'] for j in [1,2]])['exit_code'],0)
    def test_absent_platform_or_journey_fails(self):
        self.assertNotEqual(aggregate([profile()])['exit_code'],0)
    def test_missing_case_fails(self):
        p=profile();del p['cases']['V5'];self.assertTrue(validate_profile(p))
    def test_unverified_closure_fails(self):
        p=profile();p['closure_verified']=False;self.assertTrue(validate_profile(p))
    def test_warm_transfer_fails(self):
        p=profile();p['warm_body_delta']=1;self.assertTrue(validate_profile(p))
    def test_missing_cleanup_fields_fail(self):
        for field in profile()['cleanup']:
            p=profile();del p['cleanup'][field];self.assertTrue(validate_profile(p),field)
    def test_stale_checkpoint_after_ack_fails(self):
        p=profile();p['recovered_revision']='sha256:old';self.assertTrue(validate_profile(p))
    def test_swallowed_interruption_fails(self):
        p=profile();p['interrupted']=True;self.assertTrue(validate_profile(p))
    def test_retained_resources_fail(self):
        for field in ['remaining_mounts','remaining_containers','remaining_pids']:
            p=profile();p['cleanup'][field]=['owned'];self.assertTrue(validate_profile(p))
    def test_skipped_case_and_empty_assertions_fail(self):
        for update in [{'state':'skipped'},{'assertions':[]},{'evidence':[]},{'assertions':[{'passed':True}]}]:
            p=profile();p['cases']['V8'].update(update);self.assertTrue(validate_profile(p))
    def test_missing_prerequisite_is_blocked_not_passed(self):
        result=aggregate([],blocked=['Docker unavailable']);self.assertEqual(result['exit_code'],2)

if __name__=='__main__':unittest.main()

class Orchestration(unittest.TestCase):
    def test_interrupted_retained_runner_cannot_be_success(self):
        import os,signal,sys,time
        from run import execute
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'retained'
            class Interrupted:
                count=1
            started=time.monotonic()
            record=execute([sys.executable,'-c','import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);time.sleep(30)'],output,Interrupted(),seconds=.2,grace=.1)
            self.assertLess(time.monotonic()-started,2)
            self.assertNotEqual(record['exit'],0)
            self.assertIn('supervision',record)
            if record['supervision']['runner_alive']:
                os.kill(record['supervision']['runner_pid'],signal.SIGKILL)
                os.waitpid(record['supervision']['runner_pid'],0)

class RawEvidence(unittest.TestCase):
    def normalized(self,native):
        from qualification import normalize
        return normalize('macos',1,native,{},{},{},{k:Path(k+'.json') for k in ['native','cli','archive','retention']})
    def test_closure_claim_without_comparable_inventories_fails(self):
        n={'full_closure':{'verified':True,'daemon_stopped':True}}
        self.assertEqual(self.normalized(n)['cases']['V1']['state'],'failed')
    def test_readonly_success_errno_cannot_qualify(self):
        n={'cases':{'permissions-view':{'mode000_errno':13,'no_search_errno':13,'no_read_errno':13,'readonly_child_unlink':True},'mapping-view':{'foreign_owner_uid':10001,'other_gid':10001,'group_other_and_execute':{'group':13,'other':13,'denied-other':13,'noexec':13}},'readonly-ro':{'denials':[0]*9}}}
        self.assertEqual(self.normalized(n)['cases']['V7']['state'],'failed')
