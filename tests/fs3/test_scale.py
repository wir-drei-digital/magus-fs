import copy
import unittest
from scale import validate_scale


def fixture():
    cohorts = []
    for count in (1, 5, 20):
        receivers = [{'name': 'r'+str(n), 'replica': 'replica:'+str(n), 'state': '/private/r'+str(n), 'credential_sha256': str(n), 'kernel_mounted': True, 'ordinary_uid': 1001} for n in range(count)]
        saves = []
        for kind in ('in-place', 'atomic', 'new-file'):
            saves.append({'kind': kind, 'head': 'head:abc', 'revision': 'sha256:abc', 'sha256': 'a'*64, 'shared': True,
                          'attempted': count, 'successful': count, 'failed': 0,
                          'receivers': [{'name': r['name'], 'head': 'head:abc', 'revision': 'sha256:abc', 'applied': True, 'applied_revision':'sha256:abc',
                                         'fresh_sha256': 'a'*64, 'seconds': 1., 'error': None} for r in receivers]})
        cohorts.append({'count': count, 'ceiling_seconds': 600, 'seconds': 10, 'publisher': {'kind': 'full-native', 'ordinary_uid': 1001},
                        'receivers': receivers, 'saves': saves})
    return {'coverage': 'full', 'cohorts': cohorts,
            'cache': {'quota_bytes': 11, 'occupancy_bytes': [8, 11, 3], 'pressure_error': 'backpressure',
                      'protected_before': {'dirty': 'a', 'pin': 'b', 'pending': 'c', 'failed': 'd', 'uncertain': 'e', 'handle': 'f'},
                      'protected_after': {'dirty': 'a', 'pin': 'b', 'pending': 'c', 'failed': 'd', 'uncertain': 'e', 'handle': 'f'},
                      'stale_token_error': 'stale_prune_token', 'refetch_expected_sha256': 'c'*64, 'refetch_sha256': 'c'*64,
                      'restart_verified': True},
            'read_samples': [{'kind': k, 'seconds': 1., 'verified': True} for k in ('metadata-cold', 'ranges-cold', 'ranges-warm', 'full-scan')],
            'faults': [{'kind': k, 'passed': True} for k in ('disconnected', 'dropped-hint', 'slow', 'revoked')]}


class ScaleTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(validate_scale(fixture()), [])
    def assert_rejected(self, mutate):
        e = fixture(); mutate(e)
        self.assertTrue(validate_scale(e))
    def test_missing_receiver(self):
        self.assert_rejected(lambda e: e['cohorts'][2]['saves'][0]['receivers'].pop())
    def test_wrong_exact_revision(self):
        self.assert_rejected(lambda e: e['cohorts'][0]['saves'][0]['receivers'][0].update(revision='stale'))
    def test_wrong_fresh_bytes(self):
        self.assert_rejected(lambda e: e['cohorts'][0]['saves'][0]['receivers'][0].update(fresh_sha256='wrong'))
    def test_discarded_failure(self):
        self.assert_rejected(lambda e: e['cohorts'][0]['saves'][0].update(attempted=2))
    def test_failed_sample_cannot_claim_success(self):
        self.assert_rejected(lambda e: e['cohorts'][0]['saves'][0]['receivers'][0].update(error='deadline'))
    def test_bound(self):
        self.assert_rejected(lambda e: e['cache']['occupancy_bytes'].append(12))
    def test_protected_bytes(self):
        self.assert_rejected(lambda e: e['cache']['protected_after'].update(uncertain='changed'))
    def test_verified_refetch(self):
        self.assert_rejected(lambda e: e['cache'].update(refetch_sha256='wrong'))
    def test_subset_full_claim(self):
        self.assert_rejected(lambda e: e['cohorts'].pop())
    def test_duplicate_identity(self):
        self.assert_rejected(lambda e: e['cohorts'][1]['receivers'][1].update(replica=e['cohorts'][1]['receivers'][0]['replica']))
    def test_ceiling(self):
        self.assert_rejected(lambda e: e['cohorts'][0].update(seconds=601))
    def test_missing_named_fault(self):
        self.assert_rejected(lambda e: e['faults'].pop())
    def test_subset_label_is_incomplete(self):
        e=fixture();e['cohorts']=e['cohorts'][:1];e['coverage']='focused'
        self.assertIn('full scale phase requires all 1/5/20 cohorts', validate_scale(e))

class ScaleSourceBridgeTests(unittest.TestCase):
    def test_only_frozen_new_core_test_is_exempt(self):
        from common import allowed_source_changes
        path='crates/magus-fs-core/tests/fs3_cache.rs'
        exact={'image':None,'current':'ddfa10203861d12c9be7722755b05cf4cbe8dacbb552a2af1da3810bce74bf28'}
        self.assertTrue(allowed_source_changes({path:exact},'same','same'))
        for row in ({'image':'old','current':exact['current']},{'image':None,'current':'changed'}):
            self.assertFalse(allowed_source_changes({path:row},'same','same'))
        self.assertFalse(allowed_source_changes({'crates/magus-fs-core/tests/other.rs':exact},'same','same'))

class ScaleCredentialTests(unittest.TestCase):
    def test_root_credential_is_fresh_and_uses_owner_policy(self):
        from scale import owner_record, ALICE
        from unittest.mock import patch
        with patch('scale.secrets.token_hex',side_effect=['old','fresh']):
            row=owner_record({'owner':ALICE},{'old'},100)
        self.assertEqual(row['token'],'fresh')
        self.assertEqual(row['expires'],3700)
        self.assertEqual(row['authority']['principal'],row['root_policy']['owner'])
    def test_child_expiry_is_bounded_by_actual_parent(self):
        from scale import receiver_grant
        for now in (100,3699):
            row=receiver_grant('replica:x',3700,now)['delegate']
            self.assertLessEqual(row['expires'],3700)
            self.assertEqual(row['replica'],'replica:x')

class ExactAppliedTests(unittest.TestCase):
    def test_stale_live_revision(self):
        e=fixture();e['cohorts'][0]['saves'][0]['receivers'][0]['applied_revision']='stale'
        self.assertTrue(validate_scale(e))

class ScaleFailureReportingTests(unittest.TestCase):
    def run_missing_prerequisite(self, cleanup_error=False):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from scale import main, InfrastructureUnavailable
        class MissingInfra:
            def __init__(self, output):
                self.output=Path(output);self.output.mkdir()
            def write_json(self, name, value):
                (self.output/name).write_text(json.dumps(value))
            def setup(self, image):
                raise InfrastructureUnavailable('docker unavailable')
            def cleanup(self):
                if cleanup_error:raise RuntimeError('owned cleanup failed')
        with tempfile.TemporaryDirectory() as tmp, patch('scale.BudgetInfra',MissingInfra):
            output=Path(tmp)/'phase'
            code=main(['--image','unused','--output',str(output)])
            result=json.loads((output/'result.json').read_text())
        return code,result
    def test_missing_prerequisite_is_blocked_without_invented_results(self):
        code,result=self.run_missing_prerequisite()
        self.assertEqual(code,2)
        self.assertEqual(result['status'],'blocked')
        self.assertEqual(result['blocked'],['docker unavailable'])
        self.assertEqual(result['failures'],[])
        self.assertEqual(result['assertions'],[])
    def test_cleanup_failure_still_fails_when_prerequisite_missing(self):
        code,result=self.run_missing_prerequisite(cleanup_error=True)
        self.assertEqual(code,1)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['failures'],['cleanup 1: owned cleanup failed'])
        self.assertEqual(result['assertions'],[])
    def test_failed_peer_publication_retains_attempt_and_original_error(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from scale import Cohort
        saved=[];snapshots=[]
        journey=Cohort.__new__(Cohort)
        journey.row={'saves':[]};journey.mounts={'r00':object()};journey.client={}
        journey.publisher=SimpleNamespace(status=lambda _: {'status':{'submissions':[]}},
                                         write=Mock(side_effect=TimeoutError('synthetic publication timeout')))
        journey.transfers=Mock(side_effect=[{'authorized_body':0},{'authorized_body':7}])
        journey.save=lambda:snapshots.append(copy.deepcopy(journey.row))
        journey.i=SimpleNamespace(write_json=lambda name,row:saved.append((name,copy.deepcopy(row))))
        with self.assertRaisesRegex(TimeoutError,'synthetic publication timeout'):
            journey.publish_save('peer-cases','reports/live',b'body',['r00'],False)
        self.assertGreaterEqual(len(saved),2)
        self.assertEqual(saved[0][0],'peer-case-save.json')
        self.assertEqual(saved[0][1]['attempted'],1)
        row=saved[-1][1]
        self.assertEqual(row['error'],'synthetic publication timeout')
        self.assertEqual((row['attempted'],row['successful'],row['failed']),(1,0,1))
        self.assertFalse(row['shared'])
        self.assertEqual(row['receivers'],[])
        self.assertGreaterEqual(row['seconds'],0)
        self.assertEqual(row['transfer'],{'authorized_body':7})
        self.assertTrue(all(s['saves']==[] for s in snapshots))
