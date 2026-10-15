import copy
import unittest
from qualification import normalize

CASES = ['same-principal', 'different-principal', 'isolated-private', 'explicit-integration', 'private-history', 'api-bypass', 'readonly', 'scope-mode', 'revoked-reconnect', 'unaffected-peer']

def valid():
    return {'schema': 1, 'phase': 'isolation', 'status': 'passed',
            'source': {'verified': True, 'head': 'a'*40, 'manifest_sha256': 'b'*64, 'bridge': 'source-bridge.json'},
            'binaries': {'verified': True, 'image': 'sha256:'+'c'*64, 'sha256': {'magus-fs': 'd'*64, 'magus-fs-service': 'e'*64}},
            'assertions': [{'acceptance': 'F3-1' if n < 4 else 'F3-2', 'case': c, 'expected': 'denied' if c == 'api-bypass' else 'verified', 'observed': 'denied' if c == 'api-bypass' else 'verified', 'passed': True, 'provenance': ['observations.json']} for n,c in enumerate(CASES)],
            'measurements': {'mounts': [{'actor': c, 'kernel_mounted': True, 'ordinary_uid': 1001, 'provenance': 'mounts.json'} for c in ['a1', 'a2', 'b', 'readonly', 'peer']]},
            'cleanup': {'ok': True, 'mounts_absent': True, 'resources_removed': True, 'provenance': ['cleanup.json']}, 'failures': [], 'blocked': []}

class QualificationTests(unittest.TestCase):
    def test_phase_alone_passes_without_claiming_whole_fs3(self):
        self.assertEqual(normalize(valid())['status'], 'passed')
    def test_missing_history_or_api_fails(self):
        for case in ['private-history', 'api-bypass']:
            e=valid();e['assertions']=[a for a in e['assertions'] if a['case'] != case]
            self.assertEqual(normalize(e)['status'], 'failed')
    def test_claim_without_real_mount_proof_fails(self):
        e=valid();e['measurements']['mounts']=[]
        self.assertEqual(normalize(e)['status'], 'failed')
    def test_cross_replica_private_result_fails_even_forged_flag(self):
        e=valid();e['assertions'][5]['observed']='private-result-disclosed'
        self.assertEqual(normalize(e)['status'], 'failed')
    def test_cleanup_failure_fails(self):
        e=valid();e['cleanup']['mounts_absent']=False
        self.assertEqual(normalize(e)['status'], 'failed')
    def test_unverified_binary_source_fails(self):
        e=valid();e['source']['verified']=False
        self.assertEqual(normalize(e)['status'], 'failed')
    def test_blocked_prerequisite_is_not_pass(self):
        e=valid();e['status']='blocked';e['blocked']=['no FUSE'];e['assertions']=[]
        self.assertEqual(normalize(e)['status'], 'blocked')

def composed():
    e=valid()
    e['measurements']['composition']={
        'source_chain':{'verified':True,'earlier_image':e['binaries']['image'],
                        'earlier_binaries':copy.deepcopy(e['binaries']['sha256']),
                        'differences':['tests/fs3/common.py'],
                        'current_manifest_sha256':e['source']['manifest_sha256'],
                        'earlier_manifest_sha256':'f'*64},
        'earlier_result_sha256':'1'*64,'continuation_result_sha256':'2'*64,
        'owned_cleanup_verified':True}
    return e


class CompositionTests(unittest.TestCase):
    def test_verified_composition_passes(self):
        self.assertEqual(normalize(composed())['status'],'passed')

    def test_composition_without_verified_source_chain_fails(self):
        e=composed();e['measurements']['composition'].pop('source_chain')
        self.assertEqual(normalize(e)['status'],'failed')

    def test_runtime_difference_in_composition_fails(self):
        e=composed();e['measurements']['composition']['source_chain']['differences']=['crates/magus-fs/src/main.rs']
        self.assertEqual(normalize(e)['status'],'failed')

    def test_binary_difference_in_composition_fails(self):
        e=composed();e['measurements']['composition']['source_chain']['earlier_binaries']['magus-fs']='0'*64
        self.assertEqual(normalize(e)['status'],'failed')

    def test_missing_continuation_case_fails(self):
        e=composed();e['assertions']=[r for r in e['assertions'] if r['case']!='revoked-reconnect']
        self.assertEqual(normalize(e)['status'],'failed')

if __name__ == '__main__': unittest.main()
