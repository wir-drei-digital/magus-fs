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

class RawCompositionTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.e=Path(self.tmp.name)/'e';self.f=Path(self.tmp.name)/'f';self.e.mkdir();self.f.mkdir()
        self.old=valid();self.old['status']='failed';self.old['assertions']=self.old['assertions'][:-2]
        self.new=valid()
        self.new['measurements']['composition']={'earlier_failed_result':str(self.e/'result.json'),
            'earlier_source_bridge':str(self.e/'source-bridge.json'),
            'unchanged_passed_cases':[r['case'] for r in self.old['assertions']],
            'remaining_cases':['revoked-reconnect','unaffected-peer']}
        for row in self.new['assertions'][:-2]:row['provenance']=[str(self.e/'observations.json')]
        for row in self.new['measurements']['mounts']:row['provenance']=str(self.e/'mounts.json')
        bridge={'current':{},'image':self.new['binaries']['image'],'binaries':self.new['binaries']['sha256']}
        from common import digest
        self.new['source']['manifest_sha256']=digest({})
        resources=[{'kind':'container','name':'owned','id':'123','removed':True}]
        for p in (self.e,self.f):
            for leaf in ('observations.json','mounts.json','altered.json'):self.write(p/leaf,{})
            self.write(p/'source-bridge.json',bridge)
        self.write(self.e/'ownership.json',{'owner':'fixture','resources':resources})
        self.write(self.f/'ownership-transfer.json',{'owner':'fixture','resources':resources})
        self.write(self.f/'cleanup.json',{'ok':True,'resources':resources})
        for name in ('a1','a2','b','readonly','peer'):
            self.write(self.f/(name+'-kernel-mount-cleanup.json'),{'verified':True,'remaining':{'/shared/'+name:False}})
        self.save()

    def write(self,path,value):
        import json
        path.write_text(json.dumps(value))

    def save(self,refresh_hash=True):
        import hashlib
        self.write(self.e/'result.json',self.old)
        if refresh_hash:self.new['measurements']['composition']['earlier_result_sha256']=hashlib.sha256((self.e/'result.json').read_bytes()).hexdigest()
        self.write(self.f/'result.json',self.new)

    def rejected(self):
        from common import compose_evidence
        with self.assertRaises((AssertionError,ValueError)):compose_evidence(self.e,self.f)

    def test_valid_raw_chain(self):
        from common import compose_evidence
        self.assertEqual(compose_evidence(self.e,self.f)['status'],'passed')

    def test_changed_predecessor_hash_rejected(self):
        self.old['extra']='corrected';self.save(refresh_hash=False);self.rejected()

    def test_failed_predecessor_row_rejected_even_with_current_hash(self):
        self.old['assertions'][0]['passed']=False;self.save();self.rejected()

    def test_mismatched_predecessor_outcome_rejected(self):
        self.old['assertions'][0]['observed']='leaked';self.save();self.rejected()

    def test_altered_import_rejected(self):
        self.new['assertions'][0]['provenance']=[str(self.e/'altered.json')];self.save();self.rejected()

    def test_wrong_predecessor_reference_rejected(self):
        self.new['measurements']['composition']['earlier_failed_result']=str(self.f/'result.json');self.save();self.rejected()

    def test_altered_mount_provenance_rejected(self):
        self.new['measurements']['mounts'][0]['provenance']=str(self.e/'altered.json');self.save();self.rejected()

    def test_corrected_cases_replace_old_raw_rows(self):
        from common import compose_evidence, digest
        import json
        g=self.e.parent/'api';g.mkdir()
        corrected=valid();corrected['phase']='isolation-api-correction'
        corrected['assertions']=[r for r in corrected['assertions'] if r['case'] in ('private-history','api-bypass')]
        corrected['measurements']['mounts']=[];corrected['source']['manifest_sha256']=digest({})
        for row in corrected['assertions']:row['provenance']=['corrected.json']
        self.write(g/'result.json',corrected);self.write(g/'corrected.json',{})
        self.write(g/'source-bridge.json',json.loads((self.f/'source-bridge.json').read_text()))
        self.write(g/'ownership.json',{'resources':[]});self.write(g/'cleanup.json',{'ok':True,'resources':[]})
        result=compose_evidence(self.e,self.f,g)
        self.assertEqual(result['status'],'passed')
        replacements=[r for r in result['assertions'] if r['case'] in ('private-history','api-bypass')]
        self.assertTrue(all(r['provenance']==[str((g/'corrected.json').resolve())] for r in replacements))
        self.assertEqual(len(result['measurements']['composition']['correction']['superseded_rows']),2)
        corrected['assertions'][0]['passed']=False;self.write(g/'result.json',corrected)
        with self.assertRaises(AssertionError):compose_evidence(self.e,self.f,g)

if __name__ == '__main__': unittest.main()

class ProviderAssertionTests(unittest.TestCase):
    def fixture(self):
        from test_aggregate import DisposableCleanupTests
        row=DisposableCleanupTests().fixture()
        cases={'scope':'F3-2','readonly':'F3-2','private-history':'F3-2','api-bypass':'F3-2','revoked-reconnect':'F3-2','cold-warm-range':'F3-5','shared-publication':'F3-1','disposable-lifecycle':'F3-7'}
        row['assertions']=[{'case':c,'acceptance':a,'passed':True,'expected':'verified','observed':'verified','provenance':['raw.json']} for c,a in cases.items()]
        return row

    def test_complete_provider_assertions_pass(self):
        self.assertEqual(normalize(self.fixture())['status'],'passed')

    def test_missing_false_duplicate_or_wrong_acceptance_fails(self):
        for kind in ('missing','false','duplicate','acceptance','outcome','provenance'):
            with self.subTest(kind=kind):
                row=self.fixture();a=row['assertions']
                if kind=='missing':a.pop()
                elif kind=='false':a[0]['passed']=False
                elif kind=='duplicate':a.append(dict(a[0]))
                elif kind=='acceptance':a[0]['acceptance']='wrong'
                elif kind=='outcome':a[0]['observed']='denied obligation unresolved'
                else:a[0]['provenance']=[]
                self.assertEqual(normalize(row)['status'],'failed')

class ProviderRawAssertionTests(unittest.TestCase):
    def raw_assertions(self,revoked_row=None):
        import tempfile,json,hashlib
        from pathlib import Path
        from daytona import provider_assertions
        from test_daytona import disposable
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            raw={
                'scope':{'before':{},'after':{},'scope_read':{'secret':2},'rejected':{'state':'Denied','private_receipt':None,'shared_receipt':None}},
                'readonly':{'errnos':{'write':0},'direct_upload':404},
                'private-history':{'private_entry':'private','hidden_entry':'hidden','observed_entries':[],'readonly_denied':404,'page':{'next':None}},
                'api-bypass':{'before':{},'after':{},'own_view_private_object':{'allowed_status':200,'private_status':404,'denied':{'code':'not_found'}}},
                'revoked-reconnect':{'denied':{'read':13},'status':{'live':{'authorized':False}},'kernel_daemon_proof':{'mountinfo':'1 0 0:1 / /shared/a2 rw - fuse magus rw','pid':2,'expected_pid':2,'binary_sha256':'a'*64,'expected_binary_sha256':'a'*64,'command':['magus-fs','mount','--state','/private/a2/state','--mountpoint','/shared/a2']}}}
            if revoked_row is not None:raw['revoked-reconnect']=revoked_row
            cases={}
            for case,value in raw.items():
                path=p/(case+'.json');path.write_text(json.dumps(value));cases[case]={'passed':True,'provenance':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            metric=p/'metrics-service';metric.mkdir()
            (metric/'read-proof.json').write_text(json.dumps({'metadata':{'authorized_body':0},'cold':{'authorized_body':262144},'warm':{'authorized_body':262144},'expected_sha256':'a'*64}))
            (metric/'hosted-commands.json').write_text(json.dumps([{'exit':0,'code':'hashlib.sha256(open','stdout':json.dumps('a'*64)}]))
            for name in ('publication-private','publication-shared','publication-server','provider-deletion','recovery-before','recovery-after','owned-cleanup'):(p/(name+'.json')).write_text('{}')
            rows=provider_assertions(p,disposable(),cases)
            readonly=next(r for r in rows if r['case']=='readonly')
            self.assertFalse(readonly['observed']);self.assertFalse(readonly['passed'])
            self.assertEqual(len(rows),8)
            return rows

    def test_false_raw_outcome_is_not_replaced_by_true_case_flag(self):
        self.raw_assertions()


    def test_live_revoked_producer_matches_actual_assertion_reader(self):
        import daytona,copy
        self.assertTrue(hasattr(daytona,'revoked_reconnect_case'))
        proof={'pid':272,'expected_pid':272,'binary_sha256':'a'*64,'expected_binary_sha256':'a'*64,
            'command':['/opt/fs3-task4/bin/magus-fs','mount','--state','/private/a2/state','--mountpoint','/shared/a2'],
            'mountinfo':'1 0 0:1 / /shared/a2 rw - fuse magus rw','stat_ismount':False}
        class Remote:
            def execute(self,code,settings):
                assert settings=={'name':'a2','expected_pid':272,'expected_binary_sha256':'a'*64}
                return copy.deepcopy(proof)
            def status(self,name):return {'live':{'authorized':False}}
        emitted=daytona.revoked_reconnect_case(Remote(),{'read:reports/result':13,'write:reports/live':13},proof)
        rows=self.raw_assertions(emitted)
        self.assertTrue(next(r for r in rows if r['case']=='revoked-reconnect')['passed'])
        self.assertEqual(emitted['kernel_daemon_proof'],proof)

    def test_live_revoked_producer_rejects_changed_pid_binary_or_missing_mount(self):
        import daytona
        self.assertTrue(hasattr(daytona,'revoked_reconnect_case'))
        before={'pid':272,'expected_pid':272,'binary_sha256':'a'*64,'expected_binary_sha256':'a'*64,
            'command':['/opt/fs3-task4/bin/magus-fs','mount','--state','/private/a2/state','--mountpoint','/shared/a2'],
            'mountinfo':'1 0 0:1 / /shared/a2 rw - fuse magus rw'}
        for change in ({'pid':273},{'binary_sha256':'b'*64},{'mountinfo':'1 0 0:1 / / rw - overlay root rw'}):
            with self.subTest(change=change):
                class Remote:
                    def execute(self,code,settings):
                        return {'pid':272,'expected_pid':272,'binary_sha256':'a'*64,'expected_binary_sha256':'a'*64,
                            'command':['/opt/fs3-task4/bin/magus-fs','mount','--state','/private/a2/state','--mountpoint','/shared/a2'],
                            'mountinfo':'1 0 0:1 / /shared/a2 rw - fuse magus rw',**change}
                    def status(self,name):return {'live':{'authorized':False}}
                with self.assertRaises(AssertionError):daytona.revoked_reconnect_case(Remote(),{'read':13},before)
