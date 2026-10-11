"""Full-gate negative contract tests; synthetic evidence is never runtime proof."""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'fs2'))
import qualification
import importlib.util
spec=importlib.util.spec_from_file_location('connected_contract',Path(__file__).resolve().parents[1]/'fs2'/'test_qualification.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
connected_complete=legacy.complete

class FullQualificationTests(unittest.TestCase):
    def check(self,e):return getattr(qualification,'normalize_full',qualification.normalize)(e)
    def test_connected_success_cannot_qualify_full_gate(self):
        self.assertNotEqual(self.check(connected_complete())['exit'],0)
    def test_each_required_family_missing_fails(self):
        for family in [*(f'S{x}' for x in range(1,16)),*(f'P{x}' for x in range(1,13))]:
            with self.subTest(family=family):
                e=connected_complete();e['matrix']={k:[] for k in [*(f'S{x}' for x in range(1,16)),*(f'P{x}' for x in range(1,13))] if k!=family}
                self.assertNotEqual(self.check(e)['exit'],0)
    def test_missing_app_restore_and_static_source_fail(self):
        for field in ['editor','agents','archive','crdt','predecessors']:
            with self.subTest(field=field):
                e=connected_complete();e[field]=None
                self.assertNotEqual(self.check(e)['exit'],0)
if __name__=='__main__':unittest.main()

class CompleteEvidenceTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        spec=importlib.util.spec_from_file_location('full_contract',Path(__file__).with_name('qualification.py'));self.q=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.q)
    def write(self,name,value):
        import json
        p=self.root/name;p.write_text(json.dumps(value));return self.q.artifact(p)
    def fixture(self):
        old=connected_complete();source=old['source'];source['build_profile']={'runtime':'release'}
        e={**old,'scope':'FS2 and integrated PoC','matrix':copy.deepcopy(self.q.MATRIX),'journeys':[],'source_artifacts':[self.write('source.json',source)],'static':self.write('static.json',{'crdt':{'passed':True},'predecessors':{'files':['fixture']},'artifacts':[self.write('crdt.json',{'fixture':True})]})}
        for n in range(2):
            j={'owner':str(n),'seconds':1,'components':{}}
            for name,cases in self.q.CASES.items():
                records=[{'case':case,**{k:True for k in fields}} for case,fields in cases.items()]
                if name=='connected':
                    editor={'api':'TextDocument.save','saved':True,'dirty':False,'installed_version':'actual-test-version','cleanup':{'remaining':[]},'sha256':'a'*64,'expected_sha256':'a'*64,'progress':{'shared_receipt':{'head':'h'}}}
                    inventory={'instructions.md':{'sha256':'a'*64},'reports/result.json':{'sha256':'b'*64}}
                    archive={'network_mode':'none','mounts':[],'credentials_absent':True,'network_denied':[1,1],'original_denied':[1,1,1],'actual':inventory,'expected':{'inventory':inventory},'rejected_absent':True,'corruption':{'ok':False}}
                    connected_row=old['journeys'][n];connected_row['worker_private']={'expected_hash':'b'*64};connected_row['replacement']={'actual':{'file':'hash'},'expected':{'file':'hash'},'unmount':{'still_mounted':False},'discarded':'/private/live'};records=[{'case':'connected','journey':connected_row,'editor':editor,'archive':archive}]
                if name=='mounted':
                    records=[r for r in records if not r['case'].startswith('actual-agent')];before=[];after=[]
                    for phase,out in [('write',before),('follow-up',after)]:
                        for agent in ['a','b']:
                            report=self.write(f'report-{n}-{phase}-{agent}.json',{'fixture':True})
                            out += [{'case':'actual-agent-file','phase':phase,'name':agent,'body':'00','metadata':{'agent_id':agent,'report':report['path']},'report_sha256':report['sha256']},{'case':'actual-agent-receipts','phase':phase,'name':agent,'progress':[True],'before':{}}]
                    records=before+records+after
                if name=='dependencies':
                    next(r for r in records if r['case']=='dependency-declarations').update(requests={'receipt':{'coverage':'complete_declared','reads':[{'revision':'sha256:'+'a'*64,'view':'view','entry':'entry'}]}},policy={'version':'2','image_digest':'sha256:'+'a'*64,'executable_hash':'sha256:'+'a'*64})
                    final_policy=next(r for r in records if r['case']=='dependency-declarations')['policy'];next(r for r in records if r['case']=='configured-validation')['policy']={**final_policy,'version':'1'}
                    next(r for r in records if r['case']=='publication-route-and-policy-races')['policy_race']=[409,{'code':'recompute_required'}]
                    row=next(r for r in records if r['case']=='paused-mounted-report-recompute-validate-visible');row.update(retry={'progress':{'error':'dependency_changed'}},stale={'shared_receipt':None},integrated={'progress':{'shared_receipt':{'head':'h'}}})
                j['components'][name]={'owner':f'{n}-{name}','exit':0,'image':source['image'],'profile':'release','source_sha256':source['sha256'],'cleanup':{'verified':True,'mounts':[],'pids':[],'resources':[]},'raw':self.write(f'{n}-{name}.json',records),'platforms':['macos','linux']}
            e['journeys'].append(j)
        return e
    def mutate_raw(self,e,name,fn):
        ref=e['journeys'][0]['components'][name]['raw'];rows=self.q.read(ref);fn(rows);e['journeys'][0]['components'][name]['raw']=self.write('mutated.json',rows)
    def test_complete_artifact_contract(self):
        result=self.q.normalize(self.fixture());self.assertEqual(result['exit'],0,result['errors'])
    def test_every_raw_family_is_required(self):
        for name,cases in self.q.CASES.items():
            for case in cases:
                with self.subTest(component=name,case=case):
                    e=self.fixture();self.mutate_raw(e,name,lambda rows:rows.__setitem__(slice(None),[r for r in rows if r['case']!=case]));self.assertNotEqual(self.q.normalize(e)['exit'],0)
    def test_artifact_tamper_and_source_profile_cleanup(self):
        for kind in ['tamper','source','profile','cleanup','duplicate','version']:
            with self.subTest(kind=kind):
                e=self.fixture();c=e['journeys'][0]['components']['connected']
                if kind=='tamper':Path(c['raw']['path']).write_text('[]')
                elif kind=='source':c['source_sha256']={}
                elif kind=='profile':c['profile']='debug'
                elif kind=='cleanup':c['cleanup']['pids']=[1]
                elif kind=='duplicate':e['journeys'][1]=e['journeys'][0]
                else:self.mutate_raw(e,'connected',lambda rows:rows[0]['editor'].update(installed_version=''))
                self.assertNotEqual(self.q.normalize(e)['exit'],0)
    def test_bad_nested_original_receipt_and_false_restore(self):
        for kind in ['receipt','base','restore','agent']:
            e=self.fixture()
            if kind=='receipt':self.mutate_raw(e,'connected',lambda rows:rows[0]['journey']['receipts'][0]['private'].update(receipt='wrong'))
            elif kind=='base':self.mutate_raw(e,'connected',lambda rows:rows[0]['journey']['receipts'][0]['private'].update(original_head='wrong'))
            elif kind=='restore':self.mutate_raw(e,'connected',lambda rows:rows[0]['archive'].update(rejected_absent=False))
            else:self.mutate_raw(e,'mounted',lambda rows:next(r for r in rows if r['case']=='actual-agent-file')['metadata'].update(agent_id=''))
            self.assertNotEqual(self.q.normalize(e)['exit'],0)
    def test_false_positive_assertion_and_boolean_exit_fail(self):
        for kind in ['assertion','exit','coverage','validator']:
            e=self.fixture()
            if kind=='assertion':self.mutate_raw(e,'recovery',lambda rows:next(r for r in rows if r['case']=='history-restore').update(current_metadata=False))
            elif kind=='exit':e['journeys'][0]['components']['native']['exit']=False
            elif kind=='coverage':self.mutate_raw(e,'dependencies',lambda rows:next(r for r in rows if r['case']=='dependency-declarations')['requests']['receipt'].update(coverage='made-up'))
            else:self.mutate_raw(e,'dependencies',lambda rows:next(r for r in rows if r['case']=='dependency-declarations')['policy'].update(version='unknown'))
            with self.subTest(kind=kind):self.assertNotEqual(self.q.normalize(e)['exit'],0)

    def test_exact_policy_transition_is_required(self):
        for kind in ['initial','final','identity','race_status','race_body']:
            e=self.fixture()
            def change(rows):
                initial=next(r for r in rows if r['case']=='configured-validation')['policy']
                final=next(r for r in rows if r['case']=='dependency-declarations')['policy']
                race=next(r for r in rows if r['case']=='publication-route-and-policy-races')
                if kind=='initial':initial['version']='2'
                elif kind=='final':final['version']='3'
                elif kind=='identity':final['executable_hash']='sha256:'+'b'*64
                elif kind=='race_status':race['policy_race']=[200,{'code':'recompute_required'}]
                else:race['policy_race']=[409,{'code':'other'}]
            self.mutate_raw(e,'dependencies',change)
            with self.subTest(kind=kind):self.assertNotEqual(self.q.normalize(e)['exit'],0)
