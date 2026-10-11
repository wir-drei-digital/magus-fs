"""Source admission negatives; synthetic data is not experiment qualification."""
import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
saved_path=sys.path.copy()
spec=importlib.util.spec_from_file_location('poc_prerequisites',Path(__file__).with_name('run.py'));runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
sys.path[:]=saved_path
class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.folders=[]
        self.assessment=[{'name':'overlap','intent_fragments_preserved':False}]
        for name in ['one','two']:
            p=self.root/name;p.mkdir();self.folders.append(p)
            source={'sha256':{'tests/poc/run.py':runner.journey.q.sha(runner.ROOT/'tests/poc/run.py')}}
            values={'source':source,'binary':{'sha256':'fixture'},'dependencies':[],'registry':[],'benchmarks':[],'result':{'passed':True,'assessments':self.assessment,'semantic_findings':self.assessment}}
            for leaf,value in values.items():(p/(leaf+'.json')).write_text(json.dumps(value))
            (p/'raw.jsonl').write_text('{"heads":["same"],"elapsed_us":1}\n');(p/'state.am').write_bytes(b'fixture')
        self.mock=patch('crdt_comparison.validate_evidence',return_value=self.assessment);self.mock.start();self.addCleanup(self.mock.stop)
    def test_missing_and_duplicate_prerequisites_reject(self):
        with self.assertRaises(runner.InfrastructureUnavailable):runner.current_crdt(None)
        with self.assertRaises(AssertionError):runner.current_crdt([self.folders[0]]*2)
    def test_current_pair_and_source_mismatch(self):
        self.assertTrue(runner.current_crdt(self.folders)[1]['passed'])
        p=self.folders[1]/'source.json';p.write_text(json.dumps({'sha256':{'tests/poc/run.py':'0'*64}}))
        with self.assertRaisesRegex(AssertionError,'current source mismatch'):runner.current_crdt(self.folders)
    def test_raw_semantics_must_repeat_but_timings_may_differ(self):
        p=self.folders[1]/'raw.jsonl';p.write_text('{"heads":["same"],"elapsed_us":999}\n');runner.current_crdt(self.folders)
        p.write_text('{"heads":["different"],"elapsed_us":999}\n')
        with self.assertRaisesRegex(AssertionError,'repeatability mismatch'):runner.current_crdt(self.folders)
    def test_failed_intent_evidence_cannot_be_missing(self):
        p=self.folders[1]/'result.json';value=json.loads(p.read_text());value['semantic_findings']=[];p.write_text(json.dumps(value))
        with self.assertRaisesRegex(AssertionError,'intent assessment'):runner.current_crdt(self.folders)
