import unittest
from run import validate_source_compatibility

class SourceCompatibilityTests(unittest.TestCase):
    def test_exact_named_harness_delta(self):
        old={'tests/fs3/daytona.py':'a'*64};new={'tests/fs3/daytona.py':'b'*64}
        delta={'tests/fs3/daytona.py':{'earlier':'a'*64,'current':'b'*64}}
        self.assertEqual(validate_source_compatibility(old,new,delta),delta)

    def test_unlisted_change_rejected(self):
        with self.assertRaisesRegex(ValueError,'exact source delta'):
            validate_source_compatibility({'tests/fs3/daytona.py':'a'*64},{'tests/fs3/daytona.py':'b'*64},{})

    def test_runtime_change_cannot_be_declared_compatible(self):
        old={'crates/magus-fs/src/main.rs':'a'*64};new={'crates/magus-fs/src/main.rs':'b'*64}
        delta={'crates/magus-fs/src/main.rs':{'earlier':'a'*64,'current':'b'*64}}
        with self.assertRaisesRegex(ValueError,'unreviewed runtime'):
            validate_source_compatibility(old,new,delta)

    def test_dependency_change_cannot_be_declared_compatible(self):
        with self.assertRaisesRegex(ValueError,'unreviewed runtime'):
            validate_source_compatibility({'Cargo.lock':'a'*64},{'Cargo.lock':'b'*64},{'Cargo.lock':{'earlier':'a'*64,'current':'b'*64}})

class RetainedAggregateTests(unittest.TestCase):
    def setUp(self):
        import tempfile,sys
        from pathlib import Path
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
        from package import source_manifest
        self.index={'current_source':source_manifest(),'phases':{}}

    def run_index(self):
        import json
        from run import aggregate_existing
        path=self.path/'index.json';path.write_text(json.dumps(self.index))
        return aggregate_existing(path)

    def test_missing_provider_never_passes(self):
        self.assertEqual(self.run_index()['status'],'blocked')

    def test_current_snapshot_tamper_rejected(self):
        self.index['current_source']['Cargo.lock']='0'*64
        with self.assertRaisesRegex(ValueError,'current source snapshot'):
            self.run_index()

    def test_retained_result_hash_checked(self):
        p=self.path/'provider.json';p.write_text('{}')
        self.index['phases']['provider']={'result':str(p),'sha256':'0'*64}
        with self.assertRaisesRegex(ValueError,'phase result hash'):
            self.run_index()

    def test_unexecuted_result_cannot_pass(self):
        import json,hashlib
        p=self.path/'provider.json';p.write_text(json.dumps({'phase':'provider','executed':False,'status':'passed'}))
        self.index['phases']['provider']={'result':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        with self.assertRaisesRegex(ValueError,'unexecuted evidence'):
            self.run_index()
