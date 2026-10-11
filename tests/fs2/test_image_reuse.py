"""Exercise reuse through real runner control flow; isolate external native tools."""
import contextlib
import io
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import native_complete
import reconciliation
import provenance
from infra import OwnedInfra

IMAGE = 'sha256:' + 'a' * 64

class ImageReuseTests(unittest.TestCase):
    def run_gate(self, module, reuse=True, profile='dev', stale=False, missing=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);binary = root / 'target/debug';binary.mkdir(parents=True)
            for name in ['magus-fs', 'magus-fs-client-faults']:(binary / name).write_bytes(b'host')
            output = root / 'evidence'
            source = {'sha256': {'src.rs': 'current'}}
            def run(infra, args, **kwargs):
                if args[:3] == ['cargo', '+stable', 'build']:
                    (binary / 'magus-fs').write_bytes(b'fault-build' if '--features' in args else b'default-build')
                return SimpleNamespace(stdout='tool version', stderr='', returncode=0)
            def docker(infra, *args, **kwargs):
                if args[:2] == ('image', 'inspect'):
                    if missing:raise RuntimeError('No such image')
                    return SimpleNamespace(stdout=json.dumps([{'Id': IMAGE, 'Config': {'Labels': {'magus.fs2.build-profile': profile}}}]))
                if args[0] == 'build':
                    if reuse:raise AssertionError('borrowed image was rebuilt')
                    return SimpleNamespace(stdout='built')
                if stale and args[:2] == ('exec', '-i'):
                    return SimpleNamespace(stdout=json.dumps({'src.rs': 'old'}))
                return SimpleNamespace(stdout='abc binary', stderr='')
            def setup(infra, image):
                infra.service = 'synthetic-service'
                infra.write_json('fixture-image.json', {'image': image})
            def journey_run(journey):journey.i.write_json('journey-started.json', {'started': True})
            argv = ['runner', '--output', str(output)] + (['--reuse-image', 'moving-tag'] if reuse else [])
            journey = module.Reconciliation if module is reconciliation else module.Complete
            with contextlib.ExitStack() as stack:
                for target, value in [('sys.argv', argv), ('sys.platform', 'darwin')]:stack.enter_context(patch(target, value))
                for name, value in [('ROOT', root), ('capture', lambda i: source)]:stack.enter_context(patch.object(module, name, value))
                for name, value in [('preflight', lambda i: None), ('run', run), ('docker', docker), ('setup', setup), ('cleanup', lambda i: None)]:stack.enter_context(patch.object(OwnedInfra, name, value))
                stack.enter_context(patch('service_storage.ssl.create_default_context', lambda **k: None))
                stack.enter_context(patch.object(journey, 'run', journey_run));stack.enter_context(patch.object(journey, 'cleanup', lambda j: None))
                if stale:
                    stack.enter_context(patch.object(provenance, 'sources', lambda: source['sha256']))
                else:stack.enter_context(patch.object(module, 'verify_image', lambda i, s: None))
                if module is native_complete:
                    stack.enter_context(patch.object(module, 'host_matrix', lambda i, r: None))
                    stack.enter_context(patch.object(module, 'linux_matrix', lambda i, r: None))
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    try:code = module.main()
                    except SystemExit as error:code = error.code
            return code, {p.name: json.loads(p.read_text()) for p in output.glob('*.json')}

    def test_reuse_accepts_cli_and_records_development_result_without_image_ownership(self):
        for module in [reconciliation, native_complete]:
            with self.subTest(runner=module.__name__):
                code, files = self.run_gate(module)
                self.assertEqual(code, 0)
                self.assertFalse(files['result.json']['complete_gate'])
                self.assertEqual(files['result.json']['build_reuse'], {'requested': 'moving-tag', 'image': IMAGE, 'profile': 'dev'})
                self.assertEqual(files['fixture-image.json']['image'], IMAGE)
                self.assertTrue(files['journey-started.json']['started'])
                binaries = files['binaries.json']['host'] if module is reconciliation else {name: row['host'] for name, row in files['native-binaries.json'].items()}
                self.assertEqual(binaries['magus-fs'], hashlib.sha256(b'default-build').hexdigest())
                self.assertEqual(binaries['magus-fs-client-faults'], hashlib.sha256(b'fault-build').hexdigest())
                self.assertNotIn('image-ownership.json', files)

    def test_fresh_build_remains_complete_and_owned(self):
        for module in [reconciliation, native_complete]:
            with self.subTest(runner=module.__name__):
                code, files = self.run_gate(module, reuse=False)
                self.assertEqual(code, 0)
                self.assertTrue(files['result.json']['complete_gate'])
                self.assertIn('image-ownership.json', files)
                self.assertIsNone(files['result.json']['build_reuse'])

    def test_invalid_reuse_fails_before_journey(self):
        for module in [reconciliation, native_complete]:
            for options, reason in [({'profile': 'release'}, 'dev'), ({'profile': None}, 'dev'), ({'stale': True}, 'differs from built image'), ({'missing': True}, 'No such image')]:
                with self.subTest(runner=module.__name__, options=options):
                    code, files = self.run_gate(module, **options)
                    self.assertEqual(code, 1)
                    self.assertIn(reason, files['failure.json']['reason'])
                    self.assertNotIn('journey-started.json', files)
                    self.assertNotIn('image-ownership.json', files)
                    self.assertFalse(files['result.json']['complete_gate'])

if __name__ == '__main__':unittest.main()
