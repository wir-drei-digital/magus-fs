"""Exercise the executable driver's real finalization path with owned synthetic resources."""
import ast
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import types
import unittest


class LatencyCleanupTests(unittest.TestCase):
    def fixture(self, *, missing_trace=False, service_failure=False, unmount_failure=False):
        temporary = tempfile.TemporaryDirectory(prefix='latency-cleanup-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        resources = root / 'owned-resources'
        resources.mkdir()
        mounted = resources / 'mounted'
        mounted.write_text('owned synthetic mount and helper')
        (root / 'live.log').write_text('live diagnostic')
        if not missing_trace:
            (root / 'gone.log').write_text('other diagnostic')
        calls = []

        class Lazy:
            mounts = ['gone', 'live']

            def execute(self, code, name):
                calls.append(('trace', name))
                return (root / (name + '.log')).read_text()

        class Infra:
            service = 'owned-service'

            def write_json(self, name, value):
                (root / name).write_text(json.dumps(value))

            def docker(self, *args, **kwargs):
                calls.append(('trace', 'service'))
                if service_failure:
                    raise subprocess.CalledProcessError(1, ['docker', *args], stderr='service log unavailable')
                return types.SimpleNamespace(stdout='service diagnostic')

            def cleanup(self):
                calls.append(('cleanup', 'infra'))
                if mounted.exists():
                    raise AssertionError('unsafe resource removal before normal unmount')
                shutil.rmtree(resources)

        class Journey:
            lazy = Lazy()

            def cleanup(self):
                calls.append(('cleanup', 'journey'))
                if unmount_failure:
                    raise RuntimeError('normal unmount refused; keep mounted helper resources')
                mounted.unlink()

        report = {'phases': {}, 'failures': []}
        state = dict(i=Infra(), j=Journey(), report=report, code=0, started=time.monotonic(),
                     source={'sha256': {}}, sources=lambda: {}, a=types.SimpleNamespace(output=str(root)), time=time, json=json)
        state['save'] = lambda: (root / 'profile.json').write_text(json.dumps(report))
        driver = Path(__file__).with_name('latency.py')
        # Run the exact executable finally block without booting its main Docker journey.
        finalizer = next(node for node in reversed(ast.parse(driver.read_text()).body)
                         if isinstance(node, ast.Try) and node.finalbody)
        code = compile(ast.Module(body=finalizer.finalbody, type_ignores=[]), str(driver), 'exec')
        with contextlib.redirect_stdout(io.StringIO()):
            exec(code, state)
        return root, resources, mounted, calls, report, state['code']

    def test_missing_daemon_trace_and_failed_service_exec_still_unmount_and_clean(self):
        root, resources, mounted, calls, report, code = self.fixture(missing_trace=True, service_failure=True)
        self.assertFalse(resources.exists(), 'diagnostic failure skipped safe owned cleanup')
        self.assertFalse(mounted.exists())
        self.assertEqual(calls, [('trace', 'gone'), ('trace', 'live'), ('trace', 'service'),
                                 ('cleanup', 'journey'), ('cleanup', 'infra')])
        self.assertTrue((root / 'trace-live.json').exists(), 'one missing trace must not skip later diagnostics')
        self.assertEqual(len(report['failures']), 2)
        self.assertTrue(all('diagnostic_error' in failure for failure in report['failures']))
        self.assertEqual(code, 1, 'incomplete diagnostic evidence remains a reported failure')

    def test_unmount_failure_preserves_mounted_helpers_and_reports_cleanup_error(self):
        _, resources, mounted, calls, report, code = self.fixture(unmount_failure=True)
        self.assertTrue(resources.exists())
        self.assertTrue(mounted.exists())
        self.assertNotIn(('cleanup', 'infra'), calls, 'do not destroy resources while normal unmount failed')
        self.assertEqual(len(report['failures']), 1)
        self.assertIn('cleanup_error', report['failures'][0])
        self.assertEqual(code, 1)

    def test_success_cleans_after_diagnostics_without_new_failure(self):
        _, resources, _, calls, report, code = self.fixture()
        self.assertFalse(resources.exists())
        self.assertEqual(calls[-2:], [('cleanup', 'journey'), ('cleanup', 'infra')])
        self.assertEqual(report['failures'], [])
        self.assertEqual(code, 0)


if __name__ == '__main__':
    unittest.main()
