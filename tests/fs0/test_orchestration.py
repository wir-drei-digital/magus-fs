"""Synthetic exception-boundary reports; no native mount/daemon claims or calls."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import linux_run
import run


class OrchestrationFailures(unittest.TestCase):
    def execute(self, runner):
        def prerequisites(args, **_kwargs):
            allowed = (['git','rev-parse','HEAD'], ['git','status','--short'],
                       ['docker','image','inspect','fs0-task4-runtime'])
            if args not in allowed:
                raise AssertionError('unexpected external command: ' + repr(args))
            return subprocess.CompletedProcess(args,0,'synthetic revision','')
        with tempfile.TemporaryDirectory(prefix='fs0-orchestration-') as directory:
            output = Path(directory) / 'combined'
            with patch.object(run,'collect',return_value={'scope':'synthetic test inventory'}), \
                 patch.object(run.subprocess,'run',side_effect=prerequisites), \
                 patch.object(linux_run,'run',side_effect=runner):
                code = run.main(['--platform','linux','--image','fs0-task4-runtime','--output',str(output)])
            report = json.loads((output / 'result.json').read_text())
            path = output / 'linux-1-65536/result.json'
            native = json.loads(path.read_text()) if path.exists() else None
            return code,report,native

    def test_retained_read_failure_and_escaping_cleanup_timeout_fail(self):
        native = {'platform':'linux','token':'synthetic-token','passed':False,
                  'error':'synthetic required mounted read failed',
                  'owned_containers':['synthetic-owned-daemon'], 'owned_vm_path':'/tmp/synthetic-owned-path',
                  'daemon':{'pids':[123456789]},
                  'cases':{'root-readonly':{'range_reads':{'state':'failed','detail':'synthetic exact-byte mismatch'}}},
                  'cleanup':[{'error':'synthetic Docker cleanup timed out','owned_container_retained':'synthetic-owned-daemon'}]}
        def runner(output,*_args):
            output.mkdir()
            (output / 'result.json').write_text(json.dumps(native))
            raise subprocess.TimeoutExpired(['docker','ps','-a'],45)
        code,report,retained = self.execute(runner)
        self.assertEqual(code,1)
        self.assertEqual(report['state'],'failed')
        self.assertTrue(report['failures'])
        profile = report['platforms']['linux']['profiles'][0]
        self.assertEqual(profile['error'],'synthetic required mounted read failed')
        self.assertEqual(profile['orchestration_error']['command'],['docker','ps','-a'])
        self.assertEqual(profile['orchestration_error']['timeout'],45)
        self.assertEqual(profile['owned_resources']['containers'],['synthetic-owned-daemon'])
        self.assertEqual(profile['owned_resources']['pids'],[123456789])
        self.assertIn('synthetic-owned-daemon',profile['remaining_owned_resources'])
        self.assertEqual(profile['native_report_snapshot'],retained)
        self.assertEqual(retained,native)

    def test_escaping_cleanup_error_fails_even_with_prior_pass_flag(self):
        native = {'passed':True,'cleanup':[{'owned_container_retained':'synthetic-retained-daemon'}]}
        def runner(output,*_args):
            output.mkdir()
            (output / 'result.json').write_text(json.dumps(native))
            raise subprocess.TimeoutExpired(['docker','ps','-a'],45)
        code,report,_ = self.execute(runner)
        self.assertEqual(code,1)
        profile = report['platforms']['linux']['profiles'][0]
        self.assertEqual(profile['cases']['cleanup']['state'],'failed')
        self.assertIn('synthetic-retained-daemon',profile['owned_resources']['containers'])
        self.assertIn('synthetic-retained-daemon',profile['remaining_owned_resources'])
        self.assertEqual(profile['orchestration_error']['type'],'TimeoutExpired')

    def test_missing_native_launcher_without_report_is_blocked(self):
        def runner(_output,*_args):
            raise FileNotFoundError('synthetic missing launcher prerequisite')
        code,report,_ = self.execute(runner)
        self.assertEqual(code,2)
        self.assertEqual(report['state'],'blocked')
        self.assertFalse(report['failures'])
        self.assertEqual(len(report['platforms']['linux']['profiles']),1)
        profile = report['platforms']['linux']['profiles'][0]
        self.assertEqual(profile['orchestration_error']['type'],'FileNotFoundError')
        self.assertIn('native_report_error',profile)
