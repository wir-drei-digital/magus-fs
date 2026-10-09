"""Real coordinator over synthetic native-report writers; no native mount actions."""
import contextlib
import io
import copy
import json
import os
import signal
import sys
import time
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import macos_supervisor
import run
from permission_source import project_manifest

FIXTURES=Path(__file__).with_name('fixtures')


def native_fixture(output,chunk):
    raw=(FIXTURES/'macos-report.json').read_text().replace('/synthetic/fs0',str(output))
    report=json.loads(raw);manifest=json.loads((FIXTURES/'normal-manifests.json').read_text())[str(chunk)]
    report['chunk_size']=chunk;report['manifest_digest']=manifest['digest']
    report['owned_token']=output.name
    report['fixture_identity']['projected_digest']=manifest['digest']
    report['mounts']['normal-ro']['manifest']=manifest
    report['generation_digests']={'old':manifest['digest'],'fresh':project_manifest(manifest,file_mode=0o640)['digest']}
    variants={'group':(None,0o040,12345,20),'other':(None,0o004,12345,12345),'file000':(None,0,501,20),'file644':(None,0o644,501,20),
              'directory000':(0,None,501,20),'directory400':(0o400,None,501,20),'directory100':(0o100,None,501,20)}
    for name,mount in report['mounts'].items():
        mount['manifest_digest']=(project_manifest(manifest,*variants[name])['digest'] if name in variants else
                                  report['generation_digests']['fresh'] if name=='generation-fresh' else manifest['digest'])
    t=report['transfer'];cold=2*chunk
    for key in ('cold','warm'):t[key].update(content_body_bytes=cold,unique_chunks=2)
    t['full']['unique_chunks']=67108864//chunk
    t.update(cold_delta=cold,warm_delta=0,full_scan_delta=67108864-cold)
    return report


class MacCoordinator(unittest.TestCase):
    def execute(self,runner):
        def prerequisite(args,**kwargs):
            if args not in (['git','rev-parse','HEAD'],['git','status','--short']):
                raise AssertionError('unexpected command: '+repr(args))
            return subprocess.CompletedProcess(args,0,'synthetic revision','')
        with tempfile.TemporaryDirectory(prefix='fs0-mac-coordinator-') as folder:
            output=Path(folder)/'combined'
            with patch.object(run,'collect',return_value={'scope':'synthetic inventory'}),patch.object(run.subprocess,'run',side_effect=prerequisite),patch.object(macos_supervisor,'run',side_effect=runner),patch('macos_run.run',side_effect=AssertionError('unbounded native call forbidden in unit test')),contextlib.redirect_stdout(io.StringIO()):
                code=run.main(['--platform','macos','--output',str(output)])
            return code,json.loads((output/'result.json').read_text())
    def test_schedules_two_fresh_three_size_journeys(self):
        def runner(output,prepare,chunk,uid,gid,**kwargs):
            self.assertFalse(prepare);self.assertEqual((uid,gid),(501,20))
            output.mkdir();(output/'result.json').write_text(json.dumps(native_fixture(output,chunk)));return 0
        code,result=self.execute(runner)
        self.assertEqual(code,0)
        self.assertEqual([(p['journey'],p['chunk_size']) for p in result['platforms']['macos']['profiles']],[(j,c) for j in (1,2) for c in (65536,262144,1048576)])
    def test_existing_mac_failure_and_escaping_cleanup_timeout_preserve_resources(self):
        def runner(output,prepare,chunk,uid,gid,**kwargs):
            output.mkdir();report=native_fixture(output,chunk)
            report.update(passed=False,state='failed',error='synthetic mounted read failure',cleanup_errors=['synthetic cleanup timeout'],remaining_owned_resources=[str(output/'mount-normal-ro')])
            report['cases']['partial-cold']['state']='failed'
            (output/'result.json').write_text(json.dumps(report))
            raise subprocess.TimeoutExpired(['/sbin/umount',str(output/'mount-normal-ro')],5)
        code,result=self.execute(runner)
        self.assertEqual(code,1)
        profile=result['platforms']['macos']['profiles'][0]
        self.assertEqual(profile['error'],'synthetic mounted read failure')
        self.assertEqual(len(profile['owned_resources']['pids']),15)
        self.assertEqual(len(profile['owned_resources']['mountpoints']),13)
        self.assertEqual(profile['orchestration_error']['type'],'TimeoutExpired')
        self.assertTrue(profile['native_report_snapshot'])
        self.assertTrue(profile['remaining_owned_resources'])
    def test_pending_supervised_runner_fails_and_retains_exact_child(self):
        def runner(output,prepare,chunk,uid,gid,**kwargs):
            output.mkdir();report=native_fixture(output,chunk)
            report.update(state='cleanup_pending',passed=False,cleanup_errors=['synthetic pending'],remaining_owned_resources=[str(output/'mount-normal-ro')])
            (output/'result.json').write_text(json.dumps(report))
            record={'state':'failed_pending','reason':'native cleanup pending','runner_pid':999999,'runner_alive':True,'native_snapshot':report,
                    'native_evidence':str(output/'result.json'),'recovery_action':{'instruction':'retain serving child'}}
            raise macos_supervisor.SupervisionFailure(record)
        code,result=self.execute(runner)
        self.assertEqual(code,1)
        profile=result['platforms']['macos']['profiles'][0]
        self.assertEqual(profile['supervision']['runner_pid'],999999)
        self.assertIn(999999,profile['owned_resources']['supervisor_runner_pids'])
        self.assertTrue(profile['supervision']['recovery_action'])
        self.assertTrue(profile['remaining_owned_resources'])
        self.assertEqual(len(result['platforms']['macos']['profiles']),1)

    def test_late_real_parent_signals_fail_cleanup_and_serialized_publication(self):
        # Catches reconciling only before final cleanup or only before json.dumps.
        # Native reports are synthetic; handlers, cleanup, encoder and writes run.
        original_cleanup = run.OwnedOutput.cleanup
        original_dumps = json.dumps
        original_aggregate = run.aggregate
        def runner(output, prepare, chunk, uid, gid, **kwargs):
            output.mkdir()
            (output/'result.json').write_text(original_dumps(native_fixture(output, chunk)))
            return 0
        for stage in ('cleanup', 'serialization'):
            for signum in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(stage=stage, signal=signum):
                    delivered = []
                    previous = signal.getsignal(signum)
                    def cleanup(owned, *args, **kwargs):
                        errors = original_cleanup(owned, *args, **kwargs)
                        if stage == 'cleanup' and not delivered:
                            delivered.append(True)
                            os.kill(os.getpid(), signum)
                        return errors
                    def aggregate(*args):
                        result = original_aggregate(*args)
                        # Force real indent=2 encoding long enough for the owned sender.
                        if stage == 'serialization':
                            result['serialization_probe'] = [{'value': i} for i in range(800000)]
                        return result
                    def dumps(value, *args, **kwargs):
                        if stage != 'serialization' or 'exit_code' not in value or delivered:
                            return original_dumps(value, *args, **kwargs)
                        # A separate owned process can deliver while 3.14's C
                        # encoder holds the GIL. Handshake excludes startup timing.
                        sender_code = (
                            'import os,sys,time; print("ready",flush=True); '
                            'sys.stdin.readline(); time.sleep(.005); '
                            'sent=time.time(); os.kill(int(sys.argv[1]),int(sys.argv[2])); '
                            'print(sent,flush=True)')
                        process = subprocess.Popen(
                            [sys.executable, '-c', sender_code, str(os.getpid()), str(int(signum))],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
                        try:
                            self.assertEqual(process.stdout.readline().strip(), 'ready')
                            started = time.time()
                            process.stdin.write('encode\n')
                            process.stdin.flush()
                            encoded = original_dumps(value, *args, **kwargs)
                            finished = time.time()
                            out, err = process.communicate(timeout=5)
                            self.assertEqual((process.returncode, err), (0, ''))
                            delivered.append(started < float(out.strip()) < finished)
                            return encoded
                        finally:
                            if process.poll() is None:
                                process.terminate()
                                process.communicate(timeout=5)
                    with patch.object(run.OwnedOutput, 'cleanup', cleanup), \
                         patch.object(run, 'aggregate', side_effect=aggregate), \
                         patch.object(run.json, 'dumps', side_effect=dumps):
                        code, result = self.execute(runner)
                    self.assertEqual(delivered, [True], 'signal must arrive inside the named stage')
                    self.assertEqual(code, 1)
                    self.assertEqual(result['exit_code'], 1)
                    self.assertEqual(result['state'], 'failed')
                    self.assertIs(result['passed'], False)
                    self.assertEqual(result['parent_interrupts'], 1)
                    self.assertEqual(result['failures'].count(
                        'parent interrupted; inspect retained owned profile resources'), 1)
                    self.assertEqual(signal.getsignal(signum), previous)

    def test_missing_mac_launcher_is_blocked(self):
        def runner(*args):raise FileNotFoundError('synthetic missing prerequisite')
        code,result=self.execute(runner)
        self.assertEqual(code,2);self.assertEqual(result['state'],'blocked')
