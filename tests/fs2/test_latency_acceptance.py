"""Real ordinary-save/observer helpers and error-inclusive distribution checks."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from latency_acceptance import WATCH, WRITE, distribution


class AcceptanceTests(unittest.TestCase):
    def test_capacity_override_is_confined_to_acceptance_s3_creation(self):
        from latency_acceptance import acceptance_s3_capacity
        original=['--memory','1g','--cpus','2','--pids-limit','256','-v','owned:/data','-volume.max=1','-master.volumeSizeLimitMB=1024']
        for phase in ['wakeups','reuse','pooled','backend-preflight']:
            self.assertEqual(acceptance_s3_capacity(phase,'container','s3',original),original)
        for kind,suffix in [('volume','s3'),('container','service'),('container','acceptance-sender')]:
            self.assertEqual(acceptance_s3_capacity('acceptance',kind,suffix,original),original)
        accepted=acceptance_s3_capacity('acceptance','container','s3',original)
        self.assertEqual(accepted,original[:-2]+['-volume.max=8',original[-1]])
        self.assertEqual(original[-2],'-volume.max=1','baseline configuration must remain intact')

    def test_backend_diagnostics_continue_after_missing_log_and_exclude_credentials(self):
        from latency_acceptance import backend_diagnostics
        with tempfile.TemporaryDirectory(prefix='latency-backend-diagnostics-') as temporary:
            root=Path(temporary)
            class Infra:
                owner='owned';resources=[{'kind':'container','name':'owned-s3','id':'original-id'}]
                def inspect(self,kind,name):
                    return {'Id':'original-id','State':{'OOMKilled':True,'ExitCode':137},'HostConfig':{'Memory':1024},'Config':{'Env':['secret=private']}}
                def validate_owned(self,row,data):
                    assert data['Id']==row['id']
                def docker(self,*args,**kw):
                    if args[0]=='logs':raise RuntimeError('log unavailable')
                    return subprocess.CompletedProcess(args,0,'retained resource diagnostic','')
                def write_json(self,name,value):(root/name).write_text(json.dumps(value))
            result=backend_diagnostics(Infra(),'failure')
            self.assertEqual(result['containers'][0]['state']['ExitCode'],137)
            self.assertIn('log unavailable',str(result['errors']))
            self.assertTrue(result['containers'][0]['stats']['stdout'])
            self.assertTrue(result['containers'][0]['disk']['stdout'])
            self.assertNotIn('secret', (root/'failure-backends.json').read_text())

    def denied_observer(self, persistent):
        with tempfile.TemporaryDirectory(prefix='latency-denied-observer-') as temporary:
            root=Path(temporary);uid=1001 if os.geteuid()==0 else os.geteuid()
            if os.geteuid()==0:os.chown(root,uid,1001)
            path=root/'bench';path.write_bytes(b'denied old identity');path.chmod(0)
            marker=str(root/'observer');body=b'permitted replacement identity'
            watch=WATCH.replace("'/shared/b/reports/bench'",repr(str(path)))
            def unprivileged():
                if os.geteuid()==0:os.setgid(1001);os.setuid(uid)
            child=subprocess.Popen(['python3','-c',"import os;assert os.geteuid()!=0\n"+watch,json.dumps({'body':body.hex(),'marker':marker,'deadline_seconds':.2})],preexec_fn=unprivileged)
            try:
                deadline=time.monotonic()+2
                while not Path(marker+'-first-error').exists() and not Path(marker+'-result').exists():
                    self.assertLess(time.monotonic(),deadline);time.sleep(.005)
                if not persistent:
                    replacement=root/'replacement';replacement.write_bytes(body);replacement.chmod(0o644);os.replace(replacement,path)
                self.assertEqual(child.wait(timeout=2),0)
                row=json.loads(Path(marker+'-result').read_text())
                self.assertTrue(row['transient_errors'],'actual unprivileged denial must be observed')
                self.assertTrue(all(e['errno']==13 for e in row['transient_errors']))
                if persistent:
                    self.assertTrue(row.get('timeout'),'persistent denial must fail the bounded observation')
                    self.assertNotIn('fresh_read_ns',row)
                else:
                    self.assertNotIn('error',row,'identity transition must retry ordinary fresh open')
                    self.assertNotIn('timeout',row)
                    self.assertEqual(row['sha256'],hashlib.sha256(body).hexdigest())
                    self.assertGreater(row['fresh_read_ns'],row['transient_errors'][0]['monotonic_ns'])
            finally:
                if child.poll() is None:child.terminate();child.wait(timeout=2)

    def test_denied_old_identity_retries_fresh_open_of_permitted_replacement(self):
        self.denied_observer(False)

    def test_persistent_denial_remains_bounded_failure_with_all_errors_retained(self):
        self.denied_observer(True)

    def test_distribution_retains_slow_and_failed_sample(self):
        rows = [{'seconds': .1}, {'seconds': .3}, {'seconds': 20, 'timeout': True, 'transient_errors': [{'errno': 5}]}]
        found = distribution(rows, 'seconds')
        self.assertEqual(found['n'], 3)
        self.assertEqual(found['p50_ms'], 300)
        self.assertEqual(found['p95_ms'], 20000)
        self.assertEqual(found['p99_ms'], 20000)
        self.assertEqual(found['errors'], 1)
        self.assertEqual(found['transient_read_errors'], 1)
        self.assertEqual(found['over_500ms'], 1)

    def test_ordinary_in_place_and_atomic_helpers_record_exact_fresh_bytes(self):
        with tempfile.TemporaryDirectory(prefix='latency-acceptance-helper-') as temporary:
            root = Path(temporary); path = root / 'bench'
            for atomic in [False, True]:
                body = os.urandom(1024); marker = str(root / ('atomic' if atomic else 'in-place'))
                watch = WATCH.replace("'/shared/b/reports/bench'", repr(str(path)))
                child = subprocess.Popen(['python3', '-c', watch, json.dumps({'body': body.hex(), 'marker': marker})])
                try:
                    deadline = time.monotonic() + 2
                    while not Path(marker + '-ready').exists():
                        self.assertLess(time.monotonic(), deadline); time.sleep(.005)
                    writer = subprocess.run(['python3', '-c', WRITE], input=json.dumps({'body': body.hex(), 'path': str(path), 'atomic': atomic}), text=True, capture_output=True, check=True)
                    self.assertEqual(child.wait(timeout=2), 0)
                    saved = json.loads(writer.stdout); observed = json.loads(Path(marker + '-result').read_text())
                    self.assertGreaterEqual(observed['fresh_read_ns'], saved['save_started_ns'])
                    self.assertEqual(observed['sha256'], hashlib.sha256(body).hexdigest())
                    self.assertEqual(path.read_bytes(), body)
                    self.assertFalse(Path(str(path) + '.save').exists())
                finally:
                    if child.poll() is None: child.terminate(); child.wait(timeout=2)


if __name__ == '__main__': unittest.main()
