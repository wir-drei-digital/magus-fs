"""Real process lifecycle checks for untimed native fixture supervision."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import types
import unittest
from latency_acceptance import native_startup

OWNER = '''#!/usr/bin/env python3
import json,os,socket,sys,time
from pathlib import Path
state=Path(sys.argv[sys.argv.index('--state')+1]);scenario=(state/'scenario').read_text()
if sys.argv[1:3]==['sync','run']:
 p=state/'count';n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
 if scenario.startswith('pressure') and n<=int(scenario.split('-')[1]) or scenario=='denied':
  if scenario=='pressure-20':time.sleep(.12)
  error={'error':'permission_denied'} if scenario=='denied' else {'error':'base_unavailable','details':'BaseUnavailable { object: x, cause: Transport { kind: "backpressure" } }'}
  print(json.dumps(error),flush=True);sys.exit(1)
 if scenario!='live':
  sock=socket.socket(socket.AF_UNIX);sock.bind(str(state/'control.sock'));sock.listen()
 while True:time.sleep(.02)
print(json.dumps({'native':{'status':{'Ready':{'revision':'revision'}}},'live':{'applied':True,'authorized':True},'status':{'binding':{'source':'normal-source','view':{'view':'view','head':'head','revision':'revision'}}}}))
'''


class NativeStartupTests(unittest.TestCase):
    def fixture(self, scenario):
        temporary=tempfile.TemporaryDirectory(prefix='latency-startup-process-',dir='/tmp');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);state=root/'state';state.mkdir();(state/'scenario').write_text(scenario)
        tree=root/'tree';tree.mkdir();(tree/'bench').write_bytes(b'unchanged bytes')
        ca=root/'ca';ca.write_text('owned trust');token=root/'token';token.write_text('owned credential')
        (root/'profile').write_text(json.dumps({'ca_file':str(ca),'token_file':str(token)}))
        binary=root/'owner';binary.write_text(OWNER);binary.chmod(0o755)
        report={};client={'path':str(root),'root':str(tree),'state':str(state),'binding':{'source':'initial-source','view':{'view':'view','head':'head','revision':'revision'}}}
        class Infra:
            def run(self,argv,**kw):return subprocess.run(argv,text=True,capture_output=True,**kw)
            def write_json(self,name,value):(root/name).write_text(json.dumps(value))
        infra=Infra()
        class Mac:
            i=infra
            def __init__(self):self.binary=str(binary);self.faults=self.binary;self.j=types.SimpleNamespace(until=self.until)
            def until(self,fn,seconds):
                end=time.monotonic()+seconds
                while time.monotonic()<end:
                    if fn():return
                    time.sleep(.005)
                raise TimeoutError('test process wait')
            def run(self,code,data=None):
                script='import json,os,sys,subprocess,time,hashlib,signal\ns=json.load(sys.stdin)\n'+code
                p=self.i.run(['python3','-c',script],input=json.dumps(data),timeout=25)
                if p.returncode:raise AssertionError(p.stderr)
                return json.loads(p.stdout)
            def status(self,c):
                p=self.i.run([self.binary,'sync','status','--state',c['state']],timeout=12);return json.loads(p.stdout)
            def save(self):infra.write_json('ownership.json',client)
            def stop(self,c):
                pid=c.pop('pid');c['stopped_pid']=pid
                try:os.kill(pid,signal.SIGTERM)
                except ProcessLookupError:pass
        mac=Mac()
        def cleanup():
            for row in report.get('native_startup_attempts',[]):
                if row.get('pid'):
                    try:os.kill(row['pid'],signal.SIGTERM)
                    except ProcessLookupError:pass
        self.addCleanup(cleanup)
        return mac,client,infra,report,lambda:infra.write_json('report.json',report)

    def test_exited_pressure_restarts_same_owner_state_and_retains_every_pid(self):
        mac,c,i,report,save=self.fixture('pressure-2');original=mac.i
        result=native_startup(mac,c,i,report,save,budget=3)
        rows=report['native_startup_attempts'];self.assertEqual(len(rows),3);self.assertEqual(len({r['pid'] for r in rows}),3)
        self.assertTrue(all(r['retryable_pressure'] and r['exited'] for r in rows[:2]));self.assertTrue(rows[-1]['ready'])
        self.assertEqual(result['status']['binding']['view'],c['binding']['view']);self.assertIs(mac.i,original)
        self.assertTrue(all(r['before']['profile_sha256']==rows[-1]['after']['profile_sha256'] for r in rows))

    def test_persistent_pressure_fails_after_three_total_starts(self):
        mac,c,i,report,save=self.fixture('pressure-10');original=mac.i
        with self.assertRaisesRegex(AssertionError,'exhausted three'):native_startup(mac,c,i,report,save,budget=3)
        self.assertEqual(len(report['native_startup_attempts']),3);self.assertIs(mac.i,original)

    def test_denial_is_terminal_without_restart(self):
        mac,c,i,report,save=self.fixture('denied');original=mac.i
        with self.assertRaisesRegex(AssertionError,'non-pressure'):native_startup(mac,c,i,report,save,budget=3)
        self.assertEqual(len(report['native_startup_attempts']),1);self.assertFalse(report['native_startup_attempts'][0]['retryable_pressure']);self.assertIs(mac.i,original)

    def test_live_unready_owner_is_never_restarted_and_deadline_is_not_reset(self):
        mac,c,i,report,save=self.fixture('live');original=mac.i;start=time.monotonic()
        with self.assertRaises((TimeoutError,subprocess.TimeoutExpired)):native_startup(mac,c,i,report,save,budget=.35)
        self.assertEqual(len(report['native_startup_attempts']),1);self.assertLess(time.monotonic()-start,.6);self.assertIs(mac.i,original)


if __name__=='__main__':unittest.main()
