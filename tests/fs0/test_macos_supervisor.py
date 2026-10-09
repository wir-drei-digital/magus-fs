"""Real disposable serving processes; no mounts or mounted-path operations."""
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

CHILD='''import json,signal,subprocess,sys,time
from pathlib import Path
signal.signal(signal.SIGINT,lambda *_:None)
out=Path(sys.argv[1]);out.mkdir()
server=subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);time.sleep(60)'])
report={'state':sys.argv[2],'passed':False,'owned_token':'disposable-test','owned_output':str(out),
        'owned_pids':[server.pid],'remaining_owned_resources':[str(out/'synthetic-unresolved-mount')],
        'remaining_owned_command_pids':[],'cleanup_errors':['synthetic never resolving cleanup']}
(out/'result.json').write_text(json.dumps(report))
while True:time.sleep(.1)
'''


class Supervisor(unittest.TestCase):
    def test_supervisor_module_is_available(self):
        self.assertIsNotNone(importlib.util.find_spec('macos_supervisor'),'bounded serving-child supervisor is missing')

    def execute(self,state,interrupt=False,seconds=2):
        import macos_supervisor as supervisor
        with tempfile.TemporaryDirectory(prefix='fs0-supervisor-') as folder:
            output=Path(folder)/'native'
            command=[sys.executable,'-c',CHILD,str(output),state]
            timer=None;record=None
            started=time.monotonic()
            try:
                with supervisor.Interrupts() as interrupts:
                    if interrupt:
                        timer=threading.Timer(.4,lambda:os.kill(os.getpid(),signal.SIGINT));timer.start()
                    with self.assertRaises(supervisor.SupervisionFailure) as caught:
                        supervisor.supervise(command,output,seconds=seconds,report_grace=.15,interrupts=interrupts)
                    record=caught.exception.supervision
                self.assertLess(time.monotonic()-started,seconds+1)
                self.assertEqual(record['state'],'failed_pending')
                self.assertEqual(record['command'],command)
                self.assertTrue(record['runner_alive'])
                os.kill(record['runner_pid'],0)
                native=json.loads((output/'result.json').read_text())
                for pid in native['owned_pids']:os.kill(pid,0)
                self.assertEqual(record['native_snapshot']['owned_pids'],native['owned_pids'])
                self.assertEqual(record['remaining_owned_resources'],native['remaining_owned_resources'])
                self.assertTrue(record['recovery_action'])
                self.assertEqual(json.loads(Path(record['evidence']).read_text())['runner_pid'],record['runner_pid'])
                return record
            finally:
                if timer:timer.cancel();timer.join()
                # Explicit test-only cleanup: these are sleep processes, no real mounts.
                if (output/'result.json').exists():
                    for pid in json.loads((output/'result.json').read_text())['owned_pids']:
                        try:os.kill(pid,signal.SIGTERM)
                        except ProcessLookupError:pass
                if record:
                    try:os.kill(record['runner_pid'],signal.SIGTERM)
                    except ProcessLookupError:pass
                    supervisor._retained.pop(record['runner_pid']).wait(timeout=2)

    def test_never_resolving_cleanup_returns_and_preserves_servers(self):
        record=self.execute('cleanup_pending')
        self.assertEqual(record['reason'],'native cleanup pending')

    def test_profile_deadline_does_not_kill_serving_process(self):
        record=self.execute('running',seconds=.5)
        self.assertEqual(record['reason'],'profile deadline exceeded')
        self.assertEqual(record['cleanup_request_signal'],'SIGINT to runner only')

    def test_parent_interrupt_returns_and_preserves_servers(self):
        record=self.execute('running',interrupt=True)
        self.assertEqual(record['reason'],'parent interrupted')
        self.assertEqual(record['parent_interrupts'],1)

    def test_successful_child_is_reaped(self):
        import macos_supervisor as supervisor
        with tempfile.TemporaryDirectory(prefix='fs0-supervisor-') as folder:
            output=Path(folder)/'native'
            code=supervisor.supervise([sys.executable,'-c','pass'],output,seconds=2)
            self.assertEqual(code,0)
            record=json.loads(output.with_name(output.name+'.supervision.json').read_text())
            self.assertFalse(record['runner_alive'])
            self.assertEqual(record['returncode'],0)
