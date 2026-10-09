"""Synthetic process lifecycle tests. Never invoke mount_nfs or inspect live mounts."""
import ast
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
from types import SimpleNamespace

import macos_run
from resources import OwnedOutput


class MacosLifecycleTests(unittest.TestCase):
    def test_runner_finalization_retains_endpoints_after_unmount_interrupt(self):
        self.exercise_finalization(injected=True)

    def test_runner_finalization_defers_repeated_sigint_until_resources_are_safe(self):
        self.exercise_finalization(injected=False)

    def exercise_finalization(self, injected):
        # Execute the runner's actual finalbody: setup/workloads would require real
        # mounts. Keep its guard, command children, persistence and signals real.
        module = ast.parse(Path(macos_run.__file__).read_text())
        run = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        body = next(n for n in run.body if isinstance(n, ast.Try)).finalbody
        code = compile(ast.Module(body=body, type_ignores=[]), macos_run.__file__, 'exec')
        with tempfile.TemporaryDirectory(prefix='fs0-finalize-') as directory:
            owned = OwnedOutput(str(Path(directory) / 'owned'))
            server = owned.own_process(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']))
            mounted = [True]
            guard = macos_run.MountGuard(owned, lambda path: mounted[0])
            point = owned.path / 'synthetic-mount'
            guard.candidate(point)
            report = {'passed': True, 'cleanup_errors': []}
            saved = []
            unresolved = []
            waiting = []
            gateway_alive = threading.Event()
            gateway_alive.set()
            gateway_stopped = threading.Event()
            gateway_thread = threading.Thread(target=gateway_stopped.wait, daemon=True)
            gateway_thread.start()
            test = self
            class Gateway:
                def shutdown(self):
                    test.assertFalse(mounted[0])
                    test.assertTrue(all(p.poll() is not None for p in guard.attempts))
                    signal.raise_signal(signal.SIGINT)
                    gateway_alive.clear()
                    gateway_stopped.set()
                def server_close(self):
                    pass
            def save():
                result_path = owned.path / 'result.json'
                result_path.write_text(json.dumps(report))
                saved.append(json.loads(result_path.read_text()))
                if report.get('state') == 'cleanup_pending':
                    signal.raise_signal(signal.SIGINT)
            def unmount(item):
                child = owned.own_process(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']))
                guard.track(child)
                unresolved.append(child)
                if injected:
                    raise KeyboardInterrupt()
                macos_run.command([sys.executable, '-c',
                    'import os,signal; os.kill(os.getppid(),signal.SIGINT)'],
                    owned.path / 'interrupt.log', owned=owned, guard=guard)
                raise RuntimeError('synthetic unmount remains unresolved')
            def wait(seconds):
                self.assertIsNone(server.poll(), 'serving process stopped before resolution')
                self.assertTrue(gateway_alive.is_set() and gateway_thread.is_alive())
                pending = saved[-1]
                self.assertEqual(pending.get('state'), 'cleanup_pending')
                self.assertIn(unresolved[0].pid, pending['remaining_owned_command_pids'])
                if not waiting:
                    self.assertIn(str(point), pending['remaining_owned_resources'])
                    mounted[0] = False
                else:
                    unresolved[0].kill()
                    unresolved[0].wait(timeout=5)
                waiting.append(True)
                signal.raise_signal(signal.SIGINT)
            env = dict(vars(macos_run), guard=guard, endpoints=[{'path':point}],
                       mount_state=lambda path: mounted[0], unmount=unmount,
                       report=report, report_path=owned.path/'result.json', save=save,
                       gateway=Gateway(), gateway_thread=gateway_thread, processes=[server],
                       time=SimpleNamespace(sleep=wait))
            previous = signal.getsignal(signal.SIGINT)
            try:
                try:
                    exec(code, env)
                except KeyboardInterrupt:
                    self.fail('runner finalization escaped while an owned mount/source was unresolved')
                self.assertEqual(signal.getsignal(signal.SIGINT), previous)
                self.assertEqual(len(waiting), 2, 'must wait for both mount absence and child settlement')
                self.assertFalse(gateway_alive.is_set())
                self.assertIsNotNone(server.poll())
                self.assertFalse(report['passed'])
                self.assertEqual(report['remaining_owned_resources'], [])
                self.assertEqual(report['remaining_owned_command_pids'], [])
                self.assertGreaterEqual(report['cleanup_interrupts'], 3)
                self.assertEqual(saved[-1]['state'], 'failed')
            finally:
                signal.signal(signal.SIGINT, previous)
                gateway_stopped.set()
                gateway_thread.join(timeout=5)
                owned.cleanup(remove_output=False)

    def test_interrupted_command_reaps_its_child(self):
        with tempfile.TemporaryDirectory(prefix="fs0-interrupt-") as directory:
            path = Path(directory)
            marker = path / "child.pid"
            child_pid = []
            def interrupt_when_started():
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if marker.exists() and marker.read_text():
                        child_pid.append(int(marker.read_text()))
                        os.kill(os.getpid(), signal.SIGINT)
                        return
                    time.sleep(0.01)
            sender = threading.Thread(target=interrupt_when_started)
            sender.start()
            code = "import os,time,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
            try:
                with self.assertRaises(KeyboardInterrupt):
                    macos_run.command([sys.executable, "-c", code, str(marker)], path / "log")
                sender.join(timeout=6)
                self.assertTrue(child_pid, "synthetic child never started")
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid[0], 0)
            finally:
                sender.join(timeout=6)
                if child_pid:
                    try:
                        os.kill(child_pid[0], signal.SIGKILL)
                        os.waitpid(child_pid[0], 0)
                    except (ProcessLookupError, ChildProcessError):
                        pass

    def test_unresolved_attempt_and_status_retain_servers(self):
        with tempfile.TemporaryDirectory(prefix="fs0-guard-") as directory:
            owned = OwnedOutput(str(Path(directory) / "owned"))
            server = owned.own_process(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]))
            child = owned.own_process(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]))
            state = [False]
            guard = macos_run.MountGuard(owned, lambda path: state[0])
            guard.candidate(owned.path / "mount")
            guard.track(child)
            try:
                self.assertFalse(guard.cleanup(), "unresolved command must retain servers even before mount appears")
                self.assertIsNone(server.poll())
                child.kill()
                child.wait(timeout=5)
                state[0] = None
                self.assertFalse(guard.cleanup(), "unresolved mount status must retain servers")
                self.assertIsNone(server.poll())
                state[0] = True
                self.assertFalse(guard.cleanup(), "mounted path must retain servers")
                self.assertIsNone(server.poll())
                state[0] = False
                self.assertTrue(guard.cleanup())
                self.assertIsNotNone(server.poll())
            finally:
                owned.cleanup(remove_output=False)

    def test_candidate_is_tracked_before_command_launch(self):
        with tempfile.TemporaryDirectory(prefix="fs0-command-") as directory:
            owned = OwnedOutput(str(Path(directory) / "owned"))
            guard = macos_run.MountGuard(owned, lambda path: False)
            path = owned.path / "mount"
            result = macos_run.command([sys.executable, "-c", "raise SystemExit(7)"], owned.path / "log", owned=owned, guard=guard, mountpoint=path)
            self.assertEqual(result["returncode"], 7)
            self.assertIn(path, guard.paths)
            self.assertEqual(len(owned.processes), 1)
            self.assertIsNotNone(owned.processes[0].poll())
            self.assertTrue(guard.cleanup())


if __name__ == "__main__":
    unittest.main()
