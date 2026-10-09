"""Synthetic process lifecycle tests. Never invoke mount_nfs or inspect live mounts."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import macos_run
from resources import OwnedOutput


class MacosLifecycleTests(unittest.TestCase):
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
