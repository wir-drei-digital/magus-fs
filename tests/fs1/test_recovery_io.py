"""Qualification prerequisite failures must stay distinct from tested failures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RUNNER = Path(__file__).with_name("recovery_io.py").resolve()
DAEMON_ERROR = "Cannot connect to the Docker daemon at unix:///synthetic/missing.sock. Is the docker daemon running?"


class RecoveryPrerequisites(unittest.TestCase):
    def run_case(self, failure):
        with tempfile.TemporaryDirectory(prefix="fs1-recovery-prerequisite-") as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(f"#!{sys.executable}\n" +
                "import sys\n" +
                f"failure = {failure!r}\n" +
                "operation = sys.argv[1]\n" +
                "if operation == failure:\n" +
                f"    print({DAEMON_ERROR!r} if failure == 'info' else 'synthetic ' + failure + ' failure', file=sys.stderr)\n" +
                "    sys.exit(1)\n" +
                "print('synthetic healthy prerequisite or container')\n")
            docker.chmod(0o700)
            output = root / "output"
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--platform", "linux", "--image",
                 "synthetic-unavailable", "--output", str(output)],
                env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", "")),
                capture_output=True, text=True, timeout=10)
            report = json.loads((output / "result.json").read_text())
            commands = json.loads((output / "linux/commands.json").read_text())
            cleanup = json.loads((output / "linux/cleanup.json").read_text())
            return result, report, commands, cleanup

    def test_executable_present_daemon_unavailable_is_blocked(self):
        result, report, commands, cleanup = self.run_case("info")
        self.assertEqual(result.returncode, 2, (report, result.stderr))
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual([c["argv"][1] for c in commands], ["info"])
        self.assertEqual(commands[0]["exit"], 1)
        self.assertIn(DAEMON_ERROR, commands[0]["stderr"])
        self.assertEqual(cleanup, [])

    def test_missing_image_is_blocked_before_container_creation(self):
        result, report, commands, cleanup = self.run_case("image")
        self.assertEqual(result.returncode, 2, (report, result.stderr))
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual([c["argv"][1] for c in commands], ["info", "image"])
        self.assertEqual(commands[1]["argv"][2:], ["inspect", "synthetic-unavailable"])
        self.assertEqual(commands[1]["exit"], 1)
        self.assertEqual(cleanup, [])

    def test_setup_failure_after_healthy_prerequisites_remains_failed(self):
        result, report, commands, cleanup = self.run_case("create")
        self.assertEqual(result.returncode, 1, (report, result.stderr))
        self.assertEqual(report["status"], "failed")
        self.assertEqual([c["argv"][1] for c in commands], ["info", "image", "create"])
        self.assertEqual([c["exit"] for c in commands], [0, 0, 1])
        self.assertEqual(cleanup, [])

    def test_execution_failure_after_healthy_prerequisites_remains_failed(self):
        result, report, commands, cleanup = self.run_case("start")
        self.assertEqual(result.returncode, 1, (report, result.stderr))
        self.assertEqual(report["status"], "failed")
        self.assertEqual([c["argv"][1] for c in commands], ["info", "image", "create", "start"])
        self.assertEqual([c["exit"] for c in commands], [0, 0, 0, 1])
        self.assertEqual(len(cleanup), 1)
        self.assertTrue(cleanup[0]["name"].startswith("fs1-recovery-producer-"))
        self.assertEqual(cleanup[0]["exit"], 0)


if __name__ == "__main__":
    unittest.main()
