"""Owned macOS NFS qualification. Never treats mount registration as a pass."""
import argparse
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import shlex
import subprocess
import time
import urllib.request

from resources import OwnedOutput

BINARY = Path(__file__).resolve().parents[2] / "target/debug/magus-fs-probe"


def ready(process, seconds=30):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    event = selector.select(seconds)
    selector.close()
    if not event:
        raise RuntimeError("server readiness timeout")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("server exited before readiness; inspect stderr file")
    return line.strip()


def mount_state(path):
    """Read the OS mount table without issuing stat into a possibly stalled mount."""
    try:
        result = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=3)
        if result.returncode != 0:
            return None
        return any(" on " + str(path) + " (" in line for line in result.stdout.splitlines())
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        return None


class MountGuard:
    def __init__(self, owned, query=mount_state):
        self.owned = owned
        self.query = query
        self.paths = []
        self.attempts = []
        self.cleanup_errors = []

    def candidate(self, path):
        if path not in self.paths:
            self.paths.append(path)

    def track(self, process):
        self.attempts.append(process)

    def safe(self):
        if any(process.poll() is None for process in self.attempts):
            return False
        try:
            return all(self.query(path) is False for path in self.paths)
        except (Exception, KeyboardInterrupt):
            return False

    def cleanup(self):
        if not self.safe():
            return False
        self.cleanup_errors = self.owned.cleanup(remove_output=False)
        return True


def settle(process):
    """Bounded stop/reap; an unresolved process remains in the guard registry."""
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        return True
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        return False


def command(args, output, timeout=20, *, owned=None, guard=None, mountpoint=None):
    if mountpoint is not None:
        if guard is None:
            raise ValueError("mount command requires a guard")
        # Track before launching: interruption may happen before mount_nfs returns.
        guard.candidate(mountpoint)
    process = None
    with output.open("w") as log:
        try:
            # Avoid the Popen -> registration SIGINT window. Unblocking below may
            # immediately interrupt; the outer handler still owns/reaps the child.
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
                if owned is not None:
                    owned.own_process(process)
                if guard is not None:
                    guard.track(process)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            code = process.wait(timeout=timeout)
            return {"command": args, "pid": process.pid, "returncode": code, "log": str(output)}
        except subprocess.TimeoutExpired:
            reaped = settle(process)
            return {"command": args, "timeout": True, "pid": process.pid, "kill_pending": not reaped, "log": str(output)}
        except BaseException:
            if process is not None:
                settle(process)
            raise


def run(output, prepare_only):
    if platform.system() != "Darwin":
        raise RuntimeError("macOS runner requires Darwin")
    owned = OwnedOutput(output)
    report = {"passed": False, "platform": platform.platform(), "owned_output": str(owned.path), "mounts": [], "cleanup_errors": []}
    report_path = owned.path / "report.json"
    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    def start(args, name):
        log = (owned.path / (name + ".stderr")).open("w")
        process = owned.own_process(subprocess.Popen([str(BINARY), *args], stdout=subprocess.PIPE, stderr=log, text=True))
        log.close()
        return process
    guard = MountGuard(owned)
    try:
        source = start(["source", "--root", str(owned.path / "fixture")], "source")
        url = ready(source)
        report.update(source_url=url, source_pid=source.pid, runner_pid=os.getpid())
        with urllib.request.urlopen(url + "/manifest", timeout=5) as response:
            manifest = response.read()
        (owned.path / "manifest.json").write_bytes(manifest)
        for mode in ("ro", "private"):
            path = owned.path / ("mount-" + mode)
            guard.candidate(path)
            args = ["mount", "--backend", "nfs", "--source", url, "--mountpoint", str(path), "--mode", mode, "--prepare-only"]
            if mode == "private":
                args += ["--backing", str(owned.path / "backing")]
            process = start(args, mode)
            info = json.loads(ready(process))
            report["mounts"].append(info)
            save()
            print(json.dumps(info), flush=True)
            if prepare_only:
                # Human can inspect exact path, process and command before mounting.
                print("Ready; run: " + shlex.join(info["mount_command"]), flush=True)
                while mount_state(path) is not True:
                    time.sleep(1)
            else:
                info["mount_attempt"] = command(info["mount_command"], owned.path / (mode + "-mount.log"), owned=owned, guard=guard, mountpoint=path)
            if mount_state(path) is not True:
                info["state"] = "blocked"
                save()
                break
            with urllib.request.urlopen(url + "/stats", timeout=5) as response:
                info["source_before"] = json.load(response)
            info["ordinary_process"] = command(["python3", str(Path(__file__).with_name("ordinary_io.py")),
                "--mountpoint", str(path), "--mode", mode, "--manifest", str(owned.path / "manifest.json"),
                "--output", str(owned.path / (mode + "-ordinary.json"))], owned.path / (mode + "-ordinary.log"), 45, owned=owned, guard=guard)
            with urllib.request.urlopen(url + "/stats", timeout=5) as response:
                info["source_after"] = json.load(response)
            info["state"] = "passed" if info["ordinary_process"].get("returncode") == 0 else "failed"
            save()
            info["unmount"] = command(["/sbin/umount", str(path)], owned.path / (mode + "-unmount.log"), 5, owned=owned, guard=guard)
            if not guard.safe():
                report["cleanup_errors"].append("owned mount/command unresolved: " + str(path))
                save()
                print("Cleanup needs attention; server retained. Exact command: " + shlex.join(["sudo", "/sbin/umount", "-f", str(path)]), flush=True)
                break
            process.terminate()
            process.wait(timeout=5)
            if info["state"] != "passed":
                break
        # No overall qualification until generation/handle/failure and both mode gates pass.
        report["qualification"] = "incomplete: see per-scenario evidence; live-generation and failure gates remain separate"
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = repr(error)
    finally:
        if not guard.cleanup():
            report["cleanup_errors"].append("servers retained: candidate mount, status or command unresolved")
            report["candidate_mountpoints"] = [str(path) for path in guard.paths]
            report["command_pids"] = [process.pid for process in guard.attempts]
            save()
            print("Cleanup pending; servers remain available. Report: " + str(report_path), flush=True)
            while not guard.cleanup():
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    # Repeated interruption cannot bypass the mount safety guard.
                    continue
        report["cleanup_errors"].extend(guard.cleanup_errors)
        save()
    print(str(report_path), flush=True)
    return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    raise SystemExit(run(args.output, args.prepare_only))
