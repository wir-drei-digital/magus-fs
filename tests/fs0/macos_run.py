"""Owned macOS NFS qualification. Never treats mount registration as a pass."""
import argparse
import json
import os
from pathlib import Path
import platform
import selectors
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


def command(args, output, timeout=20):
    with output.open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        try:
            code = process.wait(timeout=timeout)
            return {"command": args, "returncode": code, "log": str(output)}
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return {"command": args, "timeout": True, "pid": process.pid, "kill_pending": True}
            return {"command": args, "timeout": True, "log": str(output)}


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
    live = []
    try:
        source = start(["source", "--root", str(owned.path / "fixture")], "source")
        url = ready(source)
        report.update(source_url=url, source_pid=source.pid, runner_pid=os.getpid())
        with urllib.request.urlopen(url + "/manifest", timeout=5) as response:
            manifest = response.read()
        (owned.path / "manifest.json").write_bytes(manifest)
        for mode in ("ro", "private"):
            path = owned.path / ("mount-" + mode)
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
                while not os.path.ismount(path):
                    time.sleep(1)
            else:
                info["mount_attempt"] = command(info["mount_command"], owned.path / (mode + "-mount.log"))
            if not os.path.ismount(path):
                info["state"] = "blocked"
                save()
                break
            live.append(path)
            with urllib.request.urlopen(url + "/stats", timeout=5) as response:
                info["source_before"] = json.load(response)
            info["ordinary_process"] = command(["python3", str(Path(__file__).with_name("ordinary_io.py")),
                "--mountpoint", str(path), "--mode", mode, "--manifest", str(owned.path / "manifest.json"),
                "--output", str(owned.path / (mode + "-ordinary.json"))], owned.path / (mode + "-ordinary.log"), 45)
            with urllib.request.urlopen(url + "/stats", timeout=5) as response:
                info["source_after"] = json.load(response)
            info["state"] = "passed" if info["ordinary_process"].get("returncode") == 0 else "failed"
            save()
            info["unmount"] = command(["/sbin/umount", str(path)], owned.path / (mode + "-unmount.log"), 5)
            if os.path.ismount(path):
                report["cleanup_errors"].append("owned mount still active: " + str(path))
                save()
                print("Cleanup needs attention; server retained. Exact command: " + shlex.join(["sudo", "/sbin/umount", "-f", str(path)]), flush=True)
                while os.path.ismount(path):
                    time.sleep(1)
                # Retain initial failure evidence even after manual recovery.
                info["manual_cleanup_observed"] = True
            live.remove(path)
            process.terminate()
            process.wait(timeout=5)
            if info["state"] != "passed":
                break
        # No overall qualification until generation/handle/failure and both mode gates pass.
        report["qualification"] = "incomplete: see per-scenario evidence; live-generation and failure gates remain separate"
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = repr(error)
    finally:
        if any(os.path.ismount(path) for path in live):
            report["cleanup_errors"].append("servers retained because owned mounts remain; use recorded exact resources")
            save()
            print("Mount cleanup pending; servers remain available. Report: " + str(report_path), flush=True)
            while any(os.path.ismount(path) for path in live):
                time.sleep(1)
        report["cleanup_errors"].extend(owned.cleanup(remove_output=False))
        save()
    print(str(report_path), flush=True)
    return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    raise SystemExit(run(args.output, args.prepare_only))
