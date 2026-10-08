import os
import platform
import shutil
import subprocess


def check(which=shutil.which):
    required = ["cargo", "rustc", "python3"]
    tools = {name: which(name) for name in required}
    system = platform.system()
    mount = {"status": "unproven", "reason": "real mount qualification required"}
    if system == "Darwin":
        tools["mount_nfs"] = which("mount_nfs")
        mount["adapter"] = "NFS"
    elif system == "Linux":
        tools["fusermount"] = which("fusermount3") or which("fusermount")
        mount.update(adapter="FUSE", device=os.path.exists("/dev/fuse"))
    else:
        mount = {"status": "unsupported", "reason": system}
    missing = [name for name, path in tools.items() if path is None]
    if system == "Linux" and not mount["device"]:
        missing.append("/dev/fuse")
    if system not in ("Darwin", "Linux"):
        missing.append("supported OS")
    versions = {}
    for name in required:
        if tools[name]:
            try:
                result = subprocess.run(
                    [tools[name], "--version"], capture_output=True, text=True,
                    timeout=5, check=True,
                )
                versions[name] = result.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                missing.append(name + " version")
                versions[name] = "unavailable"
    return {
        "system": system, "machine": platform.machine(), "tools": tools,
        "versions": versions, "mount": mount, "missing": missing,
        "exit_code": 2 if missing else 0,
    }
