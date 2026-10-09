"""Ordinary-process syscall evidence. A real mount is mandatory."""
import argparse
import errno
import fcntl
import json
import mmap
import os
from pathlib import Path
import stat
import subprocess
import sys
from lock_io import contend


def expected(offset, length):
    result = bytearray((i * 31 + i // 4096) % 251 for i in range(offset, offset + length))
    for n in range(length):
        position = offset + n
        if position % 65536 < 8:
            result[n] = ((position // 65536) >> (8 * (position % 65536))) & 255
    return bytes(result)


def run(path, mode, manifest):
    path = Path(path)
    result = {}
    if not os.path.ismount(path):
        return {"mount": {"state": "blocked", "detail": "path is not an actual mounted filesystem"}}
    result["mount"] = {"state": "passed", "device": os.stat(path).st_dev}

    def case(name, action):
        try:
            detail = action()
            result[name] = {"state": "passed", "detail": detail}
        except Exception as error:
            result[name] = {"state": "failed", "detail": repr(error), "errno": getattr(error, "errno", None)}

    def metadata():
        names = sorted(entry.name for entry in path.iterdir())
        assert names == ["data.bin", "empty", "instructions.md", "nested", "run.sh"], names
        assert sorted(x.name for x in (path / "nested").iterdir()) == ["table.csv"]
        values = []
        for entry in manifest["entries"]:
            info = (path / entry["path"]).stat()
            observed = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
            assert observed == [entry["uid"], entry["gid"], entry["mode"]], (entry, observed)
            values.append({"path": entry["path"], "uid_gid_mode": observed})
        assert (path / "nested/../instructions.md").read_bytes().startswith(b"# Synthetic")
        return values

    def ranges():
        with (path / "data.bin").open("rb", buffering=0) as handle:
            for offset, length in [(0, 17), (65530, 20), (67108864 - 19, 19)]:
                assert os.pread(handle.fileno(), length, offset) == expected(offset, length)
            assert os.pread(handle.fileno(), 10, 67108864) == b""
        return "pread header, cross-boundary, tail, EOF"

    def mapped():
        with (path / "data.bin").open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                assert view[0:17] == expected(0, 17)
                assert view[-19:] == expected(67108864 - 19, 19)
        return "mmap ACCESS_READ header/tail"

    def denied(action):
        try:
            action()
        except OSError as error:
            assert error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), error
            return {"errno": error.errno, "message": str(error)}
        raise AssertionError("mutation unexpectedly succeeded")

    case("metadata_permissions", metadata)
    case("range_reads", ranges)
    case("warm_repeat", ranges)
    case("mmap_read", mapped)
    file = path / "instructions.md"
    if mode == "ro":
        case("readonly_write", lambda: denied(lambda: file.write_bytes(b"bad")))
        case("readonly_truncate", lambda: denied(lambda: os.truncate(file, 0)))
        case("readonly_chmod", lambda: denied(lambda: os.chmod(file, 0o777)))
        case("readonly_unlink", lambda: denied(file.unlink))
        case("readonly_rename", lambda: denied(lambda: os.rename(file, path / "renamed")))
        case("readonly_create", lambda: denied(lambda: (path / "new").write_bytes(b"bad")))
    else:
        def writes():
            with file.open("r+b", buffering=0) as handle:
                old = handle.read()
                handle.seek(0)
                handle.write(b"private")
                os.fsync(handle.fileno())
                assert os.pread(handle.fileno(), 7, 0) == b"private"
                handle.seek(0)
                handle.write(old)
                handle.truncate(len(old))
                os.fsync(handle.fileno())
            return "write, fsync, pread, restore, truncate, fsync"
        case("private_writes", writes)
        def replacement():
            with file.open("rb", buffering=0) as old_handle:
                old = old_handle.read()
                temp = path / "replacement.tmp"
                temp.write_bytes(b"replacement")
                os.replace(temp, file)
                assert file.read_bytes() == b"replacement"
                old_handle.seek(0)
                assert old_handle.read() == old
                file.write_bytes(old)
            return "replace preserves old open handle"
        case("rename_replacement_old_handle", replacement)

    def locks():
        with file.open("rb") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observation = contend(file)
            fcntl.flock(handle, fcntl.LOCK_UN)
            return observation
    case("locks_observation", locks)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mountpoint", required=True)
    parser.add_argument("--mode", choices=("ro", "private"), required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run(args.mountpoint, args.mode, json.loads(Path(args.manifest).read_text()))
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    sys.exit(0 if all(case["state"] == "passed" for case in report.values()) else 2)
