"""Wire tests against the real CLI endpoint; no kernel mount implied."""
import json
import hashlib
import http.server
import threading
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import tempfile
import unittest
import urllib.request

BIN = Path(__file__).resolve().parents[2] / "target/debug/magus-fs-probe"


def ready(process):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    events = selector.select(15)
    selector.close()
    if not events:
        raise AssertionError("server readiness timeout")
    line = process.stdout.readline()
    if not line:
        raise AssertionError("server exited before readiness: " + process.stderr.read())
    return line.strip()


def words(*values):
    return struct.pack(">" + "I" * len(values), *values)


def opaque(value):
    return words(len(value)) + value + b"\0" * (-len(value) % 4)


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError("unexpected RPC EOF")
        data += part
    return data


class Rpc:
    def __init__(self, port):
        self.port = port
        self.xid = 10

    def call(self, program, procedure, body, uid=501, accepted=0):
        self.xid += 1
        auth = words(0) + opaque(b"fs0-test") + words(uid, 20, 0)
        request = words(self.xid, 0, 2, program, 3, procedure, 1) + opaque(auth) + words(0, 0) + body
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(words(0x80000000 | len(request)) + request)
            response = b""
            while True:
                header = struct.unpack(">I", exact(sock, 4))[0]
                response += exact(sock, header & 0x7fffffff)
                if header & 0x80000000:
                    break
        assert struct.unpack(">6I", response[:24]) == (self.xid, 1, 0, 0, 0, accepted), response.hex()
        return response[24:]

    def mount(self):
        result = self.call(100005, 1, opaque(b"/"))
        assert result[:4] == words(0), result.hex()
        length = struct.unpack(">I", result[4:8])[0]
        return result[8:8 + length]

    def lookup(self, parent, name):
        result = self.call(100003, 3, opaque(parent) + opaque(name))
        assert result[:4] == words(0), result.hex()
        length = struct.unpack(">I", result[4:8])[0]
        return result[8:8 + length]


class NfsWireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magus-fs0-nfs-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.processes = []
        self.addCleanup(self.stop)
        source = self.start("source", "--root", str(self.root / "source"))
        self.url = ready(source)

    def start(self, *args, **kwargs):
        process = subprocess.Popen([str(BIN), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
        self.processes.append(process)
        return process

    def stop(self):
        for process in reversed(self.processes):
            process.terminate()
            process.communicate(timeout=10)

    def endpoint(self, url=None):
        process = self.start("mount", "--backend", "nfs", "--source", url or self.url,
                             "--mountpoint", str(self.root / "mount"), "--mode", "ro", "--prepare-only")
        info = json.loads(ready(process))
        self.assertEqual(info["mode"], "ro")
        self.assertEqual(info["principal_uid"], os.getuid())
        return Rpc(info["port"]), info

    def test_raw_readonly_rpc_and_pinned_identity(self):
        # Catches a writable capability, mutation callback or wrong ID/range mapping.
        rpc, info = self.endpoint()
        with urllib.request.urlopen(self.url + "/manifest") as response:
            manifest = json.load(response)
        self.assertEqual(info["manifest_digest"], manifest["digest"])
        root = rpc.mount()
        handle = rpc.lookup(root, b"instructions.md")
        data = rpc.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 20))
        self.assertEqual(data[:4], words(0))
        self.assertIn(b"Synthetic", data)
        requests = [
            (7, opaque(handle) + struct.pack(">QII", 0, 1, 2) + opaque(b"X")),
            (2, opaque(handle) + words(1, 0o777, 0, 0, 0, 0, 0, 0)),
            (2, opaque(handle) + words(0, 0, 0, 1) + struct.pack(">Q", 0) + words(0, 0, 0)),
            (12, opaque(root) + opaque(b"instructions.md")),
            (14, opaque(root) + opaque(b"instructions.md") + opaque(root) + opaque(b"other")),
        ]
        for uid in (os.getuid(), 0, 12345):
            for procedure, body in requests:
                self.assertEqual(rpc.call(100003, procedure, body, uid)[:4], words(30))
        self.assertEqual(rpc.lookup(root, b".."), root)
        invalid = rpc.call(100003, 3, opaque(root) + opaque(b"../outside"))
        self.assertNotEqual(invalid[:4], words(0))

    def test_private_stable_write_survives_restart(self):
        # Catches a false stable ACK backed only by the ephemeral Probe overlay.
        backing = self.root / "backing"
        def endpoint(name, resume=False):
            args = ["mount", "--backend", "nfs", "--source", self.url,
                    "--mountpoint", str(self.root / name), "--mode", "private", "--backing", str(backing), "--prepare-only"]
            if resume:
                args.append("--resume-backing")
            process = self.start(*args)
            return process, Rpc(json.loads(ready(process))["port"])
        process, rpc = endpoint("private1")
        handle = rpc.lookup(rpc.mount(), b"instructions.md")
        result = rpc.call(100003, 7, opaque(handle) + struct.pack(">QII", 0, 7, 0) + opaque(b"durable"))
        self.assertEqual(result[:4], words(0))
        self.assertEqual(result[-12:-8], words(2))  # FILE_SYNC, followed by verifier
        self.assertTrue((backing / "tree/instructions.md").read_bytes().startswith(b"durable"))
        # A stable write response does not imply the library implements COMMIT.
        self.assertEqual(rpc.call(100003, 21, opaque(handle) + struct.pack(">QI", 0, 0), accepted=3), b"")
        # Native backing mtime must be observable and change with mutations.
        attrs = rpc.call(100003, 1, opaque(handle))
        self.assertNotEqual(attrs[-16:-8], words(0, 0))
        # Unsupported client times must not be silently acknowledged.
        set_time = opaque(handle) + words(0, 0, 0, 0, 0, 2, 123456, 0, 0)
        self.assertEqual(rpc.call(100003, 2, set_time)[:4], words(10004))
        truncate = opaque(handle) + words(0, 0, 0, 1) + struct.pack(">Q", 7) + words(0, 0, 0)
        self.assertEqual(rpc.call(100003, 2, truncate)[:4], words(0))
        self.assertEqual((backing / "tree/instructions.md").read_bytes(), b"durable")
        process.kill()
        process.communicate(timeout=5)
        process, rpc = endpoint("private2", resume=True)
        handle = rpc.lookup(rpc.mount(), b"instructions.md")
        result = rpc.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 7))
        self.assertEqual(result[:4], words(0))
        self.assertIn(b"durable", result)

    def test_pinned_generation_and_parent_traversal(self):
        # An incoming manifest must not retarget IDs in an already connected pinned view.
        with urllib.request.urlopen(self.url + "/manifest") as response:
            original = json.load(response)
        changed = json.loads(json.dumps(original))
        for entry in changed["entries"]:
            if entry["path"] == "nested":
                entry["mode"] = 0
        canonical = ["magus-fs-manifest-v1", changed["chunk_size"], changed["entries"]]
        changed["digest"] = hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
        current = [original]
        source_url = self.url
        class Gateway(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/manifest":
                    data = json.dumps(current[0], separators=(",", ":")).encode()
                else:
                    with urllib.request.urlopen(source_url + self.path, timeout=5) as response:
                        data = response.read()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        gateway = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(gateway.server_close)
        self.addCleanup(gateway.shutdown)
        url = "http://127.0.0.1:" + str(gateway.server_port)
        rpc, info = self.endpoint(url)
        parent = rpc.lookup(rpc.mount(), b"nested")
        handle = rpc.lookup(parent, b"table.csv")
        current[0] = changed
        self.assertNotEqual(info["manifest_digest"], changed["digest"])
        self.assertEqual(rpc.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 20))[:4], words(0))
        # New view sees changed directory mode, including a forged direct child handle.
        process = self.start("mount", "--backend", "nfs", "--source", url, "--mountpoint",
                             str(self.root / "generation2"), "--mode", "ro", "--prepare-only")
        newer = Rpc(json.loads(ready(process))["port"])
        root = newer.mount()
        parent = newer.lookup(root, b"nested")
        denied = newer.call(100003, 3, opaque(parent) + opaque(b"table.csv"))
        self.assertEqual(denied[:4], words(13))
        index = next(i for i, entry in enumerate(changed["entries"]) if entry["path"] == "nested/table.csv") + 2
        forged = root[:-8] + struct.pack(">Q", index)
        self.assertEqual(newer.call(100003, 6, opaque(forged) + struct.pack(">QI", 0, 20))[:4], words(13))
        self.assertEqual(newer.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 20))[:4], words(70))
        _, private = self.private_endpoint("restricted-private", url=url, umask=0o077)
        parent = private.lookup(private.mount(), b"nested")
        self.assertEqual(private.call(100003, 1, opaque(parent))[8:12], words(0))
        self.assertEqual(private.call(100003, 3, opaque(parent) + opaque(b"table.csv"))[:4], words(13))

    def private_endpoint(self, name, url=None, resume=False, **kwargs):
        args = ["mount", "--backend", "nfs", "--source", url or self.url,
                "--mountpoint", str(self.root / name), "--mode", "private",
                "--backing", str(self.root / "backing"), "--prepare-only"]
        if resume:
            args.append("--resume-backing")
        process = self.start(*args, **kwargs)
        return process, Rpc(json.loads(ready(process))["port"])

    def test_private_directory_modes_ignore_umask(self):
        # A shell umask must not change the advertised/authorized manifest modes.
        process, rpc = self.private_endpoint("umask", umask=0o077)
        root = rpc.mount()
        nested = rpc.lookup(root, b"nested")
        for handle in (root, nested):
            attrs = rpc.call(100003, 1, opaque(handle))
            self.assertEqual(attrs[8:12], words(0o755))

    def test_private_chmod_modes_survive_resume(self):
        # Acknowledged metadata must survive restart even when O_RDWR is denied.
        process, rpc = self.private_endpoint("chmod0")
        handle = rpc.lookup(rpc.mount(), b"instructions.md")
        backing = self.root / "backing"
        backing.chmod(0o500)
        try:
            request = opaque(handle) + words(1, 0o444, 0, 0, 0, 0, 0, 0)
            self.assertEqual(rpc.call(100003, 2, request)[:4], words(5))
            self.assertEqual(rpc.call(100003, 1, opaque(handle))[8:12], words(0o644))
        finally:
            backing.chmod(0o700)
        for index, mode in enumerate((0o444, 0o200, 0o000)):
            handle = rpc.lookup(rpc.mount(), b"instructions.md")
            chmod = opaque(handle) + words(1, mode, 0, 0, 0, 0, 0, 0)
            self.assertEqual(rpc.call(100003, 2, chmod)[:4], words(0))
            process.kill()
            process.communicate(timeout=5)
            process, rpc = self.private_endpoint("chmod" + str(index + 1), resume=True)
            handle = rpc.lookup(rpc.mount(), b"instructions.md")
            attrs = rpc.call(100003, 1, opaque(handle))
            self.assertEqual(attrs[8:12], words(mode))
            read = rpc.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 7))
            self.assertEqual(read[:4], words(0 if mode & 0o400 else 13))
            write = rpc.call(100003, 7, opaque(handle) + struct.pack(">QII", 0, 7, 2) + opaque(b"durable"))
            self.assertEqual(write[:4], words(0 if mode & 0o200 else 13))
        # Restore exported access and observe content acknowledged in the write-only round.
        self.assertEqual(rpc.call(100003, 2, opaque(handle) + words(1, 0o644, 0, 0, 0, 0, 0, 0))[:4], words(0))
        self.assertIn(b"durable", rpc.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 7)))
        process.kill()
        process.communicate(timeout=5)
        (backing / "permissions.json").rename(backing / "saved-permissions.json")
        legacy = self.start("mount", "--backend", "nfs", "--source", self.url,
                            "--mountpoint", str(self.root / "legacy"), "--mode", "private",
                            "--backing", str(backing), "--resume-backing", "--prepare-only")
        _, error = legacy.communicate(timeout=10)
        self.assertEqual(legacy.returncode, 2)
        self.assertIn("legacy FS0 backing is unsupported", error)
        self.assertTrue((backing / "tree/instructions.md").read_bytes().startswith(b"durable"))

    def test_fixed_principal_read_denial(self):
        # Raw RPC cannot bypass the fixed actor's mode check, including root credentials.
        source = self.start("source", "--root", str(self.root / "denied"), "--mode", "000")
        rpc, _ = self.endpoint(ready(source))
        handle = rpc.lookup(rpc.mount(), b"instructions.md")
        for uid in (os.getuid(), 0, 12345):
            result = rpc.call(100003, 6, opaque(handle) + struct.pack(">QI", 0, 20), uid)
            self.assertEqual(result[:4], words(13))


if __name__ == "__main__":
    unittest.main()
