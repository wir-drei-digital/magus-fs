"""Negative authority checks inside a separate root workload container."""
import ctypes
import errno
import os
from pathlib import Path
import socket


def run(source_url):
    assert os.geteuid() == 0
    status = Path('/proc/self/status').read_text()
    caps = {line.split(':')[0]: line.split(':')[1].strip() for line in status.splitlines() if line.startswith(('Cap','NoNewPrivs','Seccomp'))}
    assert int(caps['CapEff'],16) == 2, caps
    assert int(caps['CapBnd'],16) == 2, caps
    assert caps['NoNewPrivs'] == '1', caps
    for path in ['/private/control.json','/private/fixture-normal','/shared','/dev/fuse','/var/run/docker.sock']:
        assert not Path(path).exists(), path
    # Private PID namespace must contain no serving source or daemon process.
    processes = [Path(p).read_bytes() for p in Path('/proc').glob('[0-9]*/cmdline')]
    assert not any(b'magus-fs-probe' in p or b'linux_daemon.py' in p for p in processes), processes
    import urllib.parse
    port = urllib.parse.urlparse(source_url).port
    with socket.socket() as sock:
        sock.settimeout(1)
        assert sock.connect_ex(('127.0.0.1', port)) != 0, 'source reachable'
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.umount2(b'/view', 0) == -1 and ctypes.get_errno() == errno.EPERM
    assert libc.mount(None,b'/view',None,32,None) == -1 and ctypes.get_errno() == errno.EPERM
    assert libc.unshare(0x00020000) == -1 and ctypes.get_errno() == errno.EPERM
    return {'capabilities': caps, 'uid': os.geteuid(), 'source_unreachable': True, 'control_paths_absent': True, 'daemon_pids_absent': True, 'umount_remount_namespace_denied': True, 'mountinfo': Path('/proc/self/mountinfo').read_text()}
