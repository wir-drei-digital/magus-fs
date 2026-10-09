"""Linux FUSE syscall cases; run only against an actual synthetic mount."""
import argparse
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from ordinary_io import run as ordinary, expected
from lock_io import contend


def run(path, mode, manifest):
    path = Path(path)
    if not os.path.ismount(path):
        return {'mount': {'state': 'blocked', 'detail': 'real mount missing'}}
    if mode == 'ro':
        result = ordinary(path, mode, manifest)
        if result.get('locks_observation', {}).get('state') == 'passed':
            result['locks_observation']['detail']['scope'] = 'one Linux kernel; no distributed lock guarantee'
    else:
        # NFS durability/replacement expectations intentionally remain unchanged.
        result = {'mount': {'state': 'passed', 'device': path.stat().st_dev}}
    def case(name, action):
        try:
            result[name] = {'state': 'passed', 'detail': action()}
        except Exception as error:
            result[name] = {'state': 'failed', 'errno': getattr(error, 'errno', None), 'detail': repr(error)}
    def denied(action, allowed=(errno.EROFS, errno.EACCES, errno.EPERM)):
        try:
            action()
        except OSError as error:
            assert error.errno in allowed, error
            return {'errno': error.errno}
        raise AssertionError('operation unexpectedly succeeded')
    file = path / 'instructions.md'
    if mode == 'ro':
        for name, action in [
            ('mkdir', lambda: (path / 'new-dir').mkdir()),
            ('rmdir', lambda: (path / 'nested').rmdir()),
            ('chown', lambda: os.chown(file, 1234, 1234)),
            ('utime', lambda: os.utime(file, (1, 1))),
            ('symlink', lambda: os.symlink('instructions.md', path / 'link')),
            ('hardlink', lambda: os.link(file, path / 'hardlink')),
            ('xattr', lambda: os.setxattr(file, 'user.fs0', b'bad')),
            ('mknod', lambda: os.mknod(path / 'node', 0o600)),
        ]:
            case('readonly_' + name, lambda action=action: denied(action))
        def unchanged():
            assert file.read_bytes() == b'# Synthetic workspace\nUse relative paths.\n'
            assert sorted(x.name for x in path.iterdir()) == ['data.bin', 'empty', 'instructions.md', 'nested', 'run.sh']
            return 'content and namespace preserved'
        case('readonly_unchanged', unchanged)
    else:
        def private():
            with file.open('r+b', buffering=0) as handle, file.open('rb', buffering=0) as peer:
                old = handle.read()
                handle.seek(0)
                assert handle.write(b'private') == 7
                assert os.pread(handle.fileno(), 7, 0) == b'private'
                assert os.pread(peer.fileno(), 7, 0) == b'private'
                durability = denied(lambda: os.fsync(handle.fileno()), (errno.EOPNOTSUPP, errno.ENOSYS))
                handle.seek(0)
                handle.write(old)
                assert file.read_bytes() == old
            return {'same_open_and_peer_visible': True, 'durability_explicitly_unsupported': durability}
        case('private_writes', private)
        case('rename_classification', lambda: denied(lambda: os.rename(path / 'nested/table.csv', path / 'nested/renamed'), (errno.EOPNOTSUPP, errno.ENOSYS)))
        case('create_classification', lambda: denied(lambda: (path / 'nested/new').write_bytes(b'x'), (errno.EOPNOTSUPP, errno.ENOSYS)))
        case('truncate_classification', lambda: denied(lambda: os.truncate(file, 0), (errno.EOPNOTSUPP, errno.ENOSYS)))
        case('chmod_classification', lambda: denied(lambda: os.chmod(file, 0o777), (errno.EOPNOTSUPP, errno.ENOSYS)))
        for name in ['rename_classification','create_classification','truncate_classification','chmod_classification']:
            result[name]['observed_support'] = ('unsupported; the denial classification assertion passed' if result[name]['state'] == 'passed' else 'not established; classification failed')
        def mapped():
            import mmap
            with (path / 'data.bin').open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                assert view[0:17] == expected(0, 17)
                assert view[-19:] == expected(67108864 - 19, 19)
            return 'read mmap works; no live generation mutation API in pinned FS0'
        case('mmap_read', mapped)
        def mapped_private_visibility():
            import mmap
            with file.open('rb') as reader, mmap.mmap(reader.fileno(), 0, access=mmap.ACCESS_READ) as view, file.open('r+b', buffering=0) as writer:
                old = view[:]
                writer.write(b'mapped!')
                assert view[:7] == b'mapped!'
                assert file.read_bytes()[:7] == b'mapped!'
                writer.seek(0)
                writer.write(old)
                assert view[:] == old
            return 'existing mmap, old descriptor and reopened file see private byte changes; kernel write visibility only'
        case('mmap_private_visibility', mapped_private_visibility)
        def extension():
            empty = path / 'empty'
            with empty.open('r+b', buffering=0) as handle:
                assert os.pwrite(handle.fileno(), b'gap', 3) == 3
                assert os.pread(handle.fileno(), 20, 0) == b'\0\0\0gap'
                assert empty.stat().st_size == 6
            assert empty.read_bytes() == b'\0\0\0gap'
            return 'bounded sparse extension metadata and reopen match; ephemeral only'
        case('private_extension', extension)
        def locks():
            import fcntl
            with file.open('rb') as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return contend(file)
        case('locks_observation', locks)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--mountpoint', required=True)
    p.add_argument('--mode', choices=('ro','private'), required=True)
    p.add_argument('--manifest', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    report = run(a.mountpoint, a.mode, json.loads(Path(a.manifest).read_text()))
    Path(a.output).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(0 if all(x['state'] == 'passed' for x in report.values()) else 2)
