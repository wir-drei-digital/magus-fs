"""Ordinary macOS syscalls against owned mounts; explicit FS0 characterization."""
import argparse
import errno
import json
import mmap
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

from ordinary_io import expected, run as ordinary
from measurement_io import scan

ORIGINAL = b'# Synthetic workspace\nUse relative paths.\n'


def denied(action, allowed=(errno.EACCES, errno.EPERM)):
    try:
        action()
    except OSError as error:
        assert error.errno in allowed, error
        return {'errno': error.errno}
    raise AssertionError('operation unexpectedly succeeded')


def require_unsupported(action):
    return dict(denied(action, (errno.EROFS, errno.EOPNOTSUPP, errno.ENOSYS)),
                observed_support='unsupported; only the denial characterization passed')


def run(case, path, manifest, extra):
    path = Path(path)
    assert os.path.ismount(path), 'ordinary syscall proof requires an actual mount'
    file = path / 'instructions.md'
    if case == 'warm-file':
        assert file.read_bytes()==ORIGINAL
        return {'exact_tiny_file':True}
    if case == 'enumeration':
        names = sorted(os.listdir(path))
        assert names == ['data.bin','empty','instructions.md','nested','run.sh'], names
        return names
    if case == 'partial':
        with (path / 'data.bin').open('rb', buffering=0) as handle:
            for offset in (0, 67108864 - 4096):
                assert os.pread(handle.fileno(),4096,offset) == expected(offset,4096)
        return {'exact_head_tail': True}
    if case == 'full':
        return scan(path / 'data.bin',extra['digest'])
    if case in ('ro','private'):
        result = ordinary(path,case,manifest)
        root = path.stat()
        result['root_metadata'] = {'state':'passed','detail':{'uid':root.st_uid,'gid':root.st_gid,'mode':stat.S_IMODE(root.st_mode),'scope':'daemon-mapped root; outside manifest digest'}}
        if case == 'private':
            # The shared helper's replacement scenario first attempts unsupported CREATE.
            replacement = result['rename_replacement_old_handle']
            assert replacement['state'] == 'failed' and replacement['errno'] == errno.EROFS, replacement
            replacement.update(state='passed', observed_support='unsupported CREATE; replacement was not performed')
            with file.open('rb',buffering=0) as old:
                before = old.read()
                result['rename_existing_classification'] = require_unsupported(lambda: os.replace(path/'nested/table.csv',file))
                assert os.pread(old.fileno(),len(before),0) == before and file.read_bytes() == before
            # Exercise visibility through already-open descriptors and mmap before restoring.
            with file.open('rb') as reader, mmap.mmap(reader.fileno(),0,access=mmap.ACCESS_READ) as view, file.open('r+b',buffering=0) as writer:
                before = view[:]
                assert os.pwrite(writer.fileno(),b'mapped!',0) == 7
                os.fsync(writer.fileno())
                assert view[:7] == b'mapped!' and file.read_bytes()[:7] == b'mapped!'
                os.pwrite(writer.fileno(),before,0)
                os.fsync(writer.fileno())
                assert view[:] == before
            script=path/'run.sh'
            os.chmod(script,0o644)
            result['private_execute0644_denied']=denied(lambda:subprocess.run([str(script)],capture_output=True,timeout=5))
            os.chmod(script,0o755)
            direct=subprocess.run([str(script)],capture_output=True,text=True,timeout=5)
            assert direct.returncode==0 and direct.stdout=='synthetic\n',direct
            result['private_execute0755']={'state':'passed','stdout':direct.stdout}
            result['old_handle_mmap_visibility'] = {'state':'passed','detail':'same kernel private byte writes visible; no replacement generation guarantee'}
        assert all(item.get('state','passed') == 'passed' for item in result.values()), result
        return result
    if case == 'subprocess':
        args = ['/bin/sh', str(path/'run.sh')]
        child = subprocess.run(args,capture_output=True,text=True,timeout=5)
        assert child.returncode == 0 and child.stdout == 'synthetic\n' and not child.stderr, child
        direct = subprocess.run([str(path/'run.sh')],capture_output=True,text=True,timeout=5)
        assert direct.returncode == 0 and direct.stdout == 'synthetic\n' and not direct.stderr, direct
        return {'interpreter_command':args,'output':child.stdout,'direct_execute':{'supported':True,'stdout':direct.stdout}}
    if case == 'permissions':
        kind = extra['kind']
        if kind in ('group','other'):
            assert file.read_bytes() == ORIGINAL
            expected_mode = 0o040 if kind == 'group' else 0o004
            info=file.stat()
            assert stat.S_IMODE(info.st_mode)==expected_mode
            return {'read_via_'+kind:True,'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
        if kind == 'file644':
            return {'direct_execute_denied':denied(lambda:subprocess.run([str(path/'run.sh')],capture_output=True,timeout=5))}
        if kind == 'file000':
            assert stat.S_IMODE(file.stat().st_mode)==0
            return {'read_denied':denied(file.read_bytes)}
        nested=path/'nested'
        if kind == 'directory400':
            assert os.listdir(nested)==['table.csv']
            return {'names_readable_without_search':True,'child_read_denied':denied((nested/'table.csv').read_bytes),
                    'child_stat_denied':denied(lambda: (nested/'table.csv').stat())}
        if kind == 'directory100':
            listing=denied(lambda: os.listdir(nested))
            assert (nested/'table.csv').read_bytes()==b'id,value\n1,synthetic\n'
            return {'listing_denied':listing,'search_without_listing':True}
        if kind == 'directory000':
            return {'listing_denied':denied(lambda:os.listdir(nested)), 'child_read_denied':denied((nested/'table.csv').read_bytes)}
        raise ValueError(kind)
    if case == 'persist':
        with file.open('r+b',buffering=0) as handle:
            assert os.pwrite(handle.fileno(),b'durable',0)==7
            os.fsync(handle.fileno())
            assert os.pread(handle.fileno(),7,0)==b'durable'
        os.chmod(file,0o444)
        assert stat.S_IMODE(file.stat().st_mode)==0o444
        return {'native_fsync_returned':True,'durable_prefix':'durable','mode':0o444}
    if case == 'resumed':
        assert file.read_bytes()==b'durable'+ORIGINAL[7:]
        assert stat.S_IMODE(file.stat().st_mode)==0o444
        return {'native_remount_data_and_chmod_preserved':True,'write_open_denied':denied(lambda:os.open(file,os.O_WRONLY)),'process_restart_only':'not power-cut proof'}
    if case == 'fault':
        assert file.read_bytes()==ORIGINAL
        result=denied(lambda:(path/'data.bin').read_bytes(),(errno.EIO,))
        return {'warmed_file_survives_source_failure':True,'uncached_read':result}
    if case == 'generation':
        signal=Path(extra['signal'])
        with file.open('rb',buffering=0) as handle, mmap.mmap(handle.fileno(),0,access=mmap.ACCESS_READ) as view:
            assert handle.read()==ORIGINAL and stat.S_IMODE(file.stat().st_mode)==0o644
            print('ready',flush=True)
            deadline=time.monotonic()+25
            while not signal.exists():
                if time.monotonic()>deadline: raise TimeoutError('generation publication signal')
                time.sleep(0.05)
            fresh=Path(signal.read_text())/'instructions.md'
            assert stat.S_IMODE(fresh.stat().st_mode)==0o640 and fresh.read_bytes()==ORIGINAL
            assert os.pread(handle.fileno(),42,0)==ORIGINAL and view[:]==ORIGINAL
            # Observe beyond the controlled TTL; existing mount stays pinned deliberately.
            time.sleep(1.1)
            assert stat.S_IMODE(file.stat().st_mode)==0o644 and file.read_bytes()==ORIGINAL
        return {'old_open_and_mmap_pinned':True,'fresh_generation_mode':0o640,'old_mode_after_ttl':0o644,
                'in_place_invalidation':'unsupported: no generation publication API'}
    raise ValueError(case)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--case',required=True)
    parser.add_argument('--mountpoint',required=True)
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--extra',default='{}')
    args=parser.parse_args()
    try:
        result={'state':'passed','observed':run(args.case,args.mountpoint,json.loads(Path(args.manifest).read_text()),json.loads(args.extra))}
    except Exception as error:
        result={'state':'failed','error':repr(error),'errno':getattr(error,'errno',None)}
    print(json.dumps(result),flush=True)
    raise SystemExit(0 if result['state']=='passed' else 1)
