"""Ordinary native file APIs: durability adapter regressions, independent expected bytes."""
import errno, fcntl, hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path
ROOT=Path('/view')
def expected(offset, length):
    # Fixture producer uses sha256(counter); independently reconstruct only needed blocks.
    first=offset//32; end=(offset+length+31)//32
    return b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(first,end))[offset%32:offset%32+length]
def denied(fn, codes):
    try: fn()
    except OSError as e:
        assert e.errno in codes, (e.errno,codes)
        return e.errno
    raise AssertionError('operation unexpectedly succeeded')
def run(case):
    r={}
    if case=='metadata':
        assert 'large' in os.listdir(ROOT)
        for p in [ROOT,ROOT/'large',ROOT/'empty']:
            s=p.stat(); assert (s.st_uid,s.st_gid)==(1001,1001)
        assert stat.S_IMODE(ROOT.stat().st_mode)==0o755
        assert stat.S_IMODE((ROOT/'large').stat().st_mode)==0o644
        return {'root_entry_mapping':True,'names':os.listdir(ROOT)}
    if case=='partial':
        with open(ROOT/'large','rb',buffering=0) as f:
            for off in [0,67108864-4096]: assert os.pread(f.fileno(),4096,off)==expected(off,4096)
        return {'header_tail':4096}
    if case=='full':
        digest=hashlib.sha256()
        with open(ROOT/'large','rb') as f:
            while b:=f.read(1024*1024): digest.update(b)
        return {'sha256':digest.hexdigest(),'size':(ROOT/'large').stat().st_size}
    if case=='writes':
        p=ROOT/'new'; fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o666)
        assert stat.S_IMODE(os.fstat(fd).st_mode)==0o644
        assert os.write(fd,b'abc')==3; os.fsync(fd)
        a=os.open(p,os.O_WRONLY|os.O_APPEND); os.write(a,b'de'); os.close(a)
        os.ftruncate(fd,9); assert os.pread(fd,20,0)==b'abcde\0\0\0\0'
        os.pwrite(fd,b'Z',8); os.fsync(fd)
        assert os.pread(fd,20,0)==b'abcde\0\0\0Z'
        os.unlink(p); assert os.fstat(fd).st_size==9; assert os.pread(fd,20,0)==b'abcde\0\0\0Z'
        os.pwrite(fd,b'OLD',0); assert not p.exists()
        p.write_bytes(b'replacement'); assert os.pread(fd,3,0)==b'OLD'
        os.close(fd)
        old=os.open(p,os.O_RDWR); q=ROOT/'atomic';q.write_bytes(b'new generation');os.replace(q,p)
        assert os.pread(old,99,0)==b'replacement';os.pwrite(old,b'OLD',0)
        assert p.read_bytes()==b'new generation';os.close(old)
        d=ROOT/'made';d.mkdir(mode=0o777);assert stat.S_IMODE(d.stat().st_mode)==0o755
        (d/'child').write_bytes(b'child');os.rename(d,ROOT/'moved');assert (ROOT/'moved/child').read_bytes()==b'child'
        (ROOT/'moved/child').unlink();(ROOT/'moved').rmdir()
        os.chmod(p,0o640);assert stat.S_IMODE(p.stat().st_mode)==0o640
        os.chown(p,1001,1001);assert p.stat().st_uid==1001
        with open(p,'rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            code="import fcntl,sys; f=open(sys.argv[1],'rb');\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(0)\nelse: sys.exit(7)"
            assert subprocess.run([sys.executable,'-c',code,str(p)],timeout=3).returncode==0
        with open(p,'r+b') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(f,fcntl.LOCK_UN)
            r['advanced_lock']=denied(lambda:fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB),[errno.EOPNOTSUPP])
        r['links']=denied(lambda:os.link(p,ROOT/'hard'),[errno.EOPNOTSUPP])
        r['symlink']=denied(lambda:os.symlink('new',ROOT/'sym'),[errno.EOPNOTSUPP])
        r['xattr']=denied(lambda:os.setxattr(p,'user.test',b'x'),[errno.EOPNOTSUPP])
        return {**r,'append_sparse_unlink_replace_mkdir_rename_modes_fsync_flock':True}
    if case=='offline':
        with open(ROOT/'large','rb',buffering=0) as f: assert os.pread(f.fileno(),4096,0)==expected(0,4096)
        start=time.monotonic()
        r['uncached_errno']=denied(lambda:(ROOT/'uncached').read_bytes(),[errno.EIO,errno.ENETDOWN])
        r['uncached_seconds']=time.monotonic()-start;assert r['uncached_seconds']<5
        with open(ROOT/'uncached','wb',buffering=0) as f: f.write(b'full offline replacement');os.fsync(f.fileno())
        with open(ROOT/'offline-new','wb',buffering=0) as f: f.write(b'ACK survives daemon loss');os.fsync(f.fileno())
        return r
    if case=='recovered':
        assert (ROOT/'offline-new').read_bytes()==b'ACK survives daemon loss'
        assert (ROOT/'uncached').read_bytes()==b'full offline replacement'
        assert (ROOT/'new').read_bytes()==b'new generation'
        return {'every_ack_verified':True}
    if case=='diskfull':
        fd=os.open(ROOT/'large',os.O_WRONLY)
        try: r['errno']=denied(lambda:os.pwrite(fd,b'diskfull-change',0),[errno.ENOSPC])
        finally: os.close(fd)
        return r
    if case=='historical':
        assert (ROOT/'uncached').read_bytes()==b'unhydrated original revision'*12000
        assert not (ROOT/'offline-new').exists()
        return {'old_revision_references_preserved':True}
    if case=='old-head':
        with open(ROOT/'large','rb',buffering=0) as f: assert os.pread(f.fileno(),4096,0)==expected(0,4096)
        return {'old_head_bytes':True}
    raise AssertionError(case)
if __name__=='__main__': print(json.dumps(run(sys.argv[1])))
