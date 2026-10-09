"""Kernel and engine authority checks through actual OS calls."""
import errno,json,os,stat,sys
from pathlib import Path
from ordinary_io import denied
P=Path('/view')
def run(case):
    r={}
    if case=='readonly':
        for name,fn in [('write',lambda:(P/'large').open('r+b')),('create',lambda:(P/'create').touch()),('mkdir',lambda:(P/'mkdir').mkdir()),('truncate',lambda:os.truncate(P/'large',0)),('rename',lambda:os.rename(P/'large',P/'renamed')),('unlink',lambda:(P/'large').unlink()),('chmod',lambda:os.chmod(P/'large',0o777)),('chown',lambda:os.chown(P/'large',1001,1001)),('root-chmod',lambda:os.chmod(P,0o777)),('xattr',lambda:os.setxattr(P/'large','user.x',b'x'))]:
            r[name]=denied(fn,[errno.EROFS])
        return r
    if case=='owner':
        assert os.listdir(P/'read-dir')==['child']
        r['read_without_search']=denied(lambda:(P/'read-dir/child').read_bytes(),[errno.EACCES])
        assert (P/'search-dir/child').read_bytes()==b'child'
        r['search_without_read']=denied(lambda:os.listdir(P/'search-dir'),[errno.EACCES])
        r['mode000']=denied(lambda:(P/'locked').read_bytes(),[errno.EACCES])
        (P/'unlink-parent/no-write').unlink();assert not (P/'unlink-parent/no-write').exists()
        return {**r,'writable_parent_unlink':True}
    if case=='group':
        assert (P/'group').read_bytes()==b'group'
        r['group_write']=denied(lambda:(P/'group').open('wb'),[errno.EACCES]);return r
    if case=='other':
        r['other_read']=denied(lambda:(P/'group').read_bytes(),[errno.EACCES]);return r
    if case=='root':
        assert (P/'locked').read_bytes()==b'locked'
        for path in ['/private/lazy','/private/lazy/control.sock','/private/source/objects','/shared']:
            assert not Path(path).exists(),path
        assert not any(b'magus-fs\x00mount' in path.read_bytes() for path in Path('/proc').glob('[0-9]*/cmdline'))
        from root_confinement import run as confined
        return {'configured_root_dac':True,'confinement':confined('http://127.0.0.1:8765')}
    raise AssertionError(case)
if __name__=='__main__': print(json.dumps(run(sys.argv[1])))
