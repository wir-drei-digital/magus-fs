"""Focused ordinary mounted permission regression cases for Task3 review."""
import errno
import os
from pathlib import Path
from root_confinement import run as confined


def run(kind, source):
    result = {}
    def case(name, action):
        try:
            result[name] = {'state':'passed','detail':action()}
        except Exception as error:
            result[name] = {'state':'failed','detail':repr(error),'errno':getattr(error,'errno',None)}
    def deny(action, code):
        try:
            action()
        except OSError as error:
            assert error.errno == code, error
            return {'errno':error.errno}
        raise AssertionError('operation unexpectedly succeeded')
    assert os.path.ismount('/view'), 'not a real mount'
    file = Path('/view/instructions.md')
    if kind == 'directory400':
        def listing():
            assert os.listdir('/view/nested') == ['table.csv']
            return 'owner mode0400 names readable without search'
        case('list_names', listing)
        case('child_lookup_denied', lambda: deny(lambda: os.stat('/view/nested/table.csv'), errno.EACCES))
        case('child_read_denied', lambda: deny(lambda: Path('/view/nested/table.csv').read_bytes(), errno.EACCES))
    elif kind == 'directory100':
        case('listing_denied', lambda: deny(lambda: os.listdir('/view/nested'), errno.EACCES))
        def lookup():
            assert Path('/view/nested/table.csv').read_bytes() == b'id,value\n1,synthetic\n'
            return 'owner mode0100 child lookup/read works without directory read'
        case('child_lookup_read', lookup)
    elif kind == 'private-root':
        def writes():
            with file.open('r+b', buffering=0) as writer, file.open('rb',buffering=0) as peer:
                old = writer.read()
                assert os.pwrite(writer.fileno(), b'private', 0) == 7
                assert os.pread(peer.fileno(), 7, 0) == b'private'
                assert file.read_bytes()[:7] == b'private'
                durability = deny(lambda: os.fsync(writer.fileno()), errno.EOPNOTSUPP)
                os.pwrite(writer.fileno(), old, 0)
                assert peer.read() == old
            return {'root_private_write_readback':True,'fsync':durability}
        case('write_readback', writes)
        case('confined_root', lambda: confined(source))
    elif kind == 'private-denied':
        case('nonroot_write_denied', lambda: deny(lambda: os.open(file, os.O_RDWR), errno.EACCES))
    elif kind == 'readonly-root':
        case('readonly_write_denied', lambda: deny(lambda: os.open(file, os.O_RDWR), errno.EROFS))
        def intact():
            assert file.read_bytes() == b'# Synthetic workspace\nUse relative paths.\n'
            return 'readonly source bytes preserved despite private sibling writes'
        case('source_intact', intact)
        case('confined_root', lambda: confined(source))
    else:
        raise ValueError(kind)
    return result
