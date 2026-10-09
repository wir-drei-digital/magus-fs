"""Fail-closed macOS evidence parsing; no native mounts in these regressions."""
import unittest
import macos_run


class MacosEvidenceTests(unittest.TestCase):
    def test_effective_options_match_only_owned_mount(self):
        # Catches accepting another mount's TTL/lock options or original argv as proof.
        text = '''/other from 127.0.0.1:/
 -- Current mount parameters:
 General mount flags: ro
 NFS parameters: vers=3,locallocks,acregmin=1,acregmax=1,acdirmin=1,acdirmax=1,acrootdirmin=1,acrootdirmax=1
/owned from 127.0.0.1:/
 -- Original mount options:
 General mount flags: ro
 NFS parameters: locallocks,acregmin=1,acregmax=1,acdirmin=1,acdirmax=1,acrootdirmin=1,acrootdirmax=1
 -- Current mount parameters:
 General mount flags: ro
 NFS parameters: vers=3,nolocks,acregmin=0,acregmax=0,acdirmin=0,acdirmax=0,acrootdirmin=0,acrootdirmax=0
'''
        with self.assertRaises(AssertionError):
            macos_run.effective_options(text, '/owned', True)
        valid = text.replace('vers=3,nolocks,acregmin=0,acregmax=0,acdirmin=0,acdirmax=0,acrootdirmin=0,acrootdirmax=0', 'vers=3,locallocks,acregmin=1,acregmax=1,acdirmin=1,acdirmax=1,acrootdirmin=1,acrootdirmax=1')
        result = macos_run.effective_options(valid, '/owned', True)
        self.assertIn('locallocks', result)
        with self.assertRaises(AssertionError):
            macos_run.effective_options(valid, '/missing', True)
        with self.assertRaises(AssertionError):
            macos_run.effective_options(valid, '/owned', False)

    def test_native_failures_never_normalized_as_unsupported(self):
        # Catches treating unexpected EIO/EACCES as a successful unsupported operation.
        from macos_io import require_unsupported
        import errno
        def fail(number):
            raise OSError(number, 'synthetic')
        for code in (errno.EROFS, errno.EOPNOTSUPP, errno.ENOSYS):
            self.assertEqual(require_unsupported(lambda: fail(code))['errno'], code)
        for code in (errno.EIO, errno.EACCES, errno.ENOENT):
            with self.assertRaises(AssertionError):
                require_unsupported(lambda: fail(code))
        with self.assertRaises(AssertionError):
            require_unsupported(lambda: None)
