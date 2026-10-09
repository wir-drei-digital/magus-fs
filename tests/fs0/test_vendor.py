"""The reviewed dependency delta must reconstruct the exact pinned upstream files."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class VendorProvenanceTests(unittest.TestCase):
    def test_reviewed_patch_reconstructs_exact_upstream_baseline(self):
        # Catches unrecorded edits or missing license/source files in the local dependency.
        vendor = Path(__file__).resolve().parents[2] / 'vendor'
        baseline = json.loads((vendor/'nfsserve-0.11.0-baseline.json').read_text())
        with tempfile.TemporaryDirectory(prefix='fs0-vendor-audit-') as directory:
            copy = Path(directory)/'crate'
            shutil.copytree(vendor/'nfsserve-0.11.0',copy)
            done = subprocess.run(['patch','-R','-p1','--batch','-i',str(vendor/'nfsserve-access.patch')],
                                  cwd=copy,capture_output=True,text=True,timeout=5)
            self.assertEqual(done.returncode,0,done.stdout+done.stderr)
            files = {str(p.relative_to(copy)):hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in copy.rglob('*') if p.is_file()}
            self.assertEqual(files,baseline['files'])


if __name__ == '__main__':
    unittest.main()
