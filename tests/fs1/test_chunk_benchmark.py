"""Benchmark contract: reconstruct bytes, never deduplicate ordered descriptors."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BenchmarkContract(unittest.TestCase):
    def test_release_example_produces_verifiable_ordered_descriptors(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input'
            data = b'a' * 262144 + b'a' * 262144 + b'changed-tail'
            path.write_bytes(data)
            for layout in ('fixed', 'cdc'):
                done = subprocess.run(['cargo', 'run', '--release', '--example', 'chunk_layout',
                                       '--', str(path), layout], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                import json
                observed = json.loads(done.stdout)
                reconstructed = b''.join(data[d['offset']:d['offset']+d['length']]
                                         for d in observed['descriptors'])
                self.assertEqual(reconstructed, data)
                self.assertEqual(observed['sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(observed['bytes_scanned_rechunked'], len(data))
                self.assertEqual(observed['descriptor_encoded_bytes'],
                                 48 * len(observed['descriptors']))

    def test_independent_verifier_rejects_repeated_identity_hiding_changes(self):
        driver = ROOT / 'tests/fs1/chunk_benchmark.py'
        self.assertTrue(driver.exists(), 'independent descriptor verifier is required')
        spec = importlib.util.spec_from_file_location('chunk_benchmark', driver)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input'
            path.write_bytes(b'aaaaCHANGED')
            report = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          bytes_scanned_rechunked=11,
                          descriptors=[dict(offset=0, length=4, sha256=hashlib.sha256(b'aaaa').hexdigest()),
                                       dict(offset=4, length=7, sha256=hashlib.sha256(b'aaaa').hexdigest())])
            with self.assertRaises(AssertionError):
                module.verify(path, report)

    def test_measurement_includes_child_lifetime_peak_memory(self):
        import json
        import sys
        driver = ROOT / 'tests/fs1/chunk_benchmark.py'
        spec = importlib.util.spec_from_file_location('chunk_benchmark', driver)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            record = Path(folder) / 'command.json'
            value = module.checked([sys.executable, '-c',
                                    'data=bytearray(32*1024*1024); print("complete")'], record)
            self.assertEqual(value.strip(), 'complete')
            observed = json.loads(record.read_text())
            self.assertIn('process_usage', observed, 'full child lifetime measurements required')
            self.assertGreaterEqual(observed['process_usage']['peak_rss_bytes'], 32 * 1024 * 1024)
            self.assertGreater(observed['process_usage']['cpu_seconds'], 0)
            self.assertGreater(observed['process_usage']['elapsed_seconds'], 0)
