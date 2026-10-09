"""Ownership mistakes must fail before issuing a destructive Docker command."""
import tempfile
import sys
import json
import unittest
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, classify_docker

class InfrastructureTests(unittest.TestCase):
    def test_unavailable_is_distinct_from_observed_failure(self):
        self.assertEqual(classify_docker(1, 'Cannot connect to the Docker daemon'), 2)
        self.assertEqual(classify_docker(1, 'permission denied docker.sock'), 2)
        self.assertEqual(classify_docker(1, 'unexpected API response'), 1)
        self.assertEqual(classify_docker(0, 'linux'), 0)

    def test_refuses_existing_output_without_mutating_it(self):
        with tempfile.TemporaryDirectory() as p:
            Path(p, 'keep').write_text('unchanged')
            with self.assertRaises(FileExistsError):
                OwnedInfra(Path(p))
            self.assertEqual(Path(p, 'keep').read_text(), 'unchanged')

    def test_cleanup_refuses_unrecorded_resource(self):
        with tempfile.TemporaryDirectory() as p:
            infra = OwnedInfra(Path(p) / 'run')
            with self.assertRaises(ValueError):
                infra.remove('container', 'unrelated')
            self.assertEqual(infra.commands, [])

    def test_cleanup_refuses_label_mismatch(self):
        with tempfile.TemporaryDirectory() as p:
            infra = OwnedInfra(Path(p) / 'run')
            infra.resources.append({'kind':'volume', 'name':'foreign', 'id':'foreign'})
            # The validator is also invoked on actual Docker inspect output.
            with self.assertRaises(ValueError):
                infra.validate_owned(infra.resources[0], {'Name':'foreign', 'Labels':{'magus.fs2.owner':'someone-else'}})

    def test_subprocess_deadline_is_recorded_without_an_unbounded_wait(self):
        with tempfile.TemporaryDirectory() as p:
            infra=OwnedInfra(Path(p).resolve()/'run')
            result=infra.run([sys.executable,'-c','import time; time.sleep(2)'],timeout=.1,check=False)
            self.assertEqual(result.returncode,124)
            self.assertEqual(json.loads((infra.output/'commands.json').read_text())[0]['status'],124)

    def test_correct_label_with_wrong_id_is_not_ownership(self):
        with tempfile.TemporaryDirectory() as p:
            infra=OwnedInfra(Path(p).resolve()/'run')
            row={'kind':'network','name':'same-name','id':'original-id'}
            with self.assertRaises(ValueError):
                infra.validate_owned(row,{'Id':'replacement-id','Labels':{'magus.fs2.owner':infra.owner}})

    def test_restart_readiness_requires_recorded_volume_ids_when_content_exists(self):
        with tempfile.TemporaryDirectory() as p:
            infra=OwnedInfra(Path(p).resolve()/'run')
            with self.assertRaisesRegex(ValueError,'volume'):
                infra.wait_s3('acknowledged-content', require_volumes=True)
            self.assertEqual(infra.commands, [])

if __name__ == '__main__':
    unittest.main()
