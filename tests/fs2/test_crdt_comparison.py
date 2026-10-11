"""Reject misleading experiment evidence independently of CRDT mechanics."""
import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

from crdt_comparison import BINARY, fixture, validate_case


class EvidenceValidation(unittest.TestCase):
    def actual(self, spec):
        with tempfile.TemporaryDirectory(prefix='fs2b-crdt-validator-') as name:
            directory = pathlib.Path(name)
            spec = copy.deepcopy(spec)
            spec['directory'] = name
            (directory / 'base.txt').write_text(spec['base'])
            for save in spec['saves']:
                (directory / (save['id'] + '.txt')).write_text(save['text'])
            path = directory / 'input.json'
            path.write_text(json.dumps(spec))
            result = subprocess.run([str(BINARY),str(path)],capture_output=True,text=True,check=True)
            return json.loads(result.stdout)

    def test_unknown_frontier_cannot_claim_latest_heads(self):
        spec = fixture('unknown', 'a\nb\n','A\nb\n','a\nB\n',frontier='unknown',helper='unknown')
        output = self.actual(spec)
        validate_case(spec, output)
        output['saves'][1]['heads_before'] = output['base_heads']
        with self.assertRaises(AssertionError):
            validate_case(spec, output)

    def test_missing_history_must_retain_actual_fork_error(self):
        spec = fixture('missing','a\nb\n','A\nb\n','a\nB\n',frontier='unavailable',helper='base_unavailable')
        output = self.actual(spec)
        validate_case(spec, output)
        output['saves'][1]['frontier_error'] = None
        with self.assertRaises(AssertionError):
            validate_case(spec, output)

    def test_missing_operation_cannot_pass_by_zip_truncation(self):
        spec = fixture('two','a\nb\nc\n','A\nb\nc\n','a\nb\nC\n','A\nb\nC\n')
        output = self.actual(spec)
        output['saves'].pop()
        with self.assertRaises(AssertionError):
            validate_case(spec, output)

    def test_convergence_does_not_satisfy_declared_intent(self):
        spec = fixture('overlap','old\n','alice\n','bob\n',helper='overlap',fragments=['alice','bob'])
        assessment = validate_case(spec, self.actual(spec))
        self.assertTrue(assessment['converged'])
        self.assertIsNone(assessment['intent_exact_match'])
        self.assertFalse(assessment['intent_fragments_preserved'])


if __name__ == '__main__':
    unittest.main()
