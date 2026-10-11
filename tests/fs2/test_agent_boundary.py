"""Task semantics for real agent edits; no simulated application qualification."""
import unittest
from mounted_lifecycle import validate_agent_edit
class AgentEditTests(unittest.TestCase):
    original=b'task-value: 29\n'
    before=original+b'completed-value: 36 and procedure-code: mounted-ordinary-v1\n'
    line=b'peer-observed completed-value: 36; procedure-code: mounted-ordinary-v1\n'
    def test_natural_peer_observation_without_hidden_marker(self):
        validate_agent_edit(self.original,self.before,self.before+self.line,'follow-up')
    def test_missing_wrong_or_multiple_observations_fail(self):
        for suffix in [b'',b'follow-up\n',self.line.replace(b'36',b'18'),self.line.replace(b'mounted-ordinary-v1',b'wrong'),self.line+self.line,b'\n'+self.line]:
            with self.subTest(suffix=suffix),self.assertRaises(AssertionError):
                validate_agent_edit(self.original,self.before,self.before+suffix,'follow-up')
    def test_mutation_or_lost_prefix_fails(self):
        for body in [self.line,self.before.replace(b'29',b'28')+self.line,self.before.replace(b'36',b'18')+self.line]:
            with self.subTest(body=body),self.assertRaises(AssertionError):
                validate_agent_edit(self.original,self.before,body,'follow-up')
    def test_initial_edit_preserves_original_and_computes_value(self):
        validate_agent_edit(self.original,self.original,self.before,'write')
        for body in [self.original,self.before.replace(b'36',b'18'),self.before.replace(b'29',b'28')]:
            with self.subTest(body=body),self.assertRaises(AssertionError):
                validate_agent_edit(self.original,self.original,body,'write')
