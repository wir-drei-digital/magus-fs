"""Actual signals and writes at the reusable final publication boundary."""
import copy
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

try:
    from publication import publish_result
except ImportError:
    publish_result = None


class Publication(unittest.TestCase):
    def test_real_signal_during_each_encoding_returns_sticky_failure(self):
        self.assertIsNotNone(publish_result, 'bounded publication helper is required')
        for signum in (signal.SIGINT, signal.SIGTERM):
            class Scalar:
                count = 0
            scalar = Scalar()
            result = dict(state='passed', passed=True, exit_code=0, failures=[],
                          remaining_owned_resources=['serving-owned-child'])
            snapshots = []
            original = json.dumps
            def encode(value, *args, **kwargs):
                before = copy.deepcopy(value)
                os.kill(os.getpid(), signum)
                self.assertEqual(value, before, 'handler must never mutate the report')
                snapshots.append(before)
                return original(value, *args, **kwargs)
            def record(*args):
                scalar.count += 1
            previous = signal.signal(signum, record)
            try:
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / 'result.json'
                    with patch('publication.json.dumps', side_effect=encode):
                        code = publish_result(result, path, scalar)
                    saved = json.loads(path.read_text())
                self.assertEqual(code, 1)
                self.assertEqual(scalar.count, 2)
                self.assertEqual(len(snapshots), 2)
                self.assertEqual(saved['parent_interrupts'], 1)
                self.assertEqual(saved['exit_code'], 1)
                self.assertFalse(saved['passed'])
                self.assertEqual(saved['remaining_owned_resources'], ['serving-owned-child'])
                self.assertEqual(len(saved['failures']), 1)
                print('helper-signal', int(signum), 'attempts', len(snapshots),
                      'delivered', scalar.count, 'sampled', saved['parent_interrupts'])
            finally:
                signal.signal(signum, previous)

    def test_without_signals_preserves_blocked_and_resources(self):
        self.assertIsNotNone(publish_result, 'bounded publication helper is required')
        class Scalar:
            count = 0
        result = dict(state='blocked', passed=False, exit_code=2,
                      remaining_owned_resources=['retained'])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'result.json'
            self.assertEqual(publish_result(result, path, Scalar()), 2)
            self.assertEqual(json.loads(path.read_text())['remaining_owned_resources'], ['retained'])
