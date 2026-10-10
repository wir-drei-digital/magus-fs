"""Cleanup decisions use the authoritative kernel table even when stat is denied."""
import copy
import unittest
from unittest.mock import Mock, patch
from connected import Connected, kernel_mount_present

TABLE='31 20 0:27 / /shared/worker rw,nosuid,nodev - fuse.magus-fs1 magus-fs1 rw,user_id=0,group_id=0\n'
class KernelCleanupTests(unittest.TestCase):
    def test_stat_denial_cannot_disprove_the_recorded_kernel_mount(self):
        # This path does not exist on the unit-test host. Kernel presence is independent of stat.
        self.assertTrue(kernel_mount_present('/shared/worker',TABLE))
    def test_similar_path_is_not_an_owned_mount(self):
        self.assertFalse(kernel_mount_present('/shared/worker-other',TABLE))
    def test_empty_mount_table_cannot_prove_absence(self):
        with self.assertRaises(ValueError):kernel_mount_present('/shared/worker','')
class VisibilityObservationTests(unittest.TestCase):
    def observer(self):return object.__new__(Connected)
    def test_exact_boundary_is_accepted(self):
        with patch('connected.time.monotonic',side_effect=[115,115]):self.assertTrue(self.observer().until_visible(lambda:True,100))
    def test_predicate_completion_over_budget_is_rejected(self):
        with patch('connected.time.monotonic',side_effect=[114,115.001]):
            with self.assertRaises(AssertionError):self.observer().until_visible(lambda:True,100)
    def test_expired_budget_does_not_start_observation(self):
        predicate=Mock(return_value=True)
        with patch('connected.time.monotonic',return_value=115.001):
            with self.assertRaises(AssertionError):self.observer().until_visible(predicate,100)
        predicate.assert_not_called()
    def test_false_at_boundary_fails_without_sleep(self):
        with patch('connected.time.monotonic',return_value=115),patch('connected.time.sleep') as sleep:
            with self.assertRaises(AssertionError):self.observer().until_visible(lambda:False,100)
            sleep.assert_not_called()
    def test_second_observation_uses_original_save_budget(self):
        with patch('connected.time.monotonic',side_effect=[113,113,115.001]):
            observer=self.observer();self.assertTrue(observer.until_visible(lambda:True,100))
            with self.assertRaises(AssertionError):observer.until_visible(lambda:True,100)

class ReceiptObservationTests(unittest.TestCase):
    def record(self):
        from test_qualification import complete
        r=complete()['journeys'][0]['receipts'][0];p=copy.deepcopy(r['raw_progress']);p['request']={'original_view':r['original_view'],'original_head':r['original_head']}
        return p,r['applied'],{'branch':'main','view':{'view':r['original_view'],'head':r['original_head']}}
    def observer(self):
        j=object.__new__(Connected);j.result={'receipts':[]};return j
    def test_distinct_candidate_and_integration_operations_are_accepted(self):
        p,a,b=self.record();self.assertNotEqual(p['operation'],p['integration']['operation']);self.assertEqual(self.observer().receipt(p,a,b),0)
    def test_rebased_or_mismatched_integration_is_rejected(self):
        for field in ['expected_head','candidate_receipt','operation','replica','branch']:
            with self.subTest(field=field):
                p,a,b=self.record();p['integration'][field]='wrong'
                with self.assertRaises(AssertionError):self.observer().receipt(p,a,b)
if __name__=='__main__':unittest.main()
