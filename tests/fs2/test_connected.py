"""Cleanup decisions use the authoritative kernel table even when stat is denied."""
import unittest
from connected import kernel_mount_present

TABLE='31 20 0:27 / /shared/worker rw,nosuid,nodev - fuse.magus-fs1 magus-fs1 rw,user_id=0,group_id=0\n'
class KernelCleanupTests(unittest.TestCase):
    def test_stat_denial_cannot_disprove_the_recorded_kernel_mount(self):
        # This path does not exist on the unit-test host. Kernel presence is independent of stat.
        self.assertTrue(kernel_mount_present('/shared/worker',TABLE))
    def test_similar_path_is_not_an_owned_mount(self):
        self.assertFalse(kernel_mount_present('/shared/worker-other',TABLE))
    def test_empty_mount_table_cannot_prove_absence(self):
        with self.assertRaises(ValueError):kernel_mount_present('/shared/worker','')
if __name__=='__main__':unittest.main()
