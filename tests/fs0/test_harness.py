import pathlib
import tempfile
import unittest

from preflight import check
from report import MANDATORY, qualifies
from resources import OwnedOutput


class Harness(unittest.TestCase):
    def test_refuses_existing_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "old").mkdir()
            (root / "old" / "keep").write_text("x")
            (root / "link").symlink_to(root / "old")
            for path in [root / "old", root / "link"]:
                with self.assertRaises(ValueError):
                    OwnedOutput(path)

    def test_cleanup_only_owned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "keep").write_text("x")
            owned = OwnedOutput(root / "new")
            self.assertEqual(owned.cleanup(), [])
            self.assertTrue((root / "keep").exists())

    def test_fail_closed(self):
        self.assertFalse(qualifies({}, []))
        passed = {case: "passed" for case in MANDATORY}
        self.assertTrue(qualifies(passed, []))
        blocked = dict(passed, mount="blocked")
        self.assertFalse(qualifies(blocked, []))
        self.assertFalse(qualifies(passed, ["cleanup error"]))

    def test_cleanup_errors_prevent_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = OwnedOutput(pathlib.Path(directory) / "new")
            owned.marker.write_text("other")
            errors = owned.cleanup()
            self.assertTrue(errors)
            self.assertFalse(qualifies({case: "passed" for case in MANDATORY}, errors))

    def test_missing_requirements_exit_two(self):
        self.assertEqual(check(which=lambda _: None)["exit_code"], 2)


if __name__ == "__main__":
    unittest.main()
