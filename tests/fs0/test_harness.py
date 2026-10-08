import unittest,tempfile,pathlib
from resources import OwnedOutput
from report import qualifies
from preflight import check
class Harness(unittest.TestCase):
 def test_refuses_existing_and_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); (p/'old').mkdir(); (p/'old'/'keep').write_text('x'); (p/'link').symlink_to(p/'old')
   for q in [p/'old',p/'link']:
    with self.assertRaises(ValueError): OwnedOutput(q)
 def test_cleanup_only_owned(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d); (p/'keep').write_text('x'); r=OwnedOutput(p/'new'); r.cleanup(); self.assertTrue((p/'keep').exists())
 def test_fail_closed(self):
  self.assertFalse(qualifies({},[])); self.assertFalse(qualifies({'mount':'blocked'},[])); self.assertFalse(qualifies({'mount':'passed'},['cleanup error']))
 def test_cleanup_errors_prevent_pass(self):
  with tempfile.TemporaryDirectory() as d:
   r=OwnedOutput(pathlib.Path(d)/'new'); r.marker.write_text('other')
   errors=r.cleanup(); self.assertTrue(errors); self.assertFalse(qualifies({k:'passed' for k in ('mount','range_reads','private_writes','readonly_view','permissions','cleanup')},errors))
 def test_missing_requirements_exit_two(self):
  self.assertEqual(check(which=lambda _:None)['exit_code'],2)
if __name__=='__main__': unittest.main()
