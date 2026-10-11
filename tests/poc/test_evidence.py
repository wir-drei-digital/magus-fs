import importlib.util,json,tempfile,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('evidence.py'));a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
class AuditTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.e={'journeys':[]}
  for number in [1,2]:
   root=self.root/str(number);root.mkdir()
   for name in a.MANDATORY:(root/name).write_text(json.dumps([{'case':'actual','status':200}] if name=='observations.json' else [{'log':'command.log'}] if name=='commands.json' else {}))
   (root/'command.log').write_text('actual retained command output')
   self.e['journeys'].append({'components':{'fixture':{'raw':{'path':str(root/'raw.json')}}}})
  self.result={'exit':0,'passed':True,'errors':[],'evidence':self.e}
 def test_complete(self):self.assertTrue(a.finalize(self.root,self.result)['artifact_integrity']['verified'])
 def test_missing_observations_or_command_rejects(self):
  for leaf in ['observations.json','command.log']:
   p=self.root/'1'/leaf;old=p.read_bytes();p.unlink();self.assertEqual(a.finalize(self.root,self.result)['exit'],1);p.write_bytes(old)
 def test_changed_or_removed_sealed_artifact_rejects(self):
  ref=a.seal(self.root,self.e);p=self.root/'1'/'command.log';p.write_text('tampered')
  with self.assertRaises(AssertionError):a.verify(ref,self.e)
 def test_false_original_result_not_upgraded(self):self.assertEqual(a.finalize(self.root,{**self.result,'exit':1,'passed':False})['exit'],1)
if __name__=='__main__':unittest.main()
