import unittest
from latency_collaboration import profile_matrix, validate_passive_capture, profile_docker_args
class CollaborationTests(unittest.TestCase):
 def test_profile_matrix_is_fourteen(self):
  rows=profile_matrix();self.assertEqual(len(rows),14)
  self.assertEqual([r["size"] for r in rows[:6]],[24,1024,16384]*2)
  self.assertEqual([r["background"] for r in rows[:6]],[50]*3+[500]*3)
  self.assertEqual([r["size"] for r in rows[6:12]],[1024]*6)
  self.assertEqual([r["enabled"] for r in rows],[True]*12+[False]*2)
 def test_passive_capture_requires_exact_post_applied_read(self):
  row={"save_started_ns":10,"exact_shared_ns":20,"exact_applied_ns":30,"first_read_ns":25,"post_applied_read":{"fresh_after_applied_ns":31,"uid":1001,"bytes":24,"sha256":"hash"},"size":24,"sha256":"hash","status_polls":[]}
  self.assertTrue(validate_passive_capture(row))
  for key,value in [("post_applied_read",None),("exact_applied_ns",9),("status_polls",[1])]:
   with self.assertRaises((AssertionError,ValueError)):validate_passive_capture(dict(row,**{key:value}))

class ProfileStartupTests(unittest.TestCase):
 def test_profile_opt_in_reaches_actual_client_exec_i_startup(self):
  args=('exec','-i','--user','0:0','owned-client','python3','-c','startup')
  actual=profile_docker_args(args)
  self.assertIn('MAGUS_METADATA_PROFILE=1',actual)
  self.assertEqual(actual[-len(args[2:]):],args[2:])
 def test_profile_opt_in_preserves_service_and_non_exec_commands(self):
  self.assertIn('MAGUS_LATENCY_TRACE=1',profile_docker_args(('exec','-d','owned-service','service')))
  self.assertEqual(profile_docker_args(('image','inspect','sha256:abc')),('image','inspect','sha256:abc'))

class AttributionTests(unittest.TestCase):
 def test_enabled_requires_real_collection_and_retains_ambiguity(self):
  from latency_collaboration import validate_profile_attribution
  p={'window':1,'callback_count':10,'load_count':10,'ambiguous':True}
  self.assertEqual(validate_profile_attribution({'ok':True,'profile':p},True),{'mode':'enabled','ambiguous':True})
 def test_enabled_rejects_missing_or_zero_counters(self):
  from latency_collaboration import validate_profile_attribution
  p={'window':1,'callback_count':10,'load_count':10,'ambiguous':False}
  for key in ['window','callback_count','load_count']:
   with self.assertRaises(AssertionError):validate_profile_attribution({'ok':True,'profile':dict(p,**{key:0})},True)
  with self.assertRaises(AssertionError):validate_profile_attribution({'ok':True,'profile':None},True)
 def test_control_off_distinguished_and_rejects_active_window(self):
  from latency_collaboration import validate_profile_attribution
  p={'window':0,'callback_count':0,'load_count':0,'ambiguous':False}
  self.assertEqual(validate_profile_attribution({'ok':True,'profile':p},False),{'mode':'control-off','ambiguous':None})
  with self.assertRaises(AssertionError):validate_profile_attribution({'ok':True,'profile':dict(p,window=1)},False)
