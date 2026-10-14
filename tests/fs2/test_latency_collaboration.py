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
  row={"save_started_ns":10,"exact_shared_ns":20,"exact_applied_ns":30,"first_read_ns":25,"post_applied_read":{"read_started_ns":30,"fresh_after_applied_ns":31,"uid":1001,"bytes":24,"sha256":"hash"},"size":24,"sha256":"hash","status_polls":[]}
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

class ContinuationServiceRunnerTests(unittest.TestCase):
 def test_service_failure_retained_and_owned_cleanup_always_runs(self):
  from continuation_proof import execute
  class Infra:
   def __init__(self):self.records={};self.cleaned=False
   def preflight(self):pass
   def setup(self,image):pass
   def isolate_service_control(self):pass
   def cleanup(self):self.cleaned=True
   def write_json(self,name,value):self.records[name]=value
  class BadJourney:
   def __init__(self,i):pass
   def run(self):raise AssertionError('retained failed journey')
  i=Infra()
  self.assertEqual(execute(i,'sha256:'+'1'*64,BadJourney,lambda _: {},lambda *_: None),1)
  self.assertTrue(i.cleaned);self.assertIn('retained failed journey',i.records['failure.json']['reason'])
 def test_source_mismatch_prevents_service_journey_and_cleanup_failure_is_failure(self):
  from continuation_proof import execute
  class Infra:
   def preflight(self):pass
   def setup(self,image):pass
   def isolate_service_control(self):pass
   def cleanup(self):raise RuntimeError('owned cleanup incomplete')
   def write_json(self,name,value):pass
  def bad_source(*_):raise AssertionError('source mismatch')
  def forbidden(_):self.fail('journey reached before provenance')
  self.assertEqual(execute(Infra(),'sha256:'+'1'*64,forbidden,lambda _: {},bad_source),1)
 def test_mutable_image_refused(self):
  from continuation_proof import validate_image
  with self.assertRaises(ValueError):validate_image('latest')

class MetadataReuseTests(unittest.TestCase):
 def test_immediate_post_applied_read_precedes_diagnostics(self):
  from latency_collaboration import immediate_post_applied_read
  events=[]
  def read():
   events.append('read');return {'read_started_ns':31,'fresh_after_applied_ns':35,'uid':1001,'bytes':24,'sha256':'hash'}
  def diagnostics():events.append('diagnostics');return {'receipt':'later'}
  post,after=immediate_post_applied_read(read,diagnostics,30,24,'hash')
  self.assertEqual(events,['read','diagnostics']);self.assertEqual(after,{'receipt':'later'})
  for change in [{'read_started_ns':29},{'fresh_after_applied_ns':28},{'uid':0},{'sha256':'stale'},{'bytes':1}]:
   events.clear()
   with self.assertRaises(AssertionError):immediate_post_applied_read(lambda:dict(post,**change),diagnostics,30,24,'hash')
   self.assertEqual(events,[])
 def test_comparison_gate_rejects_incomplete_or_slow(self):
  from metadata_reuse import comparison_gate
  blocks=[{'kind':'block','mechanism':m,'block':b,'requests':1000,'cpu_ns':1000000 if m=='C' else 9000000,'wall_ns':1000000 if m=='C' else 9000000} for b in range(5) for m in 'ABC']
  cold={'cpu_ns':1000,'wall_ns':1000}
  endpoints={'a':{'operations':3000,'residual_cpu_ns':100000000,'scheduling_plausible':True},'b':{'operations':3000,'residual_cpu_ns':100000000,'scheduling_plausible':True}}
  self.assertEqual(comparison_gate(blocks,cold,endpoints,True)['status'],'passed')
  self.assertEqual(comparison_gate(blocks[:-1],cold,endpoints,True)['status'],'inconclusive')
  self.assertEqual(comparison_gate(blocks,cold,endpoints,False)['status'],'failed')
  for changed in [dict(blocks[2],cpu_ns=None),dict(blocks[2],cpu_ns=1000000000),dict(blocks[2],cpu_ns=10000000)]:
   self.assertNotEqual(comparison_gate(blocks[:2]+[changed]+blocks[3:],cold,endpoints,True)['status'],'passed')
  endpoints['b']['residual_cpu_ns']=600000000
  self.assertEqual(comparison_gate(blocks,cold,endpoints,True)['status'],'failed')
 def test_fixed_comparison_and_mounted_workload(self):
  from metadata_reuse import comparison_schedule,mounted_matrix
  schedule=comparison_schedule()
  self.assertEqual(schedule,{'warmups':100,'requests':1000,'orders':['ABC','BCA','CAB','ABC','BCA'],'budget_seconds':120})
  self.assertEqual([(r['background'],r['size']) for r in mounted_matrix()],[(500,24),(500,1024),(500,16384)])

class ExactReadBindingTests(unittest.TestCase):
 def test_wrong_revision_receipt_or_denial_cannot_qualify_read(self):
  import copy
  from latency_collaboration import validate_exact_peer_binding
  captured={'head':'new','applied':{'b':[{'revision':'revision-new'}]}}
  peer={'live':{'applied':True,'authorized':True},'status':{'binding':{'view':{'head':'new','revision':'revision-new'}}}}
  self.assertEqual(validate_exact_peer_binding(captured,peer,{'head':'new'}),'revision-new')
  for field in ('head','revision'):
   bad=copy.deepcopy(peer);bad['status']['binding']['view'][field]='old'
   with self.assertRaises(AssertionError):validate_exact_peer_binding(captured,bad,{'head':'new'})
  with self.assertRaises(AssertionError):validate_exact_peer_binding(captured,peer,{'head':'old'})
  bad=copy.deepcopy(peer);bad['live']['authorized']=False
  with self.assertRaises(AssertionError):validate_exact_peer_binding(captured,bad,{'head':'new'})
 def test_receipts_bind_operation_revision_and_original_view(self):
  import copy
  from latency_support import validate_receipts
  progress={'operation':'private-op','local_revision':'local','private_receipt':{'operation':'private-op','replica':'replica','submitted_revision':'local','original_view':'view','original_head':'head','receipt':'private-receipt'},'shared_receipt':{'operation':'shared-op','replica':'replica','submitted_revision':'local','branch':'main'},'request':{'operation':'private-op','replica':'replica','revision':'local','original_view':'view','original_head':'head'},'integration':{'operation':'shared-op','replica':'replica','candidate_receipt':'private-receipt','branch':'main'}}
  binding={'branch':'main','view':{'view':'view','head':'head'}}
  validate_receipts(progress,binding,'replica')
  for section,key in [('private_receipt','operation'),('shared_receipt','submitted_revision'),('request','original_view'),('integration','candidate_receipt')]:
   bad=copy.deepcopy(progress);bad[section][key]='wrong'
   with self.assertRaises(AssertionError):validate_receipts(bad,binding,'replica')

class PostReadSettlementTests(unittest.TestCase):
 def scenario(self, mode):
  import json
  from latency_collaboration import immediate_post_applied_read, collect_post_read_evidence
  order=[];now=[0.0];snapshots=[0];row={}
  captured={'head':'new','applied':{'a':[],'b':[{'revision':'peer-new','monotonic_ns':30}]}}
  def read():
   order.append('read')
   return {'read_started_ns':31,'fresh_after_applied_ns':35,'uid':1001,'bytes':24,'sha256':'hash'}
  def status():order.append('status');return {}
  post,_=immediate_post_applied_read(read,status,30,24,'hash')
  row['post_applied_read']=post
  def profile(revision,ok=True):return 'metadata_profile '+json.dumps({'revision':revision,'ok':ok,'profile':{}})
  def logs():
   order.append('logs');snapshots[0]+=1
   # Wrong-head Applied and unrelated successful profiles cannot qualify.
   sender='latency stage=applied head=old revision=old monotonic_ns=29\n'+profile('old')
   if mode!='missing' and snapshots[0]>=2:
    sender+='\nlatency stage=applied head=new revision=sender-new monotonic_ns=40'
    if snapshots[0]>=3:sender+='\n'+profile('sender-new',mode!='failed')
   return {'a':{'log':sender},'b':{'log':profile('peer-new')}}
  def events(log,owner):
   return [dict(dict(x.split('=',1) for x in line.split()[1:]),owner=owner) for line in log.splitlines() if line.startswith('latency ')]
  def sleep(seconds):
   self.assertGreater(seconds,0);self.assertLessEqual(seconds,.1);now[0]+=seconds
  try:
   result=collect_post_read_evidence(logs,events,captured,row,clock=lambda:now[0],sleep=sleep)
  except AssertionError as error:result=error
  self.assertEqual(order[:3],['read','status','logs'])
  self.assertEqual(order.count('read'),1)
  self.assertEqual(row['post_applied_read'],{'read_started_ns':31,'fresh_after_applied_ns':35,'uid':1001,'bytes':24,'sha256':'hash'})
  self.assertEqual((max(20,30,post['fresh_after_applied_ns'])-10)/1e9,25e-9)
  return result,row,now[0],snapshots[0]
 def test_later_sender_applied_and_profile_succeed_after_peer_read(self):
  result,row,elapsed,count=self.scenario('delayed')
  self.assertNotIsInstance(result,Exception)
  logs,events,profiles=result
  self.assertEqual(profiles['a']['revision'],'sender-new')
  self.assertEqual(profiles['b']['revision'],'peer-new')
  self.assertEqual(count,3);self.assertAlmostEqual(elapsed,.2)
 def test_missing_exact_sender_fails_at_existing_settle_bound(self):
  result,row,elapsed,count=self.scenario('missing')
  self.assertIsInstance(result,AssertionError)
  self.assertIn('sender Applied',str(result));self.assertAlmostEqual(elapsed,60)
  self.assertGreater(count,1)
  self.assertIn('head=old',row['post_read_diagnostics']['logs']['a']['log'])
 def test_failed_exact_sender_profile_is_retained(self):
  result,row,elapsed,count=self.scenario('failed')
  self.assertIsInstance(result,AssertionError)
  self.assertIn('failed',str(result))
  self.assertIn('"ok": false',row['post_read_diagnostics']['logs']['a']['log'])
