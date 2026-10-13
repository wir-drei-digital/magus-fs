"""Source-matched, disk-backed ordinary-save latency diagnostics; owned synthetic fixtures."""
import argparse, hashlib, json, math, secrets, statistics, subprocess, sys, time, traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/fs2'))
from infra import OwnedInfra
from provenance import capture,verify_image,sources
from full_native import NativeJourney
from connected import Lazy,Mac
from service_protocol import identity,file_entry,GROUP,REPLICA,WORKER
from service_storage import NS,ALICE,object_id

def validate_receipts(progress,binding,replica):
 private=progress['private_receipt'];shared=progress['shared_receipt'];request=progress['request'];integration=progress['integration']
 assert private and shared and request and integration,'missing exact publication evidence'
 assert private['operation']==progress['operation']==request['operation']
 assert private['replica']==shared['replica']==request['replica']==integration['replica']==replica
 assert private['submitted_revision']==shared['submitted_revision']==request['revision']==progress['local_revision']
 assert private['original_view']==request['original_view']==binding['view']['view']
 assert private['original_head']==request['original_head']==binding['view']['head']
 assert integration['candidate_receipt']==private['receipt']
 assert shared['operation']==integration['operation'] and shared['operation']!=private['operation']
 assert shared['branch']==integration['branch']==binding['branch']

p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--image',required=True);p.add_argument('--phase',choices=['wakeups'],required=True);p.add_argument('--skip-boundaries',action='store_true');p.add_argument('--skip-native-small',action='store_true');a=p.parse_args()
assert Path(a.output).is_absolute()
assert a.image.startswith('sha256:') and len(a.image)==71,'immutable image required'
IMAGE=a.image
BASELINE_DRIVER_SHA256='dac32ce23852f4a5146528675058d8f406ac9fc6e529037d9804e2a189c6cbc9'
class TraceInfra(OwnedInfra):
 def docker(self,*args,**kw):
  if args[:2]==('exec','-d'):args=('exec','-d','-e','MAGUS_LATENCY_TRACE=1',*args[2:])
  return super().docker(*args,**kw)
i=TraceInfra(a.output);i.runtime_profile='release';j=None;code=1;started=time.monotonic()
(i.output/'driver.py').write_bytes(Path(__file__).read_bytes())
source=capture(i)
report={'kind':'latency diagnostic, not qualification','image':IMAGE,'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'runtime_head':source['head'],'phases':{},'failures':[],'runtime_changes':True,'timing':'Linux mounted edits use one VM monotonic clock and no control/status calls while timed; native estimates include host/VM command overhead.'}
def save():i.write_json('profile.json',report)
def stats(v):return {'n':len(v),'p50_ms':statistics.median(v)*1000,'p95_ms':sorted(v)[math.ceil(.95*len(v))-1]*1000,'min_ms':min(v)*1000,'max_ms':max(v)*1000}

class TraceMac(Mac):
 def run(self,code,settings=None):
  return super().run("os.environ['MAGUS_LATENCY_TRACE']='1'\n"+code,settings)

class DiskLazy(Lazy):
 def execute(self,code,settings=None,user='0:0',check=True):
  return super().execute("import os;os.environ['MAGUS_LATENCY_TRACE']='1'\n"+code,settings,user,check)

 def __init__(self,j):
  self.commands=[];self.i=j.i;self.image=j.image;self.tokens=j.tokens;self.mounts=[];self.holders=[];self.evidence={};self.owner=j
  volume=self.i.create('volume','profile-replica-state',[])
  self.daemon=self.i.create('container','disk-mounted',['--network',self.i.ingress,'--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','DAC_OVERRIDE','--cap-add','SYS_CHROOT','--security-opt','apparmor=unconfined','--security-opt','no-new-privileges','--device','/dev/fuse','--memory','512m','--cpus','2','--pids-limit','256','-v',volume+':/private','--tmpfs','/shared:rw,nosuid,nodev,mode=755,size=16m',self.image,'python3','-c',"import os,signal,time;os.chmod('/private',0o700)\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
  self.i.docker('start',self.daemon)
  mounts=self.i.inspect('container',self.daemon)['Mounts'];assert any(m['Type']=='volume' and m['Destination']=='/private' and m['Name']==volume for m in mounts);self.i.write_json('disk-state-mount.json',{'state_volume':volume,'mounts':mounts,'scope':'Rancher VM-backed disk; no host/VM power-loss qualification'})

class Profile(NativeJourney):
 def __init__(self):super().__init__(i,IMAGE,['linux','macos']);self.lazy=None;self.rows=[]
 def cleanup(self):
  if self.lazy:self.lazy.cleanup()
  for ep in self.endpoints:ep.cleanup()
 def settle(self,mac=None,client=None,expected_head=None):
  deadline=time.monotonic()+60
  while time.monotonic()<deadline:
   sa=self.lazy.status('a');sb=self.lazy.status('b');ma=mac.status(client) if mac else None
   heads=[sa['status']['binding']['view']['head'],sb['status']['binding']['view']['head']]
   ready=sa['live']['applied'] and sb['live']['applied']
   if ma:heads.append(ma['status']['binding']['view']['head']);ready=ready and ma['live']['applied'] and 'Ready' in ma['native']['status']
   if ready and len(set(heads))==1 and (expected_head is None or heads[0]==expected_head):return {'a':sa,'b':sb,'mac':ma}
   time.sleep(.1)
  raise AssertionError('target quiescence failed')
 def mounted(self,label):
  self.settle()
  measure=r'''import os,json,time,sys,errno,hashlib
s=json.load(sys.stdin);body=bytes.fromhex(s['body']);t=time.monotonic();start_ns=time.monotonic_ns()
with open('/shared/a/reports/bench','wb') as f:f.write(body);f.flush();os.fsync(f.fileno())
saved=time.monotonic();deadline=t+20;errors=[];reads=0
while time.monotonic()<deadline:
 try:
  v=open('/shared/b/reports/bench','rb').read();reads+=1
  if v==body:
   print(json.dumps({'save_started_ns':start_ns,'fresh_read_ns':time.monotonic_ns(),'save_to_visible':time.monotonic()-t,'save_fsync':saved-t,'fsync_to_visible':time.monotonic()-saved,'sha256':hashlib.sha256(v).hexdigest(),'reads':reads,'transient_errors':errors}));break
 except OSError as e:
  errors.append({'errno':e.errno,'seconds':time.monotonic()-t})
  if e.errno not in [errno.ENOENT,errno.ESTALE,errno.EIO]:raise
 time.sleep(.005)
else:print(json.dumps({'timeout':True,'save_started_ns':start_ns,'elapsed':time.monotonic()-t,'reads':reads,'transient_errors':errors}))
'''
  rows=[];phase_start=time.monotonic()
  for n,size in enumerate([24,1024,16384]*4):
   before=self.settle();prior={v['operation'] for v in before['a']['status']['submissions']};tag=(label+'-%02d'%n).encode();body=(tag+b'.'*size)[:size]
   row=self.lazy.execute(measure,{'body':body.hex()},user='1001:1001');report.setdefault('raw_attempts',[]).append({'phase':label,'number':n,'size':size,'before_binding':before['a']['status']['binding'],**row});save();assert not row.get('timeout'),'timed sample timeout; raw attempt retained'
   after=self.settle();new=[v for v in after['a']['status']['submissions'] if v['operation'] not in prior]
   assert len(new)==1 and new[0]['shared_receipt'],new
   validate_receipts(new[0],before['a']['status']['binding'],REPLICA)
   row['before_binding']=before['a']['status']['binding']
   row.update(self.stages(row,new[0],after));row.update(number=n,size=size,operation=new[0]['operation'],revision=new[0]['local_revision'],private_receipt=new[0]['private_receipt'],shared_receipt=new[0]['shared_receipt']);rows.append(row)
   report['phases'][label]={'route':'Linux mounted sender→Linux mounted receiver; independent engines in one diagnostic container','rows':rows,'save_to_visible':stats([r['save_to_visible'] for r in rows]),'save_to_exact_applied_and_read':stats([r['save_to_exact_applied_and_read'] for r in rows]),'fsync_to_visible':stats([r['fsync_to_visible'] for r in rows]),'fsync':stats([r['save_fsync'] for r in rows]),'seconds':time.monotonic()-phase_start};save()
  print(label,json.dumps(report['phases'][label]['save_to_visible']),flush=True)
 def stages(self,row,p,after):
  head=p['shared_receipt']['head'];revision=after['b']['status']['binding']['view']['revision']
  assert after['b']['status']['binding']['view']['head']==head and after['b']['live']['applied']
  logs={name:self.lazy.execute("import json,sys;print(json.dumps(open('/private/'+json.load(sys.stdin)+'/daemon.log').read()))",name) for name in ['a','b']}
  logs['service']=self.i.docker('exec',self.i.service,'cat','/tmp/service.log',evidence=False).stdout
  events=[]
  for owner,log in logs.items():
   for line in log.splitlines():
    if not line.startswith('latency '):continue
    event=dict(field.split('=',1) for field in line.split()[1:]);event['owner']=owner;event['monotonic_ns']=int(event['monotonic_ns'])
    if event['monotonic_ns']>=row['save_started_ns'] and (event.get('operation')==p['operation'] or event.get('operation')==p['integration']['operation'] or event.get('head')==head):events.append(event)
  applied=[e for e in events if e['owner']=='b' and e['stage']=='applied' and e['revision']==revision and e['head']==head]
  assert applied,'exact Applied event missing'
  committed=[e for e in events if e['owner']=='service' and e['stage']=='shared_committed' and e['head']==head and e['operation']==p['shared_receipt']['operation']]
  assert len(committed)==1,'exact service Shared commit stage missing or duplicated'
  applied_ns=min(e['monotonic_ns'] for e in applied)
  return {'events':events,'peer_projected_revision':revision,'peer_shared_head':head,'exact_applied_ns':applied_ns,'save_to_exact_applied_and_read':(max([applied_ns,row['fresh_read_ns']]+[e['monotonic_ns'] for e in events if e['stage']=='shared_committed'])-row['save_started_ns'])/1e9}
 def atomic(self):
  body=b'atomic editor save smoke'
  self.lazy.execute("import json,os;f=open('/shared/a/reports/.atomic','wb');f.write(b'atomic editor save smoke');f.flush();os.fsync(f.fileno());f.close();os.replace('/shared/a/reports/.atomic','/shared/a/reports/bench');print('{}')",user='1001:1001')
  self.until(lambda:self.lazy.read('b/reports/bench')==body.hex(),20);after=self.settle()
  report['atomic_smoke']={'passed':True,'head':after['b']['status']['binding']['view']['head'],'peer_revision':after['b']['live']['revision']};save()
 def boundaries(self):
  # Healthy timed cohorts above exclude deliberate hint omissions and reconnects.
  boundary_replica=identity('replica')
  grant=self.expect('wakeups-boundary-grant','POST',self.root+'/grants',200,body={'delegate':{'replica':boundary_replica,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}})
  self.tokens['boundary']=grant['token'];replica=boundary_replica
  self.lazy.start('fallback',actor='boundary',drop=True,replica_identity=replica)
  body=b'fallback durable replay'
  self.lazy.execute("import os,json;f=open('/shared/a/reports/bench','wb');f.write(b'fallback durable replay');f.flush();os.fsync(f.fileno());f.close();print('{}')",user='1001:1001')
  self.until(lambda:self.lazy.read('fallback/reports/bench')==body.hex(),15)
  dropped=self.lazy.execute("import json;print(json.dumps(open('/private/fallback/daemon.log').read()))")
  assert 'test_drop_wss_hint' in dropped
  self.i.docker('network','disconnect',self.i.ingress,self.lazy.daemon)
  try:self.lazy.execute("import os,json;f=open('/shared/a/reports/bench','wb');f.write(b'reconnect same admitted operation');f.flush();os.fsync(f.fileno());f.close();print('{}')",user='1001:1001');time.sleep(.4)
  finally:self.i.docker('network','connect',self.i.ingress,self.lazy.daemon)
  self.until(lambda:self.lazy.read('b/reports/bench')==b'reconnect same admitted operation'.hex(),30);self.settle()
  sock=self.websocket('boundary')
  try:
   self.read_hint(sock)
   start=time.monotonic();self.expect('wakeups-revoke','POST',self.root+'/grants',200,body={'revoke':grant['credential']})
   self.expect('wakeups-current-read-denied','GET',self.root+'/changes?branch=main&after=0&limit=128',401,{'code':'invalid_credential'},actor='boundary')
   frame=sock.recv(2);assert frame and frame[0]&15==8,frame
   close_seconds=time.monotonic()-start;assert close_seconds<3
  finally:sock.close()
  isolated_replica=identity('replica');g=self.expect('wakeups-isolated-grant','POST',self.root+'/grants',200,body={'delegate':{'replica':isolated_replica,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}});self.tokens['isolated']=g['token']
  self.lazy.start('isolated',actor='isolated',publication='isolated',replica_identity=isolated_replica)
  self.lazy.execute("import os,json;f=open('/shared/isolated/reports/private','wb');f.write(b'private never shared');f.flush();os.fsync(f.fileno());f.close();print('{}')",user='1001:1001')
  self.until(lambda:any(p['private_receipt'] for p in self.lazy.status('isolated')['status']['submissions']),30)
  private=self.lazy.status('isolated');assert all(not p['shared_receipt'] for p in private['status']['submissions']);assert not self.lazy.has('b/reports/private')
  readonly_replica=identity('replica');g=self.expect('wakeups-readonly-grant','POST',self.root+'/grants',200,body={'delegate':{'replica':readonly_replica,'expires':int(time.time())+1800,'actions':['read'],'branches':['main'],'prefixes':['']}});self.tokens['readonly']=g['token']
  self.lazy.start('readonly',actor='readonly',readonly=True,replica_identity=readonly_replica)
  denial=self.lazy.execute("import os,errno,json\ntry:open('/shared/readonly/reports/bench','wb');raise AssertionError('readonly write succeeded')\nexcept OSError as e:assert e.errno==errno.EROFS;print(json.dumps(e.errno))",user='1001:1001');assert not self.lazy.status('readonly')['status']['submissions']
  quiesced={name:self.lazy.unmount(name) for name in ['fallback','isolated','readonly']}
  report['boundaries']={'quiesced':quiesced,'dropped_authenticated_hints_recovered':True,'reconnect_durable_replay':True,'revoked_socket_close_seconds':close_seconds,'current_read_denied':True,'isolated_private_only':True,'readonly_errno':denial};save()
 def native(self,label):
  mac=next((ep for ep in self.endpoints if isinstance(ep,TraceMac)),None)
  if mac is None:mac=TraceMac(self,'macos',IMAGE);self.endpoints.append(mac)
  c=mac.create(label);mac.start(c);self.until(lambda:mac.ready(c),60);self.settle(mac,c);rows=[]
  for n in range(3):
   before=self.settle(mac,c);prior={p['operation'] for p in before['mac']['status']['submissions']};body=(label+' native %02d '%n).encode()+b'x'*1024
   t=time.monotonic();mac.write(c,body,'reports/bench');written=time.monotonic()
   self.lazy.execute("import json,sys,time; s=json.load(sys.stdin); target=bytes.fromhex(s);end=time.monotonic()+20;polls=0\nwhile time.monotonic()<end:\n v=open('/shared/b/reports/bench','rb').read();polls+=1\n if v==target:break\n time.sleep(.005)\nelse:raise AssertionError('native peer timeout')\nprint(json.dumps({'polls':polls}))",body.hex(),user='1001:1001')
   visible=time.monotonic();end=self.settle(mac,c);new=[p for p in end['mac']['status']['submissions'] if p['operation'] not in prior];assert len(new)==1 and new[0]['shared_receipt'],new
   validate_receipts(new[0],before['mac']['status']['binding'],c['replica'])
   rows.append({'before_binding':before['mac']['status']['binding'],'sample':n,'save_to_visible_upper_seconds':visible-t,'write_command_seconds':written-t,'after_peer_to_ready_observation_seconds':time.monotonic()-visible,'operation':new[0]['operation'],'revision':new[0]['local_revision'],'private_receipt':new[0]['private_receipt'],'shared_receipt':new[0]['shared_receipt']});report['phases'][label]={'route':'Mac native sender→Linux mounted receiver','rows':rows,'save_to_visible_upper':stats([r['save_to_visible_upper_seconds'] for r in rows])};save()
  # Time diagnostic observation while idle, separately from every save interval.
  costs=[]
  for _ in range(3):t=time.monotonic();mac.status(c);costs.append(time.monotonic()-t)
  report['phases'][label]['idle_status_command']=stats(costs);mac.stop(c);save();print(label,json.dumps(report['phases'][label]['save_to_visible_upper']),flush=True)
 def run(self):
  i.start_service();self.wait();authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
  i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
  directory={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}};initial=b'initial latency input';entry=file_entry('reports/bench',directory['id'],initial)
  upload,rid=self.stage(self.descriptor([directory,entry]),bodies=[initial]);self.expect('profile-seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
  grant=self.expect('profile-reader-grant','POST',self.root+'/grants',200,body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}});self.tokens['worker']=grant['token']
  self.lazy=DiskLazy(self);self.lazy.start('a');self.lazy.start('b',actor='worker')
  if not a.skip_native_small:self.native('native-small')
  else:report['native_small']='not-run; explicitly skipped unaffected native sender workload'
  self.mounted('mounted-small-disk');self.atomic()
  if not a.skip_boundaries:self.boundaries()
  else:report['boundaries']='not-run; explicitly skipped previously measured unchanged authority/recovery behavior'
  save()
  # Large unchanged body is setup only, never part of a measured small edit.
  chunks=[hashlib.sha256(('profile background '+str(n)).encode()).digest()*8192 for n in range(256)];view,r=self.view();large=file_entry('large',self.tree_root['id'],b'');large['content']['version']={'size':64*1024*1024,'extents':[{'kind':'chunk','object':object_id(b),'object_size':len(b),'offset':0,'length':len(b)} for b in chunks]};r['tree']['entries'].append(large);_,receipt=self.candidate(view,r,'alice',chunks);background=self.expect('profile-background-integrate','POST',self.root+'/integrations',200,body=self.integrate_request(receipt,view));self.settle(expected_head=background['head'])
  expected=hashlib.sha256(b''.join(chunks)).hexdigest()
  for name in ['a','b']:
   found=self.lazy.execute("import json,hashlib,sys;s=json.load(sys.stdin);h=hashlib.sha256()\nwith open('/shared/'+s+'/large','rb') as f:\n while True:\n  b=f.read(1048576)\n  if not b:break\n  h.update(b)\nprint(json.dumps(h.hexdigest()))",name,user='1001:1001');assert found==expected
  self.native('native-64MiB');self.mounted('mounted-64MiB-disk')
  report['background']={'bytes':64*1024*1024,'sha256':expected,'both_mounted_caches_fully_hydrated':True}

try:
 i.setup(IMAGE);i.isolate_service_control();verify_image(i,source,host_profile='release');j=Profile();j.run();assert sources()==source['sha256'];code=0
except Exception as error:
 report['failures'].append({'reason':str(error),'trace':traceback.format_exc()});save()
 if j:
  for ep in j.endpoints:
   for c in ep.clients:
    try:i.write_json('failure-native-log.json',{'path':c['path'],'log':ep.run("print(json.dumps(open(s+'/daemon.log').read()))",c['path'])})
    except Exception as error:report['failures'].append({'diagnostic_error':str(error),'trace_source':c['path']})
finally:
 # Missing diagnostics cannot bypass normal-unmount-first owned cleanup.
 if j:
  if j.lazy:
   for name in j.lazy.mounts:
    try:i.write_json('trace-'+name+'.json',{'log':j.lazy.execute("import json,sys;print(json.dumps(open('/private/'+json.load(sys.stdin)+'/daemon.log').read()))",name)})
    except Exception as error:report['failures'].append({'diagnostic_error':str(error),'trace_source':name});code=1
  try:i.write_json('trace-service.json',{'log':i.docker('exec',i.service,'cat','/tmp/service.log',evidence=False).stdout})
  except Exception as error:report['failures'].append({'diagnostic_error':str(error),'trace_source':'service'});code=1
 try:
  if j:j.cleanup()
  # Preserve helpers/resources if normal unmount itself failed above.
  i.cleanup()
 except Exception as error:report['failures'].append({'cleanup_error':str(error)});code=1
 report.update(exit=code,seconds=time.monotonic()-started,source_unchanged=sources()==source['sha256']);save()
 print(json.dumps({'output':a.output,'exit':code,'phases':list(report['phases']),'seconds':report['seconds'],'failures':report['failures']}),flush=True)
raise SystemExit(code)
