"""Import-safe bounded collaboration diagnostic."""
def profile_matrix():
 return [{"background":n,"size":s,"enabled":True} for n in [50,500] for s in [24,1024,16384]]+[{"background":500,"size":1024,"enabled":True} for _ in range(6)]+[{"background":500,"size":1024,"enabled":False} for _ in range(2)]
def validate_passive_capture(row):
 assert not row["status_polls"]
 assert row["exact_shared_ns"]>=row["save_started_ns"] and row["exact_applied_ns"]>=row["save_started_ns"]
 post=row["post_applied_read"];assert post and post["fresh_after_applied_ns"]>=max(row["exact_shared_ns"],row["exact_applied_ns"])
 assert post["uid"]==1001 and post["bytes"]==row["size"] and post["sha256"]==row["sha256"]
 return True


def profile_docker_args(args):
 if args[0:1]==('exec',) and args[1:2] in [('-d',),('-i',)]:return ('exec',args[1],'-e','MAGUS_LATENCY_TRACE=1','-e','MAGUS_METADATA_PROFILE=1',*args[2:])
 return args


def main():
 import argparse,hashlib,json,secrets,time,traceback
 from pathlib import Path
 from infra import OwnedInfra,InfrastructureUnavailable
 from full_native import NativeJourney
 from latency_support import DiskLazy,validate_receipts
 from latency_acceptance import acceptance_s3_capacity,backend_diagnostics,WATCH,WRITE
 from provenance import capture,verify_linux_image
 from service_protocol import identity,file_entry,GROUP,REPLICA,WORKER
 from service_storage import NS,ALICE
 args=argparse.ArgumentParser();args.add_argument('--mode',choices=['profile'],required=True);args.add_argument('--image',required=True);args.add_argument('--output',required=True);a=args.parse_args()
 assert a.image.startswith('sha256:') and len(a.image)==71,'immutable image required'
 class TraceInfra(OwnedInfra):
  def create(self,kind,suffix,args):return super().create(kind,suffix,acceptance_s3_capacity('acceptance',kind,suffix,args))
  def docker(self,*args,**kw):
   return super().docker(*profile_docker_args(args),**kw)
 i=TraceInfra(a.output);i.runtime_profile='release';j=None;endpoints=[];rows=[];phase='preflight';code=1
 (i.output/'driver.py').write_bytes(Path(__file__).read_bytes())
 i.write_json('diagnostic-plan.json',{'matrix':profile_matrix(),'bounds':{'observation_seconds':25,'settle_seconds':60},'qualification':False,'controls':'same daemon, counters switched outside timed saves'})
 def logread(e,n,offset=0,marker=None):
  return e.execute("import json,sys,time,os;s=json.load(sys.stdin)\nwith open('/private/'+s['name']+'/daemon.log','rb') as f:f.seek(s['offset']);text=f.read().decode(errors='replace')\nr={'guest_ns':time.monotonic_ns(),'log':text}\nif s.get('marker') and os.path.exists(s['marker']+'-result'):r['ordinary_observer']=json.load(open(s['marker']+'-result'))\nprint(json.dumps(r))",{'name':n,'offset':offset,'marker':marker})
 def events(log,owner):
  out=[]
  for line in log.splitlines():
   if line.startswith('latency '):
    e=dict(x.split('=',1) for x in line.split()[1:]);e.update(owner=owner,monotonic_ns=int(e['monotonic_ns']));out.append(e)
  return out
 def save():i.write_json('profile.json',{'diagnostic_only':True,'rows':rows})
 def snap(label):
  result={'phase':phase,'errors':[]}
  for n,e in endpoints:
   try:result[n]={'status':e.status(n),'log':logread(e,n),'history':e.cli('history','--state','/private/'+n+'/state')}
   except Exception as error:result['errors'].append({'endpoint':n,'error':str(error)})
  try:
   result['operations']=json.loads(i.sql("SELECT coalesce(json_agg(json_build_object('operation',operation,'kind',kind,'digest',digest,'request',request::json,'result',result::json,'status',status,'submitted_revision',submitted_revision,'derived_revision',derived_revision,'view_id',view_id,'receipt',receipt)),'[]'::json) FROM operations;"))
   result['views']=json.loads(i.sql("SELECT coalesce(json_agg(json_build_object('view',id,'head',head,'projected_revision',projected_revision,'full_revision',full_revision,'descriptor',convert_from(descriptor,'UTF8')::json)),'[]'::json) FROM views;"))
  except Exception as error:result['errors'].append({'service':str(error)})
  i.write_json(label+'.json',result)
 def settle(expected=None):
  deadline=time.monotonic()+60
  while time.monotonic()<deadline:
   statuses={n:e.status(n) for n,e in endpoints};heads=[s['status']['binding']['view']['head'] for s in statuses.values()]
   if all(s['live']['applied'] and s['live']['authorized'] for s in statuses.values()) and len(set(heads))==1 and (expected is None or heads[0]==expected):return statuses
   time.sleep(.1)
  raise AssertionError('existing60s settle deadline')
 try:
  i.preflight();source=capture(i);i.setup(a.image);i.isolate_service_control();i.start_service();verify_linux_image(i,source)
  j=NativeJourney(i,a.image,[]);j.wait();j.tokens['alice']=secrets.token_hex(32);expiry=int(time.time())+7200
  authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
  i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':j.tokens['alice'],'expires':expiry,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':j.tree_root}])
  directory={'path':'reports','id':identity('entry'),'parent':j.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':493,'content':{'kind':'directory'}};old=b'initial acceptance input';entries=[directory,file_entry('reports/bench',directory['id'],old)]
  upload,rid=j.stage(j.descriptor(entries),bodies=[old]);j.expect('profile-seed','POST',j.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
  j.tokens['worker']=j.expect('profile-grant','POST',j.root+'/grants',200,body={'delegate':{'replica':WORKER,'expires':expiry-3600,'actions':['read','write','integrate','history'],'branches':['main'],'prefixes':['']}})['token']
  for n,actor in [('a','alice'),('b','worker')]:
   e=DiskLazy(j,'profile-'+n);endpoints.append((n,e));e.start(n,actor=actor)
   assert any(line.startswith('metadata_profile ') for line in logread(e,n)['log'].splitlines()),'startup metadata profile opt-in absent'
  background=0
  for number,spec in enumerate(profile_matrix()):
   phase='sample-'+str(number);size=spec['size']
   if spec['background']!=background:
    phase='grow-'+str(spec['background']);view,revision=j.view();bodies=[]
    for k in range(background,spec['background']):
     body=(f'# Synthetic note {k}\nOwned latency fixture.\n'.encode()*20)[:1024];revision['tree']['entries'].append(file_entry(f'note-{k:03d}.md',j.tree_root['id'],body));bodies.append(body)
    _,receipt=j.candidate(view,revision,'alice',bodies);shared=j.expect(phase,'POST',j.root+'/integrations',200,body=j.integrate_request(receipt,view));settle(shared['head']);background=spec['background']
    expected=[hashlib.sha256((f'# Synthetic note {k}\nOwned latency fixture.\n'.encode()*20)[:1024]).hexdigest() for k in range(background)]
    for n,e in endpoints:
     observed=e.execute("import json,hashlib;print(json.dumps([hashlib.sha256(open('/shared/"+n+"/note-%03d.md'%k,'rb').read()).hexdigest() for k in range("+str(background)+")]))",user='1001:1001');assert observed==expected
   if number==12:
    for n,e in endpoints:
     switch=e.cli('sync','metadata-profile','--state','/private/'+n+'/state','--enabled','false');assert switch['enabled'] is False
   before=settle();prior={s['operation'] for s in before['a']['status']['submissions']}
   offsets={n:e.execute("import json,os;print(json.dumps(os.path.getsize('/private/"+n+"/daemon.log')))") for n,e in endpoints}
   value=(hashlib.sha256(('collaboration-profile-'+str(number)).encode()).digest()+b'.'*size)[:size];digest=hashlib.sha256(value).hexdigest();marker='/tmp/collaboration-read-'+secrets.token_hex(8);sender=endpoints[0][1];receiver=endpoints[1][1]
   observer=receiver.execute("import json,subprocess,sys;code,s=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code,json.dumps(s)],stdout=open(s['marker']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",[WATCH,{'body':value.hex(),'marker':marker,'deadline_seconds':25}],user='1001:1001');receiver.holders.append(observer)
   i.write_json('ordinary-observer-ownership.json',{'container':receiver.daemon,'pids':receiver.holders,'records':[{'number':r['number'],'pid':r['observer_pid'],'marker':r['marker']} for r in rows]+[{'number':number,'pid':observer,'marker':marker}]})
   j.until(lambda:receiver.execute("import json,os,sys;print(json.dumps(os.path.exists(json.load(sys.stdin)+'-ready')))",marker),5)
   row=dict(spec,number=number,before=before,log_offsets=offsets,observer_pid=observer,marker=marker,expected_sha256=digest,status_polls=[]);rows.append(row);save()
   try:
    row.update(sender.execute(WRITE,{'body':value.hex(),'atomic':False,'path':'/shared/a/reports/bench'},user='1001:1001'));deadline=time.monotonic()+25;captured=None
    while time.monotonic()<deadline:
     logs={n:logread(e,n,offsets[n],marker if n=='b' else None) for n,e in endpoints}
     row.update(logs['b'].get('ordinary_observer',{}));es=events(logs['a']['log'],'a')+events(logs['b']['log'],'b');shared=[x for x in es if x['owner']=='a' and x['stage']=='shared_receipt'];head=shared[-1]['head'] if shared else None
     applied={n:[x for x in es if x['owner']==n and x['stage']=='applied' and x['head']==head] for n,e in endpoints}
     if head and all(applied.values()) and row.get('fresh_read_ns'):captured={'head':head,'applied':applied,'logs':logs};break
     if row.get('timeout') or row.get('error'):raise AssertionError('ordinary observer failed')
     time.sleep(.1)
    assert captured,'existing25s exact appended Applied/read deadline';row['captured_appended_applied']=captured;assert row['sha256']==digest
    after={n:e.status(n) for n,e in endpoints};subs=[s for s in after['a']['status']['submissions'] if s['operation'] not in prior];assert len(subs)==1 and subs[0]['shared_receipt'];progress=subs[0];validate_receipts(progress,before['a']['status']['binding'],REPLICA)
    assert progress['shared_receipt']['head']==captured['head'] and after['b']['live']['applied'] and after['b']['live']['authorized'];revision=after['b']['status']['binding']['view']['revision'];assert after['b']['status']['binding']['view']['head']==captured['head'] and captured['applied']['b'][-1]['revision']==revision
    serviceevents=[x for x in events(i.docker('exec',i.service,'cat','/tmp/service.log',evidence=False).stdout,'service') if x.get('head')==captured['head'] and x.get('operation')==progress['shared_receipt']['operation'] and x['stage']=='shared_committed'];assert len(serviceevents)==1
    stamp=serviceevents[0]['monotonic_ns'];peer=captured['applied']['b'][-1]['monotonic_ns'];row.update(progress=progress,after=after,peer_projected_revision=revision,events=es+serviceevents,exact_shared_ns=stamp,exact_applied_ns=peer)
    post=receiver.execute("import json,hashlib,time,os;v=open('/shared/b/reports/bench','rb').read();print(json.dumps({'fresh_after_applied_ns':time.monotonic_ns(),'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest(),'uid':os.geteuid()}))",user='1001:1001');row['post_applied_read']=post;validate_passive_capture(row)
    row['seconds']=(max(stamp,peer,post['fresh_after_applied_ns'])-row['save_started_ns'])/1e9;row['firstbytes_seconds']=(row['fresh_read_ns']-row['save_started_ns'])/1e9;row['target_pass']=row['seconds']<=.5
    row['metadata_profiles']={}
    for n in ['a','b']:
     aggregate=[json.loads(line[len('metadata_profile '):]) for line in logs[n]['log'].splitlines() if line.startswith('metadata_profile ')];exact=[x for x in aggregate if x['revision']==captured['applied'][n][-1]['revision'] and x['ok']];assert len(exact)==1;row['metadata_profiles'][n]=exact[0]
    row['qualified']=True;print(json.dumps({k:row[k] for k in ['number','size','background','enabled','seconds','firstbytes_seconds','target_pass']}),flush=True)
   except Exception as error:row.update(error=str(error),qualified=False);raise
   finally:save();snap('sample-'+str(number)+'-every-outcome')
  verify_linux_image(i,source);code=0
 except InfrastructureUnavailable as error:
  code=2;i.write_json('unavailable.json',{'phase':phase,'error':str(error)})
 except Exception as error:i.write_json('failure.json',{'phase':phase,'error':str(error),'trace':traceback.format_exc()});print(traceback.format_exc(),flush=True)
 finally:
  if j:snap('precleanup-every-outcome')
  backend_diagnostics(i,'precleanup')
  cleanup_errors=[]
  for n,e in endpoints:
   try:
    e.cleanup()
    for filename in ['mount-cleanup.json','kernel-mount-cleanup.json','mount-ownership.json','holder-cleanup.json']:
     f=i.output/filename
     if f.exists():(i.output/(n+'-'+filename)).write_bytes(f.read_bytes())
   except Exception as error:cleanup_errors.append({'endpoint':n,'error':str(error)})
  if not cleanup_errors:i.cleanup()
  else:code=1;i.write_json('endpoint-cleanup-errors.json',cleanup_errors)
  i.write_json('result.json',{'exit':code,'diagnostic_only':True,'saves':len(rows),'qualified':sum(bool(r.get('qualified')) for r in rows),'cleanup_errors':cleanup_errors})
 return code

if __name__=='__main__':raise SystemExit(main())
