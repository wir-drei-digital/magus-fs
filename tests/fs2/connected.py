"""One fresh Mac full -> Linux lazy -> isolated Python worker -> Mac result journey."""
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from full_native import Endpoint, NativeJourney
from linux_live import LiveJourney
from service_protocol import identity, file_entry, GROUP, REPLICA, WORKER, canonical
from service_storage import NS, ALICE, object_id

SCRIPT=b'''import csv,json,os\nfrom pathlib import Path\nrows=[int(r["value"]) for r in csv.DictReader(open("reports/data.csv"))]\nresult={"count":len(rows),"sum":sum(rows),"sum_squares":sum(x*x for x in rows),"procedure":Path("reports/procedure.txt").read_text().strip()}\nwith open("reports/result.json","w") as f:json.dump(result,f,sort_keys=True);f.flush();os.fsync(f.fileno())\n'''

def fixture():
    files={'instructions.md':b'Follow reports/procedure.txt and run python3 reports/report.py.\n','reports/procedure.txt':b'initial procedure\n','reports/data.csv':('value\n'+''.join(str(n)+'\n' for n in range(1,101))).encode(),'reports/report.py':SCRIPT,'empty':b'','executable':b'#!/bin/sh\nprintf "fixture executable\\n"\n','opaque':bytes(range(256))*4}
    chunks=[hashlib.sha256(('connected chunk '+str(n)).encode()).digest()*8192 for n in range(256)]
    files['large']=b''.join(chunks)
    return files,chunks

def inventory_code():
    return '''from pathlib import Path
root=Path(s);rows={}
for p in sorted(root.rglob('*')):
 st=p.stat();rows[str(p.relative_to(root))]={'kind':'directory' if p.is_dir() else 'file','mode':st.st_mode&511,'uid':st.st_uid,'gid':st.st_gid}
 if p.is_file():rows[str(p.relative_to(root))].update(size=st.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
print(json.dumps(rows))'''

def kernel_mount_present(path,table):
    lines=table.splitlines()
    if not lines:raise ValueError('empty kernel mount table cannot prove absence')
    paths=[]
    for line in lines:
        fields=line.split()
        if len(fields)<10 or not fields[0].isdigit() or not fields[1].isdigit() or '-' not in fields[6:]:raise ValueError('invalid kernel mount table')
        paths.append(fields[4])
    return path in paths

def public_settings(value):
    if isinstance(value,dict):return {k:('[private]' if k in ['token','ca','bodies'] else public_settings(v)) for k,v in value.items()}
    if isinstance(value,list):return [public_settings(v) for v in value]
    return value

class Mac(Endpoint):
    def __init__(self,*args):
        self.commands=[]
        super().__init__(*args)
        from infra import ROOT
        self.binary=str(ROOT/'target/release/magus-fs');self.faults=str(ROOT/'target/release/magus-fs-client-faults')
    def run(self,code,data=None):
        started=time.monotonic();record={'python':code,'settings':public_settings(data),'started_monotonic':started}
        self.commands.append(record);self.i.write_json('mac-native-commands.json',self.commands)
        try:
            result=super().run(code,data);record.update(result=result,seconds=time.monotonic()-started);return result
        except Exception as error:record.update(error=str(error),seconds=time.monotonic()-started);raise
        finally:self.i.write_json('mac-native-commands.json',self.commands)
    def start(self,c,*args,**kw):
        marker=super().start(c,*args,**kw)
        # Never race an opening owner with a separate CLI engine open.
        self.j.until(lambda:self.run("import socket\nready=False\ntry:\n sock=socket.socket(socket.AF_UNIX);sock.connect(s+'/control.sock');ready=True\nexcept (FileNotFoundError,ConnectionRefusedError):pass\nfinally:sock.close()\nprint(json.dumps(ready))",c['state']),10)
        return marker

class Lazy(LiveJourney):
    def __init__(self,j):
        # Reuse real FUSE lifecycle/helpers without re-provisioning a second authority.
        self.commands=[]
        self.i=j.i;self.image=j.image;self.tokens=j.tokens;self.mounts=[];self.holders=[];self.evidence={};self.owner=j
        self.daemon=self.i.create('container','lazy',['--network',self.i.ingress,'--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','DAC_OVERRIDE','--cap-add','SYS_CHROOT','--security-opt','apparmor=unconfined','--security-opt','no-new-privileges','--device','/dev/fuse','--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/private:rw,nosuid,nodev,mode=700,size=256m','--tmpfs','/shared:rw,nosuid,nodev,mode=755,size=16m',self.image,'python3','-c',"import os,signal,time\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
        self.i.docker('start',self.daemon)
    def execute(self,code,settings=None,user='0:0',check=True):
        started=time.monotonic();record={'python':code,'settings':public_settings(settings),'user':user,'started_monotonic':started}
        self.commands.append(record);self.i.write_json('linux-native-commands.json',self.commands)
        try:
            result=super().execute(code,settings,user,check);record.update(result=result,seconds=time.monotonic()-started);return result
        except Exception as error:record.update(error=str(error),seconds=time.monotonic()-started);raise
        finally:self.i.write_json('linux-native-commands.json',self.commands)
    def start(self,name,readonly=False,publication='shared-live',actor='alice',drop=False,lookup_barrier=False):
        settings={'name':name,'namespace':NS,'replica':WORKER if actor=='worker' else REPLICA if actor=='alice' else 'replica:'+f'{3:032x}','principal':ALICE,'group':GROUP,'token':self.tokens[actor],'ca':(self.i.control/'ca.crt').read_text(),'readonly':readonly,'publication':publication,'drop':drop,'lookup_barrier':lookup_barrier}
        self.mounts.append(name);self.i.write_json('mount-ownership.json',{'container':self.daemon,'mounts':self.mounts})
        result=self.execute('''import json,os,subprocess,sys,time
s=json.load(sys.stdin);name=s['name'];control='/private/'+name;os.mkdir(control,0o700)
def private(n,v):
 p=control+'/'+n;fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'w') as f:f.write(v if isinstance(v,str) else json.dumps(v))
 return p
def cli(*a):
 p=subprocess.run(['magus-fs',*a],capture_output=True,text=True);assert p.returncode==0,(a,p.stdout,p.stderr);return json.loads(p.stdout)
mount='/shared/'+name
config={'replica':{'replica':s['replica'],'authorities':[{'principal':s['principal'],'uid':1001,'gid':1001,'primary_group':s['group'],'groups':[s['group']],'dac_override':False,'ownership_transfer':False},{'principal':'principal:'+'c'*32,'uid':0,'gid':0,'primary_group':'group:'+'c'*32,'groups':['group:'+'c'*32],'dac_override':True,'ownership_transfer':True}],'content_roots':[mount],'cache_bytes':96*1024*1024},'root':mount,'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
cli('init','--state',control+'/state','--config',private('config',config))
profile=private('profile',{'endpoint':'https://service:8443','namespace':s['namespace'],'replica':s['replica'],'ca_file':private('ca',s['ca']),'token_file':private('token',s['token']),'publication_principal':s['principal']})
attached=cli('sync','attach','--state',control+'/state','--profile',profile,'--branch','main','--publication',s['publication'])
argv=['magus-fs-client-faults' if s['drop'] else 'magus-fs','mount','--state',control+'/state','--revision',attached['binding']['view']['revision'],'--mountpoint',mount,'--mode','read-only' if s['readonly'] else 'private']
env=os.environ.copy()
if s['drop']:env['MAGUS_TEST_DROP_WSS_HINTS']='1'
if s['lookup_barrier']:env.update(MAGUS_TEST_LOOKUP_EPOCH_NAME='live',MAGUS_TEST_LOOKUP_EPOCH_BARRIER=control+'/lookup-epoch')
log=open(control+'/daemon.log','w');p=subprocess.Popen(argv,stdout=log,stderr=log,env=env);private('pid',str(p.pid))
deadline=time.monotonic()+10
while not os.path.ismount(mount):
 assert p.poll() is None,(p.poll(),open(control+'/daemon.log').read())
 assert time.monotonic()<deadline,'mount timeout'
 time.sleep(.05)
print(json.dumps({'pid':p.pid,'binding':attached['binding'],'attach_counters':attached['counters']}))''',settings)
        if publication=='shared-live':self.until(lambda:self.status(name)['live']['applied'])
        return result
    def status(self,name='live'):return self.cli('sync','status','--state','/private/'+name+'/state')
    def read(self,path):return self.execute("import json,sys;print(json.dumps(open('/shared/'+json.load(sys.stdin),'rb').read().hex()))",path,user='1001:1001')
    def has(self,path):return self.execute("import os,json,sys;print(json.dumps(os.path.exists('/shared/'+json.load(sys.stdin))))",path,user='1001:1001')
    def save(self):self.i.write_json('lazy-evidence.json',self.evidence)
    def cleanup(self):
        created=[];intent_rows=[];original=list(self.mounts)
        for name in original:
            observed=self.execute("import json,os,sys\nfrom pathlib import Path\nsys.path.insert(0,'/src/tests/fs2');from connected import kernel_mount_present\nname=json.load(sys.stdin);mount='/shared/'+name;pidfile='/private/'+name+'/pid';pid=int(open(pidfile).read()) if os.path.exists(pidfile) else None;matches=[]\nfor p in Path('/proc').glob('[0-9]*/cmdline'):\n try:\n  args=p.read_bytes().split(b'\\0')\n  if b'--mountpoint' in args and args[args.index(b'--mountpoint')+1]==mount.encode():matches.append(int(p.parent.name))\n except (OSError,IndexError):pass\nprint(json.dumps({'mount':mount,'mounted':kernel_mount_present(mount,Path('/proc/self/mountinfo').read_text()),'stat_ismount':os.path.ismount(mount),'pid':pid,'pid_record':os.path.exists(pidfile),'alive':bool(pid and os.path.exists('/proc/'+str(pid))),'matching_mount_processes':matches}))",name)
            if observed['mounted']:created.append(name)
            else:
                assert not observed['alive'] and not observed['matching_mount_processes'],('unresolved starting mount; helpers retained',observed)
                intent_rows.append({'mount':observed['mount'],'created':False,'intent_only':True,'observed':observed,'unmount':None,'still_mounted':False,'pid':observed['pid'],'exited':True,'reaped':True})
        self.mounts=created
        try:
            super().cleanup()
            absence=self.execute("import json,sys;from pathlib import Path;sys.path.insert(0,'/src/tests/fs2');from connected import kernel_mount_present;paths=json.load(sys.stdin);table=Path('/proc/self/mountinfo').read_text();print(json.dumps({p:kernel_mount_present(p,table) for p in paths}))",['/shared/'+n for n in original]);assert not any(absence.values());self.i.write_json('kernel-mount-cleanup.json',{'verified':True,'remaining':absence})
            rows=json.loads((self.i.output/'mount-cleanup.json').read_text())
            self.i.write_json('mount-cleanup.json',[{**r,'created':True} for r in rows]+intent_rows)
        finally:self.mounts=original


class Connected(NativeJourney):
    def __init__(self,i,image,number):
        super().__init__(i,image,['macos','linux']);self.lazy=None;self.result={'id':str(number),'fresh_owner':i.owner,'platforms':['macos','linux'],'assertions':{'native':{},'lazy':{},'security':{},'faults':{}},'receipts':[],'saves':[]};self.archived_logs=[]
    def save_result(self):self.i.write_json('journey.json',self.result)
    def assertion(self,group,name,value,**observed):
        assert value,(group,name,observed)
        self.result['assertions'][group][name]=True
        self.result.setdefault('observed',{})[group+'.'+name]=observed;self.save_result()
    def log(self):return self.i.docker('exec',self.i.service,'cat','/tmp/service.log',evidence=False).stdout
    def transfers(self):
        out={k:0 for k in ['install_body','backend_put_body','backend_verification_body','authorized_body']}
        for line in self.log().splitlines():
            fields=line.split()
            if len(fields)==3 and fields[0]=='fs2_transfer':out[fields[1]]+=int(fields[2])
        return out
    def service_start(self):
        self.i.docker('exec','-d','-e','MAGUS_TEST_TRANSFER_LOG=1',self.i.service,'sh','-c','echo $$ > /tmp/service.pid; exec magus-fs-service-faults serve /control/service.json >> /tmp/service.log 2>&1')
        self.i.port=int(self.i.docker('port',self.i.service,'8443/tcp').stdout.strip().split(':')[-1]);self.wait()
    def restart(self):
        before=self.i.port
        self.i.docker('exec',self.i.service,'python3','-c',"import os,signal;pid=int(open('/tmp/service.pid').read());assert os.readlink('/proc/'+str(pid)+'/exe')=='/usr/local/bin/magus-fs-service-faults';os.kill(pid,signal.SIGTERM)")
        self.until(lambda:self.i.docker('exec',self.i.service,'python3','-c',"import os;print(int(not os.path.exists('/proc/'+open('/tmp/service.pid').read().strip())))",evidence=False).stdout.strip()=='1',10)
        self.service_start();assert before==self.i.port
    def receipt(self,p,applied,original_binding):
        req=p['request'];private=p['private_receipt'];shared=p['shared_receipt'];integration=p['integration']
        assert private and shared and integration
        assert private['receipt']==integration['candidate_receipt'] and shared['submitted_revision']==p['local_revision']
        assert p['applied_revision']==applied
        assert req['original_view']==original_binding['view']['view'] and req['original_head']==original_binding['view']['head']
        record={'operation':p['operation'],'revision':p['local_revision'],'original_view':original_binding['view']['view'],'original_head':original_binding['view']['head'],'private':private,'private_receipt':private['receipt'],'shared':{**shared,'candidate_receipt':integration['candidate_receipt']},'integration':integration,'applied':applied,'raw_progress':p}
        self.result['receipts'].append(record);return len(self.result['receipts'])-1
    def run(self):
        self.service_start()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        files,chunks=fixture();reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}}
        emptydir={'path':'empty-dir','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}}
        entries=[reports,emptydir]
        bodies=[]
        for path,body in files.items():
            e=file_entry(path,reports['id'] if path.startswith('reports/') else self.tree_root['id'],body);e['mode']=0o755 if path=='executable' else 0o600
            if path=='large':e['content']['version']['extents']=[{'kind':'chunk','object':object_id(part),'object_size':len(part),'offset':0,'length':len(part)} for part in chunks];bodies.extend(chunks)
            elif body:bodies.append(body)
            entries.append(e)
        upload,rid=self.stage(self.descriptor(entries),bodies=bodies);seed=self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        expected={path:{'sha256':hashlib.sha256(body).hexdigest(),'size':len(body)} for path,body in files.items()};self.i.write_json('expected.json',{'files':expected,'report_math':{'count':100,'sum':5050,'sum_squares':338350},'seed':seed})
        readonly_view,_=self.view('readonly')
        code,grant=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['reports']}});assert code==200
        self.tokens['worker']=grant['token'];self.worker_credential=grant['credential'];self.result['worker_scope']={'replica':WORKER,'credential':grant['credential'],'branches':['main'],'prefixes':['reports'],'publication':'isolated','meaning':'independent private candidate lineage anchored to authorized main view'}
        bootstrap_transfer=self.transfers()
        mac=Mac(self,'macos',self.image);self.endpoints.append(mac);c=mac.create('full');bootstrap=time.monotonic();mac.start(c,drop_hints=True);self.until(lambda:mac.ready(c),60);self.result['bootstrap_seconds']=time.monotonic()-bootstrap;mac.stop(c)
        inv=mac.run(inventory_code(),c['root']);assert all(inv[p]['sha256']==v['sha256'] and inv[p]['size']==v['size'] for p,v in expected.items());assert inv['empty-dir']['kind']=='directory' and inv['executable']['mode']==0o755
        self.result['full_bootstrap_transfer']={k:self.transfers()[k]-bootstrap_transfer[k] for k in bootstrap_transfer}
        self.assertion('native','offline',True,inventory=inv,owner_stopped=True)
        mac.start(c,drop_hints=True);self.until(lambda:mac.ready(c))
        self.lazy=Lazy(self);lazy=self.lazy
        before=self.transfers();mounted=lazy.start('live',drop=True)
        self.assertion('lazy','metadata_zero',self.transfers()['authorized_body']==before['authorized_body'] and mounted['attach_counters']['downloaded_body_bytes']==0,mount=mounted,counters=self.transfers())
        lazy.execute("import json,os;print(json.dumps(sorted(os.listdir('/shared/live'))))",user='1001:1001')
        self.assertion('lazy','metadata_zero',self.transfers()['authorized_body']==before['authorized_body'],after_listing=self.transfers())
        def ranges():return lazy.execute("import json,os,hashlib;f=os.open('/shared/live/large',os.O_RDONLY);v=[os.pread(f,4096,0),os.pread(f,4096,64*1024*1024-4096)];os.close(f);print(json.dumps([hashlib.sha256(b).hexdigest() for b in v]))",user='1001:1001')
        expected_ranges=[hashlib.sha256(files['large'][:4096]).hexdigest(),hashlib.sha256(files['large'][-4096:]).hexdigest()]
        start=self.transfers();assert ranges()==expected_ranges;cold=self.transfers()['authorized_body']-start['authorized_body'];self.assertion('lazy','cold_bounded',0<cold<=2*1024*1024,bytes=cold,hashes=expected_ranges)
        start=self.transfers();assert ranges()==expected_ranges;warm=self.transfers()['authorized_body']-start['authorized_body'];self.assertion('lazy','warm_zero',warm==0,bytes=warm)
        full=lazy.execute("import json,hashlib;print(json.dumps(hashlib.sha256(open('/shared/live/large','rb').read()).hexdigest()))",user='1001:1001');self.assertion('lazy','full_hash',full==expected['large']['sha256'],sha256=full)
        baseline=self.transfers();start=time.monotonic();new_procedure=b'connected revised procedure\n';before_status=mac.status(c);mac.write(c,new_procedure,'reports/procedure.txt')
        self.save_target(mac,c,lazy,before_status,start,new_procedure,measure=False)
        self.assertion('native','live',lazy.read('live/reports/procedure.txt')==new_procedure.hex(),mac=mac.status(c),linux=lazy.status())
        procedure_transfer=self.transfers()['install_body']-baseline['install_body'];assert 0<procedure_transfer<=2*1024*1024
        for n in range(0 if getattr(self,"probe",False) else 20):
            before_status=mac.status(c);start=time.monotonic();body=('serialized procedure %02d\n'%n).encode();mac.write(c,body,'reports/procedure.txt');self.save_target(mac,c,lazy,before_status,start,body,measure=True)
        if not getattr(self,'probe',False):self.result['latency']={k:{'p50':sorted(s[k] for s in self.result['saves'])[9],'p95':sorted(s[k] for s in self.result['saves'])[18]} for k in ['capture','private','shared','visible']};self.result['environment']={'visibility_deadline':15,'target_drain_deadline':60,'scan_seconds':2,'poll_seconds':1,'sampling':'observed upper bounds; serialized exact target revision drains; nearest-rank p50/p95','universal_sla':False}
        current_body=new_procedure if getattr(self,"probe",False) else body
        self.worker(mac,c,lazy,current_body)
        self.security(lazy,readonly_view)
        self.faults(mac,c,lazy)
        logs=mac.run("print(json.dumps(open(s+'/daemon.log').read()))",c['path']);linux_logs=lazy.execute("import json;print(json.dumps(open('/private/live/daemon.log').read()))")
        self.i.write_json('hint-boundaries.json',{'native':logs,'linux':linux_logs})
        self.assertion('faults','watch_event','test_drop_native_hint' in logs,dropped_actual_native_callback=True,scan_recovered=True)
        self.assertion('faults','wss_hint','test_drop_wss_hint cursor=' in linux_logs,dropped_authenticated_text_frame=True,durable_poll_recovered=True)
        total=self.transfers();self.result['transfer'].update(procedure_body_bytes=procedure_transfer,backend_verification_bytes=total['backend_verification_body'],retries=self.result.get('fault_retries',0),unchanged_chunks_reused=True,all_physical_body_counters=total)
        self.i.write_json('service-transfer.log.json',self.log());self.save_result()
    def save_target(self,mac,c,lazy,before,start,body,measure):
        prior={p['operation'] for p in before['status']['submissions']}
        p=self.until(lambda:next((p for p in mac.status(c)['status']['submissions'] if p['operation'] not in prior),None));capture=time.monotonic()-start
        private=mac.cli(c,'sync','drain','--revision',p['local_revision'],'--level','private-remote','--deadline-ms','60000')['progress'];private_time=time.monotonic()-start;assert private['private_receipt']['submitted_revision']==p['local_revision']
        shared=mac.cli(c,'sync','drain','--revision',p['local_revision'],'--level','shared','--deadline-ms','60000')['progress'];shared_time=time.monotonic()-start
        self.until(lambda:lazy.read('live/reports/procedure.txt')==body.hex());self.until(lambda:mac.ready(c,shared['shared_receipt']['head']));visible=time.monotonic()-start
        final=mac.cli(c,'sync','drain','--revision',p['local_revision'],'--level','applied','--deadline-ms','60000')['progress'];assert final['local_revision']==p['local_revision'];applied=mac.status(c)['native']['status']['Ready']['revision'];index=self.receipt(final,applied,before['status']['binding'])
        if measure:self.result['saves'].append({'capture':capture,'private':private_time,'shared':shared_time,'visible':visible,'receipt_index':index,'local_revision':p['local_revision'],'operation':p['operation']})
        self.save_result()
    def worker(self,mac,c,lazy,procedure):
        mounted=lazy.start('worker',publication='isolated',actor='worker');before=self.transfers();head=mac.status(c)['status']['binding']['view']['head'];assert not mac.exists(c['root']+'/reports/result.json') and not lazy.has('live/reports/result.json')
        output=lazy.execute("import json,subprocess,hashlib,os;v=subprocess.run(['python3','reports/report.py'],cwd='/shared/worker',capture_output=True,text=True);assert v.returncode==0,(v.stdout,v.stderr);body=open('/shared/worker/reports/result.json','rb').read();st=os.stat('/shared/worker/reports/result.json');print(json.dumps({'body':body.hex(),'sha256':hashlib.sha256(body).hexdigest(),'uid':st.st_uid,'gid':st.st_gid}))",user='1001:1001')
        expected=json.dumps({'count':100,'sum':5050,'sum_squares':338350,'procedure':procedure.decode().strip()},sort_keys=True).encode();assert output['body']==expected.hex() and output['uid']==1001
        operation=identity('operation');revision=lazy.cli('checkpoint','--state','/private/worker/state','--operation-id',operation)['revision'];enqueued=lazy.cli('sync','run','--state','/private/worker/state','--revision',revision,'--operation-id',operation,'--enqueue-only','true');local=next(p for p in enqueued['status']['submissions'] if p['operation']==operation);assert not local['private_receipt'] and not local['shared_receipt']
        drained=lazy.cli('sync','drain','--state','/private/worker/state','--revision',revision,'--level','private-remote','--deadline-ms','60000');private=drained['progress'];assert private['state']=='PrivateRemote' and private['private_receipt']['replica']==WORKER and private['private_receipt']['original_view']==mounted['binding']['view']['view'] and private['private_receipt']['original_head']==head
        assert not mac.exists(c['root']+'/reports/result.json') and not lazy.has('live/reports/result.json');assert mac.status(c)['status']['binding']['view']['head']==head
        delta=self.transfers()['install_body']-before['install_body'];assert 0<delta<=2*1024*1024 and drained['counters']['logical_unique_upload_bytes']==len(expected)
        # Retain exact worker private state before the explicitly authorized integration.
        worker_before=lazy.status('worker')['status']['submissions'];self.result['worker_private']={'local':local,'private':private,'output':output,'expected_hash':hashlib.sha256(expected).hexdigest(),'shared_unchanged':True,'drain':drained}
        integrated=lazy.cli('sync','integrate','--state','/private/worker/state','--revision',revision,'--expected-head',head)['progress'];assert integrated['shared_receipt'] and integrated['integration']['expected_head']==head and integrated['integration']['candidate_receipt']==private['private_receipt']['receipt']
        self.until(lambda:mac.exists(c['root']+'/reports/result.json') and mac.read(c,'reports/result.json')==expected.hex());self.until(lambda:mac.ready(c,integrated['shared_receipt']['head']));self.until(lambda:lazy.read('live/reports/result.json')==expected.hex())
        view,descriptor=self.view();report=next(e for e in descriptor['tree']['entries'] if e['path']=='reports/result.json');assert report['owner']==ALICE
        stored=json.loads(self.i.sql("SELECT request FROM operations WHERE operation='"+operation+"';"));assert stored==private['request'] and stored['replica']==WORKER
        audit=json.loads(self.i.sql("SELECT json_build_object('credential',credential,'principal',principal,'replica',replica)::text FROM operations WHERE operation='"+operation+"';"));assert audit=={'credential':self.worker_credential,'principal':ALICE,'replica':WORKER}
        controls=lazy.execute("import json,os;rows={}\nfor path in ['/control/service.json','/private/worker/token']:\n try:open(path,'rb').read();rows[path]=0\n except OSError as e:rows[path]=e.errno\nassert rows['/control/service.json']==2 and rows['/private/worker/token']==13;assert not any(k.startswith('AWS_') for k in os.environ);print(json.dumps(rows))",user='1001:1001')
        self.result['worker_controls_denied']=controls
        self.result['worker_integrated']={'progress':integrated,'mac_applied':mac.status(c),'linux_applied':lazy.status(),'entry':report,'original_request_sql':stored,'authenticated_attribution_sql':audit,'retained_private_before':worker_before};self.result['transfer']={'report_body_bytes':delta,'logical_unique_report_bytes':drained['counters']['logical_unique_upload_bytes']};self.assertion('native','worker',True,exact_expected_hash=hashlib.sha256(expected).hexdigest(),replica=WORKER,credential=self.worker_credential,owner=ALICE)
    def security(self,lazy,old_readonly_view):
        self.expect('cross-namespace-api','POST',self.root+'/views',404,body={'branch':'main'},actor='bob');self.assertion('security','api',True)
        view,_=self.view('worker');self.expect('raw-large-hash-no-authority','GET',self.root+'/views/'+view['view']+'/objects/'+object_id(fixture()[1][0]),404,actor='worker');upload=self.create();self.expect('invalid-content-hash-denied','PUT',self.root+'/uploads/'+upload+'/objects/'+object_id(b'expected-hash-body'),400,{'code':'hash_mismatch'},raw=b'wrong hash body');self.assertion('security','hash',True)
        self.expect('old-readonly-view-history-denied','GET',self.root+'/views/'+old_readonly_view['view']+'/descriptor',404,actor='readonly');self.assertion('security','history',True)
        self.expect('readonly-upload-denied','POST',self.root+'/uploads',404,body={},actor='readonly');lazy.start('readonly',readonly=True,actor='readonly')
        errnos=lazy.execute("import json,errno\nrows={}\nfor name,fn in [('write',lambda:open('/shared/readonly/reports/procedure.txt','wb')),('create',lambda:open('/shared/readonly/reports/denied','wb')),('unlink',lambda:__import__('os').unlink('/shared/readonly/reports/result.json'))]:\n try:fn();rows[name]=0\n except OSError as e:rows[name]=e.errno\nassert set(rows.values())=={errno.EROFS};print(json.dumps(rows))",user='1001:1001');self.assertion('security','readonly',True,errno=errnos)
        self.expect('revoke-worker','POST',self.root+'/grants',200,body={'revoke':self.worker_credential});self.expect('revoked-view','POST',self.root+'/views',401,body={'branch':'main'},actor='worker');self.expect('revoked-original-result','GET',self.op_path(self.result['worker_private']['private']['request']),401,actor='worker')
        self.until(lambda:not lazy.status('worker')['live']['authorized'])
        denied=lazy.execute("import json,errno\nrows={}\nfor name,fn in [('read',lambda:open('/shared/worker/reports/result.json','rb').read()),('write',lambda:open('/shared/worker/reports/result.json','wb'))]:\n try:fn();rows[name]=0\n except OSError as e:rows[name]=e.errno\nassert set(rows.values())=={errno.EACCES};print(json.dumps(rows))",user='1001:1001');self.assertion('security','revoked',True,errno=denied)
    def faults(self,mac,c,lazy):
        before=mac.status(c);self.restart();self.until(lambda:mac.ready(c,before['status']['binding']['view']['head']));self.assertion('faults','service_restart',True,same_endpoint=self.i.port)
        mac.stop(c,kill=True);retained=mac.status(c)['status']['submissions'];assert retained==before['status']['submissions'];mac.start(c,drop_hints=True);self.until(lambda:mac.ready(c));self.assertion('faults','client_restart',True,exact_submissions=retained)
        # Discard a real committed candidate HTTPS response, restart actual service,
        # recover the exact operation, and replay frozen original request.
        view,r=self.view();new=b'committed response discarded procedure\n';entry=next(e for e in r['tree']['entries'] if e['path']=='reports/procedure.txt');entry['content']=file_entry(entry['path'],entry['parent'],new)['content'];r['parents']=[view['revision']];r['replica']=REPLICA;r['operation']=identity('operation');upload,rid=self.stage(r,bodies=[new]);request={'operation':r['operation'],'replica':REPLICA,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
        self.i.write_json('discarded-ack-candidate.json',{'canonical_hex':canonical(r).hex(),'request':request});self.drop_response(self.root+'/candidates',request,'alice');self.restart();private=self.expect('committed-ack-exact-result','GET',self.op_path(request),200);self.expect('committed-ack-exact-replay','POST',self.root+'/candidates',200,private,body=request);assert private['original_head']==request['original_head'] and private['submitted_revision']==rid
        changed={**request,'original_head':'0'*32};self.expect('same-operation-wrong-base','POST',self.root+'/candidates',409,body=changed)
        integrated=self.expect('committed-ack-integrate','POST',self.root+'/integrations',200,body=self.integrate_request(private,view));self.until(lambda:mac.ready(c,integrated['head']));self.until(lambda:lazy.read('live/reports/procedure.txt')==new.hex());self.result['fault_retries']=1;self.assertion('faults','committed_ack',True,request=request,private=private,shared=integrated,committed_sql=True,discarded_response=True)
    def cleanup(self):
        # Failed normal unmount preserves serving containers and backend helpers.
        if self.lazy:self.lazy.cleanup()
        super().cleanup()
