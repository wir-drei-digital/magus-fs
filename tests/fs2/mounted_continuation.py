#!/usr/bin/env python3
"""Owned real mounted continuation gate. No manual publisher drains or simulated mounts."""
import argparse, hashlib, json, secrets, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable
from provenance import capture, verify_linux_image
from full_native import NativeJourney, Endpoint
from latency_support import DiskLazy
from latency_acceptance import acceptance_s3_capacity, WRITE
from service_protocol import identity, file_entry, GROUP, REPLICA, WORKER
from service_storage import NS, ALICE

CASES = ['normal-atomic', 'held-own-atomic', 'foreign-never-issued', 'mmap-after-fd-close', 'overlap-explicit-recovery', 'restart-retains-policy', 'merge-produced-own', 'lost-response-restart', 'current-denial-retention', 'native-route-unregistered', 'two-ordinary-agents', 'old-client-schema-refusal']

def currently_blocked(status):
    return bool(status.get('recovery')) and isinstance(status.get('readiness'),dict) and 'Blocked' in status['readiness']

class Journey(NativeJourney):
    def __init__(self, infra, image):
        super().__init__(infra, image, [])
        self.endpoints = {}
        self.observations = []
        self.stopped = set()
        self.native = None
        self.mappings = []
    def record(self, case, **evidence):
        self.observations.append({'case':case, **evidence})
        self.i.write_json('mounted-cases.json', self.observations)
    def status(self, name): return self.endpoints[name].status(name)
    def read(self, name, path): return self.endpoints[name].read(name+'/'+path)
    def write(self, name, path, body, atomic=False):
        return self.endpoints[name].execute(WRITE, {'path':'/shared/'+name+'/'+path,'body':body.hex(),'atomic':atomic}, user='1001:1001')
    def settled(self, names=('a','b'), head=None):
        result={n:self.status(n) for n in names}
        heads={v['status']['binding']['view']['head'] for v in result.values()}
        return result if len(heads)==1 and (head is None or heads=={head}) and all(v['live']['applied'] for v in result.values()) else None
    def settle(self, names=('a','b'), head=None):
        result=None
        def check():
            nonlocal result
            result=self.settled(names,head)
            return bool(result)
        self.until(check,60)
        return result
    def signal(self,name,signal):
        self.endpoints[name].execute("import json,os,signal,sys;s=json.load(sys.stdin);pid=int(open('/private/'+s[0]+'/pid').read());os.kill(pid,getattr(signal,s[1]));print('{}')",[name,signal])
        if signal=='SIGSTOP':self.stopped.add(name)
        if signal=='SIGCONT':self.stopped.discard(name)
    def freeze_integration(self):
        self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-integration-barrier')
        (self.i.control/'pause-integration').write_text('owned Task3 fixture')
    def release_integration(self): (self.i.control/'pause-integration').unlink(missing_ok=True)
    def barrier(self):
        self.until(lambda:self.i.docker('exec',self.i.service,'test','-f','/tmp/fs2-integration-barrier',check=False,evidence=False).returncode==0,15)
    def local(self,name,action,*args):
        return self.endpoints[name].cli('sync','local-work',action,'--state','/private/'+name+'/state',*args)
    def setup_mounts(self):
        self.i.start_service(faults=True);self.wait();expiry=int(time.time())+7200
        self.tokens['alice']=secrets.token_hex(32)
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':self.tokens['alice'],'expires':expiry,'actions':['admin','read','write','integrate'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        entries=[file_entry('target',self.tree_root['id'],b'initial'),file_entry('foreign',self.tree_root['id'],b'foreign-initial')]
        upload,rid=self.stage(self.descriptor(entries),bodies=[b'initial',b'foreign-initial'])
        self.expect('mounted-seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        status,grant=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':expiry-3600,'actions':['read','write','integrate'],'branches':['main'],'prefixes':['']}})
        assert status==200
        self.tokens['worker']=grant['token'];self.worker_credential=grant['credential']
        for name,actor in [('a','alice'),('b','worker')]:
            endpoint=DiskLazy(self,'task3-'+name);self.endpoints[name]=endpoint;endpoint.start(name,actor=actor)
        self.settle()
    def held(self,case,foreign=False,mapped=False,overlap=False):
        before=self.settle();prior={p['operation'] for p in before['a']['status']['submissions']}
        marker='/tmp/task3-map-'+secrets.token_hex(6)
        if mapped:
            code="""import json,sys,os,time,ctypes,traceback
s=json.loads(sys.argv[1])
try:
 libc=ctypes.CDLL(None,use_errno=True);libc.mmap.restype=ctypes.c_void_p;libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long];libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
 fd=os.open(s['path'],os.O_RDONLY);size=os.fstat(fd).st_size;address=libc.mmap(None,size,1,2,fd,0)
 if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
 os.close(fd)
 targets=[]
 for name in os.listdir('/proc/self/fd'):
  try:targets.append(os.readlink('/proc/self/fd/'+name))
  except FileNotFoundError:pass
 assert s['path'] not in targets
 initial=ctypes.string_at(address,size).hex()
 open(s['marker']+'-ready','w').write(json.dumps({'uid':os.geteuid(),'fd_target_present':False,'initial':initial,'mapping':'MAP_PRIVATE/PROT_READ'}))
 while not os.path.exists(s['marker']+'-release'):time.sleep(.02)
 assert ctypes.string_at(address,size).hex()==initial
 assert libc.munmap(address,size)==0
 open(s['marker']+'-done','w').write('unmapped')
except BaseException:
 open(s['marker']+'-error','w').write(traceback.format_exc());raise
"""
            endpoint=self.endpoints['a']
            pid=endpoint.execute("import json,subprocess,sys;code,s=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code,json.dumps(s)],stdout=subprocess.DEVNULL,stderr=open(s['marker']+'-stderr','w'),start_new_session=True);print(json.dumps(p.pid))",[code,{'path':'/shared/a/foreign','marker':marker}],user='1001:1001')
            endpoint.holders.append(pid)
            self.mappings.append(('a',marker,pid))
            def mapping_ready():
                evidence=endpoint.execute("import json,os,sys;p=json.load(sys.stdin);print(json.dumps({'ready':json.load(open(p+'-ready')) if os.path.exists(p+'-ready') else None,'error':open(p+'-error').read() if os.path.exists(p+'-error') else None}))",marker)
                assert evidence['error'] is None,evidence
                return evidence['ready']
            mapped_evidence=self.until(mapping_ready,5)
            assert mapped_evidence['uid']==1001 and mapped_evidence['fd_target_present'] is False
            self.i.write_json('mmap-after-fd-close-capability.json',mapped_evidence)
        self.freeze_integration()
        body=(case+'-local').encode()
        self.write('a','temporary',body)
        self.barrier()
        original=self.status('a')['status']['submissions']
        self.endpoints['a'].execute("import os,json;os.replace('/shared/a/temporary','/shared/a/target');fd=os.open('/shared/a',os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);print('{}')",user='1001:1001')
        if foreign:
            self.signal('a','SIGSTOP')
        self.release_integration()
        if foreign:
            # A cannot discover/issue its own view while stopped; B performs the foreign save.
            old_head=before['b']['status']['binding']['view']['head']
            current=None
            def advanced():
                nonlocal current
                current=self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
                return current!=old_head
            self.until(advanced,60)
            self.settle(('b',),current)
            self.write('b','target' if overlap else 'foreign',(case+'-remote').encode())
            self.settle(('b',))
            self.signal('a','SIGCONT')
        if mapped or overlap:
            recovery=None
            def blocked():
                nonlocal recovery
                recovery=self.local('a','list')
                return currently_blocked(recovery)
            self.until(blocked,30)
            assert self.read('a','target')==body.hex()
            self.record(case+'-blocked',recovery=recovery,original=original,fd_closed_before_foreign=mapped)
            if mapped:
                self.endpoints['a'].execute("import json,sys;open(json.load(sys.stdin)+'-release','w').close();print('{}')",marker,user='1001:1001')
                self.until(lambda:self.endpoints['a'].execute("import json,os,sys;print(json.dumps(os.path.exists(json.load(sys.stdin)+'-done')))",marker),5)
            else:
                operation=recovery['recovery'][-1]['operation']
                destination='/tmp/task3-export-'+secrets.token_hex(6)
                self.local('a','export','--id',operation,'--destination',destination)
                exported=self.endpoints['a'].execute("import json,sys;print(json.dumps(open(json.load(sys.stdin)+'/target','rb').read().hex()))",destination)
                assert exported==body.hex()
                generation=self.status('a')['local']['generation'] if 'local' in self.status('a') else self.endpoints['a'].execute("import sqlite3,json;d=sqlite3.connect('/private/a/state/journal.sqlite');print(json.dumps(json.loads(d.execute('SELECT value FROM working').fetchone()[0])['generation']))")
                self.local('a','use-remote','--operation-id',operation,'--expected-generation',str(generation))
        after=self.settle()
        expected=(case+'-remote').encode() if overlap else body
        assert self.read('a','target')==self.read('b','target')==expected.hex()
        if foreign and not overlap:assert self.read('a','foreign')==self.read('b','foreign')==(case+'-remote').encode().hex()
        current=after['a']['status']['submissions']
        for old in original:
            found=next(p for p in current if p['operation']==old['operation'])
            for key in ['operation','local_revision','request','request_digest']:
                if old.get(key) is not None:assert found.get(key)==old.get(key),(case,key)
        log=self.endpoints['a'].execute("import json;print(json.dumps(open('/private/a/daemon.log').read()))")
        if not overlap:assert ('DirtyReconciled' if foreign else 'OwnBaseAdvanced') in log
        self.record(case,before=before,after=after,original=original,new=[p for p in current if p['operation'] not in prior],ordinary_uid=1001,logs=log)
    def run(self):
        self.setup_mounts()
        self.write('a','target',b'normal-atomic',True);after=self.settle();assert self.read('b','target')==b'normal-atomic'.hex();self.record('normal-atomic',after=after)
        self.held('held-own-atomic')
        self.held('foreign-never-issued',foreign=True)
        self.held('mmap-after-fd-close',foreign=True,mapped=True)
        self.held('overlap-explicit-recovery',foreign=True,overlap=True)
        self.restart_mount('a')
        self.settle();self.write('a','target',b'after-restart',True);self.settle();assert self.read('b','target')==b'after-restart'.hex();self.record('restart-retains-policy',after=self.status('a'))
        self.parked_publication('merge-produced-own','sync-before-send',foreign=True)
        self.parked_publication('lost-response-restart','sync-lost-ack')
        self.native=Endpoint(self,'linux',self.image)
        client=self.native.create('task3-native-routing',actions=['read','write','integrate']);self.native.start(client);self.until(lambda:self.native.ready(client),30)
        registered=self.native.run("import sqlite3;d=sqlite3.connect(s['state']+'/journal.sqlite');print(json.dumps(d.execute('SELECT count(*) FROM mounted_collaboration').fetchone()[0]))",client)
        assert registered==0;self.record('native-route-unregistered',registered=registered);self.native.stop(client)
        self.denial()
        self.two_agents()
    def restart_mount(self,name,fault=None,crash=False,old_client=False):
        # Only this owned daemon is stopped; its durable journal is reused unchanged.
        return self.endpoints[name].execute("""import os,json,subprocess,time,sqlite3,signal,sys
s=json.load(sys.stdin);name=s['name'];control='/private/'+name;mount='/shared/'+name;pid=int(open(control+'/pid').read())
if s['crash']:os.kill(pid,signal.SIGKILL)
else:subprocess.run(['fusermount3','-u',mount],check=True)
for _ in range(200):
 if not os.path.exists('/proc/'+str(pid)):break
 time.sleep(.025)
assert not os.path.exists('/proc/'+str(pid))
sys.path.insert(0,'/src/tests/fs2');from connected import kernel_mount_present
if kernel_mount_present(mount,open('/proc/self/mountinfo').read()):subprocess.run(['fusermount3','-u',mount],check=True)
assert not kernel_mount_present(mount,open('/proc/self/mountinfo').read())
os.rmdir(mount);d=sqlite3.connect(control+'/state/journal.sqlite');w=json.loads(d.execute('SELECT value FROM working').fetchone()[0]);schema=d.execute('PRAGMA user_version').fetchone()[0];d.close()
if s['old_client']:
 old=subprocess.run(['/tmp/task3-old-magus-fs','status','--state',control+'/state'],capture_output=True,text=True,timeout=10)
 assert old.returncode!=0 and 'unsupported_schema' in old.stdout,(old.returncode,old.stdout,old.stderr)
 open(control+'/old-client-result.json','w').write(json.dumps({'status':old.returncode,'stdout':old.stdout,'stderr':old.stderr,'schema':schema}))
log=open(control+'/daemon.log','a');env=os.environ.copy();marker=control+'/task3-fault'
if os.path.exists(marker):os.unlink(marker)
if s['fault']:env.update(MAGUS_TEST_FAULT_POINT=s['fault'],MAGUS_TEST_FAULT_MARKER=marker)
p=subprocess.Popen(['magus-fs-client-faults' if s['fault'] else 'magus-fs','mount','--state',control+'/state','--revision',w['head'],'--mountpoint',mount,'--mode','private'],stdout=log,stderr=log,env=env);open(control+'/pid','w').write(str(p.pid))
deadline=time.monotonic()+10
while not kernel_mount_present(mount,open('/proc/self/mountinfo').read()):
 assert p.poll() is None,(p.poll(),open(control+'/daemon.log').read())
 assert time.monotonic()<deadline
 time.sleep(.02)
print(json.dumps({'pid':p.pid,'schema':schema}))""",{'name':name,'fault':fault,'crash':crash,'old_client':old_client})
    def parked_publication(self,case,fault,foreign=False):
        self.settle();self.restart_mount('a',fault=fault)
        body=(case+'-local').encode();self.write('a','temporary',body)
        self.until(lambda:self.endpoints['a'].execute("import json,os;print(json.dumps(os.path.exists('/private/a/task3-fault')))"),15)
        original=self.status('a')['status']['submissions']
        self.endpoints['a'].execute("import os;os.replace('/shared/a/temporary','/shared/a/target');print('{}')",user='1001:1001')
        if foreign:
            self.write('b','foreign',(case+'-remote').encode());self.settle(('b',))
        self.restart_mount('a',crash=True);after=self.settle()
        assert self.read('a','target')==self.read('b','target')==body.hex()
        for old in original:
            found=next(p for p in after['a']['status']['submissions'] if p['operation']==old['operation'])
            for key in ['request','request_digest']:
                if old.get(key) is not None:assert found[key]==old[key]
        if foreign:
            candidate=next(p for p in reversed(after['a']['status']['submissions']) if p.get('request') and any(o['operation']==p['operation'] and o.get('request') for o in original))
            receipt=candidate['shared_receipt'];assert receipt
            actual=self.i.sql("SELECT published_revision FROM publication_results WHERE namespace='"+NS+"' AND receipt='"+receipt['receipt']+"';")
            derived=self.i.sql("SELECT derived_revision FROM operations WHERE operation='"+receipt['operation']+"';")
            assert actual!=derived,('expected actual merge result',actual,derived)
        self.record(case,original=original,after=after,ordinary_uid=1001)
    def two_agents(self):
        self.i.write_json('agent-ready.json',{'owner':self.i.owner,'containers':{name:ep.daemon for name,ep in self.endpoints.items()},'uid':'1001:1001','paths':{'a':'/shared/a/agent-a','b':'/shared/b/agent-b'},'completion_files':['agent-a-result.json','agent-b-result.json']})
        self.until(lambda:all((self.i.output/('agent-'+n+'-result.json')).exists() for n in ['a','b']),120)
        agents=[json.loads((self.i.output/('agent-'+n+'-result.json')).read_text()) for n in ['a','b']]
        assert all(v['status']=='passed' and v['uid']==1001 for v in agents)
        self.settle()
        for name in ['a','b']:assert self.read('a','agent-'+name)==self.read('b','agent-'+name)
        self.record('two-ordinary-agents',agents=agents,after=self.settle())
    def denial(self):
        # Final case deliberately leaves a retained blocked branch; no credential or
        # frozen candidate is silently replaced to make teardown look successful.
        self.settle()
        replica=identity('replica')
        status,grant=self.request('POST',self.root+'/grants',body={'delegate':{'replica':replica,'expires':int(time.time())+1800,'actions':['read','write','integrate'],'branches':['main'],'prefixes':['']}});assert status==200
        self.tokens['denied']=grant['token'];credential=grant['credential']
        endpoint=DiskLazy(self,'task3-denial');self.endpoints['denial']=endpoint;endpoint.start('denial',actor='denied',replica_identity=replica)
        self.freeze_integration();self.write('denial','temporary',b'denied-local');self.barrier()
        self.endpoints['denial'].execute("import os;os.replace('/shared/denial/temporary','/shared/denial/target');print('{}')",user='1001:1001')
        status,_=self.request('POST',self.root+'/grants',body={'revoke':credential});assert status==200
        self.release_integration();recovery=None
        def blocked():
            nonlocal recovery
            recovery=self.local('denial','list');return currently_blocked(recovery)
        self.until(blocked,30);before=self.status('denial')
        old_image='sha256:9c7b55e2e231b8f06e6b7f6f2110fa056bd9e21d2b4e5c8b473ac4f286e18569'
        legacy=self.i.create('container','old-client',['--network','none',old_image,'sleep','infinity']);self.i.docker('start',legacy)
        old_hash=self.i.docker('exec',legacy,'sha256sum','/usr/local/bin/magus-fs').stdout.split()[0]
        assert old_hash=='072b1a17796c9b1945fef8aba980768f03e290ed1f43787c3b1fd0008f284637'
        binary=self.i.output/'old-magus-fs';self.i.docker('cp',legacy+':/usr/local/bin/magus-fs',str(binary));self.i.docker('cp',str(binary),self.endpoints['denial'].daemon+':/tmp/task3-old-magus-fs')
        self.restart_mount('denial',crash=True,old_client=True)
        old_result=self.endpoints['denial'].execute("import json;print(open('/private/denial/old-client-result.json').read())")
        self.record('old-client-schema-refusal',image=old_image,binary_sha256=old_hash,result=old_result)
        after=self.local('denial','list');assert after['recovery'];assert not self.status('denial')['live']['applied']
        self.record('current-denial-retention',before=before,recovery=recovery,after=after)
    def cleanup(self):
        self.release_integration()
        for name in list(self.stopped):self.signal(name,'SIGCONT')
        errors=[]
        for name,marker,pid in self.mappings:
            try:
                endpoint=self.endpoints[name]
                endpoint.execute("import json,sys;open(json.load(sys.stdin)+'-release','w').close();print('{}')",marker,user='1001:1001')
                self.until(lambda:not endpoint.execute("import json,os,sys;print(json.dumps(os.path.exists('/proc/'+str(json.load(sys.stdin)))))",pid),5)
                if pid in endpoint.holders:endpoint.holders.remove(pid)
            except Exception as error:errors.append({'mapping':marker,'pid':pid,'error':str(error)})
        if self.native:
            try:self.native.cleanup()
            except Exception as error:errors.append({'native':str(error)})
        for name,endpoint in self.endpoints.items():
            try:
                endpoint.cleanup()
                for filename in ['mount-cleanup.json','kernel-mount-cleanup.json','mount-ownership.json','holder-cleanup.json']:
                    path=self.i.output/filename
                    if path.exists():(self.i.output/(name+'-'+filename)).write_bytes(path.read_bytes())
            except Exception as error:errors.append({'endpoint':name,'error':str(error)})
        self.i.write_json('mounted-cleanup-errors.json',errors)
        if errors:raise AssertionError('owned mounted cleanup incomplete')

def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--output',required=True);args=parser.parse_args(argv)
    from continuation_proof import validate_image
    validate_image(args.image)
    class Infra(OwnedInfra):
        def create(self,kind,suffix,args):return super().create(kind,suffix,acceptance_s3_capacity('acceptance',kind,suffix,args))
        def docker(self,*args,**kwargs):
            if args[:1]==('exec',) and args[1:2] in [('-d',),('-i',)]:args=('exec',args[1],'-e','MAGUS_LATENCY_TRACE=1',*args[2:])
            return super().docker(*args,**kwargs)
    infra=Infra(args.output);infra.runtime_profile='release';journey=None;status=1
    infra.write_json('mounted-plan.json',{'cases':CASES,'ordinary_uid':1001,'manual_drains':False})
    try:
        infra.preflight();source=capture(infra);infra.setup(args.image);infra.isolate_service_control();verify_linux_image(infra,source)
        journey=Journey(infra,args.image);journey.run();verify_linux_image(infra,source);status=0
    except InfrastructureUnavailable as error:infra.write_json('failure.json',{'classification':'blocked','reason':str(error)});status=2
    except Exception as error:infra.write_json('failure.json',{'classification':'failed','reason':str(error),'trace':traceback.format_exc()});print(traceback.format_exc(),flush=True)
    finally:
        try:
            if journey:journey.cleanup()
            infra.cleanup()
        except Exception as error:infra.write_json('cleanup-failure.json',{'reason':str(error)});status=1
        infra.write_json('result.json',{'status':status,'scope':'mounted continuation correctness','completed':journey.observations if journey else [],'not_run':[c for c in CASES if not journey or not any(r['case']==c for r in journey.observations)]})
    return status

if __name__=='__main__':raise SystemExit(main())
