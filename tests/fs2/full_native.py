#!/usr/bin/env python3
"""Real macOS/Linux ordinary folders, native owner processes and authenticated PG/S3 service.
No FUSE acknowledgements or filesystem mocks. All clients and processes are owned fixtures.
"""
import argparse, hashlib, json, os, secrets, shutil, subprocess, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, verify_image
from service_protocol import Journey, identity, file_entry, GROUP, REPLICA
from service_storage import NS, ALICE

class Endpoint:
    def __init__(self,j,platform,image):
        self.j=j;self.i=j.i;self.platform=platform;self.container=None;self.clients=[];self.children=[]
        self.binary=str(ROOT/'target/debug/magus-fs');self.faults=str(ROOT/'target/debug/magus-fs-client-faults')
        if platform=='linux':
            self.container=self.i.create('container','native',['--network',self.i.ingress,'--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','2','--pids-limit','256','--user','1001:1001',image,'python3','-c',"import os,signal,time\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
            self.i.docker('start',self.container);self.binary='/usr/local/bin/magus-fs';self.faults='/usr/local/bin/magus-fs-client-faults'
        self.base=str(self.i.output/'mac') if platform=='macos' else '/tmp/full-native'
        self.run("os.mkdir(s,0o700);print('{}')",self.base)
    def run(self,code,data=None):
        script='import json,os,sys,subprocess,time,hashlib,signal\ns=json.load(sys.stdin)\n'+code
        argv=['python3','-c',script]
        if self.container:p=self.i.docker('exec','-i',self.container,*argv,input=json.dumps(data),evidence=False,check=False,timeout=25)
        else:p=self.i.run(argv,input=json.dumps(data),evidence=False,check=False,timeout=25)
        assert p.returncode==0,{'platform':self.platform,'code':code,'stdout':p.stdout,'stderr':p.stderr}
        return json.loads(p.stdout)
    def cli(self,c,*args):
        return self.run("deadline=time.monotonic()+3\nwhile True:\n p=subprocess.run([s[0],*s[1]],capture_output=True,text=True,timeout=12)\n if p.returncode==0:break\n if json.loads(p.stdout).get('error')!='replica_busy' or time.monotonic()>=deadline:raise AssertionError((s[1],p.stdout,p.stderr))\n time.sleep(.03)\nprint(p.stdout)",[self.binary,[*args,'--state',c['state']]])
    def status(self,c):return self.cli(c,'sync','status')
    def create(self,name):
        replica=identity('replica')
        code,grant=self.j.request('POST',self.j.root+'/grants',body={'delegate':{'replica':replica,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}});assert code==200,grant
        view,r=self.j.view();bodies={}
        for e in r['tree']['entries']:
            if e['content']['kind']=='file':
                body=b''
                for x in e['content']['version']['extents']:
                    assert x['kind']=='chunk'
                    import http.client
                    conn=http.client.HTTPSConnection('127.0.0.1',self.i.port,context=self.j.ca,timeout=10);conn.request('GET',self.j.root+'/views/'+view['view']+'/objects/'+x['object'],headers={'Authorization':'Bearer '+self.j.tokens['alice']});response=conn.getresponse();part=response.read();assert response.status==200;conn.close();body+=part[x['offset']:x['offset']+x['length']]
                bodies[e['path']]=body.hex()
        path=self.base+'/'+name;self.clients.append({'path':path,'creating':True});self.save()
        c=self.run('''p=s['path'];os.mkdir(p,0o700);root=p+'/tree';os.mkdir(root,s['revision']['tree']['root']['mode']);os.chmod(root,s['revision']['tree']['root']['mode'])
for e in sorted(s['revision']['tree']['entries'],key=lambda e:e['path'].count('/')):
 f=root+'/'+e['path']
 if e['content']['kind']=='directory':os.mkdir(f,0o700)
 else:open(f,'wb').write(bytes.fromhex(s['bodies'][e['path']]))
 if e['content']['kind']!='directory':os.chmod(f,e['mode'])
for e in sorted(s['revision']['tree']['entries'],key=lambda e:e['path'].count('/'),reverse=True):
 if e['content']['kind']=='directory':os.chmod(root+'/'+e['path'],e['mode'])
def private(name,value):
 f=p+'/'+name;fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as out:out.write(value if isinstance(value,str) else json.dumps(value))
 return f
config={'replica':{'replica':s['replica'],'authorities':[{'principal':s['principal'],'uid':os.geteuid(),'gid':os.stat(root).st_gid,'primary_group':s['group'],'groups':[s['group']],'dac_override':False,'ownership_transfer':False}],'content_roots':[root],'cache_bytes':96*1024*1024},'root':root,'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
state=p+'/state'
def cli(*args):
 v=subprocess.run([s['binary'],*args],capture_output=True,text=True,timeout=12);assert v.returncode==0,(args,v.stdout,v.stderr);return json.loads(v.stdout)
cli('init','--state',state,'--config',private('config',config))
profile=private('profile',{'endpoint':s['endpoint'],'namespace':s['namespace'],'replica':s['replica'],'ca_file':private('ca',s['ca']),'token_file':private('token',s['token']),'publication_principal':s['principal']})
binding=cli('sync','attach','--state',state,'--profile',profile,'--branch','main','--publication','shared-live')['binding']
print(json.dumps({'path':p,'root':root,'state':state,'binding':binding,'replica':s['replica']}))''',{'path':path,'revision':r,'bodies':bodies,'replica':replica,'principal':ALICE,'group':GROUP,'binary':self.binary,'endpoint':'https://service:8443' if self.container else 'https://localhost:'+str(self.i.port),'namespace':NS,'ca':(self.i.control/'ca.crt').read_text(),'token':grant['token']})
        self.clients[-1]=c;self.save();return c
    def save(self):self.i.write_json(self.platform+'-native-ownership.json',{'container':self.container,'clients':self.clients,'children':self.children})
    def start(self,c,fault=None,drop_hints=False):
        marker=c['path']+'/barrier-'+secrets.token_hex(4);c['starting']={'fault':fault,'marker':marker,'drop_hints':drop_hints};self.save()
        c['pid']=self.run("env=os.environ.copy()\nif s['drop_hints']:env['MAGUS_TEST_DROP_NATIVE_HINTS']='1'\nif s['fault']:env.update(MAGUS_TEST_FAULT_POINT=s['fault'],MAGUS_TEST_FAULT_ACTION='barrier',MAGUS_TEST_FAULT_MARKER=s['marker'])\nlog=open(s['path']+'/daemon.log','a');p=subprocess.Popen([s['binary'],'sync','run','--state',s['state'],'--serve','true'],stdout=log,stderr=log,env=env,start_new_session=True);print(json.dumps(p.pid))",{**c,'binary':self.faults if fault or drop_hints else self.binary,'fault':fault,'marker':marker,'drop_hints':drop_hints})
        c['marker']=marker;self.save();return marker+'.1'
    def stop(self,c,kill=False):
        if not c.get('pid'):return
        self.run("pid=s['pid']\ntry:os.kill(pid,signal.SIGKILL if s['kill'] else signal.SIGTERM)\nexcept ProcessLookupError:pass\nprint('{}')",{'pid':c['pid'],'kill':kill});c['stopped_pid']=c.pop('pid');self.save()
        # A completed CLI open proves the exact owner's journal lock is released.
        self.j.until(lambda:self.run("try:\n os.kill(s,0);alive=True\nexcept ProcessLookupError:alive=False\nprint(json.dumps(not alive))",c['stopped_pid']),5)
    def read(self,c,path='reports/live'):return self.run("print(json.dumps(open(s,'rb').read().hex()))",c['root']+'/'+path)
    def write(self,c,body,path='reports/live',atomic=False):
        return self.run("p=s['path'];target=p+'.save' if s['atomic'] else p\nwith open(target,'wb') as f:f.write(bytes.fromhex(s['body']));f.flush();os.fsync(f.fileno())\nif s['atomic']:os.replace(target,p)\nprint('{}')",{'path':c['root']+'/'+path,'body':body.hex(),'atomic':atomic})
    def exists(self,path):return self.run("print(json.dumps(os.path.exists(s)))",path)
    def ready(self,c,head=None):
        s=self.status(c);return bool(s.get('native') and 'Ready' in s['native']['status'] and s['live']['applied'] and (head is None or s['status']['binding']['view']['head']==head))
    def barrier(self,c):self.j.until(lambda:self.exists(c['marker']+'.1'),10)
    def release(self,c):self.run("open(s+'.1.release','w').close();print('{}')",c['marker'])
    def cleanup(self):
        for c in self.clients:
            if c.get('pid'):self.stop(c)
        for p in self.children:
            if not p.get('stopped'):
                self.run("try:os.kill(s,signal.SIGTERM)\nexcept ProcessLookupError:pass\nprint('{}')",p['pid']);p['stopped']=True
        self.save()

class NativeJourney(Journey):
    def __init__(self,i,image,platforms,case='full'):super().__init__(i);self.image=image;self.platforms=platforms;self.case=case;self.endpoints=[];self.evidence=[]
    def until(self,fn,seconds=15):
        deadline=time.monotonic()+seconds;last=None
        while time.monotonic()<deadline:
            last=fn()
            if last:return last
            time.sleep(.08)
        raise AssertionError(('native visibility deadline',seconds,last))
    def record(self,platform,case,**data):self.evidence.append({'platform':platform,'case':case,**data});self.i.write_json('native-evidence.json',self.evidence)
    def publish(self,body=None,path='reports/live',directory=False):
        view,r=self.view()
        if directory:r['tree']['entries'].append({'path':path,'id':identity('entry'),'parent':r['tree']['root']['id'],'owner':ALICE,'group':GROUP,'mode':493,'content':{'kind':'directory'}})
        else:
            old=next((e for e in r['tree']['entries'] if e['path']==path),None)
            fresh=file_entry(path,next(e['id'] for e in r['tree']['entries'] if e['path']=='reports'),body)
            if old:
                assert old['content']!=fresh['content'],'fixture must publish a changed file generation'
                old['content']=fresh['content']
            else:r['tree']['entries'].append(fresh)
        _,private=self.candidate(view,r,'alice',[] if directory else [body]);return self.expect('native-integrate','POST',self.root+'/integrations',200,body=self.integrate_request(private,view))
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':493,'content':{'kind':'directory'}}
        body=b'initial native ordinary bytes';upload,rid=self.stage(self.descriptor([reports,file_entry('reports/live',reports['id'],body)]),bodies=[body]);self.expect('native-seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        for platform in self.platforms:
            ep=Endpoint(self,platform,self.image);self.endpoints.append(ep);self.retention(ep) if self.case=='retention' else self.supplement(ep) if self.case=='supplement' else self.permissions(ep) if self.case=='permissions' else self.platform(ep)
    def directory_mode(self,mode):
        view,r=self.view();next(e for e in r['tree']['entries'] if e['path']=='reports')['mode']=mode
        _,private=self.candidate(view,r,'alice',[]);return self.expect('native-directory-mode','POST',self.root+'/integrations',200,body=self.integrate_request(private,view))
    def retention(self,ep):
        c=ep.create('verified-gap');ep.start(c);self.until(lambda:ep.ready(c));ep.stop(c)
        tag=c['path']+'/held';ep.children.append({'creating':tag});ep.save()
        code="import json,os,sys,time\ns=json.loads(sys.argv[1]);fd=os.open(s['file'],os.O_RDWR);old=os.fstat(fd).st_ino;open(s['tag']+'-ready','w').close();deadline=time.monotonic()+40\nwhile not os.path.exists(s['tag']+'-go'):\n assert time.monotonic()<deadline\n time.sleep(.02)\nbody=b'verification gap alternative';os.pwrite(fd,body,0);os.ftruncate(fd,len(body));os.fsync(fd);open(s['tag']+'-done','w').write(json.dumps({'old_inode':old,'current_inode':os.stat(s['file']).st_ino,'bytes':os.pread(fd,4096,0).hex()}));os.close(fd)"
        pid=ep.run("p=subprocess.Popen(['python3','-c',s['code'],json.dumps(s['args'])],stdout=open(s['tag']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",{'code':code,'args':{'file':c['root']+'/reports/live','tag':tag},'tag':tag});ep.children[-1]={'pid':pid,'tag':tag};ep.save();self.until(lambda:ep.exists(tag+'-ready'))
        incoming=(ep.platform+' verified gap incoming').encode();self.publish(incoming);ep.start(c,'native-displaced-verified');ep.barrier(c)
        ep.run("open(s+'-go','w').close();print('{}')",tag);self.until(lambda:ep.exists(tag+'-done'));held=ep.run("print(open(s+'-done').read())",tag);ep.children[-1]['stopped']=True;ep.save();assert held['old_inode']!=held['current_inode'];ep.release(c)
        self.until(lambda:any(d['ambiguous'] and d['versions'] for d in ep.status(c)['native']['displacements']))
        before=ep.status(c);records=before['native']['displacements'];assert 'Ready' not in before['native']['status'] and not before['live']['applied'];assert ep.read(c)==incoming.hex()
        retained={v:ep.run("print(json.dumps(open(s,'rb').read().hex()))",v) for d in records for v in d['versions']};assert held['bytes'] in retained.values()
        ep.stop(c,kill=True);reopened=ep.status(c);assert reopened['native']['displacements']==records;assert 'Ready' not in reopened['native']['status'];assert all(ep.run("print(json.dumps(open(s,'rb').read().hex()))",v)==body for v,body in retained.items())
        self.record(ep.platform,'verified-gap-held-write-owner-restart',before=before,reopened=reopened,held=held,retained=retained,barrier='native-displaced-verified')
        # The ahead head triggers rejected applications; enumeration must also survive those writes.
        self.publish((ep.platform+' subsequent incoming blocked').encode());ep.start(c)
        self.until(lambda:ep.status(c)['native']['incoming_revision']!=before['native']['incoming_revision'])
        rejected=ep.status(c);assert rejected['native']['displacements']==records;assert 'Ready' not in rejected['native']['status'];ep.stop(c,kill=True);reopened=ep.status(c)
        assert reopened['native']['displacements']==records;assert 'Ready' not in reopened['native']['status'] and not reopened['live']['applied'];assert ep.read(c)==incoming.hex();assert all(ep.run("print(json.dumps(open(s,'rb').read().hex()))",v)==body for v,body in retained.items())
        self.record(ep.platform,'rejected-apply-retained-enumeration-reopen',rejected=rejected,reopened=reopened,retained=retained)
    def supplement(self,ep):
        c=ep.create('late-restart');ep.start(c);self.until(lambda:ep.ready(c));original=ep.status(c)
        self.i.docker('exec',self.i.service,'python3','-c',"import os,signal;pid=int(open('/tmp/service.pid').read());assert os.readlink('/proc/'+str(pid)+'/exe')=='/usr/local/bin/magus-fs-service';os.kill(pid,signal.SIGTERM)")
        self.until(lambda:bool(ep.status(c).get('native') and 'Ready' not in ep.status(c)['native']['status']))
        interrupted=ep.status(c);original_port=self.i.port;self.i.start_service();assert self.i.port==original_port;self.wait();started=time.monotonic()
        try:self.until(lambda:ep.ready(c,original['status']['binding']['view']['head']))
        finally:self.record(ep.platform,'transport-recovery-unchanged-head',before=original,interrupted=interrupted,after=ep.status(c),seconds=time.monotonic()-started)
        # Preserve a descriptor in another ordinary process across an incoming exchange.
        tag=c['path']+'/late';ep.children.append({'creating':tag});ep.save()
        code="import json,os,sys,time\ns=json.loads(sys.argv[1]);fd=os.open(s['file'],os.O_RDWR);open(s['tag']+'-ready','w').close();deadline=time.monotonic()+30\nwhile not os.path.exists(s['tag']+'-go'):\n assert time.monotonic()<deadline\n time.sleep(.02)\nos.pwrite(fd,b'pending alternative',0);os.ftruncate(fd,19);os.fsync(fd);os.close(fd);open(s['tag']+'-done','w').close()"
        pid=ep.run("p=subprocess.Popen(['python3','-c',s['code'],json.dumps(s['args'])],stdout=open(s['tag']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",{'code':code,'args':{'file':c['root']+'/reports/live','tag':tag},'tag':tag});ep.children[-1]={'pid':pid,'tag':tag};ep.save();self.until(lambda:ep.exists(tag+'-ready'))
        body=(ep.platform+' supplemental accepted').encode();shared=self.publish(body);self.until(lambda:ep.ready(c,shared['head']));ep.run("open(s+'-go','w').close();print('{}')",tag);self.until(lambda:ep.exists(tag+'-done'));ep.children[-1]['stopped']=True
        self.until(lambda:any(d['ambiguous'] and d['versions'] for d in ep.status(c)['native']['displacements']));before=ep.status(c);records=before['native']['displacements'];alternatives=[v for d in records if d['ambiguous'] for v in d['versions']];assert alternatives
        retained={v:ep.run("print(json.dumps(open(s,'rb').read().hex()))",v) for v in alternatives};assert b'pending alternative'.hex() in retained.values()
        ep.stop(c);ep.start(c);self.until(lambda:bool(ep.status(c).get('native') and ep.status(c)['native']['displacements']))
        after=ep.status(c);assert after['native']['displacements']==records;assert 'Ready' not in after['native']['status'] and not after['live']['applied'];assert ep.read(c)==body.hex();assert all(ep.run("print(json.dumps(open(s,'rb').read().hex()))",v)==data for v,data in retained.items());assert not after['status']['submissions']
        self.record(ep.platform,'late-displacement-owner-restart',before=before,after=after,retained=retained,canonical_or_private_receipt=False);ep.stop(c)
    def platform(self,ep):
        platform=ep.platform;c=ep.create('automatic');ep.start(c,drop_hints=True);self.until(lambda:ep.ready(c))
        before=ep.status(c);_,prior_descriptor=self.view();prior_id=next(e['id'] for e in prior_descriptor['tree']['entries'] if e['path']=='reports/live');inode=ep.run("print(json.dumps(os.stat(s).st_ino))",c['root']+'/reports/live')
        for atomic in [False,True]:
            body=(platform+(' atomic save' if atomic else ' in place save')).encode();started=time.monotonic();ep.write(c,body,atomic=atomic);saved_inode=ep.run("print(json.dumps(os.stat(s).st_ino))",c['root']+'/reports/live')
            progress=self.until(lambda:next((p for p in ep.status(c)['status']['submissions'] if p['local_revision']!=before['live']['revision'] and p['operation'] not in [q['operation'] for q in before['status']['submissions']]),None))
            captured=time.monotonic()-started
            self.until(lambda:any(p['operation']==progress['operation'] and p['shared_receipt'] for p in ep.status(c)['status']['submissions']));accepted=time.monotonic()-started
            self.until(lambda:ep.ready(c) and ep.status(c)['live']['revision']!=before['live']['revision']);visible=time.monotonic()-started
            after=ep.status(c);_,accepted_descriptor=self.view();accepted_id=next(e['id'] for e in accepted_descriptor['tree']['entries'] if e['path']=='reports/live');assert (accepted_id!=prior_id) if atomic else (accepted_id==prior_id);assert ep.run("print(json.dumps(os.stat(s).st_ino))",c['root']+'/reports/live')==saved_inode;assert ep.read(c)==body.hex();assert len(after['status']['submissions'])==len(before['status']['submissions'])+1
            time.sleep(2.2);assert len(ep.status(c)['status']['submissions'])==len(after['status']['submissions'])
            self.record(platform,'automatic-atomic' if atomic else 'automatic-in-place',capture_seconds=captured,accepted_seconds=accepted,visible_seconds=visible,before=before,after=after,sha256=hashlib.sha256(body).hexdigest(),all_native_hints_dropped=True,canonical_entry_before=prior_id,canonical_entry_after=accepted_id,saved_inode=saved_inode);before=after;prior_id=accepted_id
        # Actual old descriptor survives an incoming swap and writes after pathname readiness.
        holder=c['path']+'/holder';ep.children.append({'creating':holder});ep.save()
        code="import json,os,sys,time\ns=json.loads(sys.argv[1]);fd=os.open(s['path'],os.O_RDWR);old=os.pread(fd,4096,0);ino=os.fstat(fd).st_ino;open(s['tag']+'-ready','w').close();deadline=time.monotonic()+40\nwhile not os.path.exists(s['tag']+'-go'):\n assert time.monotonic()<deadline\n time.sleep(.02)\nos.pwrite(fd,b'late old descriptor bytes',0);os.ftruncate(fd,25);os.fsync(fd);open(s['tag']+'-result','w').write(json.dumps({'old':old.hex(),'old_inode':ino,'held':os.pread(fd,4096,0).hex(),'new_inode':os.stat(s['path']).st_ino}));os.close(fd)"
        pid=ep.run("p=subprocess.Popen(['python3','-c',s['code'],json.dumps(s['args'])],stdout=open(s['tag']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",{'code':code,'args':{'path':c['root']+'/reports/live','tag':holder},'tag':holder});ep.children[-1]={'pid':pid,'tag':holder};ep.save();self.until(lambda:ep.exists(holder+'-ready'))
        incoming=(platform+' remote exchange').encode();started=time.monotonic();shared=self.publish(incoming);self.until(lambda:ep.ready(c,shared['head']));latency=time.monotonic()-started
        ep.run("open(s+'-go','w').close();print('{}')",holder);self.until(lambda:ep.exists(holder+'-result'));held=ep.run("print(open(s+'-result').read())",holder);assert held['old_inode']!=held['new_inode'];assert ep.read(c)==incoming.hex()
        self.until(lambda:any(d['ambiguous'] and d['versions'] for d in ep.status(c)['native']['displacements']))
        status=ep.status(c);assert 'Ready' not in status['native']['status'] and not status['live']['applied'];assert any(ep.run("print(json.dumps(open(s,'rb').read().hex()))",v)==held['held'] for d in status['native']['displacements'] for v in d['versions'])
        ep.children[-1]['stopped']=True;self.record(platform,'exchange-old-fd-late-write',held=held,status=status,visible_seconds=latency,new_sha256=hashlib.sha256(incoming).hexdigest());ep.stop(c);assert ep.read(c)==incoming.hex()
        # Real owner kills at each durable boundary, for exchange and no-replace creation.
        for create in [False,True]:
            for point in ['native-intent','native-exchanged','native-before-commit']:
                label=('create-' if create else 'exchange-')+point;c=ep.create(label)
                path='reports/'+platform+'-'+point if create else 'reports/live';body=(platform+' '+label).encode();shared=self.publish(body,path)
                ep.start(c,point);ep.barrier(c);ep.stop(c,kill=True);interrupted=ep.read(c,path) if ep.exists(c['root']+'/'+path) else None
                ep.start(c);self.until(lambda:ep.ready(c,shared['head']));assert ep.read(c,path)==body.hex();status=ep.status(c);ep.stop(c)
                self.record(platform,label,interrupted=interrupted,expected=body.hex(),status=status,readable_without_daemon=ep.read(c,path)==body.hex())
        # Editor replacement races with exchange/no-replace and with final applied commit.
        for create,point in [(False,'native-before-exchange'),(True,'native-before-exchange'),(False,'native-before-commit')]:
            label=('create-' if create else 'exchange-')+point+'-race';c=ep.create(label);path='reports/'+platform+'-racing-created' if create else 'reports/live';shared=self.publish((platform+' accepted race target '+label).encode(),path)
            ep.start(c,point);ep.barrier(c);ep.write(c,b'editor replacement preserved',path,atomic=True);ep.release(c)
            self.until(lambda:ep.status(c).get('native') is not None);time.sleep(.3);status=ep.status(c);assert 'Ready' not in status['native']['status'];ep.stop(c);current=ep.read(c,path)
            retained=ep.run("from pathlib import Path\nprint(json.dumps([p.read_bytes().hex() for p in Path(s).glob('native-*/generation-*') if p.is_file()]))",c['state']);assert b'editor replacement preserved'.hex() in [current,*retained]
            ep.start(c);time.sleep(.4);ep.stop(c);assert b'editor replacement preserved'.hex() in [ep.read(c,path),*ep.run("from pathlib import Path\nprint(json.dumps([p.read_bytes().hex() for p in Path(s).glob('native-*/generation-*') if p.is_file()]))",c['state'])]
            self.record(platform,label,status=status,current=current,retained=retained)
        # Parent substitution/symlink cannot redirect writes; readonly parents and directory changes block.
        for symlink in [False,True]:
            c=ep.create('parent-'+str(symlink));self.publish((platform+' parent incoming '+str(symlink)).encode());ep.start(c,'native-before-exchange');ep.barrier(c)
            ep.run("p=s['root']+'/reports';os.rename(p,p+'-moved')\nif s['symlink']:os.symlink(p+'-moved',p)\nelse:\n os.mkdir(p);open(p+'/live','wb').write(b'unowned parent bytes')\nprint('{}')",{'root':c['root'],'symlink':symlink});ep.release(c);time.sleep(.4);status=ep.status(c);assert 'Ready' not in status['native']['status'];ep.stop(c)
            if not symlink:assert ep.read(c)==b'unowned parent bytes'.hex()
            self.record(platform,'parent-symlink' if symlink else 'parent-movement',status=status,moved=ep.read(c,'reports-moved/live'))
        c=ep.create('dirty');ep.start(c);self.until(lambda:ep.ready(c));ep.stop(c);original=ep.status(c)['status']['binding'];ep.write(c,b'local dirty collision retained');shared=self.publish((platform+' remote collision accepted').encode());ep.start(c)
        self.until(lambda:any(p['private_receipt'] and p['error']=='stale_head' for p in ep.status(c)['status']['submissions']))
        status=ep.status(c);assert ep.read(c)==b'local dirty collision retained'.hex();assert 'Ready' not in status['native']['status'];assert status['status']['binding']['view']['head']==original['view']['head'];assert all(p['private_receipt']['original_head']==original['view']['head'] for p in status['status']['submissions'] if p['private_receipt']);self.record(platform,'dirty-collision-frozen-base',status=status,original=original,incoming=shared);ep.stop(c)
        self.permissions(ep)
    def permissions(self,ep):
        platform=ep.platform
        self.directory_mode(0o555);c=ep.create('readonly');ep.start(c);self.until(lambda:ep.ready(c));before=ep.read(c);self.publish((platform+' must not overwrite readonly').encode());
        try:self.until(lambda:bool(ep.status(c).get('native') and 'ApplyBlocked' in ep.status(c)['native']['status']))
        finally:self.i.write_json(platform+'-permissions-last-status.json',ep.status(c))
        assert ep.read(c)==before;self.record(platform,'readonly-parent',status=ep.status(c),bytes=before);ep.stop(c);self.directory_mode(0o755)
        # FS2-B: directory creation is applied by verified root exchange instead of blocking.
        c=ep.create('directory');ep.start(c);self.until(lambda:ep.ready(c));shared=self.publish(path=platform+'-new-directory',directory=True);self.until(lambda:ep.ready(c,shared['head']));assert ep.run("print(json.dumps(os.path.isdir(s)))",c['root']+'/'+platform+'-new-directory');self.record(platform,'directory-creation-applied',status=ep.status(c),shared=shared);ep.stop(c)
    def cleanup(self):
        for ep in self.endpoints:ep.cleanup()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--platform',choices=['all','macos','linux'],default='all');ap.add_argument('--skip-build',action='store_true');ap.add_argument('--image');ap.add_argument('--case',choices=['full','supplement','permissions','retention'],default='full');a=ap.parse_args();i=OwnedInfra(a.output);j=None;code=1
    try:
        i.preflight();source=capture(i);image=a.image or i.owner+'-native';i.write_json('image-ownership.json',{'tag':image,'intent':'retained native test image'})
        if not a.skip_build:
            i.run(['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],timeout=300);shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults');os.chmod(ROOT/'target/debug/magus-fs-client-faults',0o755)
            i.run(['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
            i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=0','--label','magus.fs2.owner='+i.owner,'-t',image,'.',timeout=900)
        elif not a.image:raise ValueError('--skip-build requires exact --image')
        i.setup(image);verify_image(i,source)
        i.write_json('native-binaries.json',{n:{'host':hashlib.sha256((ROOT/'target/debug'/n).read_bytes()).hexdigest(),'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+n).stdout.split()[0]} for n in ['magus-fs','magus-fs-client-faults']})
        j=NativeJourney(i,image,['macos','linux'] if a.platform=='all' else [a.platform],a.case);started=time.monotonic();j.run();elapsed=time.monotonic()-started;assert elapsed<=600;i.write_json('native-duration.json',{'seconds':elapsed,'limit':600});code=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});code=2
    except Exception as e:i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()})
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e)});code=1
        i.write_json('result.json',{'passed':code==0,'exit':code,'scope':'native-owner-service','platform':a.platform,'case':a.case})
    return code
if __name__=='__main__':sys.exit(main())
