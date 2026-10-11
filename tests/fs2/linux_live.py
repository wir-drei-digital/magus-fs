#!/usr/bin/env python3
"""Owned real Linux FUSE + authenticated service live-adoption gate."""
import argparse,hashlib,json,os,secrets,subprocess,sys,time,traceback
from pathlib import Path
from infra import OwnedInfra,InfrastructureUnavailable,ROOT
from provenance import capture,verify_image
from service_protocol import Journey,identity,file_entry,GROUP,REPLICA,WORKER
from service_storage import NS,ALICE

class LiveJourney(Journey):
    def __init__(self,i,image):
        super().__init__(i);self.image=image;self.daemon=None;self.mounts=[];self.evidence={};self.holders=[]
    def execute(self,code,settings=None,user='0:0',check=True):
        result=self.i.docker('exec','-i','--user',user,self.daemon,'python3','-c',code,input=json.dumps(settings) if settings is not None else '',evidence=False,check=False,timeout=70)
        if check:assert result.returncode==0,(result.stdout,result.stderr)
        return json.loads(result.stdout) if result.returncode==0 else result
    def cli(self,*args):
        return self.execute("import json,subprocess,sys; a=json.load(sys.stdin);p=subprocess.run(['magus-fs',*a],capture_output=True,text=True);assert p.returncode==0,(a,p.stdout,p.stderr);print(p.stdout)",list(args))
    def publish(self,mutate,bodies=()):
        view,r=self.view();mutate(r);_,private=self.candidate(view,r,'alice',bodies)
        return self.expect('live-integrate','POST',self.root+'/integrations',200,body=self.integrate_request(private,view))
    def start(self,name,readonly=False,publication='shared-live',actor='alice'):
        settings={'name':name,'namespace':NS,'replica':WORKER if actor=='worker' else REPLICA,'principal':ALICE,'group':GROUP,'token':self.tokens[actor],'ca':(self.i.control/'ca.crt').read_text(),'readonly':readonly,'publication':publication}
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
config={'replica':{'replica':s['replica'],'authorities':[{'principal':s['principal'],'uid':1001,'gid':1001,'primary_group':s['group'],'groups':[s['group']],'dac_override':False,'ownership_transfer':True},{'principal':'principal:'+'b'*32,'uid':1002,'gid':1001,'primary_group':s['group'],'groups':[s['group']],'dac_override':False,'ownership_transfer':False},{'principal':'principal:'+'c'*32,'uid':0,'gid':0,'primary_group':'group:'+'c'*32,'groups':['group:'+'c'*32],'dac_override':True,'ownership_transfer':True}],'content_roots':[mount],'cache_bytes':96*1024*1024},'root':mount,'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
cli('init','--state',control+'/state','--config',private('config',config))
profile=private('profile',{'endpoint':'https://service:8443','namespace':s['namespace'],'replica':s['replica'],'ca_file':private('ca',s['ca']),'token_file':private('token',s['token']),'publication_principal':s['principal']})
attached=cli('sync','attach','--state',control+'/state','--profile',profile,'--branch','main','--publication',s['publication'])
argv=['magus-fs','mount','--state',control+'/state','--revision',attached['binding']['view']['revision'],'--mountpoint',mount,'--mode','read-only' if s['readonly'] else 'private']
log=open(control+'/daemon.log','w');p=subprocess.Popen(argv,stdout=log,stderr=log);private('pid',str(p.pid))
deadline=time.monotonic()+10
while not os.path.ismount(mount):
 assert p.poll() is None,(p.poll(),open(control+'/daemon.log').read())
 assert time.monotonic()<deadline,'mount timeout'
 time.sleep(.05)
print(json.dumps({'pid':p.pid,'binding':attached['binding']}))''',settings)
        if publication=='shared-live':self.until(lambda:self.cli('sync','status','--state','/private/'+name+'/state')['live']['applied'])
        return result
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':True}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o775,'content':{'kind':'directory'}}
        old=b'held epoch original bytes';entry=file_entry('reports/live',reports['id'],old);entry['mode']=0o660
        upload,rid=self.stage(self.descriptor([reports,entry]),bodies=[old]);self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        code,delegated=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['reports']}});assert code==200
        self.tokens['worker']=delegated['token'];self.credential=delegated['credential']
        self.daemon=self.i.create('container','live',['--network',self.i.ingress,'--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','DAC_OVERRIDE','--cap-add','SYS_CHROOT','--security-opt','apparmor=unconfined','--security-opt','no-new-privileges','--device','/dev/fuse','--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/private:rw,nosuid,nodev,mode=700,size=256m','--tmpfs','/shared:rw,nosuid,nodev,mode=755,size=16m',self.image,'python3','-c',"import os,signal,time,json\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\n  with open('/tmp/reaped','a') as f:f.write(json.dumps({'pid':p,'status':s})+'\\n')\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
        self.i.docker('start',self.daemon);mounted=self.start('live');self.evidence['initial']=mounted
        # Ordinary process keeps the descriptor across remote acceptance. Its output is outside control.
        holder='''import errno,hashlib,json,os,time
root='/shared/live';h=os.open(root+'/reports/live',os.O_RDWR);before=os.fstat(h);old=os.pread(h,1000,0)
open('/tmp/held-ready','w').write('ready')
deadline=time.monotonic()+20
while not os.path.exists('/tmp/held-go'):
 assert time.monotonic()<deadline
 time.sleep(.02)
after=os.fstat(h);held=os.pread(h,1000,0);fresh=open(root+'/reports/live','rb').read()
try:os.pwrite(h,b'bad',0);native=0
except OSError as e:native=e.errno
out={'old_hash':hashlib.sha256(old).hexdigest(),'held_hash':hashlib.sha256(held).hexdigest(),'new_hash':hashlib.sha256(fresh).hexdigest(),'old_size':before.st_size,'held_size':after.st_size,'new_size':os.stat(root+'/reports/live').st_size,'stale_errno':native,'old_inode':before.st_ino,'new_inode':os.stat(root+'/reports/live').st_ino}
open('/tmp/held-result','w').write(json.dumps(out));os.close(h)
'''
        self.holders.append(self.execute("import json,subprocess,sys;code=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code],stdout=open('/tmp/held-log','w'),stderr=subprocess.STDOUT);print(json.dumps({'pid':p.pid}))",holder,user='1001:1001')['pid']);self.i.write_json('holder-ownership.json',self.holders)
        self.until(lambda:self.execute("import json,os;print(json.dumps(os.path.exists('/tmp/held-ready')))"))
        self.evidence['before_publish']=self.cli('sync','status','--state','/private/live/state')['live']
        new=b'accepted remote version with a longer body'
        def change(r):r['tree']['entries'][1]['content']=file_entry('unused',reports['id'],new)['content']
        start=time.monotonic();shared=self.publish(change,[new]);self.evidence['shared']=shared
        self.until(lambda:self.execute("import json\ntry:v=open('/shared/live/reports/live','rb').read().hex()\nexcept FileNotFoundError:v=None\nprint(json.dumps(v))",user='1001:1001')==new.hex(),15)
        elapsed=time.monotonic()-start
        self.execute("import json;open('/tmp/held-go','w').write('go');print('{}')",user='1001:1001')
        self.until(lambda:self.execute("import json,os;print(json.dumps(os.path.exists('/tmp/held-result')))"))
        held=self.execute("print(open('/tmp/held-result').read())");self.evidence.update({'held':held,'visible_seconds':elapsed,'status':self.cli('sync','status','--state','/private/live/state')});self.save()
        assert held['held_hash']==hashlib.sha256(old).hexdigest() and held['held_size']==len(old)
        assert held['new_hash']==hashlib.sha256(new).hexdigest() and held['new_size']==len(new)
        assert held['stale_errno']==116 and held['old_inode']!=held['new_inode']
        if getattr(self, "isolated_authority_only", False):self.isolated_authority_case()
        else:self.more_cases(reports)
    def isolated_authority_case(self):
        self.start('isolated',publication='isolated',actor='worker')
        cached=self.read('isolated/reports/live')
        self.start('isolated-clean',publication='isolated',actor='worker')
        assert self.read('isolated-clean/reports/live')==cached
        clean_before=self.cli('sync','status','--state','/private/isolated-clean/state')['live']
        self.execute("import json,os;f=open('/shared/isolated/reports/private','wb');f.write(b'never published private bytes');f.flush();os.fsync(f.fileno());f.close();print('{}')",user='1001:1001')
        before=self.cli('sync','status','--state','/private/isolated/state')['live']
        def denied():
            return self.execute("import json,os\ndef write(path):\n fd=os.open(path,os.O_WRONLY)\n try:os.pwrite(fd,open(path,'rb').read(1),0)\n finally:os.close(fd)\nrows={}\nfor name,fn in [('cached_read',lambda:open('/shared/isolated/reports/live','rb').read()),('clean_read',lambda:open('/shared/isolated-clean/reports/live','rb').read()),('cached_write',lambda:write('/shared/isolated/reports/live')),('private_write',lambda:write('/shared/isolated/reports/private'))]:\n try:fn();rows[name]=0\n except OSError as e:rows[name]=e.errno\nprint(json.dumps(rows))",user='1001:1001')
        self.expect('isolated-revoke','POST',self.root+'/grants',200,body={'revoke':self.credential})
        try:self.until(lambda:set(denied().values())=={13},15)
        finally:self.evidence['isolated_authority']={'before':before,'denied_errno':denied()};self.save()
        code,renewed=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['reports']}});assert code==200
        self.execute("import json,sys;token=json.load(sys.stdin)\nfor name in ['isolated','isolated-clean']:open('/private/'+name+'/token','w').write(token)\nprint('{}')",renewed['token'])
        self.until(lambda:set(denied().values())=={0},15)
        refreshed=self.cli('sync','status','--state','/private/isolated/state')['live']
        assert refreshed['epoch']==before['epoch'] and refreshed['revision']==before['revision']
        assert self.read('isolated/reports/live')==cached and self.read('isolated/reports/private')==b'never published private bytes'.hex()
        def change_content(r):
            entry=next(e for e in r['tree']['entries'] if e['path']=='reports/live');entry['content']=file_entry('unused',entry['parent'],b'changed shared bytes')['content']
        shared=self.publish(change_content,[b'changed shared bytes']);self.accepted(shared)
        self.until(lambda:self.cli('sync','status','--state','/private/isolated-clean/state')['live']['pending_revision'] is not None,15)
        clean_after=self.cli('sync','status','--state','/private/isolated-clean/state')['live']
        assert clean_after['epoch']==clean_before['epoch'] and clean_after['revision']==clean_before['revision'] and self.read('isolated-clean/reports/live')==cached
        assert self.read('isolated/reports/live')==cached and self.read('live/reports/live')==b'changed shared bytes'.hex()
        refreshed_errno=denied();assert set(refreshed_errno.values())=={0}
        def revoke_mode(r):next(e for e in r['tree']['entries'] if e['path']=='reports/live')['mode']=0
        shared=self.publish(revoke_mode);self.accepted(shared)
        self.until(lambda:denied()['cached_read']==13 and denied()['cached_write']==13 and denied()['clean_read']==13,15)
        assert denied()['private_write']==0
        after=self.cli('sync','status','--state','/private/isolated/state')['live'];assert after['epoch']==before['epoch'] and after['revision']==before['revision']
        assert self.read('isolated/reports/private')==b'never published private bytes'.hex()
        self.evidence['isolated_authority'].update({'clean_before':clean_before,'clean_after':clean_after,'clean_bytes_retained':True,'refreshed':refreshed,'mode_revoked':after,'mode_errno':denied(),'refreshed_errno':refreshed_errno,'cached_hash':hashlib.sha256(bytes.fromhex(cached)).hexdigest(),'cached_size':len(bytes.fromhex(cached)),'private_hash':hashlib.sha256(b'never published private bytes').hexdigest(),'private_size':len(b'never published private bytes')});self.save()

    def accepted(self,shared,name='live'):
        def ready():
            status=self.cli('sync','status','--state','/private/'+name+'/state')
            return status['status']['binding']['view']['head']==shared['head'] and status['live']['applied']
        self.until(ready,15)
    def read(self,path,user='1001:1001'):
        return self.execute("import json,sys;print(json.dumps(open(json.load(sys.stdin),'rb').read().hex()))",'/shared/'+path,user=user)
    def hold(self,path):
        tag='held-'+secrets.token_hex(5)
        self.i.write_json('holder-ownership.json',{'pids':self.holders,'creating':tag})
        code='''import errno,hashlib,json,os,sys,time
path,tag=json.loads(sys.argv[1]);fd=os.open(path,os.O_RDONLY);before=os.fstat(fd);initial=os.pread(fd,4096,0)
open('/tmp/'+tag+'-ready','w').write('ready');deadline=time.monotonic()+40
while not os.path.exists('/tmp/'+tag+'-go'):
 assert time.monotonic()<deadline
 time.sleep(.02)
row={'before_size':before.st_size,'before_hash':hashlib.sha256(initial).hexdigest()}
try:row['after_size']=os.fstat(fd).st_size
except OSError as e:row['stat_errno']=e.errno
try:row['after_hash']=hashlib.sha256(os.pread(fd,4096,0)).hexdigest()
except OSError as e:row['read_errno']=e.errno
os.close(fd);open('/tmp/'+tag+'-result','w').write(json.dumps(row))
'''
        pid=self.execute("import json,subprocess,sys;code,args,tag=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code,json.dumps(args)],stdout=open('/tmp/'+tag+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",[code,['/shared/'+path,tag],tag],user='1001:1001');self.holders.append(pid);self.i.write_json('holder-ownership.json',{'pids':self.holders})
        self.until(lambda:self.execute("import json,os,sys;print(json.dumps(os.path.exists('/tmp/'+json.load(sys.stdin)+'-ready')))",tag));return tag
    def finish(self,tag):
        self.execute("import json,sys;open('/tmp/'+json.load(sys.stdin)+'-go','w').write('go');print('{}')",tag,user='1001:1001')
        self.until(lambda:self.execute("import json,os,sys;print(json.dumps(os.path.exists('/tmp/'+json.load(sys.stdin)+'-result')))",tag))
        return self.execute("import json,sys;print(open('/tmp/'+json.load(sys.stdin)+'-result').read())",tag)
    def confined_root(self,code):
        # Chroot before dropping all authority except DAC_OVERRIDE; no outside directory FDs.
        wrapper='''import ctypes,json,os,sys,errno,socket,stat,hashlib
code=json.load(sys.stdin);libc=ctypes.CDLL(None,use_errno=True)
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Caps(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
os.chroot('/shared');os.chdir('/')
assert libc.prctl(38,1,0,0,0)==0
h=Header(0x20080522,0);c=(Caps*2)();c[0].effective=2;c[0].permitted=2
assert libc.capset(ctypes.byref(h),ctypes.byref(c))==0
exec(code)
'''
        return self.execute(wrapper,code)
    def more_cases(self,reports):
        # Rename keeps identity; replacement/unlink conservatively remove old-epoch authority.
        held=self.hold('live/reports/live')
        shared=self.publish(lambda r:next(e for e in r['tree']['entries'] if e['path']=='reports/live').update(path='reports/renamed'));self.accepted(shared)
        renamed=self.finish(held);assert renamed['before_hash']==renamed['after_hash'] and renamed['before_size']==renamed['after_size']
        held=self.hold('live/reports/renamed');replacement=b'replacement identity'
        def replace(r):
            r['tree']['entries']=[e for e in r['tree']['entries'] if e['path']!='reports/renamed'];r['tree']['entries'].append(file_entry('reports/renamed',reports['id'],replacement))
        shared=self.publish(replace,[replacement]);self.accepted(shared);replaced=self.finish(held);assert replaced['read_errno']==13 and replaced['stat_errno']==13
        held=self.hold('live/reports/renamed')
        shared=self.publish(lambda r:r['tree'].update(entries=[e for e in r['tree']['entries'] if e['path']!='reports/renamed']));self.accepted(shared);unlinked=self.finish(held);assert unlinked['read_errno']==13
        sub={'path':'reports/sub','id':identity('entry'),'parent':reports['id'],'owner':ALICE,'group':GROUP,'mode':0o775,'content':{'kind':'directory'}};body=b'parent move content';child=file_entry('reports/sub/child',sub['id'],body);child['mode']=0o660
        shared=self.publish(lambda r:r['tree']['entries'].extend([sub,child]),[body]);self.accepted(shared);held=self.hold('live/reports/sub/child')
        def move_parent(r):
            for e in r['tree']['entries']:
                if e['path']=='reports/sub' or e['path'].startswith('reports/sub/'):e['path']=e['path'].replace('reports/sub','reports/next',1)
        shared=self.publish(move_parent);self.accepted(shared);parent=self.finish(held);assert parent['before_hash']==parent['after_hash']
        metadata=self.execute("import json,os;v=os.stat('/shared/live/reports/next/child');print(json.dumps({'uid':v.st_uid,'gid':v.st_gid,'mode':v.st_mode&511,'names':os.listdir('/shared/live/reports')}))",user='1001:1001');assert metadata=={'uid':1001,'gid':1001,'mode':0o660,'names':['next']}
        assert self.read('live/reports/next/child',user='1002:1001')==body.hex()
        self.evidence['structure']={'rename':renamed,'replacement':replaced,'unlink':unlinked,'parent':parent,'metadata':metadata};self.save()
        self.start('readonly',readonly=True)
        readonly='''root=ROOT
rows={}
for name,fn in [('write',lambda:open(root+'/reports/next/child','wb')),('create',lambda:open(root+'/reports/new','w')),('mkdir',lambda:os.mkdir(root+'/reports/new-dir')),('truncate',lambda:os.truncate(root+'/reports/next/child',0)),('rename',lambda:os.rename(root+'/reports/next/child',root+'/reports/moved')),('unlink',lambda:os.unlink(root+'/reports/next/child')),('chmod',lambda:os.chmod(root+'/reports/next/child',511)),('chown',lambda:os.chown(root+'/reports/next/child',1001,1001)),('root-chmod',lambda:os.chmod(root,511))]:
 try:fn();rows[name]=0
 except OSError as e:rows[name]=e.errno
assert set(rows.values())=={errno.EROFS},rows
print(json.dumps(rows))
'''
        nonroot=self.execute('import json,os,errno\n'+readonly.replace('ROOT',repr('/shared/readonly')),user='1001:1001')
        root=self.confined_root(readonly.replace('ROOT',repr('/readonly')))
        control=self.execute("import errno,json,os,socket;rows={}\nfor name,fn in [('credential',lambda:open('/private/live/token').read()),('control',lambda:socket.socket(socket.AF_UNIX).connect('/private/live/state/control.sock'))]:\n try:fn();rows[name]=0\n except OSError as e:rows[name]=e.errno\nassert set(rows.values())=={errno.EACCES};print(json.dumps(rows))",user='1001:1001')
        jail=self.confined_root("rows={}\nfor path in ['/private/live/token','/private/live/state/control.sock','/proc/1/root/private/live/token']:\n try:open(path);rows[path]=0\n except OSError as e:rows[path]=e.errno\nassert set(rows.values())=={errno.ENOENT};print(json.dumps(rows))")
        self.evidence['readonly']={'nonroot':nonroot,'confined_root':root,'control_denial':control,'root_jail':jail};self.save()
        # Dirty content remains pending while the clean reader applies the same publication.
        self.start('dirty',actor='worker');self.start('reauth',actor='worker')
        self.read('dirty/reports/next/child')
        self.execute("import json,os;f=open('/shared/dirty/reports/private','wb');f.write(b'private retained bytes');f.flush();os.fsync(f.fileno());f.close();print('{}')",user='1001:1001')
        before=self.cli('sync','status','--state','/private/dirty/state');newbody=b'new remote body while worker is dirty'
        def changed(r):next(e for e in r['tree']['entries'] if e['path']=='reports/next/child')['content']=file_entry('unused',sub['id'],newbody)['content']
        shared=self.publish(changed,[newbody]);self.accepted(shared);self.accepted(shared,'reauth')
        self.until(lambda:self.cli('sync','status','--state','/private/dirty/state')['live']['pending_revision'] is not None)
        pending=self.cli('sync','status','--state','/private/dirty/state');assert pending['live']['epoch']==before['live']['epoch'] and self.read('dirty/reports/next/child')==body.hex() and self.read('dirty/reports/private')==b'private retained bytes'.hex()
        oldsource=self.cli('sync','status','--state','/private/reauth/state')['status']['binding']['source']
        self.expect('revoke-worker','POST',self.root+'/grants',200,body={'revoke':self.credential})
        self.until(lambda:not self.cli('sync','status','--state','/private/dirty/state')['live']['authorized']);self.until(lambda:not self.cli('sync','status','--state','/private/reauth/state')['live']['authorized'])
        denied=self.execute("import json,os,errno;rows={}\nfor name in ['dirty','reauth']:\n try:open('/shared/'+name+'/reports/next/child','rb').read();rows[name]=0\n except OSError as e:rows[name]=e.errno\nassert set(rows.values())=={errno.EACCES};print(json.dumps(rows))",user='1001:1001')
        code,renewed=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['reports']}});assert code==200;self.tokens['worker']=renewed['token']
        self.execute("import json,sys;token=json.load(sys.stdin)\nfor name in ['dirty','reauth']:open('/private/'+name+'/token','w').write(token)\nprint('{}')",renewed['token'])
        self.until(lambda:self.cli('sync','status','--state','/private/reauth/state')['status']['binding']['source']!=oldsource)
        self.until(lambda:self.cli('sync','status','--state','/private/dirty/state')['live']['authorized'])
        assert self.read('reauth/reports/next/child')==newbody.hex();assert self.read('dirty/reports/private')==b'private retained bytes'.hex()
        refreshed=self.cli('sync','status','--state','/private/dirty/state');assert refreshed['live']['epoch']==before['live']['epoch'] and refreshed['live']['pending_revision']
        self.evidence['dirty_and_credential']={'before':before['live'],'pending':pending['live'],'denied_errno':denied,'refreshed':refreshed['live'],'old_source':oldsource,'new_source':self.cli('sync','status','--state','/private/reauth/state')['status']['binding']['source']};self.save()
        # An isolated ordinary Python workload writes Alice-owned output; checkpoint is trusted control.
        self.start('worker',publication='isolated',actor='worker')
        output=self.execute("import hashlib,json,os;value=json.dumps({'sum':sum(i*i for i in range(1000))},sort_keys=True).encode();f=open('/shared/worker/reports/python-output','wb');f.write(value);f.flush();os.fsync(f.fileno());f.close();s=os.stat('/shared/worker/reports/python-output');print(json.dumps({'sha256':hashlib.sha256(value).hexdigest(),'size':len(value),'uid':s.st_uid,'gid':s.st_gid}))",user='1001:1001');assert output['uid']==1001 and output['gid']==1001
        operation=identity('operation');revision=self.cli('checkpoint','--state','/private/worker/state','--operation-id',operation)['revision'];private=self.cli('sync','run','--state','/private/worker/state','--revision',revision,'--operation-id',operation)['progress'];assert private['state']=='PrivateRemote' and private['private_receipt']['submitted_revision']==revision and private['shared_receipt'] is None
        self.execute("import json,os;assert not os.path.exists('/shared/live/reports/python-output');print('{}')",user='1001:1001')
        self.evidence['private_python']={'output':output,'revision':revision,'receipt':private['private_receipt'],'shared_reader_unchanged':True};self.save()
        # Current mode removal applies to dirty cached reads without replacing private bytes.
        def revoke_mode(r):next(e for e in r['tree']['entries'] if e['path']=='reports/next/child')['mode']=0
        shared=self.publish(revoke_mode);self.accepted(shared)
        self.until(lambda:self.execute("import json,errno\ntry:open('/shared/dirty/reports/next/child','rb').read();code=0\nexcept OSError as e:code=e.errno\nprint(json.dumps(code))",user='1001:1001')==13)
        assert self.read('dirty/reports/private')==b'private retained bytes'.hex()
        self.evidence['dirty_current_mode_revoke']={'errno':13,'private_bytes_retained':True}
        logs=self.execute("import json;print(json.dumps(open('/private/live/daemon.log').read()))");assert 'live_hint cursor=' in logs and 'live_applied epoch=' in logs
        self.evidence['daemon_log']=logs;self.save()

    def until(self,predicate,seconds=10):
        deadline=time.monotonic()+seconds
        while not predicate():
            assert time.monotonic()<deadline,'observable mounted visibility deadline exceeded'
            time.sleep(.05)
    def save(self):self.i.write_json('live-evidence.json',self.evidence)
    def unmount(self,name):
        assert name in self.mounts,'unrecorded mount'
        return self.execute('''import json,os,subprocess,sys,time
name=json.load(sys.stdin);mount='/shared/'+name;control='/private/'+name
deadline=time.monotonic()+10
while True:
 p=subprocess.run(['umount',mount],capture_output=True,text=True,timeout=10)
 if p.returncode==0:break
 assert 'busy' in p.stderr.lower() and time.monotonic()<deadline,(p.stdout,p.stderr)
 time.sleep(.05)
assert not os.path.ismount(mount)
pid=int(open(control+'/pid').read());deadline=time.monotonic()+10
while os.path.exists('/proc/'+str(pid)):
 assert time.monotonic()<deadline,'daemon failed normal exit'
 time.sleep(.05)
print(json.dumps({'mount':mount,'unmount':p.returncode,'still_mounted':False,'pid':pid,'exited':True,'reaped':True}))''',name)

    def cleanup(self):
        if not self.daemon:return
        rows=[]
        # Release/reap exact owned workloads before attempting normal unmount.
        if self.holders:
            self.execute("import json,os,signal,sys,time;ids=json.load(sys.stdin)\nfor pid in ids:\n try:os.kill(pid,signal.SIGTERM)\n except ProcessLookupError:pass\ndeadline=time.monotonic()+5\nwhile any(os.path.exists('/proc/'+str(pid)) for pid in ids):\n assert time.monotonic()<deadline\n time.sleep(.05)\nprint('{}')",self.holders)
        for name in self.mounts:
            rows.append(self.unmount(name))
        self.i.write_json('mount-cleanup.json',rows)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--image',default='magus-fs2-task4-live');p.add_argument('--reuse-image',action='store_true');p.add_argument('--isolated-authority-only',action='store_true');a=p.parse_args()
    i=OwnedInfra(Path(a.output));j=None;status=1;clean=False
    try:
        i.preflight();source=capture(i)
        if not a.reuse_image:i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=client-fix','-t',a.image,'.',timeout=900)
        i.setup(a.image);verify_image(i,source)
        i.write_json('binary-identity.json',{'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/magus-fs').stdout})
        j=LiveJourney(i,a.image);j.isolated_authority_only=a.isolated_authority_only;started=time.monotonic();j.run();assert time.monotonic()-started<600;status=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});status=2
    except Exception as e:i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()})
    finally:
        try:
            if j:j.save();j.cleanup()
            clean=True;i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e),'helpers_retained':not clean});status=1
        i.write_json('result.json',{'status':status,'scope':'Task4 Linux mounted live adoption','cleanup':clean})
    print(json.dumps({'status':status,'output':str(i.output)}));return status
if __name__=='__main__':sys.exit(main())
