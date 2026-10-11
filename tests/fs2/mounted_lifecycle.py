#!/usr/bin/env python3
"""Ordinary mounted saves progress through the single owner without publication controls.
The optional actual-agent boundary is coordinated by the root chat, never emulated here.
"""
import argparse, hashlib, json, os, re, secrets, shutil, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, verify_image, sources, resolve_reused_image
from full_native import NativeJourney, Endpoint
from connected import Lazy
from service_protocol import GROUP, REPLICA, WORKER, identity, file_entry
from service_storage import NS, ALICE

ROOT_INSTRUCTIONS = b'''# Synthetic ICM\nRead work/AGENTS.md before editing work files. Use ordinary files only. Preserve existing records.\n'''
WORK_INSTRUCTIONS = b'''# Work procedures\nRead procedure.txt and the selected task file. Append a line with completed-value: COMPUTED_VALUE and procedure-code: ACTUAL_CODE from the procedure. Keep all prior lines, including task-value.\n'''
PROCEDURE = b'''procedure-code: mounted-ordinary-v1\nUse integer arithmetic: completed-value is task-value plus seven.\n'''

class Mounted(NativeJourney):
    def __init__(self,i,image,focused=False,agents=False):
        super().__init__(i,image,['linux','macos']);self.lazy=None;self.secondary=None;self.workloads=[];self.focused=focused;self.agents=agents;self.records=[];self.observer=None;self.mac=None
    def owner(self,name):
        return self.secondary if name=='b' else self.lazy
    def note(self,case,**data):
        self.records.append({'case':case,**data});self.i.write_json('mounted-evidence.json',self.records)
    def write(self,name,path,body):
        return self.owner(name).execute("import json,sys,os;s=json.load(sys.stdin)\nwith open('/shared/'+s['name']+'/'+s['path'],'wb') as f:f.write(bytes.fromhex(s['body']));f.flush();os.fsync(f.fileno())\nprint('{}')",{'name':name,'path':path,'body':body.hex()},user='1001:1001')
    def received(self,name,path,body):
        return self.owner(name).has(name+'/'+path) and self.owner(name).read(name+'/'+path)==body.hex()
    def receipt(self,name,prior):
        return next((p for p in self.owner(name).status(name)['status']['submissions'] if p['operation'] not in prior and p['shared_receipt']),None)
    def save_and_wait(self,name,path,body,other):
        before=self.owner(name).status(name);prior=[p['operation'] for p in before['status']['submissions']];start=time.monotonic();self.write(name,path,body)
        try:self.until(lambda:self.received(other,path,body),15)
        finally:self.note('ordinary-save',name=name,path=path,body_sha256=hashlib.sha256(body).hexdigest(),before=before,after=self.owner(name).status(name),other=self.owner(other).status(other),seconds=time.monotonic()-start)
        p=self.until(lambda:self.receipt(name,prior));pending=self.owner(name).cli('sync','status','--state','/private/'+name+'/state')
        assert p['private_receipt']['submitted_revision']==p['local_revision'] and p['private_receipt']['original_head']==before['status']['binding']['view']['head']
        self.until(lambda:self.owner(other).status(other)['live']['applied'])
        assert p['shared_receipt']['submitted_revision']==p['local_revision']
        counts={op:self.i.sql("SELECT count(*) FROM operations WHERE operation='"+op+"';") for op in [p['operation'],p['integration']['operation']]}
        assert set(counts.values())=={'1'};assert p['operation']!=p['integration']['operation']
        self.note('exact-receipts',progress=p,status=pending,operation_cardinality=counts)
        return p
    def run(self):
        self.i.start_service();self.wait();authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        dirs=[]
        for path in ['work','reports']:
            dirs.append({'path':path,'id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}})
        parent={e['path']:e['id'] for e in dirs};bodies={'AGENTS.md':ROOT_INSTRUCTIONS,'work/AGENTS.md':WORK_INSTRUCTIONS,'work/procedure.txt':PROCEDURE,'work/task-a.txt':b'task-value: 11\n','work/task-b.txt':b'task-value: 29\n','reports/live':b'initial mounted content'}
        entries=dirs+[file_entry(path,parent.get(path.split('/')[0],self.tree_root['id']),body) for path,body in bodies.items()]
        for e in entries:
            if e['content']['kind']=='file':e['mode']=0o644
        upload,rid=self.stage(self.descriptor(entries),bodies=list(bodies.values()));self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        for actor,replica in [('bob','replica:'+f'{3:032x}'),('worker',WORKER),('readonly','replica:'+f'{4:032x}')]:
            g=self.expect('grant-'+actor,'POST',self.root+'/grants',200,body={'delegate':{'replica':replica,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}});self.tokens[actor]=g['token']
        self.lazy=Lazy(self,suffix='lazy-a');self.secondary=Lazy(self,suffix='lazy-b');l=self.lazy
        self.initial={'a':l.start('a'),'b':self.secondary.start('b',actor='bob')};self.note('mounted-roots',roots=self.initial)
        assert not l.status('a')['status']['submissions'] and not self.secondary.status('b')['status']['submissions']
        if not self.focused:
            self.observer=Endpoint(self,'macos',self.image);self.endpoints.append(self.observer);self.mac=self.observer.create('observer');self.observer.start(self.mac);self.until(lambda:self.observer.ready(self.mac))
        self.save_and_wait('a','reports/live',b'ordinary save one','b')
        if self.focused:return
        self.save_and_wait('a','reports/live',b'ordinary save two','b')
        fresh=bytes.fromhex(self.secondary.read('b/reports/live'));self.save_and_wait('b','reports/live',fresh+b' freshly reread follow-up','a')
        l.execute("import os;os.mkdir('/shared/a/work/new');os.rename('/shared/a/work/new','/shared/a/work/renamed');print('{}')",user='1001:1001');self.until(lambda:self.secondary.has('b/work/renamed'))
        self.save_and_wait('a','work/renamed/later',b'work after directory rename','b')
        self.restart_capture();self.contention();self.conflict();self.negatives();self.converge()
        if self.agents:self.agent_boundary(bodies)
        self.inventories()
    def head(self):
        return self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
    def ready(self,name,head=None):
        s=self.owner(name).status(name);return s['live']['applied'] and (head is None or s['status']['binding']['view']['head']==head)
    def converge(self):
        head=self.head();self.until(lambda:self.ready('a',head) and self.ready('b',head),15)
        if self.observer:self.until(lambda:self.observer.ready(self.mac,head),15)
        return head
    def restart(self,name,fault=False,kill=False):
        l=self.owner(name);state='/private/'+name+'/state';control='/private/'+name
        if kill:
            l.execute("import json,sys,os,signal,time;n=json.load(sys.stdin);p=int(open('/private/'+n+'/pid').read());assert os.readlink('/proc/'+str(p)+'/exe') in ['/usr/local/bin/magus-fs','/usr/local/bin/magus-fs-client-faults'];os.kill(p,signal.SIGKILL);deadline=time.monotonic()+5\nwhile os.path.exists('/proc/'+str(p)):\n assert time.monotonic()<deadline\n time.sleep(.02)\nprint('{}')",name)
        row=l.unmount(name);self.note('normal-unmount-for-restart',name=name,**row)
        status=l.status(name);history=l.cli('history','--state',state)
        self.note('stopped-owner-state',name=name,status=status,history=history)
        launched=l.execute('''import json,os,sys,subprocess,time
s=json.load(sys.stdin);n=s['name'];control='/private/'+n;mount='/shared/'+n
assert not os.path.ismount(mount);os.rmdir(mount)
env=os.environ.copy()
if s['fault']:env.update(MAGUS_TEST_FAULT_POINT='after-commit',MAGUS_TEST_FAULT_ACTION='pause',MAGUS_TEST_FAULT_MARKER=control+'/captured-before-admit')
log=open(control+'/daemon.log','a');p=subprocess.Popen(['magus-fs-client-faults' if s['fault'] else 'magus-fs','mount','--state',control+'/state','--revision',s['revision'],'--mountpoint',mount,'--mode','private'],stdout=log,stderr=log,env=env)
open(control+'/pid','w').write(str(p.pid));deadline=time.monotonic()+10
while not os.path.ismount(mount) or not os.path.exists(control+'/state/control.sock'):
 assert p.poll() is None,(p.poll(),open(control+'/daemon.log').read())
 assert time.monotonic()<deadline
 time.sleep(.02)
print(json.dumps({'pid':p.pid,'revision':s['revision']}))''',{'name':name,'fault':fault,'revision':status['status']['binding']['view']['revision']})
        self.note('restarted-owner',name=name,launched=launched,fault=fault)
        return status,history
    def restart_capture(self):
        self.converge();before=self.lazy.status('a');known={p['operation'] for p in before['status']['submissions']};self.restart('a',fault=True)
        self.write('a','work/restarted.txt',b'exact pre-admission mounted work')
        self.until(lambda:self.lazy.execute("import os,json;print(json.dumps(os.path.exists('/private/a/captured-before-admit')))"),10)
        # Capture is durable, but the owner was interrupted before admission. A competing
        # remote edit advances the head while the original operation/base remains frozen.
        self.save_and_wait('b','work/parallel.txt',b'incoming during interrupted admission','b')
        stopped,history=self.restart('a',kill=True)
        frozen=next(r for r in history['revisions'] if r['revision']==stopped['live']['revision'])
        operation=frozen['descriptor']['operation'];revision=frozen['revision'];assert operation not in known
        assert all(p['local_revision']!=revision for p in stopped['status']['submissions'])
        p=self.until(lambda:next((p for p in self.lazy.status('a')['status']['submissions'] if p['operation']==operation and p['shared_receipt']),None),60)
        assert p['local_revision']==revision and p['private_receipt']['original_head']==before['status']['binding']['view']['head'] and p['private_receipt']['original_view']==before['status']['binding']['view']['view']
        self.until(lambda:self.received('b','work/restarted.txt',b'exact pre-admission mounted work'));self.converge()
        self.note('captured-before-admission-original-binding',frozen=frozen,before=before,stopped=stopped,progress=p)
        self.save_and_wait('a','work/resumed.txt',b'ordinary edit after capture restart','b')
    def contention(self):
        self.converge();before={n:self.owner(n).status(n) for n in ['a','b']}
        # Disconnect only the owned mounted container from its fixture ingress network.
        self.i.docker('network','disconnect',self.i.ingress,self.secondary.daemon)
        try:
            self.write('a','work/offline-a.txt',b'disconnected A');self.write('b','work/offline-b.txt',b'disconnected B')
            self.until(lambda:all(len(self.owner(n).status(n)['status']['submissions'])>len(before[n]['status']['submissions']) for n in ['a','b']),15)
            local={n:self.owner(n).status(n) for n in ['a','b']};self.until(lambda:self.receipt('a',{p['operation'] for p in before['a']['status']['submissions']}));self.restart('b')
            self.note('disconnected-original-captures',before=before,local=local)
        finally:self.i.docker('network','connect','--alias','lifecycle',self.i.ingress,self.secondary.daemon)
        self.until(lambda:self.received('a','work/offline-b.txt',b'disconnected B') and self.received('b','work/offline-a.txt',b'disconnected A'),60);self.converge()
        for n in ['a','b']:
            for old in local[n]['status']['submissions'][len(before[n]['status']['submissions']):]:
                p=next(p for p in self.owner(n).status(n)['status']['submissions'] if p['operation']==old['operation']);assert p['local_revision']==old['local_revision'] and p['request']['original_head']==before[n]['status']['binding']['view']['head']
        self.save_and_wait('b','work/reconnect-later.txt',b'continued after transport recovery','a')
        # Dirty incoming contention uses an uncheckpointed generation that keeps changing
        # across the debounce interval, while the other root publishes a disjoint file.
        before=self.lazy.status('a');l=self.lazy
        holder="import os,time;path='/shared/a/work/dirty.txt';deadline=time.monotonic()+3\nwhile time.monotonic()<deadline:\n with open(path,'wb') as f:f.write(b'retained dirty generation');f.flush();os.fsync(f.fileno())\n time.sleep(.02)\nopen('/tmp/lifecycle-dirty-done','w').close()"
        pid=l.execute("import json,subprocess,sys;code=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code],stdout=open('/tmp/lifecycle-dirty-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",holder,user='1001:1001');self.workloads.append({'name':'a','pid':pid,'uid':'1001:1001'});self.i.write_json('mounted-workload-ownership.json',self.workloads)
        self.until(lambda:l.cli('status','--state','/private/a/state')['uncaptured'] is True,5)
        self.save_and_wait('b','work/incoming-dirty.txt',b'incoming contended but preserved','b')
        during=l.status('a');assert l.read('a/work/dirty.txt')==b'retained dirty generation'.hex()
        self.until(lambda:l.has('a/work/incoming-dirty.txt') and self.received('b','work/dirty.txt',b'retained dirty generation'),15);self.converge();self.note('dirty-incoming-contention',before=before,during=during,after=l.status('a'))
    def conflict(self):
        base=self.converge();l=self.lazy;before={n:self.owner(n).status(n) for n in ['a','b']};plans={'a':b'competing content A','b':b'competing content B'}
        self.i.docker('network','disconnect',self.i.ingress,self.secondary.daemon)
        try:
            for n in plans:self.write(n,'reports/live',plans[n])
            self.until(lambda:all(len(self.owner(n).status(n)['status']['submissions'])>len(before[n]['status']['submissions']) for n in plans))
        finally:self.i.docker('network','connect','--alias','lifecycle',self.i.ingress,self.secondary.daemon)
        def outcome():
            rows={n:[p for p in self.owner(n).status(n)['status']['submissions'] if p['operation'] not in {p['operation'] for p in before[n]['status']['submissions']}] for n in plans}
            return rows if all(rows[n] and all(p['shared_receipt'] or p['error']=='conflicted' for p in rows[n]) for n in plans) else None
        results=self.until(outcome,60);loser=next(n for n in plans if any(p['error']=='conflicted' for p in results[n]));p=results[loser][-1]
        l=self.owner(loser);items=l.cli('sync','conflicts','list','--state','/private/'+loser+'/state')['page']['items'];mine=[x for x in items if x['receipt']==p['private_receipt']['receipt']]
        assert mine;details=[l.cli('sync','conflicts','show','--state','/private/'+loser+'/state','--conflict',x['id'])['conflict'] for x in mine]
        assert all({a['side'] for a in d['alternatives']}=={'base','current','candidate'} for d in details)
        assert p['private_receipt']['original_head']==base and p['shared_receipt'] is None
        resolved=l.cli('sync','resolve','--state','/private/'+loser+'/state','--conflicts',','.join(x['id'] for x in mine),'--expected-head',self.head(),'--select','candidate','--operation-id',identity('operation'))
        assert resolved['progress']['shared_receipt'];self.until(lambda:all(self.received(n,'reports/live',plans[loser]) for n in plans),15);self.converge()
        retained=l.cli('sync','conflicts','list','--state','/private/'+loser+'/state')['page']['items'];assert all(next(x for x in retained if x['id']==old['id'])['state']=='resolved' for old in mine)
        self.note('retained-conflict-explicit-resolution',base=base,loser=loser,results=results,details=details,resolution=resolved,retained=retained)
        self.save_and_wait('a','work/after-resolution.txt',b'ordinary save continues after explicit resolution','b')
    def negatives(self):
        l=self.lazy;head=self.converge();private=l.start('isolated',publication='isolated',actor='worker');isolated_base=l.status('isolated')['status']['binding']['view'];self.write('isolated','work/private.txt',b'private automatic mounted save')
        p=self.until(lambda:next((p for p in l.status('isolated')['status']['submissions'] if p['private_receipt']),None),60)
        assert p['state']=='PrivateRemote' and p['shared_receipt'] is None and p['private_receipt']['original_head']==head
        self.save_and_wait('a','work/shared-after-private.txt',b'shared policy remains explicit','b')
        assert not l.has('a/work/private.txt') and not self.secondary.has('b/work/private.txt') and not l.has('isolated/work/shared-after-private.txt')
        assert l.status('isolated')['status']['binding']['view']==isolated_base
        self.note('automatic-isolated-private-pinned',initial=private,progress=p,status=l.status('isolated'))
        readonly=l.start('readonly',readonly=True,actor='readonly',replica_identity='replica:'+f'{4:032x}')
        rows=l.execute("import os,errno,json;rows={}\nfor path in ['/shared/readonly/reports/live','/shared/readonly/work/denied']:\n try:open(path,'wb').close();rows[path]=0\n except OSError as e:rows[path]=e.errno\nassert set(rows.values())=={errno.EROFS};print(json.dumps(rows))",user='1001:1001')
        assert not l.status('readonly')['status']['submissions'];self.note('readonly-no-automatic-submission',initial=readonly,errors=rows,status=l.status('readonly'))
        denied={}
        for n in ['a','b']:
            denied[n]=self.owner(n).execute("import os,json,sys;n=json.load(sys.stdin);rows={}\nfor p in ['/private/'+n+'/token','/private/'+n+'/state/control.sock']:\n try:open(p,'rb');rows[p]=0\n except OSError as e:rows[p]=e.errno\nassert set(rows.values())=={13};print(json.dumps(rows))",n,user='1001:1001')
        self.note('workload-control-credential-denial',uid=1001,gid=1001,denials=denied)
    def inventories(self):
        from connected import inventory_code
        a=self.lazy.execute('import json,sys,hashlib;s=json.load(sys.stdin)\n'+inventory_code(),'/shared/a',user='1001:1001');b=self.secondary.execute('import json,sys,hashlib;s=json.load(sys.stdin)\n'+inventory_code(),'/shared/b',user='1001:1001')
        def content(rows):return {p:{k:v for k,v in r.items() if k not in ['uid','gid']} for p,r in rows.items()}
        assert content(a)==content(b)
        mac=self.observer.run(inventory_code(),self.mac['root']) if self.observer else None
        if mac:assert content(a)==content(mac)
        head=self.converge();self.note('authorized-inventory-and-readiness',a=a,b=b,mac=mac,head=head,status={n:self.owner(n).status(n) for n in ['a','b']})

    def agent_boundary(self,bodies):
        tasks={'write':{'a':'Read actual root and nested instructions, then complete work/task-a.txt through ordinary file APIs. Do not use publication controls.','b':'Read actual root and nested instructions, then complete work/task-b.txt through ordinary file APIs. Do not use publication controls.'},'follow-up':{'a':'Reread actual root/nested instructions and both task files. Freshly open the received work/task-b.txt and append one follow-up line stating the peer completed value and procedure code. Create work/agent-dir, rename it to work/agent-renamed, and write work/agent-renamed/notes.txt documenting those peer observations using ordinary APIs. Report actual peer bytes and changes.','b':'Reread actual root/nested instructions and both task files. Freshly open the received work/task-a.txt and append one follow-up line stating the peer completed value and procedure code. Wait at most30seconds through ordinary file reads for work/agent-renamed/notes.txt, then read and report its actual bytes. Do not use publication controls.'}}
        identities=None
        for phase in ['write','follow-up']:
            before_phase={n:self.owner(n).status(n) for n in ['a','b']}
            resume=self.i.output/('agents-'+phase+'-resume.json')
            recipe={'containers':{n:self.owner(n).daemon for n in ['a','b']},'roots':{'a':'/shared/a','b':'/shared/b'},'uid':1001,'gid':1001,'mapping':{'principal':ALICE,'group':GROUP},'owner_pids':{n:self.owner(n).execute("import json,sys;print(open('/private/'+json.load(sys.stdin)+'/pid').read())",n) for n in ['a','b']},'allowed':{'a':['AGENTS.md','work'],'b':['AGENTS.md','work']},'initial_sha256':{p:hashlib.sha256(b).hexdigest() for p,b in bodies.items()},'phase':phase,'deadline_seconds':600,'resume':str(resume),'report_prefix':str(self.i.output/('actual-agent-'+phase+'-')),'task':tasks[phase],'control_boundary':'/private0700 inaccessible to1001; do not execute owner/control commands; stdout reports are stored by coordinator outside content'}
            self.i.write_json('agent-bridge-'+phase+'.json',recipe);print(json.dumps({'agent_boundary':str(self.i.output/('agent-bridge-'+phase+'.json'))}),flush=True);deadline=time.monotonic()+600
            while not resume.exists():
                assert time.monotonic()<deadline,'actual agents bridge timeout';time.sleep(.2)
            evidence=json.loads(resume.read_text());assert set(evidence)=={'a','b'} and all(evidence[k].get('agent_id') and evidence[k].get('report') and Path(evidence[k]['report']).is_file() for k in evidence)
            ids={k:evidence[k]['agent_id'] for k in evidence};assert len(set(ids.values()))==2
            if identities is None:identities=ids
            else:assert ids==identities,'same actual agent identities must continue'
            paths=[('a','work/task-a.txt'),('b','work/task-b.txt')] if phase=='write' else [('a','work/task-b.txt'),('b','work/task-a.txt')]
            for name,path in paths:
                body=bytes.fromhex(self.owner(name).read(name+'/'+path));assert b'completed' in body and b'mounted-ordinary-v1' in body
                value=int(re.search(rb'task-value: (\d+)',bodies[path]).group(1))+7
                assert value in [int(v) for v in re.findall(rb'completed-value: (\d+)',body)]
                if phase=='follow-up':assert b'follow-up' in body.lower()
                self.until(lambda:self.received('b' if name=='a' else 'a',path,body));self.note('actual-agent-file',phase=phase,name=name,path=path,body=body.hex(),metadata=evidence[name],report_sha256=hashlib.sha256(Path(evidence[name]['report']).read_bytes()).hexdigest())
            self.converge()
            for n in ['a','b']:
                prior={p['operation'] for p in before_phase[n]['status']['submissions']};progress=[p for p in self.owner(n).status(n)['status']['submissions'] if p['operation'] not in prior]
                assert progress and all(p['private_receipt'] and p['shared_receipt'] for p in progress)
                for p in progress:
                    assert p['request']['original_head']==p['private_receipt']['original_head'] and p['request']['original_view']==p['private_receipt']['original_view']
                    assert p['private_receipt']['operation']==p['operation'] and p['private_receipt']['submitted_revision']==p['local_revision'] and p['shared_receipt']['submitted_revision']==p['local_revision']
                    assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+p['operation']+"';")=='1'
                self.note('actual-agent-receipts',phase=phase,name=n,progress=progress,before=before_phase[n])
        self.until(lambda:self.secondary.has('b/work/agent-renamed/notes.txt'))
    def cleanup(self):
        for w in self.workloads:
            self.owner(w['name']).execute("import json,sys,os,signal,time;p=json.load(sys.stdin)\ntry:os.kill(p,signal.SIGTERM)\nexcept ProcessLookupError:pass\ndeadline=time.monotonic()+5\nwhile os.path.exists('/proc/'+str(p)):\n assert time.monotonic()<deadline\n time.sleep(.02)\nprint('{}')",w['pid'],user=w['uid'])
        rows=[]
        for client in [self.lazy,self.secondary]:
            if not client:continue
            for name in client.mounts:
                self.i.write_json('mounted-'+name+'-log.json',client.execute("import json,sys;print(json.dumps(open('/private/'+json.load(sys.stdin)+'/daemon.log').read()))",name))
            client.cleanup();rows.extend(json.loads((self.i.output/'mount-cleanup.json').read_text()))
            self.i.write_json('mounted-all-cleanup.json',rows)
        super().cleanup()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--reuse-image');ap.add_argument('--focused',action='store_true');ap.add_argument('--actual-agents',action='store_true');a=ap.parse_args();i=OwnedInfra(a.output);j=None;code=1
    try:
        i.preflight();source=capture(i);reuse=resolve_reused_image(i,a.reuse_image) if a.reuse_image else None;image=reuse['image'] if reuse else i.owner+'-mounted'
        for args in [['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service']]:
            i.run(args,timeout=900)
            if '--features' in args:shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults')
        if not reuse:i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=0','--label','magus.fs2.owner='+i.owner,'-t',image,'.',timeout=2400)
        i.setup(image);verify_image(i,source);i.isolate_service_control();i.write_json('client-binaries.json',{'host':{n:hashlib.sha256((ROOT/'target/debug'/n).read_bytes()).hexdigest() for n in ['magus-fs','magus-fs-client-faults']},'linux':{n:i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+n).stdout.split()[0] for n in ['magus-fs','magus-fs-client-faults']}});j=Mounted(i,image,a.focused,a.actual_agents);j.run();assert sources()==source['sha256'];code=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});code=2
    except Exception as e:i.write_json('failure.json',{'reason':str(e),'trace':traceback.format_exc()});traceback.print_exc()
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e),'trace':traceback.format_exc()});code=1
        i.write_json('result.json',{'exit':code,'passed':code==0,'actual_agents':a.actual_agents,'focused':a.focused,'records':len(j.records) if j else 0,'image':image if 'image' in locals() else None})
    print(json.dumps({'exit':code,'output':str(i.output)}));return code
if __name__=='__main__':sys.exit(main())
