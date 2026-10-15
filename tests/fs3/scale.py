"""Bounded FS3 scale phase; raw observations, never a statistical qualification."""
import math


def validate_scale(m):
    errors = []
    def require(ok, message):
        if not ok: errors.append(message)
    cohorts = m.get('cohorts', [])
    require(m.get('coverage') == 'full' and sorted(c.get('count', 0) for c in cohorts) == [1, 5, 20],
            'full scale phase requires all 1/5/20 cohorts')
    for c in cohorts:
        n = c.get('count', 0); rs = c.get('receivers', [])
        require(n in (1, 5, 20) and len(rs) == n, 'receiver cardinality')
        for key in ('name', 'replica', 'state', 'credential_sha256'):
            require(len({r.get(key) for r in rs}) == n and all(r.get(key) for r in rs), 'independent receiver '+key)
        require(all(r.get('kernel_mounted') is True and r.get('ordinary_uid') == 1001 for r in rs), 'ordinary mounted receivers')
        require(c.get('publisher', {}).get('kind') == 'full-native' and c.get('publisher', {}).get('ordinary_uid') == 1001, 'ordinary full publisher')
        require(c.get('ceiling_seconds') == 600 and 0 <= c.get('seconds', math.inf) <= 600, 'whole cohort ceiling')
        saves = c.get('saves', [])
        require(sorted(s.get('kind', '') for s in saves) == ['atomic', 'in-place', 'new-file'], 'three representative saves')
        for s in saves:
            rows = s.get('receivers', [])
            require(s.get('shared') is True and bool(s.get('head')) and bool(s.get('revision')) and bool(s.get('sha256')), 'exact Shared publication')
            require(len(rows) == n and {r.get('name') for r in rows} == {r.get('name') for r in rs}, 'every receiver observed')
            require(s.get('attempted') == n and s.get('successful') == n and s.get('failed') == 0, 'attempt accounting')
            for r in rows:
                require(r.get('error') is None and r.get('applied') is True and r.get('head') == s.get('head')
                        and r.get('revision') == s.get('revision') and r.get('applied_revision') == s.get('revision') and r.get('fresh_sha256') == s.get('sha256')
                        and isinstance(r.get('seconds'), (float,int)) and math.isfinite(r['seconds']) and 0 <= r['seconds'] <= 30, 'exact receiver Applied/read/timing')
    cache = m.get('cache', {})
    require(cache.get('quota_bytes', 0) > 0 and bool(cache.get('occupancy_bytes'))
            and all(0 <= n <= cache['quota_bytes'] for n in cache.get('occupancy_bytes', [])), 'content admission bound')
    require(cache.get('pressure_error') == 'backpressure' and cache.get('restart_verified') is True, 'pressure refusal and restart')
    before, after = cache.get('protected_before', {}), cache.get('protected_after', {})
    require(set(before) == {'dirty','pin','pending','failed','uncertain','handle'} and before == after and all(before.values()), 'protected bytes retained')
    require(cache.get('stale_token_error') == 'stale_prune_token', 'stale prune token rejected')
    require(bool(cache.get('refetch_expected_sha256')) and cache.get('refetch_sha256') == cache.get('refetch_expected_sha256'), 'verified authorized refetch')
    reads = m.get('read_samples', [])
    require(sorted(r.get('kind','') for r in reads) == ['full-scan','metadata-cold','ranges-cold','ranges-warm']
            and all(r.get('verified') is True and isinstance(r.get('seconds'), (int,float)) and r['seconds'] >= 0 for r in reads), 'separate read measurements')
    faults = m.get('faults', [])
    require(sorted(r.get('kind','') for r in faults) == ['disconnected','dropped-hint','revoked','slow']
            and all(r.get('passed') is True for r in faults), 'bounded named peer cases')
    return errors

import argparse
import hashlib
import json
import secrets
import time
import traceback
from pathlib import Path
from common import PhaseInfra, RecordedLazy, source_bridge, restart_retained, InfrastructureUnavailable
from full_native import NativeJourney, Endpoint
from connected import public_settings
from service_protocol import ALICE, GROUP, REPLICA, file_entry, identity
from service_storage import NS, object_id


def owner_record(root, existing_tokens, now):
    from isolation import provision_record
    token=secrets.token_hex(32)
    while token in existing_tokens:token=secrets.token_hex(32)
    actor={'principal':ALICE,'replica':REPLICA,'group':GROUP}
    record=provision_record('a1',actor,{'a1':actor},token,root)
    record['expires']=now+3600
    return record


def receiver_grant(replica, parent_expires, now):
    return {'delegate':{'replica':replica,'expires':min(now+1800,parent_expires),
                        'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['']}}


class BudgetInfra(PhaseInfra):
    """Predeclared total fixture bound; individual command limits remain smaller."""
    deadline = None
    def run(self, argv, timeout=120, **kw):
        if self.deadline is not None:
            remaining = self.deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError('600-second whole cohort ceiling')
            timeout = min(timeout, remaining)
        return super().run(argv, timeout=timeout, **kw)


class Publisher(Endpoint):
    def __init__(self, *args):
        self.commands = []
        super().__init__(*args)
    def run(self, code, data=None):
        row = {'code':code, 'settings':public_settings(data)}; started=time.monotonic()
        try:
            result=super().run(code,data);row['result']=result;return result
        except Exception as error:
            row['error']=str(error);raise
        finally:
            row['seconds']=time.monotonic()-started;self.commands.append(row)
            self.i.write_json('publisher-commands.json',self.commands)


class Cohort(NativeJourney):
    def __init__(self, infra, image, count):
        super().__init__(infra,image,['linux']);self.count=count;self.mounts={};self.publisher=None
        self.row={'count':count,'ceiling_seconds':600,'publisher':{'kind':'full-native','ordinary_uid':1001},'receivers':[],'saves':[]}
        self.read_samples=[];self.faults=[];self.grants={};self.paused=None;self.disconnected=[];self.http_accounting=[]
        self.row['startup_attempts']=[]
    def request(self, method, path, **kw):
        response_bytes=kw.pop('response_bytes',False)
        payload=kw.get('raw')
        if kw.get('body') is not None:payload=json.dumps(kw['body']).encode()
        if isinstance(payload,str):payload=payload.encode()
        status,raw=super().request(method,path,response_bytes=True,**kw)
        self.http_accounting.append({'method':method,'path':path,'status':status,'request_body_bytes':len(payload or b''),
                                     'response_body_bytes':len(raw),'kind':'content' if '/objects/' in path else 'control'})
        self.i.write_json('scripted-http-accounting.json',self.http_accounting)
        return status,raw if response_bytes else json.loads(raw) if raw else None
    def save(self):
        self.i.write_json('cohort.json',self.row)
        self.i.write_json('read-samples.json',self.read_samples)
        self.i.write_json('faults.json',self.faults)
    def transfers(self):
        log=self.i.docker('exec',self.i.service,'cat','/tmp/service.log',evidence=False).stdout
        out={k:0 for k in ('install_body','backend_put_body','backend_verification_body','authorized_body')}
        for line in log.splitlines():
            fields=line.split()
            if len(fields)==3 and fields[0]=='fs2_transfer':out[fields[1]]+=int(fields[2])
        self.i.write_json('service-transfers.json',{'counters':out,'log':log})
        return out
    def setup(self):
        self.i.docker('exec','-d','-e','MAGUS_TEST_TRANSFER_LOG=1',self.i.service,'sh','-c',
            'echo $$ > /tmp/service.pid; exec magus-fs-service-faults serve '+self.i.service_config+' > /tmp/service.log 2>&1')
        self.i.port=int(self.i.docker('port',self.i.service,'8443/tcp').stdout.strip().split(':')[-1]);self.wait()
        owner=owner_record(self.tree_root,set(self.tokens.values()),int(time.time()))
        self.tokens['alice']=owner['token'];self.parent_expires=owner['expires']
        self.i.provision([owner])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}}
        # Sixteen independently hashed 256KiB chunks; enough to distinguish ranges from scan.
        self.chunks=[hashlib.sha256(('fs3-chunk-%d'%n).encode()).digest()*8192 for n in range(16)]
        self.large=b''.join(self.chunks)
        large=file_entry('large',self.tree_root['id'],b'');large['content']['version']={'size':len(self.large),'extents':[{'kind':'chunk','object':object_id(b),'object_size':len(b),'offset':0,'length':len(b)} for b in self.chunks]}
        upload,rid=self.stage(self.descriptor([reports,file_entry('reports/live',reports['id'],b'seed'),large]),bodies=[b'seed',*self.chunks])
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        self.publisher=Publisher(self,'linux',self.image);self.client=self.publisher.create('publisher');self.publisher.start(self.client)
        self.until(lambda:self.publisher.ready(self.client),15)
        self.row['publisher']['binary']=self.publisher.run("p='/proc/'+str(s)+'/exe';print(json.dumps({'path':os.readlink(p),'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}))",self.client['pid'])
        assert self.row['publisher']['binary']['sha256']==json.loads((self.i.output/'source-bridge.json').read_text())['binaries']['magus-fs']
        self.row['publisher'].update(replica=self.client['replica'],state=self.client['state'],container=self.publisher.container)
        for n in range(self.count):
            name='r%02d'%n;replica=identity('replica')
            attempt={'receiver':name,'replica':replica,'state':'starting'};self.row['startup_attempts'].append(attempt);self.save()
            grant=self.expect('receiver-grant','POST',self.root+'/grants',200,body=receiver_grant(replica,self.parent_expires,int(time.time())))
            assert grant['token'] not in self.tokens.values() and grant['credential'] not in self.grants.values()
            self.tokens[name]=grant['token'];self.grants[name]=grant['credential']
            ep=RecordedLazy(self,name);self.mounts[name]=ep
            code,data=self.request('POST',self.root+'/views',actor=name,body={'branch':'main'})
            diagnostic={'receiver':name,'replica':replica,'view_probe_status':code,'view_probe_body':data,
                'credentials':json.loads(self.i.sql("SELECT coalesce(json_agg(row_to_json(x)), '[]'::json) FROM (SELECT id,replica,principal,parent,parent_generation,generation,revoked,expires FROM credentials WHERE namespace='"+NS+"') x;"))}
            self.i.write_json(name+'-attach-diagnostic.json',diagnostic)
            try:
                binding=ep.start(name,actor=name,replica_identity=replica,drop=self.count==5 and n==1)
            except Exception:
                follow_code,follow_body=self.request('POST',self.root+'/views',actor=name,body={'branch':'main'})
                diagnostic.update(followup_status=follow_code,followup_body=follow_body,
                    resource_snapshot=self.i.docker('stats','--no-stream','--format','{{json .}}',self.i.service,self.i.pg,*[e.daemon for e in self.mounts.values()]).stdout,
                    service_log=self.i.docker('exec',self.i.service,'cat','/tmp/service.log',evidence=False).stdout)
                self.i.write_json(name+'-attach-diagnostic.json',diagnostic)
                attempt.update(state='failed',provenance=name+'-attach-diagnostic.json');self.save()
                raise
            proof=ep.execute("import json,os,sys;sys.path.insert(0,'/src/tests/fs2');from connected import kernel_mount_present;n=json.load(sys.stdin);print(json.dumps({'ordinary_uid':os.geteuid(),'kernel_mounted':kernel_mount_present('/shared/'+n,open('/proc/self/mountinfo').read())}))",name,user='1001:1001')
            binary=ep.execute("import json,os,sys,hashlib;n=json.load(sys.stdin);pid=open('/private/'+n+'/pid').read().strip();p='/proc/'+pid+'/exe';print(json.dumps({'path':os.readlink(p),'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}))",name)
            expected='magus-fs-client-faults' if self.count==5 and n==1 else 'magus-fs'
            assert binary['path']=='/usr/local/bin/'+expected and binary['sha256']==json.loads((self.i.output/'source-bridge.json').read_text())['binaries'][expected]
            proof['binary']=binary;proof['image']=self.i.inspect('container',ep.daemon)['Image'];assert proof['image']==self.image
            attempt.update(state='mounted',provenance=name+'-commands.json')
            self.row['receivers'].append({'name':name,'replica':replica,'state':ep.daemon+':/private/'+name+'/state',
                'credential_sha256':hashlib.sha256(grant['token'].encode()).hexdigest(),'container':ep.daemon,'binding':binding,**proof})
            self.save()
    def observe(self, names, path, body, head, started):
        rows=[];expected=hashlib.sha256(body).hexdigest()
        # One unchanged visibility deadline for the save, not a renewed deadline per receiver.
        deadline=started+30
        for name in names:
            ep=self.mounts[name];row={'name':name,'error':None}
            try:
                while True:
                    if time.monotonic()>=deadline:raise TimeoutError('30-second save visibility deadline')
                    status=ep.status(name);view=status['status']['binding']['view']
                    if status['live']['applied'] and status['live']['revision']==view['revision'] and view['head']==head:
                        actual=bytes.fromhex(ep.read(name+'/'+path))
                        if hashlib.sha256(actual).hexdigest()==expected:break
                    if time.monotonic()>=deadline:raise TimeoutError('30-second save visibility deadline')
                    time.sleep(.08)
                row.update(head=view['head'],revision=view['revision'],applied=status['live']['applied'],applied_revision=status['live']['revision'],fresh_sha256=hashlib.sha256(actual).hexdigest(),status=status)
            except Exception as error:row['error']=str(error)
            finally:row['seconds']=time.monotonic()-started;rows.append(row)
        return rows
    def publish_save(self,kind,path,body,names=None,store=True):
        names=list(self.mounts) if names is None else names
        before=self.publisher.status(self.client);old={p['operation'] for p in before['status']['submissions']}
        transfer=self.transfers();started=time.monotonic()
        row={'kind':kind,'path':path,'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),'attempted':len(names),'receivers':[],'shared':False}
        if store:self.row['saves'].append(row)
        def persist_attempt():
            if not store:self.i.write_json('peer-case-save.json',row)
            self.save()
        persist_attempt()
        try:
            self.publisher.write(self.client,body,path,atomic=kind=='atomic')
            progress=self.until(lambda:next((p for p in self.publisher.status(self.client)['status']['submissions'] if p['operation'] not in old and p['shared_receipt']),None),15)
            shared=progress['shared_receipt'];head=shared['head']
            self.until(lambda:self.publisher.ready(self.client,head),15)
            view,descriptor=self.view()
            assert view['head']==head
            entry=next(e for e in descriptor['tree']['entries'] if e['path']==path)
            assert entry['content']['version']['size']==len(body)
            assert progress['private_receipt']['submitted_revision']==progress['local_revision']==shared['submitted_revision']
            assert progress['request']['revision']==progress['local_revision'] and progress['integration']['candidate_receipt']==progress['private_receipt']['receipt']
            row.update(head=head,revision=view['revision'],shared=True,progress=progress,publisher_status=self.publisher.status(self.client),descriptor_entry=entry)
            row['receivers']=self.observe(names,path,body,head,started)
            return row
        except Exception as error:
            row['error']=str(error)
            raise
        finally:
            row.update(successful=sum(r['error'] is None for r in row['receivers']),failed=len(names)-sum(r['error'] is None for r in row['receivers']),seconds=time.monotonic()-started,
                       transfer={k:v-transfer[k] for k,v in self.transfers().items()})
            persist_attempt()
    def metrics(self,name):
        ep=self.mounts[name]
        return ep.execute("""import json,sys,os
from pathlib import Path
n=json.load(sys.stdin);state=Path('/private/'+n+'/state');pid=Path('/private/'+n+'/pid').read_text().strip();stat=Path('/proc/'+pid+'/stat').read_text().split();objects=list((state/'objects').glob('sha256:*'))
print(json.dumps({'cpu_ticks':int(stat[13])+int(stat[14]),'clock_ticks':os.sysconf('SC_CLK_TCK'),'rss_bytes':int(stat[23])*os.sysconf('SC_PAGE_SIZE'),'object_bytes':sum(p.stat().st_size for p in objects),'sqlite_bytes':sum(p.stat().st_size for p in state.glob('journal.sqlite*')),'object_count':len(objects)}))""",name)
    def reads(self):
        name='r00';ep=self.mounts[name]
        offsets=[12345,9*262144+54321];expected=[hashlib.sha256(self.large[o:o+4096]).hexdigest() for o in offsets]
        codes={
            'metadata-cold':"import os,json;print(json.dumps({r:sorted(fs) for r,ds,fs in os.walk('/shared/r00')}))",
            'ranges-cold':"import os,json,hashlib;f=os.open('/shared/r00/large',os.O_RDONLY);print(json.dumps([hashlib.sha256(os.pread(f,4096,o)).hexdigest() for o in "+repr(offsets)+"]));os.close(f)",
            'full-scan':"import json,hashlib;print(json.dumps(hashlib.sha256(open('/shared/r00/large','rb').read()).hexdigest()))"}
        codes['ranges-warm']=codes['ranges-cold']
        for kind in ('metadata-cold','ranges-cold','ranges-warm','full-scan'):
            before=self.metrics(name);transfers=self.transfers();control={'continuous_client_body_bytes':None,'reason':'not exposed by existing status API','scripted_http_samples':len(self.http_accounting)};started=time.monotonic()
            actual=ep.execute(codes[kind],user='1001:1001');seconds=time.monotonic()-started
            delta={k:v-transfers[k] for k,v in self.transfers().items()};after=self.metrics(name)
            if kind=='metadata-cold':assert delta['authorized_body']==0 and after['object_bytes']==before['object_bytes']==0
            elif kind.startswith('ranges'):
                assert actual==expected
                if kind=='ranges-cold':assert 0<delta['authorized_body']<len(self.large)
                else:assert delta['authorized_body']==0
            else:assert actual==hashlib.sha256(self.large).hexdigest()
            self.read_samples.append({'kind':kind,'seconds':seconds,'verified':True,'actual':actual,'transfer':delta,'before':before,'after':after,'control_before':control,'control_after':{'continuous_client_body_bytes':None,'scripted_http_samples':len(self.http_accounting)}});self.save()
    def peer_cases(self):
        disconnected,slow,revoked='r00','r02','r03'
        for name in (disconnected,revoked):
            self.i.docker('network','disconnect',self.i.ingress,self.mounts[name].daemon);self.disconnected.append(name)
        self.expect('revoke-peer','POST',self.root+'/grants',200,body={'revoke':self.grants[revoked]})
        self.mounts[slow].execute("import os,signal,json,sys;n=json.load(sys.stdin);os.kill(int(open('/private/'+n+'/pid').read()),signal.SIGSTOP);print('{}')",slow);self.paused=slow
        body=b'bounded named peer case';healthy=[n for n in self.mounts if n not in (disconnected,slow,revoked)]
        row=self.publish_save('peer-cases','reports/live',body,healthy,False)
        assert row['failed']==0
        self.mounts[slow].execute("import os,signal,json,sys;n=json.load(sys.stdin);os.kill(int(open('/private/'+n+'/pid').read()),signal.SIGCONT);print('{}')",slow);self.paused=None
        self.i.docker('network','connect',self.i.ingress,self.mounts[disconnected].daemon);self.disconnected.remove(disconnected)
        recovered=self.observe([disconnected,slow],'reports/live',body,row['head'],time.monotonic())
        self.i.write_json('peer-recovery.json',recovered);assert all(r['error'] is None for r in recovered)
        self.i.docker('network','connect',self.i.ingress,self.mounts[revoked].daemon);self.disconnected.remove(revoked)
        self.expect('revoked-view','POST',self.root+'/views',401,body={'branch':'main'},actor=revoked)
        for kind in ('disconnected','slow','revoked'):
            self.faults.append({'kind':kind,'passed':True,'provenance':['peer-case-save.json','peer-recovery.json','observations.json'],'healthy_receivers':healthy,'recovered':recovered if kind!='revoked' else [],'revoked_credential_denied':kind=='revoked'})
        self.save()
    def run(self):
        self.setup()
        if self.count==1:
            self.reads();self.refetch=prune_refetch(self)
        self.row['resources_before']=self.i.docker('stats','--no-stream','--format','{{json .}}',self.i.service,*[e.daemon for e in self.mounts.values()],self.publisher.container).stdout
        for kind,path,body in [('in-place','reports/live',b'I'*1024),('atomic','reports/live',b'A'*1024),('new-file','reports/new',b'N'*1024)]:
            row=self.publish_save(kind,path,body)
            assert row['failed']==0, 'receiver failure retained in cohort.json'
        if self.count==5:
            assert all(next(r for r in s['receivers'] if r['name']=='r01')['error'] is None for s in self.row['saves'])
            self.faults.append({'kind':'dropped-hint','passed':True,'receiver':'r01','saves':3,'provenance':['r01-commands.json','cohort.json']})
            self.peer_cases()
        self.row['resources_after']=self.i.docker('stats','--no-stream','--format','{{json .}}',self.i.service,*[e.daemon for e in self.mounts.values()],self.publisher.container).stdout
        self.row['cache_occupancy']={n:self.metrics(n) for n in self.mounts}
        self.row['control_transfer']={'continuous_client_body_bytes':None,'reason':'existing status API has no continuous control-body counter','scripted_http':self.http_accounting,'bootstrap_counters':{r['name']:r['binding']['attach_counters'] for r in self.row['receivers']},'docker_network_scope':'total container network including content/control/TLS; not a control-body estimate'};self.save()
    def cleanup(self):
        if self.paused:
            self.mounts[self.paused].execute("import os,signal,json,sys;n=json.load(sys.stdin);os.kill(int(open('/private/'+n+'/pid').read()),signal.SIGCONT);print('{}')",self.paused);self.paused=None
        for name in list(self.disconnected):
            self.i.docker('network','connect',self.i.ingress,self.mounts[name].daemon);self.disconnected.remove(name)
        for ep in self.mounts.values():ep.cleanup()
        if self.publisher:self.publisher.cleanup()


def prune_refetch(j):
    """CLI prune only while the mount owner is normally stopped."""
    ep=j.mounts['r00'];state='/private/r00/state'
    stopped=ep.execute("""import json,subprocess,time,os
from pathlib import Path
subprocess.run(['fusermount3','-u','/shared/r00'],check=True);pid=Path('/private/r00/pid').read_text().strip();deadline=time.monotonic()+60
while Path('/proc/'+pid).exists():
 assert time.monotonic()<deadline,'normal shutdown ceiling'
 time.sleep(.05)
print(json.dumps({'owner_exited':True,'kernel_mount_absent':not any(line.split()[4]=='/shared/r00' for line in Path('/proc/self/mountinfo').read_text().splitlines())}))""")
    assert stopped['owner_exited'] and stopped['kernel_mount_absent']
    dry=ep.cli('prune','--state',state,'--dry-run')['report'];assert dry['reclaimable_bytes']>0
    applied=ep.cli('prune','--state',state,'--token',dry['token'])['report'];assert applied['reclaimed_bytes']>0
    restarted=restart_retained(ep,'r00');before=j.transfers()
    actual=ep.execute("import hashlib,json;print(json.dumps(hashlib.sha256(open('/shared/r00/large','rb').read()).hexdigest()))",user='1001:1001')
    expected=hashlib.sha256(j.large).hexdigest();assert actual==expected
    delta={k:v-before[k] for k,v in j.transfers().items()};assert delta['authorized_body']>0
    result={'stopped':stopped,'dry':dry,'applied':applied,'restart':restarted,'refetch_expected_sha256':expected,'refetch_sha256':actual,'transfer':delta}
    j.i.write_json('prune-refetch.json',result);return result



def cache_evidence(infra, refetch):
    """Run three focused Core proofs; source-asserted reuse is labelled explicitly."""
    from common import ROOT
    definitions=[('fs3_cache','pressure_preserves_frozen_submission_base_and_dirty_bytes_across_restart'),
                 ('qualification','retention_observations'),
                 ('retention','explicit_prune_token_revalidates_new_roots_and_reports_reclaimed_objects')]
    proofs=[];closure=None;retention=None
    for target,test in definitions:
        argv=['cargo','+stable','test','--locked','-p','magus-fs-core','--test',target,test,'--','--exact','--nocapture']
        response=infra.run(argv,timeout=60);output=response.stdout+response.stderr
        assert '1 passed; 0 failed' in output
        path='core-'+target+'.log';(infra.output/path).write_text(output)
        source=ROOT/('crates/magus-fs-core/tests/'+target+'.rs')
        proofs.append({'command':argv,'exit':response.returncode,'source':str(source.relative_to(ROOT)),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'log':str(infra.output/path),'log_sha256':hashlib.sha256(output.encode()).hexdigest()})
        if target=='fs3_cache':closure=json.loads(next(l.removeprefix('FS3_CACHE_OBSERVATIONS ') for l in output.splitlines() if l.startswith('FS3_CACHE_OBSERVATIONS ')))
        if target=='qualification':retention=json.loads(next(l.removeprefix('FS1_OBSERVATION ') for l in output.splitlines() if l.startswith('FS1_OBSERVATION ')))
    assert {r['state'] for r in closure}=={'Queued','Failed','Uncertain'}
    before={};after={}
    for row in closure:
        assert row['frozen_before']==row['frozen_after'] and row['frozen_before']['request'] and row['frozen_before']['request_digest']
        assert row['objects_before']==row['verified_objects'] and row['restart_verified'] and row['overbudget_reopen_error']=='backpressure'
        key={'Queued':'pending','Failed':'failed','Uncertain':'uncertain'}[row['state']]
        before[key]={'request':row['frozen_before'],'objects':row['objects_before']}
        after[key]={'request':row['frozen_after'],'objects':row['verified_objects']}
    before['dirty']=closure[0]['objects_before'][2];after['dirty']=closure[0]['verified_objects'][2]
    # Existing exact source assertions exercise pin/held-handle roots in one owner.
    # These entries identify test proof, not invented before/after runtime hashes.
    for key in ('pin','handle'):
        proof={'kind':'source-asserted focused test','test':'retention_observations','log':proofs[1]['log'],'source_sha256':proofs[1]['source_sha256']}
        before[key]=proof;after[key]=dict(proof)
    infra.write_json('core-proofs.json',{'proofs':proofs,'closure':closure,'retention':retention,'compiler':infra.run(['rustc','+stable','--version','--verbose']).stdout})
    return {'quota_bytes':12,'occupancy_bytes':[n for row in closure for n in (row['resident_before'],row['resident_after'])],
            'pressure_error':'backpressure','protected_before':before,'protected_after':after,'restart_verified':True,
            'stale_token_error':'stale_prune_token','stale_token_proof':proofs[2],'proofs':proofs,
            'refetch_expected_sha256':refetch['refetch_expected_sha256'],'refetch_sha256':refetch['refetch_sha256'],
            'quota_scope':'object contents only; SQLite, history and conservative NFS roots are not a total-state bound'}

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--image',required=True);ap.add_argument('--output',required=True)
    ap.add_argument('--replicas',type=int,choices=(1,5,20));args=ap.parse_args(argv)
    root=Path(args.output)
    if not root.is_absolute():raise ValueError('new absolute output required')
    root.mkdir(mode=0o700)
    result={'schema':1,'phase':'scale','status':'failed','source':{},'binaries':{},'assertions':[],
            'measurements':{'coverage':'focused' if args.replicas else 'full','cohorts':[],'read_samples':[],'faults':[]},'cleanup':{},'failures':[],'blocked':[]}
    def persist(): (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    persist();cleanups=[]
    for count in ([args.replicas] if args.replicas else [1,5,20]):
        i=BudgetInfra(str(root/('cohort-'+str(count))));j=None;started=time.monotonic()
        i.write_json('limits.json',{'declared_before_execution':True,'whole_cohort_seconds':600,'missing_object_seconds':4.5,'save_visibility_seconds':30,'publication_seconds':15,'readiness_seconds':15,'mount_start_seconds':10,'fixture_owner_shutdown_seconds':60,'statistical_qualification':False})
        i.deadline=started+600
        try:
            i.setup(args.image);i.isolate_service_control()
            source,binaries=source_bridge(i,args.image)
            if result['source']:assert (source,binaries)==(result['source'],result['binaries'])
            result['source'],result['binaries']=source,binaries
            (root/'source-bridge.json').write_bytes((i.output/'source-bridge.json').read_bytes())
            j=Cohort(i,args.image,count);result['measurements']['cohorts'].append(j.row)
            j.run()
            if count==1:
                result['measurements']['refetch']=j.refetch
                result['measurements']['cache']=cache_evidence(i,j.refetch)
            result['measurements']['read_samples'].extend(j.read_samples);result['measurements']['faults'].extend(j.faults)
            assert source_bridge(i,args.image)==(source,binaries)
        except InfrastructureUnavailable as error:result['blocked'].append(str(error))
        except Exception as error:
            result['failures'].append('cohort '+str(count)+': '+str(error));(i.output/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True)
        finally:
            if j:j.row['seconds']=time.monotonic()-started;j.save()
            i.deadline=None
            try:
                if j:j.cleanup()
                i.cleanup();cleanups.append({'ok':True,'cohort':count,'provenance':str(i.output/'cleanup.json')})
            except Exception as error:result['failures'].append('cleanup '+str(count)+': '+str(error));cleanups.append({'ok':False,'cohort':count,'error':str(error)})
            result['cleanup']={'ok':all(c['ok'] for c in cleanups),'mounts_absent':all(c['ok'] for c in cleanups),'resources_removed':all(c['ok'] for c in cleanups),'provenance':cleanups}
            persist()
        if result['failures'] or result['blocked']:break
    from qualification import normalize, SCALE_CASES
    if result['blocked']:
        # Unexecuted cases are neither successes nor runtime failures. Keep any
        # actual failure (including cleanup) while leaving partial evidence intact.
        result['status']='failed' if result['failures'] else 'blocked'
        if not result['failures']:result=normalize(result)
        persist();return 1 if result['failures'] else 2
    result['failures'].extend(validate_scale(result['measurements']))
    for case, acceptance in SCALE_CASES.items():
        result['assertions'].append({'case':case,'acceptance':acceptance,'expected':'verified','observed':'verified' if not result['failures'] else 'incomplete','passed':not result['failures'],'provenance':['cohort-1/cohort.json','cohort-5/cohort.json','cohort-20/cohort.json']})
    result['status']='failed' if result['failures'] else 'blocked' if result['blocked'] else 'passed'
    result=normalize(result)
    persist();return {'passed':0,'failed':1,'blocked':2}[result['status']]


if __name__=='__main__':raise SystemExit(main())
