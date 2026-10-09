#!/usr/bin/env python3
"""Real scoped authority, publication and replay gate; 0 passed, 1 failed, 2 blocked."""
import argparse, concurrent.futures, copy, hashlib, http.client, json, secrets, socket, ssl, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable
from provenance import capture, verify_image
from service_storage import Journey as StorageJourney, NS, OTHER, ALICE, BOB, object_id
GROUP='group:'+'a'*32
REPLICA='replica:'+f'{1:032x}'
WORKER='replica:'+f'{5:032x}'
def identity(kind): return kind+':'+secrets.token_hex(16)
def canonical(r):
    r=copy.deepcopy(r);r['tree']['entries'].sort(key=lambda e:e['path']);r['coverage'].sort()
    r={key:r[key] for key in ['format','hash','layout','parents','operation','replica','principal','captured_at_ns','coverage','provenance','restoration','tree'] if key in r}
    return json.dumps(r,separators=(',',':'),ensure_ascii=False).encode()
def file_entry(path,parent,data=b'base'):
    return {'path':path,'id':identity('entry'),'parent':parent,'owner':ALICE,'group':GROUP,'mode':384,'content':{'kind':'file','version':{'size':len(data),'extents':[] if not data else [{'kind':'chunk','object':object_id(data),'object_size':len(data),'offset':0,'length':len(data)}]}}}
class Journey(StorageJourney):
    def __init__(self,infra):
        super().__init__(infra);self.root=f'/v1/n/{NS}';self.tree_root={'id':identity('entry'),'owner':ALICE,'group':GROUP,'mode':493}
    def descriptor(self,entries):
        return {'format':'magus-fs/v1','hash':'sha256','layout':'fixed262144','parents':[],'operation':identity('operation'),'replica':REPLICA,'principal':ALICE,'captured_at_ns':1,'coverage':[''],'provenance':'explicit','tree':{'root':self.tree_root,'entries':entries}}
    def stage(self,r,actor='alice',bodies=()):
        upload=self.create(actor)
        for data in bodies:self.expect('upload-'+actor,'PUT',self.root+'/uploads/'+upload+'/objects/'+object_id(data),200,raw=data,actor=actor)
        raw=canonical(r);rid=object_id(raw)
        self.expect('stage-'+actor,'PUT',self.root+'/uploads/'+upload+'/revisions/'+rid,200,raw=raw,actor=actor)
        return upload,rid
    def view(self,actor='alice'):
        v=self.expect('view-'+actor,'POST',self.root+'/views',200,body={'branch':'main'},actor=actor)
        r=self.expect('descriptor-'+actor,'GET',self.root+'/views/'+v['view']+'/descriptor',200,actor=actor)
        assert object_id(canonical(r))==v['revision'];assert r['parents']==[]
        return v,r
    def candidate(self,view,r,actor='worker',bodies=(),drop=False):
        r['parents']=[view['revision']];r['replica']=WORKER if actor=='worker' else REPLICA;r['operation']=identity('operation')
        upload,rid=self.stage(r,actor,bodies)
        request={'operation':r['operation'],'replica':r['replica'],'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
        if drop:
            self.drop_response(self.root+'/candidates',request,actor);self.i.restart_service();self.wait()
            result=self.expect('private-recover','GET',self.op_path(request),200,actor=actor)
        else:result=self.expect('private-'+actor,'POST',self.root+'/candidates',200,body=request,actor=actor)
        return request,result
    def integrate_request(self,receipt,view):return {'operation':identity('operation'),'replica':receipt['replica'],'candidate_receipt':receipt['receipt'],'expected_head':view['head'],'branch':'main'}
    def op_path(self,r):return self.root+'/operations/'+r['replica']+'/'+r['operation']
    def drop_response(self,path,request,actor):
        payload=json.dumps(request).encode()
        with socket.create_connection(('127.0.0.1',self.i.port),timeout=2) as raw:
            with self.ca.wrap_socket(raw,server_hostname='localhost') as sock:
                sock.sendall(('POST '+path+' HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+self.tokens[actor]+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload))+'\r\nConnection: close\r\n\r\n').encode()+payload)
                # Deliberately discard the committed response; DB witness, not timing, establishes commit.
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if self.i.sql("SELECT count(*) FROM operations WHERE operation='"+request['operation']+"';")=='1':break
                    time.sleep(.05)
                else:raise AssertionError('operation never committed')
    def run(self):
        self.i.start_service();self.wait()
        self.expect('unconfigured-seed-denied','POST',self.root+'/seed',404,body={'branch':'main','revision':'sha256:'+'0'*64,'upload':'0'*32})
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        # Trusted provisioning configures immutable logical policy, no HTTP identity selection.
        record={'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}
        self.i.provision([record])
        self.expect('malformed-wss-authenticated','GET',self.root+'/notifications?branch=main',400,{'code':'invalid_request'})
        self.tokens['invalid']='0'*64
        self.expect('malformed-wss-invalid-credential','GET',self.root+'/notifications?branch=main',401,{'code':'invalid_credential'},actor='invalid')
        if getattr(self,'handshake_only',False):return
        self.policy_and_depth(record)
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':448,'content':{'kind':'directory'}}
        secret=file_entry('secret',self.tree_root['id'],b'hidden')
        r=self.descriptor([reports,secret]);upload,rid=self.stage(r,bodies=[b'hidden'])
        self.expect('forged-revision-hash','PUT',self.root+'/uploads/'+upload+'/revisions/sha256:'+'0'*64,400,{'code':'hash_mismatch'},raw=canonical(r))
        seed=self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        code,worker=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['reports']}})
        assert code==200;self.tokens['worker']=worker['token'];self.i.private('worker-token',worker['token'])
        if getattr(self,'ancestry_only',False):self.ancestry_sizes();return
        if getattr(self,'pressure_only',False):self.pressure();return
        self.i.snapshot_volumes();self.i.docker('stop','--time','5',self.i.s3)
        view,projected=self.view('worker')
        self.observations.append({'case':'metadata-bootstrap-zero-bodies','s3_stopped':True})
        self.i.docker('start',self.i.s3);self.i.wait_s3('metadata-bootstrap-restart')
        assert [e['path'] for e in projected['tree']['entries']]==['reports']
        self.expect('hidden-object','GET',self.root+'/views/'+view['view']+'/objects/'+object_id(b'hidden'),404,actor='worker')
        self.expect('guessed-view','GET',self.root+'/views/'+'0'*32+'/descriptor',404,actor='worker')
        self.expect('foreign-view','GET',self.root+'/views/'+view['view']+'/descriptor',404,actor='readonly')
        self.expect('cross-namespace-view','POST',self.root+'/views',404,body={'branch':'main'},actor='bob')
        self.expect('guessed-branch','POST',self.root+'/views',404,body={'branch':'unknown'},actor='worker')
        projected['tree']['entries'].append(file_entry('reports/result',reports['id'],b'worker-report'))
        request,private=self.candidate(view,projected,bodies=[b'worker-report'],drop=True)
        self.first_request=request
        assert private['submitted_revision']==request['revision'];assert private['original_head']==view['head']
        readonly_binding,before=self.view('readonly');self.readonly_view=readonly_binding['view'];assert 'reports/result' not in [e['path'] for e in before['tree']['entries']]
        stored=json.loads(self.i.sql("SELECT request FROM operations WHERE operation='"+request['operation']+"';"));assert stored==request
        derived=json.loads(self.i.sql("SELECT convert_from(r.descriptor,'UTF8') FROM revisions r JOIN operations o ON o.namespace=r.namespace AND o.derived_revision=r.revision WHERE o.operation='"+request['operation']+"';"))
        assert derived['parents']==[rid] and 'secret' in [e['path'] for e in derived['tree']['entries']]
        assert object_id(canonical(derived))!=request['revision']
        self.observations.append({'case':'exact-submitted-and-derived-identities','submitted':request['revision'],'derived':object_id(canonical(derived)),'original_full_parent':rid})
        self.expect('private-replay','POST',self.root+'/candidates',200,private,body=request,actor='worker')
        self.expect('operation-get','GET',self.op_path(request),200,private,actor='worker')
        changed=dict(request,revision='sha256:'+'f'*64);self.expect('digest-mismatch','POST',self.root+'/candidates',409,body=changed,actor='worker')
        self.expect('operation-theft','GET',self.op_path(request),404,actor='alice')
        integration=self.integrate_request(private,view)
        hints=self.websocket('worker')
        self.drop_response(self.root+'/integrations',integration,'worker')
        hint=self.read_hint(hints);hints.close()
        assert set(hint)=={'cursor'}
        self.observations.append({'case':'wss-cursor-only','hint':hint})
        self.i.restart_service();self.wait()
        shared=self.expect('shared-recover','GET',self.op_path(integration),200,actor='worker')
        self.expect('shared-exact-replay','POST',self.root+'/integrations',200,shared,body=integration,actor='worker')
        assert shared['submitted_revision']==request['revision']
        accepted,accepted_tree=self.view('worker')
        status,data=self.bytes_request(self.root+'/views/'+accepted['view']+'/objects/'+object_id(b'worker-report'))
        assert status==200 and data==b'worker-report',(status,data)
        self.observations.append({'case':'authorized-object-bytes','status':status,'sha256':hashlib.sha256(data).hexdigest()})
        self.i.snapshot_volumes();self.i.docker('stop','--time','5',self.i.service,self.i.pg,self.i.s3)
        self.i.docker('start',self.i.pg,self.i.s3,self.i.service);self.i.start_service();self.wait();self.i.wait_s3('protocol-all-process-restart')
        status,data=self.bytes_request(self.root+'/views/'+accepted['view']+'/objects/'+object_id(b'worker-report'))
        assert status==200 and data==b'worker-report'
        self.expect('shared-recover-all-processes','GET',self.op_path(integration),200,shared,actor='worker')
        _,after=self.view('readonly');assert sorted(e['path'] for e in after['tree']['entries'])==['reports','reports/result','secret']
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+integration['operation']+"';")=='1'
        assert self.i.sql("SELECT count(*) FROM changes WHERE head='"+shared['head']+"';")=='1'
        assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==shared['head']
        page=self.expect('durable-backfill','GET',self.root+'/changes?branch=main&after=0&limit=128',200,actor='worker')
        assert any(e['head']==shared['head'] for e in page['events']);assert 'secret' not in json.dumps(page)
        # Hint loss is recovered from zero; duplicated delivery reuses the same durable cursor.
        assert hint['cursor']<=page['cursor']
        for _ in range(2):self.expect('duplicate-hint-no-duplicate-event','GET',self.root+'/changes?branch=main&after='+str(page['cursor'])+'&limit=128',200,{'events':[],'cursor':page['cursor']},actor='worker')
        self.i.write_json('cursor.json',{'cursor':page['cursor']});self.i.restart_service();self.wait()
        self.expect('cursor-after-restart','GET',self.root+'/changes?branch=main&after='+str(page['cursor'])+'&limit=128',200,{'events':[],'cursor':page['cursor']},actor='worker')
        self.denials_and_races(worker)
        # The actual read boundary verifies bytes and retires a corrupted ready witness.
        final_view,_=self.view('alice');oid=object_id(b'hidden');key=self.i.sql("SELECT storage_key FROM objects WHERE object_id='"+oid+"';")
        self.i.s3_request('PUT','/fs2/'+key,'broken')
        self.expect('read-corruption-denied','GET',self.root+'/views/'+final_view['view']+'/objects/'+oid,400,{'code':'corrupt_object'})
        assert self.i.sql("SELECT state FROM objects WHERE object_id='"+oid+"';")=='corrupt'
        self.expect('read-corrupt-witness-unusable','GET',self.root+'/views/'+final_view['view']+'/objects/'+oid,404)
        logs=self.i.docker('exec',self.i.service,'cat','/tmp/service.log').stdout
        assert not any(token in logs for token in self.tokens.values())
        self.observations.append({'case':'service-log-redaction','credential_matches':0})
        self.i.write_json('observations.json',self.observations)
    def websocket(self,actor):
        raw=socket.create_connection(('127.0.0.1',self.i.port),timeout=2)
        sock=self.ca.wrap_socket(raw,server_hostname='localhost');sock.settimeout(10)
        key=__import__('base64').b64encode(secrets.token_bytes(16)).decode()
        sock.sendall(('GET '+self.root+'/notifications?branch=main HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\nAuthorization: Bearer '+self.tokens[actor]+'\r\n\r\n').encode())
        header=b''
        while not header.endswith(b'\r\n\r\n'):header+=sock.recv(1)
        assert header.startswith(b'HTTP/1.1 101'),header
        accept=__import__('base64').b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        assert accept in header
        return sock
    def read_hint(self,sock):
        def read(n):
            data=b''
            while len(data)<n:
                chunk=sock.recv(n-len(data));assert chunk,'closed before hint';data+=chunk
            return data
        header=read(2);assert header[0]==129 and header[1]<126,header
        return json.loads(read(header[1]))
    def policy_and_depth(self,record):
        for name,change in [('authority-principal',lambda x:x['authority'].update(principal=BOB)),('authority-primary-group',lambda x:x['authority'].update(primary_group='group:'+'b'*32)),('unknown-policy-field',lambda x:x['authority'].update(unknown=True)),('root-mode',lambda x:x['root_policy'].update(mode=4095)),('policy-overwrite',lambda x:x['authority'].update(ownership_transfer=True))]:
            invalid=copy.deepcopy(record);invalid['token']=secrets.token_hex(32);change(invalid)
            path=self.i.private('invalid-'+name+'.json',[invalid])
            result=self.i.docker('exec',self.i.service,'magus-fs-service','provision','/control/service.json','/control/'+path.name,check=False)
            assert result.returncode!=0,name
            self.observations.append({'case':name,'exit':result.returncode})
        token=self.tokens['alice'];chain_expiry=int(time.time())+1200
        for depth in range(1,9):
            status,response=self.request('POST',self.root+'/grants',body={'delegate':{'replica':identity('replica'),'expires':chain_expiry,'actions':['admin','read','write'],'branches':['main'],'prefixes':['']}},actor=token)
            assert status==200,(depth,status,response)
            token=response['token']
            self.observations.append({'case':'delegation-depth-'+str(depth),'status':status,'credential':response['credential']})
        self.expect('eighth-level-token-usable','POST',self.root+'/uploads',201,body={},actor=token)
        self.expect('ninth-level-token-rejected','POST',self.root+'/grants',400,{'code':'delegation_depth'},body={'delegate':{'replica':identity('replica'),'expires':int(time.time())+1100,'actions':['read'],'branches':['main'],'prefixes':['']}},actor=token)
    def fault_rechecks(self):
        view,r=self.view('worker');r['parents']=[view['revision']];r['replica']=WORKER;r['operation']=identity('operation')
        r['tree']['entries'].append(file_entry('reports/race-revoke',r['tree']['entries'][0]['id'],b''))
        upload,rid=self.stage(r,'worker');request={'operation':r['operation'],'replica':WORKER,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
        before=self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
        self.i.private('pause-candidate','pause');self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-candidate-barrier');self.i.restart_service(faults=True);self.wait()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future=pool.submit(self.request,'POST',self.root+'/candidates',body=request,actor='worker')
            self.barrier('candidate')
            self.i.sql("UPDATE credentials SET generation=generation+1 WHERE replica='"+WORKER+"';")
            (self.i.control/'pause-candidate').unlink()
            status,body=future.result();assert status==404,(status,body)
            self.observations.append({'case':'candidate-generation-race','status':status,'body':body})
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+request['operation']+"';")=='0'
        assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
        view,r=self.view('worker');r['tree']['entries'].append(file_entry('reports/race-grant',r['tree']['entries'][0]['id'],b''))
        _,private=self.candidate(view,r);integration=self.integrate_request(private,view)
        self.i.private('pause-integration','pause');self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-integration-barrier');self.i.restart_service(faults=True);self.wait()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future=pool.submit(self.request,'POST',self.root+'/integrations',body=integration,actor='worker');self.barrier('integration')
            self.i.sql("UPDATE grants SET actions=ARRAY['read']::text[] WHERE credential IN (SELECT id FROM credentials WHERE replica='"+WORKER+"');UPDATE credentials SET generation=generation+1 WHERE replica='"+WORKER+"';")
            (self.i.control/'pause-integration').unlink();status,body=future.result();assert status==404,(status,body)
            self.observations.append({'case':'integration-grant-race','status':status,'body':body})
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+integration['operation']+"';")=='0'
        assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
        self.i.sql("UPDATE grants SET actions=ARRAY['read','write','history','integrate']::text[] WHERE credential IN (SELECT id FROM credentials WHERE replica='"+WORKER+"');UPDATE credentials SET generation=generation+1 WHERE replica='"+WORKER+"';")
        self.i.restart_service();self.wait()
    def barrier(self,name):
        until=time.monotonic()+15
        while time.monotonic()<until:
            if self.i.docker('exec',self.i.service,'test','-f','/tmp/fs2-'+name+'-barrier',check=False,evidence=False).returncode==0:return
            time.sleep(.05)
        raise AssertionError(name+' barrier not reached')
    def history_and_hidden(self):
        view,r=self.view('alice');reports=next(e for e in r['tree']['entries'] if e['path']=='reports')
        hidden=file_entry('reports/hidden',reports['id'],b'');hidden['mode']=0;r['tree']['entries'].append(hidden)
        _,receipt=self.candidate(view,r,'alice');self.expect('hide-descendant','POST',self.root+'/integrations',200,body=self.integrate_request(receipt,view))
        worker_view,worker_r=self.view('worker');assert 'reports/hidden' not in [e['path'] for e in worker_r['tree']['entries']]
        before=self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
        worker_r['tree']['entries']=[];worker_r['parents']=[worker_view['revision']];worker_r['operation']=identity('operation');worker_r['replica']=WORKER
        upload,rid=self.stage(worker_r,'worker');request={'operation':worker_r['operation'],'replica':WORKER,'original_view':worker_view['view'],'original_head':worker_view['head'],'revision':rid,'upload':upload}
        self.expect('hidden-descendant-delete','POST',self.root+'/candidates',404,body=request,actor='worker')
        assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
        view,r=self.view('alice');target=next(e for e in r['tree']['entries'] if e['path']=='reports/result');r['tree']['entries']=[e for e in r['tree']['entries'] if e['id']!=target['id']]
        _,receipt=self.candidate(view,r,'alice');self.expect('delete-visible-identity','POST',self.root+'/integrations',200,body=self.integrate_request(receipt,view))
        self.expect('absent-identity-history-denied','GET',self.root+'/views/'+worker_view['view']+'/descriptor',404,actor='worker')
        worker_view,_=self.view('worker');view,r=self.view('alice');next(e for e in r['tree']['entries'] if e['path']=='reports')['mode']=0
        _,receipt=self.candidate(view,r,'alice');self.expect('revoke-current-ancestor','POST',self.root+'/integrations',200,body=self.integrate_request(receipt,view))
        self.expect('current-ancestor-history-denied','GET',self.root+'/views/'+worker_view['view']+'/descriptor',404,actor='worker')
        self.expect('current-ancestor-receipt-denied','GET',self.op_path(self.first_request),404,actor='worker')
        self.expect('current-ancestor-object-denied','GET',self.root+'/views/'+worker_view['view']+'/objects/'+object_id(b'worker-report'),404,actor='worker')
        self.expect('readonly-old-view-no-history','GET',self.root+'/views/'+self.readonly_view+'/descriptor',404,actor='readonly')
    def bytes_request(self,path,actor='worker'):
        c=http.client.HTTPSConnection('127.0.0.1',self.i.port,context=self.ca,timeout=10)
        try:
            c.request('GET',path,headers={'Authorization':'Bearer '+self.tokens[actor]});r=c.getresponse();return r.status,r.read()
        finally:c.close()
    def pressure(self):
        view,r=self.view('worker');requests=[]
        for n in range(3):
            edit=copy.deepcopy(r);edit['tree']['entries'].append(file_entry('reports/pressure'+str(n),edit['tree']['entries'][0]['id'],b''));edit['parents']=[view['revision']];edit['operation']=identity('operation');edit['replica']=WORKER
            upload,rid=self.stage(edit,'worker');requests.append({'operation':edit['operation'],'replica':WORKER,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload})
        before=self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
        self.i.private('pause-candidate','pause');self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-candidate-barrier');self.i.restart_service(faults=True);self.wait()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            futures=[pool.submit(self.request,'POST',self.root+'/candidates',body=q,actor='worker') for q in requests[:2]]
            try:
                self.barrier('candidate');deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    status,body=self.request('POST',self.root+'/views',body={'branch':'main'},actor='worker')
                    if status==503:break
                    time.sleep(.05)
                assert (status,body)==(503,{'code':'backpressure'}),(status,body)
                self.expect('revision-admission-pressure','POST',self.root+'/candidates',503,{'code':'backpressure'},body=requests[2],actor='worker')
                self.create('worker')
                for q in requests:assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+q['operation']+"';")=='0'
                assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
                rss=self.i.docker('stats','--no-stream','--format','{{.MemUsage}}',self.i.service).stdout.strip()
                self.observations.append({'case':'fixture-memory-observation','memory_usage':rss,'scope':'small synthetic pressure fixture; not worst-case qualification'})
            finally:(self.i.control/'pause-candidate').unlink(missing_ok=True)
            assert all(f.result()[0]==200 for f in futures)
        self.expect('revision-pressure-recovery','POST',self.root+'/candidates',200,body=requests[2],actor='worker')
        assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
        self.i.restart_service();self.wait()
    def credential_race(self,worker):
        view,r=self.view('worker');_,receipt=self.candidate(view,r);q=self.integrate_request(receipt,view)
        before=self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")
        self.i.private('pause-integration','pause');self.i.docker('exec',self.i.service,'rm','-f','/tmp/fs2-integration-barrier');self.i.restart_service(faults=True);self.wait()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future=pool.submit(self.request,'POST',self.root+'/integrations',body=q,actor='worker')
            try:
                self.barrier('integration');self.expect('revoke-at-commit-barrier','POST',self.root+'/grants',200,body={'revoke':worker['credential']})
            finally:(self.i.control/'pause-integration').unlink(missing_ok=True)
            status,body=future.result();assert (status,body)==(401,{'code':'invalid_credential'}),(status,body)
            self.observations.append({'case':'integration-credential-revocation-race','status':status,'body':body})
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+q['operation']+"';")=='0'
        assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
        self.i.restart_service();self.wait()
    def ancestry_sizes(self):
        view,base=self.view('worker');before=view['head'];data=b'ancestry-content'
        for inconsistent in [True,False]:
            upload=self.create('worker');self.expect('ancestry-object','PUT',self.root+'/uploads/'+upload+'/objects/'+object_id(data),200,raw=data,actor='worker')
            first=copy.deepcopy(base);first['parents']=[view['revision']];first['replica']=WORKER;first['operation']=identity('operation')
            first['tree']['entries'].append(file_entry('reports/ancestry',first['tree']['entries'][0]['id'],data))
            content=first['tree']['entries'][-1]['content']['version']
            if inconsistent:
                content['size']-=1;content['extents'][0]['object_size']-=1;content['extents'][0]['length']-=1
            raw=canonical(first);parent=object_id(raw)
            self.expect('ancestry-stage-parent','PUT',self.root+'/uploads/'+upload+'/revisions/'+parent,200,raw=raw,actor='worker')
            last=copy.deepcopy(first);last['parents']=[parent];last['operation']=identity('operation');last['tree']['entries'][-1]['content']=file_entry('unused','unused',data)['content']
            raw=canonical(last);rid=object_id(raw)
            self.expect('ancestry-stage-final','PUT',self.root+'/uploads/'+upload+'/revisions/'+rid,200,raw=raw,actor='worker')
            req={'operation':last['operation'],'replica':WORKER,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
            self.expect('inconsistent-ancestry-object-size' if inconsistent else 'consistent-multi-revision-ancestry','POST',self.root+'/candidates',400 if inconsistent else 200,{'code':'invalid_descriptor'} if inconsistent else None,body=req,actor='worker')
            assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==before
            if inconsistent:assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+req['operation']+"';")=='0'
    def revoked_read_noop(self):
        view,r=self.view('worker');r['parents']=[view['revision']];r['operation']=identity('operation');r['replica']=WORKER
        self.i.sql("UPDATE grants SET actions=ARRAY['write','history','integrate']::text[] WHERE credential IN (SELECT id FROM credentials WHERE replica='"+WORKER+"');UPDATE credentials SET generation=generation+1 WHERE replica='"+WORKER+"';")
        try:
            upload,rid=self.stage(r,'worker');q={'operation':r['operation'],'replica':WORKER,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
            self.expect('revoked-read-noop-base-reuse','POST',self.root+'/candidates',404,{'code':'not_found'},body=q,actor='worker')
            assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+q['operation']+"';")=='0'
            assert self.i.sql("SELECT head FROM branches WHERE namespace='"+NS+"' AND name='main';")==view['head']
        finally:
            self.i.sql("UPDATE grants SET actions=ARRAY['read','write','history','integrate']::text[] WHERE credential IN (SELECT id FROM credentials WHERE replica='"+WORKER+"');UPDATE credentials SET generation=generation+1 WHERE replica='"+WORKER+"';")
    def denials_and_races(self,worker):
        view,r=self.view('worker')
        # Candidate bytes do not authorize guessed hidden refs, owner changes or out-of-scope paths.
        for name,mutate,status in [
          ('root-mode-smuggling',lambda x:x['tree']['root'].update(mode=511),404),
          ('out-of-scope-rename',lambda x:x['tree']['entries'][1].update(path='outside',parent=x['tree']['root']['id']),404),
          ('outside',lambda x:x['tree']['entries'].append(file_entry('outside',x['tree']['root']['id'],b'')),404),
          ('owner-smuggling',lambda x:x['tree']['entries'][0].update(owner=BOB),404),
          ('missing-reference',lambda x:x['tree']['entries'].append(file_entry('reports/missing',x['tree']['entries'][0]['id'],b'never-installed')),404),
          ('forged-reference',lambda x:x['tree']['entries'].append(file_entry('reports/guess',x['tree']['entries'][0]['id'],b'hidden')),404)]:
            bad=copy.deepcopy(r);bad['parents']=[view['revision']];bad['replica']=WORKER;bad['operation']=identity('operation');mutate(bad)
            upload,rid=self.stage(bad,'worker');req={'operation':bad['operation'],'replica':WORKER,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
            self.expect(name,'POST',self.root+'/candidates',status,body=req,actor='worker')
        for kind in ['ancestry','restore']:
            bad=copy.deepcopy(r);bad['parents']=[view['revision'] if kind=='restore' else 'sha256:'+'0'*64];bad['replica']=WORKER;bad['operation']=identity('operation')
            if kind=='restore':bad['format']='magus-fs/v2';bad['restoration']={'source_revision':view['revision'],'restore_metadata':False,'recreated':{}}
            upload,rid=self.stage(bad,'worker');req={'operation':bad['operation'],'replica':WORKER,'original_view':view['view'],'original_head':view['head'],'revision':rid,'upload':upload}
            self.expect('invalid-'+kind,'POST',self.root+'/candidates',400 if kind=='restore' else 404,{'code':'unsupported_operation'} if kind=='restore' else {'code':'not_found'},body=req,actor='worker')
        # Two retained private candidates share one expected head: exactly one integrates.
        pairs=[]
        for n in range(2):
            edit=copy.deepcopy(r);edit['tree']['entries'].append(file_entry('reports/race'+str(n),edit['tree']['entries'][0]['id'],b''));pairs.append(self.candidate(view,edit))
        requests=[self.integrate_request(p[1],view) for p in pairs]
        with concurrent.futures.ThreadPoolExecutor() as pool: results=list(pool.map(lambda q:self.request('POST',self.root+'/integrations',body=q,actor='worker'),requests))
        assert sorted(status for status,_ in results)==[200,409],results
        stale=results.index(next(x for x in results if x[0]==409));self.expect('stale-retained','GET',self.op_path(requests[stale]),409,{'code':'stale_head'},actor='worker')
        assert self.i.sql("SELECT count(*) FROM operations WHERE kind='candidate';")=='3'
        self.ancestry_sizes()
        self.revoked_read_noop()
        self.pressure()
        self.fault_rechecks()
        self.history_and_hidden()
        self.credential_race(worker)
        self.expect('revoke-worker','POST',self.root+'/grants',200,body={'revoke':worker['credential']})
        self.expect('revoked-private-replay','POST',self.root+'/candidates',401,body=pairs[0][0],actor='worker')
        self.expect('revoked-result','GET',self.op_path(requests[0]),401,actor='worker')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--image',default='magus-fs2-task2');ap.add_argument('--skip-build',action='store_true');ap.add_argument('--red',action='store_true');ap.add_argument('--skip-checks',action='store_true');ap.add_argument('--pressure-only',action='store_true');ap.add_argument('--service-checks',action='store_true');ap.add_argument('--ancestry-only',action='store_true');ap.add_argument('--handshake-only',action='store_true');args=ap.parse_args()
    infra=OwnedInfra(Path(args.output));status=1
    try:
        infra.preflight();source=capture(infra)
        if not args.red and not args.skip_checks:
            infra.run(['cargo','+stable','fmt','--all','--check'],timeout=60)
            infra.run(['cargo','+stable','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings'],timeout=300)
            infra.run(['cargo','+stable','test','--locked',*(['-p','magus-fs-service'] if args.service_checks else ['--workspace']),'--all-features'],timeout=300)
            infra.run(['cargo','+stable','build','--locked','-p','magus-fs-service'],timeout=300)
        if not args.skip_build:infra.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=0' if args.skip_checks else 'VERIFY=service' if args.service_checks else 'VERIFY=1','-t',args.image,'.',timeout=900)
        infra.setup(args.image)
        if not args.red:verify_image(infra,source)
        started=time.monotonic();journey=Journey(infra);journey.handshake_only=args.handshake_only;journey.pressure_only=args.pressure_only;journey.ancestry_only=args.ancestry_only;journey.run();elapsed=time.monotonic()-started;assert elapsed<600,elapsed;infra.write_json("journey-duration.json",{"seconds":elapsed,"limit":600});status=0
    except InfrastructureUnavailable as e:infra.write_json('failure.json',{'classification':'blocked','reason':str(e)});status=2
    except Exception as e:
        if hasattr(infra,'service'):infra.docker('exec',infra.service,'cat','/tmp/service.log',check=False)
        infra.write_json('failure.json',{'classification':'failed','type':type(e).__name__,'reason':str(e),'trace':traceback.format_exc()});status=1
    finally:
        try:infra.cleanup()
        except Exception:status=1
        infra.write_json('result.json',{'status':status,'scope':'FS2-A Task2 actual service protocol'})
    print(json.dumps({'status':status,'output':str(infra.output)}));return status
if __name__=='__main__':sys.exit(main())
