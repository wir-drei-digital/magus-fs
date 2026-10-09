#!/usr/bin/env python3
"""Task3 real client/HTTPS/PG/S3 boundary. Native live application is not claimed."""
import argparse, datetime, concurrent.futures, hashlib, http.client, http.server, json, os, secrets, socket, ssl, subprocess, sys, threading, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, verify_image
from service_protocol import Journey as ProtocolJourney, identity, canonical, file_entry, GROUP, REPLICA, WORKER
from service_storage import NS, ALICE, object_id

class FaultProxy:
    """Actual TLS fault injector: authorized upstream response before body corruption."""
    def __init__(self,j,certificate="server.crt"):
        self.j=j;self.mode='forward';self.objects=0
        proxy=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.forward()
            def do_POST(self):self.forward()
            def do_PUT(self):self.forward()
            def forward(self):
                size=int(self.headers.get('Content-Length','0'));assert size<=16*1024*1024
                body=self.rfile.read(size)
                conn=http.client.HTTPSConnection('127.0.0.1',j.i.port,context=j.ca,timeout=10)
                try:
                    conn.request(self.command,self.path,body,{'Authorization':self.headers.get('Authorization',''),'Content-Type':'application/json'})
                    reply=conn.getresponse();data=reply.read();status=reply.status
                finally:conn.close()
                fault='/objects/' in self.path and self.command=='GET'
                if fault:
                    proxy.objects+=1
                    if proxy.mode=='stall':time.sleep(5);return
                    if proxy.mode=='missing':status=404;data=b'{"code":"not_found"}'
                    if proxy.mode=='corrupt' and status==200:data=bytes([data[0]^1])+data[1:]
                    if proxy.mode=='redirect':
                        self.send_response(302);self.send_header('Location','http://127.0.0.1:1/token-leak');self.send_header('Content-Length','0');self.end_headers();return
                self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers()
                if fault and proxy.mode=='partial':data=data[:17]
                try:self.wfile.write(data)
                except (BrokenPipeError,ssl.SSLError):pass
                self.close_connection=True
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(j.i.control/certificate,j.i.control/'server.key')
        self.server.socket=ctx.wrap_socket(self.server.socket,server_side=True)
        self.port=self.server.server_port
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join()

class Journey(ProtocolJourney):
    def __init__(self,i):
        super().__init__(i);self.children=[];self.proxy=None;self.operations={}
    def cli(self,*args,check=True,binary='magus-fs'):
        p=self.i.run([str(ROOT/'target/debug'/binary),*map(str,args)],timeout=70,check=False)
        value=json.loads(p.stdout)
        if check:assert p.returncode==0 and value['ok'],(args,value,p.stderr)
        return value
    def cli_failure(self,*args):
        p=self.i.run([str(ROOT/'target/debug/magus-fs'),*map(str,args)],timeout=70,check=False)
        value=json.loads(p.stdout);assert p.returncode!=0 and value['ok'] is False,(p.returncode,value)
        return value
    def probe(self,state,*args,check=True):
        p=self.i.run([str(ROOT/'target/debug/examples/client_probe'),str(state),*map(str,args)],timeout=70,check=False)
        value=json.loads(p.stdout)
        if check:assert p.returncode==0 and value['ok'],(args,value,p.stderr)
        return value
    def client(self,name,actor='worker',port=None,ca='ca.crt'):
        root=self.i.output/(name+'-root');root.mkdir(mode=0o700)
        state=self.i.output/(name+'-state')
        replica=WORKER if actor=='worker' else REPLICA
        config={'replica':{'replica':replica,'authorities':[{'principal':ALICE,'uid':os.geteuid(),'gid':os.getegid(),'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}],'content_roots':[str(root)],'cache_bytes':96*1024*1024},'root':str(root),'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
        config_path=self.i.private(name+'-config.json',config)
        token=self.i.private(name+'-token',self.tokens[actor])
        profile=self.i.private(name+'-profile.json',{'endpoint':f'https://127.0.0.1:{port or self.i.port}','namespace':NS,'replica':replica,'ca_file':str(self.i.control/ca),'token_file':str(token)})
        self.cli('init','--state',state,'--config',config_path)
        return state,profile
    def attach(self,state,profile,publication='isolated'):return self.cli('sync','attach','--state',state,'--profile',profile,'--branch','main','--publication',publication)
    def checkpoint(self,state,text):
        self.probe(state,'write','reports/result',text)
        op=identity('operation');revision=self.cli('checkpoint','--state',state,'--operation-id',op)['revision'];self.operations[revision]=op;return revision
    def queued(self,state,revision,operation=None):
        operation=operation or self.operations[revision]
        value=self.cli('sync','run','--state',state,'--revision',revision,'--operation-id',operation,'--enqueue-only','true')
        p=next(p for p in value['status']['submissions'] if p['operation']==operation)
        assert p['private_receipt'] is None and p['applied_revision'] is None
        return operation,p
    def spawn(self,args,name,env=None):
        row={'name':name,'argv':list(map(str,args)),'pid':None};self.children.append(row);self.save_children()
        log=open(self.i.output/(name+'.log'),'w');p=subprocess.Popen(list(map(str,args)),cwd=ROOT,stdout=log,stderr=log,env=env);row['pid']=p.pid;row['process']=p;row['logfile']=log;self.save_children();return p
    def save_children(self):self.i.write_json('client-processes.json',[{k:v for k,v in row.items() if k not in ('process','logfile')} for row in self.children])
    def kill(self,p):
        p.kill();p.wait(timeout=5)
        row=next(r for r in self.children if r['pid']==p.pid);row['reaped']=True;row['logfile'].close();self.save_children()
    def kill_at(self,state,revision,point,enqueue=False):
        marker=self.i.output/(point+'-'+secrets.token_hex(3));env=dict(os.environ,MAGUS_TEST_FAULT_POINT=point,MAGUS_TEST_FAULT_ACTION='pause',MAGUS_TEST_FAULT_MARKER=str(marker))
        op=self.operations[revision];args=[ROOT/'target/debug/magus-fs-client-faults','sync','run','--state',state]
        if enqueue:args+=['--revision',revision,'--operation-id',op]
        p=self.spawn(args,point+'-'+secrets.token_hex(3),env)
        deadline=time.monotonic()+65
        while not marker.exists() and p.poll() is None and time.monotonic()<deadline:time.sleep(.05)
        assert marker.exists(),(point,p.poll())
        self.kill(p)
        progress=self.cli('sync','status','--state',state,'--revision',revision)['progress']
        if not enqueue:op=progress['operation']
        return op,progress
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':448,'content':{'kind':'directory'}}
        chunks=[hashlib.sha256(f'fs2-client-{i}'.encode()).digest()*8192 for i in range(256)]
        full_hash=hashlib.sha256(b''.join(chunks)).hexdigest()
        large=file_entry('reports/large',reports['id']);large['content']['version']={'size':64*1024*1024,'extents':[{'kind':'chunk','object':object_id(b),'object_size':len(b),'offset':0,'length':len(b)} for b in chunks]}
        revision=self.descriptor([reports,large]);upload,rid=self.stage(revision,bodies=chunks)
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        code,delegated=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history','integrate'],'branches':['main'],'prefixes':['reports']}})
        assert code==200
        self.tokens['worker']=delegated['token']
        # Do not retain bearer output in ordinary observation evidence.
        self.observations.append({'case':'delegate','credential':delegated['credential']});self.i.write_json('observations.json',self.observations)
        state,profile=self.client('main')
        self.i.snapshot_volumes();self.i.docker('stop','--time','5',self.i.s3)
        attached=self.attach(state,profile);binding=attached['binding']
        assert attached['counters']['downloaded_body_bytes']==0 and attached['applied_revision'] is None
        self.i.docker('start',self.i.s3);self.i.wait_s3('client-lazy-restart',require_volumes=True)
        status,data=self.bytes_request(self.root+'/views/'+binding['view']['view']+'/objects/'+object_id(chunks[0]));self.i.write_json('restart-independent-read.json',{'status':status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()});assert status==200 and data==chunks[0],(status,len(data))
        cold=[]
        for name,offset in [('head',0),('tail',64*1024*1024-4096)]:
            out=self.i.output/(name+'.bin');v=self.probe(state,'read','reports/large',offset,4096,out);cold.append(v['counters']['downloaded_body_bytes']);expected=chunks[0][:4096] if offset==0 else chunks[-1][-4096:];assert out.read_bytes()==expected
            warm=self.probe(state,'read','reports/large',offset,4096,out);assert warm['counters']['downloaded_body_bytes']==0
        assert sum(cold)<=2*1024*1024
        output=self.i.output/'full.bin';self.probe(state,'full','reports/large',output);assert output.stat().st_size==64*1024*1024 and hashlib.sha256(output.read_bytes()).hexdigest()==full_hash
        self.i.write_json('lazy.json',{'size':output.stat().st_size,'independent_sha256':full_hash,'cold_bytes':cold,'warm_bytes':0,'metadata_body_bytes':0})
        self.fault_reads()
        linux=self.i.docker('exec','-i',self.i.service,'python3','/src/tests/fs2/linux_client.py',input=json.dumps({'namespace':NS,'replica':WORKER,'principal':ALICE,'group':GROUP,'token':self.tokens['worker'],'head_hash':hashlib.sha256(chunks[0][:4096]).hexdigest()}),evidence=False,timeout=90);self.i.write_json('linux-client.json',json.loads(linux.stdout))
        rev=self.checkpoint(state,'first local result')
        op,queued=self.kill_at(state,rev,'sync-enqueued',True)
        assert queued['state']=='Queued'
        self.cli('prune','--state',state,'--dry-run')
        self.stop_service_process()
        unavailable=self.cli('sync','run','--state',state);assert unavailable['progress']['state']=='Retryable' and unavailable['counters']['requests']==3 and unavailable['counters']['retries']==2,unavailable
        old_port=self.i.port;self.i.start_service();self.wait();assert self.i.port==old_port
        self.i.write_json('retry-bound.json',unavailable)
        private_result=self.cli('sync','drain','--state',state,'--revision',rev,'--level','private-remote');private=private_result['progress'];assert private_result['counters']['uploaded_body_bytes']==len(b'first local result') and private_result['counters']['logical_unique_upload_bytes']==len(b'first local result'),private_result
        self.i.write_json('private-transfer.json',private_result)
        assert private['state']=='PrivateRemote' and private['private_receipt']['operation']==op and private['shared_receipt'] is None
        not_shared=self.cli_failure('sync','drain','--state',state,'--revision',rev,'--level','shared');assert not_shared['error']=='integration_required' and not_shared['progress']==private
        self.i.write_json('drain-isolated.json',not_shared)
        assert self.i.sql("SELECT count(*) FROM changes;")=='1'
        shared=self.cli('sync','integrate','--state',state,'--revision',rev,'--expected-head',binding['view']['head'])['progress'];assert shared['state']=='Shared' and shared['integration']['operation']!=op
        assert shared['private_receipt']==private['private_receipt'] and shared['applied_revision'] is None
        later=self.checkpoint(state,'later dirty result')
        assert self.cli('sync','status','--state',state,'--revision',rev)['progress']==shared
        # A separate original projected view remains a private candidate after head advances.
        state2,profile2=self.client('recovery');b2=self.attach(state2,profile2)['binding']
        pre=self.checkpoint(state2,'pre-send recovery');self.queued(state2,pre)
        _,uncertain=self.kill_at(state2,pre,'sync-before-send');assert uncertain['remote_outcome_unknown']
        recovered=self.cli('sync','run','--state',state2)['progress'];assert recovered['request']==uncertain['request'] and recovered['state']=='PrivateRemote'
        lost=self.checkpoint(state2,'committed lost ack');self.queued(state2,lost)
        lost_op,before=self.kill_at(state2,lost,'sync-lost-ack');assert before['private_receipt'] is None and before['remote_outcome_unknown']
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+lost_op+"';")=='1'
        after=self.cli('sync','run','--state',state2)['progress'];assert after['request']==before['request'] and after['request_digest']==before['request_digest'] and after['state']=='PrivateRemote'
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+lost_op+"';")=='1'
        self.owner_control(state2,after,lost)
        advanced=self.cli('sync','integrate','--state',state2,'--revision',pre,'--expected-head',b2['view']['head'])['progress'];assert advanced['state']=='Shared'
        stale=self.cli('sync','integrate','--state',state2,'--revision',lost,'--expected-head',b2['view']['head'])['progress'];assert stale['state']=='Failed' and stale['error']=='stale_head' and not stale['remote_outcome_unknown'] and stale['private_receipt']==after['private_receipt']
        auto_state,auto_profile=self.client('shared-recovery');self.attach(auto_state,auto_profile,'shared-live')
        auto_revision=self.checkpoint(auto_state,'automatic shared restart');self.queued(auto_state,auto_revision)
        self.kill_at(auto_state,auto_revision,'sync-lost-ack')
        auto_private=self.cli('sync','run','--state',auto_state)['progress'];assert auto_private['state']=='PrivateRemote'
        auto_shared=self.cli('sync','run','--state',auto_state,check=False);self.i.write_json('shared-restart.json',auto_shared)
        shared_restart_ok=auto_shared.get('progress',{}).get('state')=='Shared'
        for args in [('local','sha256:'+'0'*64),('unknown',lost),('applied',lost)]:
            assert not self.cli('sync','drain','--state',state2,'--revision',args[1],'--level',args[0],check=False)['ok']
        queued_rev=self.checkpoint(state2,'deadline retained');self.queued(state2,queued_rev)
        t=time.monotonic();bounded=self.cli_failure('sync','drain','--state',state2,'--revision',queued_rev,'--level','private-remote','--deadline-ms','0');assert time.monotonic()-t<2 and bounded['error']=='deadline' and bounded['progress']['private_receipt'] is None
        self.i.write_json('drain-deadline.json',bounded)
        denied_rev=self.checkpoint(state,'revoked local result');self.queued(state,denied_rev)
        denied_op,unknown=self.kill_at(state,denied_rev,'sync-lost-ack')
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+denied_op+"';")=='1'
        self.expect('revoke','POST',self.root+'/grants',200,body={'revoke':delegated['credential']})
        denied=self.cli('sync','run','--state',state)['progress'];assert denied['state']=='Denied' and denied['error']=='invalid_credential' and denied['remote_outcome_unknown'] and denied['request']==unknown['request']
        self.expect('revoked-exact-replay','POST',self.root+'/candidates',401,{'code':'invalid_credential'},actor='worker',body=unknown['request'])
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+denied_op+"';")=='1'
        local=self.i.output/'revoked-local.bin';self.probe(state,'read','reports/result',0,4096,local);assert local.read_bytes()==b'revoked local result'
        self.i.write_json('receipts.json',{'private':private,'shared':shared,'pre_send':recovered,'lost_ack_before':before,'lost_ack_after':after,'denied':denied,'stale':stale,'automatic_shared':auto_shared})
        assert shared_restart_ok,'SharedLive restart did not resume integration from private receipt'
    def stop_service_process(self):
        script="import os,signal,time; p=int(open('/tmp/service.pid').read()); assert os.readlink('/proc/%d/exe'%p).endswith('/magus-fs-service'); os.kill(p,signal.SIGTERM); end=time.monotonic()+7\nwhile os.path.exists('/proc/%d'%p) and time.monotonic()<end: time.sleep(.05)\nassert not os.path.exists('/proc/%d'%p); print('owned service process stopped; ingress retained')"
        self.i.docker('exec',self.i.service,'python3','-c',script)
    def owner_control(self,state,receipt,revision):
        p=self.spawn([ROOT/'target/debug/magus-fs','sync','run','--state',state,'--serve','true'],'owner')
        deadline=time.monotonic()+5
        while not (state/'control.sock').exists() and p.poll() is None and time.monotonic()<deadline:time.sleep(.05)
        assert (state/'control.sock').exists()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            values=list(ex.map(lambda _:self.cli('sync','status','--state',state,'--revision',revision),range(4)))
        assert all(v['progress']==receipt for v in values)
        assert self.cli('sync','drain','--state',state,'--revision',revision,'--level','private-remote')['progress']==receipt
        unmet=self.cli_failure('sync','drain','--state',state,'--revision',revision,'--level','shared');assert unmet['error']=='integration_required' and unmet['progress']==receipt
        self.i.write_json('drain-owner.json',unmet)
        assert not self.cli('prune','--state',state,'--dry-run',check=False)['ok']
        self.kill(p)
    def fault_reads(self):
        self.proxy=FaultProxy(self)
        state,profile=self.client('faults',port=self.proxy.port);self.attach(state,profile)
        for mode in ['missing','corrupt','partial','redirect','stall']:
            self.proxy.mode=mode
            for attempt in range(2):
                start=time.monotonic();value=self.probe(state,'read','reports/large',0,4096,self.i.output/'bad.bin',check=False);elapsed=time.monotonic()-start
                assert not value['ok'] and elapsed<=5,(mode,value,elapsed)
                self.observations.append({'case':'client-'+mode,'seconds':elapsed,'error':value['error'],'counters':value.get('counters')})
            assert self.cli('status','--state',state)['resident_verified_bytes']==0
        self.proxy.mode='forward';self.probe(state,'read','reports/large',0,4096,self.i.output/'repaired.bin')
        assert self.proxy.objects==11
        original=profile.read_bytes();changed=json.loads(original);changed['endpoint']='https://127.0.0.1:1';profile.write_text(json.dumps(changed))
        retarget=self.probe(state,'read','reports/large',262144,4096,self.i.output/'retarget.bin',check=False);assert not retarget['ok'] and retarget['error']=='config_mismatch' and self.proxy.objects==11
        profile.write_bytes(original)
        token=Path(json.loads(original)['token_file']);old_token=token.read_bytes();token.write_text('0'*64)
        rotated=self.probe(state,'read','reports/large',262144,4096,self.i.output/'rotated.bin',check=False);assert not rotated['ok'] and self.proxy.objects==12
        assert self.cli('status','--state',state)['resident_verified_bytes']==262144
        token.write_bytes(old_token);restored=self.probe(state,'read','reports/large',262144,4096,self.i.output/'restored-token.bin');assert restored['counters']['downloaded_body_bytes']==262144
        self.observations.append({'case':'immutable-profile-and-current-token','retarget':retarget,'rotated':rotated,'restored':restored})
        self.proxy.close();self.proxy=None
        wrong,profile=self.client('wrong-ca',ca='wrong-ca.crt');assert not self.cli('sync','attach','--state',wrong,'--profile',profile,'--branch','main',check=False)['ok']
        unsafe,profile=self.client('unsafe');profile.chmod(0o644);assert not self.cli('sync','attach','--state',unsafe,'--profile',profile,'--branch','main',check=False)['ok'];profile.chmod(0o600)
        symlink=self.i.control/'profile-link';symlink.symlink_to(profile);assert not self.cli('sync','attach','--state',unsafe,'--profile',symlink,'--branch','main',check=False)['ok']
        self.tls_denials()
        confined,profile=self.client('confined');inside=self.i.output/'confined-root'/'profile.json';inside.write_bytes(profile.read_bytes());inside.chmod(0o600);assert not self.cli('sync','attach','--state',confined,'--profile',inside,'--branch','main',check=False)['ok']
        self.i.write_json('observations.json',self.observations)
    def tls_denials(self):
        d=self.i.control;now=datetime.datetime.now(datetime.timezone.utc)
        common=['openssl','x509','-req','-in',str(d/'server.csr'),'-CA',str(d/'ca.crt'),'-CAkey',str(d/'ca.key'),'-CAserial',str(d/'ca.srl')]
        self.i.run(common+['-not_before',(now-datetime.timedelta(days=2)).strftime('%Y%m%d%H%M%SZ'),'-not_after',(now-datetime.timedelta(days=1)).strftime('%Y%m%d%H%M%SZ'),'-extfile',str(d/'extensions'),'-out',str(d/'expired.crt')])
        extension=d/'wrong-host-extensions';extension.write_text('subjectAltName=DNS:wrong.invalid\nextendedKeyUsage=serverAuth\n');extension.chmod(0o600)
        self.i.run(common+['-days','1','-extfile',str(extension),'-out',str(d/'wrong-host.crt')])
        for cert in ['expired.crt','wrong-host.crt']:
            (d/cert).chmod(0o600);self.proxy=FaultProxy(self,cert);state,profile=self.client(cert,port=self.proxy.port)
            result=self.cli('sync','attach','--state',state,'--profile',profile,'--branch','main',check=False);assert not result['ok'],cert
            self.observations.append({'case':cert,'result':result});self.proxy.close();self.proxy=None
    def cleanup(self):
        if self.proxy:self.proxy.close()
        for row in self.children:
            p=row.get('process')
            if p and p.poll() is None:self.kill(p)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--image',default='magus-fs2-task3');ap.add_argument('--skip-build',action='store_true');ap.add_argument('--skip-checks',action='store_true');args=ap.parse_args()
    i=OwnedInfra(Path(args.output));status=1;j=None
    try:
        i.preflight();source=capture(i)
        if not args.skip_checks:
            i.run(['python3','-m','unittest','discover','-s','tests/fs2','-p','test_*.py'],timeout=60)
            i.run(['cargo','+stable','fmt','--all','--check'],timeout=60)
            i.run(['cargo','+stable','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings'],timeout=300)
            i.run(['cargo','+stable','test','--locked','--workspace','--all-features'],timeout=300)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],timeout=300)
        import shutil
        shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults');os.chmod(ROOT/'target/debug/magus-fs-client-faults',0o755)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--examples'],timeout=300)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
        if not args.skip_build:i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY='+('0' if args.skip_checks else '1'),'-t',args.image,'.',timeout=900)
        i.setup(args.image);verify_image(i,source)
        binaries={}
        for name,local in [('magus-fs','magus-fs'),('magus-fs-client-faults','magus-fs-client-faults'),('client_probe','examples/client_probe')]:
            binaries[name]={'host':hashlib.sha256((ROOT/'target/debug'/local).read_bytes()).hexdigest(),'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+name).stdout.split()[0]}
        i.write_json('client-binaries.json',binaries)
        j=Journey(i);start=time.monotonic();j.run();elapsed=time.monotonic()-start;assert elapsed<600
        i.write_json('journey-duration.json',{'seconds':elapsed,'limit':600});status=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});status=2
    except Exception as e:i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()})
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e)});status=1
        i.write_json('result.json',{'status':status,'scope':'Task3 client protocol; no native applied claim'})
    print(json.dumps({'status':status,'output':str(i.output)}));return status
if __name__=='__main__':sys.exit(main())
