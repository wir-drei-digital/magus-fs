#!/usr/bin/env python3
"""Deterministic real owner/control publication race and deadline regression."""
import argparse,hashlib,http.client,http.server,json,os,secrets,shutil,ssl,sys,threading,time,traceback
from pathlib import Path
from client_protocol import Journey
from infra import OwnedInfra,InfrastructureUnavailable,ROOT
from provenance import capture,verify_image
from service_protocol import identity,GROUP,REPLICA,WORKER
from service_storage import NS,ALICE

class PublicationBarrier:
    def __init__(self,j):
        self.upload_started=threading.Event();self.release_uploads=threading.Event()
        self.integration_started=threading.Event();self.release_integrations=threading.Event()
        self.lock=threading.Lock();self.uploads=[];self.integrations=[];self.operation_gets=0
        barrier=self
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
                if self.command=='POST' and self.path.endswith('/uploads') and status==201:
                    with barrier.lock:barrier.uploads.append(json.loads(data)['upload'])
                    barrier.upload_started.set();assert barrier.release_uploads.wait(10),'upload barrier deadline'
                if self.command=='POST' and self.path.endswith('/integrations') and status==200:
                    with barrier.lock:barrier.integrations.append(json.loads(body)['operation'])
                    barrier.integration_started.set();assert barrier.release_integrations.wait(10),'integration barrier deadline'
                if self.command=='GET' and '/operations/' in self.path:
                    with barrier.lock:barrier.operation_gets+=1
                try:
                    self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                except (BrokenPipeError,ssl.SSLError):pass
                self.close_connection=True
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(j.i.control/'server.crt',j.i.control/'server.key')
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True);self.port=self.server.server_port
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):
        self.release_uploads.set();self.release_integrations.set();self.server.shutdown();self.server.server_close();self.thread.join()

class OwnerJourney(Journey):
    def completed(self,p):
        code=p.wait(timeout=10);row=next(r for r in self.children if r['pid']==p.pid)
        row['reaped']=True;row['logfile'].close();self.save_children()
        value=json.loads((self.i.output/(row['name']+'.log')).read_text());assert code==0 and value['ok'],(code,value)
        return value
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':448,'content':{'kind':'directory'}}
        upload,rid=self.stage(self.descriptor([reports]));self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        code,delegated=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','integrate','history'],'branches':['main'],'prefixes':['reports']}});assert code==200
        self.tokens['worker']=delegated['token'];self.proxy=PublicationBarrier(self)
        state,profile=self.client('owner',port=self.proxy.port);binding=self.attach(state,profile,'shared-live')['binding']
        revision=self.checkpoint(state,'one immutable owner candidate');operation,queued=self.queued(state,revision)
        owner=self.spawn([ROOT/'target/debug/magus-fs','sync','run','--state',state,'--serve','true'],'owner-background')
        assert self.proxy.upload_started.wait(5),'background tick never reached upload barrier'
        started=time.monotonic();held=self.cli('sync','status','--state',state,'--revision',revision)['progress'];status_seconds=time.monotonic()-started
        assert held==queued and status_seconds<2
        started=time.monotonic();drained=self.cli_failure('sync','drain','--state',state,'--revision',revision,'--level','private-remote','--deadline-ms','200');elapsed=time.monotonic()-started
        self.proxy.release_uploads.set()
        progress=held
        deadline=time.monotonic()+8
        while not self.proxy.integration_started.is_set() and time.monotonic()<deadline:
            progress=self.cli('sync','status','--state',state,'--revision',revision)['progress']
            if progress['state']=='Failed':break
            time.sleep(.02)
        observation={'held':held,'drain':drained,'drain_seconds':elapsed,'status_seconds':status_seconds,'created_uploads':self.proxy.uploads,'after_upload':progress}
        self.i.write_json('owner-race.json',observation)
        assert drained['error']=='deadline' and elapsed<2 and drained['progress']==queued,observation
        assert len(self.proxy.uploads)==1 and self.proxy.integration_started.is_set(),observation
        during=self.cli('sync','status','--state',state,'--revision',revision)['progress']
        assert during['private_receipt'] and during['integration'] and during['remote_outcome_unknown']
        assert during['request']['original_view']==binding['view']['view'] and during['request']['original_head']==binding['view']['head']
        clients=[self.spawn([ROOT/'target/debug/magus-fs','sync','integrate','--state',state,'--revision',revision,'--expected-head',binding['view']['head']],f'control-integrate-{i}') for i in range(2)]
        # The accepted integration response remains held while both command processes are live.
        time.sleep(.2);assert all(p.poll() is None for p in clients)
        self.proxy.release_integrations.set();outcomes=[self.completed(p)['progress'] for p in clients]
        after=self.cli('sync','status','--state',state,'--revision',revision)['progress']
        assert all(p==after for p in outcomes) and after['state']=='Shared' and after['error'] is None
        assert after['request']==during['request'] and after['request_digest']==during['request_digest'] and after['integration']==during['integration'] and after['private_receipt']==during['private_receipt']
        assert after['applied_revision'] is None and not after['remote_outcome_unknown']
        assert self.proxy.integrations==[after['integration']['operation']] and self.proxy.operation_gets==0
        for op in [operation,after['integration']['operation']]:assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+op+"';")=='1'
        observation.update({'during_integration':during,'after':after,'concurrent_integrations':outcomes,'integration_posts':self.proxy.integrations,'operation_gets':self.proxy.operation_gets});self.i.write_json('owner-race.json',observation)
        self.kill(owner)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--image',default='magus-fs2-task3-owner-fix1');checks=parser.add_mutually_exclusive_group();checks.add_argument('--skip-checks',action='store_true');checks.add_argument('--control-only-checks',action='store_true');args=parser.parse_args()
    i=OwnedInfra(Path(args.output));status=1;j=None
    try:
        i.preflight();source=capture(i)
        if not args.skip_checks:
            i.run(['python3','-m','unittest','discover','-s','tests/fs2','-p','test_*.py'],timeout=60)
            i.run(['cargo','+stable','fmt','--all','--check'],timeout=60)
            packages=['-p','magus-fs'] if args.control_only_checks else ['-p','magus-fs-core','-p','magus-fs']
            i.run(['cargo','+stable','clippy','--locked',*packages,'--all-targets','--all-features','--','-D','warnings'],timeout=300)
            i.run(['cargo','+stable','test','--locked',*packages,'--all-targets','--all-features'],timeout=300)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],timeout=300)
        shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults');os.chmod(ROOT/'target/debug/magus-fs-client-faults',0o755)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--examples'],timeout=300)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
        i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY='+('0' if args.skip_checks else 'client' if args.control_only_checks else 'client-fix'),'-t',args.image,'.',timeout=900)
        i.setup(args.image);verify_image(i,source)
        binaries={}
        for name,local in [('magus-fs','magus-fs'),('magus-fs-client-faults','magus-fs-client-faults'),('client_probe','examples/client_probe')]:
            binaries[name]={'host':hashlib.sha256((ROOT/'target/debug'/local).read_bytes()).hexdigest(),'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+name).stdout.split()[0]}
        i.write_json('client-binaries.json',binaries)
        j=OwnerJourney(i);start=time.monotonic();j.run();elapsed=time.monotonic()-start;assert elapsed<600
        i.write_json('journey-duration.json',{'seconds':elapsed,'limit':600});status=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});status=2
    except Exception as e:i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()})
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e)});status=1
        i.write_json('result.json',{'status':status,'scope':'Task3 fix1 concurrent mutating owner control; no native applied claim'})
    print(json.dumps({'status':status,'output':str(i.output)}));return status
if __name__=='__main__':sys.exit(main())
