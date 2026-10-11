#!/usr/bin/env python3
"""Actual HTTPS, PostgreSQL and S3 process boundary; exit 0/1/2 = pass/fail/blocked."""
import argparse
import copy
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import time
import traceback
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture,verify_image

NS='1'*32
OTHER='2'*32
ALICE='principal:'+'a'*32
BOB='principal:'+'b'*32

def object_id(data):
    return 'sha256:'+hashlib.sha256(data).hexdigest()

class Journey:
    def __init__(self, infra):
        self.i=infra; self.observations=[]
        self.ca=ssl.create_default_context(cafile=str(infra.control/'ca.crt'))
        self.tokens={k:secrets.token_hex(32) for k in ['alice','bob','readonly','expired','worker']}
        now=int(time.time())
        rows=[]
        for n,name in enumerate(self.tokens):
            if name=='worker':
                continue
            rows.append({'namespace':OTHER if name=='bob' else NS,'principal':BOB if name=='bob' else ALICE,'replica':'replica:'+f'{n+1:032x}','token':self.tokens[name], 'expires':now-1 if name=='expired' else now+3600,'actions':['read'] if name=='readonly' else ['read','write','history','integrate','admin'],'branches':['main'],'prefixes':['']})
        infra.provision(rows)

    def request(self, method, path, actor='alice', body=None, raw=None, headers=None, timeout=10, response_bytes=False):
        c=http.client.HTTPSConnection('127.0.0.1',self.i.port,context=self.ca,timeout=timeout)
        h={'Authorization':'Bearer '+self.tokens.get(actor,actor)}
        if body is not None:
            raw=json.dumps(body).encode();h['Content-Type']='application/json'
        h.update(headers or {})
        try:
            c.request(method,path,body=raw,headers=h)
            r=c.getresponse();data=r.read()
            return r.status,(data if response_bytes else json.loads(data) if data else None)
        finally:
            c.close()

    def expect(self, name, method, path, status, value=None, response_bytes=False, **kw):
        # Scripted fixture calls obey the existing admission backoff without
        # regenerating candidate/upload/operation identities or extending10s.
        before=time.monotonic();deadline=before+10;actor=kw.get('actor','alice')
        headers={'Authorization':'Bearer '+self.tokens.get(actor,actor)}
        if kw.get('body') is not None:
            kw['raw']=json.dumps(kw.pop('body')).encode();headers['Content-Type']='application/json'
        headers.update(kw.get('headers') or {});kw['headers']=headers
        raw=kw.get('raw');payload=raw.encode() if isinstance(raw,str) else bytes(raw or b'')
        if raw is not None:kw['raw']=payload
        request={'method':method,'path':path,'actor':actor,'body_sha256':hashlib.sha256(payload).hexdigest(),'body_bytes':len(payload),'authorization_sha256':hashlib.sha256(headers['Authorization'].encode()).hexdigest()}
        for attempt in range(3):
            if attempt:time.sleep(min((.1,.3)[attempt-1],max(0,deadline-time.monotonic())))
            remaining=deadline-time.monotonic();assert remaining>0,(name,'request deadline exceeded')
            started=time.monotonic();actual,data=self.request(method,path,timeout=remaining,**({'response_bytes':True} if response_bytes else {}),**kw)
            elapsed=time.monotonic()-before
            classification=data;recorded=copy.deepcopy(data)
            if response_bytes:
                data=bytes(data);leaf='http-body-'+str(len(self.observations))+'.bin';(self.i.output/leaf).write_bytes(data)
                recorded={'artifact':leaf,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
                try:classification=json.loads(data)
                except (ValueError,UnicodeDecodeError):classification=None
            self.observations.append({'case':name,'status':actual,'body':recorded,'seconds':time.monotonic()-started,'elapsed_seconds':elapsed,'attempt':attempt+1,'request':request})
            self.i.write_json('observations.json',self.observations)
            assert elapsed<=10,(name,'request deadline exceeded')
            if 200<=status<300 and actual==503 and classification=={'code':'backpressure'} and attempt<2:continue
            assert actual==status,(name,actual,data,status)
            if value is not None:assert data==value,(name,data,value)
            return data

    def expect_bytes(self,name,path,actor='alice'):
        return self.expect(name,'GET',path,200,actor=actor,response_bytes=True)

    def wait(self):
        until=time.monotonic()+30
        while time.monotonic()<until:
            try:
                if self.request('GET','/health')[0]==200:
                    return
            except (OSError,ssl.SSLError,http.client.HTTPException) as error:
                last=type(error).__name__+': '+str(error)
            time.sleep(.1)
        raise AssertionError('HTTPS readiness deadline: '+locals().get('last','unexpected HTTP response'))

    def create(self,actor='alice'):
        return self.expect('create-'+actor,'POST',f'/v1/n/{NS}/uploads',201,actor=actor,body={})['upload']

    def run(self):
        self.i.start_service();self.wait()
        self.expect('health','GET','/health',200,{'protocol':'magus-fs/service-v1','status':'ok'})
        code,worker=self.request('POST',f'/v1/n/{NS}/grants',body={'delegate':{'replica':'replica:'+f'{5:032x}','expires':int(time.time())+1800,'actions':['read','write'],'branches':['main'],'prefixes':['reports']}})
        assert code==200,code
        self.tokens['worker']=worker['token']
        self.i.private('worker-token',worker['token'])
        self.observations.append({'case':'narrow-delegation','status':code,'credential':worker['credential']})
        root=f'/v1/n/{NS}/uploads'
        for actor in ['unknown','expired']:
            self.expect(actor,'POST',root,401,{'code':'invalid_credential'},actor=actor,body={})
        self.expect('cross-namespace','POST',root,404,{'code':'not_found'},actor='bob',body={})
        self.expect('readonly','POST',root,404,{'code':'not_found'},actor='readonly',body={})
        self.expect('closed-json','POST',root,400,{'code':'invalid_request'},body={'unknown':1})
        self.expect('control-limit','POST',root,413,{'code':'limit_exceeded'},raw=b' '*65537)
        upload=self.create(); path=root+'/'+upload
        self.expect('empty-list','GET',path,200,{'upload':upload,'objects':[]})
        self.expect('foreign-session','GET',path,404,{'code':'not_found'},actor='worker')
        body=b'acknowledged persistent bytes\x00\xff'
        oid=object_id(body); put=path+'/objects/'+oid
        self.expect('bad-hash','PUT',put,400,{'code':'hash_mismatch'},raw=b'wrong')
        self.expect('invalid-id','PUT',path+'/objects/nope',400,{'code':'invalid_id'},raw=body)
        self.expect('chunk-limit','PUT',put,413,{'code':'limit_exceeded'},raw=b'x'*1048577)
        c=http.client.HTTPSConnection('127.0.0.1',self.i.port,context=self.ca,timeout=10)
        c.request('PUT',put,body=iter([b'x'*524288,b'x'*524288,b'x']),headers={'Authorization':'Bearer '+self.tokens['alice']},encode_chunked=True)
        response=c.getresponse();chunked=json.loads(response.read());c.close()
        assert (response.status,chunked)==(413,{'code':'limit_exceeded'}),(response.status,chunked)
        self.observations.append({'case':'chunked-body-limit','status':response.status,'body':chunked})
        result={'object':oid,'size':len(body),'ready':True}
        self.expect('install','PUT',put,200,result,raw=body)
        self.expect('identical-reinstall','PUT',put,200,result,raw=body)
        listed={'upload':upload,'objects':[{'object':oid,'size':len(body)}]}
        self.expect('completed-list','GET',path,200,listed)
        assert self.i.sql('SELECT count(*) FROM objects;')=='1'
        assert self.i.sql('SELECT count(*) FROM session_objects;')=='1'
        assert self.i.sql("SELECT state FROM objects;")=='ready'
        key=self.i.sql('SELECT storage_key FROM objects;')
        independent=json.loads(self.i.s3_request('GET','/fs2/'+key).stdout)
        assert independent['sha256']==hashlib.sha256(body).hexdigest(),independent
        self.i.write_json('independent-object.json',{'key':key,**independent})
        assert json.loads(self.i.s3_request('HEAD','/fs2/'+key).stdout)['status']==200
        unsigned=json.loads(self.i.s3_request('GET','/fs2/'+key,anonymous=True,check=False).stdout)
        assert unsigned['status']==403,unsigned
        self.observations.append({'case':'s3-anonymous-denied','status':403})
        self.expect('hash-not-read-authority','GET',f'/v1/n/{NS}/objects/'+oid,404,{'code':'not_found'})
        probe='/fs2/independent-probe'
        assert json.loads(self.i.s3_request('PUT',probe,'independent').stdout)['status']==200
        assert json.loads(self.i.s3_request('DELETE',probe).stdout)['status'] in (200,204)
        assert json.loads(self.i.s3_request('GET',probe,check=False).stdout)['status']==404
        self.tls_negatives()
        self.truncated(path)
        self.session_rechecks(root,body,oid)
        # Revocation/generation/expiry checked again for reused sessions, not only creation.
        worker_upload=self.create('worker')
        worker_id=self.i.sql("SELECT id FROM credentials WHERE replica='replica:00000000000000000000000000000005';")
        self.expect('revoke','POST',f'/v1/n/{NS}/grants',200,{'revoked':True},body={'revoke':worker_id})
        self.expect('revoked-replay','PUT',root+'/'+worker_upload+'/objects/'+oid,401,{'code':'invalid_credential'},actor='worker',raw=body)
        # Stop/restart all actual processes with retained volumes.
        self.i.snapshot_volumes()
        self.i.docker('stop','--time','5',self.i.service,self.i.pg,self.i.s3)
        self.i.docker('start',self.i.pg,self.i.s3,self.i.service)
        self.i.start_service();self.wait()
        self.expect('restart-session','GET',path,200,listed)
        self.i.wait_s3('all-process-restart')
        again=json.loads(self.i.s3_request('GET','/fs2/'+key).stdout)
        assert again['sha256']==independent['sha256']
        self.observations.append({'case':'all-process-restart','independent_sha256':again['sha256']})
        # Backend failure cannot acknowledge or mark ready.
        failed=b'backend unavailable chunk';fid=object_id(failed)
        self.i.docker('stop','--time','5',self.i.s3)
        self.expect('failed-install','PUT',path+'/objects/'+fid,503,{'code':'backend_unavailable'},raw=failed)
        assert self.i.sql("SELECT state FROM objects WHERE object_id='"+fid+"';")=='uploading'
        self.expect('failed-not-listed','GET',path,200,listed)
        self.i.docker('start',self.i.s3)
        self.i.wait_s3('backend-failure-restart')
        self.expect('failed-retry','PUT',path+'/objects/'+fid,200,{'object':fid,'size':len(failed),'ready':True},raw=failed)
        self.crash_boundary(path)
        self.redirect_denial(path)
        self.expired_certificate()
        # A trusted backend-admin corruption must never leave a usable ready witness.
        self.i.s3_request('PUT','/fs2/'+key,'X'*len(body))
        self.expect('stored-corruption','PUT',put,400,{'code':'corrupt_object'},raw=body)
        assert self.i.sql("SELECT state FROM objects WHERE object_id='"+oid+"';")=='corrupt'
        assert oid not in [x['object'] for x in self.request('GET',path)[1]['objects']]
        self.clean_shutdown()
        # Only hashes, never bearer tokens, are persisted in authority rows.
        hashes=self.i.sql('SELECT token_hash FROM credentials;').splitlines()
        assert hashes and all(len(h)==64 and h not in self.tokens.values() for h in hashes)
        self.i.write_json('observations.json',self.observations)

    def session_rechecks(self,root,body,oid):
        session=self.create('worker')
        self.i.sql("UPDATE credentials SET generation=generation+1 WHERE replica='replica:00000000000000000000000000000005';")
        self.expect('generation-replay','PUT',root+'/'+session+'/objects/'+oid,404,{'code':'not_found'},actor='worker',raw=body)
        lease=self.create('worker')
        self.i.sql("UPDATE credentials SET expires=clock_timestamp()-interval '1 second' WHERE replica='replica:00000000000000000000000000000005';")
        self.expect('credential-expiry-replay','GET',root+'/'+lease,401,{'code':'invalid_credential'},actor='worker')
        self.i.sql("UPDATE credentials SET expires=clock_timestamp()+interval '900 seconds' WHERE replica='replica:00000000000000000000000000000005';")
        self.i.sql("UPDATE upload_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id='"+lease+"';")
        self.expect('expired-session','GET',root+'/'+lease,404,{'code':'not_found'},actor='worker')
        self.expect('worker-admin-denial','POST',f'/v1/n/{NS}/grants',404,{'code':'not_found'},actor='worker',body={'revoke':'0'*32})
        # Bounds are reached through a valid owned row, and reject before S3 installation.
        capped=self.create()
        self.i.sql("UPDATE upload_sessions SET reserved_objects=4096 WHERE id='"+capped+"';")
        data=b'object-count-pressure'
        self.expect('session-object-bound','PUT',root+'/'+capped+'/objects/'+object_id(data),413,{'code':'limit_exceeded'},raw=data)
        assert self.i.sql("SELECT count(*) FROM objects WHERE object_id='"+object_id(data)+"';")=='0'
        self.i.sql("UPDATE upload_sessions SET reserved_objects=0,reserved_bytes=536870912 WHERE id='"+capped+"';")
        self.expect('session-byte-bound','PUT',root+'/'+capped+'/objects/'+object_id(data),413,{'code':'limit_exceeded'},raw=data)

    def redirect_denial(self,path):
        self.clean_shutdown()
        config_path=self.i.control/'service.json';config=json.loads(config_path.read_text());endpoint=config['s3_endpoint']
        config['s3_endpoint']='http://127.0.0.1:8999';config_path.write_text(json.dumps(config))
        script="""from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
class Redirect(BaseHTTPRequestHandler):
 def do_PUT(self):
  self.rfile.read(int(self.headers.get('Content-Length','0')))
  counter=Path('/tmp/redirect-count');counter.write_text(str(int(counter.read_text())+1))
  if self.path=='/trap': Path('/tmp/redirect-followed').touch()
  self.send_response(307);self.send_header('Location','http://127.0.0.1:8999/trap');self.send_header('Content-Length','0');self.end_headers()
 def log_message(self,*args): pass
server=HTTPServer(('127.0.0.1',8999),Redirect)
Path('/tmp/redirect-count').write_text('0');Path('/tmp/redirect-ready').touch();server.serve_forever()
"""
        self.i.docker('exec','-d',self.i.service,'python3','-c',script)
        until=time.monotonic()+5
        while time.monotonic()<until:
            if self.i.docker('exec',self.i.service,'test','-f','/tmp/redirect-ready',check=False,evidence=False).returncode==0:
                break
            time.sleep(.1)
        else:
            raise AssertionError('redirect fixture readiness')
        self.i.start_service();self.wait()
        data=b'redirect must not follow'
        self.expect('backend-redirect-denied','PUT',path+'/objects/'+object_id(data),503,{'code':'backend_unavailable'},raw=data)
        assert self.i.docker('exec',self.i.service,'cat','/tmp/redirect-count').stdout.strip()=='1'
        assert self.i.docker('exec',self.i.service,'test','-f','/tmp/redirect-followed',check=False).returncode==1
        self.observations.append({'case':'no-redirect-no-implicit-retry','attempts':1,'followed':False})
        config['s3_endpoint']=endpoint;config_path.write_text(json.dumps(config))
        self.i.restart_service();self.wait()

    def expired_certificate(self):
        d=str(self.i.control)
        now=datetime.datetime.now(datetime.timezone.utc)
        before=(now-datetime.timedelta(days=2)).strftime('%Y%m%d%H%M%SZ')
        after=(now-datetime.timedelta(days=1)).strftime('%Y%m%d%H%M%SZ')
        self.i.run(['openssl','x509','-req','-in',d+'/server.csr','-CA',d+'/ca.crt','-CAkey',d+'/ca.key','-CAserial',d+'/ca.srl','-not_before',before,'-not_after',after,'-extfile',d+'/extensions','-out',d+'/expired.crt'])
        (self.i.control/'expired.crt').chmod(0o600)
        path=self.i.control/'service.json';config=json.loads(path.read_text());original=config['tls_cert'];config['tls_cert']='/control/expired.crt';path.write_text(json.dumps(config))
        self.i.restart_service()
        until=time.monotonic()+15
        while time.monotonic()<until:
            try:
                self.request('GET','/health')
            except ssl.SSLCertVerificationError as e:
                assert e.verify_code==10,(e.verify_code,str(e))
                self.observations.append({'case':'expired-certificate','verify_code':e.verify_code});break
            except (OSError,http.client.HTTPException):
                time.sleep(.1)
            else:
                raise AssertionError('expired certificate accepted')
        else:
            raise AssertionError('expired certificate test never reached TLS')
        config['tls_cert']=original;path.write_text(json.dumps(config))
        self.i.restart_service();self.wait()

    def clean_shutdown(self):
        script="import os,signal,time; p=int(open('/tmp/service.pid').read()); assert os.readlink('/proc/%d/exe'%p).endswith('/magus-fs-service'); os.kill(p,signal.SIGTERM); end=time.monotonic()+7\nwhile os.path.exists('/proc/%d'%p) and time.monotonic()<end: time.sleep(.05)\nassert not os.path.exists('/proc/%d'%p); print('clean service shutdown')"
        self.i.docker('exec',self.i.service,'python3','-c',script)
        self.observations.append({'case':'graceful-shutdown','within_seconds':7})

    def tls_negatives(self):
        for name,ctx,hostname in [
            ('wrong-ca',ssl.create_default_context(cafile=str(self.i.control/'wrong-ca.crt')),'localhost'),
            ('wrong-hostname',self.ca,'wrong.invalid'),
            ('untrusted-root',ssl.create_default_context(),'localhost')]:
            try:
                with socket.create_connection(('127.0.0.1',self.i.port),timeout=2) as sock:
                    with ctx.wrap_socket(sock,server_hostname=hostname):
                        pass
            except ssl.SSLCertVerificationError:
                self.observations.append({'case':name,'denied':True})
            else:
                raise AssertionError(name+' accepted')
        c=http.client.HTTPConnection('127.0.0.1',self.i.port,timeout=3)
        try:
            c.request('GET','/health');r=c.getresponse()
            assert r.status not in range(200,400),r.status
        except (OSError,http.client.HTTPException):
            pass
        finally:
            c.close()
        self.observations.append({'case':'plaintext-downgrade-no-redirect','denied':True})

    def truncated(self,path):
        oid=object_id(b'truncated')
        with socket.create_connection(('127.0.0.1',self.i.port),timeout=2) as raw:
            with self.ca.wrap_socket(raw,server_hostname='localhost') as s:
                s.sendall(('PUT '+path+'/objects/'+oid+' HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+self.tokens['alice']+'\r\nContent-Length: 9\r\n\r\ntrunc').encode())
                # An incomplete body reaches the bounded body deadline, not installation.
                s.settimeout(11)
                reply=s.recv(4096)
                assert b'408' in reply or b'400' in reply,(reply,)
        assert self.i.sql("SELECT count(*) FROM objects WHERE object_id='"+oid+"';")=='0'
        self.observations.append({'case':'truncated-body','status_line':reply.split(b'\r\n')[0].decode()})

    def crash_boundary(self,path):
        import concurrent.futures
        data=b'killed after S3 install before ready';oid=object_id(data)
        self.i.private('pause-install','pause')
        self.i.restart_service(faults=True);self.wait()
        with concurrent.futures.ThreadPoolExecutor() as ex:
            future=ex.submit(self.request,'PUT',path+'/objects/'+oid,raw=data)
            until=time.monotonic()+15
            while time.monotonic()<until:
                # Barrier marker printed only by fault binary, carries no data/token.
                p=self.i.docker('exec',self.i.service,'test','-f','/tmp/fs2-install-barrier',check=False,evidence=False)
                if p.returncode==0:
                    break
                time.sleep(.1)
            else:
                raise AssertionError('install barrier not reached')
            assert self.i.sql("SELECT state FROM objects WHERE object_id='"+oid+"';")=='uploading'
            key=self.i.sql("SELECT storage_key FROM objects WHERE object_id='"+oid+"';")
            assert json.loads(self.i.s3_request('GET','/fs2/'+key).stdout)['sha256']==hashlib.sha256(data).hexdigest()
            self.i.docker('kill','--signal','KILL',self.i.service)
            try:
                future.result()
            except (OSError,http.client.HTTPException):
                pass
            else:
                raise AssertionError('fault install acknowledged')
        (self.i.control/'pause-install').unlink()
        self.i.docker('start',self.i.service);self.i.start_service();self.wait()
        listing=self.request('GET',path)[1]
        assert oid not in [x['object'] for x in listing['objects']]
        self.expect('kill-retry','PUT',path+'/objects/'+oid,200,{'object':oid,'size':len(data),'ready':True},raw=data)
        self.observations.append({'case':'kill-before-ready','stored_bytes_verified':True,'unacknowledged_until_retry':True})

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--image',default='magus-fs2-task1');ap.add_argument('--skip-build',action='store_true');args=ap.parse_args()
    infra=OwnedInfra(Path(args.output));status=1
    try:
        infra.preflight()
        source=capture(infra)
        infra.run(['cargo','+stable','fmt','--all','--check'],timeout=60)
        infra.run(['cargo','+stable','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings'],timeout=300)
        infra.run(['cargo','+stable','test','--locked','--workspace','--all-features'],timeout=300)
        infra.run(['cargo','+stable','build','--locked','-p','magus-fs-service'],timeout=300)
        if not args.skip_build:
            infra.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=1','-t',args.image,'.',timeout=900)
        infra.setup(args.image);verify_image(infra,source);Journey(infra).run();status=0
    except InfrastructureUnavailable as e:
        infra.write_json('failure.json',{'classification':'blocked','reason':str(e)});status=2
    except Exception as e:
        if hasattr(infra,'service'):
            infra.docker('exec',infra.service,'cat','/tmp/service.log',check=False)
        infra.write_json('failure.json',{'classification':'failed','type':type(e).__name__,'reason':str(e),'trace':traceback.format_exc()});status=1
    finally:
        try:
            infra.cleanup()
        except Exception:
            status=1
        infra.write_json('result.json',{'status':status,'scope':'FS2-A Task1 local backend qualification; not Infomaniak'})
    print(json.dumps({'status':status,'output':str(infra.output)}))
    return status
if __name__=='__main__':
    sys.exit(main())
