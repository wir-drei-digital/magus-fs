#!/usr/bin/env python3
"""Narrow real client resume gate for the bounded upload-list response exception."""
import argparse,hashlib,json,os,secrets,shutil,sys,time,traceback
from pathlib import Path
from client_protocol import Journey
from infra import OwnedInfra,InfrastructureUnavailable,ROOT
from provenance import capture,verify_image
from service_protocol import identity,GROUP,REPLICA,WORKER
from service_storage import NS,ALICE,object_id

class ListingJourney(Journey):
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':448,'content':{'kind':'directory'}}
        upload,rid=self.stage(self.descriptor([reports]))
        self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        code,delegated=self.request('POST',self.root+'/grants',body={'delegate':{'replica':WORKER,'expires':int(time.time())+1800,'actions':['read','write','history'],'branches':['main'],'prefixes':['reports']}});assert code==200
        self.tokens['worker']=delegated['token']
        state,profile=self.client('listing');binding=self.attach(state,profile)['binding']
        content='completed required chunk';revision=self.checkpoint(state,content);self.queued(state,revision)
        _,before=self.kill_at(state,revision,'sync-upload-created')
        assert before['state']=='Preparing' and not before['remote_outcome_unknown'] and before['request']['original_head']==binding['view']['head']
        path=self.root+'/uploads/'+before['request']['upload']
        bodies=[content.encode()]+[n.to_bytes(8,'little') for n in range(800)]
        for body in bodies:
            status,value=self.request('PUT',path+'/objects/'+object_id(body),actor='worker',raw=body);assert status==200,(status,value)
        status,encoded=self.bytes_request(path);listing=json.loads(encoded)
        assert status==200 and 64*1024<len(encoded)<=512*1024 and len(listing['objects'])==801
        resumed=self.cli('sync','run','--state',state);after=resumed['progress']
        assert after['state']=='PrivateRemote' and after['request']==before['request'] and after['request_digest']==before['request_digest']
        assert resumed['counters']['uploaded_body_bytes']==0 and resumed['counters']['logical_unique_upload_bytes']==0 and resumed['counters']['requests']==3,resumed
        self.i.write_json('upload-listing.json',{'response_bytes':len(encoded),'response_sha256':hashlib.sha256(encoded).hexdigest(),'completed_objects':len(listing['objects']),'staged_body_bytes':sum(map(len,bodies)),'required_object':object_id(content.encode()),'before':before,'resumed':resumed})
        assert self.i.sql("SELECT count(*) FROM operations WHERE operation='"+after['operation']+"';")=='1'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--image',default='magus-fs2-task3-listing');args=parser.parse_args()
    i=OwnedInfra(Path(args.output));status=1;j=None
    try:
        i.preflight();source=capture(i)
        i.run(['python3','-m','unittest','discover','-s','tests/fs2','-p','test_*.py'],timeout=60)
        i.run(['cargo','+stable','fmt','--all','--check'],timeout=60)
        i.run(['cargo','+stable','clippy','--locked','-p','magus-fs','--all-targets','--all-features','--','-D','warnings'],timeout=300)
        i.run(['cargo','+stable','test','--locked','-p','magus-fs','--all-targets','--all-features'],timeout=300)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--features','test-faults'],timeout=300)
        shutil.copyfile(ROOT/'target/debug/magus-fs',ROOT/'target/debug/magus-fs-client-faults');os.chmod(ROOT/'target/debug/magus-fs-client-faults',0o755)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','--examples'],timeout=300)
        i.run(['cargo','+stable','build','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
        i.docker('build','-f','tests/fs2/Dockerfile.linux','--build-arg','VERIFY=client','-t',args.image,'.',timeout=900)
        i.setup(args.image);verify_image(i,source)
        binaries={}
        for name,local in [('magus-fs','magus-fs'),('magus-fs-client-faults','magus-fs-client-faults'),('client_probe','examples/client_probe')]:
            binaries[name]={'host':hashlib.sha256((ROOT/'target/debug'/local).read_bytes()).hexdigest(),'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+name).stdout.split()[0]}
        i.write_json('client-binaries.json',binaries)
        j=ListingJourney(i);start=time.monotonic();j.run();elapsed=time.monotonic()-start;assert elapsed<600
        i.write_json('journey-duration.json',{'seconds':elapsed,'limit':600});status=0
    except InfrastructureUnavailable as e:i.write_json('failure.json',{'classification':'blocked','reason':str(e)});status=2
    except Exception as e:i.write_json('failure.json',{'classification':'failed','reason':str(e),'trace':traceback.format_exc()})
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e)});status=1
        i.write_json('result.json',{'status':status,'scope':'Task3 route-specific bounded upload-list resume; no native applied claim'})
    print(json.dumps({'status':status,'output':str(i.output)}));return status
if __name__=='__main__':sys.exit(main())
