#!/usr/bin/env python3
"""Deterministic actual FUSE LOOKUP/adopt/OPEN race, including held-FD semantics."""
import argparse,hashlib,json,os,secrets,shutil,sys,time,traceback
from pathlib import Path
from infra import OwnedInfra,ROOT
from provenance import capture,verify_image
from full_native import NativeJourney
from connected import Lazy
from service_protocol import GROUP,REPLICA,identity,file_entry
from service_storage import NS,ALICE

class Race(NativeJourney):
    def __init__(self,i,image):super().__init__(i,image,['linux']);self.lazy=None;self.records=[]
    def run(self):
        self.i.start_service();self.wait()
        authority={'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':False}
        self.i.provision([{'namespace':NS,'principal':ALICE,'replica':REPLICA,'token':secrets.token_hex(32),'expires':int(time.time())+3600,'actions':['admin','read','write','integrate','history'],'branches':['main'],'prefixes':[''],'authority':authority,'root_policy':self.tree_root}])
        reports={'path':'reports','id':identity('entry'),'parent':self.tree_root['id'],'owner':ALICE,'group':GROUP,'mode':0o755,'content':{'kind':'directory'}}
        old=b'original held bytes';upload,rid=self.stage(self.descriptor([reports,file_entry('reports/live',reports['id'],old)]),bodies=[old]);self.expect('seed','POST',self.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        self.lazy=Lazy(self);l=self.lazy;l.start('live',drop=True,lookup_barrier=True)
        for held in [True,False]:
            before=l.status();base='/private/live/lookup-epoch';tag='/tmp/epoch-'+str(held)
            if held:
                code="import os,json,time,errno;fd=os.open('/shared/live/reports/live',os.O_RDWR);body=os.pread(fd,1000,0);before=os.fstat(fd);open('"+tag+"-held-ready','w').close();deadline=time.monotonic()+30\nwhile not os.path.exists('"+tag+"-held-go'):\n assert time.monotonic()<deadline\n time.sleep(.02)\nafter=os.fstat(fd);rows={'old':body.hex(),'held':os.pread(fd,1000,0).hex(),'old_size':before.st_size,'held_size':after.st_size}\ntry:os.pwrite(fd,b'no',0);rows['write_errno']=0\nexcept OSError as e:rows['write_errno']=e.errno\nos.close(fd);open('"+tag+"-held-result','w').write(json.dumps(rows))"
                l.holders.append(l.execute("import json,subprocess,sys;code=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code],stdout=open('"+tag+"-held-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",code,user='1001:1001'))
                self.until(lambda:l.execute("import os,json;print(json.dumps(os.path.exists('"+tag+"-held-ready')))"))
            l.execute("import os,json\nfor suffix in ['hit','release','arm']:\n try:os.unlink('"+base+".'+suffix)\n except FileNotFoundError:pass\nopen('"+base+".arm','w').close();print('{}')")
            reader="import json,os\ntry:\n body=open('/shared/live/reports/live','rb').read();out={'errno':0,'body':body.hex()}\nexcept OSError as e:out={'errno':e.errno}\nopen('"+tag+"-new-result','w').write(json.dumps(out))"
            l.holders.append(l.execute("import json,subprocess,sys;code=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code],stdout=open('"+tag+"-new-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",reader,user='1001:1001'));self.i.write_json('lookup-holder-ownership.json',l.holders)
            self.until(lambda:l.execute("import json,os;print(json.dumps(os.path.exists('"+base+".hit')))"),5)
            incoming=('new accepted epoch '+str(held)).encode();shared=self.publish(incoming)
            self.until(lambda:l.status()['live']['epoch']>before['live']['epoch'],5)
            during=l.status();assert during['status']['binding']['view']['head']==shared['head']
            l.execute("import json;open('"+base+".release','w').close();print('{}')")
            self.until(lambda:l.execute("import json,os;print(json.dumps(os.path.exists('"+tag+"-new-result')))"),5)
            result=l.execute("print(open('"+tag+"-new-result').read())")
            if held:
                l.execute("import json;open('"+tag+"-held-go','w').close();print('{}')")
                self.until(lambda:l.execute("import json,os;print(json.dumps(os.path.exists('"+tag+"-held-result')))"),5)
                kept=l.execute("print(open('"+tag+"-held-result').read())");assert kept['held']==old.hex() and kept['held_size']==len(old) and kept['write_errno']==116
            else:kept=None
            record={'held':held,'before':before,'during':during,'shared':shared,'single_open_result':result,'expected_body':incoming.hex(),'held_result':kept,'application_retries':0};self.records.append(record);self.i.write_json('lookup-epoch-evidence.json',self.records)
            assert result['errno']==0 and result['body']==incoming.hex(),record
            self.until(lambda:l.status()['live']['applied'],5);old=incoming
    def cleanup(self):
        if self.lazy:
            self.lazy.execute("import json;open('/private/live/lookup-epoch.release','w').close();print('{}')")
            self.i.write_json('lookup-daemon.log.json',self.lazy.execute("import json;print(json.dumps(open('/private/live/daemon.log').read()))"));self.lazy.cleanup()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);ap.add_argument('--image');a=ap.parse_args();i=OwnedInfra(a.output);j=None;code=1
    try:
        source=capture(i);image=a.image or i.owner+'-epoch';i.write_json('image-ownership.json',{'tag':image,'intent':'retained epoch-boundary regression image'})
        if not a.image:
            i.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service','--features','test-faults'],timeout=300)
            for name in ['magus-fs','magus-fs-service']:
                dest='magus-fs-client-faults' if name=='magus-fs' else name+'-faults';shutil.copyfile(ROOT/'target/release'/name,ROOT/'target/release'/dest);os.chmod(ROOT/'target/release'/dest,0o755)
            i.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
            i.docker('build','--pull=false','-f','tests/fs2/Dockerfile.linux','--build-arg','BUILD_PROFILE=release','--build-arg','BIN_DIR=release','--build-arg','VERIFY=0','-t',image,'.',timeout=900)
        i.setup(image);verify_image(i,source,host_profile='release');j=Race(i,image);j.run();verify_image(i,source,host_profile='release');code=0
    except Exception as e:i.write_json('failure.json',{'reason':str(e),'trace':traceback.format_exc()})
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json',{'reason':str(e),'helpers_retained':True});code=1
        i.write_json('result.json',{'exit':code,'scope':'actual Linux lookup/epoch/open boundary','records':j.records if j else []})
    print(json.dumps({'exit':code,'output':str(i.output)}));return code
if __name__=='__main__':sys.exit(main())
