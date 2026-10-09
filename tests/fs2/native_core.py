#!/usr/bin/env python3
"""Independent Task5 native-Core API gate. This does NOT qualify the watcher/service journey."""
import argparse,hashlib,json,sys,traceback
from infra import OwnedInfra,InfrastructureUnavailable,ROOT
from provenance import capture,sources

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);args=ap.parse_args()
    i=OwnedInfra(args.output);result={'scope':'partial-native-core-only','passed':False,'cleanup':False};code=1
    try:
        i.preflight();before=capture(i)
        tag=i.owner+'-native-core';i.write_json('image-ownership.json',{'owner':i.owner,'tag':tag,'intent':'retained test image'})
        i.docker('build','-f','tests/fs2/Dockerfile.native-core','--label','magus.fs2.owner='+i.owner,'-t',tag,'.',timeout=1200)
        image=json.loads(i.docker('image','inspect',tag).stdout)[0];result['image']=image['Id'];i.write_json('image.json',image)
        container=i.create('container','native-core',['--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=1200m',image['Id']])
        p=i.docker('start','--attach',container,timeout=300,check=False);result['native_output']=p.stdout+p.stderr
        data=i.inspect('container',container);assert data['State']['ExitCode']==0,(data['State']['ExitCode'],p.stdout,p.stderr)
        image_source=i.output/'image-source';image_source.mkdir();i.docker('cp',container+':/src/.',str(image_source))
        actual={p:hashlib.sha256((image_source/p).read_bytes()).hexdigest() for p in before['sha256']}
        assert actual==before['sha256'] and sources()==before['sha256'],'source changed or image mismatch'
        i.docker('cp',container+':/out/native-tests',str(i.output/'native-tests'))
        result['binary_sha256']=hashlib.sha256((i.output/'native-tests').read_bytes()).hexdigest();result['source_files_verified']=len(actual)
        result['passed']=True;code=0
    except InfrastructureUnavailable as e:result['blocked']=str(e);code=2
    except Exception as e:result['error']=str(e);traceback.print_exc()
    finally:
        try:i.cleanup();result['cleanup']=True
        except Exception as e:result['cleanup_error']=str(e);code=1
        i.write_json('result.json',result)
    return code
if __name__=='__main__':sys.exit(main())
