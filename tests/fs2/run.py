#!/usr/bin/env python3
"""Source-matched twice-fresh connected FS2-A slice. 0 verified, 1 failed, 2 blocked."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, sources, verify_image
from connected import Connected
from qualification import normalize


def inspect_cleanup(i,j):
    rows={kind:i.docker(kind,'ls',*(['-a'] if kind=='container' else []),'--format','{{.Names}}' if kind=='container' else '{{.Name}}',evidence=False).stdout.splitlines() for kind in ['container','network','volume']}
    remaining=[r['name'] for r in i.resources if r['name'] in rows[r['kind']]]
    pids=[]
    for ep in j.endpoints:
        if ep.platform=='macos':
            for c in ep.clients:
                pid=c.get('pid') or c.get('stopped_pid')
                if pid:
                    try:os.kill(pid,0)
                    except ProcessLookupError:pass
                    else:pids.append(pid)
    if j.lazy:
        mount_rows=json.loads((i.output/'mount-cleanup.json').read_text())
        assert len(mount_rows)==len(j.lazy.mounts)
    else:
        mount_rows=[]
        i.write_json('mount-cleanup.json',{'no_mount_created':True,'owned_mounts':[]})
    unresolved=[r['mount'] for r in mount_rows if r.get('still_mounted') is not False or r.get('exited') is not True or r.get('reaped') is not True or r.get('created') is True and r.get('unmount')!=0]
    assert (not j.lazy or mount_rows) and not remaining and not pids and not unresolved and all(r.get('removed') is True for r in i.resources)
    return {'verified':True,'mounts':unresolved,'pids':pids,'containers':remaining,'resources_removed':True,'independent_lists':rows,'normal_unmount_rows':mount_rows,'retained_host_fixture':str(i.output/'mac')}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--slice',choices=['connected'],default='connected');ap.add_argument('--platform',choices=['all','macos','linux'],default='all');ap.add_argument('--output',type=Path,required=True);ap.add_argument('--probe',action='store_true');ap.add_argument('--reuse-image');a=ap.parse_args()
    if not a.output.is_absolute() or a.output.exists() or not a.output.parent.is_dir():ap.error('--output must be absolute, new, with existing parent')
    output=a.output;build=OwnedInfra(output);data={'platform':a.platform,'failures':[],'blocked':[],'journeys':[],'source':{},'probe':a.probe};image=a.reuse_image or build.owner+'-connected';code=1
    try:
        if a.platform!='all':raise InfrastructureUnavailable('connected slice requires both macOS full and Linux lazy')
        if sys.platform!='darwin':raise InfrastructureUnavailable('native macOS host required')
        if os.environ.get('RUSTFLAGS') or any(k.startswith('CARGO_PROFILE_RELEASE_') for k in os.environ):raise InfrastructureUnavailable('qualification requires default release profile without inherited override flags')
        build.preflight();source=capture(build);source["build_profile"]={"runtime":"release","checks":"debug","flags":"cargo --release; default release optimization, no RUSTFLAGS"};checks={}
        if not a.reuse_image:
            if not a.probe:
                for label,argv in [('fmt',['cargo','+stable','fmt','--all','--check']),('clippy',['cargo','+stable','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings']),('host',['cargo','+stable','test','--locked','--workspace','--all-features']),('python',[sys.executable,'-m','unittest','discover','-s','tests/fs2','-p','test_*.py'])]:
                    build.run(argv,timeout=600);checks[label]=0
            build.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service','--features','test-faults'],timeout=300);shutil.copyfile(ROOT/'target/release/magus-fs',ROOT/'target/release/magus-fs-client-faults');os.chmod(ROOT/'target/release/magus-fs-client-faults',0o755);shutil.copyfile(ROOT/'target/release/magus-fs-service',ROOT/'target/release/magus-fs-service-faults');os.chmod(ROOT/'target/release/magus-fs-service-faults',0o755)
            build.run(['cargo','+stable','build','--release','--locked','-p','magus-fs','-p','magus-fs-service'],timeout=300)
            build.write_json('image-ownership.json',{'tag':image,'intent':'retained source-matched connected qualification image'})
            build.docker('build','--pull=false','--progress=plain','-f','tests/fs2/Dockerfile.linux','--build-arg','BUILD_PROFILE=release','--build-arg','BIN_DIR=release','--build-arg','VERIFY='+('0' if a.probe else '1'),'--label','magus.fs2.owner='+build.owner,'-t',image,'.',timeout=1200)
            if not a.probe:checks['linux']=0
        elif not a.probe:raise ValueError('--reuse-image permitted only for focused probes; final always checks/builds fresh')
        data['source']={**source,'matched':False,'checks':checks,'host_binary':hashlib.sha256((ROOT/'target/release/magus-fs').read_bytes()).hexdigest(),'image':json.loads(build.docker('image','inspect',image).stdout)[0]['Id']}
        hook_names=[b'MAGUS_TEST_DROP_WSS_HINTS',b'test_drop_wss_hint',b'MAGUS_TEST_DROP_NATIVE_HINTS',b'fs2_transfer',b'MAGUS_TEST_TRANSFER_LOG',b'MAGUS_TEST_FAULT_POINT',b'test_drop_native_hint',b'MAGUS_TEST_LOOKUP_EPOCH_BARRIER',b'test_lookup_epoch_barrier']
        host_default=(ROOT/'target/release/magus-fs').read_bytes();host_service=(ROOT/'target/release/magus-fs-service').read_bytes();assert all(marker not in host_default and marker not in host_service for marker in hook_names)
        for number in range(1,2 if a.probe else 3):
            i=OwnedInfra(output/('journey-'+str(number)));j=None;safe_to_remove=False;started=time.monotonic()
            try:
                i.setup(image);verify_image(i,source,host_profile="release")
                image_labels=json.loads(i.docker('image','inspect',image).stdout)[0]['Config']['Labels'];assert image_labels['magus.fs2.build-profile']=='release'
                binaries={name:{'host':hashlib.sha256((ROOT/'target/release'/name).read_bytes()).hexdigest(),'linux':i.docker('exec',i.service,'sha256sum','/usr/local/bin/'+name).stdout.split()[0]} for name in ['magus-fs','magus-fs-client-faults','magus-fs-service','magus-fs-service-faults']};i.write_json('runtime-binaries.json',{'profile':'release','binaries':binaries,'image_labels':image_labels});data['source']['runtime_binaries']=binaries
                data['source']['linux_binary']=i.docker('exec',i.service,'sha256sum','/usr/local/bin/magus-fs').stdout.split()[0]
                absence=i.docker('exec',i.service,'python3','-c',"from pathlib import Path;markers="+repr(hook_names)+";assert all(m not in Path('/usr/local/bin/'+n).read_bytes() for m in markers for n in ['magus-fs','magus-fs-service']);print('default fault hook strings absent')").stdout.strip();data['source']['fault_hooks_absent_default']=absence=='default fault hook strings absent'
                j=Connected(i,image,number);j.probe=a.probe;j.run();assert time.monotonic()-started<=600
                verify_image(i,source,host_profile="release");j.result['duration_seconds']=time.monotonic()-started
            except Exception as error:
                failure={'journey':number,'reason':str(error),'trace':traceback.format_exc()};data['failures'].append(failure);i.write_json('failure.json',failure)
            finally:
                try:
                    if j:j.cleanup()
                    safe_to_remove=True;i.cleanup()
                    if j:j.result['cleanup']=inspect_cleanup(i,j);j.save_result();data['journeys'].append(j.result)
                except Exception as error:
                    failure={'journey':number,'cleanup':str(error),'helpers_retained':not safe_to_remove,'trace':traceback.format_exc()};data['failures'].append(failure);i.write_json('cleanup-failure.json',failure)
            build.write_json('evidence.json',data)
            if data['failures']:break
        assert sources()==source['sha256'];data['source']['matched']=True
        if a.probe:data['blocked'].append('focused probe intentionally omits repeat/save qualification')
    except InfrastructureUnavailable as error:data['blocked'].append(str(error))
    except Exception as error:data['failures'].append({'reason':str(error),'trace':traceback.format_exc()})
    finally:
        result=normalize(data);build.write_json('evidence.json',data);build.write_json('result.json',result);code=result['exit']
    print(json.dumps({'exit':code,'output':str(output),'scope':'FS2-A connected slice only','image':image}));return code
if __name__=='__main__':sys.exit(main())
