#!/usr/bin/env python3
"""Finite package installs, real native client I/O and default PG/S3 service startup."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import traceback
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from package import install,load_manifest,sha,canonical_sha,source_manifest,PLATFORMS
from common import PhaseInfra,InfrastructureUnavailable


def validate_packaging(m):
    failures=[]
    if not re.fullmatch('[a-f0-9]{64}',m.get('manifest_sha256','')):failures.append('missing package manifest digest')
    if m.get('interrupted_prefix_retained') is not True:failures.append('missing interrupted install/retry proof')
    for platform_name in PLATFORMS:
        for attempt in (1,2):
            rows=[r for r in m.get('installs',[]) if r.get('platform')==platform_name and r.get('attempt')==attempt]
            if len(rows)!=1:failures.append('missing native package attempt: '+platform_name+'/'+str(attempt));continue
            r=rows[0]
            if not (all(r.get(k) is True for k in ('kernel_mounted','normal_unmount','owner_stopped','state_preserved','prefix_removed')) and r.get('read_sha256')==r.get('expected_sha256') and r.get('write_sha256')==r.get('written_sha256') and all(re.fullmatch('[a-f0-9]{64}',r.get(k,'')) for k in ('binary_sha256','read_sha256','write_sha256')) and r.get('provenance')):failures.append('incomplete native package proof: '+platform_name+'/'+str(attempt))
    s=m.get('service',{})
    if not (s.get('default_binary') is True and s.get('health')==200 and s.get('stopped') is True and re.fullmatch('[a-f0-9]{64}',s.get('sha256','')) and s.get('provenance')):failures.append('missing packaged default service proof')
    return failures



def packaging_assertions(measurements,evidence,manifest_path,interruption_evidence=None):
    """Derive shared assertions from recorded native/service/extraction outcomes."""
    from qualification import PACKAGING_CASES
    evidence=Path(evidence);manifest_path=Path(manifest_path)
    manifest=json.loads(manifest_path.read_text());rows=[]
    def raw(path):return json.loads(path.read_text())
    def add(case,passed,paths):
        rows.append({'case':case,'acceptance':PACKAGING_CASES[case],'expected':True,
            'observed':bool(passed),'passed':bool(passed),
            'provenance':[{'path':str(p.resolve()),'sha256':sha(p.read_bytes())} for p in paths]})
    for platform_name in PLATFORMS:
        binary=next(r['binary_sha256'] for r in manifest['packages'] if r['role']=='client' and r['platform']==platform_name)
        for attempt in (1,2):
            matches=[r for r in measurements['installs'] if r['platform']==platform_name and r['attempt']==attempt]
            assert len(matches)==1,'native assertion identity missing/duplicate'
            path=evidence/matches[0]['provenance'];r=raw(path)
            verified=(all(r.get(k) is True for k in ('kernel_mounted','normal_unmount','owner_stopped','state_preserved','prefix_removed'))
                and r.get('binary_sha256')==binary and r.get('read_sha256')==r.get('expected_sha256')
                and r.get('write_sha256')==r.get('written_sha256')
                and all(re.fullmatch('[a-f0-9]{64}',r.get(k,'')) for k in ('read_sha256','write_sha256')))
            add('native-'+platform_name+'-'+str(attempt),verified,[path,manifest_path])
    path=evidence/measurements['service']['provenance'];r=raw(path)
    binary=next(r['binary_sha256'] for r in manifest['packages'] if r['role']=='service' and r['platform']==PLATFORMS[1])
    add('default-service',r.get('default_binary') is True and r.get('sha256')==binary and r.get('health')==200
        and r.get('stopped') is True and r.get('executable')=='/opt/package-service/bin/magus-fs-service',[path,manifest_path])
    license_path=evidence/'interrupted/LICENSE'
    interrupted=Path(interruption_evidence) if interruption_evidence is not None else evidence/'interrupted-install.json'
    observation=raw(interrupted);observation=observation.get('measurements',observation)
    add('interrupted-install',observation.get('interrupted_prefix_retained') is True and observation.get('interrupted_error')=='simulated extraction interruption after LICENSE'
        and license_path.is_file() and sha(license_path.read_bytes())==manifest['licenses']['LICENSE']
        and not (evidence/'interrupted/THIRD_PARTY_NOTICES.md').exists()
        and all(r['passed'] for r in rows if r['case'].startswith('native-')),
        [interrupted,license_path,manifest_path])
    cleanup=evidence/'cleanup.json';r=raw(cleanup)
    add('package-evidence',sha(manifest_path.read_bytes())==measurements['manifest_sha256']
        and all(r.get(k) is True for k in ('ok','mounts_absent','resources_removed')),[cleanup,manifest_path])
    return rows

def native_helpers():
    before=list(sys.path)
    try:
        sys.path.insert(0,str(ROOT/'tests/fs0'))
        from resources import OwnedOutput
        spec=importlib.util.spec_from_file_location('package_mac_lifecycle',ROOT/'tests/fs0/macos_run.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        sys.path.insert(0,str(ROOT/'tests/fs1'));import macos_wire
        return OwnedOutput,m,macos_wire
    finally:sys.path[:]=before


def native_mac(prefix,output):
    """Use qualified normal-unmount guard; retain helpers if cleanup is unresolved."""
    OwnedOutput,m,macos_wire=native_helpers()
    macos_wire.BIN=prefix/'bin/magus-fs'
    owned=OwnedOutput(output);guard=m.MountGuard(owned);fixture=None;row={'binary_sha256':sha(macos_wire.BIN.read_bytes()),'commands':[]};mount=output/'view'
    def save():(output/'native.json').write_text(json.dumps(row,indent=2)+'\n')
    def cmd(argv,label,timeout=30,mountpoint=None):
        r=m.command(argv,output/(label+'.log'),timeout,owned=owned,guard=guard,mountpoint=mountpoint);row['commands'].append(r);save();assert r.get('returncode')==0,r;return r
    try:
        fixture=macos_wire.Fixture(output);guard.candidate(mount)
        owner,rpc,info=fixture.endpoint();owned.own_process(owner);row['owner_pid']=owner.pid;row['endpoint']=info;save()
        cmd(info['mount_command'],'mount',mountpoint=mount);assert m.mount_state(mount) is True;row['kernel_mounted']=True
        code="import hashlib,json,os,sys;from pathlib import Path;p=Path(sys.argv[1]);old=(p/'binary').read_bytes();body=b'packaged native write';f=open(p/'package-write','wb');f.write(body);f.flush();os.fsync(f.fileno());f.close();print(json.dumps({'read_sha256':hashlib.sha256(old).hexdigest(),'write_sha256':hashlib.sha256((p/'package-write').read_bytes()).hexdigest()}))"
        r=cmd([sys.executable,'-c',code,str(mount)],'ordinary-io');row.update(json.loads(Path(r['log']).read_text()));row.update(expected_sha256=sha(bytes(range(256))*2400),written_sha256=sha(b'packaged native write'),ordinary_uid=os.getuid())
        # State is outside installation; remove only this freshly verified prefix while owner lives.
        assert (output/'lazy/journal.sqlite').is_file();shutil.rmtree(prefix);row['prefix_removed']=not prefix.exists()
        r=cmd([sys.executable,'-c',"from pathlib import Path;import sys;assert Path(sys.argv[1]).read_bytes()==b'packaged native write'",str(mount/'package-write')],'read-after-remove');row['state_preserved']=(output/'lazy/journal.sqlite').is_file();save()
    finally:
        try:
            if m.mount_state(mount) is True:cmd(['/sbin/umount',str(mount)],'normal-unmount',timeout=10)
            row['normal_unmount']=m.mount_state(mount) is False
            if not guard.safe():raise RuntimeError('native helpers retained: unresolved mount/workload')
            if fixture:fixture.close()
            errors=owned.cleanup(remove_output=False);assert not errors,errors
            row['owner_stopped']=all(p.poll() is not None for p in owned.processes);save()
        except BaseException:
            row['cleanup_error']=traceback.format_exc();save();raise
    return row


def copy_prefix(i,container,prefix,dest,binary):
    i.docker('cp',str(prefix),container+':'+dest)
    i.docker('exec',container,'python3','-c',"import os,sys;path='/usr/local/bin/'+sys.argv[1];os.unlink(path);os.symlink(sys.argv[2]+'/bin/'+sys.argv[1],path)",binary,dest)


def linux_attempt(i,j,prefix,attempt):
    from common import RecordedLazy
    ep=RecordedLazy(j,'package'+str(attempt));name='package';row={'attempt':attempt,'platform':PLATFORMS[1],'provenance':'linux-'+str(attempt)+'.json'}
    try:
        copy_prefix(i,ep.daemon,prefix,'/opt/package','magus-fs');started=ep.start(name,publication='isolated');row['pid']=started['pid']
        identity=ep.execute("import json,hashlib,os,sys;pid=json.load(sys.stdin);p='/proc/'+str(pid)+'/exe';print(json.dumps({'path':os.readlink(p),'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest(),'kernel_mounted':os.path.ismount('/shared/package')}))",started['pid'])
        assert identity['path']=='/opt/package/bin/magus-fs';assert identity['sha256']==sha((prefix/'bin/magus-fs').read_bytes());row.update(binary_sha256=identity['sha256'],kernel_mounted=identity['kernel_mounted'],executable=identity['path'])
        row.update(ep.execute("import json,hashlib,os;from pathlib import Path;p=Path('/shared/package');body=b'packaged Linux write';old=(p/'initial').read_bytes();f=open(p/'written','wb');f.write(body);f.flush();os.fsync(f.fileno());f.close();print(json.dumps({'read_sha256':hashlib.sha256(old).hexdigest(),'write_sha256':hashlib.sha256((p/'written').read_bytes()).hexdigest(),'ordinary_uid':os.getuid()}))",user='1001:1001'))
        row.update(expected_sha256=sha(b'packaged initial'),written_sha256=sha(b'packaged Linux write'))
        row.update(ep.execute("import json,shutil;from pathlib import Path;assert Path('/private/package/state/journal.sqlite').is_file();shutil.rmtree('/opt/package');assert Path('/shared/package/written').read_bytes()==b'packaged Linux write';print(json.dumps({'prefix_removed':not Path('/opt/package').exists(),'state_preserved':Path('/private/package/state/journal.sqlite').is_file()}))"))
    finally:
        i.write_json('linux-'+str(attempt)+'.json',row)
        ep.cleanup();cleanup=json.loads((i.output/(ep.label+'-mount-cleanup.json')).read_text());row['normal_unmount']=all(r['unmount']==0 and not r['still_mounted'] for r in cleanup);row['owner_stopped']=all(r['exited'] and r['reaped'] for r in cleanup);i.write_json('linux-'+str(attempt)+'.json',row)
    return row


def initialize_service(i,image):
    # Provisioning opens/migrates PostgreSQL too. Serialize it before serve,
    # matching the established service fixtures rather than racing two opens.
    from service_protocol import Journey
    from scale import owner_record
    j=Journey(i);j.image=image
    owner=owner_record(j.tree_root,set(j.tokens.values()),int(time.time()))
    j.tokens['alice']=owner['token']
    i.provision([owner])
    i.start_service();j.wait()
    return j


def run(manifest_path,output):
    m=load_manifest(manifest_path);output=Path(output);output.mkdir(mode=0o700)
    result={'schema':1,'phase':'packaging','status':'failed','failures':[],'blocked':[],'assertions':[],'measurements':{'manifest_sha256':sha(Path(manifest_path).read_bytes()),'installs':[]},'cleanup':{'ok':True,'mounts_absent':True,'resources_removed':True,'provenance':['cleanup.json']}}
    measurements=result['measurements'];i=None;linux_clean=True;mac_clean=True;started=time.monotonic()
    def save():(output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    save()
    try:
        if platform.system()!='Darwin' or platform.machine()!='arm64':raise InfrastructureUnavailable('packaging phase requires qualified ARM64 Mac host plus Linux ARM64 Docker fixture')
        current=source_manifest();result['source']={'verified':True,'head':m['source']['head'],'manifest_sha256':canonical_sha(current),'bridge':'package-source-bridge.json'}
        (output/'package-source-bridge.json').write_text(json.dumps({'package_manifest':str(Path(manifest_path).resolve()),'package_sha256':measurements['manifest_sha256'],'current':current,'package_source':m['source'],'differences':{n:{'package':m['source']['manifest'].get(n),'current':current.get(n)} for n in sorted(set(current)|set(m['source']['manifest'])) if current.get(n)!=m['source']['manifest'].get(n)}},indent=2)+'\n')
        # No unreviewed source change may be called execution of the packaged source.
        assert current==m['source']['manifest'],'package source differs from current harness; repackage without rebuilding unchanged runtime'
        image=m['builds']['linux']['image'];result['binaries']={'verified':True,'image':image,'sha256':{Path(r['binary']).name:r['binary_sha256'] for r in m['packages'] if r['platform']==PLATFORMS[1]}}
        # Fault injection is confined to extraction failure, never a runtime success proof.
        from unittest.mock import patch
        interrupted=output/'interrupted';original_open=Path.open
        def interrupted_open(path,*args,**kwargs):
            if path==interrupted/'THIRD_PARTY_NOTICES.md':raise InterruptedError('simulated extraction interruption after LICENSE')
            return original_open(path,*args,**kwargs)
        with patch.object(Path,'open',interrupted_open):
            try:install(manifest_path,PLATFORMS[0],'client',interrupted);raise AssertionError('interruption did not occur')
            except InterruptedError as error:measurements['interrupted_error']=str(error)
        try:install(manifest_path,PLATFORMS[0],'client',interrupted);raise AssertionError('existing prefix overwritten')
        except FileExistsError:pass
        measurements['interrupted_prefix_retained']=sha((interrupted/'LICENSE').read_bytes())==m['licenses']['LICENSE'];save()
        (output/'interrupted-install.json').write_text(json.dumps({k:measurements[k] for k in ('interrupted_error','interrupted_prefix_retained')},indent=2)+'\n')
        for attempt in (1,2):
            prefix=output/('mac-install-'+str(attempt));install(manifest_path,PLATFORMS[0],'client',prefix);mac_clean=False
            row=native_mac(prefix,output/('mac'+str(attempt)));mac_clean=True;row.update(platform=PLATFORMS[0],attempt=attempt,provenance='mac'+str(attempt)+'/native.json');measurements['installs'].append(row);save()
        i=PhaseInfra(output/'linux');i.setup(image)
        service_prefix=output/'service-install';service_row=install(manifest_path,PLATFORMS[1],'service',service_prefix);copy_prefix(i,i.service,service_prefix,'/opt/package-service','magus-fs-service')
        from service_protocol import Journey,file_entry,GROUP,REPLICA
        from service_storage import ALICE,NS
        j=initialize_service(i,image)
        entry=file_entry('initial',j.tree_root['id'],b'packaged initial');upload,rid=j.stage(j.descriptor([entry]),bodies=[b'packaged initial']);j.expect('seed','POST',j.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        ident=json.loads(i.docker('exec',i.service,'python3','-c',"import os,json,hashlib;pid=open('/tmp/service.pid').read().strip();p='/proc/'+pid+'/exe';print(json.dumps({'path':os.readlink(p),'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}))").stdout)
        assert ident['path']=='/opt/package-service/bin/magus-fs-service' and ident['sha256']==service_row['binary_sha256'];measurements['service']={'default_binary':True,'sha256':ident['sha256'],'health':j.request('GET','/health')[0],'stopped':False,'provenance':'linux/service.json','executable':ident['path']};i.write_json('service.json',measurements['service']);save()
        for attempt in (1,2):
            assert time.monotonic()-started<600,'predeclared package phase ceiling600s'
            prefix=output/('linux-install-'+str(attempt));install(manifest_path,PLATFORMS[1],'client',prefix);linux_clean=False
            row=linux_attempt(i,j,prefix,attempt);linux_clean=True;row['provenance']='linux/'+row['provenance'];measurements['installs'].append(row);save()
        i.docker('exec',i.service,'python3','-c',"import os,signal,time;from pathlib import Path;pid=int(Path('/tmp/service.pid').read_text());os.kill(pid,signal.SIGTERM);end=time.monotonic()+10\nwhile Path('/proc/'+str(pid)).exists():\n assert time.monotonic()<end,'service stop deadline';time.sleep(.05)")
        measurements['service']['stopped']=True;i.write_json('service.json',measurements['service'])
        result['failures'].extend(validate_packaging(measurements))
    except InfrastructureUnavailable as error:result['blocked'].append(str(error))
    except BaseException as error:result['failures'].append(type(error).__name__+': '+str(error));(output/'failure.log').write_text(traceback.format_exc())
    finally:
        try:
            if not mac_clean or not linux_clean:raise RuntimeError('mount cleanup unresolved; helpers retained')
            if i:
                if hasattr(i,'service'):
                    logs=i.docker('exec',i.service,'cat','/tmp/service.log',check=False,evidence=False)
                    (i.output/'service.log').write_text(logs.stdout+logs.stderr)
                i.cleanup()
        except BaseException as error:result['failures'].append('cleanup: '+str(error));result['cleanup'].update(ok=False,mounts_absent=False,resources_removed=False)
        result['elapsed_seconds']=time.monotonic()-started
        result['status']='failed' if result['failures'] else 'blocked' if result['blocked'] else 'passed'
        (output/'cleanup.json').write_text(json.dumps(result['cleanup'],indent=2)+'\n');save()
    if result['status']=='passed':
        try:result['assertions']=packaging_assertions(measurements,output,manifest_path)
        except Exception as error:
            result['status']='failed';result['failures'].append('assertion derivation: '+str(error))
    from qualification import normalize
    result=normalize(result);save();return {'passed':0,'failed':1,'blocked':2}[result['status']]

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package-manifest',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    if not a.output.is_absolute():p.error('new absolute output required')
    sys.exit(run(a.package_manifest,a.output))
