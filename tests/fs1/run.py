#!/usr/bin/env python3
"""Build final inputs and execute two independent native FS1 journeys per OS."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from inventory import ROOT,digest,sources
from qualification import aggregate,normalize
from macos_supervisor import supervise,SupervisionFailure,_module
Interrupts=_module.Interrupts
sys.path.insert(0,str(ROOT/'tests/support'))
from publication import publish_result

def read(path):
    try:return json.loads(path.read_text())
    except (OSError,ValueError):return {}

def execute(argv,output,interrupts,seconds=600,grace=5):
    record={'argv':list(map(str,argv))}
    try:record['exit']=supervise(record['argv'],output,interrupts=interrupts,seconds=seconds,report_grace=grace)
    except SupervisionFailure as error:record.update(exit=1,supervision=error.supervision)
    except OSError as error:record.update(exit=2,error=repr(error))
    record['stdout']=str(output.with_name(output.name+'.runner.stdout'));record['stderr']=str(output.with_name(output.name+'.runner.stderr'))
    return record

def absent(platform,native,image,commands,output,interrupts):
    result={'verified':False,'remaining_mounts':[],'remaining_containers':[],'remaining_pids':[]}
    if platform=='macos':
        mounts=subprocess.run(['/sbin/mount','-t','nfs'],capture_output=True,text=True,timeout=5)
        result['mount_table']=mounts.stdout
        for value in native.get('mounts',{}).values():
            path=value.get('mountpoint')
            if path and ' on '+path+' (' in mounts.stdout:result['remaining_mounts'].append(path)
        for pid in native.get('owned_pids',[]):
            try:os.kill(pid,0)
            except ProcessLookupError:pass
            else:result['remaining_pids'].append(pid)
        result['verified']=bool(native.get('cleanup')) and mounts.returncode==0 and native.get('cleanup_errors')==[] and native.get('remaining_owned_resources')==[] and all(x.get('exit') is not None for x in native.get('reaped',[]))
    else:
        names=native.get('owned_containers',[])
        probe=subprocess.run(['docker','ps','-a','--format','{{.Names}}'],capture_output=True,text=True,timeout=10)
        result['remaining_containers']=[name for name in names if name in probe.stdout.splitlines()]
        vm=native.get('owned_vm_path')
        if vm:
            argv=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','-v','/tmp:/vm:ro',image,'python3','-c','from pathlib import Path; p=Path("/vm")/'+repr(Path(vm).name)+'; assert not p.exists(),str(p)']
            check=execute(argv,output/'vm-absence',interrupts,seconds=30);commands.append(check)
            result['vm_absence_exit']=check['exit']
        cleanup=native.get('cleanup',[])
        result['verified']=bool(names) and probe.returncode==0 and result.get('vm_absence_exit')==0 and bool(cleanup) and not native.get('cleanup_error') and native.get('remaining_owned_containers')=='' and all(not x.get('mounted_remaining') and all(y.get('returncode') is not None for y in x.get('reaped',[])) and all(y.get('returncode')==0 and y.get('still_mounted') is False for y in x.get('cleanup',[])) for x in cleanup)
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--platform',choices=['all','macos','linux'],default='all');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--image',default='magus-fs1-runtime');args=parser.parse_args()
    if not args.output.is_absolute() or args.output.exists() or not args.output.parent.is_dir():parser.error('--output must be an absolute new path with existing parent')
    output=args.output;output.mkdir();profiles=[];commands=[];blocked=[];failures=[]
    provenance={'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'dirty':subprocess.check_output(['git','status','--short'],cwd=ROOT,text=True),'source_hashes':sources()}
    (output/'source.json').write_text(json.dumps(provenance,indent=2)+'\n')
    image_info={};binary=ROOT/'target/fs1-default/debug/magus-fs';fault=ROOT/'target/fs1-fault/debug/magus-fs'
    with Interrupts() as interrupts:
        def command(argv,label,seconds=600):
            value=execute(argv,output/label,interrupts,seconds=seconds);commands.append(value)
            (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            if value['exit']:raise RuntimeError(label+' failed: '+str(value))
            return Path(value['stdout']).read_text()
        try:
            if args.platform!='all':blocked.append('complete acceptance requires --platform all')
            if sys.platform!='darwin' or not Path('/sbin/mount_nfs').exists() or not Path('/usr/bin/sandbox-exec').exists():blocked.append('native macOS NFS/Seatbelt prerequisites unavailable')
            if not shutil.which('docker'):blocked.append('Docker executable unavailable')
            else:
                probe=subprocess.run(['docker','info','--format','{{.ServerVersion}}'],capture_output=True,text=True,timeout=15)
                provenance['docker_probe']={'exit':probe.returncode,'stdout':probe.stdout,'stderr':probe.stderr}
                if probe.returncode:blocked.append('Docker daemon unavailable')
            if blocked:raise FileNotFoundError('; '.join(blocked))
            rust=command(['rustc','+stable','--version','--verbose'],'rustc',30)
            if not rust.startswith('rustc 1.92.0 '):blocked.append('Rust1.92.0 not available as configured stable alias');raise FileNotFoundError(blocked[-1])
            env=['env','RUSTUP_TOOLCHAIN=stable']
            command(env+['cargo','fmt','--all','--check'],'fmt')
            command(env+['cargo','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings'],'clippy')
            command(env+['cargo','test','--locked','--workspace','--all-features'],'rust-tests')
            for target,features in [('fs1-default',[]),('fs1-fault',['--features','test-faults'])]:
                command(env+['CARGO_TARGET_DIR='+str(ROOT/'target'/target),'cargo','build','--locked','-p','magus-fs',*features],'build-'+target)
            provenance.update(binary_sha256=digest(binary),fault_binary_sha256=digest(fault))
            command(['docker','build','--pull=false','--progress=plain','--build-arg','VERIFY=1','-f','tests/fs1/Dockerfile.linux','-t',args.image,'.'],'image-build',1200)
            provenance['image']=json.loads(command(['docker','image','inspect',args.image],'image-inspect',30))[0]['Id']
            observed=json.loads(command(['docker','run','--rm','--network','none',args.image,'python3','/src/tests/fs1/inventory.py','--sources'],'image-sources',30))
            assert observed==provenance['source_hashes'],'image source content mismatch'
            image_info=json.loads(command(['docker','run','--rm','--network','none',args.image,'python3','-c',"import hashlib,json;from pathlib import Path;print(json.dumps({n:hashlib.sha256(Path('/out',n).read_bytes()).hexdigest() for n in ['magus-fs','magus-fs-faults','fs1-retention']}))"],'image-binaries',30))
            provenance['image_binaries']=image_info
            os.environ['MAGUS_FS_BIN']=str(binary);os.environ['MAGUS_FS_FAULT_BIN']=str(fault)
            for journey in [1,2]:
                for platform in ['macos','linux']:
                    if interrupts.count:raise InterruptedError('coordinator interrupted')
                    folder=output/(platform+str(journey));folder.mkdir()
                    native_path=folder/'native'
                    argv=[sys.executable,str(ROOT/'tests/fs1'/('macos_run.py' if platform=='macos' else 'linux_run.py')),'--output',str(native_path)]
                    argv+=['--native'] if platform=='macos' else ['--image',args.image]
                    native_run=execute(argv,native_path,interrupts);commands.append(native_run)
                    native=read(native_path/'result.json')
                    if native_run['exit']!=0:
                        if native_run['exit']==2:blocked.append(platform+' native prerequisite blocked')
                        failures.append(platform+' native failed; see '+str(native_path))
                        profiles.append({'platform':platform,'journey':journey,'native':native,'execution':native_run})
                        raise RuntimeError(failures[-1])
                    cli_path=folder/'cli.json';container='fs1-combined-cli-'+uuid.uuid4().hex
                    if platform=='macos':argv=['env','MAGUS_FS_BIN='+str(fault),'MAGUS_TEST_FEATURES=test-faults',sys.executable,str(ROOT/'tests/fs1/inventory.py'),'--cli',str(cli_path)]
                    else:argv=['docker','run','--rm','--name',container,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,exec,mode=1777','--user','1001:1001','-e','MAGUS_FS_BIN=/out/magus-fs-faults','-e','MAGUS_TEST_FEATURES=test-faults',args.image,'sh','-c','python3 /src/tests/fs1/inventory.py --cli /tmp/cli.json; result=$?; cat /tmp/cli.json; exit "$result"']
                    cli_run=execute(argv,folder/'cli',interrupts);commands.append(cli_run)
                    if platform=='linux':cli_path.write_text(Path(cli_run['stdout']).read_text())
                    archive_path=folder/'archive'
                    archive_run=execute([sys.executable,str(ROOT/'tests/fs1/recovery_io.py'),'--output',str(archive_path),'--platform',platform,'--binary',str(binary),'--image',args.image],archive_path,interrupts);commands.append(archive_run)
                    retention_cmd=env+['cargo','test','--locked','-p','magus-fs-core','--test','qualification','--','--nocapture'] if platform=='macos' else ['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--tmpfs','/tmp:rw,mode=1777','--user','1001:1001',args.image,'/out/fs1-retention','--nocapture']
                    retention_run=execute(retention_cmd,folder/'retention',interrupts);commands.append(retention_run)
                    retention=next((json.loads(line.split('FS1_OBSERVATION ',1)[1]) for line in Path(retention_run['stdout']).read_text().splitlines() if 'FS1_OBSERVATION ' in line),{})
                    (folder/'retention.json').write_text(json.dumps(retention,indent=2)+'\n')
                    paths={'native':native_path/'result.json','cli':cli_path,'archive':archive_path/'result.json','retention':folder/'retention.json'}
                    expected_binary=provenance['binary_sha256'] if platform=='macos' else image_info['magus-fs']
                    expected_fault=provenance['fault_binary_sha256'] if platform=='macos' else image_info['magus-fs-faults']
                    native_binary=native.get('binary_sha256') if platform=='macos' else native.get('cleanup',[{}])[-1].get('binaries',{}).get('magus-fs')
                    native_fault=native.get('fault_binary_sha256') if platform=='macos' else native.get('cleanup',[{}])[-1].get('binaries',{}).get('magus-fs-faults')
                    assert native_binary==expected_binary and native_fault==expected_fault,'native binary provenance mismatch'
                    assert all(provenance['source_hashes'].get(name)==value for name,value in native.get('source_hashes',{}).items()),'native source provenance mismatch'
                    assert read(cli_path).get('source_hashes')==provenance['source_hashes'] and read(cli_path).get('binary_sha256')==expected_fault,'CLI provenance mismatch'
                    archive_report=read(paths['archive']);assert archive_report.get('platforms',{}).get(platform,{}).get('binary_sha256')==expected_binary,'archive binary provenance mismatch'
                    profile=normalize(platform,journey,native,read(cli_path),read(paths['archive']),retention,paths)
                    profile.update(source_hashes=provenance['source_hashes'],binary_sha256=provenance['binary_sha256'] if platform=='macos' else image_info['magus-fs'],fault_binary_sha256=provenance['fault_binary_sha256'] if platform=='macos' else image_info['magus-fs-faults'],image=provenance['image'] if platform=='linux' else None,native_exit=native_run['exit'],cli_exit=cli_run['exit'],archive_exit=archive_run['exit'],retention_exit=retention_run['exit'],interrupted=bool(interrupts.count),cleanup=absent(platform,native,args.image,commands,folder,interrupts))
                    # Independently inspect every disposable archive/CLI name after its own cleanup.
                    if platform=='linux':
                        archive_cleanup=read(archive_path/'linux/cleanup.json')
                        assert isinstance(archive_cleanup,list) and len(archive_cleanup)==2 and all(x.get('exit')==0 for x in archive_cleanup),'archive cleanup unverified'
                        names=[container]+[x['name'] for x in archive_cleanup]
                        probe=subprocess.run(['docker','ps','-a','--format','{{.Names}}'],capture_output=True,text=True,timeout=10)
                        profile['cleanup']['remaining_containers'] += [name for name in names if name in probe.stdout.splitlines()]
                        profile['cleanup']['verified'] &= probe.returncode==0
                    profiles.append(profile);(folder/'profile.json').write_text(json.dumps(profile,indent=2)+'\n')
            assert sources()==provenance['source_hashes'],'sources changed during gate'
        except FileNotFoundError as error:
            if not blocked:blocked.append(str(error))
        except BaseException as error:failures.append(repr(error))
        result=aggregate(profiles,blocked);result.update(provenance=provenance,commands=commands)
        if failures:
            result['failures']+=failures;result['passed']=False
            if not blocked:result.update(state='failed',exit_code=1)
        (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        code=publish_result(result,output/'result.json',interrupts)
        print(output/'result.json');return code
if __name__=='__main__':sys.exit(main())
