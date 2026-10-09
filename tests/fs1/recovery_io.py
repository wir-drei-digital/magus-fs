#!/usr/bin/env python3
"""Independent archive qualification. Fresh output only; retain all commands/failures.
macOS uses inherited Seatbelt denial; Linux uses a separate --network none container
with no original-state mount. No mounts, host users or privileged setup are needed.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid
import io
import tarfile

ROOT = Path(__file__).resolve().parents[2]
P='principal:'+'1'*32
G='group:'+'1'*32

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,value): path.write_text(json.dumps(value,indent=2)+'\n')
def command(argv,records,expected=0,env=None,input_data=None):
    r=subprocess.run(list(map(str,argv)),input=input_data,capture_output=True,text=input_data is None,timeout=120,env=env)
    if input_data is not None:r.stdout=r.stdout.decode();r.stderr=r.stderr.decode()
    record={'argv':list(map(str,argv)),'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr};records.append(record)
    if r.returncode!=expected: raise AssertionError(record)
    return r.stdout

class PrerequisiteUnavailable(RuntimeError):
    """The native qualification could not start; no product result is implied."""


def docker_prerequisites(image,records):
    # Check only availability here. Errors after these probes remain test failures.
    for argv in [['docker','info','--format','{{.ServerVersion}}'],
                 ['docker','image','inspect',image]]:
        try:
            command(argv,records)
        except AssertionError as e:
            raise PrerequisiteUnavailable(str(e)) from e


def prepare(base,binary,uid=None):
    base.mkdir(exist_ok=False)
    original=base/'original';original.mkdir();tree=original/'tree';tree.mkdir();(tree/'empty').mkdir()
    (tree/'report.sh').write_bytes(b'#!/bin/sh\nprintf "recovered report\\n"\n');(tree/'report.sh').chmod(0o755)
    (tree/'data.csv').write_bytes(b'id,value\n1,old\n')
    (tree/'deleted.txt').write_bytes(b'recover deleted entry\n')
    (tree/'binary').write_bytes(bytes(range(256))*2400)
    (tree/'._ordinary').write_bytes(b'ordinary AppleDouble-like visible bytes')
    records=[]
    authority={'principal':P,'uid':os.geteuid(),'primary_group':G,'gid':tree.stat().st_gid,'groups':[G],'dac_override':False,'ownership_transfer':True}
    config={'replica':{'replica':'replica:'+'1'*32,'authorities':[authority],'history_administrators':[P],'content_roots':[str(tree)],'cache_bytes':32*1024*1024},'root':str(tree),'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
    write(original/'config.json',config);state=original/'state'
    command([binary,'init','--state',state,'--config',original/'config.json'],records)
    first=json.loads(command([binary,'capture','--state',state,'--root',tree,'--operation-id','operation:'+'1'*32],records))['revision']
    deleted=next(e for e in json.loads(command([binary,'history','--state',state],records))['revisions'][0]['descriptor']['tree']['entries'] if e['path']=='deleted.txt')
    (tree/'deleted.txt').unlink()
    (tree/'data.csv').write_bytes(b'id,value\n1,current\n')
    second=json.loads(command([binary,'capture','--state',state,'--root',tree,'--operation-id','operation:'+'2'*32],records))['revision']
    write(original/'grants.json',[{'principal':P,'revision':first,'entries':[deleted['id']]}])
    command([binary,'history-grants','--state',state,'--config',original/'grants.json'],records)
    restored=json.loads(command([binary,'restore','--state',state,'--revision',first,'--operation-id','operation:'+'3'*32],records))['revision']
    command([binary,'export','--state',state,'--revision',restored,'--destination',base/'archive'],records)
    expected={'files':{str(f.relative_to(tree)):{'length':f.stat().st_size,'sha256':digest(f),'mode':0o700 if f.name=='report.sh' else 0o600} for f in tree.rglob('*') if f.is_file()},'directories':['empty'],'revisions':[first,second,restored],'original_paths':[str(state/'journal.sqlite'),str(state/'objects'),str(tree/'binary')]}
    for relative,body in [('data.csv',b'id,value\n1,old\n'),('deleted.txt',b'recover deleted entry\n')]:expected['files'][relative]={'length':len(body),'sha256':hashlib.sha256(body).hexdigest(),'mode':0o600}
    authority=dict(authority,uid=uid if uid is not None else os.geteuid(),gid=1001 if uid is not None else tree.stat().st_gid)
    policy={'authorities':[authority],'actor':{'principal':P},'owner':P,'group':G,'file_mode':0o600,'directory_mode':0o700,'entries':[{'path':'report.sh','owner':P,'group':G,'mode':0o700}]}
    write(base/'expected.json',expected);write(base/'policy.json',policy);write(base/'prepare.json',records)
    for p in (base/'archive').rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
    (base/'archive').chmod(0o755)
    return expected

def worker(fixture,binary,port=9):
    records=[];expected=json.loads((fixture/'expected.json').read_text());report={'platform':sys.platform,'uid':os.geteuid(),'binary_sha256':digest(binary),'commands':records,'original_access':[],'network':[]}
    for path in expected['original_paths']:
        try:
            fd=os.open(path,os.O_RDONLY);os.close(fd)
        except OSError as e: report['original_access'].append({'path':path,'errno':e.errno,'error':str(e)})
        else: raise AssertionError('original state is accessible: '+path)
    for kind,address in [('tcp',('127.0.0.1',port) if sys.platform=='darwin' else ('192.0.2.1',9)),('udp',('192.0.2.1',9))]:
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                if kind=='tcp':s.connect(address)
                else:s.sendto(b'isolated-fs1-denial-probe',address)
        except OSError as e:
            if e.errno not in [errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH]:raise
            report['network'].append({'kind':kind,'address':address,'errno':e.errno,'error':str(e)})
        else:raise AssertionError('network was not denied')
    archive=fixture/'archive'
    manifest=json.loads((archive/'archive.json').read_text())
    # Independently verify the archive members, before invoking the Rust verifier.
    for member in manifest['members']:
        f=archive/member['path'];assert f.stat().st_size==member['length'];assert digest(f)==member['sha256']
    descriptors=[json.loads(f.read_text()) for f in (archive/'revisions').iterdir()]
    assert len(descriptors)==3 and any(r['parents']==[expected['revisions'][0]] for r in descriptors)
    v2=next(r for r in descriptors if r['format']=='magus-fs/v2');assert v2['restoration']['source_revision']==expected['revisions'][0];assert len(v2['restoration']['recreated'])==1
    verified=json.loads(command([binary,'verify','--archive',archive],records));assert verified['verification']['revisions']==3
    destination=fixture/'output'
    restored=json.loads(command([binary,'restore','--archive',archive,'--destination',destination,'--config',fixture/'policy.json'],records))['result']
    assert restored['source_revision']==expected['revisions'][2] and not restored['head_changed']
    assert restored['derived_revision']!=restored['source_revision']
    assert {str(f.relative_to(destination)) for f in destination.rglob('*')}==set(expected['files'])|set(expected['directories'])
    for relative,metadata in expected['files'].items():
        f=destination/relative;assert f.stat().st_size==metadata['length'];assert digest(f)==metadata['sha256'];assert f.stat().st_mode&0o777==metadata['mode'];assert f.stat().st_uid==os.geteuid()
    assert subprocess.check_output([str(destination/'report.sh')],text=True)=='recovered report\n'
    report['restored']=restored;report['files']=expected['files'];report['malformed']=[]
    for damage in ['missing','corrupt','extra','descriptor_reference','provenance']:
        altered=fixture/('bad-'+damage);shutil.copytree(archive,altered)
        obj=next((altered/'objects').iterdir())
        if damage=='missing':obj.unlink()
        elif damage=='corrupt':obj.write_bytes(b'corrupt')
        elif damage=='extra':(altered/'extra').write_bytes(b'extra')
        else:
            m=json.loads((altered/'archive.json').read_text());entry=next(e for e in m['members'] if e['path']=='revisions/'+m['revision'].split(':')[1]);f=altered/entry['path'];r=json.loads(f.read_text());
            if damage=='provenance':r['restoration']['recreated']={}
            else:r['parents']=['sha256:'+'0'*64]
            body=json.dumps(r,separators=(',',':'),ensure_ascii=False).encode();new=hashlib.sha256(body).hexdigest();f.unlink();entry.update(path='revisions/'+new,length=len(body),sha256=new);(altered/entry['path']).write_bytes(body);m['revision']='sha256:'+new;m['members'].sort(key=lambda x:x['path']);(altered/'archive.json').write_text(json.dumps(m,separators=(',',':')))
        out=fixture/('reject-'+damage)
        result=json.loads(command([binary,'restore','--archive',altered,'--destination',out,'--config',fixture/'policy.json'],records,expected=1));assert not out.exists();report['malformed'].append({'case':damage,'error':result['error'],'destination_absent':True})
    report['passed']=True
    return report

def run_host(output,binary):
    fixture=output/'fixture';prepare(fixture,binary)
    profile=output/'worker.sb';original=str(fixture/'original')
    profile.write_text('(version 1)\n(allow default)\n(deny network*)\n(deny file-read* file-write* (subpath '+json.dumps(original)+'))\n')
    records=[]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
        # A live listener proves denial is not merely ECONNREFUSED.
        with socket.create_connection(('127.0.0.1',port),timeout=2):pass
        try:
            result=command(['/usr/bin/sandbox-exec','-f',profile,sys.executable,__file__,'--worker',fixture,'--binary',binary,'--port',str(port)],records)
        finally:write(output/'worker-commands.json',records)
    report=json.loads(result);write(output/'result.json',report);return report

def run_linux(output,image):
    records=[];token=uuid.uuid4().hex;producer='fs1-recovery-producer-'+token;worker_name='fs1-recovery-worker-'+token;owned=[]
    try:
        docker_prerequisites(image,records)
        command(['docker','create','--name',producer,'--network','none',image,'python3','/src/tests/fs1/recovery_io.py','--prepare','/tmp/fixture','--binary','/out/magus-fs','--uid','1001'],records);owned.append(producer)
        command(['docker','start','--attach',producer],records)
        assert command(['docker','inspect','--format','{{.State.ExitCode}}',producer],records).strip()=='0'
        command(['docker','cp',producer+':/tmp/fixture',output/'fixture'],records)
        # Input contains only archive, expectation, policy; original state never enters worker.
        isolated=output/'isolated';isolated.mkdir()
        for leaf in ['archive','expected.json','policy.json']:
            if (output/'fixture'/leaf).is_dir():shutil.copytree(output/'fixture'/leaf,isolated/leaf)
            else:shutil.copy2(output/'fixture'/leaf,isolated/leaf)
        command(['docker','create','--interactive','--name',worker_name,'--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,exec,mode=1777','--user','1001:1001',image,'sh','-c','mkdir /tmp/worker && tar -xf - -C /tmp/worker && python3 /src/tests/fs1/recovery_io.py --worker /tmp/worker --binary /out/magus-fs'],records);owned.append(worker_name)
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as bundle:
            for leaf in sorted(isolated.iterdir()):bundle.add(leaf,arcname=leaf.name)
        records.append({'input_tar_sha256':hashlib.sha256(stream.getvalue()).hexdigest(),'input_tar_bytes':len(stream.getvalue()),'source_only':['archive','expected.json','policy.json']})
        inspect=json.loads(command(['docker','inspect',worker_name],records))[0];assert inspect['HostConfig']['NetworkMode']=='none';assert not inspect['Mounts']
        result=command(['docker','start','--attach','--interactive',worker_name],records,input_data=stream.getvalue());assert command(['docker','inspect','--format','{{.State.ExitCode}}',worker_name],records).strip()=='0';report=json.loads(result);report['container']=worker_name;report['network_mode']='none';report['image']=inspect['Image'];write(output/'result.json',report)
        return report
    finally:
        cleanup=[]
        for name in owned:
            r=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True);cleanup.append({'name':name,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        write(output/'commands.json',records);write(output/'cleanup.json',cleanup)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);p.add_argument('--binary',type=Path,default=ROOT/'target/debug/magus-fs');p.add_argument('--platform',choices=['all','macos','linux'],default='all');p.add_argument('--image',default='magus-fs1-task7-recovery');p.add_argument('--worker',type=Path);p.add_argument('--prepare',type=Path);p.add_argument('--uid',type=int);p.add_argument('--port',type=int,default=9);args=p.parse_args()
    if args.prepare:prepare(args.prepare,args.binary,args.uid);return 0
    if args.worker:print(json.dumps(worker(args.worker,args.binary,args.port)));return 0
    if not args.output or not args.output.is_absolute():p.error('--output must be an absolute new path')
    args.output.mkdir(exist_ok=False);report={'platforms':{},'source':{},'status':'failed'}
    for folder in ['crates','tests/fs1','vendor']:
        for file in sorted((ROOT/folder).rglob('*')):
            if file.is_file() and '__pycache__' not in file.parts:report['source'][str(file.relative_to(ROOT))]=digest(file)
    for leaf in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']:report['source'][leaf]=digest(ROOT/leaf)
    try:
        if args.platform in ['all','macos']:
            if sys.platform!='darwin' or not Path('/usr/bin/sandbox-exec').exists():raise FileNotFoundError('macOS Seatbelt unavailable')
            out=args.output/'macos';out.mkdir();report['platforms']['macos']=run_host(out,args.binary)
        if args.platform in ['all','linux']:
            out=args.output/'linux';out.mkdir();report['platforms']['linux']=run_linux(out,args.image)
        report['status']='passed';return 0
    except (FileNotFoundError,PrerequisiteUnavailable) as e:report['status']='unavailable';report['error']=repr(e);return 2
    except Exception as e:report['error']=repr(e);return 1
    finally:write(args.output/'result.json',report)
if __name__=='__main__':sys.exit(main())
