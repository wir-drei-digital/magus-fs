"""Restore the Connected accepted revision in an isolated, credential-free process."""
import hashlib,io,json,tarfile
from pathlib import Path
from connected import inventory_code,fixture
from service_storage import ALICE
from service_protocol import GROUP

WORKER=r'''
import hashlib,json,os,socket,errno,subprocess,shutil
from pathlib import Path
root=Path('/tmp/recovery');expected=json.loads((root/'expected.json').read_text());archive=root/'archive';rows=[]
assert not any(k.startswith(('AWS_','MAGUS_')) for k in os.environ)
for path in expected['original_paths']:
 try:open(path,'rb');raise AssertionError('original state accessible')
 except OSError as e:rows.append({'path':path,'errno':e.errno})
network=[]
for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
 s=socket.socket(socket.AF_INET,kind);s.settimeout(2)
 try:
  if kind==socket.SOCK_STREAM:s.connect(('192.0.2.1',9))
  else:s.sendto(b'owned-denial-probe',('192.0.2.1',9))
 except OSError as e:assert e.errno in [errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH];network.append(e.errno)
 else:raise AssertionError('network accessible')
 finally:s.close()
def cli(*args,code=0):
 p=subprocess.run(['magus-fs',*map(str,args)],capture_output=True,text=True,timeout=60);assert p.returncode==code,(p.stdout,p.stderr);return json.loads(p.stdout)
manifest=json.loads((archive/'archive.json').read_text())
for member in manifest['members']:
 p=archive/member['path'];assert p.stat().st_size==member['length'] and hashlib.sha256(p.read_bytes()).hexdigest()==member['sha256']
verified=cli('verify','--archive',archive)
restored=cli('restore','--archive',archive,'--destination',root/'restored','--config',root/'policy.json')
actual={}
for p in sorted((root/'restored').rglob('*')):
 st=p.stat();v={'kind':'directory' if p.is_dir() else 'file','mode':st.st_mode&511}
 if p.is_file():v.update(size=st.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
 assert st.st_uid==1001 and st.st_gid==1001
 actual[str(p.relative_to(root/'restored'))]=v
assert actual==expected['inventory'],(actual,expected['inventory'])
shutil.copytree(archive,root/'corrupt');obj=next((root/'corrupt'/'objects').iterdir());obj.write_bytes(b'corrupt owned archive body')
negative=cli('restore','--archive',root/'corrupt','--destination',root/'rejected','--config',root/'policy.json',code=1);assert not (root/'rejected').exists()
print(json.dumps({'source_revision':manifest['revision'],'verified':verified,'restored':restored,'actual':actual,'original_denied':rows,'network_denied':network,'credentials_absent':True,'corruption':negative,'rejected_absent':True}))
'''

def restore(j):
    ep=j.mac_endpoint;c=j.mac_client;head=j.until(lambda:ep.status(c)['status']['binding']['view'] if ep.ready(c) else None)
    expected=ep.run(inventory_code(),c['root']);inventory={p:{k:v for k,v in x.items() if k not in ['uid','gid']} for p,x in expected.items()}
    files,_=fixture();files['instructions.md']+=b'VSCode ordinary TextDocument.save qualification.\n';files['reports/procedure.txt']=b'committed response discarded procedure\n'
    for path,body in files.items():assert inventory[path]['sha256']==hashlib.sha256(body).hexdigest() and inventory[path]['size']==len(body)
    assert set(inventory)==set(files)|{'reports','empty-dir','reports/result.json'}
    assert all(v['mode']==(0o755 if v['kind']=='directory' or p=='executable' else 0o644 if p=='reports/result.json' else 0o600) for p,v in inventory.items())
    assert inventory['instructions.md']['sha256']==j.editor_result['expected_sha256']
    assert inventory['reports/result.json']['sha256']==j.result['worker_private']['expected_hash']
    archive=j.i.output/'archive';ep.stop(c)
    exported=ep.cli(c,'export','--revision',head['revision'],'--destination',str(archive))
    manifest=json.loads((archive/'archive.json').read_text());assert manifest['revision']==head['revision']
    policy={'authorities':[{'principal':ALICE,'uid':1001,'gid':1001,'primary_group':GROUP,'groups':[GROUP],'dac_override':False,'ownership_transfer':True}],'actor':{'principal':ALICE},'owner':ALICE,'group':GROUP,'file_mode':0o600,'directory_mode':0o755,'entries':[{'path':p,'owner':ALICE,'group':GROUP,'mode':x['mode']} for p,x in inventory.items()]}
    source={'inventory':inventory,'original_paths':[c['state']+'/journal.sqlite',c['state']+'/objects',str(j.i.control/'service.json'),c['root']+'/reports/result.json']}
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as t:
        t.add(archive,arcname='archive')
        for name,value in [('expected.json',source),('policy.json',policy)]:
            b=json.dumps(value).encode();info=tarfile.TarInfo(name);info.size=len(b);info.mode=0o644;t.addfile(info,io.BytesIO(b))
    worker=j.i.create('container','offline-restore',['-i','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--user','1001:1001','--tmpfs','/tmp:rw,nosuid,nodev,mode=1777,size=384m',j.image,'python3','-c',"import sys,tarfile,io,os;os.mkdir('/tmp/recovery');t=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()));assert all(not m.name.startswith('/') and '..' not in m.name.split('/') and (m.isfile() or m.isdir()) for m in t.getmembers());t.extractall('/tmp/recovery');exec("+repr(WORKER)+")"])
    config=j.i.inspect('container',worker);assert config['HostConfig']['NetworkMode']=='none' and not config['Mounts']
    # Existing OwnedInfra text command recorder cannot feed arbitrary tar bytes. The exact
    # owned container execution is still recorded with input hash and retained stdout.
    import subprocess
    p=subprocess.run(['docker','start','--attach','--interactive',worker],input=stream.getvalue(),capture_output=True,timeout=120)
    (j.i.output/'archive-worker.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0 and j.i.inspect('container',worker)['State']['ExitCode']==0
    result=json.loads(p.stdout);assert result['source_revision']==head['revision'] and result['actual']==inventory
    result.update(exported=exported,head=head,input_sha256=hashlib.sha256(stream.getvalue()).hexdigest(),input_members=['archive','expected.json','policy.json'],image=config['Image'],container=worker,network_mode='none',mounts=config['Mounts'],argv=['docker','start','--attach','--interactive',worker],expected=source)
    j.i.write_json('archive.json',result);return result
