"""Trusted local qualification launcher. Only this launcher holds service credentials.
OwnedInfra owns containers; restricted workload gets fixed snapshot/output paths only.
The public runner contract is run(owned, pinned image, exact snapshot, fresh output).
"""
import hashlib,io,json,os,selectors,subprocess,tarfile,time
from pathlib import Path
LIMIT=1048576

def run(owned,image,snapshot,output,executable_hash):
    assert image.startswith('sha256:') and len(image)==71
    snapshot=Path(snapshot);output=Path(output)
    assert snapshot.is_absolute() and snapshot.is_dir() and not snapshot.is_symlink()
    assert output.is_absolute() and not output.exists()
    output.mkdir(mode=0o777);os.chmod(output,0o777)
    for p in snapshot.iterdir():
        assert p.name in ('input.csv','report.txt') and p.is_file() and not p.is_symlink()
        os.chmod(p,0o444)
    os.chmod(snapshot,0o555)
    name=owned.create('container','validation-'+os.urandom(4).hex(),[
        '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--pids-limit','64','--memory','256m','--cpus','1','--user','1001:1001',
        '--mount',f'type=bind,source={snapshot},target=/input,readonly',
        '--mount',f'type=bind,source={output},target=/output',
        '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16m',
        '--env','PATH=/usr/bin','--env','LANG=C','--env','PYTHONDONTWRITEBYTECODE=1',image])
    inspected=owned.inspect('container',name)
    copied=subprocess.run(['docker','cp',name+':/validator.py','-'],capture_output=True,timeout=10,check=True)
    assert len(copied.stdout)<=65536
    with tarfile.open(fileobj=io.BytesIO(copied.stdout)) as archive:
        member=archive.getmembers()[0];assert member.isfile() and member.size<=32768
        code=archive.extractfile(member).read()
    assert 'sha256:'+hashlib.sha256(code).hexdigest()==executable_hash

    started=time.monotonic();buf=bytearray();outcome='fail';bounded=False;timed=False
    proc=subprocess.Popen(['docker','start','--attach',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    try:
        selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
        while True:
            remain=30-(time.monotonic()-started)
            if remain<=0:timed=True;break
            events=selector.select(min(.1,remain))
            if events:
                data=os.read(proc.stdout.fileno(),min(65536,LIMIT+1-len(buf)))
                if not data:break
                buf.extend(data)
                if len(buf)>LIMIT:bounded=True;break
            elif proc.poll() is not None:break
        if timed or bounded:
            owned.docker('kill',name,check=False)
            # Docker attach may itself be blocked writing the capped pipe; reap both
            # the exact container and its owned client without reading past the bound.
            if proc.poll() is None:proc.kill()
            proc.wait(timeout=5)
        else:
            proc.wait(timeout=5)
        outcome='timeout' if timed else 'fail' if bounded or proc.returncode else 'pass'
    finally:
        if proc.poll() is None:
            owned.docker('kill',name,check=False);proc.kill();proc.wait(timeout=5)
        proc.stdout.close()
        owned.remove('container',name)
    result={'outcome':outcome,'seconds':time.monotonic()-started,'result_bytes':min(len(buf),LIMIT),
            'result_sha256':hashlib.sha256(buf[:LIMIT]).hexdigest(),'bounded':bounded,'timed_out':timed,
            'image':image,'executable_hash':executable_hash,'container':name,'launch':inspected,'stdout':buf[:LIMIT].decode(errors='replace')}
    owned.write_json('validation-'+name+'.json',result)
    return result

def verify_snapshot(binding,inputs,output,receipt,declaration,input_body,output_body):
    """Trusted launcher verifies exact published input and private output descriptor/bytes.
    It obtains the former through authorized HTTP and latter through the owner history.
    Caller filenames, scripts or a claimed hash cannot select the executable.
    """
    def canonical(value):
        # Frozen v1/v2 struct field order; owner history JSON may reorder object keys.
        def fields(obj,keys):return {k:obj[k] for k in keys if k in obj}
        result=fields(value,['format','hash','layout','parents','operation','replica','principal','captured_at_ns','coverage','provenance','restoration','tree'])
        tree=value['tree'];entries=[]
        for entry in sorted(tree['entries'],key=lambda e:e['path']):
            e=fields(entry,['path','id','parent','owner','group','mode','content'])
            content={'kind':entry['content']['kind']}
            if content['kind']=='file':
                version=entry['content']['version'];extents=[]
                for x in version['extents']:extents.append(fields(x,['kind','object','object_size','offset','length']))
                content['version']={'size':version['size'],'extents':extents}
            e['content']=content;entries.append(e)
        result['tree']={'root':fields(tree['root'],['id','owner','group','mode']),'entries':entries}
        return json.dumps(result,separators=(',',':'),ensure_ascii=False).encode()
    def digest(b):return 'sha256:'+hashlib.sha256(b).hexdigest()
    assert digest(canonical(inputs))==binding['revision']
    assert digest(canonical(output))==receipt['submitted_revision']
    assert declaration['candidate']==receipt['receipt']
    entry=next(e for e in inputs['tree']['entries'] if e['path']=='input.csv')
    assert {'view':binding['view'],'revision':binding['revision'],'entry':entry['id']} in declaration['reads']
    assert all(d['view']==binding['view'] and d['revision']==binding['revision'] for d in declaration['reads']+declaration['missing'])
    for e,body in [(entry,input_body),(next(e for e in output['tree']['entries'] if e['path']=='report.txt'),output_body)]:
        version=e['content']['version'];assert version['size']==len(body)
        offset=0
        for x in version['extents']:
            assert x['kind']=='chunk' and x['offset']==0 and x['object_size']==x['length']
            part=body[offset:offset+x['length']];assert digest(part)==x['object'];offset+=x['length']
        assert offset==len(body)
