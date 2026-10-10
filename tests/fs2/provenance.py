"""Source and build evidence, separate from private fixture control files."""
import hashlib
import json
from pathlib import Path
from infra import ROOT, PG, S3

def sources():
    files=[ROOT/name for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
    for directory in ['src','vendor','benches','crates','tests']:
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}

def capture(infra):
    compiler=infra.run(['rustc','+stable','--version','--verbose']).stdout
    if not compiler.startswith('rustc 1.92.0 '):
        raise RuntimeError('Rust1.92.0 required')
    metadata=json.loads(infra.run(['cargo','+stable','metadata','--locked','--format-version','1'],evidence=False).stdout)
    dependencies=[{'name':p['name'],'version':p['version'],'license':p['license'],'source':p['source']} for p in metadata['packages']]
    infra.write_json('dependencies.json',{'packages':dependencies,'resolve':metadata['resolve']})
    infra.run(['cargo','+stable','tree','--locked','--workspace','-e','features'])
    data={'head':infra.run(['git','rev-parse','HEAD']).stdout.strip(),'status':infra.run(['git','status','--porcelain']).stdout,'compiler':compiler,'sha256':sources(),'dockerignore_sha256':hashlib.sha256((ROOT/'.dockerignore').read_bytes()).hexdigest()}
    infra.write_json('source.json',data)
    return data

def verify_image(infra,before,host_profile="debug"):
    script="import hashlib,json; from pathlib import Path; expected=json.load(__import__('sys').stdin); print(json.dumps({p:hashlib.sha256((Path('/src')/p).read_bytes()).hexdigest() for p in expected}))"
    actual=json.loads(infra.docker('exec','-i',infra.service,'python3','-c',script,input=json.dumps(before['sha256']),evidence=False).stdout)
    if sources()!=before['sha256'] or actual!=before['sha256']:
        raise AssertionError('source changed during gate or differs from built image')
    infra.docker('exec',infra.service,'dpkg-query','-W')
    infra.docker('exec',infra.service,'python3','--version')
    infra.docker('exec',infra.s3,'weed','version')
    binaries={}
    for name in ['magus-fs-service','magus-fs-service-faults']:
        binaries[name]=infra.docker('exec',infra.service,'sha256sum','/usr/local/bin/'+name).stdout.strip().split()[0]
    binaries['host-magus-fs-service']=hashlib.sha256((ROOT/('target/'+host_profile+'/magus-fs-service')).read_bytes()).hexdigest()
    selected={}
    arch=infra.inspect('container',infra.service)['Platform']
    for ref in [PG,S3]:
        index=json.loads(infra.docker('buildx','imagetools','inspect','--raw',ref).stdout)
        arm=[m for m in index['manifests'] if m.get('platform',{}).get('architecture')=='arm64' and m['platform'].get('os')=='linux']
        if len(arm)!=1:
            raise AssertionError('ambiguous pinned ARM64 image')
        selected[ref]=arm[0]
    expected={PG:'sha256:67ba68a22dc7d5af3627b7e0f33d10bbefad07562ff9703b3a6c2de247649129',S3:'sha256:f1f303474940e9e088edbd2c1658f7ac38cb0dd90f91a2b0a51916d74b8575a1'}
    assert {ref:m['digest'] for ref,m in selected.items()}==expected
    for name in [infra.pg,infra.s3,infra.service]:
        x=infra.inspect('container',name)
        image=json.loads(infra.docker('image','inspect',x['Image']).stdout)[0]
        assert image['Architecture']=='arm64'
    infra.write_json('image-source.json',{'matched':True,'files':len(actual),'binaries':binaries,'service_image':infra.inspect('container',infra.service)['Image'],'platform':arch,'selected_backend_manifests':selected})
