#!/usr/bin/env python3
"""Deterministic unsigned archives; explicit source/build identity, safe fresh installs."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parents[1]
PLATFORMS=('aarch64-apple-darwin','aarch64-unknown-linux-gnu')
AMD64='x86_64-unknown-linux-gnu'
CLIENT_BUILD=['cargo','build','--locked','--release','-p','magus-fs','--bin','magus-fs','--target',AMD64]
BASE_MANIFEST_SHA256='56d8592d1ba9fd84a4a2ed8ae93d41824608e334f75645b56ea674eb42c98da8'
LICENSES=('LICENSE','THIRD_PARTY_NOTICES.md')
MARKERS=(b'MAGUS_TEST_',b'client_probe')
MANIFESTS=('Cargo.toml','crates/magus-fs/Cargo.toml','crates/magus-fs-core/Cargo.toml','crates/magus-fs-service/Cargo.toml')

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical_sha(value):return sha(json.dumps(value,sort_keys=True).encode())
def require(ok,message):
    if not ok:raise ValueError(message)
# Accepted FS3 local release freeze. Qualifying another build requires new evidence,
# not simply supplying a mutable tag or replacing a self-reported checksum.
FROZEN={'image':'sha256:875888cb5586f46489613188c8b227227348d6fcb056ec0b675e2571c8335f32',
        'source_manifest_sha256':'6b3f1cf18971dc76f79026899a3f022a5e57503af561cefc3b9c307cd55ce251',
        'build_head':'3fe99d84138fdf37561edc76fa5c937d1aa73964',
        'build_dirty':True,
        'build_record_sha256':'48878ab8c17f358f6aa6030ef885d92e323585206261bf2ec5912cde18e78ac8',
        'compiler':'rustc 1.92.0', 'profile':'release',
        'binaries':{'magus-fs':'372888e073185a15302e1cc69b0fe413bf5562452cb79005b31ccdf46630cd8c',
                    'magus-fs-service':'73bafa610b146013d2559f3b8fe9742738cd330003e0838d348651dcb29d0052'}}

def verify_frozen(image,source,binaries):
    require(image==FROZEN['image'] and canonical_sha(source)==FROZEN['source_manifest_sha256'] and binaries==FROZEN['binaries'],'unqualified Linux release freeze')

def license_only(old,new):
    return new.count(b'license = "MIT"\n')==1 and new.replace(b'license = "MIT"\n',b'',1)==old

def source_manifest():
    names=set(MANIFESTS)|{'Cargo.lock','rust-toolchain.toml','.dockerignore','LICENSE','THIRD_PARTY_NOTICES.md','README.md'}
    for directory in ('src','vendor','benches','crates','tests','scripts','docs'):
        names.update(str(p.relative_to(ROOT)) for p in (ROOT/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {n:sha((ROOT/n).read_bytes()) for n in sorted(names)}

def runtime_inputs(manifest):
    return {n:v for n,v in manifest.items() if n in MANIFESTS or n in ('Cargo.lock','rust-toolchain.toml') or n.startswith(('src/','vendor/','benches/')) or (n.startswith('crates/') and '/tests/' not in n)}

def binary_check(data,platform):
    require(platform in (*PLATFORMS,AMD64),'unsupported architecture label')
    require(not any(marker in data for marker in MARKERS),'test-fault/probe binary forbidden')
    if platform==PLATFORMS[0]:require(data[:4]==b'\xcf\xfa\xed\xfe' and data[4:8]==b'\x0c\x00\x00\x01','expected ARM64 Mach-O')
    elif platform==AMD64:require(data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\x3e\x00','expected AMD64 ELF')
    else:require(data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\x00','expected ARM64 ELF')

def write_archive(path,files):
    with Path(path).open('xb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w',format=tarfile.USTAR_FORMAT) as archive:
                for name,body in sorted(files.items()):
                    member=tarfile.TarInfo(name);member.size=len(body);member.mode=0o755 if name.startswith('bin/') else 0o644
                    member.uid=member.gid=member.mtime=0;member.uname=member.gname='';archive.addfile(member,io.BytesIO(body))

def load_manifest(path):
    path=Path(path);m=json.loads(path.read_text());require(m.get('schema')==1,'unsupported package schema')
    s=m.get('source',{});require(re.fullmatch('[a-f0-9]{40}',s.get('head','')) and canonical_sha(s.get('manifest'))==s.get('manifest_sha256'),'source manifest mismatch')
    for row in m.get('packages',[]):
        require(row.get('platform') in (*PLATFORMS,AMD64),'unsupported architecture label')
        require(row.get('role') in ('client','service'),'unsupported artifact role')
        require(row.get('platform')!=AMD64 or row.get('role')=='client','AMD64 service is not qualified')
        require(row.get('archive')==Path(row.get('archive','')).name and row.get('archive','').endswith('.tar.gz'),'unsafe archive path')
    require(bool(m.get('packages')),'missing packages');return m

def install(manifest_path,platform,role,prefix):
    """Validate all bytes before creating a new prefix; never generic tar extraction."""
    prefix=Path(prefix);require(prefix.is_absolute(),'absolute prefix required')
    if prefix.exists() or prefix.is_symlink():raise FileExistsError(prefix)
    require(prefix.parent.resolve()==prefix.parent,'prefix parent must be canonical')
    m=load_manifest(manifest_path);rows=[r for r in m['packages'] if r['platform']==platform and r['role']==role]
    require(len(rows)==1,'missing or duplicate platform/role');row=rows[0]
    blob=(Path(manifest_path).parent/row['archive']).read_bytes();require(sha(blob)==row['sha256'],'archive checksum mismatch')
    expected={'bin/magus-fs' if role=='client' else 'bin/magus-fs-service',*LICENSES,'fs3-qualification.md'}
    require(set(row['members'])==expected,'missing notice or unexpected member')
    files={}
    with tarfile.open(fileobj=io.BytesIO(blob),mode='r:gz') as archive:
        for member in archive:
            parts=PurePosixPath(member.name).parts
            require(not member.name.startswith('/') and '..' not in parts and member.isfile() and member.name in expected and member.name not in files,'unsafe or unexpected archive entry')
            require(member.size<=128*1024*1024,'archive member too large')
            files[member.name]=archive.extractfile(member).read()
    require(set(files)==expected,'archive member mismatch')
    require({n:sha(b) for n,b in files.items()}==row['members'],'member checksum mismatch')
    require(all(sha(files[n])==m['licenses'].get(n) for n in LICENSES),'license digest mismatch')
    binary='bin/magus-fs' if role=='client' else 'bin/magus-fs-service'
    require(row['binary']==binary and sha(files[binary])==row['binary_sha256'],'binary checksum mismatch')
    binary_check(files[binary],platform)
    if platform==AMD64:verify_client_build(m.get('builds',{}).get('client_amd64',{}),files[binary],runtime_inputs(m['source']['manifest']),m['licenses'])
    prefix.mkdir(mode=0o700);(prefix/'bin').mkdir(mode=0o755)
    # An interrupted install remains owned evidence. Retry must choose a new prefix.
    for name,body in sorted(files.items()):
        with (prefix/name).open('xb') as f:f.write(body)
        (prefix/name).chmod(0o755 if name==binary else 0o644)
    require(sha((prefix/binary).read_bytes())==row['binary_sha256'],'extracted binary mismatch')
    return row

def command(argv,timeout=120):
    p=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,timeout=timeout)
    require(p.returncode==0,'command failed: '+repr(argv)+': '+p.stderr[-2000:]);return p.stdout

def host_build(proof):
    proof=Path(proof);require(not proof.exists(),'host build proof already exists')
    compiler=command(['rustc','+stable','--version','--verbose']);require(compiler.startswith('rustc 1.92.0 '),'Rust1.92.0 required')
    before=runtime_inputs(source_manifest());argv=['cargo','+stable','build','--offline','--release','--locked','-p','magus-fs']
    p=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True,timeout=600)
    proof.with_suffix('.log').write_text(p.stdout+p.stderr)
    record={'argv':argv,'exit':p.returncode,'compiler':compiler,'profile':'release','platform':PLATFORMS[0],'source':before,'head':command(['git','rev-parse','HEAD']).strip()}
    proof.write_text(json.dumps(record,indent=2)+'\n');require(p.returncode==0,'host release build failed; evidence retained')
    require(before==runtime_inputs(source_manifest()),'source changed during build');data=(ROOT/'target/release/magus-fs').read_bytes();binary_check(data,PLATFORMS[0]);record['binary_sha256']=sha(data);proof.write_text(json.dumps(record,indent=2)+'\n')

def package(output,image,host_proof):
    output=Path(output);require(output.is_absolute(),'absolute new output required');output.mkdir(mode=0o700)
    require(re.fullmatch('sha256:[a-f0-9]{64}',image),'immutable image required')
    source=source_manifest();host=json.loads(Path(host_proof).read_text());hostdata=(ROOT/'target/release/magus-fs').read_bytes()
    require(host.get('exit')==0 and host.get('profile')=='release' and host.get('compiler','').startswith('rustc 1.92.0 ') and host.get('source')==runtime_inputs(source) and host.get('binary_sha256')==sha(hostdata),'host release provenance mismatch')
    info=json.loads(command(['docker','image','inspect',image]))[0]
    require(info['Id']==image and info['Architecture']=='arm64' and info['Os']=='linux' and info['Config']['Labels'].get('magus.fs2.build-profile')=='release','Linux release platform/profile mismatch')
    # Read only from the immutable image, no service or credentials.
    script="import sys,json,base64;from pathlib import Path;sys.path.insert(0,'/src/tests/fs2');from provenance import sources;print(json.dumps({'source':sources(),'manifests':{n:(Path('/src')/n).read_text() for n in "+repr(MANIFESTS)+"},'binaries':{n:base64.b64encode((Path('/usr/local/bin')/n).read_bytes()).decode() for n in ['magus-fs','magus-fs-service']}}))"
    actual=json.loads(command(['docker','run','--rm','--network','none',image,'python3','-c',script]))
    changed={}
    for n in sorted(set(actual['source'])|set(source)):
        old,new=actual['source'].get(n),source.get(n)
        if old==new:continue
        changed[n]={'build':old,'package':new}
        if n in MANIFESTS:require(license_only(actual['manifests'][n].encode(),(ROOT/n).read_bytes()),'non-license Cargo change: '+n)
        elif n in runtime_inputs(source) or n in runtime_inputs(actual['source']):require(False,'runtime source mismatch: '+n)
        elif n.startswith('tests/') and not n.startswith('tests/fs3/'):require(False,'non-FS3 fixture changed: '+n)
    import base64
    verify_frozen(image,actual['source'],{n:sha(base64.b64decode(b)) for n,b in actual['binaries'].items()})
    binaries=[(PLATFORMS[0],'client','magus-fs',hostdata),(PLATFORMS[1],'client','magus-fs',base64.b64decode(actual['binaries']['magus-fs'])),(PLATFORMS[1],'service','magus-fs-service',base64.b64decode(actual['binaries']['magus-fs-service']))]
    manifest={'schema':1,'version':'0.1.0','unsigned':True,'source':{'head':command(['git','rev-parse','HEAD']).strip(),'status':command(['git','status','--porcelain']),'diff_sha256':sha(command(['git','diff','--binary','HEAD']).encode()),'manifest':source,'manifest_sha256':canonical_sha(source)},'builds':{'host':host,'linux':{**FROZEN,'image':image,'profile':'release','compiler':'rustc 1.92.0','source':actual['source'],'source_manifest_sha256':canonical_sha(actual['source']),'bridge':changed,'bridge_contract':'Exact frozen binaries reused; Cargo changes only add MIT metadata. FS3 harness and documentation changes do not claim a rebuild or historical rerun.'}},'licenses':{n:source[n] for n in LICENSES},'packages':[]}
    for platform,role,name,data in binaries:
        binary_check(data,platform)
        files={'bin/'+name:data,**{n:(ROOT/n).read_bytes() for n in LICENSES},'fs3-qualification.md':(ROOT/'docs/fs3-qualification.md').read_bytes()}
        archive=f'{name}-0.1.0-{platform}.tar.gz';write_archive(output/archive,files)
        manifest['packages'].append({'role':role,'platform':platform,'archive':archive,'sha256':sha((output/archive).read_bytes()),'binary':'bin/'+name,'binary_sha256':sha(data),'members':{n:sha(b) for n,b in files.items()}})
    require(source==source_manifest(),'source changed during packaging')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    sums={r['archive']:r['sha256'] for r in manifest['packages']};sums['manifest.json']=sha((output/'manifest.json').read_bytes())
    (output/'SHA256SUMS').write_text(''.join(f'{v}  {n}\n' for n,v in sorted(sums.items())))
    return manifest

def verify_client_build(proof,data,source,licenses):
    require(proof.get('exit')==0 and proof.get('platform')==AMD64
        and proof.get('profile')=='release' and proof.get('argv')==CLIENT_BUILD,
        'default cross-client build command mismatch')
    require(proof.get('compiler','').startswith('rustc 1.92.0 ')
        and re.fullmatch('sha256:[a-f0-9]{64}',proof.get('toolchain_image','')),
        'cross-client toolchain provenance missing')
    require(proof.get('source')==source and proof.get('source_manifest_sha256')==canonical_sha(source),
        'cross-client source mismatch')
    require(proof.get('licenses')==licenses,'cross-client license mismatch')
    require(proof.get('binary_sha256')==sha(data),'cross-client binary mismatch')
    binary_check(data,AMD64)


def append_client(output,base_path,proof_path):
    """Copy immutable accepted archives; add only the independently built client."""
    import copy
    base_path=Path(base_path);proof_path=Path(proof_path);output=Path(output)
    require(output.is_absolute(),'absolute fresh output required')
    require(sha(base_path.read_bytes())==BASE_MANIFEST_SHA256,'unaccepted base manifest')
    base=load_manifest(base_path);source=source_manifest()
    require(runtime_inputs(base['source']['manifest'])==runtime_inputs(source),'base runtime source changed')
    licenses={n:source[n] for n in LICENSES}
    require(licenses==base['licenses'],'base notices changed')
    proof=json.loads(proof_path.read_text());data=Path(proof['binary_path']).read_bytes()
    verify_client_build(proof,data,runtime_inputs(source),licenses)
    archives={r['archive']:(base_path.parent/r['archive']).read_bytes() for r in base['packages']}
    require(all(sha(archives[r['archive']])==r['sha256'] for r in base['packages']),'base archive changed')
    output.mkdir(mode=0o700)
    for name,blob in archives.items():(output/name).write_bytes(blob)
    m=copy.deepcopy(base);m['base_manifest']={'sha256':BASE_MANIFEST_SHA256,'source':base['source']}
    m['source']={'head':command(['git','rev-parse','HEAD']).strip(),'manifest':source,
        'manifest_sha256':canonical_sha(source),'diff_sha256':sha(command(['git','diff','--binary','HEAD']).encode()),
        'bridge':{n:{'base':base['source']['manifest'].get(n),'current':source.get(n)}
            for n in sorted(set(source)|set(base['source']['manifest'])) if source.get(n)!=base['source']['manifest'].get(n)}}
    m['builds']['client_amd64']=proof
    m['builds']['client_amd64_proof_sha256']=sha(proof_path.read_bytes())
    files={'bin/magus-fs':data,**{n:(ROOT/n).read_bytes() for n in LICENSES},
        'fs3-qualification.md':(ROOT/'docs/fs3-qualification.md').read_bytes()}
    archive='magus-fs-0.1.0-'+AMD64+'.tar.gz';write_archive(output/archive,files)
    m['packages'].append({'role':'client','platform':AMD64,'archive':archive,
        'sha256':sha((output/archive).read_bytes()),'binary':'bin/magus-fs','binary_sha256':sha(data),
        'members':{n:sha(b) for n,b in files.items()}})
    require(source==source_manifest(),'source changed during client packaging')
    (output/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
    sums={r['archive']:r['sha256'] for r in m['packages']};sums['manifest.json']=sha((output/'manifest.json').read_bytes())
    (output/'SHA256SUMS').write_text(''.join(f'{v}  {n}\n' for n,v in sorted(sums.items())))
    return m


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output');p.add_argument('--image');p.add_argument('--host-build-proof',default=str(ROOT/'target/release/fs3-host-build.json'));p.add_argument('--prepare-host',action='store_true');p.add_argument('--client-build-proof');p.add_argument('--base-manifest');a=p.parse_args()
    if a.client_build_proof:
        if not a.base_manifest or not a.output or a.image or a.prepare_host:p.error('client-only mode requires --base-manifest and --output only')
        append_client(a.output,a.base_manifest,a.client_build_proof)
    elif a.prepare_host:host_build(a.host_build_proof)
    else:
        if not a.output or not a.image:p.error('--output and --image are required for packaging')
        package(a.output,a.image,a.host_build_proof)
if __name__=='__main__':main()
