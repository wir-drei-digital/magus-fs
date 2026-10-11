"""Final evidence integrity gate; does not run or reinterpret filesystem scenarios."""
import hashlib,json,os
from pathlib import Path
MANDATORY=('raw.json','observations.json','commands.json','ownership.json','image-source.json','final-cleanup.json','component.json')
EXCLUDED={'result.json','evidence.json','artifact-manifest.json','audit-result.json','host-audit-bridge.json'}
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')
def required_paths(e):
    paths=[]
    assert len(e['journeys'])==2,'two complete journeys required before evidence seal'
    for journey in e['journeys']:
        for name,component in journey['components'].items():
            root=Path(component['raw']['path']).parent
            for leaf in MANDATORY:
                path=root/leaf;assert path.is_file() and not path.is_symlink(),('mandatory evidence absent',name,leaf);paths.append(path)
            observations=json.loads((root/'observations.json').read_text());assert isinstance(observations,list) and observations,'empty HTTP evidence'
            commands=json.loads((root/'commands.json').read_text());assert isinstance(commands,list) and commands,'empty command evidence'
            for command in commands:
                path=root/command['log'];assert path.is_file() and not path.is_symlink(),('command evidence absent',str(path));paths.append(path)
    return paths

def seal(output,e):
    output=Path(output);mandatory=required_paths(e);entries=[]
    for path in sorted(output.rglob('*')):
        if path.parent==output and path.name in EXCLUDED:continue
        if path.is_symlink():entries.append({'path':str(path),'kind':'symlink','target':os.readlink(path)})
        elif path.is_file():entries.append({'path':str(path),'kind':'file','bytes':path.stat().st_size,'sha256':digest(path)})
    listed={r['path'] for r in entries};assert all(str(p) in listed for p in mandatory)
    manifest=output/'artifact-manifest.json';write(manifest,{'scope':'all retained owned output files except final self-referential result/evidence/audit envelopes','output':str(output),'mandatory':[str(p) for p in mandatory],'entries':entries})
    return {'path':str(manifest),'sha256':digest(manifest)}

def verify(ref,e):
    path=Path(ref['path']);assert digest(path)==ref['sha256'],'manifest hash changed'
    manifest=json.loads(path.read_text());required=required_paths(e);entries=manifest['entries'];assert len({x['path'] for x in entries})==len(entries),'duplicate manifest path'
    assert set(map(str,required))<=set(manifest['mandatory']) and set(manifest['mandatory'])<={r['path'] for r in entries}
    for row in entries:
        p=Path(row['path'])
        if row['kind']=='symlink':assert p.is_symlink() and os.readlink(p)==row['target'],('changed symlink',str(p))
        else:assert p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and digest(p)==row['sha256'],('changed artifact',str(p))
    return {'verified':True,'files':len(entries),'mandatory_files':len(set(manifest['mandatory'])),'manifest':ref}

def finalize(output,result):
    if result['exit']!=0:return result
    try:
        ref=seal(output,result['evidence']);proof=verify(ref,result['evidence']);return {**result,'artifact_integrity':proof}
    except (AssertionError,KeyError,ValueError,TypeError,OSError) as error:
        return {**result,'exit':1,'passed':False,'errors':[*result['errors'],'raw evidence integrity: '+str(error)]}
