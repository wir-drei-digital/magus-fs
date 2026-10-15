#!/usr/bin/env python3
"""Finite phase dispatcher. Missing hosted execution cannot qualify FS3."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

PHASES=('isolation','scale','packaging','provider')
def aggregate(phases):
    failures=[];blocked=[]
    for name in PHASES:
        row=phases.get(name)
        if row is None:blocked.append(name+': missing evidence');continue
        if row.get('phase')!=name or row.get('status') not in ('passed','failed','blocked'):failures.append(name+': invalid evidence');continue
        failures.extend(name+': '+str(s) for s in row.get('failures',[]))
        blocked.extend(name+': '+str(s) for s in row.get('blocked',[]))
        if row['status']=='failed':failures.append(name+': phase failed')
        if row['status']=='blocked':blocked.append(name+': phase blocked')
    return {'schema':1,'phase':'all','status':'failed' if failures else 'blocked' if blocked else 'passed','phases':phases,'failures':failures,'blocked':blocked}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase',choices=(*PHASES,'all'),required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--image');parser.add_argument('--package-manifest',type=Path);parser.add_argument('--provider-config',type=Path);parser.add_argument('--evidence-manifest',type=Path);a=parser.parse_args()
    if not a.output.is_absolute():parser.error('new absolute output required')
    a.output.mkdir(mode=0o700);phases={}
    if a.evidence_manifest:
        if a.phase!='all':parser.error('--evidence-manifest requires --phase all')
        try:result=aggregate_existing(a.evidence_manifest)
        except (OSError,ValueError,KeyError,AssertionError) as error:result={'schema':1,'phase':'all','status':'failed','failures':['retained evidence validation: '+str(error)],'blocked':[]}
        (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return {'passed':0,'failed':1,'blocked':2}[result['status']]
    for name in PHASES if a.phase=='all' else (a.phase,):
        missing=[];argv=[sys.executable,str(Path(__file__).with_name(('daytona' if name=='provider' else name)+'.py')),'--output',str(a.output/name)]
        if name in ('isolation','scale'):
            if a.image:argv+=['--image',a.image]
            else:missing.append('immutable --image required')
        if name in ('packaging','provider'):
            if a.package_manifest:argv+=['--package-manifest',str(a.package_manifest)]
            else:missing.append('--package-manifest required')
        if name=='provider':
            if a.provider_config:argv+=['--provider-config',str(a.provider_config)]
            else:missing.append('private --provider-config required')
            if not Path(argv[1]).is_file():missing.append('actual provider phase not implemented/qualified')
        if missing:row={'schema':1,'phase':name,'status':'blocked','failures':[],'blocked':missing,'executed':False}
        else:
            with (a.output/(name+'.log')).open('x') as log:
                try:p=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=3600);code=p.returncode
                except subprocess.TimeoutExpired:code=124
            result=a.output/name/'result.json'
            row=json.loads(result.read_text()) if result.exists() else {'schema':1,'phase':name,'status':'failed','failures':['no phase result'],'blocked':[]}
            row['runner']={'argv':argv,'exit':code,'raw_result':str(result)}
            expected={'passed':0,'failed':1,'blocked':2}.get(row.get('status'))
            if code!=expected:row['status']='failed';row.setdefault('failures',[]).append('phase exit/result mismatch')
        phases[name]=row
        (a.output/'progress.json').write_text(json.dumps(phases,indent=2)+'\n')
    result=aggregate(phases) if a.phase=='all' else phases[a.phase]
    (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');return {'passed':0,'failed':1,'blocked':2}[result['status']]



# Exact reviewed Task2 classification correction; no retry/deadline/permission changes.
REVIEWED_RUNTIME_DELTAS = {
    # Task2's source-included regression tests; exact pair, not a test-path exclusion.
    'crates/magus-fs/src/sync/transport_pool_tests.rs': {'earlier':'041356552a2feb7cd0334c7b77f44fae0555ff28920d4063580314877b725adc','current':'13fb145e54792d5a5d1a096a48cd06bc023a5d4e2e8d8eacd7650bbbd8a8d102'},
    'crates/magus-fs/src/sync/controller.rs': {'earlier':'8bbfcf5611c7314019a014214a9677796f93b4b26a106194f0b0693d35c5adda','current':'af0d0d3e3401f0fe5f9a7425dec2f62eb18c05dd92662ac8c3a799970fdd6d52'},
    'crates/magus-fs/src/sync/executor.rs': {'earlier':'2dbad708358bee5ac43cad1a1411570276408e4968972a10b4d0a64431e844f6','current':'968a5eb17910aaf1e3dd7a5f5b594bf1c068feac26582b1db9ecdb450ea0bde6'},
}


def validate_source_compatibility(earlier,current,declared):
    from common import LICENSE_METADATA
    actual={name:{'earlier':earlier.get(name),'current':current.get(name)}
            for name in sorted(set(earlier)|set(current)) if earlier.get(name)!=current.get(name)}
    if actual!=declared:raise ValueError('exact source delta does not match')
    for name,change in actual.items():
        runtime=(name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml','.dockerignore')
                 or name.startswith(('src/','vendor/','benches/'))
                 or (name.startswith('crates/') and '/tests/' not in name))
        license_change=LICENSE_METADATA.get(name)
        allowed_license=license_change and change=={'earlier':license_change['image'],'current':license_change['current']}
        # FS2 source inventory omitted this build-context file; exact bytes are
        # independently present in the accepted Task3 package source manifest.
        inventory_extension=(name=='.dockerignore' and change=={'earlier':None,'current':'7f87da1ac69257af86492041d397536a33c61a6e88bcef46c1b75fde060aa7ed'})
        if runtime and not inventory_extension and change!=REVIEWED_RUNTIME_DELTAS.get(name) and not allowed_license:
            raise ValueError('unreviewed runtime source delta: '+name)
    return actual


def aggregate_existing(index_path):
    """Validate retained phase files without launching services or repeating matrices.

    The index binds every input digest and enumerates every source delta. It is a
    reviewable composition, never a new execution of earlier scenarios.
    """
    import hashlib
    from qualification import normalize
    root=Path(__file__).resolve().parents[2]
    sys.path.insert(0,str(root/'scripts'))
    from package import source_manifest,canonical_sha
    index=json.loads(Path(index_path).read_text())
    current=source_manifest()
    if index.get('current_source')!=current:raise ValueError('current source snapshot differs')
    phases={};bindings={}
    for phase in PHASES:
        entry=index.get('phases',{}).get(phase)
        if entry is None:continue
        path=Path(entry['result'])
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise ValueError('phase result hash differs: '+phase)
        row=json.loads(raw)
        if row.get('phase')!=phase:raise ValueError('phase name mismatch: '+phase)
        if row.get('executed') is False:
            if row.get('status')=='passed':raise ValueError('unexecuted evidence cannot pass')
            phases[phase]=row
            bindings[phase]={'result':str(path),'sha256':entry['sha256'],'executed':False}
            continue
        earlier=entry['source']
        if canonical_sha(earlier)!=row.get('source',{}).get('manifest_sha256'):
            raise ValueError('executed source digest differs: '+phase)
        # Older source inventories did not include docs/scripts/license files.
        # Explicit absence is retained as a named delta, not silently excluded.
        delta=validate_source_compatibility(earlier,current,entry['differences'])
        phases[phase]=normalize(row)
        bindings[phase]={'result':str(path),'sha256':entry['sha256'],'source_sha256':canonical_sha(earlier),'differences':delta,'review':entry.get('review')}
    result=aggregate(phases)
    result['composition']={'new_execution':False,'current_source_sha256':canonical_sha(current),'bindings':bindings}
    return result


if __name__=='__main__':sys.exit(main())
