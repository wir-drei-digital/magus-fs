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
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase',choices=(*PHASES,'all'),required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--image');parser.add_argument('--package-manifest',type=Path);parser.add_argument('--provider-config',type=Path);a=parser.parse_args()
    if not a.output.is_absolute():parser.error('new absolute output required')
    a.output.mkdir(mode=0o700);phases={}
    for name in PHASES if a.phase=='all' else (a.phase,):
        missing=[];argv=[sys.executable,str(Path(__file__).with_name(name+'.py')),'--output',str(a.output/name)]
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
if __name__=='__main__':sys.exit(main())
