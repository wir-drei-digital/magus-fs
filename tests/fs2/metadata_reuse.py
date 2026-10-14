"""Import-safe extraction and fixed-budget metadata comparison evidence.

Input bytes are reconstructed from retained JSON values, never described as the
original SQLite bytes. No service or mounted lifecycle is owned here.
"""
import hashlib
import json
from pathlib import Path

REVISION = 'sha256:c40d27e10a9bb39f7ce5efb438f2fa40f92f9a648f6d9fa35e5ac877c684843e'

def comparison_schedule():
 return {'warmups':100,'requests':1000,'orders':['ABC','BCA','CAB','ABC','BCA'],'budget_seconds':120}

def mounted_matrix():
 return [{'background':500,'size':s,'enabled':True} for s in (24,1024,16384)]

def comparison_gate(blocks,cold,endpoints,semantics):
 if not semantics:return {'status':'failed','reason':'semantic checks failed'}
 expected={(m,b) for b in range(5) for m in 'ABC'}
 if len(blocks)!=15 or {(r['mechanism'],r['block']) for r in blocks}!=expected or any(r.get('requests')!=1000 for r in blocks):
  return {'status':'inconclusive','reason':'fixed comparison incomplete'}
 if any(r.get('cpu_ns') is None or r.get('wall_ns') is None for r in blocks+[cold]):
  return {'status':'inconclusive','reason':'CPU or wall clock unavailable'}
 costs={m:{clock:max(r[clock]/r['requests']/(3 if m in 'AC' else 1) for r in blocks if r['mechanism']==m) for clock in ('cpu_ns','wall_ns')} for m in 'ABC'}
 projections={};failures=[];unavailable=[]
 for endpoint,e in endpoints.items():
  c={clock:cold[clock]+costs['C'][clock]*e['operations'] for clock in costs['C']}
  b={clock:costs['B'][clock]*e['operations']/3 for clock in costs['B']}
  projections[endpoint]={'operations':e['operations'],'C':c,'B_hypothetical_composite_proxy':b,'residual_cpu_ns':e['residual_cpu_ns']}
  if max(c.values())>100000000 or any(c[k]>=b[k] for k in c):
   failures.append(endpoint+': descriptor allocation exceeds 100ms or composite proxy')
  if e['residual_cpu_ns'] is None:unavailable.append(endpoint+': residual attribution unavailable');continue
  if e['residual_cpu_ns']+c['cpu_ns']>500000000:
   failures.append(endpoint+': non-descriptor CPU exceeds remaining full-target allowance')
 if failures:return {'status':'failed','reasons':failures,'projections':projections,'costs':costs}
 if unavailable:return {'status':'inconclusive','reasons':unavailable,'projections':projections,'costs':costs}
 # CPU alone is not elapsed time. Require an explicit retained scheduling allowance.
 if any(e.get('scheduling_plausible',False) is not True for e in endpoints.values()):
  return {'status':'inconclusive','reason':'retained wall/scheduling attribution cannot establish full-target plausibility','projections':projections,'costs':costs}
 return {'status':'passed','projections':projections,'costs':costs}

def extract(source,output):
 raw=Path(source).read_bytes(); snapshot=json.loads(raw)
 views=[v['descriptor'] for v in snapshot['views'] if v['projected_revision']==REVISION]
 assert views and all(v==views[0] for v in views),'retained duplicate descriptors disagree'
 assert len(views[0]['tree']['entries'])==502
 data=json.dumps(views[0],separators=(',',':')).encode()
 Path(output).write_bytes(data)
 return {'source':str(source),'retained_source_sha256':hashlib.sha256(raw).hexdigest(),'selector':{'projected_revision':REVISION},'matches':len(views),'entries':502,'input_sha256':hashlib.sha256(data).hexdigest(),'representation':'generated JSON values; canonical reconstruction by Core, not original SQLite bytes'}

def retained_endpoints(path):
 rows=json.loads(Path(path).read_text())['P2']['rows'][3:12]
 assert len(rows)==9 and all(r['enabled'] and r['background']==500 for r in rows)
 out={}
 for endpoint in ('a','b'):
  evidence=[]
  for row in rows:
   e=row['endpoints'][endpoint]
   # These two exclusive spans exclude revision_load and its nested children.
   residual=sum(e['cpu_exclusive_ns'][k] for k in ('callback','metadata_context'))
   evidence.append({'number':row['number'],'operations':e['revision_loads'],'residual_cpu_ns':residual,'stages':e['stages'],'shared_s':row['shared_s'],'peer_applied_s':row['peer_applied_s']})
  out[endpoint]={'operations':max(e['operations'] for e in evidence),'residual_cpu_ns':max(e['residual_cpu_ns'] for e in evidence),'evidence':evidence,'scheduling_plausible':False}
 return out

def main():
 import argparse,os,subprocess,time
 parser=argparse.ArgumentParser();parser.add_argument('--source',required=True);parser.add_argument('--output',required=True);parser.add_argument('--profiles',required=True);parser.add_argument('--semantics-passed',action='store_true');a=parser.parse_args()
 output=Path(a.output);output.mkdir(parents=False,exist_ok=False)
 manifest=extract(a.source,output/'input.json')
 def command(args):return subprocess.check_output(args,text=True).strip()
 manifest.update(schedule=comparison_schedule(),head=command(['git','rev-parse','HEAD']),diff=command(['git','diff','--binary']),compiler=command(['rustc','+stable','--version','--verbose']),platform=command(['uname','-a']))
 paths=command(['git','ls-files']).splitlines()+['crates/magus-fs-core/src/metadata_descriptor.rs','crates/magus-fs-core/src/metadata_descriptor_tests.rs','tests/fs2/metadata_reuse.py']
 manifest['source_sha256']={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(set(paths)) if Path(p).is_file()}
 (output/'manifest.json').write_text(json.dumps(manifest,indent=2))
 env=dict(os.environ,RUSTUP_TOOLCHAIN='stable',MAGUS_METADATA_BENCH_INPUT=str(output/'input.json'),MAGUS_METADATA_BENCH_REVISION=REVISION,MAGUS_METADATA_BENCH_OUTPUT=str(output/'blocks.jsonl'))
 cmd=['cargo','test','--release','--locked','-p','magus-fs-core','--lib','metadata_descriptor::tests::comparison','--','--ignored','--exact','--nocapture']
 manifest['command']=cmd
 (output/'manifest.json').write_text(json.dumps(manifest,indent=2))
 with (output/'command.log').open('w') as log:
  process=subprocess.Popen(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  deadline=None;terminated=False
  while process.poll() is None:
   evidence=output/'blocks.jsonl'
   if deadline is None and evidence.exists():deadline=time.monotonic()+121
   if deadline is not None and time.monotonic()>=deadline:
    import signal
    os.killpg(process.pid,signal.SIGTERM);terminated=True;break
   time.sleep(.1)
  try:code=process.wait(timeout=5)
  except subprocess.TimeoutExpired:
   import signal
   os.killpg(process.pid,signal.SIGKILL);code=process.wait()
 rows=[]
 if (output/'blocks.jsonl').exists():
  for line in (output/'blocks.jsonl').read_text().splitlines():
   try:rows.append(json.loads(line))
   except json.JSONDecodeError:rows.append({'kind':'incomplete_json','raw':line})
 endpoints=retained_endpoints(a.profiles);blocks=[r for r in rows if r.get('kind')=='block'];cold=next((r for r in rows if r.get('kind')=='cold'),{})
 gate=comparison_gate(blocks,cold,endpoints,a.semantics_passed)
 if code!=0 or terminated:gate={'status':'inconclusive','reason':'benchmark failed or supervisor terminated; partial evidence retained','projection':gate}
 (output/'decision.json').write_text(json.dumps({'exit':code,'supervisor_terminated':terminated,'gate':gate,'endpoints':endpoints,'rows':rows,'mounted':'not-run; pending coordinated P3 only if gate passes','note':'historical inode inventory invalid; CPU spans and receipts retained unchanged; nested CPU not summed with inclusive wall'},indent=2))
 print(json.dumps(gate,indent=2))
 return 0 if code==0 else 1

if __name__=='__main__':raise SystemExit(main())
