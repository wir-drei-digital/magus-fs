"""Compose reviewed real-process components with fresh ownership, without rebuilding them."""
import hashlib,json,os,time,traceback
from pathlib import Path
from infra import OwnedInfra
from provenance import verify_image,sources
from connected import Connected,inventory_code
from mounted_lifecycle import Mounted
from native_complete import Complete,mounted
from reconciliation import Reconciliation
from recovery import Recovery
from dependencies import Dependencies
from client_protocol import Journey as Client
import importlib.util

def local_module(name):
    spec=importlib.util.spec_from_file_location('poc_'+name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
q=local_module('qualification');compatibility=local_module('compatibility');offline=local_module('recovery')
BOUNDS={'connected':840,'mounted':1500,'native':600,'reconciliation':600,'recovery':600,'dependencies':600,'client':600}

def cleanup(i,j):
    j.cleanup() # Do not remove a serving container if normal unmount failed.
    mounts=[]
    for name in ['mounted-all-cleanup.json','mount-cleanup.json']:
        path=i.output/name
        if path.exists():
            rows=json.loads(path.read_text())
            if isinstance(rows,list):
                mounts += [r['mount'] for r in rows if r.get('still_mounted') is not False or r.get('exited') is not True or r.get('reaped') is not True]
    for row in getattr(j,'mounts',[]):
        if isinstance(row,dict) and mounted(Path(row['mount'])):mounts.append(row['mount'])
    pids=[]
    for ep in getattr(j,'endpoints',[]):
        if ep.platform=='macos':
            for c in ep.clients:
                pid=c.get('pid') or c.get('stopped_pid')
                if pid:
                    try:os.kill(pid,0);pids.append(pid)
                    except ProcessLookupError:pass
    for proc in getattr(j,'processes',[]):
        if proc.poll() is None:pids.append(proc.pid)
    for child in getattr(j,'children',[]):
        if child['process'].poll() is None:pids.append(child['process'].pid)
    assert not mounts and not pids,(mounts,pids)
    i.cleanup()
    lists={kind:i.docker(kind,'ls',*(['-a'] if kind=='container' else []),'--format','{{.Names}}' if kind=='container' else '{{.Name}}',evidence=False).stdout.splitlines() for kind in ['container','network','volume']}
    remaining=[r['name'] for r in i.resources if r['name'] in lists[r['kind']]]
    assert not remaining and all(r.get('removed') is True for r in i.resources)
    result={'verified':True,'mounts':mounts,'pids':pids,'resources':remaining,'lists':lists};i.write_json('final-cleanup.json',result);return result

def replacement(j):
    lazy=j.lazy;expected=j.mac_endpoint.run(inventory_code(),j.mac_client['root'])
    row=lazy.unmount('live');assert row['still_mounted'] is False
    lazy.execute("import os,shutil;assert not os.path.ismount('/shared/live');shutil.rmtree('/private/live');os.rmdir('/shared/live');print('{}')")
    lazy.mounts.remove('live');fresh=lazy.start('replacement')
    actual=lazy.execute('import json,sys,hashlib;s=json.load(sys.stdin)\n'+inventory_code(),'/shared/replacement',user='1001:1001')
    logical=lambda rows:{p:{k:v for k,v in x.items() if k not in ['uid','gid']} for p,x in rows.items()}
    assert logical(actual)==logical(expected)
    j.result['replacement']={'discarded':'/private/live','unmount':row,'fresh':fresh,'expected':logical(expected),'actual':logical(actual)}

def failure_diagnostics(i,j):
    """Read exact owned live resources before normal cleanup; never mask failure."""
    result={'containers':{},'native_logs':{}}
    for item in i.resources:
        if item['kind']!='container' or item.get('removed'):continue
        name=item['name']
        try:
            result['containers'][name]=i.inspect('container',name)['State']
            log=i.docker('logs','--tail','200',name,check=False,timeout=10)
            (i.output/('failure-'+name+'.log')).write_text(log.stdout+log.stderr)
        except Exception as error:result['containers'][name]={'diagnostic_error':str(error)}
    try:
        log=i.docker('exec',i.service,'cat','/tmp/service.log',check=False,timeout=10)
        (i.output/'failure-service.log').write_text(log.stdout+log.stderr)
    except Exception as error:result['service_error']=str(error)
    for ep in getattr(j,'endpoints',[]):
        for client in ep.clients:
            try:result['native_logs'][client['path']]=ep.run("print(json.dumps(open(s+'/daemon.log').read()))",client['path'])
            except Exception as error:result['native_logs'][client.get('path','unknown')]={'diagnostic_error':str(error)}
    i.write_json('failure-diagnostics.json',result)

def component(path,name,image,source,number):
    i=OwnedInfra(path);i.runtime_profile='release';j=None;records=[];result={'owner':i.owner,'image':image,'profile':'release','source_sha256':source['sha256'],'exit':1,'platforms':['macos','linux']};start=time.monotonic()
    def record(platform,case,**data):records.append({'platform':platform,'case':case,**data});i.write_json('raw.json',records)
    try:
        i.setup(image);i.isolate_service_control();verify_image(i,source,host_profile='release')
        if name=='connected':
            j=Connected(i,image,number)
            def editor_hook(ep,c,lazy):j.editor_result=compatibility.editor(j,ep,c,lazy)
            j.editor_hook=editor_hook;j.run();replacement(j);archive=offline.restore(j)
            records=[{'case':'connected','journey':j.result,'editor':j.editor_result,'archive':archive}]
        elif name=='mounted':j=Mounted(i,image,agents=True);j.run();records=j.records
        elif name=='native':j=Complete(i,image,['macos','linux'],['structural','recovery','causality','races','nfs']);j.record=record;j.run()
        elif name=='reconciliation':j=Reconciliation(i,image,['macos','linux'],['merge','conflicts','scoped']);j.record=record;j.run()
        elif name=='recovery':j=Recovery(i,image,['macos','linux'],['history','reconnect','offline','storage']);j.record=record;j.run()
        elif name=='dependencies':
            j=Dependencies(i,image,[]);j.record=record;j.run();j.configured();j.mounted_report();j.publication_routes_and_races();j.scoped_and_revoke();record('service','dependency-declarations',requests=j.declared,policy=j.policy)
        elif name=='client':
            j=Client(i);j.run();records=[{'case':'client-protocol','drain_owner':json.loads((i.output/'drain-owner.json').read_text()),'checkpoint_admission':json.loads((i.output/'checkpoint-admission.json').read_text())}]
        assert time.monotonic()-start<=BOUNDS[name],('component bound',name)
        assert sources()==source['sha256'];result['exit']=0
    except Exception as e:
        i.write_json('failure.json',{'reason':str(e),'trace':traceback.format_exc()})
        try:failure_diagnostics(i,j)
        except Exception as diagnostic_error:i.write_json('diagnostic-error.json',{'reason':str(diagnostic_error)})
        raise
    finally:
        result['seconds']=time.monotonic()-start
        try:
            result['cleanup']=cleanup(i,j) if j else (i.cleanup() or {'verified':True,'mounts':[],'pids':[],'resources':[]})
            if name=='connected' and records:
                records[0]['journey']['cleanup']={**result['cleanup'],'containers':[],'resources_removed':True}
                j.save_result()
        except Exception as error:
            result['exit']=1;i.write_json('cleanup-failure.json',{'reason':str(error),'trace':traceback.format_exc()});raise
        finally:
            i.write_json('raw.json',records);result['raw']=q.artifact(i.output/'raw.json');i.write_json('component.json',result)
    return result

def run(output,image,source,number):
    owner=OwnedInfra(output);result={'owner':owner.owner,'components':{}};start=time.monotonic()
    for name in BOUNDS:
        print(json.dumps({'journey':number,'component':name,'output':str(output/name)}),flush=True)
        result['components'][name]=component(output/name,name,image,source,number);owner.write_json('journey.json',result)
        assert time.monotonic()-start<=5400,'whole journey bound'
    result['seconds']=time.monotonic()-start;owner.write_json('journey.json',result);return result
