#!/usr/bin/env python3
"""Real Daytona proof driver. Preflight never provisions or qualifies a phase."""
import re


def _sha(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def _recovered(row,save):
    return (row.get('independent') is True and row.get('sandbox_disk_used') is False
            and _sha(save.get('sha256')) and row.get('sha256')==save.get('sha256')
            and bool(save.get('revision')) and row.get('revision')==save.get('revision')
            and bool(row.get('provenance')))


def _complete_recovery(row, save, m):
    return (_recovered(row,save) and row.get('service_only') is True
            and row.get('whole_fixture') is True and row.get('private_closure_verified') is True
            and row.get('manifest_sha256')==save.get('manifest_sha256')
            and bool(row.get('state_id')) and row.get('run_id')==m.get('run_id')
            and row.get('sandbox_id')==m.get('owned_sandbox_id') and _sha(row.get('provenance')))


def completion_failures(m):
    """Pre-delete disposable completion only; final absence/recovery are checked later.

    This validates controller observations, not arbitrary external claims. The driver
    must hash and retain the raw observations from which these fields are derived.
    """
    errors=[]
    def require(ok,message):
        if not ok:errors.append(message)
    require(m.get('lifecycle')=='disposable-daytona','unsupported completion lifecycle')
    owned=m.get('owned_sandbox_id');run=m.get('run_id')
    require(bool(owned) and owned==m.get('provider',{}).get('sandbox_id') and bool(run),'owned identity missing')
    f=m.get('freeze',{});save=m.get('save',{});before=m.get('recovery_before',{})
    require(f.get('run_id')==run and f.get('sandbox_id')==owned
        and all(f.get(k) is True for k in ('dispatch_disabled','writers_reaped'))
        and all(f.get(k)==[] for k in ('unknown_writers','writers_before','writers_after'))
        and _sha(f.get('provenance')),'writer boundary uncertain')
    require(type(f.get('generation_before')) is int and f['generation_before']==f.get('generation_after')
        and _sha(f.get('manifest_before')) and f['manifest_before']==f.get('manifest_after')
        and f['manifest_before']==save.get('manifest_sha256'),'frozen fixture changed')
    receipt=save.get('private_receipt',{});shared=save.get('shared_receipt',{})
    require(save.get('ack_certain') is True and save.get('server_confirmed') is True
        and bool(save.get('operation')) and bool(save.get('receipt')) and _sha(save.get('provenance'))
        and all(bool(save.get(k)) for k in ('revision','replica','original_view','original_head','shared_head'))
        and receipt.get('submitted_revision')==save.get('revision')
        and all(receipt.get(k)==save.get(k) for k in ('replica','original_view','original_head'))
        and bool(receipt.get('receipt')) and save.get('receipt')==receipt.get('receipt')
        and save.get('integration',{}).get('candidate_receipt')==receipt.get('receipt')
        and shared.get('submitted_revision')==save.get('revision')
        and shared.get('head')==save.get('shared_head'),'exact private/Shared server binding missing')
    a=m.get('accounting',{});work=a.get('work',[]);exclusions=a.get('exclusions',[])
    replicas=a.get('replicas',[])
    require(a.get('complete') is True and bool(replicas) and len(set(replicas))==len(replicas)
        and save.get('replica') in replicas and _sha(a.get('provenance')),'replica accounting incomplete')
    ids=[row.get('id') for row in work];excluded=[row.get('id') for row in exclusions]
    require(all(ids) and len(set(ids))==len(ids) and all(excluded)
        and len(set(excluded))==len(excluded),'duplicate/missing accounting identity')
    covered=set()
    for row in work:
        disposition=row.get('disposition')
        valid=row.get('replica') in replicas
        if row.get('intended') is True and row.get('unique') is True:
            valid=valid and row.get('ack_certain') is True
        if disposition=='included':
            valid=valid and row.get('revision')==save.get('revision') and row.get('ack_certain') is True
            if valid:covered.add(row.get('id'))
        elif disposition in ('remote-recoverable','exported'):
            valid=valid and row.get('independently_verified') is True and _sha(row.get('content_sha256')) and _sha(row.get('provenance'))
            if valid:covered.add(row.get('id'))
        elif disposition=='excluded':
            valid=valid and row.get('intended') is False and row.get('id') in excluded
        elif disposition=='superseded':
            valid=valid and row.get('unique') is False
        else:valid=False
        require(valid,'unaccounted work: '+str(row.get('id')))
    for row in work:
        if row.get('disposition')=='superseded':
            require(row.get('covered_by') in covered,'superseded work coverage missing')
    for row in exclusions:
        valid=bool(row.get('reason')) and all(_sha(row.get(k)) for k in
            ('input_sha256','denial_provenance','local_recovery_provenance'))
        if row.get('disposition')=='synthetic-abandonment':
            valid=valid and row.get('input_sha256')==row.get('external_input_sha256') and _sha(row.get('external_provenance'))
        elif row.get('disposition')=='exported':
            valid=valid and row.get('input_sha256')==row.get('export_sha256') and row.get('independently_verified') is True and _sha(row.get('export_provenance'))
        else:valid=False
        require(valid,'unproven synthetic exclusion: '+str(row.get('id')))
    require(_complete_recovery(before,save,m),'independent whole-fixture recovery missing')
    sequence=[f.get('sequence'),save.get('sequence'),before.get('sequence'),f.get('recheck_sequence')]
    require(all(type(n) is int for n in sequence) and sequence==sorted(set(sequence)),'completion ordering uncertain')
    return errors


def deletion_permitted(measurements):
    """Receipt certainty and independent recovery are mandatory deletion guards."""
    if measurements.get('lifecycle')=='disposable-daytona':
        return not completion_failures(measurements)
    if measurements.get('lifecycle','normal')!='normal':return False
    save=measurements.get('save',{})
    before=measurements.get('recovery_before',{})
    unmount=measurements.get('unmount',{})
    return (save.get('ack_certain') is True and bool(save.get('operation'))
            and bool(save.get('receipt')) and _recovered(before,save)
            and isinstance(save.get('sequence'),int)
            and isinstance(before.get('sequence'),int)
            and save['sequence']<before['sequence']
            and all(unmount.get(k) is True for k in ('normal','kernel_absent','helpers_stopped'))
            and isinstance(unmount.get('sequence'),int)
            and before['sequence']<unmount['sequence'])


def validate_provider(m):
    failures=[]
    def require(ok,message):
        if not ok:failures.append(message)
    provider=m.get('provider',{})
    require(provider.get('name')=='daytona' and provider.get('execution')=='remote-ssh'
            and all(provider.get(k) for k in ('sandbox_id','architecture','snapshot','version','provenance')),
            'actual Daytona execution missing')
    package=m.get('package',{})
    require(package.get('verified') is True
            and all(_sha(package.get(k)) for k in ('manifest_sha256','archive_sha256','expected_binary_sha256','executed_binary_sha256'))
            and package.get('expected_binary_sha256')==package.get('executed_binary_sha256')
            and {'x86_64':'x86_64-unknown-linux-gnu','aarch64':'aarch64-unknown-linux-gnu'}.get(provider.get('architecture'))==package.get('platform'),
            'exact package binding missing')
    mount=m.get('mount',{})
    require(all(mount.get(k) is True for k in ('kernel_mounted','ordinary_io')) and bool(mount.get('provenance')),
            'actual ordinary provider mount missing')
    require(isinstance(mount.get('workload_uid'),int) and mount['workload_uid']>0
            and mount.get('control_uid')==0 and mount.get('workload_sudo_denied') is True
            and mount.get('control_credentials_unreadable') is True,
            'workload/control separation missing')
    for case in ('scope','readonly','private-history','api-bypass','revoked-reconnect','cold-warm-range'):
        row=m.get('cases',{}).get(case,{})
        require(row.get('passed') is True and bool(row.get('provenance')),'hosted assertion missing: '+case)
    save=m.get('save',{})
    before=m.get('recovery_before',{})
    after=m.get('recovery_after',{})
    require(_recovered(before,save),'independent pre-deletion recovery missing')
    require(_recovered(after,save),'independent post-deletion recovery missing')
    deletion=m.get('deletion',{})
    disposable=m.get('lifecycle')=='disposable-daytona'
    if disposable:
        failures.extend(completion_failures(m))
        require(_complete_recovery(after,save,m) and after.get('state_id')!=before.get('state_id'),
                'fresh independent post-deletion fixture recovery missing')
        require(deletion.get('terminal') is True and deletion.get('ssh_unusable') is True
                and _sha(deletion.get('provenance')),'terminal provider absence uncertain')
    boundary=m.get('freeze' if disposable else 'unmount',{})
    require(deletion_permitted(m) and isinstance(deletion.get('sequence'),int)
            and boundary.get('recheck_sequence' if disposable else 'sequence',float('inf'))<deletion['sequence']
            and isinstance(after.get('sequence'),int) and deletion['sequence']<after['sequence'],
            'unsafe deletion ordering')
    require(deletion.get('owned') is True and deletion.get('sandbox_id')==provider.get('sandbox_id')
            and deletion.get('confirmed_absent') is True and m.get('cleanup',{}).get('unresolved')==[],
            'provider resources unresolved')
    return failures


def preflight(config,manifest_path):
    """Inspect configuration and hashes only; never create or delete resources."""
    import hashlib
    import json
    from pathlib import Path
    missing=[]
    failures=[]
    capability=config.get('capability_evidence',{})
    unresolved=bool(capability.get('sandbox_id')) and capability.get('removed') is not True
    if unresolved and capability.get('normal_unmount') is not True:
        failures.append('owned capability mount cleanup unresolved')
    if not config.get('daytona_env_file'):missing.append('private daytona_env_file required')
    if not config.get('service_url'):missing.append('non-production HTTPS service endpoint required')
    elif not config['service_url'].startswith('https://'):failures.append('service endpoint must use HTTPS')
    for field in ('service_ca_file','client_config_file'):
        if not config.get(field):missing.append('private '+field+' required')
        elif not Path(config[field]).is_file():missing.append(field+' unavailable')
    package={}
    if manifest_path is None:missing.append('package manifest required')
    else:
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
        from package import load_manifest
        try:
            manifest_path=Path(manifest_path)
            manifest=load_manifest(manifest_path)
            package['manifest_sha256']=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            package['platforms']=sorted({p['platform'] for p in manifest['packages']})
            for row in manifest['packages']:
                blob=(manifest_path.parent/row['archive']).read_bytes()
                if hashlib.sha256(blob).hexdigest()!=row['sha256']:
                    failures.append('package archive hash mismatch')
            arch=capability.get('architecture')
            target={'x86_64':'x86_64-unknown-linux-gnu','aarch64':'aarch64-unknown-linux-gnu'}.get(arch)
            if target and target not in package['platforms']:missing.append('exact observed provider architecture package unavailable: '+target)
        except (OSError,ValueError,KeyError):failures.append('package manifest unavailable or invalid')
    permissions=[]
    if config.get('daytona_env_file'):
        try:
            permissions=DaytonaAPI(Path(config['daytona_env_file'])).current_permissions()
            if not {'write:sandboxes','delete:sandboxes'}<=set(permissions):missing.append('Daytona lifecycle permissions unavailable')
        except (OSError,ValueError):missing.append('Daytona read-only account preflight unavailable')
    missing.append('read-only preflight does not qualify actual mounted provider execution')
    return {'schema':1,'phase':'provider','status':'failed' if failures else 'blocked',
            'executed':False,'preflight':True,'failures':failures,'blocked':missing,
            'resources_created':[], 'permissions':permissions,'package':package,
            'capability_evidence':capability,
            'cleanup':{'ok':not unresolved,'mounts_absent':not unresolved,'resources_removed':not unresolved,
                       'provenance':'read-only preflight; referenced unresolved resources remain owned'}}


class DaytonaAPI:
    """Official REST API, stdlib transport. Values never enter logs or argv."""
    BASE='https://app.daytona.io/api'

    def __init__(self,env_path):
        self._key=None
        with env_path.open() as source:
            for line in source:
                key,sep,value=line.strip().removeprefix('export ').partition('=')
                if sep and key=='DAYTONA_API_KEY':
                    self._key=value.strip().strip('\"').strip("'")
        if not self._key:raise ValueError('required Daytona key unavailable')

    def current_permissions(self):
        import json
        import urllib.request
        # GET only: preflight cannot provision, expose ports, or alter lifecycle.
        request=urllib.request.Request(self.BASE+'/api-keys/current',headers={'Authorization':'Bearer '+self._key})
        with urllib.request.urlopen(request,timeout=20) as response:
            data=json.load(response)
        return sorted(data.get('permissions',[]))


def current_ledger(path):
    import json
    rows=json.loads((path/'commands.json').read_text())
    logs=[r.get('log') for r in rows]
    if len(set(logs))!=len(logs) or any(n!='command-'+str(k)+'.log' for k,n in enumerate(logs)):
        raise ValueError('ambiguous command ledger; preserve resources')
    return rows


def retained_mount(row,name):
    from common import ROOT
    from connected import kernel_mount_present
    command=row.get('command',[])
    return (kernel_mount_present('/shared/'+name,row.get('mountinfo',''))
        and row.get('pid')==row.get('expected_pid') and type(row.get('pid')) is int
        and _sha(row.get('binary_sha256')) and row['binary_sha256']==row.get('expected_binary_sha256')
        and command[:2]==['/opt/fs3-task4/bin/magus-fs','mount']
        and '--state' in command and command[command.index('--state')+1]=='/private/'+name+'/state'
        and '--mountpoint' in command and command[command.index('--mountpoint')+1]=='/shared/'+name)



def observe_retained_mount(remote,name,expected_pid,expected_binary_sha256=None):
    """Read kernel/process identities without stat-based mount authority or remount."""
    proof=remote.execute('''import json,sys,os,hashlib
from pathlib import Path
s=json.load(sys.stdin);pid=int(Path('/private/'+s['name']+'/pid').read_text());proc=Path('/proc')/str(pid)
expected=s['expected_binary_sha256'] or hashlib.sha256(Path('/opt/fs3-task4/bin/magus-fs').read_bytes()).hexdigest()
print(json.dumps({'pid':pid,'expected_pid':s['expected_pid'],'binary_sha256':hashlib.sha256((proc/'exe').read_bytes()).hexdigest(),
 'expected_binary_sha256':expected,'command':[x.decode() for x in (proc/'cmdline').read_bytes().split(b'\\0') if x],
 'mountinfo':Path('/proc/self/mountinfo').read_text(),'stat_ismount':os.path.ismount('/shared/'+s['name'])}))''',
        {'name':name,'expected_pid':expected_pid,'expected_binary_sha256':expected_binary_sha256})
    assert retained_mount(proof,name),'retained mount/daemon identity changed'
    return proof


def revoked_reconnect_case(remote,denied,before):
    """Producer and assertion reader share the full retained_mount proof schema."""
    assert retained_mount(before,'a2'),'pre-disconnect identity uncertain'
    proof=observe_retained_mount(remote,'a2',before['pid'],before['binary_sha256'])
    status=remote.status('a2')
    assert denied and set(denied.values())=={13} and status['live']['authorized'] is False
    return {'denied':denied,'retained_mount':True,'status':status,'transport_reconnect_only':True,
            'pre_disconnect_kernel_daemon_proof':before,'kernel_daemon_proof':proof}

class RemoteMount:
    """Existing Lazy CLI boundary carried over private SSH; workload is UID1002."""
    def __init__(self,journey,config,output):
        self.owner=journey;self.i=journey.i;self.config=config;self.output=output
        import json
        self.mounts=[];self.frozen=False
        log=self.i.output/'hosted-commands.json'
        self.commands=json.loads(log.read_text()) if log.exists() else []

    def execute(self,code,settings=None,user='0:0',check=True):
        import json,subprocess,shlex,time
        from connected import public_settings
        workload=user!='0:0'
        if workload and (self.frozen or (self.output/'freeze-dispatch.json').exists()):
            raise RuntimeError('workload dispatch frozen')
        argv=['ssh','-T','-F',self.config['ssh_config'],self.config['ssh_host'],
            'sudo -n '+('-u fs3work ' if workload else '')+'python3 -c '+shlex.quote(code)]
        start=time.monotonic()
        p=subprocess.run(argv,input=json.dumps(settings),capture_output=True,text=True,timeout=75)
        row={'code':code,'settings':public_settings(settings),'workload_uid':1002 if workload else 0,
             'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'seconds':time.monotonic()-start}
        self.commands.append(row);self.i.write_json('hosted-commands.json',self.commands)
        if check:assert p.returncode==0,('remote command failed',len(self.commands)-1)
        return json.loads(p.stdout) if p.returncode==0 else p

    def cli(self,*args):
        r=self.execute("import json,subprocess,sys;s=json.load(sys.stdin);p=subprocess.run(['/opt/fs3-task4/bin/magus-fs',*s],capture_output=True,text=True);print(json.dumps({'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}))",list(args))
        value=__import__('json').loads(r['stdout']);assert r['exit']==0 and value.get('ok') is True,r
        return value

    def status(self,name):return self.cli('sync','status','--state','/private/'+name+'/state')
    def read(self,path):return self.execute("import json,sys;print(json.dumps(open('/shared/'+json.load(sys.stdin),'rb').read().hex()))",path,user='1002:1002')
    def has(self,path):return self.execute("import json,sys,os;print(json.dumps(os.path.exists('/shared/'+json.load(sys.stdin))))",path,user='1002:1002')

    def start(self,name,readonly=False,publication='isolated',actor='alice',replica_identity=None,principal=None,group=None,additional_authorities=()):
        from service_storage import NS,ALICE
        from service_protocol import GROUP
        settings={'name':name,'replica':replica_identity,'principal':principal or ALICE,'group':group or GROUP,
            'token':self.owner.tokens[actor],'ca':(self.i.control/'ca.crt').read_text(),
            'endpoint':self.config['service_url'],'namespace':self.config['namespace'],'readonly':readonly,'publication':publication}
        self.mounts.append(name)
        self.i.write_json('hosted-mount-ownership.json',{'sandbox_id':self.config['sandbox_id'],'mounts':self.mounts})
        return self.execute('''import json,os,subprocess,sys,time
s=json.load(sys.stdin);name=s['name'];control='/private/'+name
os.makedirs('/private',mode=0o700,exist_ok=True);os.chmod('/private',0o700)
os.makedirs('/shared',mode=0o755,exist_ok=True);os.mkdir(control,0o700)
def private(n,v):
 p=control+'/'+n;fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'w') as f:f.write(v if isinstance(v,str) else json.dumps(v))
 return p
def cli(*args):
 p=subprocess.run(['/opt/fs3-task4/bin/magus-fs',*args],capture_output=True,text=True);r=json.loads(p.stdout)
 assert p.returncode==0 and r.get('ok') is True,(args,p.stdout,p.stderr)
 return r
mount='/shared/'+name
config={'replica':{'replica':s['replica'],'authorities':[{'principal':s['principal'],'uid':1002,'gid':1002,'primary_group':s['group'],'groups':[s['group']],'dac_override':False,'ownership_transfer':False},{'principal':'principal:'+'c'*32,'uid':0,'gid':0,'primary_group':'group:'+'c'*32,'groups':['group:'+'c'*32],'dac_override':True,'ownership_transfer':True}],'content_roots':[mount],'cache_bytes':96*1024*1024},'root':mount,'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
cli('init','--state',control+'/state','--config',private('config',config))
profile=private('profile',{'endpoint':s['endpoint'],'namespace':s['namespace'],'replica':s['replica'],'ca_file':private('ca',s['ca']),'token_file':private('token',s['token']),'publication_principal':s['principal']})
attached=cli('sync','attach','--state',control+'/state','--profile',profile,'--branch','main','--publication',s['publication'])
argv=['/opt/fs3-task4/bin/magus-fs','mount','--state',control+'/state','--revision',attached['binding']['view']['revision'],'--mountpoint',mount,'--mode','read-only' if s['readonly'] else 'private']
log=open(control+'/daemon.log','w');p=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True);private('pid',str(p.pid))
end=time.monotonic()+10
while not os.path.ismount(mount):
 assert p.poll() is None,(p.poll(),open(control+'/daemon.log').read())
 assert time.monotonic()<end,'mount deadline';time.sleep(.05)
print(json.dumps({'pid':p.pid,'binding':attached['binding'],'attach_counters':attached['counters'],'kernel_mounted':os.path.ismount(mount)}))''',settings)


def resume_service(path):
    """Reconstruct only recorded primitives; never reprovision a resumed service."""
    import json,ssl
    from pathlib import Path
    from common import PhaseInfra
    from service_protocol import Journey
    from service_storage import ALICE,NS
    path=Path(path);state=json.loads((path/'control/resume-infra.json').read_text())
    i=object.__new__(PhaseInfra)
    for key in ('owner','resources','commands','net','ingress','pgvol','s3vol','pg','s3','service','port','access','secret'):
        setattr(i,key,state[key])
    i.output=path;i.control=path/'control'
    i.commands=current_ledger(path)
    i.resources=json.loads((path/'ownership.json').read_text())['resources']
    for row in i.resources:i.validate_owned(row,i.inspect(row['kind'],row['name']))
    records=[]
    for p in i.control.glob('provision-*.json'):records.extend(json.loads(p.read_text()))
    owner=next(r for r in records if r.get('root_policy') and r['principal']==ALICE)
    j=object.__new__(Journey);j.i=i;j.ca=ssl.create_default_context(cafile=str(i.control/'ca.crt'))
    j.tokens={'alice':owner['token']};j.root='/v1/n/'+NS;j.tree_root=owner['root_policy'];j.observations=[]
    j.image=json.loads((path/'tls-state.json').read_text())['image']
    assert j.request('GET','/health')[0]==200
    return i,j


def prepare_hosted(config,output):
    """One initial fixture/first mount, with private primitive recovery state."""
    import json,secrets,time
    from pathlib import Path
    i,j=resume_service(config['owned_service_dir'])
    from service_storage import NS,ALICE,BOB
    from service_protocol import GROUP,REPLICA,identity,file_entry
    output=Path(output)
    namespace=config['namespace'];assert namespace!=NS and len(namespace)==32
    j.root='/v1/n/'+namespace
    j.create=lambda actor='alice':j.expect('create-'+actor,'POST',j.root+'/uploads',201,actor=actor,body={})['upload']
    j.tree_root={'id':identity('entry'),'owner':ALICE,'group':GROUP,'mode':0o755}
    remote=RemoteMount(j,config,output)
    identities={name:{'principal':BOB if name=='b' else ALICE,
        'replica':REPLICA if name=='a1' else identity('replica'),'group':GROUP}
        for name in ('a1','a2','b','readonly')}
    j.tokens={}
    state_path=i.control/('hosted-resume-'+namespace+'.json')
    prior=json.loads(state_path.read_text()) if state_path.exists() else None
    if prior:
        assert prior['config']==config and prior['output']==str(output),'resume identity mismatch'
        identities=prior['identities'];j.tokens=prior['tokens'];j.tree_root=prior['tree_root']
    rows=[]
    for name,actor in identities.items():
        if name not in j.tokens:j.tokens[name]=secrets.token_hex(32)
        rows.append({'namespace':namespace,'principal':actor['principal'],'replica':actor['replica'],
            'token':j.tokens[name],'expires':int(time.time())+3600,
            'actions':['read'] if name=='readonly' else ['read','write','history','integrate','admin'],
            'branches':['main'],'prefixes':['reports'] if name in ('a2','readonly') else [''],
            'authority':{'principal':actor['principal'],'uid':1002,'gid':1002,'primary_group':GROUP,
                'groups':[GROUP],'dac_override':False,'ownership_transfer':False},
            **({'root_policy':j.tree_root} if name=='a1' else {})})
    # Persist secrets only in the owned fixture's private control directory.
    state={'tokens':j.tokens,'tree_root':j.tree_root,'identities':identities,'image':j.image,
           'config':config,'output':str(output),'steps':{}}
    j.tokens['alice']=j.tokens['a1']
    if prior:state=prior
    else:state_path=i.private('hosted-resume-'+namespace+'.json',state)
    if not state['steps'].get('provision'):
        i.provision(rows);state['steps']['provision']=True
        state_path.write_text(json.dumps(state,indent=2)+'\n')
    reports={'path':'reports','id':identity('entry'),'parent':j.tree_root['id'],'owner':ALICE,
        'group':GROUP,'mode':0o755,'content':{'kind':'directory'}}
    bodies={'secret':b'private sibling','reports/live':b'seed','reports/procedure':b'complete intended fixture\n'}
    entries=[reports]+[file_entry(n,reports['id'] if n.startswith('reports/') else j.tree_root['id'],b) for n,b in bodies.items()]
    if 'seed' not in state['steps']:
        upload,rid=j.stage(j.descriptor(entries),bodies=list(bodies.values()))
        seeded=j.expect('hosted-seed','POST',j.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
        state['steps']['seed']={'revision':rid,'receipt':seeded};state['hidden_entry']=next(e['id'] for e in entries if e['path']=='secret')
        state_path.write_text(json.dumps(state,indent=2)+'\n')
    mounted=state['steps'].get('mounts',{})
    for name in ('a1','a2','readonly'):
        if name in mounted:
            remote.mounts.append(name);continue
        actor=identities[name]
        mounted[name]=remote.start(name,readonly=name=='readonly',actor=name,
            replica_identity=actor['replica'],principal=actor['principal'],group=GROUP)
        state['steps']['mounts']=mounted;state_path.write_text(json.dumps(state,indent=2)+'\n')
        (output/'mounted.json').write_text(json.dumps(mounted,indent=2)+'\n')
    controls=remote.execute("import json,subprocess;rows={}\nfor p in ['/private/a1/token','/private/a1/state/journal.sqlite']:\n try:open(p,'rb').read();rows[p]=0\n except OSError as e:rows[p]=e.errno\nrows['sudo_exit']=subprocess.run(['sudo','-n','true'],capture_output=True).returncode\nassert rows=={'/private/a1/token':13,'/private/a1/state/journal.sqlite':13,'sudo_exit':1},rows\nprint(json.dumps(rows))",user='1002:1002')
    state['steps']['controls']=controls;state_path.write_text(json.dumps(state,indent=2)+'\n')
    (output/'controls.json').write_text(json.dumps(controls,indent=2)+'\n')
    return i,j,remote,state


def start_relay(config,service_port,output,listen_port=18443):
    import subprocess,sys,json,time
    from pathlib import Path
    output=Path(output)
    script=Path(__file__).with_name('ssh_relay.py')
    log=(output/('relay-'+str(listen_port)+'.log')).open('xb')
    argv=[sys.executable,str(script),'--mode','local','--target-host','127.0.0.1',
        '--target-port',str(service_port),'--listen-port',str(listen_port),
        '--lifetime-seconds','3600','--ssh-config',config['ssh_config'],'--ssh-host',config['ssh_host']]
    p=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True)
    (output/('relay-'+str(listen_port)+'-owner.json')).write_text(json.dumps({'pid':p.pid,'argv':argv,'start':time.time()}))
    return p



def hosted_cases(config,output):
    import json,time,hashlib,ssl,subprocess,os,signal
    from pathlib import Path
    i,j,remote,state=prepare_hosted(config,output)
    from isolation import Isolation
    from service_protocol import identity
    from service_storage import object_id
    output=Path(output);state_path=i.control/('hosted-resume-'+config['namespace']+'.json')
    def save():state_path.write_text(json.dumps(state,indent=2)+'\n')
    class Checks(Isolation):
        def head(self):return self.i.sql("SELECT head FROM branches WHERE namespace='"+config['namespace']+"' AND name='main';")
        def request(self,method,path,actor='alice',body=None,raw=None,headers=None,timeout=10,response_bytes=False):
            payload=json.dumps(body).encode() if body is not None else raw or b''
            if isinstance(payload,str):payload=payload.encode()
            settings={'method':method,'path':path,'token':self.tokens.get(actor,actor),
                'payload':payload.hex(),'headers':{k:v for k,v in (headers or {}).items() if k.lower()!='authorization'},'timeout':timeout}
            if body is not None:settings['headers']['Content-Type']='application/json'
            data=remote.execute("import json,sys,ssl,http.client;s=json.load(sys.stdin);c=http.client.HTTPSConnection('127.0.0.1',18443,context=ssl.create_default_context(cafile='/private/a1/ca'),timeout=s['timeout']);h=s['headers'];h['Authorization']='Bearer '+s['token'];c.request(s['method'],s['path'],bytes.fromhex(s['payload']),h);r=c.getresponse();body=r.read();c.close();print(json.dumps({'status':r.status,'body':body.hex()}))",settings)
            body=bytes.fromhex(data['body'])
            return data['status'],body if response_bytes else json.loads(body) if body else None
        def assertion(self,case,details):
            n=0
            while (output/('case-'+case+'-'+str(n)+'.json')).exists():n+=1
            p=output/('case-'+case+'-'+str(n)+'.json');p.write_text(json.dumps(details,indent=2)+'\n')
            state.setdefault('cases',{})[case]={'passed':True,'provenance':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()};save()
    c=object.__new__(Checks);c.__dict__.update(j.__dict__)
    c.identities=state['identities'];c.bindings=state['steps']['mounts'];c.hidden_entry=state['hidden_entry'];c.endpoints={n:remote for n in c.identities}
    c.observations=json.loads((i.output/'observations.json').read_text()) if (i.output/'observations.json').exists() else []
    if 'ordinary' not in state['steps']:
        assert remote.read('a1/reports/live')==b'seed'.hex()
        state['steps']['ordinary']=True;save()
    body=b'known disposable private candidate'
    if 'private' not in state['steps']:
        (output/'synthetic-private-input.bin').write_bytes(body)
        c.write('a2','reports/result',body)
        op=identity('operation');revision=remote.cli('checkpoint','--state','/private/a2/state','--operation-id',op)['revision']
        remote.cli('sync','run','--state','/private/a2/state','--revision',revision,'--operation-id',op,'--enqueue-only','true')
        private=remote.cli('sync','drain','--state','/private/a2/state','--revision',revision,'--level','private-remote','--deadline-ms','60000')['progress']
        assert private['state']=='PrivateRemote' and private['private_receipt']['submitted_revision']==revision
        local=next(r['descriptor'] for r in remote.cli('history','--state','/private/a2/state')['revisions'] if r['revision']==revision)
        private_entry=next(e['id'] for e in local['tree']['entries'] if e['path']=='reports/result')
        state['steps']['private']={'progress':private,'entry':private_entry};save()
    private=state['steps']['private']['progress']
    if 'api-bypass' not in state.get('cases',{}):
        view=c.private_checks(private,state['steps']['private']['entry'],body)
        state['steps']['private_view']=view;save()
    if 'readonly' not in state.get('cases',{}):
        denied=c.denied_io('readonly',[('write','reports/live'),('write','reports/denied'),('unlink','reports/live')])
        assert set(denied.values())=={30},denied
        c.expect('hosted-readonly-upload','POST',c.root+'/uploads',404,body={},actor='readonly')
        c.assertion('readonly',{'errnos':denied,'direct_upload':404})
    if 'scope' not in state.get('cases',{}):
        denied=c.denied_io('a2',[('read','secret')]);assert all(n in (2,13) for n in denied.values()),denied
        before=c.effect();known={p['operation'] for p in remote.status('a2')['status']['submissions']}
        synthetic=b'known disposable out-of-scope collision';(output/'synthetic-collision-input.bin').write_bytes(synthetic)
        c.write('a2','secret',synthetic)
        rejected=c.until(lambda:next((p for p in remote.status('a2')['status']['submissions'] if p['operation'] not in known and p.get('request') and p.get('error')),None),30)
        assert rejected['private_receipt'] is None and rejected['shared_receipt'] is None
        c.expect('hosted-hidden-collision-candidate','POST',c.root+'/candidates',404,{'code':'not_found'},actor='a2',body=rejected['request'])
        c.expect('hosted-hidden-collision-operation','GET',c.op_path(rejected['request']),404,actor='a2')
        assert c.effect()==before and remote.read('a1/secret')==b'private sibling'.hex()
        assert remote.read('a2/secret')==synthetic.hex()
        state['steps']['negative_scope']=rejected;save()
        c.assertion('scope',{'scope_read':denied,'rejected':rejected,'local_recovery_sha256':hashlib.sha256(synthetic).hexdigest(),'before':before,'after':c.effect()})
    if 'revoked-reconnect' not in state.get('cases',{}):
        before_reconnect=observe_retained_mount(remote,'a2',state['steps']['mounts']['a2']['pid'])
        relay=json.loads((output/'relay-18443-owner.json').read_text());pid=relay['pid']
        actual=subprocess.check_output(['ps','-p',str(pid),'-o','command='],text=True)
        assert 'ssh_relay.py' in actual and config['ssh_config'] in actual and '--target-port '+str(i.port) in actual,'relay identity changed'
        (output/'relay-pre-disconnect-command.txt').write_text(actual);os.kill(pid,signal.SIGTERM)
        credential=i.sql("SELECT id FROM credentials WHERE namespace='"+config['namespace']+"' AND replica='"+c.identities['a2']['replica']+"';")
        j.expect('revoke-disconnected','POST',j.root+'/grants',200,body={'revoke':credential})
        reconnect=output/'reconnect';reconnect.mkdir();start_relay(config,i.port,reconnect)
        c.until(lambda:not remote.status('a2')['live']['authorized'],30)
        denied=c.denied_io('a2',[('read','reports/result'),('write','reports/live')]);assert set(denied.values())=={13},denied
        c.expect('hosted-revoked-view','POST',c.root+'/views',401,body={'branch':'main'},actor='a2')
        c.expect('hosted-revoked-operation','GET',c.op_path(private['request']),401,actor='a2')
        c.assertion('revoked-reconnect',revoked_reconnect_case(remote,denied,before_reconnect))
    if 'intended_write' not in state['steps']:
        body=b'complete intended final hosted bytes\n';(output/'intended-input.bin').write_bytes(body)
        c.write('a1','reports/completed',body)
        state['steps']['intended_write']={'path':'reports/completed','sha256':hashlib.sha256(body).hexdigest()};save()
    return i,j,remote,state

def hosted_metrics(config,output):
    """Separate read-only instrumented-service evidence; never the durability path."""
    import json,time,hashlib,secrets
    from pathlib import Path
    from common import PhaseInfra
    from service_protocol import Journey,ALICE,GROUP,REPLICA,file_entry
    from service_storage import NS,object_id
    from connected import fixture
    output=Path(output);i=PhaseInfra(output/'metrics-service')
    image='sha256:875888cb5586f46489613188c8b227227348d6fcb056ec0b675e2571c8335f32'
    i.setup(image);j=Journey(i);j.image=image
    from scale import owner_record
    owner=owner_record(j.tree_root,set(j.tokens.values()),int(time.time()))
    owner['authority'].update(uid=1002,gid=1002);j.tokens['alice']=owner['token']
    i.provision([owner])
    i.docker('exec','-d','-e','MAGUS_TEST_TRANSFER_LOG=1',i.service,'sh','-c',
        'echo $$ > /tmp/service.pid; exec magus-fs-service-faults serve /control/service.json >> /tmp/service.log 2>&1')
    i.port=int(i.docker('port',i.service,'8443/tcp').stdout.strip().split(':')[-1]);j.wait()
    return measure_hosted_metrics(config,output,i,j)

def measure_hosted_metrics(config,output,i,j):
    import json,time,hashlib
    from connected import fixture
    from service_protocol import ALICE,GROUP,file_entry
    from service_storage import NS,object_id
    image=j.image
    files,chunks=fixture();body=files['large'];entry=file_entry('large',j.tree_root['id'],body)
    entry['content']['version']['extents']=[{'kind':'chunk','object':object_id(b),'object_size':len(b),'offset':0,'length':len(b)} for b in chunks]
    upload,rid=j.stage(j.descriptor([entry]),bodies=chunks);j.expect('metrics-seed','POST',j.root+'/seed',200,body={'branch':'main','revision':rid,'upload':upload})
    ident=json.loads(i.docker('exec',i.service,'python3','-c',"import json,hashlib,os;from pathlib import Path;pid=Path('/tmp/service.pid').read_text().strip();p=Path('/proc')/pid;env=(p/'environ').read_bytes().split(b'\\0');print(json.dumps({'binary_sha256':hashlib.sha256((p/'exe').read_bytes()).hexdigest(),'fault_variables':[x.decode() for x in env if x.startswith(b'MAGUS_TEST_')]}))").stdout)
    assert ident['fault_variables']==['MAGUS_TEST_TRANSFER_LOG=1']
    relayout=output/'metrics-relay';relayout.mkdir();start_relay(config,i.port,relayout,18444)
    metrics_config={**config,'service_url':'https://127.0.0.1:18444','namespace':NS}
    remote=RemoteMount(j,metrics_config,output)
    def counters():
        log=i.docker('exec',i.service,'cat','/tmp/service.log',evidence=False).stdout
        result={k:0 for k in ('install_body','backend_put_body','backend_verification_body','authorized_body')}
        for line in log.splitlines():
            fields=line.split()
            if len(fields)==3 and fields[0]=='fs2_transfer':result[fields[1]]=result.get(fields[1],0)+int(fields[2])
        (i.output/'transfer-log.txt').write_text(log)
        return result
    start=counters();mounted=remote.start('metrics',readonly=True,actor='readonly',replica_identity='replica:'+f'{3:032x}',principal=ALICE,group=GROUP)
    remote.execute("import os,json;print(json.dumps(os.listdir('/shared/metrics')))",user='1002:1002')
    metadata=counters();assert metadata['authorized_body']==start['authorized_body']
    def ranges():return remote.execute("import os,json,hashlib;f=os.open('/shared/metrics/large',os.O_RDONLY);b=[os.pread(f,4096,0),os.pread(f,4096,64*1024*1024-4096)];os.close(f);print(json.dumps([hashlib.sha256(x).hexdigest() for x in b]))",user='1002:1002')
    expected=[hashlib.sha256(body[:4096]).hexdigest(),hashlib.sha256(body[-4096:]).hexdigest()]
    t=time.monotonic();assert ranges()==expected;cold=counters();cold_seconds=time.monotonic()-t
    assert 0<cold['authorized_body']-metadata['authorized_body']<=2*1024*1024
    t=time.monotonic();assert ranges()==expected;warm=counters();warm_seconds=time.monotonic()-t
    assert warm['authorized_body']==cold['authorized_body']
    full=remote.execute("import hashlib,json;print(json.dumps(hashlib.sha256(open('/shared/metrics/large','rb').read()).hexdigest()))",user='1002:1002');assert full==hashlib.sha256(body).hexdigest()
    final=counters()
    row={'passed':True,'provenance':str(i.output/'read-proof.json'),'service':ident,'image':image,
        'fixture_revision':rid,'expected_sha256':hashlib.sha256(body).hexdigest(),'object_ids':[object_id(b) for b in chunks],
        'metadata':metadata,'cold':cold,'warm':warm,'full':final,'cold_seconds':cold_seconds,
        'warm_seconds':warm_seconds,'mount':mounted,'status':remote.status('metrics'),
        'boundary':'separate read-only instrumented service; authorized_body observes verified backend bytes fetched for authorized object responses, not TLS wire bytes; no service response cache exists on this path',
        'default_service_mounted_transfer_accounting':False}
    i.write_json('read-proof.json',row)
    i.private('metrics-resume.json',{'service':i.service,'owner':i.owner,'port':i.port,
        'pg':i.pg,'s3':i.s3,'tokens':j.tokens,'tree_root':j.tree_root,'config':metrics_config})
    return i,remote,row


def freeze_observation(remote):
    """Inspect kernel process/fd ownership and the entire intended mounted tree."""
    return remote.execute('''import os,json,stat,hashlib
from pathlib import Path
writers=[];users=[];unknown=[];daemons={}
for name in ('a1','a2','readonly','metrics'):
 pid=int(Path('/private/'+name+'/pid').read_text());p=Path('/proc')/str(pid)
 args=(p/'cmdline').read_bytes().split(b'\\0');assert b'--mountpoint' in args and args[args.index(b'--mountpoint')+1]==('/shared/'+name).encode()
 daemons[name]={'pid':pid,'binary_sha256':hashlib.sha256((p/'exe').read_bytes()).hexdigest(),'command':[x.decode() for x in args if x]}
for p in Path('/proc').glob('[0-9]*'):
 try:
  uid=int(next(x for x in (p/'status').read_text().splitlines() if x.startswith('Uid:')).split()[1])
  if uid==1002:users.append({'pid':int(p.name),'command':(p/'cmdline').read_bytes().replace(b'\\0',b' ').decode()})
  for fd in (p/'fd').iterdir():
   try:
    target=os.readlink(fd)
    if target.startswith('/shared/'):
     flags=int(next(x for x in (p/'fdinfo'/fd.name).read_text().splitlines() if x.startswith('flags:')).split()[1],8)
     if flags&os.O_ACCMODE:writers.append({'pid':int(p.name),'fd':fd.name,'target':target,'flags':flags})
   except FileNotFoundError:pass
 except FileNotFoundError:pass
 except PermissionError:unknown.append(int(p.name))
root=Path('/shared/a1');rows=[]
for p in [root,*sorted(root.rglob('*'))]:
 st=p.lstat();kind='directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'unsupported'
 row={'path':str(p.relative_to(root)),'kind':kind,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}
 if kind=='file':row.update(size=st.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
 assert kind!='unsupported',row
 rows.append(row)
print(json.dumps({'writers':writers,'workload_processes':users,'unknown':unknown,'daemons':daemons,'manifest':rows,'mountinfo':Path('/proc/self/mountinfo').read_text()}))''')


def freeze_hosted(remote):
    import json,time
    marker=remote.output/'freeze-dispatch.json'
    if not marker.exists():
        marker.write_text(json.dumps({'sandbox_id':remote.config['sandbox_id'],'dispatch_disabled':True,'time':time.time()})+'\n')
    remote.frozen=True
    first=freeze_observation(remote)
    (remote.output/'freeze-first.json').write_text(json.dumps(first,indent=2)+'\n')
    assert not first['writers'] and not first['workload_processes'] and not first['unknown'],'unknown/live writers; retain resources'
    return first


def recover_hosted(config,output,label):
    """Fresh local tmpfs state/cache; only default-service TLS provides fixture data."""
    import json,hashlib
    from pathlib import Path
    from common import RecordedLazy
    output=Path(output);i,j=resume_service(config['owned_service_dir'])
    state=json.loads((i.control/('hosted-resume-'+config['namespace']+'.json')).read_text())
    j.tokens=state['tokens'];j.tokens['alice']=j.tokens['a1'];j.tree_root=state['tree_root'];j.root='/v1/n/'+config['namespace']
    local=RecordedLazy(j,'hosted-'+label)
    # Same accepted default ARM64 package binary; no compiler or worker disk input.
    proof=local.execute("import hashlib,json,os;from pathlib import Path;p=Path('/usr/local/bin/magus-fs');h=hashlib.sha256(p.read_bytes()).hexdigest();assert h=='372888e073185a15302e1cc69b0fe413bf5562452cb79005b31ccdf46630cd8c';Path('/opt/fs3-task4/bin').mkdir(parents=True);os.symlink(p,'/opt/fs3-task4/bin/magus-fs');print(json.dumps({'binary_sha256':h,'state_empty':not list(Path('/private').iterdir())}))")
    assert proof['state_empty']
    adapter=RemoteMount(j,{**config,'service_url':'https://service:8443'},output)
    adapter.execute=local.execute
    mounted=adapter.start(label,readonly=True,actor='a1',replica_identity=state['identities']['a1']['replica'])
    local.mounts.append(label)
    manifest=local.execute('''import json,stat,hashlib,sys
from pathlib import Path
root=Path('/shared')/json.load(sys.stdin);rows=[]
for p in [root,*sorted(root.rglob('*'))]:
 st=p.lstat();kind='directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'unsupported'
 row={'path':str(p.relative_to(root)),'kind':kind,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode)}
 if kind=='file':row.update(size=st.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
 assert kind!='unsupported',row
 rows.append(row)
print(json.dumps(rows))''',label)
    expected=json.loads((output/'freeze-first.json').read_text())['manifest']
    assert manifest==expected,('whole fixture recovery differs',manifest,expected)
    shared=json.loads((output/'publication-shared.json').read_text())
    assert mounted['binding']['view']['head']==shared['shared_receipt']['head']
    # Shared integration can derive a distinct revision; the source receipt binds
    # the exact submitted private revision, and this fresh view binds its result.
    row={'state_id':local.daemon+':/private/'+label,'container':local.daemon,'binary':proof,
         'mount':mounted,'manifest':manifest,'shared_receipt':shared['shared_receipt'],
         'service_only':True,'sandbox_disk_used':False,'independent':True}
    target=output/(label+'.json');assert not target.exists();target.write_text(json.dumps(row,indent=2)+'\n')
    local.cleanup()
    row['normal_local_cleanup']=True;target.write_text(json.dumps(row,indent=2)+'\n')
    return row



RETAINED_CONFLICT_SOURCES = {
    'crates/magus-fs-service/src/conflicts.rs':'92e11070d19bb57311b7db21e4d4b53624db72acb21f8ab74b7eacb5abbe4c52',
    'crates/magus-fs-service/src/publication.rs':'1bd94ee626d3409c99c39781179c760672d084005845927e550533f3e1dc1718',
    'crates/magus-fs/src/sync/controller.rs':'af0d0d3e3401f0fe5f9a7425dec2f62eb18c05dd92662ac8c3a799970fdd6d52'}


def derive_retained_conflicts(pre,final,shared,server,commands,source_binding):
    """Reviewed finite historical derivation, never a final conflict-list response.

    Pinned source: conflict INSERT occurs transactionally only in conflicted409
    integration; Isolated controllers do not auto-integrate on head movement.
    """
    if source_binding!=RETAINED_CONFLICT_SOURCES:raise ValueError('conflict derivation source binding differs')
    intended=shared['integration'];receipt=shared['shared_receipt']
    integrations=[r for r in server if r['kind']=='integration']
    assert len(integrations)==1 and integrations[0]['status']==200 and json_value(integrations[0]['result'])==receipt,'unexpected server integration/conflict obligation'
    assert all(r['kind'] in ('seed','candidate','integration') and r['status']==200 for r in server),'unknown server operation kind/outcome'
    for phase in (pre,final):
        for name,row in phase.items():
            sync=row['sync'].get('value',row['sync'])
            assert sync['status']['binding']['publication']=='Isolated','non-Isolated historical binding'
            for item in sync['status']['submissions']:
                if item.get('integration') is not None:
                    assert name=='a1' and item['integration']==intended and item.get('shared_receipt')==receipt,'unaccounted queued integration'
    start=next(n for n,r in enumerate(commands) if 'writers=[];users=[];unknown=[];daemons={}' in r.get('code',''))
    import hashlib
    frozen_code=commands[start]['code'];integrate=[]
    assert hashlib.sha256(frozen_code.encode()).hexdigest()=='a090dd05d399685027bbfc7b1bcc08981312f8cf1384ee995611fd8b2e3fcad7','unbound freeze observer code'
    for row in commands[start:]:
        assert row['workload_uid']==0,'workload dispatch after freeze'
        args=row.get('settings')
        if args is None:
            assert row['code']==frozen_code,'unknown post-freeze control command'
        else:
            assert isinstance(args,list),'unknown post-freeze request'
            assert hashlib.sha256(row['code'].encode()).hexdigest()=='e3d5b65e7d7e139bea8035e5a86adae7b47ba735de68cca2c6e5e76d76e6e268','unbound CLI observer code'
            assert args[0] in ('status','history','checkpoint','sync'),'unknown post-freeze CLI action'
            if args[0]=='sync':assert args[1:2] in (['status'],['run'],['drain'],['integrate'],['local-work'],['recovery'],['conflicts'])
            if args[:2]==['sync','integrate']:
                assert args[args.index('--revision')+1]==receipt['submitted_revision'];integrate.append(args)
            if args[:2] in (['sync','local-work'],['sync','recovery'],['sync','conflicts']):assert args[2]=='list'
    assert len(integrate)==1,'controlled integration history differs'
    coverage={}
    for name,row in pre.items():
        observation=row['conflicts'];value=observation.get('value',observation)
        if name=='a2':assert value=={'ok':False,'error':'invalid_credential'}
        else:assert value.get('ok') is True and value['page']=={'items':[],'next':None}
        coverage[name]={'kind':'historical-conflict-derivation','final_list_observed':False,
            'list_state':'unknown' if name=='a2' else 'pre-freeze-empty-only',
            'disposition':'known-synthetic-candidates' if name=='a2' else 'no-new-unaccounted-conflict-obligation',
            'basis':'pinned executed source, Isolated bindings, controlled commands, exact sole successful integration; synthetic descriptors checked separately'}
    return coverage


def json_value(value):
    import json
    return json.loads(value)


def historical_conflict_coverage(config,evidence,derived,pre,final,shared,server):
    import json,hashlib
    from pathlib import Path
    def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    package_path=Path(config['historical_conflict_package'])
    assert sha(package_path)=='1f7eab8130b5a8f9c58943f45439661ffa4204c619ccf6760a84d2ac897023ed','unreviewed historical package'
    package=json.loads(package_path.read_text());sources=package['source']['manifest']
    binding={n:sources[n] for n in RETAINED_CONFLICT_SOURCES}
    repo=Path(__file__).resolve().parents[2]
    assert binding=={n:sha(repo/n) for n in binding},'source changed since executed package'
    actual=json.loads((evidence/'default-service-final-identity.json').read_text())
    service=next(r for r in package['packages'] if r['role']=='service');assert actual['binary_sha256']==service['binary_sha256'] and not actual['fault_variables']
    client=next(r for r in package['packages'] if r['platform']=='x86_64-unknown-linux-gnu')
    assert all(r['binary_sha256']==client['binary_sha256'] for r in json.loads((evidence/'freeze-final.json').read_text())['daemons'].values())
    commands_path=Path(config['owned_service_dir'])/'hosted-commands.json';commands=json.loads(commands_path.read_text())
    coverage=derive_retained_conflicts(pre,final,shared,server,commands,binding)
    names=('pre-freeze-inventory.json','final-inventory.json','publication-shared.json','publication-server.json','freeze-final.json','accounting-history-a2.json','synthetic-private-input.bin','synthetic-collision-input.bin','default-service-final-identity.json')
    record={'new_execution':False,'final_conflict_query_missing':True,'coverage':coverage,'executed_sources':binding,
        'package_manifest_sha256':sha(package_path),'executed_binaries':{'service':service['binary_sha256'],'client':client['binary_sha256']},
        'raw_inputs':{str(evidence/n):sha(evidence/n) for n in names},'controlled_commands':{'path':str(commands_path),'sha256':sha(commands_path)}}
    (derived/'historical-conflict-derivation.json').write_text(json.dumps(record,indent=2)+'\n')
    return coverage

def account_raw_inventory(final,covered,synthetic,denied_operation,server,conflict_coverage=None):
    """Every observed item is covered explicitly or blocks; absence is never inferred."""
    rows=[]
    def require(value,message):
        if not value:raise ValueError(message)
    require(set(final)=={'a1','a2','readonly','metrics'},'unknown or missing replica inventory')
    for name,inv in final.items():
        for key in ('status','sync','work','recovery'):
            require(isinstance(inv.get(key),dict),name+': missing '+key+' inventory')
        for key in ('status','sync','work','recovery'):
            require(inv[key].get('ok') is True,name+': unavailable '+key+' inventory')
        work=inv['work'];recovery=inv['recovery']
        require(work.get('readiness')=='Ready',name+': local work readiness unknown')
        for owner,key in ((work,'recovery'),(recovery,'records'),(recovery,'imports')):
            require(isinstance(owner.get(key),list),name+': missing '+key+' listing')
            # No export/settlement is performed by this finite fixture. Nonempty
            # local recovery needs a separately verified disposition before retry.
            require(not owner[key],name+': unaccounted '+key+' items')
        require(type(recovery.get('limit')) is int and recovery['limit']>len(recovery['records']),name+': recovery listing may be truncated')
        status=inv['sync'].get('status',{});submissions=status.get('submissions')
        require(isinstance(submissions,list),name+': missing submissions')
        operations=set();receipts={}
        for item in submissions:
            op=item.get('operation');revision=item.get('local_revision')
            require(bool(op) and op not in operations,name+': duplicate or missing submission identity');operations.add(op)
            require(revision in covered[name],name+': unaccounted submission '+str(op))
            if item.get('remote_outcome_unknown') is not False:
                require(name=='a2' and op==denied_operation and revision in synthetic
                    and inv['sync'].get('live',{}).get('authorized') is False
                    and not any(r['operation']==op for r in server),name+': unresolved submission outcome '+str(op))
            receipt=item.get('private_receipt') or item.get('shared_receipt')
            if receipt:receipts[receipt['receipt']]=revision
            rows.append({'replica_name':name,'kind':'submission','id':op,'revision':revision,
                         'disposition':'known-synthetic-exclusion' if revision in synthetic and name=='a2' else 'covered-by-complete-fixture'})
        if 'conflicts' not in inv:
            require(conflict_coverage is not None and name in conflict_coverage,name+': missing conflicts inventory')
            rows.append({'replica_name':name,**conflict_coverage[name]});continue
        observation=inv['conflicts']
        # Recorded CLI exits remain explicit, including intentional revocation.
        if 'value' in observation:
            require(observation.get('exit')==(0 if observation['value'].get('ok') is True else 1),name+': inconsistent conflict command exit')
            observation=observation['value']
        if observation.get('ok') is not True:
            require(name=='a2' and observation.get('error')=='invalid_credential'
                and inv['sync'].get('live',{}).get('authorized') is False
                and all(x.get('local_revision') in synthetic for x in submissions),name+': conflict inventory denied/unknown')
            rows.append({'replica_name':name,'kind':'conflicts','disposition':'revoked-known-synthetic-only','empty_claim':False})
            continue
        pages=observation.get('pages',[observation.get('page')]);require(isinstance(pages,list) and bool(pages),name+': missing conflict pages')
        seen=set()
        for index,page in enumerate(pages):
            require(isinstance(page,dict) and isinstance(page.get('items'),list) and 'next' in page,name+': malformed conflict page')
            require(bool(page['next']) if index<len(pages)-1 else page['next'] is None,name+': incomplete conflict pagination')
            for item in page['items']:
                ident=item.get('id');require(bool(ident) and ident not in seen,name+': duplicate conflict');seen.add(ident)
                revision=receipts.get(item.get('receipt'))
                require(revision in covered[name] and (item.get('state')=='Resolved' or
                    (name=='a2' and revision in synthetic)),name+': unaccounted conflict '+str(ident))
                rows.append({'replica_name':name,'kind':'conflict','id':ident,'revision':revision,
                             'disposition':'known-synthetic-exclusion' if name=='a2' else 'resolved-covered-fixture'})
        rows.append({'replica_name':name,'kind':'inventory','local_work':0,'native_recovery':0,'imports':0,'conflict_pages':len(pages)})
    return rows

def completion_measurements(config,output,derived_output=None):
    """Derive the deletion guard only from retained actual observations."""
    import json,hashlib
    from pathlib import Path
    from common import digest
    output=Path(output);derived=Path(derived_output) if derived_output is not None else output
    def read(n):return json.loads((output/n).read_text())
    def sha(n):return hashlib.sha256((output/n).read_bytes()).hexdigest()
    first=read('freeze-first.json');post=read('freeze-after-publication.json');last=read('freeze-final.json')
    inventory=read('pre-freeze-inventory.json');final=read('final-inventory.json')
    private=read('publication-private.json');shared=read('publication-shared.json');server=read('publication-server.json')
    receipt=private['private_receipt'];sr=shared['shared_receipt'];revision=receipt['submitted_revision']
    assert any(json.loads(x['result'])==receipt and x['status']==200 for x in server)
    assert any(json.loads(x['result'])==sr and x['status']==200 for x in server)
    for x in (first,post,last):assert not x['writers'] and not x['workload_processes'] and not x['unknown']
    assert first['manifest']==post['manifest']==last['manifest']
    assert first['daemons']==last['daemons']
    for name in ('a2','readonly','metrics'):
        assert inventory[name]['status']['value']['working_generation']==final[name]['status']['working_generation']
        assert inventory[name]['status']['value']['captured_revision']==final[name]['status']['captured_revision']
    assert final['a1']['status']['working_generation']==read('publication-status-after.json')['working_generation']
    assert final['a1']['status']['captured_revision']==revision
    assert inventory['readonly']['status']['value']['working_generation']==0
    assert inventory['metrics']['status']['value']['working_generation']==0
    rejected=read('case-scope-0.json')['rejected']
    assert rejected['state']=='Denied' and rejected['private_receipt'] is None
    assert not any(x['operation']==rejected['operation'] for x in server)
    assert final['a2']['sync']['live']['authorized'] is False
    # Entire a2 history must contain only immutable baseline and these exact
    # two known synthetic inputs. No unknown path/content can be abandoned.
    history=read('accounting-history-a2.json')['revisions']
    baseline={e['path']:e for e in history[0]['descriptor']['tree']['entries']}
    inputs={'reports/result':'synthetic-private-input.bin','secret':'synthetic-collision-input.bin'}
    for rev in history:
        for e in rev['descriptor']['tree']['entries']:
            if e['path'] in baseline:assert e==baseline[e['path']]
            else:
                name=inputs[e['path']];body=(output/name).read_bytes();v=e['content']['version']
                assert v=={'size':len(body),'extents':[{'kind':'chunk','object':'sha256:'+sha(name),'object_size':len(body),'offset':0,'length':len(body)}]}
    assert history[-1]['revision']==final['a2']['status']['captured_revision']
    a1history=read('accounting-history-a1.json')['revisions']
    complete=next(r['descriptor'] for r in a1history if r['revision']==revision)
    entries={e['path']:e for e in complete['tree']['entries']}
    a1covered={r['revision'] for r in a1history if all(e==entries.get(e['path']) for e in r['descriptor']['tree']['entries'])}
    covered={'a1':a1covered,'a2':{r['revision'] for r in history},
        **{n:{final[n]['status']['captured_revision']} for n in ('readonly','metrics')}}
    conflict_coverage=None
    if config.get('historical_conflict_package'):
        assert derived!=output,'historical revalidation requires fresh derived output'
        conflict_coverage=historical_conflict_coverage(config,output,derived,inventory,final,shared,server)
    raw_dispositions=account_raw_inventory(final,covered,covered['a2'],rejected['operation'],server,conflict_coverage)
    replicas={n:final[n]['sync']['status']['submissions'][0]['request']['replica'] for n in ('a1','a2')}
    mounts=read('mounted.json')
    # Binding view doesn't expose replica; retain exact provisioned identities.
    state=json.loads((Path(config['owned_service_dir'])/'control'/('hosted-resume-'+config['namespace']+'.json')).read_text())
    replicas['readonly']=state['identities']['readonly']['replica'];replicas['metrics']='replica:'+f'{3:032x}'
    exclusions=[];work=[{'id':'intended-final','replica':replicas['a1'],'intended':True,'unique':True,'ack_certain':True,'revision':revision,'disposition':'included'}]
    for path,name in inputs.items():
        ident='synthetic:'+path
        exclusions.append({'id':ident,'input_sha256':sha(name),'external_input_sha256':sha(name),'external_provenance':sha(name),
            'reason':'known deliberately disposable negative test input; exact local descriptor and retained external input agree',
            'denial_provenance':sha('case-scope-0.json'),'local_recovery_provenance':sha('accounting-history-a2.json'),'disposition':'synthetic-abandonment'})
        work.append({'id':ident,'replica':replicas['a2'],'intended':False,'unique':True,'disposition':'excluded'})
    work.append({'id':'readonly-baseline','replica':replicas['readonly'],'intended':False,'unique':False,'disposition':'superseded','covered_by':'intended-final'})
    metric=read('metrics-service/read-proof.json')
    work.append({'id':'metrics-readonly','replica':replicas['metrics'],'intended':False,'unique':False,'disposition':'remote-recoverable',
        'independently_verified':metric['passed'],'content_sha256':metric['expected_sha256'],'provenance':sha('metrics-service/read-proof.json')})
    accounting={'raw_dispositions':raw_dispositions,'complete':True,'replicas':list(replicas.values()),'work':work,'exclusions':exclusions,
        'historical_a1':'automatic candidate contains same intended bytes; final checkpoint covers it',
        'historical_a2':'all descriptors exhaustively checked against immutable baseline and two explicit synthetic exclusions',
        'scope_unknown_resolution':{'client_flag_retained':rejected['remote_outcome_unknown'],'operation':rejected['operation'],
            'server_operation_absent':True,'credential_revoked':True,'server_provenance':sha('publication-server.json')},
        'revoked_conflict_list':'invalid_credential retained; not treated as empty; exact local descriptors and synthetic source exhaustively account controlled writes',
        'inventory_provenance':sha('final-inventory.json')}
    (derived/'accounting.json').write_text(json.dumps(accounting,indent=2)+'\n');accounting['provenance']=hashlib.sha256((derived/'accounting.json').read_bytes()).hexdigest()
    manifest=digest(first['manifest']);run=output.name
    save={'sequence':2,'revision':revision,'operation':receipt['operation'],'receipt':receipt['receipt'],
        'sha256':sha('intended-input.bin'),'manifest_sha256':manifest,'private_receipt':receipt,'shared_receipt':sr,
        'integration':shared['integration'],'shared_head':sr['head'],'ack_certain':not private['remote_outcome_unknown'],
        'server_confirmed':True,'provenance':sha('publication-server.json'),**{k:receipt[k] for k in ('replica','original_view','original_head')}}
    before=read('recovery-before.json');assert before['manifest']==first['manifest'] and before['normal_local_cleanup']
    m={'lifecycle':'disposable-daytona','run_id':run,'owned_sandbox_id':config['sandbox_id'],'provider':{'sandbox_id':config['sandbox_id']},
       'save':save,'accounting':accounting,'freeze':{'sequence':1,'recheck_sequence':4,'run_id':run,'sandbox_id':config['sandbox_id'],
           'dispatch_disabled':(output/'freeze-dispatch.json').exists(),'writers_reaped':True,'writers_before':[],'writers_after':[],'unknown_writers':[],
           'generation_before':read('publication-status-after.json')['working_generation'],'generation_after':final['a1']['status']['working_generation'],
           'manifest_before':manifest,'manifest_after':digest(last['manifest']),'provenance':sha('freeze-final.json')},
       'recovery_before':{'sequence':3,'run_id':run,'sandbox_id':config['sandbox_id'],'independent':True,'sandbox_disk_used':False,
           'service_only':True,'whole_fixture':True,'private_closure_verified':True,'state_id':before['state_id'],
           'revision':revision,'sha256':save['sha256'],'manifest_sha256':digest(before['manifest']),'provenance':sha('recovery-before.json')}}
    errors=completion_failures(m);(derived/'completion-guard.json').write_text(json.dumps({'errors':errors,'measurements':m},indent=2)+'\n')
    assert not errors,errors
    return m


def delete_completed_worker(config,output):
    import json,time,subprocess,urllib.request,urllib.error,hashlib
    from pathlib import Path
    output=Path(output)
    m=completion_measurements(config,output)
    assert deletion_permitted(m)
    api=DaytonaAPI(Path(config['daytona_env_file']))
    path='/sandbox/'+config['sandbox_id']
    def request(method):
        req=urllib.request.Request(api.BASE+path,method=method,headers={'Authorization':'Bearer '+api._key})
        try:
            with urllib.request.urlopen(req,timeout=30) as response:
                raw=response.read();return response.status,json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            if error.code==404:return 404,None
            raise
    status,actual=request('GET')
    assert status==200 and actual['id']==config['sandbox_id'] and actual['name']==config['owned_name']
    assert actual['labels'].get('magus.fs3.owner')==config['owned_name']
    proof={'sandbox_id':actual['id'],'owned_name':actual['name'],'labels':actual['labels'],
           'guard_sha256':hashlib.sha256((output/'completion-guard.json').read_bytes()).hexdigest(),'observations':[]}
    def save():
        (output/'provider-deletion.json').write_text(json.dumps(proof,indent=2)+'\n')
    assert not (output/'provider-deletion.json').exists(),'existing deletion attempt must be resolved, never repeated'
    proof['intent_time']=time.time();save()
    code,_=request('DELETE');proof['delete_status']=code;save()
    end=time.monotonic()+120
    while True:
        code,state=request('GET');proof['observations'].append({'time':time.time(),'http_status':code,'state':None if state is None else state.get('state')});save()
        if code==404:break
        assert time.monotonic()<end,'provider absence unresolved; preserve helpers'
        time.sleep(2)
    ssh=subprocess.run(['ssh','-T','-F',config['ssh_config'],config['ssh_host'],'true'],capture_output=True,text=True,timeout=20)
    proof['ssh_exit']=ssh.returncode
    assert ssh.returncode!=0,'deleted worker remains SSH reachable'
    proof.update(terminal=True,confirmed_absent=True,ssh_unusable=True);save()
    return proof


def cleanup_hosted(config,output):
    import json,os,signal,subprocess
    from pathlib import Path
    from common import PhaseInfra
    output=Path(output)
    deleted=json.loads((output/'provider-deletion.json').read_text());assert deleted.get('terminal') and deleted.get('confirmed_absent')
    before=json.loads((output/'recovery-before.json').read_text());after=json.loads((output/'recovery-after.json').read_text())
    assert before['manifest']==after['manifest'] and before['state_id']!=after['state_id']
    assert before['normal_local_cleanup'] and after['normal_local_cleanup']
    # No cleanup fallback: unqualified local mount termination must retain helpers.
    for label in ('before','after'):
        path=Path(config['owned_service_dir'])/('hosted-recovery-'+label+'-kernel-mount-cleanup.json')
        proof=json.loads(path.read_text());assert proof['verified'] and not any(proof['remaining'].values())
    rows=[]
    for path in (output/'reconnect/relay-18443-owner.json',output/'metrics-relay/relay-18444-owner.json'):
        owner=json.loads(path.read_text());pid=owner['pid']
        p=subprocess.run(['ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
        if p.returncode==0:
            assert 'ssh_relay.py' in p.stdout and config['ssh_config'] in p.stdout
            os.kill(pid,signal.SIGTERM)
        rows.append({'relay':str(path),'pid':pid,'observed_command':p.stdout.strip(),'stop_requested':p.returncode==0})
    for directory in (Path(config['owned_service_dir']),output/'metrics-service'):
        owned=json.loads((directory/'ownership.json').read_text());i=object.__new__(PhaseInfra)
        i.output=directory;i.control=directory/'control';i.owner=owned['owner'];i.resources=owned['resources'];i.commands=current_ledger(directory)
        if directory==Path(config['owned_service_dir']):
            service=next(x['name'] for x in i.resources if x['kind']=='container' and x['name'].endswith('-service'))
            actual=json.loads(i.docker('exec',service,'python3','-c',"import json,hashlib;from pathlib import Path;p=Path('/proc')/Path('/tmp/service.pid').read_text().strip();print(json.dumps({'binary_sha256':hashlib.sha256((p/'exe').read_bytes()).hexdigest(),'fault_variables':[x.decode() for x in (p/'environ').read_bytes().split(b'\\0') if x.startswith(b'MAGUS_TEST_')]}))").stdout)
            assert actual['binary_sha256']=='73bafa610b146013d2559f3b8fe9742738cd330003e0838d348651dcb29d0052' and not actual['fault_variables']
            (output/'default-service-final-identity.json').write_text(json.dumps(actual,indent=2)+'\n')
        i.cleanup();rows.append({'owner':i.owner,'cleanup':str(directory/'cleanup.json'),'resources_removed':all(x.get('removed') for x in i.resources)})
    # Observe relay exit, never infer it solely from kill acceptance.
    import time
    for row in rows:
        if 'pid' not in row:continue
        end=time.monotonic()+10
        while subprocess.run(['ps','-p',str(row['pid']),'-o','stat='],capture_output=True,text=True).stdout.strip() not in ('','Z'):
            assert time.monotonic()<end,'relay exit unresolved';time.sleep(.1)
        row['exited']=True
    result={'ok':True,'resources_removed':True,'provider_absent':True,'normal_provider_unmount_qualified':False,'local_mounts_absent':True,'rows':rows}
    (output/'owned-cleanup.json').write_text(json.dumps(result,indent=2)+'\n');return result


def record_inventory(remote,output,final=False):
    import json
    rows={}
    for name in ('a1','a2','readonly','metrics'):
        rows[name]={}
        for label,args in (('status',['status']),('sync',['sync','status']),('work',['sync','local-work','list']),('recovery',['sync','recovery','list'])):
            value=remote.cli(*args,'--state','/private/'+name+'/state')
            rows[name][label]=value if final else {'exit':0,'value':value}
        pages=[];cursor=None;seen=set()
        while True:
            args=['sync','conflicts','list','--state','/private/'+name+'/state']+(['--cursor',cursor] if cursor else [])
            raw=remote.execute("import json,subprocess,sys;p=subprocess.run(['/opt/fs3-task4/bin/magus-fs',*json.load(sys.stdin)],capture_output=True,text=True);print(json.dumps({'exit':p.returncode,'stdout':p.stdout}))",args)
            value=json.loads(raw['stdout'])
            if raw['exit']!=0:
                rows[name]['conflicts']={'exit':raw['exit'],'value':value};break
            assert value.get('ok') is True and isinstance(value.get('page'),dict)
            pages.append(value['page']);cursor=value['page'].get('next')
            if cursor is None:
                rows[name]['conflicts']={'ok':True,'pages':pages};break
            assert cursor not in seen,'conflict cursor repeated';seen.add(cursor)
    (output/('final-inventory.json' if final else 'pre-freeze-inventory.json')).write_text(json.dumps(rows,indent=2)+'\n')
    return rows


def publish_hosted(config,output,infra,remote):
    import json
    from service_protocol import identity
    def save(name,value):
        path=output/name;assert not path.exists(),'partial publication requires explicit retained-stage resolution'
        path.write_text(json.dumps(value,indent=2)+'\n');return value
    st=save('publication-status-before.json',remote.cli('status','--state','/private/a1/state'))
    op=identity('operation');save('publication-intent.json',{'operation':op,'generation':st['working_generation']})
    cp=save('publication-checkpoint.json',remote.cli('checkpoint','--state','/private/a1/state','--operation-id',op,'--expected-generation',str(st['working_generation'])))
    revision=cp['revision']
    save('publication-enqueued.json',remote.cli('sync','run','--state','/private/a1/state','--revision',revision,'--operation-id',op,'--enqueue-only','true'))
    private=save('publication-private.json',remote.cli('sync','drain','--state','/private/a1/state','--revision',revision,'--level','private-remote','--deadline-ms','60000')['progress'])
    assert private['private_receipt']['submitted_revision']==revision and not private['remote_outcome_unknown']
    head=infra.sql("SELECT head FROM branches WHERE namespace='"+config['namespace']+"' AND name='main';")
    shared=save('publication-shared.json',remote.cli('sync','integrate','--state','/private/a1/state','--revision',revision,'--expected-head',head)['progress'])
    assert shared['integration']['candidate_receipt']==private['private_receipt']['receipt']
    server=infra.sql("SELECT json_agg(json_build_object('operation',operation,'receipt',receipt,'submitted_revision',submitted_revision,'kind',kind,'result',result,'status',status)) FROM operations WHERE namespace='"+config['namespace']+"';")
    save('publication-server.json',json.loads(server));save('freeze-after-publication.json',freeze_observation(remote))
    save('publication-status-after.json',remote.cli('status','--state','/private/a1/state'))
    for name in ('a1','a2'):save('accounting-history-'+name+'.json',remote.cli('history','--state','/private/'+name+'/state'))


def execute_hosted(config,output):
    """Resume completed stages; partial uncertain stages fail without replay/cleanup."""
    import json
    if not (output/'freeze-dispatch.json').exists():
        if not (output/'relay-18443-owner.json').exists():
            i,j=resume_service(config['owned_service_dir']);start_relay(config,i.port,output)
        i,j,remote,state=hosted_cases(config,output)
        if not (output/'metrics-service/read-proof.json').exists():hosted_metrics(config,output)
        record_inventory(remote,output);freeze_hosted(remote)
    if not (output/'publication-status-after.json').exists():
        i,j=resume_service(config['owned_service_dir']);remote=RemoteMount(j,config,output)
        publish_hosted(config,output,i,remote)
    if not (output/'recovery-before.json').exists():recover_hosted(config,output,'recovery-before')
    if not (output/'provider-deletion.json').exists():
        i,j=resume_service(config['owned_service_dir']);remote=RemoteMount(j,config,output)
        record_inventory(remote,output,final=True)
        (output/'freeze-final.json').write_text(json.dumps(freeze_observation(remote),indent=2)+'\n')
        completion_measurements(config,output);delete_completed_worker(config,output)
    else:
        deletion=json.loads((output/'provider-deletion.json').read_text())
        assert deletion.get('terminal') and deletion.get('confirmed_absent') and deletion.get('ssh_unusable'),'partial deletion unresolved; do not repeat DELETE'
    if not (output/'recovery-after.json').exists():recover_hosted(config,output,'recovery-after')
    if not (output/'owned-cleanup.json').exists():cleanup_hosted(config,output)



def provider_assertions(evidence,measurements,cases):
    """Shared assertions are recomputed from raw outcomes, not copied pass flags."""
    import json,hashlib
    from qualification import PROVIDER_CASES
    rows=[]
    def raw(case):
        from pathlib import Path
        p=Path(cases[case]['provenance']);blob=p.read_bytes()
        assert hashlib.sha256(blob).hexdigest()==cases[case]['sha256'],'case provenance changed'
        return json.loads(blob),p
    def add(case,passed,paths):
        rows.append({'acceptance':PROVIDER_CASES[case],'case':case,'expected':True,'observed':bool(passed),'passed':bool(passed),
            'provenance':[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]})
    r,p=raw('scope');add('scope',r['before']==r['after'] and all(v in (2,13) for v in r['scope_read'].values())
        and r['rejected']['state']=='Denied' and r['rejected']['private_receipt'] is None and r['rejected']['shared_receipt'] is None,[p])
    r,p=raw('readonly');add('readonly',bool(r['errnos']) and set(r['errnos'].values())=={30} and r['direct_upload']==404,[p])
    r,p=raw('private-history');add('private-history',r['private_entry'] not in r['observed_entries'] and r['hidden_entry'] not in r['observed_entries'] and r['readonly_denied']==404 and r['page']['next'] is None,[p])
    r,p=raw('api-bypass');probe=r['own_view_private_object'];add('api-bypass',r['before']==r['after'] and probe['allowed_status']==200 and probe['private_status']==404 and probe['denied']=={'code':'not_found'},[p])
    r,p=raw('revoked-reconnect');add('revoked-reconnect',set(r['denied'].values())=={13} and r['status']['live']['authorized'] is False and retained_mount(r['kernel_daemon_proof'],'a2'),[p])
    p=evidence/'metrics-service/read-proof.json';r=json.loads(p.read_text())
    commands=evidence/'metrics-service/hosted-commands.json';raw_commands=json.loads(commands.read_text())
    full_hash_observed=any(x.get('exit')==0 and 'hashlib.sha256(open' in x['code'] and json.loads(x['stdout'])==r['expected_sha256'] for x in raw_commands)
    add('cold-warm-range',r['metadata']['authorized_body']==0 and 0<r['cold']['authorized_body']-r['metadata']['authorized_body']<=2*1024*1024
        and r['warm']['authorized_body']==r['cold']['authorized_body'] and full_hash_observed,[p,commands])
    add('shared-publication',not completion_failures(measurements),[evidence/'publication-private.json',evidence/'publication-shared.json',evidence/'publication-server.json'])
    add('disposable-lifecycle',not validate_provider(measurements),[evidence/'provider-deletion.json',evidence/'recovery-before.json',evidence/'recovery-after.json',evidence/'owned-cleanup.json'])
    return rows

def hosted_result(config,manifest_path,evidence,output):
    import json,hashlib,sys,subprocess,tarfile
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
    from package import load_manifest,source_manifest,runtime_inputs,canonical_sha,binary_check
    from qualification import normalize
    def read(name):return json.loads((evidence/name).read_text())
    def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    manifest=load_manifest(manifest_path);current=source_manifest();old=manifest['source']['manifest']
    assert runtime_inputs(current)==runtime_inputs(old),'runtime changed since packaged source'
    client=next(r for r in manifest['packages'] if r['platform']=='x86_64-unknown-linux-gnu' and r['role']=='client')
    service=next(r for r in manifest['packages'] if r['role']=='service')
    archive=Path(manifest_path).parent/client['archive'];assert sha(archive)==client['sha256']
    with tarfile.open(archive,'r:gz') as tar:data=tar.extractfile(client['binary']).read()
    binary_check(data,client['platform']);assert hashlib.sha256(data).hexdigest()==client['binary_sha256']
    m=completion_measurements(config,evidence,output);deletion=read('provider-deletion.json');after=read('recovery-after.json')
    assert sha(evidence/'completion-guard.json')==deletion['guard_sha256'],'original deletion guard changed'
    assert after['manifest']==read('recovery-before.json')['manifest'] and after['normal_local_cleanup']
    m['recovery_after']={**m['recovery_before'],'sequence':6,'state_id':after['state_id'],'provenance':sha(evidence/'recovery-after.json')}
    m['deletion']={**deletion,'sequence':5,'owned':True,'provenance':sha(evidence/'provider-deletion.json')}
    identity=json.loads(Path(config['worker_identity']).read_text());provider=json.loads(Path(config['provider_observation']).read_text())
    assert identity['uname'][1]==config['sandbox_id'] and provider['id']==config['sandbox_id']
    m['provider']={'name':'daytona','execution':'remote-ssh','sandbox_id':config['sandbox_id'],'architecture':identity['uname'][4],
        'snapshot':provider['snapshot'],'version':{'kernel':identity['uname'][2:4],'provider_api':'REST /api; no numeric API/daemon version exposed in retained observations'},'provenance':sha(config['worker_identity'])}
    actual=read('freeze-final.json')['daemons'];assert all(r['binary_sha256']==client['binary_sha256'] for r in actual.values())
    m['package']={'verified':True,'platform':client['platform'],'manifest_sha256':sha(manifest_path),'archive_sha256':client['sha256'],'expected_binary_sha256':client['binary_sha256'],'executed_binary_sha256':actual['a1']['binary_sha256']}
    controls=read('controls.json');assert controls['sudo_exit']==1 and controls['/private/a1/token']==13 and controls['/private/a1/state/journal.sqlite']==13
    state=json.loads((Path(config['owned_service_dir'])/'control'/('hosted-resume-'+config['namespace']+'.json')).read_text())
    m['mount']={'kernel_mounted':all(r['kernel_mounted'] for r in read('mounted.json').values()),'ordinary_io':state['steps']['ordinary'],
        'workload_uid':1002,'control_uid':0,'workload_sudo_denied':True,'control_credentials_unreadable':True,'provenance':sha(evidence/'controls.json')}
    m['cases']=state['cases'];metrics=read('metrics-service/read-proof.json')
    m['cases']['cold-warm-range']={'passed':metrics['passed'],'provenance':sha(evidence/'metrics-service/read-proof.json'),'measurement_boundary':metrics['boundary'],'default_service_mounted_transfer_accounting':False}
    m['cleanup']={'unresolved':[]};cleanup=read('owned-cleanup.json');assert cleanup['ok'] and cleanup['resources_removed']
    actualservice=read('default-service-final-identity.json');assert actualservice['binary_sha256']==service['binary_sha256'] and not actualservice['fault_variables']
    bridge={'packaged_source':old,'current_source':current,'runtime_inputs_equal':True,'differences':{n:{'earlier':old.get(n),'current':current.get(n)} for n in sorted(set(old)|set(current)) if old.get(n)!=current.get(n)}}
    (output/'source-bridge.json').write_text(json.dumps(bridge,indent=2)+'\n')
    raw={str(p):sha(p) for p in evidence.rglob('*') if p.is_file() and 'control' not in p.parts and p.suffix in ('.json','.log','.bin','.txt')}
    (output/'evidence-index.json').write_text(json.dumps(raw,indent=2)+'\n')
    return normalize({'schema':1,'phase':'provider','status':'passed','executed':True,'execution':'resumed owned staged journey','failures':[],'blocked':[],
        'source':{'verified':True,'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True,cwd=Path(__file__).resolve().parents[2]).strip(),'manifest_sha256':canonical_sha(current),'bridge':str(output/'source-bridge.json')},
        'binaries':{'verified':True,'image':state['image'],'sha256':{'magus-fs':client['binary_sha256'],'magus-fs-service':service['binary_sha256']}},
        'assertions':provider_assertions(evidence,m,state['cases']),
        'composition':{'new_execution':False,'kind':'retained-observation revalidation','original_guard_sha256':deletion['guard_sha256'],
            'original_guard_path':str(evidence/'completion-guard.json'),
            'original_result':{'path':config.get('original_result'),'sha256':sha(config['original_result'])} if config.get('original_result') else None,
            'historical_conflict_derivation':str(output/'historical-conflict-derivation.json') if config.get('historical_conflict_package') else None},
        'measurements':m,'cleanup':{'ok':True,'mounts_absent':False,'resources_removed':True,'provider_absent':True,'local_mounts_absent':True,'lifecycle':'disposable-daytona','provenance':sha(evidence/'owned-cleanup.json')}})

def run_hosted(config,manifest_path,output):
    """Actual owned journey. Exceptions retain all known resources and raw evidence."""
    import json,traceback
    from pathlib import Path
    result={'schema':1,'phase':'provider','status':'blocked','executed':False,'failures':[],
        'blocked':[],'resources_created':[],'measurements':{},
        'cleanup':{'ok':False,'mounts_absent':False,'resources_removed':False,'provenance':'owned resources preserved'}}
    try:
        required=('sandbox_id','owned_name','ssh_config','ssh_host','owned_service_dir','service_url','daytona_env_file')
        if any(not config.get(k) for k in required) or not manifest_path:
            result['blocked'].append('owned worker, private transport, service and package inputs required')
            return result
        evidence=Path(config.get('retained_output',output))
        if config.get('historical_conflict_package'):
            assert evidence!=Path(output),'revalidation output must be fresh'
            assert (evidence/'owned-cleanup.json').exists(),'historical revalidation cannot execute missing stages'
        else:execute_hosted(config,evidence)
        result=hosted_result(config,manifest_path,evidence,Path(output))
    except Exception as error:
        result['status']='failed';result['failures'].append(type(error).__name__+': '+str(error))
        (Path(output)/'failure.log').write_text(traceback.format_exc())
    finally:
        (Path(output)/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def main():
    import argparse
    import json
    from pathlib import Path
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-manifest',type=Path,required=True)
    parser.add_argument('--provider-config',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--preflight',action='store_true')
    args=parser.parse_args()
    if not args.output.is_absolute():parser.error('new absolute output required')
    args.output.mkdir(mode=0o700)
    try:
        if args.provider_config.stat().st_mode&0o077:
            raise ValueError('provider configuration must be private (0600)')
        config=json.loads(args.provider_config.read_text())
        result=preflight(config,args.package_manifest) if args.preflight else run_hosted(config,args.package_manifest,args.output)
    except (OSError,ValueError):
        result={'schema':1,'phase':'provider','status':'blocked','executed':False,'failures':[],
                'blocked':['private provider configuration unavailable or invalid'],
                'cleanup':{'ok':True,'mounts_absent':True,'resources_removed':True,'provenance':'no resources created'}}
    (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return {'passed':0,'failed':1,'blocked':2}[result['status']]


if __name__=='__main__':
    import sys
    sys.exit(main())
