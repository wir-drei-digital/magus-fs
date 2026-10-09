"""Strict V1–V12 aggregation. Evidence cannot be inferred from an exit code."""
import json
from pathlib import Path
from inventory import CLI_CASES

CASES=tuple('V'+str(i) for i in range(1,13))

def digest(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)

def revision(value):
    return isinstance(value,str) and value.startswith('sha256:') and digest(value[7:])

def nonnegative(value):
    return type(value) is int and value>=0

def status_valid(value):
    return (isinstance(value,dict) and value.get('ok') is True
            and revision(value.get('captured_revision')) and revision(value.get('base_revision'))
            and nonnegative(value.get('working_generation'))
            and (type(value.get('uncaptured')) is bool or value.get('uncaptured')=='unknown'))

def assertions_valid(values):
    return isinstance(values,list) and bool(values) and all(
        isinstance(a,dict) and isinstance(a.get('name'),str) and bool(a['name'])
        and {'observed','expected'}<=set(a) and a.get('passed') is True for a in values)

def cli_valid(test):
    commands=test.get('commands')
    if not (test.get('state')=='passed' and assertions_valid(test.get('assertions'))
            and test.get('cleanup_absent') is True and test.get('failures')==[]
            and test.get('skips')==[] and isinstance(test.get('stdout'),str)
            and isinstance(commands,list) and commands):return False
    for record in commands:
        if not isinstance(record,dict):return False
        command,options,result=record.get('command'),record.get('options'),record.get('result')
        if not (isinstance(command,list) and command and isinstance(command[0],str)
                and isinstance(options,dict) and isinstance(result,dict)):return False
        code=options.get('code',0)
        if type(code) is not int or code not in [0,1,2] or result.get('ok') is not (code==0):return False
        if code and not (isinstance(result.get('error'),str) and result['error']):return False
    return True

def closure_valid(value):
    mounted=value.get('mounted',{});complete=value.get('full',{})
    if not (value.get('verified') is True and value.get('daemon_stopped') is True
            and revision(value.get('revision')) and isinstance(mounted,dict)
            and {'.','instructions.md','data.csv','report.sh','binary','large','empty'}<=set(mounted)
            and mounted==complete):return False
    for entry in mounted.values():
        if not (isinstance(entry,dict) and entry.get('kind') in ['file','directory']
                and nonnegative(entry.get('mode')) and entry['mode']<=0o777
                and nonnegative(entry.get('uid')) and nonnegative(entry.get('gid'))):return False
        if entry['kind']=='file' and not (nonnegative(entry.get('size')) and digest(entry.get('sha256'))):return False
    return True

def recovery_valid(value,mac):
    absent={'moved','atomic','no-write'} if mac else {'made','moved','atomic','unlink-parent/no-write'}
    return (value.get('bytes')=={'new':'new generation','uncached':'full offline replacement','offline-new':'ACK survives daemon loss'}
            and value.get('modes',{}).get('new')=='0640' and absent<=set(value.get('absent',[])))

def archive_valid(value,platform,evidence):
    original=(Path(evidence).parent/'macos/fixture/original') if platform=='macos' else Path('/tmp/fixture/original')
    required={str(original/leaf) for leaf in ['state/journal.sqlite','state/objects','tree/binary']}
    access=value.get('original_access',[])
    if not (isinstance(access,list) and len(access)==3 and all(isinstance(x,dict) for x in access)
            and {x.get('path') for x in access}==required
            and all(x.get('errno') in ([1,13] if platform=='macos' else [2])
                    and isinstance(x.get('error'),str) and x['error'] for x in access)):return False
    network=value.get('network',[])
    if not (isinstance(network,list) and len(network)==2 and all(isinstance(x,dict) for x in network)
            and {x.get('kind') for x in network}=={'tcp','udp'}):return False
    for record in network:
        address=record.get('address')
        if not (record.get('errno') in ([1,13] if platform=='macos' else [1,13,101,113])
                and isinstance(record.get('error'),str) and record['error']
                and isinstance(address,list) and len(address)==2):return False
        if platform=='macos' and record['kind']=='tcp':
            if address[0]!='127.0.0.1' or type(address[1]) is not int or not 0<address[1]<65536:return False
        elif address!=['192.0.2.1',9]:return False
    errors={'missing':'io_error','corrupt':'corrupt_object','extra':'invalid_descriptor','descriptor_reference':'invalid_descriptor','provenance':'invalid_descriptor'}
    malformed=value.get('malformed',[])
    if not (isinstance(malformed,list) and len(malformed)==5 and all(isinstance(x,dict) for x in malformed)
            and {x.get('case') for x in malformed}==set(errors)
            and all(x.get('error')==errors[x['case']] and x.get('destination_absent') is True for x in malformed)):return False
    files=value.get('files',{})
    if not isinstance(files,dict) or set(files)!={'._ordinary','binary','data.csv','deleted.txt','report.sh'}:return False
    for name,entry in files.items():
        if not (isinstance(entry,dict) and nonnegative(entry.get('length')) and digest(entry.get('sha256'))
                and entry.get('mode')==(0o700 if name=='report.sh' else 0o600)):return False
    restored=value.get('restored',{})
    if not (restoration_valid(restored) and restored.get('verified_bytes')==sum(e['length'] for e in files.values())):return False
    commands=value.get('commands',[]);verified=False;restored_ok=False;rejected=set()
    if not isinstance(commands,list):return False
    for record in commands:
        if not isinstance(record,dict):return False
        argv=record.get('argv',[])
        if not isinstance(argv,list) or len(argv)<2 or not isinstance(record.get('stderr'),str):return False
        try:result=json.loads(record['stdout'])
        except (KeyError,TypeError,ValueError):return False
        if not isinstance(result,dict):return False
        if argv[1]=='verify' and record.get('exit')==0:
            verified=(result.get('ok') is True and result.get('verification',{}).get('revisions')==3
                      and result['verification'].get('revision')==restored['source_revision'])
        elif argv[1]=='restore' and record.get('exit')==0:
            restored_ok=result.get('ok') is True and result.get('result')==restored
        elif argv[1]=='restore' and record.get('exit')==1:
            try:
                damaged=Path(argv[argv.index('--archive')+1]).name
                destination=Path(argv[argv.index('--destination')+1]).name
            except (ValueError,IndexError,TypeError):return False
            name=damaged.removeprefix('bad-')
            if name not in errors or damaged!='bad-'+name or destination!='reject-'+name:return False
            if result.get('ok') is not False or result.get('error')!=errors[name]:return False
            rejected.add(name)
        else:return False
    return value.get('passed') is True and verified and restored_ok and rejected==set(errors)

def restoration_valid(value):
    return (isinstance(value,dict) and revision(value.get('source_revision')) and revision(value.get('derived_revision'))
            and value['source_revision']!=value['derived_revision'] and value.get('head_changed') is False
            and isinstance(value.get('destination'),str) and value['destination'].startswith('/')
            and nonnegative(value.get('verified_bytes')))

def validate_profile(p):
    errors=[]
    def require(ok,label):
        if not ok:errors.append(label)
    require(p.get('platform') in ['macos','linux'] and p.get('journey') in [1,2],'platform/journey')
    for field in ['source_hashes','binary_sha256','fault_binary_sha256']:
        require(bool(p.get(field)),'missing '+field)
    require(p.get('closure_verified') is True,'unverified closure')
    require(p.get('warm_body_delta')==0,'warm transfer not zero')
    require(bool(p.get('checkpoint_revision')) and p.get('checkpoint_revision')==p.get('recovered_revision'),'stale checkpoint after ACK')
    require(p.get('interrupted') is False,'interrupted or unknown interruption')
    for field in ['native_exit','cli_exit','archive_exit','retention_exit']:require(p.get(field)==0,field)
    cleanup=p.get('cleanup',{})
    require(cleanup.get('verified') is True,'cleanup unverified')
    for field in ['remaining_mounts','remaining_containers','remaining_pids']:require(cleanup.get(field)==[],field)
    for name in CASES:
        c=p.get('cases',{}).get(name,{})
        require(c.get('state')=='passed',name+' not passed')
        require(bool(c.get('evidence')),name+' missing evidence')
        assertions=c.get('assertions',[])
        require(assertions_valid(assertions),name+' missing/failed assertions')
    return errors

def aggregate(profiles,blocked=()):
    failures=[];identities=[(p.get('platform'),p.get('journey')) for p in profiles]
    required={(p,j) for p in ['macos','linux'] for j in [1,2]}
    if set(identities)!=required or len(identities)!=4:failures.append('mandatory two fresh journeys per OS absent/duplicated')
    for p in profiles:failures.extend(f"{p.get('platform')}/{p.get('journey')}: {error}" for error in validate_profile(p))
    code=2 if blocked else 1 if failures else 0
    return {'schema':'fs1-qualification-v1','passed':code==0,'state':'blocked' if blocked else 'failed' if failures else 'passed','exit_code':code,'failures':failures,'blocked':list(blocked),'profiles':profiles}

def observation(name,observed,expected,passed):return {'name':name,'observed':observed,'expected':expected,'passed':bool(passed)}
def case(assertions,evidence):return {'state':'passed' if assertions and all(a['passed'] for a in assertions) else 'failed','assertions':assertions,'evidence':evidence}

def normalize(platform,journey,native,cli,archive,retention,paths):
    n=native;c=n.get('cases',{});mac=platform=='macos';cases={}
    def add(v,name,observed,expected,passed,source='native'):
        entry=cases.setdefault(v,case([],[]));entry['assertions'].append(observation(name,observed,expected,passed));entry['evidence'].append(str(paths[source]));entry['state']='passed' if all(a['passed'] for a in entry['assertions']) else 'failed'
    cold=n.get('cold_warm_transfer',{}) if mac else n.get('transfer',{}).get('cold',{})
    warm=n.get('warm_transfer',{}) if mac else n.get('transfer',{}).get('warm',{})
    meta=n.get('metadata_transfer',{}) if mac else n.get('transfer',{}).get('metadata',{})
    delta=warm.get('body_bytes',-1)-cold.get('body_bytes',-2)
    full=c.get('full-view',{}) if mac else c.get('full',{})
    add('V2','metadata zero source bodies',meta,0,meta.get('body_bytes')==0)
    add('V2','cold range bytes',cold,'0 < bytes <= 2097152',0<cold.get('body_bytes',0)<=2097152)
    add('V2','warm delta',delta,0,delta==0)
    add('V2','full independent digest',full,{'size':67108864,'sha256':'0d9f8390657caaf114fa00a6a191f1559b488bb89f7c61b9e8d95b392330c3e4'},full=={'size':67108864,'sha256':'0d9f8390657caaf114fa00a6a191f1559b488bb89f7c61b9e8d95b392330c3e4'})
    closure=n.get('full_closure',{})
    closure_ok=closure_valid(closure)
    add('V1','same revision closure full vs mounted' ,closure,'equal hashes/names/modes/uid/gid; daemon stopped',closure_ok)
    writes=c.get('writes-view',{}) if mac else c.get('writes',{})
    key='create_append_sparse_truncate_unlink_replace_modes_fsync' if mac else 'append_sparse_unlink_replace_mkdir_rename_modes_fsync_flock'
    add('V3','native identity and mutations',writes,key,writes.get(key) is True)
    old=c.get('historical-history',{}) if mac else c.get('old-revision',{})
    add('V3','old revision remains readable',old,'old revision verified',all(old.get(key) is True for key in (['original_revision_bytes','new_paths_absent'] if mac else ['old_revision_references_preserved'])))
    recovery=c.get('recovered-old',{}) if mac else c.get('recovered',{})
    add('V4','ACK byte metadata namespace recovery',recovery,'three acknowledged byte strings, mode0640 and removed names',recovery_valid(recovery,mac))
    before_checkpoint=c.get('recovered-restart' if mac else 'dirty-fsync-recovered',{})
    add('V4','precheckpoint ACK recovery',before_checkpoint,'acknowledged working state before checkpoint',recovery_valid(before_checkpoint,mac))
    loss=n.get('crashes',[]) if mac else [n.get('dirty_fsync_loss',{}),n.get('loss',{})]
    loss_ok=(isinstance(loss,list) and len(loss)==2 and all(isinstance(x,dict) for x in loss))
    if loss_ok:
        loss_ok=all(x.get('killed_exit')==-9 and x.get('old_handle_status')==70 and x.get('normal_unmount') is True and x.get('cleanup_root_access')==0 for x in loss) if mac else all(type(x.get('pid')) is int and x['pid']>0 and x.get('returncode')==-9 and x.get('mounted') is False for x in loss)
    add('V4','owned daemon loss and safe restart',loss,'two actual process kills and safe unmount',loss_ok)
    cp=n.get('checkpoint',{}).get('revision');after=n.get('postcheckpoint_status',{}).get('captured_revision')
    add('V4','checkpoint ACK equals restart head',after,cp,revision(cp) and n.get('checkpoint',{}).get('ok') is True and status_valid(n.get('postcheckpoint_status')) and after==cp)
    dirty=n.get('dirty_recovery',{})
    add('V4','dirty fsync durable without checkpoint',dirty,'before == after; uncaptured true',status_valid(dirty.get('before')) and dirty.get('before')==dirty.get('after') and dirty.get('after',{}).get('uncaptured') is True)
    off=c.get('offline-view',{}) if mac else c.get('offline',{})
    add('V6','missing base bounded error',off,'EIO/ENETDOWN in <5s',off.get('uncached_errno') in [5,50,100] and 0<=off.get('uncached_seconds',99)<5)
    if mac:add('V6','cached reads and offline writes',off,'cached read and replacement/new fsync',off.get('cached_read') is True and off.get('offline_replacement_new_fsync') is True)
    outage=n.get('source_offline' if mac else 'source_outage',{})
    add('V6','original source stopped',outage,'listener closed and source thread joined',outage.get('listener_closed') is True and outage.get('thread_joined') is True and (mac or outage.get('offline') is True and outage.get('connect_errno')==111))
    if mac:
        perms=c.get('permissions-view',{});mapping=c.get('mapping-view',{});ro=c.get('readonly-ro',{})
        add('V7','owner parent permissions',perms,'EACCES for missing read/search; writable-parent unlink',all(perms.get(k)==13 for k in ['mode000_errno','no_search_errno','no_read_errno']) and perms.get('readonly_child_unlink') is True)
        errors=mapping.get('group_other_and_execute',{})
        add('V7','mapped authority and execute',mapping,'uid/gid10001; four EACCES denials',mapping.get('foreign_owner_uid')==10001 and mapping.get('other_gid')==10001 and set(errors)=={'group','other','denied-other','noexec'} and all(v==13 for v in errors.values()))
        add('V7','readonly mutations',ro,'nine EROFS denials',ro.get('denials')==[30]*9)
    else:
        perms=c.get('owner-permissions',{})
        add('V7','owner parent permissions',perms,'three EACCES; writable-parent unlink',all(perms.get(k)==13 for k in ['read_without_search','search_without_read','mode000']) and perms.get('writable_parent_unlink') is True)
        for name,key in [('group','group_write'),('other','other_read')]:add('V7',name,c.get(name),13,c.get(name,{}).get(key)==13)
        for name in ['readonly-owner','readonly-root']:
            value=c.get(name,{})
            add('V7',name,value,'ten EROFS denials',set(value)=={'write','create','mkdir','truncate','rename','unlink','chmod','chown','root-chmod','xattr'} and all(v==30 for v in value.values()))
        root=c.get('root-confinement',{})
        add('V7','confined root',root,'configured DAC only; no control access',root.get('configured_root_dac') is True and root.get('confinement',{}).get('uid')==0 and all(root.get('confinement',{}).get(k) is True for k in ['source_unreachable','control_paths_absent','daemon_pids_absent','umount_remount_namespace_denied']) and all(root.get('confinement',{}).get('capabilities',{}).get(k)==v for k,v in {'CapEff':'0000000000000002','CapBnd':'0000000000000002','NoNewPrivs':'1'}.items()))
    fault=n.get('fault',{}) if mac else n.get('diskfull_head',{})
    if mac:
        native_fault=fault.get('native',{})
        fault_ok=(native_fault.get('durable_write_errno')==28 and status_valid(native_fault.get('before_write'))
                  and native_fault.get('before_write')==native_fault.get('after_write')
                  and digest(native_fault.get('working_sha256_before_after')) and c.get('fault-fault')==native_fault
                  and fault.get('old_bytes_after_restart') is True
                  and c.get('binary-fault-restart')=={'bytes':614400,'sha256':'3c7e7ecba97572f06d6792084bf56a8b2e428534e1e36f0bdf009facfac29512'})
    else:
        fault_ok=(status_valid(fault.get('before')) and fault.get('before')==fault.get('after')
                  and c.get('diskfull',{}).get('errno')==28 and c.get('old-head',{}).get('old_head_bytes') is True)
    add('V8','native ENOSPC old state retained',{'status':fault,'failure':c.get('fault-fault' if mac else 'diskfull'),'restart':c.get('binary-fault-restart' if mac else 'old-head')},'ENOSPC28; equal head/generation and verified old bytes after restart',fault_ok)
    add('V8','quota corruption pin prune last copy',retention,'direct engine disk observations',retention.get('quota_error')=='backpressure' and retention.get('corruption_error')=='corrupt_object' and retention.get('last_copy_error')=='base_unavailable' and retention.get('pinned_bytes')==8 and retention.get('reclaimed_bytes')==8 and retention.get('ack_bytes')=='ACK' and retention.get('cleanup_absent') is True and nonnegative(retention.get('generation_unchanged')),'retention')
    for v,names in CLI_CASES.items():
        for name in names:
            test=cli.get('tests',{}).get(name,{})
            add(v,name,{'assertions':test.get('assertions'),'commands':test.get('commands'),'stdout':test.get('stdout')},'successful direct native CLI assertions; clean owned fixture',cli_valid(test),'cli')
    a=archive.get('platforms',{}).get(platform,{})
    add('V9','independent offline archive',a,'exact original paths denied; TCP/UDP denied; complete file metadata and five expected rejection cases',archive_valid(a,platform,paths['archive']),'archive')
    add('V10','derived current-policy revision',a.get('restored',{}),'valid source != derived; detached output',restoration_valid(a.get('restored')),'archive')
    add('V12','private checkpoint replay',n.get('checkpoint_replay'),n.get('checkpoint'),n.get('checkpoint',{}).get('ok') is True and revision(n.get('checkpoint',{}).get('revision')) and n.get('checkpoint_replay')==n['checkpoint'])
    add('V12','changed private checkpoint payload rejected',{'error':n.get('checkpoint_mismatch'),'status':n.get('postmismatch_status')},'operation_mismatch; exact head/status retained',n.get('checkpoint_mismatch',{}).get('error')=='operation_mismatch' and status_valid(n.get('postcheckpoint_status')) and n.get('postmismatch_status')==n.get('postcheckpoint_status'))
    add('V12','mounted owner commands busy',n.get('mounted_owner_busy'),'replica_busy for export restore prune grants',set(n.get('mounted_owner_busy',{}))=={'export','restore','prune','history-grants'} and all(v=='replica_busy' for v in n.get('mounted_owner_busy',{}).values()))
    return {'platform':platform,'journey':journey,'cases':cases,'closure_verified':closure_ok,'warm_body_delta':delta,'checkpoint_revision':cp,'recovered_revision':after,'qualification_limits':n.get('qualification_limits',[])}
