"""Strict V1–V12 aggregation. Evidence cannot be inferred from an exit code."""
from inventory import CLI_CASES

CASES=tuple('V'+str(i) for i in range(1,13))

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
        require(bool(assertions) and all(a.get('passed') is True and all(k in a for k in ['name','observed','expected']) for a in assertions),name+' missing/failed assertions')
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
    mounted=closure.get('mounted',{});complete=closure.get('full',{})
    closure_ok=(closure.get('verified') is True and closure.get('daemon_stopped') is True and bool(closure.get('revision'))
                and {'.','instructions.md','data.csv','report.sh','binary','large','empty'}<=set(mounted)
                and mounted==complete and all({'kind','mode','uid','gid'}<=set(entry) and (entry['kind']=='directory' or {'size','sha256'}<=set(entry)) for entry in mounted.values()))
    add('V1','same revision closure full vs mounted' ,closure,'equal hashes/names/modes/uid/gid; daemon stopped',closure_ok)
    writes=c.get('writes-view',{}) if mac else c.get('writes',{})
    key='create_append_sparse_truncate_unlink_replace_modes_fsync' if mac else 'append_sparse_unlink_replace_mkdir_rename_modes_fsync_flock'
    add('V3','native identity and mutations',writes,key,writes.get(key) is True)
    old=c.get('historical-history',{}) if mac else c.get('old-revision',{})
    add('V3','old revision remains readable',old,'old revision verified',bool(old))
    recovery=c.get('recovered-old',{}) if mac else c.get('recovered',{})
    required_absent={'moved','atomic','no-write'} if mac else {'made','moved','atomic','unlink-parent/no-write'}
    add('V4','ACK byte metadata namespace recovery',recovery,'three acknowledged byte strings, mode0640 and removed names',recovery.get('bytes')=={'new':'new generation','uncached':'full offline replacement','offline-new':'ACK survives daemon loss'} and recovery.get('modes',{}).get('new')=='0640' and required_absent<=set(recovery.get('absent',[])))
    cp=n.get('checkpoint',{}).get('revision');after=n.get('postcheckpoint_status',{}).get('captured_revision')
    add('V4','checkpoint ACK equals restart head',after,cp,bool(cp) and after==cp)
    dirty=n.get('dirty_recovery',{})
    add('V4','dirty fsync durable without checkpoint',dirty,'before == after; uncaptured true',bool(dirty.get('before')) and dirty.get('before')==dirty.get('after') and dirty.get('after',{}).get('uncaptured') is True)
    off=c.get('offline-view',{}) if mac else c.get('offline',{})
    add('V6','missing base bounded error',off,'EIO/ENETDOWN in <5s',off.get('uncached_errno') in [5,50,100] and 0<=off.get('uncached_seconds',99)<5)
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
        add('V7','confined root',root,'configured DAC only; no control access',root.get('configured_root_dac') is True and bool(root.get('confinement')))
    fault=n.get('fault',{}) if mac else n.get('diskfull_head',{})
    add('V8','native ENOSPC old state retained',fault,'native ENOSPC; restart old bytes',fault.get('old_bytes_after_restart') is True if mac else bool(fault.get('before')) and fault['before']==fault.get('after'))
    add('V8','quota corruption pin prune last copy',retention,'direct engine disk observations',retention.get('quota_error')=='backpressure' and retention.get('corruption_error')=='corrupt_object' and retention.get('last_copy_error')=='base_unavailable' and retention.get('pinned_bytes')==8 and retention.get('reclaimed_bytes')==8 and retention.get('ack_bytes')=='ACK' and retention.get('cleanup_absent') is True,'retention')
    for v,names in CLI_CASES.items():
        for name in names:
            test=cli.get('tests',{}).get(name,{})
            add(v,name,{'assertions':test.get('assertions'),'commands':test.get('commands'),'stdout':test.get('stdout')},'successful direct native CLI assertions; clean owned fixture',test.get('state')=='passed' and bool(test.get('assertions')) and bool(test.get('commands')) and test.get('cleanup_absent') is True,'cli')
    a=archive.get('platforms',{}).get(platform,{})
    add('V9','independent offline archive',a,'no original access; network denied; restored all hashes/modes and executable',a.get('passed') is True and len(a.get('original_access',[]))==3 and len(a.get('network',[]))==2 and all(x.get('errno') in [1,13,51,65,101,113] for x in a.get('network',[])) and bool(a.get('files')) and len(a.get('malformed',[]))==5,'archive')
    add('V10','derived current-policy revision',a.get('restored',{}),'source != derived; detached output',bool(a.get('restored',{}).get('derived_revision')) and a['restored']['derived_revision']!=a['restored'].get('source_revision') and a['restored'].get('head_changed') is False,'archive')
    add('V12','private checkpoint replay',n.get('checkpoint_replay'),n.get('checkpoint'),bool(n.get('checkpoint')) and n.get('checkpoint_replay')==n['checkpoint'])
    add('V12','changed private checkpoint payload rejected',{'error':n.get('checkpoint_mismatch'),'status':n.get('postmismatch_status')},'operation_mismatch; exact head/status retained',n.get('checkpoint_mismatch',{}).get('error')=='operation_mismatch' and bool(n.get('postcheckpoint_status')) and n.get('postmismatch_status')==n.get('postcheckpoint_status'))
    add('V12','mounted owner commands busy',n.get('mounted_owner_busy'),'replica_busy for export restore prune grants',set(n.get('mounted_owner_busy',{}))=={'export','restore','prune','history-grants'} and all(v=='replica_busy' for v in n.get('mounted_owner_busy',{}).values()))
    return {'platform':platform,'journey':journey,'cases':cases,'closure_verified':closure_ok,'warm_body_delta':delta,'checkpoint_revision':cp,'recovered_revision':after,'qualification_limits':n.get('qualification_limits',[])}
