"""Strict normalization of ordinary-process macOS evidence; no native actions."""
import errno
import json
import re

from permission_source import project_manifest
from qualification import validate_content_profile

MOUNTS = ('normal-ro','normal-private','resumed-private','group','other','file000','file644',
          'directory000','directory400','directory100','generation-old','generation-fresh','source-failure')
PERMISSIONS = ('group','other','file000','file644','directory000','directory400','directory100')
BASE = ('mount','metadata_permissions','range_reads','warm_repeat','mmap_read','locks_observation','root_metadata')


def value(data, *keys):
    for key in keys:
        if not isinstance(data,dict):
            return None
        data=data.get(key)
    return data


def summarize_macos(native, journey, chunk, evidence):
    cases=native.get('cases',{})
    commands=native.get('commands',[])
    mounts=native.get('mounts',{})
    actor=native.get('environment',{}).get('actor_uid_gid',[])
    manifest=mounts.get('normal-ro',{}).get('manifest',{})
    digest=native.get('manifest_digest')
    observations={name:case.get('observed') for name,case in cases.items()}
    def observed(name):
        return observations.get(name)
    def get(name,*keys):
        return value(observed(name),*keys)
    def command_ok(row):
        return (type(row.get('returncode')) is int and row['returncode']==0
                and not row.get('timeout') and not row.get('kill_pending') and bool(row.get('command')))
    def stage(name):
        rows=[row for row in commands if row.get('name')==name]
        case=cases.get(name,{})
        return (case.get('state')=='passed' and len(rows)==1 and command_ok(rows[0])
                and case.get('command')==rows[0]['command'])
    def errno_ok(result,allowed=(errno.EACCES,errno.EPERM)):
        return isinstance(result,dict) and result.get('errno') in allowed
    def states(name,required):
        return stage(name) and all(get(name,key,'state')=='passed' for key in required)
    def root_ok(name):
        root=get(name,'root_metadata','detail')
        return (isinstance(root,dict) and len(actor)==2 and root.get('uid')==actor[0]
                and root.get('gid')==actor[1] and root.get('mode')==0o755)
    def locks_ok(name):
        detail=get(name,'locks_observation','detail')
        # Darwin EAGAIN/EWOULDBLOCK are both35, even when parsing on Linux.
        return (isinstance(detail,dict) and detail.get('state')=='contended'
                and detail.get('operation')=='flock' and type(detail.get('errno')) is int
                and detail['errno']==35 and detail.get('contender_returncode')==75
                and bool(detail.get('command')))
    def metadata_ok(name):
        expected=[{'path':entry['path'],'uid_gid_mode':[entry['uid'],entry['gid'],entry['mode']]} for entry in manifest.get('entries',[])]
        return bool(expected) and get(name,'metadata_permissions','detail')==expected
    readonly_required=BASE+tuple('readonly_'+op for op in ('write','truncate','chmod','unlink','rename','create'))
    ro=states('readonly',readonly_required) and root_ok('readonly') and metadata_ok('readonly') and locks_ok('readonly')
    ro=ro and all(errno_ok(get('readonly','readonly_'+op,'detail'),(errno.EROFS,errno.EACCES,errno.EPERM)) for op in ('write','truncate','chmod','unlink','rename','create'))
    private_required=BASE+('private_writes','rename_replacement_old_handle','private_execute0755','old_handle_mmap_visibility')
    private=states('private',private_required) and root_ok('private') and metadata_ok('private') and locks_ok('private')
    private=private and errno_ok(get('private','private_execute0644_denied')) and get('private','private_execute0755','stdout')=='synthetic\n'
    private=private and get('private','rename_replacement_old_handle','errno')==errno.EROFS and get('private','rename_replacement_old_handle','observed_support')=='unsupported CREATE; replacement was not performed'
    rename=get('private','rename_existing_classification')
    private=private and errno_ok(rename,(errno.EROFS,errno.EOPNOTSUPP,errno.ENOSYS)) and value(rename,'observed_support')=='unsupported; only the denial characterization passed'
    private=private and stage('persist') and get('persist','native_fsync_returned') is True and get('persist','durable_prefix')=='durable' and get('persist','mode')==0o444
    private=private and stage('resumed') and get('resumed','native_remount_data_and_chmod_preserved') is True and errno_ok(get('resumed','write_open_denied')) and get('resumed','process_restart_only')=='not power-cut proof'
    hydration=sum(entry['size'] for entry in manifest.get('entries',[]) if not entry.get('directory'))
    private=private and hydration>67108864 and native.get('private_hydrated_bytes')==hydration and mounts.get('normal-private',{}).get('hydrated_bytes')==hydration
    generation=(stage('generation') and get('generation','old_open_and_mmap_pinned') is True
                and get('generation','fresh_generation_mode')==0o640 and get('generation','old_mode_after_ttl')==0o644
                and get('generation','in_place_invalidation')=='unsupported: no generation publication API')
    fault=(stage('failure-warm') and get('failure-warm','exact_tiny_file') is True
           and stage('source-failure') and get('source-failure','warmed_file_survives_source_failure') is True
           and errno_ok(get('source-failure','uncached_read'),(errno.EIO,))
           and stage('source-recovery') and get('source-recovery','exact_head_tail') is True)
    permission=all(stage(name) for name in PERMISSIONS) and len(actor)==2
    permission=permission and get('group','read_via_group') is True and get('group','mode')==0o040 and get('group','uid')==12345 and actor[0]!=12345 and get('group','gid')==actor[1]
    permission=permission and get('other','read_via_other') is True and get('other','mode')==0o004 and get('other','uid')==get('other','gid')==12345 and actor[1]!=12345
    permission=permission and errno_ok(get('file000','read_denied')) and errno_ok(get('file644','direct_execute_denied'))
    permission=permission and errno_ok(get('directory000','listing_denied')) and errno_ok(get('directory000','child_read_denied'))
    permission=permission and get('directory400','names_readable_without_search') is True and errno_ok(get('directory400','child_read_denied')) and errno_ok(get('directory400','child_stat_denied'))
    permission=permission and get('directory100','search_without_listing') is True and errno_ok(get('directory100','listing_denied')) and private
    subprocess_ok=(stage('subprocess') and get('subprocess','output')=='synthetic\n'
                   and get('subprocess','direct_execute','supported') is True and get('subprocess','direct_execute','stdout')=='synthetic\n'
                   and stage('file644') and errno_ok(get('file644','direct_execute_denied')) and private)
    manifest_ok=False
    expected_digests={}
    try:
        checked=project_manifest(manifest)
        identity=native.get('fixture_identity',{})
        manifest_ok=(checked['digest']==digest==identity['projected_digest'] and checked['chunk_size']==chunk==native['chunk_size']
                     and identity['projection']=={'uid':native['fixture_uid_gid'][0],'gid':native['fixture_uid_gid'][1]}
                     and all([entry['uid'],entry['gid']]==native['fixture_uid_gid'] for entry in checked['entries']))
        expected_digests={name:digest for name in ('normal-ro','normal-private','resumed-private','generation-old','source-failure')}
        variants={'group':(None,0o040,12345,actor[1]),'other':(None,0o004,12345,12345),
                  'file000':(None,0,actor[0],actor[1]),'file644':(None,0o644,actor[0],actor[1]),
                  'directory000':(0,None,actor[0],actor[1]),'directory400':(0o400,None,actor[0],actor[1]),'directory100':(0o100,None,actor[0],actor[1])}
        expected_digests.update({name:project_manifest(checked,*args)['digest'] for name,args in variants.items()})
        expected_digests['generation-fresh']=project_manifest(checked,file_mode=0o640)['digest']
        manifest_ok=manifest_ok and native['generation_digests']=={'old':digest,'fresh':expected_digests['generation-fresh']} and expected_digests['generation-fresh']!=digest
    except (KeyError,TypeError,AssertionError,IndexError):
        manifest_ok=False
    mounted=manifest_ok and set(mounts)==set(MOUNTS)
    for name in MOUNTS:
        mount=mounts.get(name,{})
        point=mount.get('mountpoint','')
        options=set(mount.get('effective_options','').split(','))
        actual=mount.get('actual_mount_command',[])
        rows=[row for row in commands if row.get('name')==name+'-mount']
        row=mount.get('mount_table_entry','')
        expected_mode='private' if name in ('normal-private','resumed-private') else 'ro'
        access='rw' if expected_mode=='private' else 'ro'
        argv_options=set(actual[2].split(',')) if len(actual)==5 and isinstance(actual[2],str) else set()
        server=mount.get('server_command',[])
        mode_index=server.index('--mode') if '--mode' in server else -1
        requested_mode=server[mode_index+1] if 0<=mode_index<len(server)-1 else None
        mounted=mounted and (point==native.get('owned_output','')+'/mount-'+name and bool(row) and ' on '+point+' (' in row
                            and mount.get('mode')==expected_mode and requested_mode==expected_mode
                            and ('read-only' in row)==(expected_mode=='ro')
                            and {access,'locallocks','vers=3','tcp','actimeo=1'}<=argv_options
                            and ('ro' if access=='rw' else 'rw') not in argv_options
                            and actual[:2]==['/sbin/mount_nfs','-o']
                            and len(actual)==5 and actual[-1]==point and len(rows)==1 and rows[0].get('command')==actual and command_ok(rows[0])
                            and {'locallocks','vers=3','tcp'}<=options and 'nolocks' not in options
                            and {key+'=1' for key in ('acregmin','acregmax','acdirmin','acdirmax','acrootdirmin','acrootdirmax')}<=options
                            and mount.get('manifest_digest')==expected_digests.get(name))
    mounted=mounted and states('readonly',BASE) and root_ok('readonly')
    cleanup=native.get('cleanup',[])
    expected_paths={mount.get('mountpoint') for mount in mounts.values()}
    owned=native.get('owned_pids',[])
    reaped=native.get('reaped',[])
    clean=(set(mounts)==set(MOUNTS) and len(cleanup)==len(MOUNTS) and {item.get('path') for item in cleanup}==expected_paths
           and all(item.get('returncode')==0 and item.get('still_mounted') is False and not item.get('timeout') for item in cleanup)
           and len(owned)==len(set(owned))==15 and {item.get('pid') for item in reaped}==set(owned) and len(reaped)==len(owned)
           and {mount.get('pid') for mount in mounts.values()}<=set(owned) and all(type(item.get('returncode')) is int for item in reaped)
           and all(command_ok(row) for row in commands) and bool(commands)
           and native.get('cleanup_errors')==[] and native.get('remaining_owned_resources')==[] and not native.get('remaining_owned_command_pids')
           and not native.get('cleanup_pending') and not native.get('cleanup_interrupts') and native.get('state')=='passed' and native.get('passed') is True and not native.get('error'))
    transfer=native.get('transfer',{})
    def report_case(names,expected,passed,detail=None):
        complete=all(stage(name) for name in names)
        failed=any(cases.get(name,{}).get('state')=='failed' for name in names)
        return {'state':'passed' if passed and complete else 'failed' if failed or complete else 'blocked',
                'expected':expected,'observed':detail if detail is not None else {name:cases.get(name) for name in names},
                'command':[row['command'] for row in commands if row.get('name') in names and row.get('command')]}
    profile_cases={
        'mount':report_case(('readonly',),'13 actual digest-pinned NFS mounts with TTL1/local locks; independently observed root metadata',mounted,{'mounts':mounts,'root_metadata':get('readonly','root_metadata')}),
        'range_reads':report_case(('readonly','generation','failure-warm','source-failure','source-recovery'),'exact ranges/EOF; pinned old/new generations; warmed/source-error/recovery contrasts',ro and generation and fault),
        'private_writes':report_case(('private','persist','resumed'),'eager existing-byte fsync/remount persistence; namespace create/rename explicitly unsupported',private),
        'readonly_view':report_case(('readonly',),'readonly mutations denied while file bytes remain intact',ro),
        'permissions':report_case((*PERMISSIONS,'private','persist','resumed'),'fixed-actor owner/group/other rwx and directory read/search contrasts',permission),
        'subprocess':report_case(('subprocess','private','persist','resumed','file644'),'direct0755 execution and0644 denial; interpreter/ordinary processes',subprocess_ok),
        'enumeration':report_case(('enumeration',),'exact names and zero source content bodies',observed('enumeration')==['data.bin','empty','instructions.md','nested','run.sh'] and transfer.get('enumeration',{}).get('content_body_bytes')==0),
        'partial_cold':report_case(('partial-cold',),'exact4KiB head/tail; <=8MiB including readahead/repeated source bodies',get('partial-cold','exact_head_tail') is True and validate_content_profile(transfer)),
        'partial_warm':report_case(('partial-warm',),'warm repetition adds zero source content bytes',get('partial-warm','exact_head_tail') is True and validate_content_profile(transfer)),
        'full_scan':report_case(('full-scan',),'actual64MiB scan equals independently known fixture SHA-256; exact deltas recorded',observed('full-scan')==transfer.get('full_scan') and validate_content_profile(transfer)),
        'cleanup':{'state':'passed' if clean else 'failed','expected':'all13 owned mounts absent; all15 owned PIDs reaped; no unresolved commands/interrupts/unknown cleanup',
                   'observed':{'cleanup':cleanup,'reaped':reaped,'cleanup_errors':native.get('cleanup_errors'),'remaining':native.get('remaining_owned_resources'),'interrupts':native.get('cleanup_interrupts')},
                   'command':[row['command'] for row in commands if row.get('name','').endswith('-unmount') and row.get('command')]},
    }
    profile_cases['mount']['command']=[row['command'] for row in commands if row.get('name')=='readonly' or row.get('name','').endswith(('-mount','-mount-table','-effective-options'))]
    def resource_list(key):
        raw=native.get(key)
        return raw if isinstance(raw,list) else []
    return {'journey':journey,'chunk_size':chunk,'manifest_digest':digest,'owned_token':native.get('owned_token'),
            'cases':profile_cases,'transfer':transfer,'cleanup_errors':resource_list('cleanup_errors'),
            'remaining_owned_resources':[*resource_list('remaining_owned_resources'),*resource_list('remaining_owned_command_pids')],
            'owned_resources':{'pids':owned,'command_pids':[row['pid'] for row in commands if 'pid' in row],'mountpoints':list(expected_paths),'output':native.get('owned_output')},
            'fixture_identity':native.get('fixture_identity'),'fixture_uid_gid':native.get('fixture_uid_gid'),'additional_fixture_digests':native.get('generation_digests'),
            'root_metadata':get('readonly','root_metadata','detail'),'source_revision':native.get('revision'),'binary_sha256':native.get('binary_sha256'),'environment':native.get('environment'),
            'mount_options':mounts,'native_evidence':str(evidence),'error':native.get('error'),
            'counter_scope':'Original Rust source response payloads; excludes projection/control/network framing bytes',
            'projected_manifest_response_bytes':len(json.dumps(manifest,separators=(',',':')).encode()),
            'guarantees':{'private_hydration':'eager','private_hydrated_bytes':native.get('private_hydrated_bytes'),
                          'private_durability':'existing-file fsync and backing remount; not power-cut proof','namespace_create_rename':'unsupported',
                          'live_invalidation':'unsupported','locks':'same-kernel client advisory locks; not distributed','root_binding':'outside manifest'},
            'observed_namespace_support':{'create':'unsupported','rename':'unsupported','private_chmod_truncate':'bounded existing-file support'}}
