"""Bounded FS0 matrix runner. Missing native proof always blocks qualification."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from inventory import collect
from preflight import check
from qualification import aggregate, CHUNKS, owned_containers_absent
from resources import OwnedOutput

MACOS_BLOCKER = ('Native macOS open/read/listdir remains unqualified after prior stalls. '
                 'Mac execution in this combined runner is disabled pending the controller-reviewed '
                 'bounded diagnostic and real native profiles. No Mac path/resource access or '
                 'macos_run invocation is performed here.')


def summarize_linux(native, journey, chunk, evidence):
    commands = native.get('commands', [])
    cases = native.get('cases', {})
    def command_for(name):
        return next((item['command'] for item in commands if item.get('stdout') == name + '.stdout'), [])
    def observation(name, expected, observed, passed):
        return {'state':'passed' if passed else 'failed' if native.get('error') else 'blocked',
                'expected':expected, 'observed':observed, 'command':command_for(name)}
    readonly_required = ('mount','metadata_permissions','range_reads','warm_repeat','mmap_read','locks_observation','readonly_unchanged','root_confinement',
                         *('readonly_' + operation for operation in ('write','truncate','chmod','unlink','rename','create','mkdir','rmdir','chown','utime','symlink','hardlink','xattr','mknod')))
    private_required = ('mount','private_writes','rename_classification','create_classification','truncate_classification','chmod_classification',
                        'mmap_read','mmap_private_visibility','private_extension','locks_observation')
    def scenario_passed(name):
        data = cases.get(name, {})
        required = private_required if name == 'private' else readonly_required
        return all(data.get(case,{}).get('state') == 'passed' for case in required)
    permission_expected = {'group-permissions':('group_read','group_write_denied','parent_search_denied'),
                           'other-permissions':('other_read_denied',), 'execute-other':('other_execute_0755',),
                           'execute-denied':('group_execute_0640_denied',), 'nonroot-mode000':('nonroot_mode000_read_denied',)}
    permission_passed = all(cases.get(name,{}).get(flag) is True for name,flags in permission_expected.items() for flag in flags)
    permission_passed = permission_passed and cases.get('execute-other',{}).get('output') == 'synthetic\n'
    ro = cases.get('root-readonly', {})
    private = cases.get('private', {})
    cleanup = native.get('cleanup', [])
    daemon = native.get('daemon', {})
    daemon_cleanup = next((item for item in cleanup if 'unmounts' in item and 'reaped' in item), {})
    unmounts, reaped = daemon_cleanup.get('unmounts', []), daemon_cleanup.get('reaped', [])
    mounted_paths = {item.get('mountpoint') for item in daemon.get('mounts',{}).values()}
    clean = (bool(mounted_paths) and {item.get('path') for item in unmounts} == mounted_paths
             and all(item.get('returncode') == 0 and item.get('still_mounted') is False for item in unmounts)
             and bool(daemon.get('pids')) and {item.get('pid') for item in reaped} == set(daemon['pids'])
             and all(item.get('returncode') is not None for item in reaped)
             and any(item.get('owned_vm_path') == native.get('owned_vm_path') and item.get('removed') is True for item in cleanup)
             and not any(item.get('error') for item in cleanup) and owned_containers_absent(native))
    transfer = native.get('transfer', {})
    profile_cases = {
        'mount': observation('root-readonly','ordinary syscalls require a real FUSE mount',ro.get('mount'),ro.get('mount',{}).get('state') == 'passed'),
        'range_reads': observation('root-readonly','independent exact header, cross-boundary, tail, EOF',ro.get('range_reads'),ro.get('range_reads',{}).get('state') == 'passed'),
        'private_writes': observation('private','existing private bytes visible to peer and reopen; fsync unsupported',private,scenario_passed('private')),
        'readonly_view': observation('root-readonly','all 14 root mutations denied; source/namespace preserved; root mode000 contrast',{'readonly':ro,'mode000':cases.get('root-mode000-readonly')},scenario_passed('root-readonly') and scenario_passed('root-mode000-readonly')),
        'permissions': observation('group-permissions','mapped entry uid/gid/modes, group read/write/traverse, other denial and execute contrasts', {name:cases.get(name) for name in ('group-permissions','other-permissions','execute-other','execute-denied','nonroot-mode000')},permission_passed),
        'cleanup': {'state':'passed' if clean else 'failed', 'expected':'owned mounts absent, processes reaped, exact VM directory/container names removed', 'observed':cleanup, 'command':[item['command'] for item in commands if 'cleanup' in item.get('stdout','') or 'remove' in item.get('stdout','')]},
        'enumeration': observation('enumeration','exact fixture names; zero source body bytes',{'names':cases.get('enumeration'),'counter':transfer.get('enumeration')},cases.get('enumeration') == ['data.bin','empty','instructions.md','nested','run.sh'] and transfer.get('enumeration',{}).get('content_body_bytes') == 0),
        'partial_cold': observation('partial-cold','two exact4KiB head/tail reads; <=8MiB source bodies',transfer.get('cold'),cases.get('partial-cold',{}).get('exact_head_tail',False)),
        'partial_warm': observation('partial-warm','same reads; zero extra source body bytes',transfer.get('warm'),cases.get('partial-warm',{}).get('exact_head_tail',False)),
        'full_scan': observation('full-scan','64MiB actual mounted scan equals independent SHA-256; actual transfer counted',transfer.get('full_scan'),bool(cases.get('full-scan'))),
        'subprocess': observation('execute-other','ordinary Python and executable processes against mounted view',cases.get('execute-other'),cases.get('execute-other',{}).get('other_execute_0755',False)),
    }
    return {'journey':journey,'chunk_size':chunk,'manifest_digest':native.get('manifest_digest'),
            'additional_fixture_digests':native.get('generation_digests'),'fixture_uid_gid':native.get('fixture_uid_gid'),'fixture_identity':native.get('daemon',{}).get('fixture_identity'),
            'root_metadata':native.get('root_metadata'),'owned_token':native.get('token'),
            'actors':{'readonly':'uid0:gid0, DAC_OVERRIDE only', 'private':str(native.get('fixture_uid_gid')) + ', no capabilities', 'permission_negatives':'disposable numeric1001 principals'},
            'counter_scope':'Original Rust source response payloads, including repeated chunk requests; excludes projection proxy manifest/control/network framing bytes',
            'projected_manifest_response_bytes':len(json.dumps(native.get('daemon',{}).get('sources',{}).get('normal',{}).get('manifest',{}),separators=(',',':')).encode()),
            'environment':native.get('daemon',{}).get('environment'),
            'mount_options':native.get('daemon',{}).get('mounts'),
            'actual_owned_mountinfo':[line for line in native.get('daemon',{}).get('mountinfo','').splitlines() if line.split()[4].startswith('/shared/')],
            'owned_resources':{'containers':native.get('owned_containers'), 'pids':native.get('daemon',{}).get('pids'), 'vm_path':native.get('owned_vm_path')},
            'source_revision':native.get('revision'),'dirty':native.get('dirty'),'image':native.get('image'),
            'cases':profile_cases,'transfer':transfer,'cleanup_errors':[item for item in cleanup if item.get('error')],
            'remaining_owned_resources':native.get('remaining_owned_containers','').splitlines(),
            'native_evidence':str(evidence),'error':native.get('error')}


def run_linux_profile(runner, output, image, journey, chunk, uid, gid):
    evidence = output / 'result.json'
    profile = {'journey':journey, 'chunk_size':chunk, 'native_evidence':str(evidence),
               'cases':{}, 'cleanup_errors':[], 'remaining_owned_resources':[]}
    code, runner_error, native = None, None, None
    try:
        code = runner(output,image,False,chunk,uid,gid)
    except Exception as error:
        runner_error = {'type':type(error).__name__, 'message':str(error), 'detail':repr(error)}
        if hasattr(error, 'cmd'):
            runner_error['command'] = error.cmd
        if hasattr(error, 'timeout'):
            runner_error['timeout'] = error.timeout
        profile['orchestration_error'] = runner_error
    profile['native_returncode'] = code
    profile['profile_started'] = output.is_dir()
    try:
        native = json.loads(evidence.read_text())
        if not isinstance(native, dict):
            raise ValueError('native report must be a JSON object')
        profile.update(summarize_linux(native,journey,chunk,evidence))
    except Exception as error:
        profile['native_report_error'] = repr(error)
    if runner_error or 'native_report_error' in profile:
        if native is not None:
            profile['native_report_snapshot'] = native
    if runner_error and (native is not None or profile['profile_started']):
        profile['cleanup_errors'].append({'phase':'native_runner_exception', **runner_error})
        cleanup = profile['cases'].setdefault('cleanup', {'expected':'verified owned-resource cleanup', 'command':[]})
        cleanup.update(state='failed', observed={'native_cleanup':cleanup.get('observed'), 'exception':runner_error})
        retained = [item['owned_container_retained'] for item in native.get('cleanup', [])
                    if isinstance(item,dict) and item.get('owned_container_retained')] if isinstance(native,dict) else []
        profile['remaining_owned_resources'] = list(dict.fromkeys([*profile['remaining_owned_resources'], *retained]))
        resources = profile.setdefault('owned_resources', {})
        resources['containers'] = list(dict.fromkeys([*(resources.get('containers') or []), *retained]))
        profile['cleanup_unconfirmed_resources'] = dict(resources)
        state, reason = 'failed', runner_error['detail']
    elif 'native_report_error' in profile:
        state, reason = 'blocked', profile['native_report_error']
    elif code or any(case.get('state') == 'failed' for case in profile['cases'].values()):
        state, reason = 'failed', profile.get('error') or 'native case/cleanup failure'
    elif any(case.get('state') != 'passed' for case in profile['cases'].values()):
        state, reason = 'blocked', 'missing native case/proof'
    else:
        state, reason = 'passed', None
    profile['state'] = state
    return profile, state, reason


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--platform',choices=('all','linux','macos'),default='all')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image',default='fs0-task4-runtime')
    parser.add_argument('--fixture-uid',type=int,default=501)
    parser.add_argument('--fixture-gid',type=int,default=20)
    args = parser.parse_args(argv)
    try:
        owned = OwnedOutput(args.output)
    except (ValueError,OSError) as error:
        print(error,file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[2]
    result = {'schema':'magus-fs-fs0-result-v1','command':[sys.executable,*sys.argv], 'owned_output':str(owned.path),
              'owned_token':owned.token,'platforms':{},'inventory':collect(), 'scope':'synthetic pinned FS0; no production release',
              'limitations':['private FUSE bytes ephemeral; fsync/fdatasync unsupported', 'private namespace operations classified unsupported',
                             'root uid/gid is daemon mapped and outside manifest identity', 'no authenticated source, live generation publication or distributed locks',
                             'real editor/external harness journey required before FS2 closure']}
    for name, command in [('source_revision',['git','rev-parse','HEAD']),('dirty',['git','status','--short'])]:
        done = subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=10)
        result[name] = {'command':command,'returncode':done.returncode,'observed':done.stdout.strip(),'stderr':done.stderr}
    path = owned.path / 'result.json'
    def save():
        path.write_text(json.dumps(result,indent=2)+'\n')
    save()
    if args.preflight:
        result['preflight'] = check()
    else:
        if args.platform in ('all','linux'):
            platform = result['platforms']['linux'] = {'state':'blocked','profiles':[]}
            try:
                done = subprocess.run(['docker','image','inspect',args.image],capture_output=True,text=True,timeout=15)
                if done.returncode:
                    raise RuntimeError('required local image unavailable: '+done.stderr.strip())
                from linux_run import run
            except Exception as error:
                platform.update(state='blocked',reason=repr(error))
            else:
                stopped = False
                for journey in (1,2):
                    for chunk in CHUNKS:
                        output = owned.path / f'linux-{journey}-{chunk}'
                        print(f'Linux fresh journey{journey}, chunk_size{chunk}',flush=True)
                        profile, state, reason = run_linux_profile(run,output,args.image,journey,chunk,args.fixture_uid,args.fixture_gid)
                        platform['profiles'].append(profile)
                        if state != 'passed':
                            platform.update(state=state,reason=reason)
                            stopped = True
                        save()
                        if stopped:
                            break
                    if stopped:
                        break
                if not stopped:
                    platform['state'] = 'passed'
        if args.platform in ('all','macos'):
            result['platforms']['macos'] = {'state':'blocked','reason':MACOS_BLOCKER,'profiles':[],
                'action':'controller-reviewed bounded native diagnostic and complete profiles required; no Mac runner invoked'}
    required = ('linux','macos') if args.platform == 'all' else (args.platform,)
    result.update(aggregate(result['platforms'],required))
    result['cleanup_errors'] = owned.cleanup(remove_output=False)
    if result['cleanup_errors']:
        result.update(state='failed',passed=False,exit_code=1)
    save()
    print(path,flush=True)
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
