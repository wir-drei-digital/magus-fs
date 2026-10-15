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


def deletion_permitted(measurements):
    """Receipt certainty and independent recovery are mandatory deletion guards."""
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
    require(deletion_permitted(m) and isinstance(deletion.get('sequence'),int)
            and m.get('unmount',{}).get('sequence',float('inf'))<deletion['sequence']
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
        result=preflight(config,args.package_manifest)
        if not args.preflight:
            result['blocked'].append('hosted run unavailable until normal provider mount teardown and private transport are qualified')
            result['preflight']=False
    except (OSError,ValueError):
        result={'schema':1,'phase':'provider','status':'blocked','executed':False,'failures':[],
                'blocked':['private provider configuration unavailable or invalid'],
                'cleanup':{'ok':True,'mounts_absent':True,'resources_removed':True,'provenance':'no resources created'}}
    (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return {'passed':0,'failed':1,'blocked':2}[result['status']]


if __name__=='__main__':
    import sys
    sys.exit(main())
