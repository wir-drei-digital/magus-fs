"""Bounded Linux FUSE qualification in owned Docker resources; no host mount install."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid

IMAGE = 'fs0-task3-runtime-final'


def run(output, image=IMAGE):
    output = Path(output).absolute()
    output.mkdir(exist_ok=False)
    token = 'fs0-task3-' + uuid.uuid4().hex[:12]
    daemon = token + '-daemon'
    vm_path = '/tmp/' + token
    report = {'platform': 'linux', 'token': token, 'owned_vm_path': vm_path, 'owned_containers': [], 'commands': [], 'cases': {}, 'cleanup': [], 'passed': False}
    path = output / 'result.json'
    def save():
        path.write_text(json.dumps(report, indent=2) + '\n')
    def cmd(args, name, timeout=45, data=None, check=True):
        command = subprocess.run(args, input=data, capture_output=True, text=True, timeout=timeout)
        (output / (name + '.stdout')).write_text(command.stdout)
        (output / (name + '.stderr')).write_text(command.stderr)
        record = {'command': args, 'returncode': command.returncode, 'stdout': name + '.stdout', 'stderr': name + '.stderr'}
        report['commands'].append(record)
        save()
        if check and command.returncode:
            raise RuntimeError(name + ' failed: ' + command.stderr[-1000:] + command.stdout[-1000:])
        return command
    def workload(name, view, script, data, user='0:0', readonly=False):
        container = token + '-' + name
        report['owned_containers'].append(container)
        args = ['docker','run','--rm','-i','--name',container,'--read-only','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--user',user,'--tmpfs','/tmp:rw,nosuid,nodev,size=4m',
                '-v',vm_path + '/' + view + ':/view:' + ('ro,' if readonly else '') + 'rslave']
        if user == '0:0':
            args += ['--cap-add','DAC_OVERRIDE']
        args += [image,'python3','-c',script]
        result = cmd(args, name, data=json.dumps(data))
        parsed = json.loads(result.stdout)
        report['cases'][name] = parsed
        save()
        return parsed
    started = False
    try:
        report['revision'] = cmd(['git','rev-parse','HEAD'],'revision').stdout.strip()
        report['dirty'] = cmd(['git','status','--short'],'dirty').stdout
        report['image'] = json.loads(cmd(['docker','image','inspect',image],'image').stdout)[0]['Id']
        report['owned_containers'].append(daemon)
        started = True
        cmd(['docker','run','-d','--name',daemon,'--read-only','--cap-drop','ALL','--cap-add','SYS_ADMIN','--security-opt','no-new-privileges',
             '--device','/dev/fuse','--tmpfs','/private:rw,nosuid,nodev,size=256m','--tmpfs','/tmp:rw,nosuid,nodev,size=4m','-v',vm_path + ':/shared:rshared',image,'python3','/opt/fs0/linux_daemon.py'],'daemon-start')
        deadline = time.monotonic() + 35
        while True:
            logs = cmd(['docker','logs',daemon],'daemon-log',check=False).stdout
            if logs.strip():
                readiness = json.loads(logs.splitlines()[0])
                if not readiness.get('ready'):
                    raise RuntimeError(str(readiness))
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('daemon ready deadline')
            time.sleep(0.2)
        control = json.loads(cmd(['docker','exec',daemon,'cat','/private/control.json'],'control').stdout)
        report['daemon'] = control
        report['daemon_inspect'] = json.loads(cmd(['docker','inspect',daemon],'daemon-inspect').stdout)[0]
        source = control['sources']['normal']['url']
        manifest = control['sources']['normal']['manifest']
        def source_stats():
            return json.loads(cmd(['docker','exec',daemon,'python3','-c',"import json,urllib.request; print(urllib.request.urlopen('" + source + "/stats').read().decode())"], 'stats-' + str(len(report['commands']))).stdout)
        # Do transfer measurements before any ordinary scenario hydrates bytes.
        before = source_stats()
        listing = workload('enumeration','normal-ro',"import json,os; print(json.dumps(sorted(os.listdir('/view'))))",{},readonly=True)
        enumerated = source_stats()
        assert before['content_body_bytes'] == enumerated['content_body_bytes'] == 0
        script = "import json,os; from ordinary_io import expected; f=os.open('/view/data.bin',os.O_RDONLY); offsets=[0,67108864-4096]; [(_ for _ in ()).throw(AssertionError('range mismatch')) for off in offsets if os.pread(f,4096,off)!=expected(off,4096)]; os.close(f); print(json.dumps({'exact_head_tail':True}))"
        workload('partial-cold','normal-ro',script,{},readonly=True)
        cold = source_stats()
        assert 0 < cold['content_body_bytes'] <= 8388608, cold
        workload('partial-warm','normal-ro',script,{},readonly=True)
        warm = source_stats()
        assert warm['content_body_bytes'] == cold['content_body_bytes'], (cold,warm)
        report['transfer'] = {'before':before,'enumeration':enumerated,'cold':cold,'warm':warm}
        script = "import json,sys; from linux_io import run; from root_confinement import run as confined; d=json.load(sys.stdin); r=run('/view',d['mode'],d['manifest']); r['root_confinement']={'state':'passed','detail':confined(d['source'])}; print(json.dumps(r)); raise SystemExit(0 if all(x['state']=='passed' for x in r.values()) else 2)"
        workload('root-readonly','normal-ro',script,{'mode':'ro','manifest':manifest,'source':source},readonly=True)
        locked = control['sources']['locked']
        workload('root-mode000-readonly','locked-ro',script,{'mode':'ro','manifest':locked['manifest'],'source':locked['url']},readonly=True)
        script = "import errno,json; from pathlib import Path;\ntry:\n Path('/view/instructions.md').read_bytes()\nexcept OSError as e:\n assert e.errno==errno.EACCES\nelse:\n raise AssertionError('nonroot mode000 read allowed')\nprint(json.dumps({'nonroot_mode000_read_denied':True}))"
        workload('nonroot-mode000','locked-ro',script,{},user='1001:1001',readonly=True)
        script = "import json,sys; from linux_io import run; d=json.load(sys.stdin); r=run('/view',d['mode'],d['manifest']); print(json.dumps(r)); raise SystemExit(0 if all(x['state']=='passed' for x in r.values()) else 2)"
        workload('private','normal-private',script,{'mode':'private','manifest':manifest})
        script = "import errno,json,os; from pathlib import Path; f=Path('/view/instructions.md'); assert f.read_bytes().startswith(b'# Synthetic');\ntry:\n f.open('r+b')\nexcept OSError as e:\n assert e.errno==errno.EACCES\nelse:\n raise AssertionError('group write allowed')\ntry:\n Path('/view/nested/table.csv').read_bytes()\nexcept OSError as e:\n assert e.errno==errno.EACCES\nelse:\n raise AssertionError('parent traversal allowed')\nprint(json.dumps({'group_read':True,'group_write_denied':True,'parent_search_denied':True}))"
        workload('group-permissions','permissions-private',script,{},user='1001:0')
        script = "import errno,json; from pathlib import Path;\ntry:\n Path('/view/instructions.md').read_bytes()\nexcept OSError as e:\n assert e.errno==errno.EACCES\nelse:\n raise AssertionError('other read allowed')\nprint(json.dumps({'other_read_denied':True}))"
        workload('other-permissions','permissions-private',script,{},user='1001:1001')
        script = "import json,subprocess; r=subprocess.run(['/view/run.sh'],capture_output=True,text=True,timeout=5); assert r.returncode==0 and r.stdout=='synthetic\\n', (r.returncode,r.stdout,r.stderr); print(json.dumps({'other_execute_0755':True,'output':r.stdout}))"
        workload('execute-other','normal-ro',script,{},user='1001:1001',readonly=True)
        script = "import errno,json,subprocess;\ntry:\n subprocess.run(['/view/run.sh'],capture_output=True,timeout=5)\nexcept OSError as e:\n assert e.errno==errno.EACCES\nelse:\n raise AssertionError('0640 execution allowed')\nprint(json.dumps({'group_execute_0640_denied':True}))"
        workload('execute-denied','permissions-private',script,{},user='1001:0')
        # Source files are snapshot inputs: touching them must not change a pinned mount.
        cmd(['docker','exec',daemon,'python3','-c',"from pathlib import Path; Path('/private/fixture-normal/instructions.md').write_bytes(b'incoming source-file edit')"], 'source-file-edit')
        workload('pinned-source-edit','normal-ro',"import json; from pathlib import Path; assert Path('/view/instructions.md').read_bytes()==b'# Synthetic workspace\\nUse relative paths.\\n'; print(json.dumps({'source_file_edit_is_not_generation_publication':True,'pinned_mount_unchanged':True}))",{},readonly=True)
        different = control['sources']['permissions']['manifest']['digest']
        assert different != manifest['digest']
        generation_container = token + '-generation'
        report['owned_containers'].append(generation_container)
        generation = cmd(['docker','run','--rm','--name',generation_container,'--network','none','--read-only','--cap-drop','ALL','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges','-v',vm_path + '/normal-ro:/old:ro,rslave','-v',vm_path + '/permissions-private:/fresh:ro,rslave',image,'python3','-c',"import json,os,stat; f=os.open('/old/instructions.md',os.O_RDONLY); before=os.pread(f,200,0); fresh=open('/fresh/instructions.md','rb').read(); assert before==fresh; assert stat.S_IMODE(os.stat('/old/instructions.md').st_mode)==0o644; assert stat.S_IMODE(os.stat('/fresh/instructions.md').st_mode)==0o640; assert os.pread(f,200,0)==before; os.close(f); print(json.dumps({'old_open_handle_and_mount_remain_pinned':True,'fresh_manifest_mode_visible_in_new_mount':True,'in_place_invalidation':'unsupported: no generation publication API'}))"],'generation-pinning')
        report['cases']['generation-pinning'] = json.loads(generation.stdout)
        report['generation_digests'] = {'old':manifest['digest'],'fresh':different}
        report['qualification'] = 'pinned FS0 byte views; namespace mutation/live generation publication unsupported'
        report['passed'] = True
    except Exception as error:
        report['error'] = repr(error)
    finally:
        for container in report['owned_containers']:
            if container == daemon:
                continue
            alive = cmd(['docker','ps','-a','--filter','name=^/' + container + '$','--format','{{.Names}}'],'workload-cleanup-check-' + container,check=False).stdout.strip()
            if alive == container:
                cmd(['docker','rm','-f',container],'workload-cleanup-' + container,check=False)
        if started:
            try:
                # Stop PID 1 only; it unmounts before stopping serving processes.
                running = cmd(['docker','inspect','--format','{{.State.Running}}',daemon],'daemon-running').stdout.strip()
                if running == 'true':
                    cmd(['docker','kill','--signal','TERM',daemon],'daemon-term')
                state = cmd(['docker','wait',daemon],'daemon-wait',timeout=15)
                logs = cmd(['docker','logs',daemon],'daemon-final-log').stdout
                cleanup = json.loads(logs.splitlines()[-1])
                (output / 'daemon-cleanup.json').write_text(json.dumps(cleanup, indent=2))
                assert all(x.get('returncode') == 0 and not x.get('still_mounted') for x in cleanup['cleanup']), cleanup['cleanup']
                assert all(x['returncode'] is not None for x in cleanup['reaped'])
                report['cleanup'].append({'daemon':daemon,'unmounts':cleanup['cleanup'],'reaped':cleanup['reaped']})
                cmd(['docker','rm',daemon],'daemon-remove')
                # Only the owned VM directory is exposed to this cleanup helper.
                cmd(['docker','run','--rm','--name',token + '-cleanup','--network','none','--cap-drop','ALL','--read-only','-v','/tmp:/vm-tmp',image,'python3','-c',"from pathlib import Path; p=Path('/vm-tmp') / " + repr(token) + "; mountpoints=[line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()]; assert not any(m.startswith(str(p)+'/') for m in mountpoints),mountpoints; [(x.rmdir() if x.is_dir() and not x.is_symlink() else (_ for _ in ()).throw(AssertionError(str(x)))) for x in p.iterdir()]; p.rmdir(); assert not p.exists()"],'owned-vm-directory-remove')
                report['cleanup'].append({'owned_vm_path':vm_path,'removed':True})
            except Exception as error:
                report['cleanup'].append({'error':repr(error),'owned_container_retained':daemon})
                report['passed'] = False
        # Workload --rm must have removed every named workload container.
        remaining = cmd(['docker','ps','-a','--filter','name=' + token,'--format','{{.Names}}'],'owned-container-check',check=False).stdout.strip()
        report['remaining_owned_containers'] = remaining
        if remaining:
            report['passed'] = False
        save()
    print(path)
    return 0 if report['passed'] else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--image',default=IMAGE)
    args = parser.parse_args()
    raise SystemExit(run(args.output,args.image))
