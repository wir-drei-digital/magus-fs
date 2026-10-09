"""Owned macOS NFS qualification. Never treats mount registration as a pass."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import shlex
import subprocess
import time
import urllib.request

from resources import OwnedOutput

BINARY = Path(__file__).resolve().parents[2] / "target/debug/magus-fs-probe"


def ready(process, seconds=30):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    event = selector.select(seconds)
    selector.close()
    if not event:
        raise RuntimeError("server readiness timeout")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("server exited before readiness; inspect stderr file")
    return line.strip()


def mount_state(path):
    """Read the OS mount table without issuing stat into a possibly stalled mount."""
    try:
        result = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=3)
        if result.returncode != 0:
            return None
        return any(" on " + str(path) + " (" in line for line in result.stdout.splitlines())
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        return None


class MountGuard:
    def __init__(self, owned, query=mount_state):
        self.owned = owned
        self.query = query
        self.paths = []
        self.attempts = []
        self.cleanup_errors = []

    def candidate(self, path):
        if path not in self.paths:
            self.paths.append(path)

    def track(self, process):
        self.attempts.append(process)

    def safe(self):
        if any(process.poll() is None for process in self.attempts):
            return False
        try:
            return all(self.query(path) is False for path in self.paths)
        except (Exception, KeyboardInterrupt):
            return False

    def cleanup(self):
        if not self.safe():
            return False
        self.cleanup_errors = self.owned.cleanup(remove_output=False)
        return True


def settle(process):
    """Bounded stop/reap; an unresolved process remains in the guard registry."""
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        return True
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        return False


def command(args, output, timeout=20, *, owned=None, guard=None, mountpoint=None):
    if mountpoint is not None:
        if guard is None:
            raise ValueError("mount command requires a guard")
        # Track before launching: interruption may happen before mount_nfs returns.
        guard.candidate(mountpoint)
    process = None
    with output.open("w") as log:
        try:
            # Avoid the Popen -> registration SIGINT window. Unblocking below may
            # immediately interrupt; the outer handler still owns/reaps the child.
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
                if owned is not None:
                    owned.own_process(process)
                if guard is not None:
                    guard.track(process)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            code = process.wait(timeout=timeout)
            return {"command": args, "pid": process.pid, "returncode": code, "log": str(output)}
        except subprocess.TimeoutExpired:
            reaped = settle(process)
            return {"command": args, "timeout": True, "pid": process.pid, "kill_pending": not reaped, "log": str(output)}
        except BaseException:
            if process is not None:
                settle(process)
            raise


def effective_options(text, path, readonly):
    """Require the owned mount's current flags, never another/original option block."""
    match = re.search(r'^' + re.escape(str(path)) + r' from .*?(?=^/|\Z)', text, re.M | re.S)
    assert match, 'owned mount missing from nfsstat'
    current = match.group().split('-- Current mount parameters:')[-1]
    assert '-- Current mount parameters:' in match.group()
    flags = re.search(r'General mount flags: ([^\n]+)', current)
    params = re.search(r'NFS parameters: ([^\n]+)', current)
    assert flags and params
    values = set(params[1].split(','))
    assert ('ro' in re.split(r'[, ]+', flags[1])) == readonly, flags[1]
    assert 'locallocks' in values and 'nolocks' not in values, values
    assert {key + '=1' for key in ('acregmin','acregmax','acdirmin','acdirmax','acrootdirmin','acrootdirmax')} <= values, values
    return params[1]


def run(output, prepare_only=False, chunk_size=262144, uid=501, gid=20):
    import hashlib
    import http.server
    import shutil
    import sys
    import threading
    from permission_source import project_manifest
    from measurement_io import independent_digest
    from qualification import validate_content_profile

    if platform.system() != 'Darwin':
        raise RuntimeError('macOS runner requires Darwin')
    assert chunk_size in (65536,262144,1048576)
    owned = OwnedOutput(output)
    guard = MountGuard(owned)
    report = {'platform':'macos','passed':False,'owned_output':str(owned.path),'owned_token':owned.token,
              'chunk_size':chunk_size,'fixture_uid_gid':[uid,gid],'commands':[],'cases':{},'mounts':{},'cleanup':[],
              'cleanup_errors':[],'environment':{'platform':platform.platform(),'python':sys.version,'actor_uid_gid':[os.geteuid(),os.getegid()]}}
    report_path = owned.path/'result.json'
    processes = []
    endpoints = []
    gateway = None
    manifest_path = owned.path/'manifest.json'
    def save():
        report['owned_pids'] = [p.pid for p in processes]
        report_path.write_text(json.dumps(report,indent=2)+'\n')
    def start(args,name):
        with (owned.path/(name+'.stderr')).open('w') as log:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT})
            try:
                process = owned.own_process(subprocess.Popen(args,stdout=subprocess.PIPE,stderr=log,text=True,
                    env={**os.environ,'RUST_LOG':'nfsserve=debug'}))
                processes.append(process)
                save()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        return process
    def cmd(args,name,seconds=15,mountpoint=None,check=True):
        result = command(args,owned.path/(name+'.stdout'),seconds,owned=owned,guard=guard,mountpoint=mountpoint)
        result['name']=name
        report['commands'].append(result)
        save()
        if check and result.get('returncode') != 0:
            raise RuntimeError(name+' failed: '+repr(result))
        return result
    def get(url,route):
        with urllib.request.urlopen(url+route,timeout=5) as response:
            return json.load(response)
    def workload(name,case,point,extra=None,seconds=35):
        args=[sys.executable,str(Path(__file__).with_name('macos_io.py')),'--case',case,'--mountpoint',str(point),
              '--manifest',str(manifest_path),'--extra',json.dumps(extra or {})]
        done=cmd(args,name,seconds,check=False)
        try:
            value=json.loads(Path(done['log']).read_text().splitlines()[-1])
        except Exception as error:
            value={'state':'failed','error':repr(error),'child':done}
        value['command']=args
        report['cases'][name]=value
        save()
        if done.get('returncode') != 0 or value.get('state') != 'passed':
            raise RuntimeError(name+' failed: '+repr(value))
        return value['observed']
    def mount(name,mode='ro',resume=False):
        point=owned.path/('mount-'+name)
        guard.candidate(point)
        args=[str(binary),'mount','--backend','nfs','--source',proxy_url,'--mode',mode,
              '--mountpoint',str(point),'--expect-digest',current['manifest']['digest'],'--prepare-only']
        if mode=='private':
            args += ['--backing',str(owned.path/'backing')]
            if resume: args += ['--resume-backing']
        process=start(args,name)
        item={'process':process,'path':point,'name':name}
        endpoints.append(item)
        info=json.loads(ready(process))
        info['server_command']=args
        info['manifest']=current['manifest']
        report['mounts'][name]=info
        assert info['manifest_digest']==current['manifest']['digest']
        argv=info['mount_command'].copy()
        assert 'actimeo=0' in argv[2] and 'nolocks' in argv[2]
        argv[2]=argv[2].replace('actimeo=0','actimeo=1').replace('nolocks','locallocks')
        info['actual_mount_command']=argv
        save()
        if prepare_only:
            print('Ready; run: '+shlex.join(argv),flush=True)
            while mount_state(point) is not True: time.sleep(1)
        else:
            cmd(argv,name+'-mount',20,mountpoint=point)
        table=cmd(['/sbin/mount','-t','nfs'],name+'-mount-table')
        info['mount_table_entry']=next((line for line in Path(table['log']).read_text().splitlines() if ' on '+str(point)+' (' in line),'')
        assert info['mount_table_entry'], 'mount registration missing'
        options=cmd(['/usr/bin/nfsstat','-m'],name+'-effective-options')
        info['effective_options']=effective_options(Path(options['log']).read_text(),point,mode=='ro')
        save()
        return item
    def unmount(item):
        state=mount_state(item['path'])
        assert state is not None, 'unknown mount table state'
        result={'name':item['name'],'path':str(item['path']),'was_mounted':state}
        if state:
            done=cmd(['/sbin/umount',str(item['path'])],item['name']+'-unmount',5,check=False)
            result.update(command=done['command'],returncode=done.get('returncode'),timeout=done.get('timeout',False))
        else:
            result['returncode']=0
        result['still_mounted']=mount_state(item['path'])
        report['cleanup'].append(result)
        save()
        if result['still_mounted'] is not False:
            raise RuntimeError('owned mount cleanup unresolved: '+str(item['path']))
        # Endpoint may be stopped only once its own mount is confirmed absent.
        if item['process'].poll() is None:
            item['process'].terminate()
        item['process'].wait(timeout=5)
    try:
        revision=cmd(['git','-C',str(BINARY.parents[2]),'rev-parse','HEAD'],'revision')
        report['revision']=Path(revision['log']).read_text().strip()
        binary=owned.path/'magus-fs-probe'
        shutil.copy2(BINARY,binary)
        report['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        source=start([str(binary),'source','--root',str(owned.path/'fixture'),'--chunk-size',str(chunk_size)],'source')
        source_url=ready(source)
        original=get(source_url,'/manifest')
        canonical=project_manifest(original,uid=uid,gid=gid)
        assert canonical['chunk_size']==chunk_size
        report['manifest_digest']=canonical['digest']
        report['fixture_identity']={'original_digest':original['digest'],'projected_digest':canonical['digest'],
            'projection':{'uid':uid,'gid':gid},'scope':'test-only metadata projection; real Rust chunk bodies unchanged'}
        report['source_url']=source_url
        report['source_command']=[str(binary),'source','--root',str(owned.path/'fixture'),'--chunk-size',str(chunk_size)]
        manifest_path.write_text(json.dumps(canonical))
        current={'manifest':canonical,'offline':False}
        class Gateway(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                if self.path=='/manifest':
                    data=json.dumps(current['manifest'],separators=(',',':')).encode()
                elif self.path=='/stats' or self.path.startswith('/chunks/'):
                    if current['offline'] and self.path.startswith('/chunks/'):
                        self.send_error(503,'owned synthetic source outage')
                        return
                    with urllib.request.urlopen(source_url+self.path,timeout=5) as response:
                        data=response.read()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length',str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        gateway=http.server.ThreadingHTTPServer(('127.0.0.1',0),Gateway)
        gateway_thread=threading.Thread(target=gateway.serve_forever,daemon=True)
        gateway_thread.start()
        proxy_url='http://127.0.0.1:'+str(gateway.server_port)
        report['projection_gateway']=proxy_url
        ro=mount('normal-ro')
        stats=lambda:get(source_url,'/stats')
        before=stats()
        workload('enumeration','enumeration',ro['path'])
        enumerated=stats()
        assert before['content_body_bytes']==enumerated['content_body_bytes']==0
        workload('partial-cold','partial',ro['path'])
        cold=stats()
        workload('partial-warm','partial',ro['path'])
        warm=stats()
        scanned=workload('full-scan','full',ro['path'],{'digest':independent_digest()},60)
        full=stats()
        report['transfer']={'before':before,'enumeration':enumerated,'cold':cold,'warm':warm,'full':full,'full_scan':scanned,
                            'cold_delta':cold['content_body_bytes']-before['content_body_bytes'],
                            'warm_delta':warm['content_body_bytes']-cold['content_body_bytes'],
                            'full_scan_delta':full['content_body_bytes']-warm['content_body_bytes']}
        assert validate_content_profile(report['transfer']),report['transfer']
        workload('readonly','ro',ro['path'])
        workload('subprocess','subprocess',ro['path'])
        unmount(ro)
        private=mount('normal-private','private')
        report['private_hydrated_bytes']=report['mounts']['normal-private']['hydrated_bytes']
        workload('private','private',private['path'])
        workload('persist','persist',private['path'])
        assert (owned.path/'backing/tree/instructions.md').read_bytes().startswith(b'durable')
        unmount(private)
        resumed=mount('resumed-private','private',True)
        workload('resumed','resumed',resumed['path'])
        unmount(resumed)
        # Fixed actor contrasts. No user switching, supplementary-group or root claim.
        variants=[('group',None,0o040,12345,os.getegid()),('other',None,0o004,12345,12345),
                  ('file000',None,0,os.geteuid(),os.getegid()),('file644',None,0o644,os.geteuid(),os.getegid()),('directory000',0,None,os.geteuid(),os.getegid()),
                  ('directory400',0o400,None,os.geteuid(),os.getegid()),('directory100',0o100,None,os.geteuid(),os.getegid())]
        for name,directory_mode,file_mode,owner,group in variants:
            current['manifest']=project_manifest(canonical,directory_mode,file_mode,owner,group)
            item=mount(name)
            workload(name,'permissions',item['path'],{'kind':name})
            unmount(item)
        current['manifest']=canonical
        old=mount('generation-old')
        signal_path=owned.path/'generation-signal'
        args=[sys.executable,str(Path(__file__).with_name('macos_io.py')),'--case','generation','--mountpoint',str(old['path']),
              '--manifest',str(manifest_path),'--extra',json.dumps({'signal':str(signal_path)})]
        watch=start(args,'generation-watch')
        guard.track(watch)
        assert ready(watch)=='ready'
        current['manifest']=project_manifest(canonical,file_mode=0o640)
        newer=mount('generation-fresh')
        signal_path.write_text(str(newer['path']))
        output,_=watch.communicate(timeout=30)
        (owned.path/'generation.stdout').write_text(output)
        report['commands'].append({'name':'generation','command':args,'returncode':watch.returncode,'log':str(owned.path/'generation.stdout')})
        report['cases']['generation']=json.loads(output.splitlines()[-1])
        report['cases']['generation']['command']=args
        report['generation_digests']={'old':canonical['digest'],'fresh':current['manifest']['digest']}
        save()
        assert watch.returncode==0 and report['cases']['generation']['state']=='passed'
        unmount(newer)
        unmount(old)
        current['manifest']=canonical
        fault=mount('source-failure')
        # Warm only the tiny file; leave data.bin cold for an actual source error.
        workload('failure-warm','warm-file',fault['path'])
        current['offline']=True
        workload('source-failure','fault',fault['path'])
        current['offline']=False
        workload('source-recovery','partial',fault['path'])
        unmount(fault)
        report['passed']=True
        report['qualification']='controlled pinned FS0; eager private backing; replacement/live generation unsupported'
    except (Exception,KeyboardInterrupt) as error:
        report['error']=repr(error)
        report['passed']=False
    finally:
        # Reap interrupted syscall helpers before touching mounts; serving daemons remain live.
        for process in guard.attempts:
            if process.poll() is None: settle(process)
        for item in reversed(endpoints):
            if mount_state(item['path']) is not False:
                try: unmount(item)
                except Exception as error:
                    report['cleanup_errors'].append(repr(error))
        save()
        if not guard.safe():
            report['passed']=False
            report['remaining_owned_resources']=[str(path) for path in guard.paths if mount_state(path) is not False]
            report['cleanup_errors'].append('servers retained until owned mounts and command children are resolved')
            save()
            print('Cleanup pending. Owned report: '+str(report_path),flush=True)
            for point in report['remaining_owned_resources']:
                print(shlex.join(['sudo','/sbin/umount','-f',point]),flush=True)
            while not guard.safe():
                try: time.sleep(1)
                except KeyboardInterrupt: continue
        if gateway is not None:
            gateway.shutdown()
            gateway.server_close()
            gateway_thread.join(timeout=5)
        guard.cleanup()
        report['cleanup_errors'].extend(guard.cleanup_errors)
        report['reaped']=[{'pid':p.pid,'returncode':p.poll()} for p in processes]
        report['remaining_owned_resources']=[str(path) for path in guard.paths if mount_state(path) is not False]
        if report['cleanup_errors'] or report['remaining_owned_resources'] or any(p.poll() is None for p in processes):
            report['passed']=False
        report['state']='passed' if report['passed'] else 'failed'
        save()
    print(report_path,flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--chunk-size',type=int,choices=(65536,262144,1048576),default=262144)
    parser.add_argument('--uid',type=int,default=501)
    parser.add_argument('--gid',type=int,default=20)
    args=parser.parse_args()
    raise SystemExit(run(args.output,args.prepare_only,args.chunk_size,args.uid,args.gid))
