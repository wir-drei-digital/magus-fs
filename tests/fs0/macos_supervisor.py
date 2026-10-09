"""Bounded parent reporting; retained native children keep serving unresolved mounts."""
from contextlib import nullcontext
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

PROFILE_SECONDS=600
REPORT_GRACE_SECONDS=5
POLL_SECONDS=.1
# Keep live Popen ownership until guarded native cleanup finishes; never auto-kill.
_retained={}


class Interrupts:
    """Record scalar signal state through child registration and aggregate publication."""
    def __init__(self):
        self.count=0
        self.previous={}
    def __enter__(self):
        def record(signum,frame):
            self.count+=1
        for signum in (signal.SIGINT,signal.SIGTERM):
            self.previous[signum]=signal.signal(signum,record)
        return self
    def __exit__(self,*args):
        for signum,handler in self.previous.items():
            signal.signal(signum,handler)


class SupervisionFailure(RuntimeError):
    def __init__(self,record):
        super().__init__(record['reason'])
        self.supervision=record


def supervise(command,output,*,seconds=PROFILE_SECONDS,report_grace=REPORT_GRACE_SECONDS,interrupts=None):
    output=Path(output)
    evidence=output.with_name(output.name+'.supervision.json')
    stdout=output.with_name(output.name+'.runner.stdout')
    stderr=output.with_name(output.name+'.runner.stderr')
    snapshot={}
    def read_native():
        nonlocal snapshot
        try:
            data=json.loads((output/'result.json').read_text())
            if isinstance(data,dict):snapshot=data
        except (OSError,ValueError):
            pass # Native save may be in progress; preserve the last complete snapshot.
    record={'command':command,'native_evidence':str(output/'result.json'),'evidence':str(evidence),
            'stdout':str(stdout),'stderr':str(stderr),'profile_deadline_seconds':seconds,
            'report_grace_seconds':report_grace,'poll_seconds':POLL_SECONDS}
    def save():
        temporary=evidence.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(record,indent=2)+'\n')
        temporary.replace(evidence)
    with (Interrupts() if interrupts is None else nullcontext(interrupts)) as signals:
        with stdout.open('w') as out,stderr.open('w') as err:
            # The scalar-only parent handlers prevent a Popen/registration interrupt
            # window. A new session protects the child gateway from terminal signals.
            process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
        _retained[process.pid]=process
        record.update(runner_pid=process.pid,runner_alive=True,state='running')
        save()
        end=time.monotonic()+seconds
        reason=None
        while True:
            read_native()
            code=process.poll()
            if signals.count:
                reason='parent interrupted'
                break
            if code is not None:
                process.wait()
                _retained.pop(process.pid,None)
                record.update(state='finished',returncode=code,runner_alive=False,native_snapshot=snapshot)
                save()
                return code
            if snapshot.get('state')=='cleanup_pending':
                reason='native cleanup pending'
                break
            if time.monotonic()>=end:
                reason='profile deadline exceeded'
                break
            time.sleep(POLL_SECONDS)
        if reason!='native cleanup pending' and process.poll() is None:
            # Request native guarded finalization, never signal its serving children
            # or process group. Its cleanup-pending handler retains the gateway.
            try:
                process.send_signal(signal.SIGINT)
                record['cleanup_request_signal']='SIGINT to runner only'
            except ProcessLookupError:
                pass
            grace_end=time.monotonic()+report_grace
            while time.monotonic()<grace_end:
                read_native()
                if process.poll() is not None or snapshot.get('state')=='cleanup_pending':break
                time.sleep(min(POLL_SECONDS,max(0,grace_end-time.monotonic())))
        read_native()
        if process.poll() is not None:
            process.wait()
            _retained.pop(process.pid,None)
        mountpoints=sorted({item['mountpoint'] for item in snapshot.get('mounts',{}).values()
                            if isinstance(item,dict) and isinstance(item.get('mountpoint'),str)}
                           |{path for path in snapshot.get('remaining_owned_resources',[]) if isinstance(path,str)})
        record.update(state='failed_pending',reason=reason,runner_alive=process.poll() is None,
                      returncode=process.poll(),parent_interrupts=signals.count,native_snapshot=snapshot,
                      owned_token=snapshot.get('owned_token'),owned_pids=snapshot.get('owned_pids',[]),
                      known_mountpoints=mountpoints,
                      remaining_owned_resources=snapshot.get('remaining_owned_resources',[]),
                      remaining_owned_command_pids=snapshot.get('remaining_owned_command_pids',[]),
                      recovery_action={'inspect_mount_table':['/sbin/mount','-t','nfs'],
                          'native_report':str(output/'result.json'),
                          'owned_unmount_commands_after_table_confirmation':[['/sbin/umount',point] for point in mountpoints],
                          'instruction':'Retain this runner and its serving children. Inspect exact owned paths/PIDs in the native report. Resolve each owned mount through separately authorized unmount; do not delete mounted paths. The retained native runner automatically completes guarded cleanup once all owned mounts and syscall helpers are confirmed absent. If it has exited, inspect recorded resources before any separately authorized recovery.'})
        save()
        raise SupervisionFailure(record)


def run(output,prepare_only=False,chunk_size=262144,uid=501,gid=20,*,interrupts=None):
    if prepare_only:
        raise ValueError('combined supervisor does not support prepare-only')
    command=[sys.executable,str(Path(__file__).with_name('macos_run.py')),'--output',str(output),
             '--chunk-size',str(chunk_size),'--uid',str(uid),'--gid',str(gid)]
    return supervise(command,output,interrupts=interrupts)
