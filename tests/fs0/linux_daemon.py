"""Disposable daemon container controller. Only synthetic owned processes/mounts."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
import urllib.request

ROOT = Path('/private')
SHARED = Path('/shared')
processes = []
mounts = []


def ready(process, seconds=20):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    events = selector.select(seconds)
    selector.close()
    if not events:
        raise RuntimeError('readiness timeout')
    line = process.stdout.readline()
    if not line:
        raise RuntimeError('exited before readiness')
    return line.strip()


def start(args, name, mask=0o022):
    with (ROOT / (name + '.stderr')).open('w') as error:
        process = subprocess.Popen(['magus-fs-probe', *args], stdout=subprocess.PIPE, stderr=error, text=True, umask=mask)
    processes.append(process)
    return process


def mounted(path):
    return any(line.split()[4] == str(path) for line in Path('/proc/self/mountinfo').read_text().splitlines())


def get(url, endpoint):
    with urllib.request.urlopen(url + endpoint, timeout=5) as response:
        return json.load(response)


def main():
    ROOT.mkdir(exist_ok=True)
    report = {'sources': {}, 'mounts': {}, 'pids': [], 'cleanup': []}
    try:
        for label, mode, mask in [('normal', None, 0o022), ('permissions', '640', 0o077), ('locked', '000', 0o022)]:
            args = ['source','--root',str(ROOT / ('fixture-' + label))]
            if mode:
                args += ['--mode', mode]
            source = start(args, 'source-' + label, mask)
            url = ready(source)
            manifest = get(url, '/manifest')
            report['sources'][label] = {'url': url, 'pid': source.pid, 'manifest': manifest}
            (ROOT / (label + '-manifest.json')).write_text(json.dumps(manifest))
            for view in (['ro','private'] if label == 'normal' else ['ro'] if label == 'locked' else ['private']):
                name = label + '-' + view
                path = SHARED / name
                mounts.append(path)
                adapter = start(['mount','--backend','fuse','--source',url,'--mountpoint',str(path),'--mode',view,'--expect-digest',manifest['digest']], name)
                info = json.loads(ready(adapter))
                deadline = time.monotonic() + 10
                while not mounted(path):
                    if adapter.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('real mount failed: ' + name)
                    time.sleep(0.1)
                report['mounts'][name] = info
        report['pids'] = [p.pid for p in processes]
        report['mountinfo'] = Path('/proc/self/mountinfo').read_text()
        report['environment'] = {'uname': list(os.uname()), 'capabilities': [line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('Cap', 'NoNewPrivs','Seccomp'))], 'packages': subprocess.check_output(['dpkg-query','-W','fuse3','libfuse3-3','python3','util-linux'],text=True)}
        (ROOT / 'control.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({'ready': True, 'control': '/private/control.json'}), flush=True)
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('owned stop')))
        while True:
            signal.pause()
    except InterruptedError:
        pass
    except Exception as error:
        report['error'] = repr(error)
        errors = {p.name: p.read_text() for p in ROOT.glob('*.stderr')}
        print(json.dumps({'ready': False, 'error': repr(error), 'stderr': errors}), flush=True)
    finally:
        for path in reversed(mounts):
            try:
                was_mounted = mounted(path)
                if was_mounted:
                    done = subprocess.run(['umount', str(path)], capture_output=True, text=True, timeout=5)
                    report['cleanup'].append({'path': str(path), 'was_mounted': True, 'returncode': done.returncode, 'stderr': done.stderr, 'still_mounted': mounted(path)})
                else:
                    report['cleanup'].append({'path': str(path), 'was_mounted': False, 'returncode': 0, 'still_mounted': False})
            except Exception as error:
                report['cleanup'].append({'path': str(path), 'error': repr(error), 'still_mounted': mounted(path)})
        if any(mounted(path) for path in mounts):
            report['cleanup_pending'] = True
            (ROOT / 'cleanup.json').write_text(json.dumps(report, indent=2))
            # Retain serving daemons while an owned mount remains unresolved.
            while True:
                time.sleep(1)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        report['reaped'] = [{'pid': p.pid, 'returncode': p.returncode} for p in processes]
        (ROOT / 'cleanup.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({'cleanup': report['cleanup'], 'reaped': report['reaped']}), flush=True)


if __name__ == '__main__':
    main()
