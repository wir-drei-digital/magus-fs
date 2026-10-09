"""Read-only inventory. Version commands never start an editor session or model call."""
import platform
from pathlib import Path
import plistlib
import shutil
import subprocess


def command(args):
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return {'command':args, 'returncode':done.returncode, 'stdout':done.stdout.strip(), 'stderr':done.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'command':args, 'state':'blocked', 'error':repr(error)}


def collect():
    result = {'os':platform.platform(), 'python':platform.python_version(), 'editors':[], 'harnesses':[], 'dependencies':[]}
    app = Path('/Applications/Visual Studio Code.app/Contents/Info.plist')
    if app.is_file():
        with app.open('rb') as handle:
            info = plistlib.load(handle)
        result['editors'].append({'name':'Visual Studio Code','path':str(app), 'version':info.get('CFBundleShortVersionString'), 'build':info.get('CFBundleVersion'), 'selected_for_FS2':True, 'journey':'not-run'})
    else:
        for name in ('nvim','vim'):
            executable = shutil.which(name)
            if executable:
                result['editors'].append({'name':name,'path':executable, 'version_evidence':command([executable,'--version']), 'selected_for_FS2':True, 'journey':'not-run'})
                break
    for name in ('codex','claude'):
        executable = shutil.which(name)
        if executable:
            result['harnesses'].append({'name':name,'path':executable, 'version_evidence':command([executable,'--version']), 'selected_for_FS2':not result['harnesses'], 'journey':'not-run; no model call'})
    for name, args in [('rustc',['rustc','+stable','--version','--verbose']), ('cargo',['cargo','+stable','--version']),('docker',['docker','version','--format','{{json .}}'])]:
        result['dependencies'].append(command(args) if shutil.which(name) else {'name':name,'state':'blocked','reason':'not installed/on PATH'})
    if not result['editors']:
        result['editors'].append({'state':'blocked','reason':'no candidate real editor found'})
    if not result['harnesses']:
        result['harnesses'].append({'state':'blocked','reason':'no external harness on PATH'})
    return result
