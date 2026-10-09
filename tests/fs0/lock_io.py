"""Structured ordinary subprocess lock contention; unrelated failures are failures."""
import errno
import json
import subprocess
import sys

CHILD = """import errno,fcntl,json,sys
try:
    handle = open(sys.argv[1], 'rb')
except OSError as error:
    print(json.dumps({'state':'failed','operation':'open','errno':error.errno,'error':str(error)}))
    sys.exit(1)
try:
    with handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as error:
    if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
        print(json.dumps({'state':'contended','operation':'flock','errno':error.errno}))
        sys.exit(75)
    print(json.dumps({'state':'failed','operation':'flock','errno':error.errno,'error':str(error)}))
    sys.exit(1)
print(json.dumps({'state':'acquired','operation':'flock'}))
sys.exit(0)
"""


def contend(path):
    args = [sys.executable, '-c', CHILD, str(path)]
    child = subprocess.run(args, capture_output=True, text=True, timeout=5)
    try:
        result = json.loads(child.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f'lock child produced invalid evidence: {child.returncode}, {child.stdout}, {child.stderr}') from error
    validate_observation(child.returncode,result,child.stderr)
    return dict(result, contender_returncode=child.returncode, command=args,
                scope='one kernel/client; no distributed lock guarantee')


def validate_observation(code, result, stderr):
    assert (code == 75 and result.get('state') == 'contended' and result.get('operation') == 'flock'
            and result.get('errno') in (errno.EAGAIN, errno.EWOULDBLOCK)
            and not stderr), (code, result, stderr)
