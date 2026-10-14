"""One bounded Core-only affected-verification comparison; no mount qualification."""
import hashlib
import json
from pathlib import Path

DELTAS = ('same-id-content', 'atomic-replacement', 'standalone-creation')
BUDGET_SECONDS = 120
SOURCE = '/private/tmp/magus-collaboration-p2-20261014-a/sample-3-every-outcome.json'

def decision(rows, code, terminated=False):
    cells = [r for r in rows if r.get('kind') == 'cell']
    expected = {(delta, sender) for delta in range(3) for sender in (False, True)}
    if code != 0 or terminated or len(cells) != 6 or {(r.get('delta'), r.get('sender')) for r in cells} != expected or not any(r.get('kind') == 'end' for r in rows):
        return {'status': 'inconclusive', 'reason': 'incomplete comparison; retained without repeat'}
    if any(r.get('mode') != ('Full' if r['sender'] or r['delta'] == 2 else 'Affected') or not r.get('applied') for r in cells):
        return {'status': 'failed', 'reason': 'required proof mode or acknowledgement missing'}
    if any(r.get('cpu_ns') is None for r in cells):
        return {'status': 'inconclusive', 'reason': 'CPU evidence unavailable'}
    senders = [r for r in cells if r['sender']]
    if any(r['cpu_ns'] > 500_000_000 or r['wall_ns'] > 500_000_000 for r in senders):
        return {'status': 'stop', 'reason': 'mutation-invalidated sender Full verification exceeds 500ms in favorable Core-only proxy', 'sender_cpu_ns': [r['cpu_ns'] for r in senders], 'sender_wall_ns': [r['wall_ns'] for r in senders], 'release': 'not-run', 'kernel': 'not-run', 'live': 'not-run'}
    return {'status': 'requires-controller-checkpoint', 'reason': 'Core-only result cannot prove kernel scheduling or mounted target'}

def main():
    import argparse, os, signal, subprocess, time
    from metadata_reuse import extract
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['offline'], required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if not output.is_absolute():
        parser.error('output must be absolute')
    output.mkdir(exist_ok=False)
    manifest = extract(SOURCE, output / 'input.json')
    def command(argv):
        return subprocess.check_output(argv, text=True).strip()
    cmd = ['cargo', 'test', '--release', '--locked', '-p', 'magus-fs-core', '--lib', 'clean_visibility::tests::offline_comparison', '--', '--ignored', '--exact', '--nocapture']
    manifest.update(command=cmd, deltas=DELTAS, budget_seconds=BUDGET_SECONDS,
                    head=command(['git','rev-parse','HEAD']), diff=command(['git','diff','--binary']),
                    compiler=command(['rustc','+stable','--version','--verbose']), platform=command(['uname','-a']),
                    timing='CPU and wall separate; nested profile spans never summed with wall',
                    kernel='unmeasured', shared_constraint='retained P2 approximately319ms median; not added to this host measurement')
    paths = command(['git','ls-files']).splitlines() + ['crates/magus-fs-core/src/clean_visibility.rs','crates/magus-fs-core/tests/clean_visibility.rs','tests/fs2/affected_verification.py']
    manifest['source_sha256'] = {p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(set(paths)) if Path(p).is_file()}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2))
    env = dict(os.environ, RUSTUP_TOOLCHAIN='stable', MAGUS_AFFECTED_INPUT=str(output/'input.json'), MAGUS_AFFECTED_OUTPUT=str(output/'rows.jsonl'))
    deadline = None
    terminated = False
    with (output/'command.log').open('w') as log:
        process = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        while process.poll() is None:
            path = output/'rows.jsonl'
            if deadline is None and path.exists() and '"kind":"start"' in path.read_text():
                deadline = time.monotonic() + BUDGET_SECONDS
            if deadline is not None and time.monotonic() >= deadline:
                os.killpg(process.pid,signal.SIGTERM)
                terminated = True
                break
            time.sleep(.05)
        try:
            code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL)
            code = process.wait()
    rows = []
    if (output/'rows.jsonl').exists():
        for line in (output/'rows.jsonl').read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({'kind':'incomplete-json','raw':line})
    result = dict(exit=code, supervisor_terminated=terminated, gate=decision(rows,code,terminated), rows=rows,
                  cleanup='no service/mount/container; actual owned offline replica directories retained under output',
                  owned_state_directories=sorted(str(p) for p in output.glob('state-*') if p.is_dir()),
                  limits='simulated Core pathname calls and notifier enumeration; no kernel scheduling or notification syscall cost; sender body writes omitted')
    (output/'decision.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result['gate'],indent=2))
    return 0 if code == 0 else 1

if __name__ == '__main__':
    raise SystemExit(main())
