#!/usr/bin/env python3
"""Independent declared-intent assertions plus raw bounded CRDT evidence."""
import argparse
import hashlib
import json
import math
import pathlib
import shutil
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'tools/crdt-experiment/Cargo.toml'
BINARY = ROOT / 'tools/crdt-experiment/target/measurement/magus-fs-crdt-experiment'


def fixture(name, base, left, right, expected=None, frontier='base', helper='merged', fragments=None, third=None):
    saves = [{'id': 'left', 'actor': '01', 'frontier': 'base', 'text': left},
             {'id': 'right', 'actor': '02', 'frontier': frontier, 'text': right}]
    if third:
        saves.append({'id': 'third', 'actor': '03', 'frontier': third[0], 'text': third[1]})
    return {'mode': 'helper' if helper in ('budget', 'unsupported') else 'case', 'name': name, 'base': base, 'saves': saves,
            'expectation': {'exact': expected, 'fragments': fragments or [], 'helper': helper}}


def fixtures():
    return [
        fixture('distinct-insert-delete', 'one\ntwo\nthree\n', 'one\nnew\ntwo\nthree\n', 'one\ntwo\n', 'one\nnew\ntwo\n'),
        fixture('overlap', 'old\n', 'alice\n', 'bob\n', helper='overlap', fragments=['alice', 'bob']),
        fixture('delayed-known-save', 'a\nb\nc\n', 'A\nb\nc\n', 'a\nb\nC\n', 'A\nb\nC\n'),
        fixture('unknown-editor', 'a\nb\n', 'A\nb\n', 'a\nB\n', frontier='unknown', helper='unknown'),
        fixture('missing-heads', 'a\nb\n', 'A\nb\n', 'a\nB\n', frontier='unavailable', helper='base_unavailable'),
        fixture('unicode', 'café\n🦀\nfin\n', 'CAFÉ\n🦀\nfin\n', 'café\n🦀\n終\n', 'CAFÉ\n🦀\n終\n'),
        fixture('repeated-lines', 'same\nsame\nend\n', 'start\nsame\nsame\nend\n', 'same\nsame\nEND\n', 'start\nsame\nsame\nEND\n'),
        fixture('empty-concurrent', '', 'α\n', 'β\n', helper='overlap', fragments=['α', 'β']),
        fixture('dependent-save', 'a\nb\nc\n', 'A\nb\nc\n', 'a\nb\nC\n', 'A\nB\nC\n', third=('left', 'A\nB\nc\n'), helper='overlap'),
        fixture('nul-unsupported', 'x\0', 'x\0', 'x\0', helper='unsupported'),
        fixture('over-byte-limit', 'x' * 262145, 'x' * 262145, 'x' * 262145, helper='budget'),
        fixture('over-line-limit', 'x\n' * 4097, 'x\n' * 4097, 'x\n' * 4097, helper='budget'),
    ]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(cmd, log, timeout=300):
    start = time.monotonic()
    with log.open('wb') as stream:
        try:
            completed = subprocess.run(cmd, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
            return {'exit': completed.returncode, 'elapsed_seconds': time.monotonic() - start, 'timeout': False}
        except subprocess.TimeoutExpired:
            return {'exit': None, 'elapsed_seconds': time.monotonic() - start, 'timeout': True}


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def validate_case(spec, output):
    assert output['name'] == spec['name']
    assert output['three_way']['outcome'] == spec['expectation']['helper'], (spec['name'], output['three_way'])
    if spec['mode'] == 'helper':
        return {'helper_outcome_visible': output['three_way']['outcome']}
    assert len(output['saves']) == len(spec['saves'])
    frontiers = {'base': output['base_heads']}
    for save, got in zip(spec['saves'], output['saves']):
        assert got['input_sha256'] == digest(save['text'].encode())
        assert got['actor'] == save['actor']
        if save['frontier'] in ('unknown', 'unavailable'):
            reason = 'unknown' if save['frontier'] == 'unknown' else 'base_unavailable'
            assert got['outcome'] == reason and got['heads_after'] is None and got['heads_before'] is None
            assert got['retained_text'] == save['text']
        else:
            assert got['outcome'] == 'applied' and got['heads_before'] == frontiers[save['frontier']] and got['heads_after']
            frontiers[save['id']] = got['heads_after']
        if save['frontier'] == 'unavailable':
            assert got['frontier_error']
    finals = output['exchanges']
    assert len(finals) == math.factorial(len([s for s in spec['saves'] if s['frontier'] not in ('unknown', 'unavailable')]))
    assert len({x['text'] for x in finals}) == 1, spec['name']
    assert len({tuple(x['heads']) for x in finals}) == 1
    for result in finals:
        assert result['sha256'] == digest(result['text'].encode())
    intent = spec['expectation']
    exact_match = None if intent['exact'] is None else finals[0]['text'] == intent['exact']
    fragment_match = all(fragment in finals[0]['text'] for fragment in intent['fragments']) if intent['fragments'] else None
    # Intent mismatches are retained findings; mechanical convergence does not hide them.
    return {'converged': True, 'intent_exact_match': exact_match, 'intent_fragments_preserved': fragment_match}


def validate_evidence(out):
    provenance = json.loads((out / 'source.json').read_text())
    assert all(digest((out / 'source' / name).read_bytes()) == value for name,value in provenance['sha256'].items())
    assert digest((out / 'experiment').read_bytes()) == json.loads((out / 'binary.json').read_text())['sha256']
    for package in json.loads((out / 'registry.json').read_text()):
        path = out / 'registry' / (package['name']+'-'+package['version'])
        assert digest((path / 'Cargo.toml').read_bytes()) == package['manifest_sha256']
        assert all(digest((path / name).read_bytes()) == value for name,value in package['license_files'].items())
    inputs = json.loads((out / 'fixtures.json').read_text())
    results = []
    for spec in inputs:
        raw = records(out / (spec['name'] + '.jsonl'))[-1]
        assessment = validate_case(spec, raw)
        for exchange in raw.get('exchanges', []):
            loaded = records(out / (spec['name'] + '-reload-' + exchange['order'] + '.jsonl'))[-1]
            assert loaded['text'] == exchange['text'] and loaded['heads'] == exchange['heads']
        results.append({'name': spec['name'], **assessment})
    for size in [16384, 262144]:
        status = json.loads((out / ('benchmark-' + str(size) + '-status.json')).read_text())
        rows = records(out / ('benchmark-' + str(size) + '.jsonl'))
        changes = [r for r in rows if r['kind'] == 'change']
        assert status['timeout'] or (status['exit'] == 0 and len(changes) == 100 and rows[-1]['kind'] == 'complete')
        if status['timeout']:
            assert status['elapsed_seconds'] >= 29, 'timeout must retain actual bounded wall result'
        assert all(row['input_bytes'] == size for row in changes)
        assert [r['index'] for r in changes] == list(range(len(changes)))
        assert all(r['state_bytes'] > 0 and r['wire_bytes'] > 0 for r in changes)
        assert all(r['helper_outcome'] == 'merged' for r in changes)
        if changes:
            initial = next(r for r in rows if r['kind'] == 'initial')
            cumulative = initial['wire_bytes']
            line = '00000000' + 'x'*55 + '\n'
            expected = line*(size//64)
            for row in changes:
                offset = (row['index'] % (size//64))*64
                expected = expected[:offset] + format(row['index']+1,'08d') + expected[offset+8:]
                assert row['input_sha256'] == digest(expected.encode())
                cumulative += row['wire_bytes']
                assert row['cumulative_wire_bytes'] == cumulative
            if not status['timeout']:
                assert (out / ('benchmark-'+str(size)) / 'ordinary.txt').read_text() == expected
                assert (out / ('benchmark-'+str(size)) / 'final.am').stat().st_size == changes[-1]['state_bytes']
                loaded = records(out / ('benchmark-'+str(size)+'-reload.jsonl'))[-1]
                assert loaded['text'] == expected and loaded['heads'] == changes[-1]['heads_after']
                assert rows[-1]['sha256'] == loaded['sha256'] == digest(expected.encode())
        results.append({'size': size, 'completed_changes': len(changes), 'timeout': status['timeout']})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path)
    parser.add_argument('--validate', type=pathlib.Path)
    args = parser.parse_args()
    if args.validate:
        print(json.dumps(validate_evidence(args.validate), indent=2)); return
    out = args.output
    if not out or not out.is_absolute() or out.exists():
        parser.error('--output must be a new absolute path')
    out.mkdir()
    specs = fixtures()
    (out / 'fixtures.json').write_text(json.dumps(specs, ensure_ascii=False, indent=2))
    metadata = subprocess.check_output(['cargo', '+stable', 'metadata', '--locked', '--manifest-path', str(MANIFEST), '--format-version', '1'], cwd=ROOT)
    (out / 'metadata.json').write_bytes(metadata)
    info = json.loads(metadata)
    registry=[]
    for package in info['packages']:
        if package['source'] is None: continue
        manifest=pathlib.Path(package['manifest_path'])
        target=out / 'registry' / (package['name']+'-'+package['version'])
        target.mkdir(parents=True)
        shutil.copyfile(manifest, target / 'Cargo.toml')
        licenses=[p for p in manifest.parent.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','COPYING','NOTICE'))]
        for license_path in licenses: shutil.copyfile(license_path, target / license_path.name)
        registry.append({'name':package['name'],'version':package['version'],'source':package['source'],'license':package['license'],'manifest_sha256':digest(manifest.read_bytes()),'license_files':{p.name:digest(p.read_bytes()) for p in licenses}})
    (out / 'registry.json').write_text(json.dumps(registry,indent=2))
    (out / 'dependencies.json').write_text(json.dumps([{'name':p['name'], 'version':p['version'], 'license':p['license'], 'source':p['source']} for p in info['packages']], indent=2))
    compiler = subprocess.check_output(['rustc', '+stable', '--version', '--verbose'], text=True)
    assert compiler.startswith('rustc 1.92.0 ')
    (out / 'toolchain.txt').write_text(compiler)
    environment = {name:subprocess.check_output(command,text=True).strip() for name,command in {'platform':['uname','-a'],'os':['sw_vers'],'hardware':['sysctl','hw.model','hw.memsize','hw.ncpu','machdep.cpu.brand_string']}.items()}
    (out / 'environment.json').write_text(json.dumps(environment,indent=2))
    snapshot = ['tools/crdt-experiment/Cargo.toml', 'tools/crdt-experiment/Cargo.lock', 'tools/crdt-experiment/src/main.rs', 'tests/fs2/crdt_comparison.py', 'tests/fs2/test_crdt_comparison.py', 'crates/magus-fs-core/src/reconcile.rs', 'crates/magus-fs-core/src/lib.rs', 'crates/magus-fs-core/Cargo.toml', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']
    snapshot += [str(p.relative_to(ROOT)) for p in (ROOT / 'crates/magus-fs-core/src').rglob('*.rs')]
    snapshot = sorted(set(snapshot))
    hashes = {}
    for name in snapshot:
        path = out / 'source' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
        hashes[name] = digest(path.read_bytes())
    (out / 'source.json').write_text(json.dumps({'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(), 'sha256':hashes}, indent=2))
    build = run(['cargo', '+stable', 'build', '--locked', '--profile', 'measurement', '--manifest-path', str(MANIFEST)], out / 'build.log', 600)
    (out / 'build-status.json').write_text(json.dumps(build)); assert build['exit'] == 0, build
    shutil.copyfile(BINARY, out / 'experiment')
    (out / 'binary.json').write_text(json.dumps({'sha256':digest(BINARY.read_bytes()), 'profile':'measurement', 'opt_level':3}))
    start = time.monotonic()
    def remaining():
        seconds = 300 - (time.monotonic() - start)
        assert seconds > 0, 'overall 300-second experiment budget exhausted'
        return min(30, seconds)
    for spec in specs:
        directory = out / spec['name']; directory.mkdir()
        for save in spec['saves']:
            (directory / (save['id'] + '.txt')).write_text(save['text'])
        (directory / 'base.txt').write_text(spec['base'])
        spec['directory'] = str(directory)
        input_path = directory / 'input.json'; input_path.write_text(json.dumps(spec))
        status = run([str(BINARY), str(input_path)], out / (spec['name']+'.jsonl'), remaining())
        assert status['exit'] == 0, (spec['name'], status)
        raw = records(out / (spec['name']+'.jsonl'))[-1]; validate_case(spec, raw)
        for exchange in raw.get('exchanges', []):
            reload_spec = directory / 'reload.json'; reload_spec.write_text(json.dumps({'mode':'reload', 'path':exchange['state_path']}))
            status = run([str(BINARY),str(reload_spec)], out / (spec['name']+'-reload-'+exchange['order']+'.jsonl'), remaining())
            assert status['exit'] == 0
    for size in [16384, 262144]:
        input_path = out / ('benchmark-'+str(size)+'-input.json')
        input_path.write_text(json.dumps({'mode':'benchmark', 'size':size, 'changes':100, 'directory':str(out / ('benchmark-'+str(size)))}))
        status = run([str(BINARY),str(input_path)], out / ('benchmark-'+str(size)+'.jsonl'), remaining())
        (out / ('benchmark-'+str(size)+'-status.json')).write_text(json.dumps(status))
        if status['exit'] == 0:
            reload_path = out / ('benchmark-'+str(size)+'-reload-input.json')
            reload_path.write_text(json.dumps({'mode':'reload','path':str(out / ('benchmark-'+str(size)) / 'final.am')}))
            reload_status = run([str(BINARY),str(reload_path)],out / ('benchmark-'+str(size)+'-reload.jsonl'),remaining())
            assert reload_status['exit'] == 0
    summaries = []
    for size in [16384, 262144]:
        status = json.loads((out / ('benchmark-' + str(size) + '-status.json')).read_text())
        rows = records(out / ('benchmark-' + str(size) + '.jsonl'))
        initial = next((r for r in rows if r['kind'] == 'initial'), None)
        changes = [r for r in rows if r['kind'] == 'change']
        summary = {'size': size, 'requested_changes':100, 'completed_changes':len(changes), **status, 'initial':initial, 'final_completed_state_bytes':changes[-1]['state_bytes'] if changes else None, 'cumulative_wire_bytes':changes[-1]['cumulative_wire_bytes'] if changes else (initial['wire_bytes'] if initial else None), 'completed_changes_per_wall_second':len(changes)/status['elapsed_seconds'], 'latency_us':{}}
        for metric in ['update_us','merge_us','serialize_us','helper_us','iteration_us']:
            values=sorted(r[metric] for r in changes)
            summary['latency_us'][metric]={'median':(values[(len(values)-1)//2]+values[len(values)//2])/2 if values else None, 'p95':values[math.ceil(.95*len(values))-1] if values else None, 'samples':len(values)}
        summaries.append(summary)
    (out / 'benchmarks.json').write_text(json.dumps(summaries,indent=2))
    assessments = validate_evidence(out)
    (out / 'assessment.json').write_text(json.dumps(assessments,indent=2))
    assert all(digest((ROOT/name).read_bytes()) == value for name,value in hashes.items()), 'source changed during gate'
    (out / 'result.json').write_text(json.dumps({'passed':True,'experiment_seconds':time.monotonic()-start,'assessments':assessments,'semantic_findings':[r for r in assessments if r.get('intent_exact_match') is False or r.get('intent_fragments_preserved') is False]},indent=2))
    print(json.dumps(assessments,indent=2))


if __name__ == '__main__':
    main()
