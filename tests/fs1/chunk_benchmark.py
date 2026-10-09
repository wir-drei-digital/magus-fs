"""Streaming corpus/layout measurement and independent SHA-256 reconstruction.

Run with release Rust 1.92.0 on each platform. All output paths must be new.
The report is platform evidence; selection requires both platform reports.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
VARIANTS = ('base', 'insert', 'overwrite', 'append', 'truncate')
LAYOUTS = ('fixed', 'cdc')
BLOCK = 65536


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(BLOCK), b''):
            digest.update(data)
    return digest.hexdigest()


def write_corpora(folder):
    paths = {}
    for name, size in (('fs0-64mib', 67108864), ('text-csv-8mib', 8388608),
                       ('empty', 0), ('small-4095', 4095)):
        path = folder / name
        with path.open('wb') as stream:
            for start in range(0, size, BLOCK):
                count = min(BLOCK, size - start)
                if name == 'text-csv-8mib':
                    row = b'# synthetic workspace notes\nid,value,category\n1,synthetic,example\n2,repeated,text\n'
                    data = bytes(row[(start + i) % len(row)] for i in range(count))
                else:
                    data = bytearray(((i * 31 + i // 4096) % 251)
                                     for i in range(start, start + count))
                    if name == 'fs0-64mib':
                        data[:8] = (start // BLOCK).to_bytes(8, 'little')
                stream.write(data)
        paths[name] = path
    # Independent known FS0 identity catches corpus drift from native evidence.
    assert sha256(paths['fs0-64mib']) == '1977adb6a954de29fb854e5ea942b2ba29bc8c7846e83440d94e37ab61858369'
    return paths


def copy_bytes(source, target, count):
    while count:
        data = source.read(min(BLOCK, count))
        if not data:
            break
        target.write(data)
        count -= len(data)


def variant(base, output, name):
    size = base.stat().st_size
    patch = bytes((i * 17 + 7) % 251 for i in range(4096))
    with base.open('rb') as source, output.open('wb') as target:
        if name == 'insert':
            # The requested offset is beyond EOF for empty/small: splice at EOF.
            offset = min(size, 65537)
            copy_bytes(source, target, offset)
            target.write(patch)
            copy_bytes(source, target, size - offset)
        elif name == 'overwrite':
            offset = 1048579
            copy_bytes(source, target, min(size, offset))
            # Explicit zero bytes for the ordinary-file extension gap.
            for start in range(size, offset, BLOCK):
                target.write(b'\0' * min(BLOCK, offset - start))
            target.write(patch)
            source.seek(offset + len(patch))
            copy_bytes(source, target, max(0, size - offset - len(patch)))
        elif name == 'append':
            copy_bytes(source, target, size)
            target.write(bytes((i * 13 + 11) % 251 for i in range(65536)))
        elif name == 'truncate':
            copy_bytes(source, target, size // 2)
        else:
            raise ValueError(name)


def verify(path, report, base=None):
    """Read each descriptor's actual bytes, retaining repeated ordered identities.

    Every chunk hash and the whole ordered reconstruction are independently
    hashed in Python. No Rust digest/chunker code constructs expected bytes.
    """
    independently_hashed = sha256(path)
    reconstructed = hashlib.sha256()
    position = 0
    unique = {}
    descriptors = report['descriptors']
    with path.open('rb') as source:
        for descriptor in descriptors:
            assert descriptor['offset'] == position, (position, descriptor)
            assert 0 < descriptor['length'] <= 1048576
            source.seek(descriptor['offset'])
            data = source.read(descriptor['length'])
            assert len(data) == descriptor['length']
            identity = hashlib.sha256(data).hexdigest()
            assert identity == descriptor['sha256'], 'changed bytes hidden by chunk identity'
            reconstructed.update(data)
            position += len(data)
            if identity in unique:
                assert unique[identity] == len(data)
            unique[identity] = len(data)
    assert position == path.stat().st_size == report['bytes_scanned_rechunked']
    assert independently_hashed == reconstructed.hexdigest() == report['sha256']
    original = {d['sha256'] for d in base['descriptors']} if base else set()
    expected_new = sum(length for identity, length in unique.items() if identity not in original)
    assert report['unique_new_bytes'] == report['transferred_bytes'] == expected_new
    assert report['descriptor_count'] == len(descriptors)
    assert report['descriptor_encoded_bytes'] == 48 * len(descriptors)
    size = position
    ranges = [(0, min(4096, size)), (max(0, size - 4096), size)] if size else []
    hydrated = {}
    for d in descriptors:
        if any(d['offset'] < end and d['offset'] + d['length'] > start for start, end in ranges):
            hydrated[d['sha256']] = d['length']
    requested = min(size, 8192)
    return dict(input_sha256=independently_hashed, reconstructed_sha256=reconstructed.hexdigest(),
                output_sha256=report['sha256'], unique_chunk_count=len(unique),
                cold_header_tail_requested_bytes=requested,
                cold_header_tail_hydrated_bytes=sum(hydrated.values()),
                cold_read_amplification=sum(hydrated.values()) / requested if requested else 0)


def checked(command, output):
    # Own/reap this exact child and measure its complete lifetime, including
    # diagnostic serialization. Files avoid pipe deadlocks on descriptor output.
    stdout_path = output.with_suffix('.stdout')
    stderr_path = output.with_suffix('.stderr')
    started = time.perf_counter()
    with stdout_path.open('w') as stdout, stderr_path.open('w') as stderr:
        with subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr) as process:
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
    elapsed = time.perf_counter() - started
    record = dict(command=command, pid=process.pid, reaped=True,
                  returncode=process.returncode, stdout=stdout_path.read_text(),
                  stderr=stderr_path.read_text(), process_usage=dict(
                      cpu_seconds=usage.ru_utime + usage.ru_stime,
                      elapsed_seconds=elapsed,
                      peak_rss_bytes=usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024)))
    output.write_text(json.dumps(record, indent=2) + '\n')
    if process.returncode:
        raise RuntimeError('command failed: ' + repr(command) + '; see ' + str(output))
    return record['stdout']


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.output
    if not output.is_absolute() or output.exists() or output.is_symlink():
        parser.error('--output must be an absolute new path')
    output.mkdir()
    inputs = output / 'owned-inputs'
    inputs.mkdir()
    report = dict(schema='magus-fs-fs1-layout-measurement-v1', state='running',
                  platform=platform.platform(), python=sys.version, executable=sys.executable,
                  command=[sys.executable, *sys.argv], layouts={
                      'fixed': dict(size=262144), 'cdc': dict(library='fastcdc', version='5.0.0',
                                                           algorithm='v2020', min=65536, avg=262144,
                                                           max=1048576, normalization=1, seed=0)},
                  descriptor_representation='candidate LE offset:u64,length:u64,SHA256:32 bytes; no final format/index/envelope',
                  measurement_scope='whole-file streaming recapture per variant; locally warm page cache, conceptual cold empty chunk cache for range amplification',
                  variants={'insert': '4096 bytes at65537 (EOF splice for short inputs)',
                            'overwrite': '4096 bytes at1048579 (explicit zero extension for short inputs)',
                            'append': '65536 bytes', 'truncate': 'half original size'},
                  timed_runs_per_nonempty_corpus_layout_variant=3,
                  unmeasured_warmup_runs_per_corpus_layout_variant=1, corpora={})
    try:
        report['rustc'] = checked(['rustc', '-Vv'], output / 'rustc.json')
        assert 'release: 1.92.0' in report['rustc'], 'requires pinned Rust 1.92.0'
        checked(['cargo', 'build', '--release', '--locked', '--example', 'chunk_layout'], output / 'build.json')
        target = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
        binary = target / 'release/examples/chunk_layout'
        report['binary_sha256'] = sha256(binary)
        report['source_revision'] = checked(['git', 'rev-parse', 'HEAD'], output / 'revision.json').strip()
        report['dirty'] = checked(['git', 'status', '--short'], output / 'dirty.json').strip()
        sources = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'benches/chunk_layout.rs',
                   'tests/fs1/chunk_benchmark.py', 'src/source.rs']
        report['sources_sha256'] = {p: sha256(ROOT / p) for p in sources}
        report['cargo_lock'] = (ROOT / 'Cargo.lock').read_text()
        for corpus, base_path in write_corpora(inputs).items():
            paths = {'base': base_path}
            for name in VARIANTS[1:]:
                paths[name] = inputs / (corpus + '-' + name)
                variant(base_path, paths[name], name)
            item = report['corpora'][corpus] = dict(size=base_path.stat().st_size,
                         independent_input_hashes={n: sha256(p) for n, p in paths.items()}, layouts={})
            for layout in LAYOUTS:
                samples = item['layouts'][layout] = dict(raw=[], medians={})
                # Empty corpus still executes and verifies every variant once.
                for sample in range(4 if item['size'] else 1):
                    results = {}
                    base_report = output / f'{corpus}-{layout}-{sample}-base.json'
                    for name in VARIANTS:
                        command = [str(binary), str(paths[name]), layout]
                        if name != 'base':
                            command.append(str(base_report))
                        raw = output / f'{corpus}-{layout}-{sample}-{name}.json'
                        command_record = raw.with_suffix('.command.json')
                        result = json.loads(checked(command, command_record))
                        for key in ('cpu_seconds', 'elapsed_seconds', 'peak_rss_bytes'):
                            result['capture_' + key] = result[key]
                            result[key] = json.loads(command_record.read_text())['process_usage'][key]
                        result['measurement_scope'] = 'independent wait4 CPU/peak RSS through child exit; elapsed includes process launch and diagnostic JSON; verification excluded'
                        result['verification'] = verify(paths[name], result, results.get('base'))
                        raw.write_text(json.dumps(result, indent=2) + '\n')
                        results[name] = result
                    samples['raw'].append(dict(sample=sample, timed=sample > 0,
                                                results=results))
                timed = samples['raw'][1:]
                for name in VARIANTS:
                    runs = [s['results'][name] for s in timed] or [samples['raw'][0]['results'][name]]
                    invariant = ('unique_new_bytes', 'transferred_bytes', 'bytes_scanned_rechunked',
                                 'descriptor_count', 'descriptor_encoded_bytes', 'sha256')
                    for key in invariant:
                        assert all(r[key] == runs[0][key] for r in runs)
                    values = {key: runs[0][key] for key in invariant}
                    values.update({key: statistics.median(r[key] for r in runs)
                                   for key in ('cpu_seconds', 'elapsed_seconds', 'peak_rss_bytes')})
                    values['verification'] = runs[0]['verification']
                    samples['medians'][name] = values
                samples['suite_cpu_median_seconds'] = statistics.median(
                    sum(s['results'][name]['cpu_seconds'] for name in VARIANTS) for s in (timed or samples['raw']))
                print(corpus, layout, 'correct; timed samples', len(timed), flush=True)
        report.update(state='passed', correctness='all ordered chunk/whole-byte hashes match')
        return_code = 0
    except Exception as error:
        report.update(state='failed', error=repr(error))
        return_code = 1
    finally:
        # Only this invocation created these synthetic files; retain all evidence.
        shutil.rmtree(inputs)
        report['cleanup'] = dict(owned_input_directory=str(inputs), removed=not inputs.exists(),
                                 retained_resources=['report + command/output/raw samples'], native_resources=[])
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output / 'result.json', flush=True)
    return return_code


if __name__ == '__main__':
    raise SystemExit(main())
