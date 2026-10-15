"""Schema 1 phase qualification. A phase pass never qualifies all of FS3."""
import copy
import re

ISOLATION_CASES = {'same-principal': 'F3-1', 'different-principal': 'F3-1',
                   'isolated-private': 'F3-1', 'explicit-integration': 'F3-1',
                   'private-history': 'F3-2', 'api-bypass': 'F3-2',
                   'readonly': 'F3-2', 'scope-mode': 'F3-2',
                   'revoked-reconnect': 'F3-2', 'unaffected-peer': 'F3-2'}


SCALE_CASES = {'cache-bound':'F3-3','protected-prune':'F3-3','reads':'F3-5','fanout-1':'F3-4','fanout-5':'F3-4','fanout-20':'F3-4','peer-cases':'F3-4'}

def normalize(evidence: dict) -> dict:
    result = copy.deepcopy(evidence)
    failures = list(result.get('failures', []))
    def require(ok, message):
        if not ok and message not in failures:
            failures.append(message)
    require(result.get('schema') == 1, 'unsupported evidence schema')
    require(result.get('phase') in ('isolation','scale'), 'unsupported phase')
    require(result.get('status') in ('passed', 'failed', 'blocked'), 'invalid phase status')
    cleanup = result.get('cleanup', {})
    require(all(cleanup.get(k) is True for k in ('ok', 'mounts_absent', 'resources_removed'))
            and bool(cleanup.get('provenance')), 'owned cleanup unresolved')
    # Missing prerequisites do not invent failed runtime assertions.
    if result.get('status') == 'blocked' and result.get('blocked') and not failures:
        return result
    source = result.get('source', {})
    require(source.get('verified') is True and bool(re.fullmatch('[a-f0-9]{40}', source.get('head', '')))
            and bool(re.fullmatch('[a-f0-9]{64}', source.get('manifest_sha256', '')))
            and bool(source.get('bridge')), 'source binding incomplete')
    binaries = result.get('binaries', {})
    require(binaries.get('verified') is True and bool(re.fullmatch('sha256:[a-f0-9]{64}', binaries.get('image', '')))
            and all(re.fullmatch('[a-f0-9]{64}', binaries.get('sha256', {}).get(n, ''))
                    for n in ('magus-fs', 'magus-fs-service')), 'binary binding incomplete')
    composition = result.get('measurements', {}).get('composition')
    if composition is not None:
        chain = composition.get('source_chain', {})
        require(chain.get('verified') is True
                and chain.get('earlier_image') == binaries.get('image')
                and chain.get('earlier_binaries') == binaries.get('sha256')
                and all(p.startswith('tests/fs3/') for p in chain.get('differences', ['unknown']))
                and chain.get('current_manifest_sha256') == source.get('manifest_sha256')
                and bool(re.fullmatch('[a-f0-9]{64}', chain.get('earlier_manifest_sha256', '')))
                and bool(composition.get('earlier_result_sha256'))
                and bool(composition.get('continuation_result_sha256'))
                and composition.get('owned_cleanup_verified') is True,
                'composition source or ownership chain incomplete')
    assertions = result.get('assertions', [])
    for case, acceptance in (SCALE_CASES if result.get('phase')=='scale' else ISOLATION_CASES).items():
        rows = [a for a in assertions if a.get('case') == case]
        require(len(rows) == 1, 'missing or duplicate assertion: '+case)
        for row in rows:
            require(row.get('acceptance') == acceptance and row.get('passed') is True
                    and row.get('expected') is not None and row.get('expected') == row.get('observed')
                    and bool(row.get('provenance')), 'assertion failed: '+case)
    mounts = result.get('measurements', {}).get('mounts', [])
    for actor in (() if result.get('phase')=='scale' else ('a1', 'a2', 'b', 'readonly', 'peer')):
        require(any(m.get('actor') == actor and m.get('kernel_mounted') is True
                    and m.get('ordinary_uid') == 1001 and m.get('provenance') for m in mounts),
                'missing ordinary mount proof: '+actor)
    if result.get('phase') == 'scale':
        from scale import validate_scale
        for message in validate_scale(result.get('measurements', {})):require(False,message)
    if result.get('status') == 'failed' and not failures:
        failures.append('phase reported failure')
    result['failures'] = failures
    result['status'] = 'failed' if failures else 'blocked' if result.get('blocked') else 'passed'
    return result
