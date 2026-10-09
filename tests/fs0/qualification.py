"""Fail-closed matrix qualification; evidence is never inferred from runner exit alone."""
import time
import re

CHUNKS = (65536, 262144, 1048576)
CASES = ('mount', 'range_reads', 'private_writes', 'readonly_view', 'permissions', 'cleanup',
         'enumeration', 'partial_cold', 'partial_warm', 'full_scan', 'subprocess')


def wait_until(predicate, seconds, interval=0.2):
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('predicate deadline expired')
        time.sleep(min(interval, remaining))


def validate_content_profile(profile):
    try:
        assert all(set(('content_body_bytes','metadata_bytes','unique_chunks','retry_requests')).issubset(profile[name]) for name in ('before','enumeration','cold','warm','full'))
        assert profile['before']['unique_chunks'] == profile['before']['retry_requests'] == 0
        counts = [profile[name]['content_body_bytes'] for name in ('before', 'enumeration', 'cold', 'warm', 'full')]
        scan = profile['full_scan']
        return (counts[0] == counts[1] == 0 and 0 < counts[2] <= 8388608
                and counts[3] == counts[2] and counts[4] >= 67108864
                and scan['bytes'] == 67108864 and bool(scan['digest'])
                and scan['digest'] == scan['independent_digest'])
    except (KeyError, TypeError, AssertionError):
        return False


def owned_containers_absent(report):
    checks = [item for item in report.get('commands', []) if item.get('stdout') == 'owned-container-check.stdout']
    return bool(checks) and checks[-1].get('returncode') == 0 and report.get('remaining_owned_containers') == ''


def aggregate(platforms, required=('linux', 'macos')):
    blocked, failed, identities = [], [], {}
    for platform in required:
        report = platforms.get(platform)
        if not report:
            blocked.append(platform + ': missing platform')
            continue
        if report.get('state') == 'blocked':
            blocked.append(platform + ': ' + report.get('reason', 'blocked'))
        if report.get('state') == 'failed':
            failed.append(platform + ': failed platform')
        profiles = report.get('profiles', [])
        tokens = set()
        for journey in (1, 2):
            for chunk in CHUNKS:
                label = f'{platform}/{journey}/{chunk}'
                matches = [p for p in profiles if p.get('journey') == journey and p.get('chunk_size') == chunk]
                if len(matches) != 1:
                    (failed if len(matches) > 1 else blocked).append(label + ': duplicate or missing profile')
                    continue
                profile = matches[0]
                token = profile.get('owned_token')
                if not token:
                    blocked.append(label + ': missing fresh-resource identity')
                elif token in tokens:
                    failed.append(label + ': reused cache/resource identity')
                tokens.add(token)
                digest = profile.get('manifest_digest')
                if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                    blocked.append(label + ': missing manifest digest')
                elif identities.setdefault(chunk, digest) != digest:
                    failed.append(label + ': inconsistent immutable manifest')
                if profile.get('cleanup_errors') or profile.get('remaining_owned_resources'):
                    failed.append(label + ': cleanup error or leaked owned resource')
                for name in CASES:
                    case = profile.get('cases', {}).get(name, {})
                    if case.get('state') == 'failed':
                        failed.append(label + '/' + name + ': failed')
                    elif case.get('state') != 'passed' or not all(k in case for k in ('expected', 'observed', 'command')) or not case.get('command'):
                        blocked.append(label + '/' + name + ': missing/blocked evidence')
                if not profile.get('transfer'):
                    blocked.append(label + ': missing transfer proof')
                elif not validate_content_profile(profile['transfer']):
                    failed.append(label + ': invalid transfer profile')
    code = 1 if failed else 2 if blocked else 0
    return {'state': {0: 'passed', 1: 'failed', 2: 'blocked'}[code], 'passed': code == 0,
            'exit_code': code, 'failures': failed, 'blockers': blocked, 'manifest_digests': identities}
