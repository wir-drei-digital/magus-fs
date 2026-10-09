import copy
import errno
import fcntl
from pathlib import Path
import tempfile
import unittest
from qualification import aggregate, wait_until, validate_content_profile
from lock_io import contend


def transfer():
    baseline = dict(content_body_bytes=0, retry_requests=0, unique_chunks=0, metadata_bytes=100)
    return {'before':baseline, 'enumeration':baseline, 'cold':dict(baseline,content_body_bytes=524288),
            'warm':dict(baseline,content_body_bytes=524288), 'full':dict(baseline,content_body_bytes=67108864),
            'full_scan':{'bytes':67108864,'digest':'a'*64,'independent_digest':'a'*64}}


def valid():
    cases = {name: {'state': 'passed', 'expected': name, 'observed': True, 'command': ['proof']} for name in
             ('mount', 'range_reads', 'private_writes', 'readonly_view', 'permissions', 'cleanup', 'enumeration', 'partial_cold', 'partial_warm', 'full_scan', 'subprocess')}
    return {'state': 'passed', 'profiles': [{'journey': j, 'chunk_size': c, 'manifest_digest': f'{c:064x}', 'owned_token':f'fresh-{j}-{c}', 'transfer': transfer(),
            'cases': copy.deepcopy(cases), 'cleanup_errors': [], 'remaining_owned_resources': []}
            for j in (1, 2) for c in (65536, 262144, 1048576)]}


class Qualification(unittest.TestCase):
    def test_complete_matrix_passes(self):
        self.assertEqual(aggregate({'linux': valid(), 'macos': valid()})['exit_code'], 0)
    def test_missing_platform_blocks(self):
        self.assertEqual(aggregate({'linux': valid()})['exit_code'], 2)
    def test_missing_case_blocks(self):
        platforms = {'linux': valid(), 'macos': valid()}
        del platforms['linux']['profiles'][0]['cases']['full_scan']
        self.assertEqual(aggregate(platforms)['exit_code'], 2)
    def test_missing_profile_blocks(self):
        platforms = {'linux': valid(), 'macos': valid()}
        platforms['macos']['profiles'].pop()
        self.assertEqual(aggregate(platforms)['exit_code'], 2)
    def test_manifest_mismatch_fails(self):
        platforms = {'linux': valid(), 'macos': valid()}
        platforms['macos']['profiles'][0]['manifest_digest'] = 'f'*64
        self.assertEqual(aggregate(platforms)['exit_code'], 1)
    def test_blocked_case_blocks(self):
        platforms = {'linux': valid(), 'macos': valid()}
        platforms['linux']['profiles'][0]['cases']['mount']['state'] = 'blocked'
        self.assertEqual(aggregate(platforms)['exit_code'], 2)
    def test_leak_fails(self):
        platforms = {'linux': valid(), 'macos': valid()}
        platforms['linux']['profiles'][0]['remaining_owned_resources'] = ['owned-mount']
        self.assertEqual(aggregate(platforms)['exit_code'], 1)
    def test_failed_case_fails(self):
        platforms = {'linux': valid(), 'macos': valid()}
        platforms['linux']['profiles'][0]['cases']['range_reads']['state'] = 'failed'
        self.assertEqual(aggregate(platforms)['exit_code'], 1)
    def test_deadline_stops_false_predicate(self):
        with self.assertRaises(TimeoutError):
            wait_until(lambda: False, seconds=0.01, interval=0.001)
    def test_transfer_rejects_stale_baseline_and_budget(self):
        baseline = dict(content_body_bytes=0, retry_requests=0, unique_chunks=0, metadata_bytes=100)
        profile = {'before': baseline, 'enumeration': baseline, 'cold': dict(baseline, content_body_bytes=524288),
                   'warm': dict(baseline, content_body_bytes=524288), 'full': dict(baseline, content_body_bytes=67108864),
                   'full_scan': {'digest': 'abc', 'independent_digest': 'abc', 'bytes': 67108864}}
        self.assertTrue(validate_content_profile(profile))
        for key, amount in [('before', 1), ('enumeration', 1), ('cold', 8388609), ('warm', 524289)]:
            bad = copy.deepcopy(profile)
            bad[key]['content_body_bytes'] = amount
            self.assertFalse(validate_content_profile(bad), key)

    def test_missing_counters_blocks(self):
        platforms = {'linux':valid(), 'macos':valid()}
        del platforms['linux']['profiles'][0]['transfer']
        self.assertNotEqual(aggregate(platforms)['exit_code'],0)
    def test_reused_cache_token_fails(self):
        platforms = {'linux':valid(), 'macos':valid()}
        platforms['linux']['profiles'][3]['owned_token'] = platforms['linux']['profiles'][0]['owned_token']
        self.assertEqual(aggregate(platforms)['exit_code'],1)
    def test_stale_source_seen_counters_fail(self):
        profile = transfer()
        profile['before'] = dict(profile['before'],unique_chunks=1)
        self.assertFalse(validate_content_profile(profile))
    def test_empty_case_command_blocks(self):
        platforms = {'linux':valid(), 'macos':valid()}
        platforms['linux']['profiles'][0]['cases']['mount']['command'] = []
        self.assertEqual(aggregate(platforms)['exit_code'],2)


class Locks(unittest.TestCase):
    def test_expected_contention_is_structured(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'
            path.write_bytes(b'x')
            with path.open('rb') as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = contend(path)
                self.assertEqual(result['state'], 'contended')
                self.assertIn(result['errno'], (errno.EAGAIN, errno.EWOULDBLOCK))
    def test_missing_file_is_never_contention(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(AssertionError):
                contend(Path(root) / 'absent')
    def test_uncontended_file_is_never_contention(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'
            path.touch()
            with self.assertRaises(AssertionError):
                contend(path)

class IdentityAndScan(unittest.TestCase):
    def test_projection_changes_only_owner_identity(self):
        import hashlib
        import json
        from permission_source import project_manifest
        entries = [{'path':'file','size':1,'mode':420,'uid':0,'gid':0,'directory':False,'chunks':['a'*64]}]
        original = {'chunk_size':65536,'entries':entries}
        original['digest'] = hashlib.sha256(json.dumps(['magus-fs-manifest-v1',65536,entries],separators=(',',':')).encode()).hexdigest()
        result = project_manifest(original, uid=501, gid=20)
        self.assertEqual(result['entries'][0]['uid'],501)
        self.assertEqual(result['entries'][0]['gid'],20)
        self.assertEqual(original['entries'][0]['uid'],0)
        self.assertEqual(result['entries'][0]['chunks'],['a'*64])
        self.assertNotEqual(result['digest'],original['digest'])

    def test_scan_checks_independent_digest_and_length(self):
        from measurement_io import scan
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'
            path.write_bytes(b'abc')
            digest = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
            self.assertEqual(scan(path,digest,3)['digest'],digest)
            with self.assertRaises(AssertionError):
                scan(path,'bad',3)
            with self.assertRaises(AssertionError):
                scan(path,digest,4)

class NativeSummary(unittest.TestCase):
    def test_missing_private_syscalls_cannot_be_collapsed_to_pass(self):
        from run import summarize_linux
        native = {'passed':True, 'cases':{'private':{'mount':{'state':'passed'}}}}
        result = summarize_linux(native,1,65536,'owned/result.json')
        self.assertNotEqual(result['cases']['private_writes']['state'],'passed')

    def test_missing_readonly_mutations_cannot_be_collapsed_to_pass(self):
        from run import summarize_linux
        minimal = {'mount':{'state':'passed'},'range_reads':{'state':'passed'}}
        native = {'passed':True, 'cases':{'root-readonly':minimal,'root-mode000-readonly':minimal}}
        result = summarize_linux(native,1,65536,'owned/result.json')
        self.assertNotEqual(result['cases']['readonly_view']['state'],'passed')

    def test_false_permission_observation_cannot_pass(self):
        from run import summarize_linux
        native = {'passed':True,'cases':{name:{'observation':False} for name in
                  ('group-permissions','other-permissions','execute-other','execute-denied','nonroot-mode000')}}
        result = summarize_linux(native,1,65536,'owned/result.json')
        self.assertNotEqual(result['cases']['permissions']['state'],'passed')

    def test_assumed_cleanup_without_mount_and_pid_proof_cannot_pass(self):
        from run import summarize_linux
        native = {'passed':True, 'cleanup':[{'assumed':'clean'}], 'remaining_owned_containers':''}
        result = summarize_linux(native,1,65536,'owned/result.json')
        self.assertNotEqual(result['cases']['cleanup']['state'],'passed')

    def test_failed_owned_container_absence_query_cannot_pass(self):
        from run import summarize_linux
        native = {'passed':True,'owned_vm_path':'/tmp/owned','remaining_owned_containers':'',
                  'daemon':{'mounts':{'view':{'mountpoint':'/shared/view'}},'pids':[7]},
                  'cleanup':[{'unmounts':[{'path':'/shared/view','returncode':0,'still_mounted':False}],
                              'reaped':[{'pid':7,'returncode':0}]},{'owned_vm_path':'/tmp/owned','removed':True}],
                  'commands':[{'stdout':'owned-container-check.stdout','returncode':1,'command':['docker','ps']}]}
        result = summarize_linux(native,1,65536,'owned/result.json')
        self.assertNotEqual(result['cases']['cleanup']['state'],'passed')


class LockOperation(unittest.TestCase):
    def test_open_eagain_is_not_lock_contention(self):
        from lock_io import validate_observation
        with self.assertRaises(AssertionError):
            validate_observation(75,{'state':'contended','errno':errno.EAGAIN,'operation':'open'},'')
