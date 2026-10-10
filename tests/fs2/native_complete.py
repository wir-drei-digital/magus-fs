#!/usr/bin/env python3
"""FS2-B Task 1 native completion gate (exit 0 passed, 1 failed, 2 missing prerequisite).

Real primitives only: macOS APFS renameatx_np(RENAME_SWAP) and loopback NFS client/server,
Linux renameat2(RENAME_EXCHANGE) in owned containers, and the authenticated HTTPS service with
PostgreSQL/S3. Ordinary processes hold descriptors and working directories across application.
"""
import argparse, errno, hashlib, json, os, secrets, shutil, signal, subprocess, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, verify_image
from service_protocol import identity, file_entry, GROUP
from service_storage import NS, ALICE, object_id
from full_native import Endpoint, NativeJourney

CORE_CASES = [
    'structural_directory_and_namespace_matrix_uses_verified_root_exchange',
    'root_and_directory_modes_apply_and_verify',
    'mapped_group_ownership_applies_and_unmappable_owner_blocks_without_loss',
    'readonly_root_parent_blocks_structural_work_without_loss',
    'capture_excluded_local_entries_survive_and_unsupported_or_colliding_entries_block',
    'held_descriptor_and_cwd_writes_land_in_retained_root_and_become_recovery_records',
    'tampered_retained_version_requires_a_new_record',
    'stale_ram_save_after_application_is_unknown_causality',
    'journal_upgrades_additively_and_newer_schema_fails_closed',
    'structural_crash_recovery_uses_durable_phases_and_inode_identities',
    'structural_nofollow_root_and_parent_races_fail_closed',
    'structural_racing_write_after_exchange_retains_both_roots',
]
WATCH_CASE = 'verified_root_exchange_rebinds_watcher_and_rescans_installed_root'
UNKNOWN = 'native_unknown_causality'

def sha(data): return hashlib.sha256(data).hexdigest()
def passed(output, names):
    rows = {l.split(' ... ')[0][5:]: l.split(' ... ')[1] for l in output.splitlines() if l.startswith('test ') and ' ... ' in l}
    missing = [n for n in names if not any(k.endswith(n) for k in rows)]
    failed = [k for k, v in rows.items() if v.strip() != 'ok']
    assert not missing and not failed and 'test result: ok' in output, {'missing': missing, 'failed': failed}
    return rows

def host_matrix(i, record):
    """macOS host: the exact Core native matrix and the watcher rebind on APFS/FSEvents."""
    core = i.run(['cargo', '+stable', 'test', '--locked', '-p', 'magus-fs-core', '--test', 'native_apply',
                  '--features', 'test-faults'], timeout=900, check=False)
    (i.output / 'macos-core-tests.txt').write_text(core.stdout + core.stderr)
    assert core.returncode == 0, core.stderr[-4000:]
    watch = i.run(['cargo', '+stable', 'test', '--locked', '-p', 'magus-fs', '--', 'sync::watch', '--nocapture'],
                  timeout=900, check=False)
    (i.output / 'macos-cli-tests.txt').write_text(watch.stdout + watch.stderr)
    assert watch.returncode == 0, watch.stderr[-4000:]
    record('macos', 'core-native-matrix', tests=passed(core.stdout, CORE_CASES),
           primitive='renameatx_np RENAME_SWAP|RENAME_EXCL', filesystem=i.run(['/sbin/mount'], check=False).stdout.count('apfs'))
    record('macos', 'watcher-rebind', tests=passed(watch.stdout, [WATCH_CASE]),
           rebound=[l for l in (watch.stdout + watch.stderr).splitlines() if 'native_watch_rebound' in l])

def linux_matrix(i, record):
    """Linux containers: the same matrix with real renameat2 on tmpfs, as root without
    capabilities (actual fchown EPERM) and as an unprivileged user with a second group."""
    tag = i.owner + '-native-complete'
    i.write_json('native-complete-image-ownership.json', {'owner': i.owner, 'tag': tag, 'intent': 'retained test image'})
    i.docker('build', '-f', 'tests/fs2/Dockerfile.native-complete', '--label', 'magus.fs2.owner=' + i.owner, '-t', tag, '.', timeout=1800)
    image = json.loads(i.docker('image', 'inspect', tag).stdout)[0]
    for label, user in [('root-no-capabilities', []), ('uid1001', ['--user', '1001:1001'])]:
        container = i.create('container', 'native-complete-' + label, ['--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--group-add', '1002', '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777,size=1200m', *user, image['Id'], 'sh', '-c', 'id && /out/native-tests --nocapture && /out/cli-tests sync::watch --nocapture'])
        p = i.docker('start', '--attach', container, timeout=600, check=False)
        (i.output / ('linux-' + label + '-tests.txt')).write_text(p.stdout + p.stderr)
        code = i.inspect('container', container)['State']['ExitCode']
        assert code == 0, (label, code, (p.stdout + p.stderr)[-6000:])
        record('linux', 'core-native-matrix-' + label, identity=p.stdout.splitlines()[0], tests=passed(p.stdout, CORE_CASES + [WATCH_CASE]),
               primitive='renameat2 RENAME_EXCHANGE|RENAME_NOREPLACE', filesystem='tmpfs', image=image['Id'],
               rebound=[l for l in (p.stdout + p.stderr).splitlines() if 'native_watch_rebound' in l])

class Complete(NativeJourney):
    def __init__(self, i, image, platforms, cases):
        super().__init__(i, image, platforms, 'full');self.cases = cases;self.mounts = [];self.processes = []
    def publish_tree(self, mutate, bodies=()):
        view, r = self.view();mutate(r['tree']);r['tree']['entries'].sort(key=lambda e: e['path'])
        _, private = self.candidate(view, r, 'alice', list(bodies))
        return self.expect('t1-integrate', 'POST', self.root + '/integrations', 200, body=self.integrate_request(private, view))
    def run(self):
        self.i.start_service();self.wait()
        authority = {'principal': ALICE, 'uid': 1001, 'gid': 1001, 'primary_group': GROUP, 'groups': [GROUP], 'dac_override': False, 'ownership_transfer': False}
        self.i.provision([{'namespace': NS, 'principal': ALICE, 'replica': 'replica:' + f'{1:032x}', 'token': secrets.token_hex(32), 'expires': int(time.time()) + 3600, 'actions': ['admin', 'read', 'write', 'integrate', 'history'], 'branches': ['main'], 'prefixes': [''], 'authority': authority, 'root_policy': self.tree_root}])
        reports = {'path': 'reports', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}}
        body = b'initial native ordinary bytes';self.base_body = body
        self.seed_entries = [reports, file_entry('reports/live', reports['id'], body)]
        upload, rid = self.stage(self.descriptor(self.seed_entries), bodies=[body])
        self.expect('native-seed', 'POST', self.root + '/seed', 200, body={'branch': 'main', 'revision': rid, 'upload': upload})
        for platform in self.platforms:
            ep = Endpoint(self, platform, self.image);self.endpoints.append(ep)
            for case in ['structural', 'recovery', 'causality', 'races']:
                if case in self.cases:getattr(self, case)(ep);self.reset()
        if 'nfs' in self.cases and 'macos' in self.platforms:self.nfs()
    def reset(self):
        """Every case starts from the seeded identities and bytes on the shared branch."""
        def seeded(t):t['entries'] = json.loads(json.dumps(self.seed_entries))
        return self.publish_tree(seeded, [self.base_body])

    # ---- ordinary-folder structural application (both OSes) ----
    def native(self, ep, c, paths):
        return ep.run("import os,stat,hashlib\nout={}\nfor p in s['paths']:\n f=s['root']+'/'+p\n try:\n  m=os.lstat(f)\n  out[p]={'kind':'dir' if stat.S_ISDIR(m.st_mode) else 'file','mode':stat.S_IMODE(m.st_mode),'ino':m.st_ino,'sha256':None if stat.S_ISDIR(m.st_mode) else hashlib.sha256(open(f,'rb').read()).hexdigest()}\n except FileNotFoundError:out[p]=None\nout['']={'ino':os.lstat(s['root']).st_ino,'mode':stat.S_IMODE(os.lstat(s['root']).st_mode)}\nprint(json.dumps(out))", {'root': c['root'], 'paths': paths})
    def log(self, ep, c):
        return ep.run("print(json.dumps(open(s,errors='replace').read()))", c['path'] + '/daemon.log')
    def structural(self, ep):
        c = ep.create('structural');ep.start(c);self.until(lambda: ep.ready(c))
        before = self.native(ep, c, ['reports', 'reports/live'])
        steps = []
        def step(label, mutate, bodies, expect):
            started = time.monotonic();shared = self.publish_tree(mutate, bodies)
            self.until(lambda: ep.ready(c, shared['head']), 15);seconds = time.monotonic() - started
            observed = self.native(ep, c, list(expect));status = ep.status(c)
            for path, want in expect.items():
                got = observed[path]
                if want is None:assert got is None, (label, path, got)
                else:
                    assert got is not None, (label, path)
                    for k, v in want.items():assert got[k] == v, (label, path, k, got, v)
            steps.append({'step': label, 'seconds': seconds, 'head': shared['head'], 'observed': observed, 'native': status['native']})
            return observed
        note = b'nested structural note';docs = {}
        def create(t):
            d = {'path': 'docs', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 0o750, 'content': {'kind': 'directory'}};docs.update(d)
            t['entries'] += [d, file_entry('docs/note', d['id'], note)]
        o1 = step('directory-and-nested-file-create', create, [note], {'docs': {'kind': 'dir', 'mode': 0o750}, 'docs/note': {'kind': 'file', 'sha256': sha(note)}, 'reports/live': {'sha256': sha(self.base_body)}})
        assert o1['']['ino'] != before['']['ino'], 'structural application must exchange the root inode'
        displaced = [d for d in ep.status(c)['native']['displacements'] if d['path'] == '']
        assert displaced and ep.run("import os\nprint(json.dumps(os.lstat(s).st_ino))", displaced[-1]['retained_path']) == before['']['ino']
        assert ep.run("print(json.dumps(open(s,'rb').read().hex()))", displaced[-1]['retained_path'] + '/reports/live') == self.base_body.hex()
        self.until(lambda: 'native_watch_rebound' in self.log(ep, c), 10)
        def move(t):
            for e in t['entries']:
                if e['path'] == 'docs':e['path'] = 'archive'
                elif e['path'] == 'docs/note':e['path'] = 'archive/note'
                elif e['path'] == 'reports/live':e['path'] = 'reports/renamed'
        step('directory-move-and-file-rename', move, [], {'docs': None, 'archive': {'kind': 'dir'}, 'archive/note': {'sha256': sha(note)}, 'reports/live': None, 'reports/renamed': {'sha256': sha(self.base_body)}})
        fresh = b'same path new identity';ids = {}
        def replace(t):
            reports = next(e for e in t['entries'] if e['path'] == 'reports');archive = next(e for e in t['entries'] if e['path'] == 'archive')
            ids['old_note'] = next(e for e in t['entries'] if e['path'] == 'archive/note')['id']
            t['entries'] = [e for e in t['entries'] if e['path'] not in ('reports/renamed', 'archive/note')]
            t['entries'].append({'path': 'reports/renamed', 'id': identity('entry'), 'parent': reports['id'], 'owner': ALICE, 'group': GROUP, 'mode': 0o755, 'content': {'kind': 'directory'}})
            n = file_entry('archive/note', archive['id'], fresh);ids['new_note'] = n['id'];t['entries'].append(n)
        step('type-replacement-and-same-path-new-identity', replace, [fresh], {'reports/renamed': {'kind': 'dir'}, 'archive/note': {'sha256': sha(fresh)}})
        def modes(t):
            next(e for e in t['entries'] if e['path'] == 'archive')['mode'] = 0o700
            next(e for e in t['entries'] if e['path'] == 'archive/note')['mode'] = 0o640
        step('directory-and-file-modes', modes, [], {'archive': {'mode': 0o700}, 'archive/note': {'mode': 0o640}})
        def delete(t):t['entries'] = [e for e in t['entries'] if not e['path'].startswith('archive')]
        step('directory-tree-delete', delete, [], {'archive': None, 'archive/note': None})
        settled = ep.status(c);time.sleep(2.5);after = ep.status(c)
        assert len(after['status']['submissions']) == len(settled['status']['submissions']), 'structural application echoed a capture'
        self.record(ep.platform, 'structural-service-matrix', before=before, steps=steps, retained_root=displaced[-1], no_echo_submissions=len(after['status']['submissions']), rebound=[l for l in self.log(ep, c).splitlines() if 'native_watch_rebound' in l])
        ep.stop(c)

    # ---- held FD/CWD across a root exchange; recovery list/capture/export; restart ----
    def cli_raw(self, ep, c, *args):
        return ep.run("p=subprocess.run([s[0],*s[1]],capture_output=True,text=True,timeout=20)\nprint(json.dumps({'code':p.returncode,'out':p.stdout,'err':p.stderr}))", [ep.binary, [*args, '--state', c['state']]])
    def recovery(self, ep):
        c = ep.create('recovery');ep.start(c);self.until(lambda: ep.ready(c))
        tag = c['path'] + '/holder';ep.children.append({'creating': tag});ep.save()
        code = """import json,os,sys,time,hashlib
s=json.loads(sys.argv[1]);fd=os.open(s['root']+'/reports/live',os.O_RDWR);os.chdir(s['root']);cwd=os.stat('.').st_ino
open(s['tag']+'-ready','w').close()
def wait(name):
 deadline=time.monotonic()+90
 while not os.path.exists(s['tag']+'-'+name):
  assert time.monotonic()<deadline,name
  time.sleep(.02)
wait('go');body=b'held descriptor late write';os.pwrite(fd,body,0);os.ftruncate(fd,len(body));os.fsync(fd)
f=os.open('cwd-late',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640);os.write(f,b'written through retained cwd');os.fsync(f);os.close(f)
open(s['tag']+'-done','w').write(json.dumps({'cwd_inode':cwd,'held_inode':os.fstat(fd).st_ino,'root_now':os.stat(s['root']).st_ino,'cwd_listing':sorted(os.listdir('.'))}))
wait('again');body=b'HELD DESCRIPTOR CHANGED AFTER RESTART';os.pwrite(fd,body,0);os.ftruncate(fd,len(body));os.fsync(fd);os.close(fd)
open(s['tag']+'-again-done','w').close()"""
        pid = ep.run("p=subprocess.Popen(['python3','-c',s['code'],json.dumps(s['args'])],stdout=open(s['tag']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))", {'code': code, 'args': {'root': c['root'], 'tag': tag}, 'tag': tag})
        ep.children[-1] = {'pid': pid, 'tag': tag};ep.save();self.until(lambda: ep.exists(tag + '-ready'))
        root_before = self.native(ep, c, [])['']['ino']
        def add_dir(t):t['entries'].append({'path': 'incoming-dir', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}})
        shared = self.publish_tree(add_dir);self.until(lambda: ep.ready(c, shared['head']), 15)
        ep.run("open(s+'-go','w').close();print('{}')", tag);self.until(lambda: ep.exists(tag + '-done'))
        held = ep.run("print(open(s+'-done').read())", tag)
        assert held['cwd_inode'] == root_before and held['root_now'] != root_before and 'cwd-late' in held['cwd_listing']
        assert not ep.exists(c['root'] + '/cwd-late') and ep.read(c) == self.base_body.hex()
        self.until(lambda: 'late_displaced_write' in json.dumps(ep.status(c)['native']['status']), 10)
        status = ep.status(c);assert not status['live']['applied']
        listed = ep.cli(c, 'sync', 'recovery', 'list');records = listed['records']
        by = {r['source_path']: r for r in records}
        assert by['reports/live']['observed_digest'] == 'sha256:' + sha(b'held descriptor late write')
        assert by['cwd-late']['observed_digest'] == 'sha256:' + sha(b'written through retained cwd')
        assert all(r['causal_coverage'] == 'Unknown' for r in records)
        submissions = len(status['status']['submissions'])
        rec = by['reports/live'];op = identity('operation')
        mismatch = self.cli_raw(ep, c, 'sync', 'recovery', 'capture', '--id', rec['id'], '--digest', 'sha256:' + '0' * 64, '--operation-id', op)
        assert mismatch['code'] == 1 and json.loads(mismatch['out'])['error'] == 'operation_mismatch', mismatch
        captured = ep.cli(c, 'sync', 'recovery', 'capture', '--id', rec['id'], '--digest', rec['observed_digest'], '--operation-id', op)
        replay = ep.cli(c, 'sync', 'recovery', 'capture', '--id', rec['id'], '--digest', rec['observed_digest'], '--operation-id', op)
        assert captured['revision'] == replay['revision'] and captured['provenance'] == UNKNOWN and captured['parents'] == [rec['original_base']] and captured['published'] is False
        time.sleep(2.5);after = ep.status(c)
        assert len(after['status']['submissions']) == submissions and after['live']['revision'] == status['live']['revision'], 'recovery capture must never auto-publish'
        dest = c['path'] + '/exported-cwd-late'
        exported = ep.cli(c, 'sync', 'recovery', 'export', '--id', by['cwd-late']['id'], '--digest', by['cwd-late']['observed_digest'], '--destination', dest)
        assert ep.run("print(json.dumps(open(s,'rb').read().hex()))", dest) == b'written through retained cwd'.hex()
        again = self.cli_raw(ep, c, 'sync', 'recovery', 'export', '--id', by['cwd-late']['id'], '--digest', by['cwd-late']['observed_digest'], '--destination', dest)
        assert again['code'] == 1 and json.loads(again['out'])['error'] == 'already_exists', again
        unchanged = ep.cli(c, 'sync', 'recovery', 'list')['records'];assert unchanged == records
        ep.stop(c);ep.start(c);self.until(lambda: bool(ep.status(c).get('native')))
        restarted = ep.cli(c, 'sync', 'recovery', 'list')['records'];assert restarted == records
        ep.run("open(s+'-again','w').close();print('{}')", tag);self.until(lambda: ep.exists(tag + '-again-done'));ep.children[-1]['stopped'] = True;ep.save()
        self.until(lambda: len(ep.cli(c, 'sync', 'recovery', 'list')['records']) == len(records) + 1, 10)
        final = ep.cli(c, 'sync', 'recovery', 'list')['records']
        assert final[:len(records)] == records and final[-1]['observed_digest'] == 'sha256:' + sha(b'HELD DESCRIPTOR CHANGED AFTER RESTART')
        self.record(ep.platform, 'held-fd-cwd-root-exchange-recovery', held=held, status=status, records=records, captured=captured, exported=exported, export_refused=again, after_restart=restarted, changed_after_restart=final[-1])
        ep.stop(c)

    # ---- stale RAM save and readonly root parent (both OSes) ----
    def causality(self, ep):
        c = ep.create('causality');ep.start(c);self.until(lambda: ep.ready(c))
        tag = c['path'] + '/editor';ep.children.append({'creating': tag});ep.save()
        code = """import json,os,sys,time
s=json.loads(sys.argv[1]);ram=open(s['file'],'rb').read();open(s['tag']+'-ready','w').close();deadline=time.monotonic()+60
while not os.path.exists(s['tag']+'-go'):
 assert time.monotonic()<deadline
 time.sleep(.02)
tmp=s['file']+'.editor-save';open(tmp,'wb').write(ram);os.replace(tmp,s['file']);open(s['tag']+'-done','w').write(ram.hex())"""
        pid = ep.run("p=subprocess.Popen(['python3','-c',s['code'],json.dumps(s['args'])],stdout=open(s['tag']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))", {'code': code, 'args': {'file': c['root'] + '/reports/live', 'tag': tag}, 'tag': tag})
        ep.children[-1] = {'pid': pid, 'tag': tag};ep.save();self.until(lambda: ep.exists(tag + '-ready'))
        incoming = (ep.platform + ' accepted while editor held old RAM').encode();shared = self.publish(incoming);self.until(lambda: ep.ready(c, shared['head']), 15)
        prior = {p['operation'] for p in ep.status(c)['status']['submissions']}
        ep.run("open(s+'-go','w').close();print('{}')", tag);self.until(lambda: ep.exists(tag + '-done'));ep.children[-1]['stopped'] = True;ep.save()
        progress = self.until(lambda: next((p for p in ep.status(c)['status']['submissions'] if p['operation'] not in prior), None), 15)
        revisions = {r['revision']: r['descriptor'] for r in ep.cli(c, 'history')['revisions']}
        stale = revisions[progress['local_revision']]
        assert stale['provenance'] == UNKNOWN, stale['provenance']
        self.record(ep.platform, 'stale-ram-save-unknown-causality', progress=progress, provenance=stale['provenance'], parents=stale['parents'], ram_sha256=sha(self.base_body))
        ep.stop(c)
        c = ep.create('readonly-parent');ep.start(c);self.until(lambda: ep.ready(c));before = self.native(ep, c, ['reports/live'])
        ep.run("os.chmod(s,0o555);print('{}')", c['path'])
        try:
            def add(t):t['entries'].append({'path': 'blocked-dir', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}})
            self.publish_tree(add);self.until(lambda: 'readonly_parent' in json.dumps(ep.status(c)['native']['status']), 15)
            status = ep.status(c);after = self.native(ep, c, ['reports/live', 'blocked-dir'])
        finally:ep.run("os.chmod(s,0o700);print('{}')", c['path'])
        assert after['blocked-dir'] is None and after['']['ino'] == before['']['ino'] and after['reports/live'] == before['reports/live']
        self.record(ep.platform, 'readonly-root-parent', status=status, before=before, after=after);ep.stop(c)

    # ---- real owner-process fault barriers: parent/root race and crash recovery ----
    def races(self, ep):
        c = ep.create('root-race');ep.start(c);self.until(lambda: ep.ready(c));ep.stop(c)
        def add(name):
            return lambda t: t['entries'].append({'path': name, 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}})
        shared = self.publish_tree(add('race-dir'));ep.start(c, 'native-root-before-exchange');ep.barrier(c)
        ep.run("r=s['root'];os.rename(r,r+'-moved');os.mkdir(r);open(r+'/unowned','wb').write(b'unowned replacement');print('{}')", {'root': c['root']});ep.release(c)
        # Later scans may report the replaced pathname; the apply result itself is recorded first.
        seen = []
        def observed():
            s = ep.status(c);seen.append(s['native']);return 'bound_root_changed' in json.dumps(s['native']['status'])
        try:self.until(observed, 15)
        finally:self.i.write_json(ep.platform + '-root-race-statuses.json', seen)
        status = ep.status(c);ep.stop(c)
        unowned = ep.run("print(json.dumps(sorted(os.listdir(s))))", c['root']);moved = ep.read(c, '../tree-moved/reports/live')
        assert unowned == ['unowned'] and moved == self.base_body.hex() and not ep.exists(c['root'] + '/race-dir')
        self.record(ep.platform, 'root-replaced-before-exchange', status=status, unowned_listing=unowned, original_preserved=True)
        c = ep.create('root-crash');ep.start(c);self.until(lambda: ep.ready(c));ep.stop(c)
        shared = self.publish_tree(add('crash-dir'));ep.start(c, 'native-root-exchanged');ep.barrier(c);ep.stop(c, kill=True)
        interrupted = self.native(ep, c, ['crash-dir'])
        ep.start(c);self.until(lambda: ep.ready(c, shared['head']), 20);recovered = self.native(ep, c, ['crash-dir']);status = ep.status(c)
        assert recovered['crash-dir']['kind'] == 'dir' and any(d['path'] == '' for d in status['native']['displacements'])
        self.record(ep.platform, 'kill-after-exchange-recovers', interrupted=interrupted, recovered=recovered, status=status);ep.stop(c)

    # ---- macOS NFS live epochs ----
    def nfs(self):
        ep = next(e for e in self.endpoints if e.platform == 'macos')
        m = self.mount(ep, 'nfslive', 'shared-live')
        result = self.nfs_epochs(ep, m)
        self.record('macos', 'nfs-live-epochs', **result)
        self.nfs_structural(ep, m)
        self.nfs_authority(ep, m)
        self.unmount(ep, m)
    def mount(self, ep, name, publication):
        replica = identity('replica')
        code, grant = self.request('POST', self.root + '/grants', body={'delegate': {'replica': replica, 'expires': int(time.time()) + 1800, 'actions': ['read', 'write', 'history', 'integrate'], 'branches': ['main'], 'prefixes': ['']}})
        assert code == 200, grant
        base = Path(ep.base) / name;base.mkdir(mode=0o700);mount = base / 'mnt'
        record = {'path': str(base), 'mount': str(mount), 'credential': grant['credential'], 'replica': replica, 'mounted': False};self.mounts.append(record);self.save_mounts()
        def private(n, v):
            p = base / n;fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:f.write(v if isinstance(v, str) else json.dumps(v))
            return str(p)
        config = {'replica': {'replica': replica, 'authorities': [{'principal': ALICE, 'uid': os.geteuid(), 'gid': os.getegid(), 'primary_group': GROUP, 'groups': [GROUP], 'dac_override': False, 'ownership_transfer': False}], 'content_roots': [str(mount)], 'cache_bytes': 96 * 1024 * 1024}, 'root': str(mount), 'policy': {'included_roots': ['.'], 'excluded_prefixes': []}, 'creation_umask': 18}
        state = str(base / 'state')
        def cli(*a):
            p = subprocess.run([ep.binary, *a], capture_output=True, text=True, timeout=20);assert p.returncode == 0, (a, p.stdout, p.stderr);return json.loads(p.stdout)
        cli('init', '--state', state, '--config', private('config', config))
        profile = private('profile', {'endpoint': 'https://localhost:' + str(self.i.port), 'namespace': NS, 'replica': replica, 'ca_file': private('ca', (self.i.control / 'ca.crt').read_text()), 'token_file': private('token', grant['token']), 'publication_principal': ALICE})
        binding = cli('sync', 'attach', '--state', state, '--profile', profile, '--branch', 'main', '--publication', publication)['binding']
        log = open(base / 'daemon.log', 'w')
        p = subprocess.Popen([ep.binary, 'mount', '--state', state, '--revision', binding['view']['revision'], '--mountpoint', str(mount), '--mode', 'private'], stdout=log, stderr=log, start_new_session=True)
        record.update({'pid': p.pid, 'state': state, 'binding': binding, 'token_file': str(base / 'token')});self.processes.append(p);self.save_mounts()
        self.until(lambda: mounted(mount), 15);record['mounted'] = True;self.save_mounts()
        if publication == 'shared-live':self.until(lambda: self.mstatus(ep, record)['live']['applied'], 15)
        return record
    def save_mounts(self):self.i.write_json('nfs-ownership.json', [{k: v for k, v in m.items() if k != 'binding'} for m in self.mounts])
    def mstatus(self, ep, m):
        p = subprocess.run([ep.binary, 'sync', 'status', '--state', m['state']], capture_output=True, text=True, timeout=20);assert p.returncode == 0, (p.stdout, p.stderr);return json.loads(p.stdout)
    def holder(self, code, args, tag):
        p = subprocess.Popen([sys.executable, '-c', code, json.dumps(args)], stdout=open(tag + '-log', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(p);return p
    def nfs_epochs(self, ep, m):
        mnt = m['mount'];tag = m['path'] + '/held'
        old = Path(mnt, 'reports/live').read_bytes();old_ino = os.stat(Path(mnt, 'reports/live')).st_ino
        code = """import errno,hashlib,json,os,sys,time
s=json.loads(sys.argv[1]);f=s['mount']+'/reports/live';fd=os.open(f,os.O_RDWR);before=os.fstat(fd);old=os.pread(fd,4096,0);os.chdir(s['mount']+'/reports')
open(s['tag']+'-ready','w').close();deadline=time.monotonic()+60
while not os.path.exists(s['tag']+'-go'):
 assert time.monotonic()<deadline
 time.sleep(.02)
row={'old_sha256':hashlib.sha256(old).hexdigest(),'old_size':before.st_size,'old_ino':before.st_ino}
st=os.fstat(fd);row.update(held_size=st.st_size,held_ino=st.st_ino,held_sha256=hashlib.sha256(os.pread(fd,4096,0)).hexdigest())
fresh=open(f,'rb').read();row.update(new_sha256=hashlib.sha256(fresh).hexdigest(),new_ino=os.stat(f).st_ino,cwd_relative_sha256=hashlib.sha256(open('live','rb').read()).hexdigest())
for name,fn in [('write',lambda:os.pwrite(fd,b'stale',0)),('fsync',lambda:os.fsync(fd)),('close',lambda:os.close(fd))]:
 try:fn();row[name+'_errno']=0
 except OSError as e:row[name+'_errno']=e.errno
row['after_stale_write_sha256']=hashlib.sha256(open(f,'rb').read()).hexdigest()
open(s['tag']+'-result','w').write(json.dumps(row))"""
        self.holder(code, {'mount': mnt, 'tag': tag}, tag);self.until(lambda: os.path.exists(tag + '-ready'))
        new = b'accepted remote bytes visible through a fresh NFS lookup';started = time.monotonic();shared = self.publish(new)
        def fresh():
            try:return Path(mnt, 'reports/live').read_bytes() == new
            except OSError:return False
        self.until(fresh, 15);visible = time.monotonic() - started
        self.until(lambda: self.mstatus(ep, m)['live']['applied'] and self.mstatus(ep, m)['status']['binding']['view']['head'] == shared['head'], 15);applied = time.monotonic() - started
        open(tag + '-go', 'w').close();self.until(lambda: os.path.exists(tag + '-result'))
        held = json.loads(Path(tag + '-result').read_text())
        assert held['old_sha256'] == sha(old) and held['held_sha256'] == sha(old) and held['held_size'] == len(old), held
        assert held['new_sha256'] == sha(new) and held['cwd_relative_sha256'] == sha(new) and held['new_ino'] != held['old_ino'], held
        assert errno.ESTALE in (held['write_errno'], held['fsync_errno'], held['close_errno']), held
        assert held['after_stale_write_sha256'] == sha(new), 'a stale write had an effect'
        assert visible <= 15 and applied <= 15
        lines = [l for l in Path(m['path'], 'daemon.log').read_text().splitlines() if l.startswith('live_applied')]
        return {'held': held, 'visible_seconds': visible, 'applied_seconds': applied, 'old_fileid': old_ino, 'live_applied': lines, 'status': self.mstatus(ep, m)['live'], 'estale': errno.ESTALE}
    def nfs_structural(self, ep, m):
        mnt = m['mount'];body = b'nfs structural child'
        def change(t):
            d = {'path': 'nfs-dir', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}}
            t['entries'] += [d, file_entry('nfs-dir/child', d['id'], body)]
        started = time.monotonic();self.publish_tree(change, [body])
        self.until(lambda: os.path.isdir(Path(mnt, 'nfs-dir')) and Path(mnt, 'nfs-dir/child').read_bytes() == body, 15);created = time.monotonic() - started
        tag = m['path'] + '/cwd';code = """import json,os,sys,time
s=json.loads(sys.argv[1]);os.chdir(s['dir']);open(s['tag']+'-ready','w').close();deadline=time.monotonic()+60
while not os.path.exists(s['tag']+'-go'):
 assert time.monotonic()<deadline
 time.sleep(.02)
row={}
for name,fn in [('listdir',lambda:sorted(os.listdir('.'))),('open_child',lambda:open('child','rb').read().hex())]:
 try:row[name]=fn()
 except OSError as e:row[name+'_errno']=e.errno
open(s['tag']+'-result','w').write(json.dumps(row))"""
        self.holder(code, {'dir': mnt + '/nfs-dir', 'tag': tag}, tag);self.until(lambda: os.path.exists(tag + '-ready'))
        replaced = b'replacement directory child'
        def replace(t):
            t['entries'] = [e for e in t['entries'] if not e['path'].startswith('nfs-dir')]
            d = {'path': 'nfs-dir', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}}
            t['entries'] += [d, file_entry('nfs-dir/other', d['id'], replaced)]
            for e in t['entries']:
                if e['path'] == 'reports/live':e['path'] = 'reports/renamed-live'
        started = time.monotonic();shared = self.publish_tree(replace, [replaced])
        self.until(lambda: sorted(os.listdir(Path(mnt, 'nfs-dir'))) == ['other'] and not Path(mnt, 'reports/live').exists() and Path(mnt, 'reports/renamed-live').exists(), 15);replaced_seconds = time.monotonic() - started
        open(tag + '-go', 'w').close();self.until(lambda: os.path.exists(tag + '-result'))
        cwd = json.loads(Path(tag + '-result').read_text())
        assert 'child' not in cwd.get('listdir', []) and cwd.get('open_child') != body.hex(), cwd
        self.until(lambda: self.mstatus(ep, m)['live']['applied'] and self.mstatus(ep, m)['status']['binding']['view']['head'] == shared['head'], 15)
        self.record('macos', 'nfs-structural-and-parent-replacement', created_seconds=created, replaced_seconds=replaced_seconds, old_cwd=cwd, listing=sorted(os.listdir(mnt)))
    def nfs_authority(self, ep, m):
        mnt = m['mount']
        def readable(path):
            try:Path(mnt, path).read_bytes();return 0
            except OSError as e:return e.errno
        def mode(value):
            def change(t):next(e for e in t['entries'] if e['path'] == 'reports/renamed-live')['mode'] = value
            return change
        self.publish_tree(mode(0));self.until(lambda: readable('reports/renamed-live') == errno.EACCES, 15);narrowed = readable('reports/renamed-live')
        self.publish_tree(mode(0o600));self.until(lambda: readable('reports/renamed-live') == 0, 15)
        isolated = self.mount(ep, 'nfsiso', 'isolated');cached = Path(isolated['mount'], 'reports/renamed-live').read_bytes()
        before = self.mstatus(ep, isolated)['live']
        update = b'shared update isolated must not adopt'
        def content(t):
            e = next(e for e in t['entries'] if e['path'] == 'reports/renamed-live');e['content'] = file_entry('x', e['parent'], update)['content']
        shared = self.publish_tree(content, [update]);self.until(lambda: self.mstatus(ep, isolated)['live']['pending_revision'] is not None, 15)
        after = self.mstatus(ep, isolated)['live'];assert after['epoch'] == before['epoch'] and Path(isolated['mount'], 'reports/renamed-live').read_bytes() == cached
        self.until(lambda: Path(mnt, 'reports/renamed-live').read_bytes() == update, 15)
        code, _ = self.request('POST', self.root + '/grants', body={'revoke': isolated['credential']});assert code == 200
        self.until(lambda: readable_in(isolated['mount'], 'reports/renamed-live') == errno.EACCES, 15);revoked = readable_in(isolated['mount'], 'reports/renamed-live')
        code, renewed = self.request('POST', self.root + '/grants', body={'delegate': {'replica': isolated['replica'], 'expires': int(time.time()) + 1800, 'actions': ['read', 'write', 'history', 'integrate'], 'branches': ['main'], 'prefixes': ['']}});assert code == 200
        Path(isolated['token_file']).write_text(renewed['token']);isolated['credential'] = renewed['credential'];self.save_mounts()
        self.until(lambda: readable_in(isolated['mount'], 'reports/renamed-live') == 0, 15)
        self.record('macos', 'nfs-authority-refresh', mode_narrowed_errno=narrowed, isolated_before=before, isolated_after=after, isolated_cached_sha256=sha(cached), revoked_errno=revoked, renewed=True)
        self.unmount(ep, isolated)
    def unmount(self, ep, m):
        p = subprocess.run(['/sbin/umount', m['mount']], capture_output=True, text=True, timeout=10)
        m['umount'] = {'code': p.returncode, 'stderr': p.stderr};assert p.returncode == 0, p.stderr
        self.until(lambda: not mounted(Path(m['mount'])), 10);m['mounted'] = False
        proc = next(p for p in self.processes if p.pid == m['pid']);proc.terminate()
        try:proc.wait(10)
        except subprocess.TimeoutExpired:m['daemon_alive'] = True
        self.save_mounts()
    def cleanup(self):
        for m in self.mounts:
            if m.get('mounted') and mounted(Path(m['mount'])):
                p = subprocess.run(['/sbin/umount', m['mount']], capture_output=True, text=True, timeout=10);m['cleanup_umount'] = p.returncode
                if p.returncode == 0:m['mounted'] = False
        for p in self.processes:
            if p.poll() is None:p.terminate()
        for p in self.processes:
            try:p.wait(10)
            except subprocess.TimeoutExpired:pass
        self.save_mounts();super().cleanup()
        unresolved = [m['mount'] for m in self.mounts if mounted(Path(m['mount']))]
        assert not unresolved, ('owned NFS mounts remain', unresolved)

def mounted(path):
    p = subprocess.run(['/sbin/mount'], capture_output=True, text=True, timeout=3)
    return any(' on ' + str(path) + ' (' in line for line in p.stdout.splitlines())
def readable_in(mount, path):
    try:Path(mount, path).read_bytes();return 0
    except OSError as e:return e.errno

def main():
    ap = argparse.ArgumentParser();ap.add_argument('--output', required=True);ap.add_argument('--platform', choices=['all', 'macos', 'linux'], default='all')
    ap.add_argument('--case', action='append', choices=['core', 'structural', 'recovery', 'causality', 'races', 'nfs'])
    a = ap.parse_args();cases = a.case or ['core', 'structural', 'recovery', 'causality', 'races', 'nfs'];i = OwnedInfra(a.output);j = None;code = 1;evidence = []
    platforms = ['macos', 'linux'] if a.platform == 'all' else [a.platform]
    def record(platform, case, **data):evidence.append({'platform': platform, 'case': case, **data});i.write_json('native-complete-evidence.json', evidence)
    try:
        if sys.platform != 'darwin' or not Path('/sbin/mount_nfs').exists():raise InfrastructureUnavailable('macOS host with /sbin/mount_nfs required')
        i.preflight();source = capture(i)
        i.write_json('toolchain.json', {'rustc': i.run(['rustc', '+stable', '--version', '--verbose']).stdout, 'sw_vers': i.run(['sw_vers']).stdout, 'uname': i.run(['uname', '-a']).stdout})
        if 'core' in cases:
            if 'macos' in platforms:host_matrix(i, record)
            if 'linux' in platforms:linux_matrix(i, record)
        service_cases = [c for c in cases if c != 'core']
        if service_cases:
            image = i.owner + '-native';i.write_json('image-ownership.json', {'tag': image, 'intent': 'retained native test image'})
            i.run(['cargo', '+stable', 'build', '--locked', '-p', 'magus-fs', '--features', 'test-faults'], timeout=600);shutil.copyfile(ROOT / 'target/debug/magus-fs', ROOT / 'target/debug/magus-fs-client-faults');os.chmod(ROOT / 'target/debug/magus-fs-client-faults', 0o755)
            i.run(['cargo', '+stable', 'build', '--locked', '-p', 'magus-fs', '-p', 'magus-fs-service'], timeout=600)
            i.docker('build', '-f', 'tests/fs2/Dockerfile.linux', '--build-arg', 'VERIFY=0', '--label', 'magus.fs2.owner=' + i.owner, '-t', image, '.', timeout=1800)
            i.setup(image);verify_image(i, source)
            i.write_json('native-binaries.json', {n: {'host': hashlib.sha256((ROOT / 'target/debug' / n).read_bytes()).hexdigest(), 'linux': i.docker('exec', i.service, 'sha256sum', '/usr/local/bin/' + n).stdout.split()[0]} for n in ['magus-fs', 'magus-fs-client-faults']})
            j = Complete(i, image, platforms, service_cases);j.record = record;j.run()
        i.write_json('source-after.json', capture(i));code = 0
    except InfrastructureUnavailable as e:i.write_json('failure.json', {'classification': 'blocked', 'reason': str(e)});code = 2
    except Exception as e:i.write_json('failure.json', {'classification': 'failed', 'reason': str(e), 'trace': traceback.format_exc()});traceback.print_exc()
    finally:
        try:
            if j:j.cleanup()
            i.cleanup()
        except Exception as e:i.write_json('cleanup-failure.json', {'reason': str(e), 'trace': traceback.format_exc()});code = 1
        i.write_json('result.json', {'passed': code == 0, 'exit': code, 'scope': 'FS2-B Task 1 native completion', 'platform': a.platform, 'cases': cases, 'evidence_records': len(evidence), 'complete_gate': a.platform == 'all' and not a.case})
    return code
if __name__ == '__main__':sys.exit(main())
