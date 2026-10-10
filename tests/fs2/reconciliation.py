#!/usr/bin/env python3
"""FS2-B Task 2 reconciliation gate (exit 0 passed, 1 failed, 2 missing prerequisite).

Real processes only: ordinary-folder native owners on the macOS host and in an owned Linux
container edit ordinary files while the authenticated HTTPS service is down, then reconnect
to PostgreSQL/S3-backed integration. Covers compatible and text merges, text/binary/namespace
conflicts, immutable alternatives and export, explicit and delayed (raced) resolution,
unknown-causality hold and exit (R1/R6/R10), scoped hidden-sibling/move/collision/revocation
negatives, the killable text worker deadline and atomicity across a killed service commit.
"""
import argparse, concurrent.futures, copy, hashlib, json, os, secrets, shutil, sys, time, traceback
from pathlib import Path
from infra import OwnedInfra, InfrastructureUnavailable, ROOT
from provenance import capture, verify_image
from service_protocol import identity, file_entry, canonical, GROUP, REPLICA, WORKER
from service_storage import NS, ALICE, object_id
from full_native import Endpoint, NativeJourney

UNKNOWN = 'native_unknown_causality'
def sha(data): return hashlib.sha256(data).hexdigest()
def lines(*items): return ''.join(i + '\n' for i in items).encode()

class Reconciliation(NativeJourney):
    PHASES = ['merge', 'conflicts', 'unknown', 'scoped', 'worker']
    def __init__(self, i, image, platforms, phases=None):
        super().__init__(i, image, platforms, 'reconciliation');self.faulted = False;self.phases = phases or self.PHASES
    # ---------- shared helpers ----------
    def sql(self, q):return self.i.sql(q)
    def head(self):return self.sql("SELECT head FROM branches WHERE namespace='" + NS + "' AND name='main';")
    def tree(self, actor='alice'):
        view, r = self.view(actor);return view, {e['path']: e for e in r['tree']['entries']}, r
    def body(self, view, entry, actor='alice'):
        out = b''
        for x in entry['content']['version']['extents']:
            status, data = self.bytes_request(self.root + '/views/' + view['view'] + '/objects/' + x['object'], actor=actor)
            assert status == 200, (status, entry['path']);out += data[x['offset']:x['offset'] + x['length']]
        return out
    def bytes_request(self, path, actor='alice'):
        import http.client
        c = http.client.HTTPSConnection('127.0.0.1', self.i.port, context=self.ca, timeout=10)
        try:
            c.request('GET', path, headers={'Authorization': 'Bearer ' + self.tokens.get(actor, actor)});r = c.getresponse();return r.status, r.read()
        finally:c.close()
    def publish_tree(self, mutate, bodies=(), label='api-publish'):
        view, r = self.view();mutate(r['tree']);r['tree']['entries'].sort(key=lambda e: e['path'])
        _, private = self.candidate(view, r, 'alice', list(bodies))
        return self.expect(label, 'POST', self.root + '/integrations', 200, body=self.integrate_request(private, view))
    def set_file(self, path, data, label='api-file', mode=None):
        def mutate(t):
            old = next((e for e in t['entries'] if e['path'] == path), None)
            parent = t['root']['id'] if '/' not in path else next(e['id'] for e in t['entries'] if e['path'] == path.rsplit('/', 1)[0])
            fresh = file_entry(path, parent, data);fresh['mode'] = 420 if mode is None else mode
            if old:
                old['content'] = fresh['content']
                if mode is not None:old['mode'] = mode
            else:t['entries'].append(fresh)
        return self.publish_tree(mutate, [data] if data else [], label)
    def raw(self, ep, c, *args, timeout=40):
        return ep.run("p=subprocess.run([s[0],*s[1]],capture_output=True,text=True,timeout=s[2])\nprint(json.dumps({'code':p.returncode,'out':p.stdout,'err':p.stderr}))", [ep.binary, [*args, '--state', c['state']], timeout])
    def ok(self, ep, c, *args):
        p = self.raw(ep, c, *args);out = json.loads(p['out']);assert p['code'] == 0 and out.get('ok') is not False, (args, p);return out
    def fail(self, ep, c, *args):
        p = self.raw(ep, c, *args);out = json.loads(p['out']);assert p['code'] != 0 and out.get('ok') is False, (args, p);return out
    def subs(self, ep, c):return ep.status(c)['status']['submissions']
    def token(self, ep, c):return ep.run("print(json.dumps(open(s).read().strip()))", c['path'] + '/token')
    def stop_service(self):
        self.i.docker('exec', self.i.service, 'python3', '-c', "import os,signal;pid=int(open('/tmp/service.pid').read());os.kill(pid,signal.SIGKILL)")
        self.until(lambda: self.i.docker('exec', self.i.service, 'python3', '-c', "import os;pid=int(open('/tmp/service.pid').read())\ntry:os.kill(pid,0);print('alive')\nexcept ProcessLookupError:print('gone')", evidence=False).stdout.strip() == 'gone', 10)
    def start_service(self, faults=False):
        port = self.i.port;self.i.start_service(faults);assert self.i.port == port, 'host port must survive a process restart';self.wait();self.faulted = faults
    def conflicts(self, actor='alice'):
        status, page = self.request('GET', self.root + '/conflicts', actor=actor);assert status == 200, (status, page);return page['items']
    def ready_files(self, ep, c, expect, head=None, seconds=20):
        def check():
            if not ep.ready(c, head):return False
            got = ep.run("out={}\nfor p in s['paths']:\n try:out[p]=open(s['root']+'/'+p,'rb').read().hex()\n except FileNotFoundError:out[p]=None\nprint(json.dumps(out))", {'root': c['root'], 'paths': list(expect)})
            return got == {p: (None if v is None else v.hex()) for p, v in expect.items()} and got
        return self.until(check, seconds)

    def run(self):
        self.i.start_service();self.wait()
        authority = {'principal': ALICE, 'uid': 1001, 'gid': 1001, 'primary_group': GROUP, 'groups': [GROUP], 'dac_override': False, 'ownership_transfer': False}
        self.i.provision([{'namespace': NS, 'principal': ALICE, 'replica': REPLICA, 'token': secrets.token_hex(32), 'expires': int(time.time()) + 3600, 'actions': ['admin', 'read', 'write', 'integrate', 'history'], 'branches': ['main'], 'prefixes': [''], 'authority': authority, 'root_policy': self.tree_root,
                           'merge_policy': {'branch': 'main', 'text_extensions': ['txt']}}])
        self.warm_storage()
        reports = {'path': 'reports', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}}
        secret = {'path': 'secret', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}}
        self.notes0 = lines('alpha', 'bravo', 'charlie', 'delta', 'echo')
        seed = [reports, secret, file_entry('reports/live', reports['id'], b'\x00seed binary'), file_entry('reports/notes.txt', reports['id'], self.notes0), file_entry('secret/plan', secret['id'], b'hidden v0')]
        upload, rid = self.stage(self.descriptor(seed), bodies=[b'\x00seed binary', self.notes0, b'hidden v0'])
        self.expect('seed', 'POST', self.root + '/seed', 200, body={'branch': 'main', 'revision': rid, 'upload': upload})
        self.protocol_surface()
        self.endpoints = [Endpoint(self, p, self.image) for p in self.platforms]
        if 'merge' in self.phases:self.compatible_merge()
        if 'conflicts' in self.phases:self.conflict_and_resolution()
        if 'unknown' in self.phases:
            for ep in self.endpoints:self.unknown_causality(ep)
        if 'scoped' in self.phases:self.scoped_negatives()
        if 'worker' in self.phases:self.worker_deadline_and_atomicity()

    def warm_storage(self):
        """A fresh SeaweedFS may allocate its first data volume slowly; the service reports that
        as retryable 503. Retry one owned warm-up object (bounded, recorded) before the seed."""
        upload = self.create('alice');attempts = [];started = time.monotonic()
        while time.monotonic() - started < 60:
            status, body = self.request('PUT', self.root + '/uploads/' + upload + '/objects/' + object_id(b'warm-up'), raw=b'warm-up')
            attempts.append({'seconds': time.monotonic() - started, 'status': status, 'body': body});self.i.write_json('storage-warm-up.json', attempts)
            if status == 200:return
            assert status == 503, attempts
            time.sleep(1)
        raise AssertionError(('storage warm-up', attempts))

    # ---------- protocol surface ----------
    def protocol_surface(self):
        status, health = self.request('GET', '/health');assert status == 200 and health == {'protocol': 'magus-fs/service-v1', 'status': 'ok'}, health
        status, caps = self.request('GET', '/capabilities', actor='0' * 64);assert status == 200 and caps == {'protocol': 'magus-fs/service-v1', 'capabilities': ['collaboration-v1']}, caps
        tables = self.sql("SELECT string_agg(table_name,',' ORDER BY table_name) FROM information_schema.tables WHERE table_name IN ('conflicts','conflict_alternatives','conflict_resolutions','revision_provenance','candidate_causality','branch_merge_policy');")
        assert tables == 'branch_merge_policy,candidate_causality,conflict_alternatives,conflict_resolutions,conflicts,revision_provenance', tables
        assert json.loads(self.sql("SELECT policy FROM branch_merge_policy WHERE branch='main';")) == {'text_extensions': ['txt']}
        self.expect('conflicts-unauthenticated', 'GET', self.root + '/conflicts', 401, actor='0' * 64)
        self.record('service', 'protocol-surface', health=health, capabilities=caps, tables=tables)

    # ---------- S4: disconnected compatible edits merge ----------
    def edit_offline(self, plan):
        """Both owners run; the service is down while ordinary files are saved and captured."""
        clients = []
        for ep in self.endpoints:
            c = ep.create('r' + secrets.token_hex(3));ep.start(c);self.until(lambda: ep.ready(c), 20);clients.append((ep, c, {p['operation'] for p in self.subs(ep, c)}))
        base_head = self.head();self.stop_service()
        for ep, c, _ in clients:
            # One ordinary process saves every file of the round in quick succession.
            ep.run("for p,b in s.items():\n with open(p,'wb') as f:f.write(bytes.fromhex(b));f.flush();os.fsync(f.fileno())\nprint('{}')", {c['root'] + '/' + path: data.hex() for path, data in plan[ep.platform].items()})
        for ep, c, known in clients:
            self.until(lambda: [p for p in self.subs(ep, c) if p['operation'] not in known and p['private_receipt'] is None], 20)
        time.sleep(2.5)
        local = {ep.platform: [p for p in self.subs(ep, c) if p['operation'] not in known] for ep, c, known in clients}
        assert all(p['private_receipt'] is None for v in local.values() for p in v), local
        self.start_service()
        return clients, base_head, local
    def outcome(self, ep, c, known):
        def done():
            new = [p for p in self.subs(ep, c) if p['operation'] not in known]
            return new and all(p['shared_receipt'] or p['error'] == 'conflicted' for p in new) and new
        return self.until(done, 45)
    def compatible_merge(self):
        notes = {'macos': lines('alpha MAC', 'bravo', 'charlie', 'delta', 'echo'), 'linux': lines('alpha', 'bravo', 'charlie', 'delta', 'echo LINUX')}
        plan = {p: {'reports/notes.txt': notes[p], 'reports/' + p + '-only.bin': (p + ' disjoint \x00 bytes').encode()} for p in self.platforms}
        clients, base, local = self.edit_offline(plan)
        results = {ep.platform: self.outcome(ep, c, known) for ep, c, known in clients}
        assert all(p['shared_receipt'] for v in results.values() for p in v), results
        merged = lines('alpha MAC' if 'macos' in self.platforms else 'alpha', 'bravo', 'charlie', 'delta', 'echo LINUX' if 'linux' in self.platforms else 'echo')
        final = self.head();view, files, _ = self.tree()
        assert self.body(view, files['reports/notes.txt']) == merged
        expect = {'reports/notes.txt': merged, **{'reports/' + p + '-only.bin': (p + ' disjoint \x00 bytes').encode() for p in self.platforms}}
        for path, data in expect.items():assert self.body(view, files[path]) == data, path
        observed = {}
        for ep, c, _ in clients:observed[ep.platform] = self.ready_files(ep, c, expect, final, 25);ep.stop(c)
        merges = json.loads(self.sql("SELECT coalesce(json_agg(payload::json),'[]') FROM revision_provenance WHERE kind='merge';"))
        superseded = [p for v in results.values() for p in v if p.get('superseded')]
        if len(self.platforms) == 2:
            assert len(merges) == 1 and superseded, (merges, results)
            m = merges[0];assert m['mechanically_merged'] == [files['reports/notes.txt']['id']], m
            parents = json.loads(self.sql("SELECT convert_from(descriptor,'UTF8') FROM revisions WHERE revision=(SELECT revision FROM branches WHERE name='main');"))['parents']
            assert parents == [m['current'], m['candidate']], (parents, m)
        self.record('both', 'disconnected-compatible-and-text-merge', base_head=base, final_head=final, local_before_reconnect=local, results=results, merges=merges, observed=observed, merged_sha256=sha(merged))

    # ---------- S4: conflicts, alternatives, explicit and delayed resolution ----------
    def conflict_and_resolution(self):
        assert len(self.platforms) == 2, 'conflict round needs two independent native owners'
        plan = {p: {'reports/notes.txt': lines('alpha', 'bravo ' + p.upper(), 'charlie', 'delta', 'echo LINUX'), 'reports/live': (p + ' binary \x00\xff edit').encode(), 'reports/new.txt': (p + ' new file').encode(), 'reports/' + p + '-extra.txt': (p + ' compatible but atomic').encode()} for p in self.platforms}
        # Start from the merged state of the previous round (fresh clients: known causality).
        clients, base, local = self.edit_offline(plan)
        results = {ep.platform: self.outcome(ep, c, known) for ep, c, known in clients}
        losers = [(ep, c, known) for ep, c, known in clients if any(p['error'] == 'conflicted' for p in results[ep.platform])]
        winners = [(ep, c, known) for ep, c, known in clients if all(p['shared_receipt'] for p in results[ep.platform])]
        assert len(losers) == 1 and len(winners) == 1, results
        (lep, lc, lknown), (wep, wc, wknown) = losers[0], winners[0]
        # The newest conflicted record carries the complete offline work (its chain covers any
        # earlier partial capture); resolving it also resolves those unpublished ancestors.
        loser = [p for p in results[lep.platform] if p['error'] == 'conflicted'][-1]
        winner_head = self.head()
        view, files, _ = self.tree()
        # Atomic: none of the conflicting candidate's changes, compatible or not, published.
        assert 'reports/' + lep.platform + '-extra.txt' not in files and self.body(view, files['reports/new.txt']) == plan[wep.platform]['reports/new.txt']
        assert self.body(view, files['reports/live']) == plan[wep.platform]['reports/live']
        assert loser['integration'] and loser['superseded'] and loser['shared_receipt'] is None and loser['private_receipt']
        items = self.ok(lep, lc, 'sync', 'conflicts', 'list')['page']['items']
        mine = [x for x in items if x['receipt'] == loser['private_receipt']['receipt']]
        reasons = sorted(x['reason'] for x in mine)
        assert reasons == ['add_add', 'add_add', 'content', 'text_overlap'] and all(x['state'] == 'open' for x in mine), items
        # The private receipt stays accessible to its owner; replay is stable; digest changes fail.
        token = self.token(lep, lc);self.tokens['loser'] = token
        self.expect('loser-private-receipt', 'GET', self.op_path(loser['request']), 200, loser['private_receipt'], actor='loser')
        stored = json.loads(self.sql("SELECT result FROM operations WHERE operation='" + loser['integration']['operation'] + "';"))
        self.expect('conflicted-integration-replay', 'POST', self.root + '/integrations', 409, stored, body=loser['integration'], actor='loser')
        self.expect('conflicted-integration-digest-change', 'POST', self.root + '/integrations', 409, {'code': 'conflict'}, body=dict(loser['integration'], expected_head=secrets.token_hex(16)), actor='loser')
        assert sorted(stored['conflicts']) == sorted(x['id'] for x in mine), stored
        # Loser's incoming application is blocked; its own bytes are retained in place.
        time.sleep(2);st = ep_status = lep.status(lc);assert 'Ready' not in ep_status['native']['status'] or ep_status['status']['binding']['view']['head'] != winner_head
        assert lep.read(lc, 'reports/live') == plan[lep.platform]['reports/live'].hex()
        # Immutable alternatives: authorized export of base/current/candidate, explicit absence.
        details = {x['id']: self.ok(lep, lc, 'sync', 'conflicts', 'show', '--conflict', x['id'])['conflict'] for x in mine}
        exports = {}
        text = next(d for d in details.values() if d['summary']['reason'] == 'text_overlap')
        for alt in text['alternatives']:
            dest = lc['path'] + '/export-' + alt['side'];out = self.ok(lep, lc, 'sync', 'conflicts', 'export', '--conflict', text['summary']['id'], '--alternative', alt['id'], '--destination', dest)
            got = bytes.fromhex(lep.run("print(json.dumps(open(s,'rb').read().hex()))", dest + '/reports/notes.txt'));exports[alt['side']] = sha(got)
            want = {'base': self.notes0_after_merge(), 'current': plan[wep.platform]['reports/notes.txt'], 'candidate': plan[lep.platform]['reports/notes.txt']}[alt['side']]
            assert got == want, (alt, got)
            assert alt['path'] == 'reports/notes.txt', alt
            assert lep.run("import stat\nprint(json.dumps(stat.S_IMODE(os.stat(s).st_mode)))", dest) == 0o700
        again = self.fail(lep, lc, 'sync', 'conflicts', 'export', '--conflict', text['summary']['id'], '--alternative', text['alternatives'][0]['id'], '--destination', lc['path'] + '/export-base')
        assert again['error'] == 'io_error' or 'exist' in json.dumps(again), again
        addadd = [d for d in details.values() if d['summary']['reason'] == 'add_add']
        absent = next(a for d in addadd for a in d['alternatives'] if a['side'] == 'base')
        assert absent['path'] is None and absent['entry'], absent
        missing = self.fail(lep, lc, 'sync', 'conflicts', 'export', '--conflict', next(d['summary']['id'] for d in addadd if absent in d['alternatives']), '--alternative', absent['id'], '--destination', lc['path'] + '/export-absent')
        # Absent and unauthorized are indistinguishable (I7): a plain not-found.
        assert missing['error'] == 'denied', missing
        # Conflicts are scoped to the namespace/principal: another namespace sees nothing.
        self.expect('conflicts-cross-namespace', 'GET', self.root + '/conflicts', 404, actor='bob')
        partial = {'operation': identity('operation'), 'replica': loser['request']['replica'], 'conflicts': [mine[0]['id']], 'expected_head': winner_head, 'replacement': loser['private_receipt']['receipt']}
        self.expect('incomplete-resolution', 'POST', self.root + '/resolutions', 400, {'code': 'incomplete_resolution'}, body=partial, actor='loser')
        self.record(lep.platform, 'conflicted-candidate-retained-atomically', loser=loser, winner_head=winner_head, conflicts=mine, details=details, export_sha256=exports, integration_replay=stored)
        # Delayed resolution: the head advances before a resolution prepared for it commits.
        ids = ','.join(x['id'] for x in mine);old = winner_head
        race = self.set_file('reports/race-one.txt', b'unrelated advance one', 'race-advance-one')
        stale = self.fail(lep, lc, 'sync', 'resolve', '--conflicts', ids, '--expected-head', old, '--select', 'candidate')
        assert stale['error'] == 'stale_head', stale
        current = self.ok(lep, lc, 'sync', 'conflicts', 'show', '--conflict', mine[0]['id'])['conflict']['expected_head'];assert current == race['head']
        # Commit-time race: pause the decided resolution, advance the head, then release it.
        self.stop_service();self.i.private('pause-resolution', 'pause');self.i.docker('exec', self.i.service, 'rm', '-f', '/tmp/fs2-resolution-barrier');self.start_service(faults=True)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            pending = pool.submit(self.raw, lep, lc, 'sync', 'resolve', '--conflicts', ids, '--expected-head', current, '--select', 'candidate', '--operation-id', identity('operation'))
            self.barrier('resolution')
            advanced = self.set_file('reports/race-two.txt', b'unrelated advance two', 'race-advance-two')
            (self.i.control / 'pause-resolution').unlink()
            raced = json.loads(pending.result()['out'])
        assert raced['ok'] is False and raced['error'] == 'stale_head', raced
        assert self.head() == advanced['head'] and all(x['state'] == 'open' for x in self.conflicts('loser'))
        recorded = self.sql("SELECT status||' '||result FROM operations WHERE kind='resolution' ORDER BY result;")
        self.stop_service();self.start_service()
        # The conflicted owner's own bytes stayed in place while the head advanced twice.
        held_bytes = {p: lep.read(lc, p) for p in ['reports/notes.txt', 'reports/live']}
        assert held_bytes == {p: plan[lep.platform][p].hex() for p in held_bytes}, held_bytes
        assert not any(x['id'] in ids.split(',') for x in self.conflicts('alice')), 'conflicts belong to the receipt-holding replica'
        # I2: content, path and metadata replacement by ordinary local edits, then a
        # per-conflict selection over the whole unpublished chain.
        manual = lines('alpha', 'bravo MANUAL MERGE', 'charlie', 'delta', 'echo LINUX')
        renamed = 'reports/new-' + lep.platform + '.txt'
        known = {p['operation'] for p in self.subs(lep, lc)}
        lep.run("r=s['root']\nwith open(r+'/reports/notes.txt','r+b') as f:\n f.write(bytes.fromhex(s['body']));f.truncate();f.flush();os.fsync(f.fileno())\nos.chmod(r+'/reports/notes.txt',0o600)\nos.rename(r+'/reports/new.txt',r+'/'+s['renamed'])\nprint('{}')", {'root': lc['root'], 'body': manual.hex(), 'renamed': renamed})
        edited = self.until(lambda: next((p for p in self.subs(lep, lc) if p['operation'] not in known and p['error'] == 'conflicted'), None), 45)
        chain = {loser['private_receipt']['receipt'], edited['private_receipt']['receipt']}
        mine = [x for x in self.ok(lep, lc, 'sync', 'conflicts', 'list')['page']['items'] if x['receipt'] in chain and x['state'] == 'open']
        details = {x['id']: self.ok(lep, lc, 'sync', 'conflicts', 'show', '--conflict', x['id'])['conflict'] for x in mine}
        live = [i for i, d in details.items() if any(a['path'] == 'reports/live' for a in d['alternatives'])]
        assert len(live) == 2, details  # the original candidate and the edited one
        # R16: another user narrows the winner's new.txt to mode 0 before the owner resolves,
        # hiding one sibling conflict of the original candidate from the owner.
        _, before_hide, _ = self.tree();winner_new = before_hide['reports/new.txt']['id']
        hidden = next(i for i, d in details.items() if d['summary']['reason'] == 'add_add' and any(a['entry'] == winner_new for a in d['alternatives']))
        cur = next(a['id'] for a in details[hidden]['alternatives'] if a['side'] == 'current');base_alt = next(a['id'] for a in details[hidden]['alternatives'] if a['side'] == 'base')
        self.set_file('reports/new.txt', plan[wep.platform]['reports/new.txt'], 'hide-entry', mode=0)
        assert hidden not in [x['id'] for x in self.ok(lep, lc, 'sync', 'conflicts', 'list')['page']['items']]
        visible = [i for i in details if i != hidden]
        ids = ','.join(visible + [hidden])
        choices = ','.join(i + ':current' for i in live)
        resolved = self.ok(lep, lc, 'sync', 'resolve', '--conflicts', ids, '--expected-head', advanced['head'], '--select', 'candidate', '--choices', choices, '--replacement', edited['local_revision'])
        progress = resolved['progress'];assert progress['state'] == 'Shared' and progress['resolution']['conflicts'] == visible, progress
        assert resolved['hidden'] == [hidden], resolved
        assert self.sql("SELECT superseded FROM conflict_resolutions WHERE conflict='" + hidden + "';") == 't'
        assert self.sql("SELECT count(*) FROM conflict_alternatives WHERE conflict='" + hidden + "';") == '3' 
        assert progress['resolves']['source'] == edited['local_revision']
        final = self.head();assert final == progress['shared_receipt']['head']
        view, files, _ = self.tree()
        expect = {'reports/notes.txt': manual, 'reports/live': plan[wep.platform]['reports/live'], renamed: plan[lep.platform]['reports/new.txt']}
        expect.update({'reports/' + p + '-extra.txt': plan[p]['reports/' + p + '-extra.txt'] for p in self.platforms})
        expect.update({'reports/race-one.txt': b'unrelated advance one', 'reports/race-two.txt': b'unrelated advance two'})
        for path, data in expect.items():assert self.body(view, files[path]) == data, path
        assert files['reports/notes.txt']['mode'] == 0o600, files['reports/notes.txt']
        # The hidden entry stayed at its head value (mode 0, unreadable, so absent from views).
        assert 'reports/new.txt' not in files
        hidden_row = json.loads(self.sql("SELECT convert_from(r.descriptor,'UTF8') FROM revisions r JOIN branches b ON b.revision=r.revision AND b.namespace=r.namespace WHERE b.name='main';"))
        assert [(e['mode'], e['id']) for e in hidden_row['tree']['entries'] if e['path'] == 'reports/new.txt'] == [(0, winner_new)]
        expect['reports/new.txt'] = None
        after = self.conflicts('loser');assert all(x['state'] == 'resolved' for x in after if x['id'] in details), after
        # The original alternatives remain addressable and exportable after resolution.
        dest = lc['path'] + '/export-after';self.ok(lep, lc, 'sync', 'conflicts', 'export', '--conflict', text['summary']['id'], '--alternative', next(a['id'] for a in text['alternatives'] if a['side'] == 'candidate'), '--destination', dest)
        assert bytes.fromhex(lep.run("print(json.dumps(open(s,'rb').read().hex()))", dest + '/reports/notes.txt')) == plan[lep.platform]['reports/notes.txt']
        links = self.sql("SELECT count(*) FROM conflict_resolutions WHERE operation='" + progress['resolution']['operation'] + "';");assert links == str(len(details)), links
        parents = json.loads(self.sql("SELECT convert_from(descriptor,'UTF8') FROM revisions WHERE revision=(SELECT revision FROM branches WHERE name='main');"))['parents']
        assert len(parents) == 3 and parents[1:] == sorted(parents[1:]), parents
        # Every record of the resolved chain is linked; held state clears and both converge.
        status = lep.status(lc);linked = {p['operation']: p.get('resolved_by') for p in status['status']['submissions'] if p['operation'] in (loser['operation'], edited['operation'])}
        assert all(l and l['operation'] == progress['resolution']['operation'] for l in linked.values()), linked
        observed = {lep.platform: self.ready_files(lep, lc, expect, final, 25), wep.platform: self.ready_files(wep, wc, expect, final, 25)}
        modes = {ep.platform: ep.run("import stat\nprint(json.dumps(stat.S_IMODE(os.stat(s).st_mode)))", c['root'] + '/reports/notes.txt') for ep, c in [(lep, lc), (wep, wc)]}
        assert modes == {lep.platform: 0o600, wep.platform: 0o600}, modes
        later = self.set_file('reports/after-resolution.txt', b'incoming resumes', 'after-resolution')
        for ep, c in [(lep, lc), (wep, wc)]:self.ready_files(ep, c, {'reports/after-resolution.txt': b'incoming resumes'}, later['head'], 20)
        for ep, c, _ in clients:ep.stop(c)
        # I6/I7: the hidden conflict stays hidden; unauthorized and absent exports are identical.
        shown = self.fail(lep, lc, 'sync', 'conflicts', 'show', '--conflict', hidden)
        unauthorized = self.fail(lep, lc, 'sync', 'conflicts', 'export', '--conflict', hidden, '--alternative', cur, '--destination', lc['path'] + '/export-hidden-current')
        absent_export = self.fail(lep, lc, 'sync', 'conflicts', 'export', '--conflict', hidden, '--alternative', base_alt, '--destination', lc['path'] + '/export-hidden-base')
        assert shown['error'] == unauthorized['error'] == absent_export['error'] == 'denied', (shown, unauthorized, absent_export)
        self.record(lep.platform, 'explicit-and-delayed-resolution', stale_cli=stale, raced=raced, recorded_resolutions=recorded, held_bytes=held_bytes, edited=edited, choices=choices, resolution=progress, final_head=final, conflicts_after=after, resolved_links=linked, observed=observed, modes=modes, incoming_after=later, hidden_conflict={'id': hidden, 'superseded': True, 'show': shown, 'unauthorized_export': unauthorized, 'absent_export': absent_export})
    def notes0_after_merge(self):
        return lines('alpha MAC', 'bravo', 'charlie', 'delta', 'echo LINUX') if 'merge' in self.phases else self.notes0

    # ---------- R1/R6/R10: unknown causality is held, conflicted, resolved, then released ----------
    def unknown_causality(self, ep):
        c = ep.create('unknown-' + secrets.token_hex(2));ep.start(c);self.until(lambda: ep.ready(c), 20)
        tag = c['path'] + '/editor';ep.children.append({'creating': tag});ep.save()
        code = """import json,os,sys,time
s=json.loads(sys.argv[1]);ram=open(s['file'],'rb').read();open(s['tag']+'-ready','w').close();deadline=time.monotonic()+60
while not os.path.exists(s['tag']+'-go'):
 assert time.monotonic()<deadline
 time.sleep(.02)
tmp=s['file']+'.editor-save';open(tmp,'wb').write(ram);os.replace(tmp,s['file']);open(s['tag']+'-done','w').write(ram.hex())"""
        pid = ep.run("p=subprocess.Popen(['python3','-c',s['code'],json.dumps(s['args'])],stdout=open(s['tag']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))", {'code': code, 'args': {'file': c['root'] + '/reports/live', 'tag': tag}, 'tag': tag})
        ep.children[-1] = {'pid': pid, 'tag': tag};ep.save();self.until(lambda: ep.exists(tag + '-ready'))
        ram = bytes.fromhex(ep.read(c, 'reports/live'))
        incoming = (ep.platform + ' accepted while the editor held old RAM').encode();shared = self.set_file('reports/live', incoming, 'unknown-incoming')
        self.until(lambda: ep.ready(c, shared['head']), 20)
        prior = {p['operation'] for p in self.subs(ep, c)}
        ep.run("open(s+'-go','w').close();print('{}')", tag);self.until(lambda: ep.exists(tag + '-done'));ep.children[-1]['stopped'] = True;ep.save()
        held = self.until(lambda: next((p for p in self.subs(ep, c) if p['operation'] not in prior and p['private_receipt'] and p['error'] == 'unknown_causality'), None), 20)
        revisions = {r['revision']: r['descriptor'] for r in self.ok(ep, c, 'history')['revisions']}
        assert revisions[held['local_revision']]['provenance'] == UNKNOWN
        head = self.head();assert head == shared['head'], 'held candidate must not reach the branch'
        assert self.sql("SELECT unknown FROM candidate_causality WHERE receipt='" + held['private_receipt']['receipt'] + "';") == 't'
        # Explicit integration is retained as an immutable unknown_causality conflict.
        integrated = self.ok(ep, c, 'sync', 'integrate', '--revision', held['local_revision'], '--expected-head', head)['progress']
        assert integrated['state'] == 'Failed' and integrated['error'] == 'conflicted' and self.head() == head, integrated
        items = [x for x in self.ok(ep, c, 'sync', 'conflicts', 'list')['page']['items'] if x['receipt'] == held['private_receipt']['receipt']]
        assert [x['reason'] for x in items] == ['unknown_causality'], items
        detail = self.ok(ep, c, 'sync', 'conflicts', 'show', '--conflict', items[0]['id'])['conflict']
        assert sorted(a['side'] for a in detail['alternatives']) == ['base', 'candidate', 'current'] and all(a['entry'] is None for a in detail['alternatives'])
        # Incoming application stays blocked while the candidate is unresolved.
        blocked_path = 'reports/blocked-' + ep.platform + '.txt'
        blocked = self.set_file(blocked_path, b'blocked while unresolved', 'unknown-blocked')
        time.sleep(3);waiting = ep.status(c)
        assert not ep.exists(c['root'] + '/' + blocked_path) and waiting['status']['binding']['view']['head'] != blocked['head'], waiting
        resolved = self.ok(ep, c, 'sync', 'resolve', '--conflicts', items[0]['id'], '--expected-head', blocked['head'], '--select', 'candidate')['progress']
        assert resolved['state'] == 'Shared', resolved
        link = next(p for p in self.subs(ep, c) if p['operation'] == held['operation'])['resolved_by'];assert link['operation'] == resolved['resolution']['operation']
        self.ready_files(ep, c, {'reports/live': ram, blocked_path: b'blocked while unresolved'}, resolved['shared_receipt']['head'], 25)
        resumed_path = 'reports/resumed-' + ep.platform + '.txt'
        resumed = self.set_file(resumed_path, (ep.platform + ' incoming application resumed').encode(), 'unknown-resumed')
        self.ready_files(ep, c, {resumed_path: (ep.platform + ' incoming application resumed').encode()}, resumed['head'], 20)
        ep.stop(c)
        self.record(ep.platform, 'unknown-causality-hold-conflict-resolve-release', held=held, integrated=integrated, conflict=detail, blocked_status=waiting, resolution=resolved, resolved_link=link, resumed_head=resumed['head'], ram_sha256=sha(ram))

    # ---------- scoped writer negatives (direct service requests) ----------
    def worker_candidate(self, view, r, bodies=(), provenance=None):
        if provenance:r['provenance'] = provenance
        return self.candidate(view, r, 'worker', bodies)
    def scoped_negatives(self):
        code, worker = self.request('POST', self.root + '/grants', body={'delegate': {'replica': WORKER, 'expires': int(time.time()) + 1800, 'actions': ['read', 'write', 'history', 'integrate'], 'branches': ['main'], 'prefixes': ['reports']}})
        assert code == 200;self.tokens['worker'] = worker['token'];self.i.private('worker-token', worker['token'])
        # (a) A stale scoped candidate merges; the hidden sibling changed meanwhile survives.
        view, r = self.view('worker');assert all(not e['path'].startswith('secret') for e in r['tree']['entries'])
        reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        hidden = self.set_file('secret/plan', b'hidden v1 by alice', 'hidden-advance')
        r['tree']['entries'].append(file_entry('reports/worker.txt', reports, b'worker output'));_, private = self.worker_candidate(view, r, [b'worker output'])
        merged = self.expect('scoped-stale-merge', 'POST', self.root + '/integrations', 200, body=self.integrate_request(private, {'head': hidden['head']}), actor='worker')
        av, files, _ = self.tree();assert self.body(av, files['secret/plan']) == b'hidden v1 by alice' and self.body(av, files['reports/worker.txt']) == b'worker output'
        # (I3/R11) A writer WITHOUT `history`: its own stale base still merges disjoint work
        # and retains overlapping work as a conflict; reading the old view stays denied.
        nohist_replica = 'replica:' + f'{7:032x}'
        code, nohist = self.request('POST', self.root + '/grants', body={'delegate': {'replica': nohist_replica, 'expires': int(time.time()) + 1800, 'actions': ['read', 'write', 'integrate'], 'branches': ['main'], 'prefixes': ['reports']}})
        assert code == 200;self.tokens['nohist'] = nohist['token']
        view, r = self.view('nohist');reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        disjoint = self.set_file('reports/nohist-other.txt', b'alice disjoint', 'nohist-disjoint-advance')
        r['tree']['entries'].append(file_entry('reports/nohist.txt', reports, b'nohist offline'))
        request, private = self.submit('nohist', nohist_replica, view, r, [b'nohist offline'])
        self.expect('nohist-old-view-read-denied', 'GET', self.root + '/views/' + view['view'] + '/descriptor', 404, actor='nohist')
        merged_nohist = self.expect('nohist-disjoint-merge', 'POST', self.root + '/integrations', 200, body=self.integrate_request(private, {'head': disjoint['head']}), actor='nohist')
        av, files, _ = self.tree();assert self.body(av, files['reports/nohist.txt']) == b'nohist offline' and self.body(av, files['reports/nohist-other.txt']) == b'alice disjoint'
        view, r = self.view('nohist')
        overlap = self.set_file('reports/nohist.txt', b'alice overlapping edit', 'nohist-overlap-advance')
        e = next(e for e in r['tree']['entries'] if e['path'] == 'reports/nohist.txt');e['content'] = file_entry('x', e['parent'], b'nohist overlapping edit')['content']
        _, private = self.submit('nohist', nohist_replica, view, r, [b'nohist overlapping edit'])
        conflicted = self.expect('nohist-overlap-conflict', 'POST', self.root + '/integrations', 409, body=self.integrate_request(private, {'head': overlap['head']}), actor='nohist')
        assert conflicted['code'] == 'conflicted' and self.head() == overlap['head']
        reasons = [x['reason'] for x in self.conflicts('nohist') if x['id'] in conflicted['conflicts']]
        assert reasons and set(reasons) <= {'text_overlap', 'content'}, reasons
        # (b) R14 / spec P7: stale scoped candidates against others' deletes, moves and renames.
        def setup(paths):
            heads = [self.set_file(p, (p + ' v0').encode(), 'p7-seed') for p in paths]
            return heads[-1]
        def mv(src, dst):
            def mutate(t):
                e = next(e for e in t['entries'] if e['path'] == src);e['path'] = dst
                e['parent'] = next(x['id'] for x in t['entries'] if x['path'] == dst.rsplit('/', 1)[0])
            return mutate
        def rm(path):
            return lambda t: t['entries'].remove(next(e for e in t['entries'] if e['path'] == path))
        def edit(r, path, body):
            e = next(e for e in r['tree']['entries'] if e['path'] == path);e['content'] = file_entry('x', e['parent'], body)['content'];return e
        def shape(conflict, actor='worker'):
            code, d = self.request('GET', self.root + '/conflicts/' + conflict, actor=actor);assert code == 200, (code, d)
            return d, sorted((a['side'], a['path'] is None) for a in d['alternatives'])
        def export(conflict, alternative, actor='worker'):
            return self.request('GET', self.root + '/conflicts/' + conflict + '/alternatives/' + alternative, actor=actor)
        sub = {'path': 'reports/sub', 'id': identity('entry'), 'parent': None, 'owner': ALICE, 'group': GROUP, 'mode': 493, 'content': {'kind': 'directory'}}
        def add_sub(t):
            sub['parent'] = next(e['id'] for e in t['entries'] if e['path'] == 'reports');t['entries'].append(dict(sub))
        self.publish_tree(add_sub, label='p7-subdir')
        setup(['reports/del.txt', 'reports/mv.txt', 'reports/ren.txt', 'reports/sub/child.txt', 'reports/unrelated.txt', 'reports/x2.txt'])
        view, r = self.view('worker')
        # Others: delete one, move one out of scope, rename one, rename the ancestor, delete an unrelated file.
        for label, mutate in [('p7-delete', rm('reports/del.txt')), ('p7-move-out', mv('reports/mv.txt', 'secret/mv.txt')), ('p7-rename', mv('reports/ren.txt', 'reports/ren-alice.txt')),
                              ('p7-ancestor-rename', mv('reports/sub', 'reports/sub2')), ('p7-unrelated-delete', rm('reports/unrelated.txt'))]:
            if label == 'p7-ancestor-rename':
                def mutate(t):
                    d = next(e for e in t['entries'] if e['path'] == 'reports/sub');d['path'] = 'reports/sub2'
                    for e in t['entries']:
                        if e['path'].startswith('reports/sub/'):e['path'] = 'reports/sub2/' + e['path'][len('reports/sub/'):]
            head = self.publish_tree(mutate, label=label)
        outcomes = {}
        for label, change, body in [('edit-vs-delete', lambda r: edit(r, 'reports/del.txt', b'w edit del'), b'w edit del'),
                                    ('edit-vs-move-out', lambda r: edit(r, 'reports/mv.txt', b'w edit mv'), b'w edit mv'),
                                    ('rename-edit-vs-rename', lambda r: (edit(r, 'reports/ren.txt', b'w edit ren').update(path='reports/ren-worker.txt')), b'w edit ren'),
                                    ('child-edit-vs-ancestor-rename', lambda r: edit(r, 'reports/sub/child.txt', b'w edit child'), b'w edit child'),
                                    ('edit-vs-unrelated-delete', lambda r: edit(r, 'reports/x2.txt', b'w edit x2'), b'w edit x2')]:
            rr = copy.deepcopy(r);change(rr)
            _, private = self.worker_candidate(copy.deepcopy(view), rr, [body])  # R14: never denied at submission
            status, body_ = self.request('POST', self.root + '/integrations', actor='worker', body=self.integrate_request(private, {'head': self.head()}))
            outcomes[label] = (status, body_)
        reason = lambda label: [x['reason'] for x in self.conflicts('worker') if x['id'] in outcomes[label][1]['conflicts']]
        assert outcomes['edit-vs-delete'][0] == 409 and reason('edit-vs-delete') == ['edit_delete'], outcomes
        assert outcomes['edit-vs-move-out'][0] == 409 and reason('edit-vs-move-out') == ['edit_delete'], outcomes
        assert outcomes['rename-edit-vs-rename'][0] == 409 and reason('rename-edit-vs-rename') == ['competing_rename'], outcomes
        assert outcomes['child-edit-vs-ancestor-rename'][0] == 200 and outcomes['edit-vs-unrelated-delete'][0] == 200, outcomes
        av, files, _ = self.tree()
        assert self.body(av, files['reports/sub2/child.txt']) == b'w edit child' and self.body(av, files['reports/x2.txt']) == b'w edit x2'
        assert self.body(av, files['secret/mv.txt']) == b'reports/mv.txt v0', 'never written outside the worker scope'
        # Deleted and moved-out-of-scope are presented identically (head side absent).
        deleted, deleted_shape = shape(outcomes['edit-vs-delete'][1]['conflicts'][0])
        moved, moved_shape = shape(outcomes['edit-vs-move-out'][1]['conflicts'][0])
        assert deleted_shape == moved_shape == [('base', False), ('candidate', False), ('current', True)], (deleted, moved)
        cur = lambda d: next(a['id'] for a in d['alternatives'] if a['side'] == 'current')
        assert export(deleted['summary']['id'], cur(deleted)) == export(moved['summary']['id'], cur(moved)) == (404, {'code': 'not_found'})
        # I6: an identity moved out of scope AFTER its conflict was recorded is likewise
        # presented as deleted; for a caller without history both are hidden alike.
        late = {}
        for path in ['reports/late-move.txt', 'reports/late-delete.txt']:
            self.set_file(path, b'late v0', 'late-seed')
        nv, nr = self.view('nohist')
        for path in ['reports/late-move.txt', 'reports/late-delete.txt']:
            self.set_file(path, ('alice ' + path).encode(), 'late-overlap')
            rr = copy.deepcopy(nr);edit(rr, path, ('nohist ' + path).encode())
            _, private = self.submit('nohist', nohist_replica, copy.deepcopy(nv), rr, [('nohist ' + path).encode()])
            code, body_ = self.request('POST', self.root + '/integrations', actor='nohist', body=self.integrate_request(private, {'head': self.head()}))
            assert code == 409, (code, body_);late[path] = body_['conflicts'][0]
        listed = [x['id'] for x in self.conflicts('nohist')];assert all(c in listed for c in late.values())
        self.publish_tree(mv('reports/late-move.txt', 'secret/late-move.txt'), label='late-move-out')
        self.publish_tree(rm('reports/late-delete.txt'), label='late-delete')
        after = [x['id'] for x in self.conflicts('nohist')]
        hidden_late = {p: self.request('GET', self.root + '/conflicts/' + c, actor='nohist') for p, c in late.items()}
        assert not any(c in after for c in late.values()) and all(v == (404, {'code': 'not_found'}) for v in hidden_late.values()), (after, hidden_late)
        # I4: a narrowed submitter whose stale candidate would merge-conflict is denied first.
        self.set_file('reports/n4.txt', b'n4 v0', 'n4-seed');view, r = self.view('worker')
        edit(r, 'reports/n4.txt', b'worker n4 overlap');_, n4_private = self.worker_candidate(copy.deepcopy(view), r, [b'worker n4 overlap'])
        # Overlapping edit plus a narrowed (read-only) mode by the owner after the submission.
        n4 = self.set_file('reports/n4.txt', b'alice n4 overlap', 'n4-overlap-narrow', mode=0o400)
        attempt = self.integrate_request(n4_private, {'head': n4['head']})
        self.expect('i4-merge-conflict-narrowed-denied', 'POST', self.root + '/integrations', 404, {'code': 'not_found'}, body=attempt, actor='worker')
        assert self.sql("SELECT count(*) FROM operations WHERE operation='" + attempt['operation'] + "';") == '0'
        assert self.sql("SELECT count(*) FROM conflicts WHERE integration='" + attempt['operation'] + "';") == '0'
        self.record('service', 'p7-r14-i4-i6', outcomes=outcomes, deleted=deleted, moved=moved, late_hidden=hidden_late)
        # (c) A collision with an entry the worker cannot read is denied without disclosure.
        view, r = self.view('worker');reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        collide = self.set_file('reports/hidden-x', b'unreadable to the worker', 'hidden-collision', mode=0)
        r['tree']['entries'].append(file_entry('reports/hidden-x', reports, b'worker claim'));request, private = self.worker_candidate(view, r, [b'worker claim'])
        integration = self.integrate_request(private, {'head': collide['head']})
        listed = self.conflicts('worker')
        self.expect('hidden-collision-denied', 'POST', self.root + '/integrations', 404, {'code': 'not_found'}, body=integration, actor='worker')
        assert self.sql("SELECT count(*) FROM conflicts WHERE integration='" + integration['operation'] + "';") == '0' and self.conflicts('worker') == listed
        # (I4/R12) Narrowed rights are re-checked before any retained outcome is recorded.
        view, r = self.view('worker');reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        r['tree']['entries'].append(file_entry('reports/r12.txt', reports, b'unknown then narrowed'));_, narrowed_private = self.worker_candidate(view, r, [b'unknown then narrowed'], UNKNOWN)
        def narrow(t):next(e for e in t['entries'] if e['path'] == 'reports')['mode'] = 0o555
        narrowed_head = self.publish_tree(narrow, label='r12-narrow')
        for label, head in [('r12-unknown-denied', narrowed_head['head']), ('r12-stale-denied', view['head'])]:
            attempt = self.integrate_request(narrowed_private, {'head': head})
            self.expect(label, 'POST', self.root + '/integrations', 404, {'code': 'not_found'}, body=attempt, actor='worker')
            assert self.sql("SELECT count(*) FROM operations WHERE operation='" + attempt['operation'] + "';") == '0'
            assert self.sql("SELECT count(*) FROM conflicts WHERE integration='" + attempt['operation'] + "';") == '0'
        def widen(t):next(e for e in t['entries'] if e['path'] == 'reports')['mode'] = 0o755
        self.publish_tree(widen, label='r12-widen')
        # (d) Service-level R1/R6/R10: an unknown-causality candidate is never fast-forwarded.
        view, r = self.view('worker');reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        r['tree']['entries'].append(file_entry('reports/unknown.txt', reports, b'unknown base'));_, private = self.worker_candidate(view, r, [b'unknown base'], UNKNOWN)
        integration = self.integrate_request(private, view)
        body = self.expect('unknown-causality-at-head', 'POST', self.root + '/integrations', 409, body=integration, actor='worker')
        assert body['code'] == 'conflicted' and len(body['conflicts']) == 1 and self.head() == view['head']
        assert [x['reason'] for x in self.conflicts('worker') if x['id'] in body['conflicts']] == ['unknown_causality']
        # Incomplete resolutions and foreign conflicts are rejected.
        unknown_conflict = body['conflicts'][0]
        # (e) Rights narrowed after the replacement candidate: resolution denied, conflict open.
        view, r = self.view('worker');reports_e = next(e for e in r['tree']['entries'] if e['path'] == 'reports')
        r['tree']['entries'].append(file_entry('reports/unknown.txt', reports_e['id'], b'explicit replacement'));_, replacement = self.worker_candidate(view, r, [b'explicit replacement'])
        def narrow(t):next(e for e in t['entries'] if e['path'] == 'reports')['mode'] = 0o555
        narrowed = self.publish_tree(narrow, label='narrow-reports')
        resolution = {'operation': identity('operation'), 'replica': WORKER, 'conflicts': [unknown_conflict], 'expected_head': narrowed['head'], 'replacement': replacement['receipt']}
        self.expect('resolution-stale-replacement', 'POST', self.root + '/resolutions', 409, {'code': 'stale_head'}, body=resolution, actor='worker')
        view, r = self.view('worker');reports_e = next(e for e in r['tree']['entries'] if e['path'] == 'reports')
        r['tree']['entries'].append(file_entry('reports/unknown.txt', reports_e['id'], b'explicit replacement'))
        status, data = self.request('POST', self.root + '/candidates', actor='worker', body=self.stage_request(view, r, [b'explicit replacement']))
        assert status == 404, (status, data)  # current rights deny the replacement itself
        def widen(t):next(e for e in t['entries'] if e['path'] == 'reports')['mode'] = 0o755
        widened = self.publish_tree(widen, label='widen-reports')
        view, r = self.view('worker');reports_e = next(e for e in r['tree']['entries'] if e['path'] == 'reports')
        r['tree']['entries'].append(file_entry('reports/unknown.txt', reports_e['id'], b'explicit replacement'));_, replacement = self.worker_candidate(view, r, [b'explicit replacement'])
        resolution = {'operation': identity('operation'), 'replica': WORKER, 'conflicts': [unknown_conflict], 'expected_head': widened['head'], 'replacement': replacement['receipt']}
        self.expect('resolution-other-credential-replacement', 'POST', self.root + '/resolutions', 404, body=dict(resolution, replica=REPLICA), actor='alice')
        # (I5/R12) Another replica's head-based replacement cannot close these conflicts.
        av, ar = self.view();_, foreign = self.candidate(av, ar, 'alice', [])
        self.expect('resolution-other-replica', 'POST', self.root + '/resolutions', 404, {'code': 'not_found'}, body={'operation': identity('operation'), 'replica': REPLICA, 'conflicts': [unknown_conflict], 'expected_head': av['head'], 'replacement': foreign['receipt']})
        assert unknown_conflict not in [x['id'] for x in self.conflicts('alice')]
        assert [x['state'] for x in self.conflicts('worker') if x['id'] == unknown_conflict] == ['open']
        view, r = self.view('worker');reports_e = next(e for e in r['tree']['entries'] if e['path'] == 'reports')
        r['tree']['entries'].append(file_entry('reports/unknown.txt', reports_e['id'], b'explicit replacement'));_, replacement = self.worker_candidate(view, r, [b'explicit replacement'])
        resolution = {'operation': identity('operation'), 'replica': WORKER, 'conflicts': [unknown_conflict], 'expected_head': view['head'], 'replacement': replacement['receipt']}
        done = self.expect('resolution-explicit', 'POST', self.root + '/resolutions', 200, body=resolution, actor='worker')
        self.expect('resolution-replay', 'POST', self.root + '/resolutions', 200, done, body=resolution, actor='worker')
        self.expect('resolution-digest-change', 'POST', self.root + '/resolutions', 409, {'code': 'conflict'}, body=dict(resolution, expected_head=secrets.token_hex(16)), actor='worker')
        self.expect('resolution-twice', 'POST', self.root + '/resolutions', 409, {'code': 'already_resolved'}, body=dict(resolution, operation=identity('operation')), actor='worker')
        # (f) Revocation between merge decision and commit: nothing published.
        view, r = self.view('worker');reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        advance = self.set_file('reports/revoke-advance.txt', b'advance before revoke', 'revoke-advance')
        r['tree']['entries'].append(file_entry('reports/revoke.txt', reports, b'worker before revoke'));_, private = self.worker_candidate(view, r, [b'worker before revoke'])
        integration = self.integrate_request(private, {'head': advance['head']})
        self.stop_service();self.i.private('pause-integration', 'pause');self.i.docker('exec', self.i.service, 'rm', '-f', '/tmp/fs2-integration-barrier');self.start_service(faults=True)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(self.request, 'POST', self.root + '/integrations', body=integration, actor='worker');self.barrier('integration')
            code, _ = self.request('POST', self.root + '/grants', body={'revoke': worker['credential']});assert code == 200
            (self.i.control / 'pause-integration').unlink();status, data = future.result()
        assert status in (401, 404), (status, data)
        assert self.head() == advance['head'] and self.sql("SELECT count(*) FROM operations WHERE operation='" + integration['operation'] + "';") == '0'
        self.stop_service();self.start_service()
        self.record('service', 'scoped-negatives', hidden_merge=merged, moved=moved, collision=collide, unknown=body, resolution=done, revoked_status=status)
    def submit(self, actor, replica, view, r, bodies):
        r['parents'] = [view['revision']];r['replica'] = replica;r['operation'] = identity('operation')
        upload, rid = self.stage(r, actor, bodies)
        request = {'operation': r['operation'], 'replica': replica, 'original_view': view['view'], 'original_head': view['head'], 'revision': rid, 'upload': upload}
        return request, self.expect('private-' + actor, 'POST', self.root + '/candidates', 200, body=request, actor=actor)
    def stage_request(self, view, r, bodies):
        r['parents'] = [view['revision']];r['replica'] = WORKER;r['operation'] = identity('operation')
        upload, rid = self.stage(r, 'worker', bodies)
        return {'operation': r['operation'], 'replica': WORKER, 'original_view': view['view'], 'original_head': view['head'], 'revision': rid, 'upload': upload}

    # ---------- killable worker deadline and atomic commit across a killed service ----------
    def text_candidate(self, body):
        view, r = self.view();e = next(e for e in r['tree']['entries'] if e['path'] == 'reports/notes.txt')
        e['content'] = file_entry('x', e['parent'], body)['content'];_, private = self.candidate(view, r, 'alice', [body]);return view, private
    def worker_deadline_and_atomicity(self):
        base_view, files, _ = self.tree();base = self.body(base_view, files['reports/notes.txt']);rows = base.decode().splitlines()
        first = lines(*(['FIRST'] + rows[1:]))
        # Both stale candidates share the pre-advance base and edit only the last line.
        view, private = self.text_candidate(lines(*(rows[:-1] + ['LAST'])))
        _, atomic_private = self.text_candidate(lines(*(rows[:-1] + ['LAST AGAIN'])))
        advanced = self.set_file('reports/notes.txt', first, 'text-advance')
        self.stop_service();self.i.private('slow-merge-worker', 'slow');self.start_service(faults=True)
        started = time.monotonic()
        integration = self.integrate_request(private, {'head': advanced['head']})
        body = self.expect('worker-deadline', 'POST', self.root + '/integrations', 409, body=integration)
        seconds = time.monotonic() - started
        assert body['code'] == 'conflicted' and 4.5 < seconds < 20, (body, seconds)
        assert [x['reason'] for x in self.conflicts() if x['id'] in body['conflicts']] == ['merge_budget'] and self.head() == advanced['head']
        workers = int(self.i.docker('exec', self.i.service, 'python3', '-c', "import os\nn=0\nfor p in os.listdir('/proc'):\n try:n+=p.isdigit() and b'merge-worker' in open('/proc/'+p+'/cmdline','rb').read().split(b'\\0')\n except OSError:pass\nprint(n)").stdout.strip())
        assert workers == 0, ('killable worker survived its deadline', workers)
        (self.i.control / 'slow-merge-worker').unlink()
        # Atomicity: the service dies after the merge decision and generated-object install,
        # before the metadata commit. Nothing is published and the same request then completes.
        integration = self.integrate_request(atomic_private, {'head': advanced['head']})
        self.i.private('pause-integration', 'pause');self.i.docker('exec', self.i.service, 'rm', '-f', '/tmp/fs2-integration-barrier')
        before = (self.head(), self.sql("SELECT count(*) FROM revision_provenance;"), self.sql("SELECT count(*) FROM changes;"))
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(self.request, 'POST', self.root + '/integrations', body=integration)
            self.barrier('integration');self.stop_service()
            try:killed = future.result()
            except Exception as e:killed = repr(e)
        (self.i.control / 'pause-integration').unlink()
        after_kill = (self.head(), self.sql("SELECT count(*) FROM revision_provenance;"), self.sql("SELECT count(*) FROM changes;"))
        assert after_kill == before and self.sql("SELECT count(*) FROM operations WHERE operation='" + integration['operation'] + "';") == '0', (before, after_kill)
        merged_text = lines(*(['FIRST'] + rows[1:-1] + ['LAST AGAIN']))
        generated = self.sql("SELECT state FROM objects WHERE object_id='" + object_id(merged_text) + "';")
        assert generated == 'ready', generated  # verified before the commit, unreferenced after the kill
        self.start_service()
        shared = self.expect('atomic-retry', 'POST', self.root + '/integrations', 200, body=integration)
        av, files, _ = self.tree();assert self.body(av, files['reports/notes.txt']) == merged_text
        payload = json.loads(self.sql("SELECT payload FROM revision_provenance WHERE operation='" + integration['operation'] + "';"))
        assert payload['mechanically_merged'] == [files['reports/notes.txt']['id']]
        self.expect('atomic-replay', 'POST', self.root + '/integrations', 200, shared, body=integration)
        self.record('service', 'worker-deadline-and-atomic-commit', deadline_conflict=body, deadline_seconds=seconds, worker_processes_after=workers, killed_response=str(killed), before=before, after_kill=after_kill, generated_object_state_before_commit=generated, retried=shared, merged_sha256=sha(merged_text))

def main():
    ap = argparse.ArgumentParser();ap.add_argument('--output', required=True)
    ap.add_argument('--phase', action='append', choices=Reconciliation.PHASES, help='focused development run; the gate needs all phases');a = ap.parse_args()
    i = OwnedInfra(a.output);j = None;code = 1;evidence = []
    def record(platform, case, **data):evidence.append({'platform': platform, 'case': case, **data});i.write_json('reconciliation-evidence.json', evidence)
    try:
        if sys.platform != 'darwin':raise InfrastructureUnavailable('macOS host required for the native ordinary-folder client')
        i.preflight();source = capture(i)
        i.write_json('toolchain.json', {'rustc': i.run(['rustc', '+stable', '--version', '--verbose']).stdout, 'sw_vers': i.run(['sw_vers']).stdout, 'uname': i.run(['uname', '-a']).stdout})
        image = i.owner + '-reconciliation';i.write_json('image-ownership.json', {'tag': image, 'intent': 'owned reconciliation test image'})
        i.run(['cargo', '+stable', 'build', '--locked', '-p', 'magus-fs', '--features', 'test-faults'], timeout=900);shutil.copyfile(ROOT / 'target/debug/magus-fs', ROOT / 'target/debug/magus-fs-client-faults');os.chmod(ROOT / 'target/debug/magus-fs-client-faults', 0o755)
        i.run(['cargo', '+stable', 'build', '--locked', '-p', 'magus-fs', '-p', 'magus-fs-service'], timeout=900)
        i.docker('build', '-f', 'tests/fs2/Dockerfile.linux', '--build-arg', 'VERIFY=0', '--label', 'magus.fs2.owner=' + i.owner, '-t', image, '.', timeout=2400)
        i.setup(image);verify_image(i, source)
        i.write_json('binaries.json', {'host': {n: hashlib.sha256((ROOT / 'target/debug' / n).read_bytes()).hexdigest() for n in ['magus-fs', 'magus-fs-client-faults']},
                                       'linux': {n: i.docker('exec', i.service, 'sha256sum', '/usr/local/bin/' + n).stdout.split()[0] for n in ['magus-fs', 'magus-fs-client-faults', 'magus-fs-service', 'magus-fs-service-faults']}})
        j = Reconciliation(i, image, ['macos', 'linux'], a.phase);j.record = record;j.run()
        i.write_json('source-after.json', capture(i));code = 0
    except InfrastructureUnavailable as e:i.write_json('failure.json', {'classification': 'blocked', 'reason': str(e)});code = 2
    except Exception as e:
        i.write_json('failure.json', {'classification': 'failed', 'reason': str(e), 'trace': traceback.format_exc()});traceback.print_exc()
        if hasattr(i, 'service'):
            log = i.docker('exec', i.service, 'cat', '/tmp/service.log', check=False, evidence=False);(i.output / 'service.log').write_text(log.stdout + log.stderr)
        # Retain every live owner's state and daemon log for diagnosis before cleanup.
        for ep in (j.endpoints if j else []):
            for c in ep.clients:
                try:i.write_json('failure-' + ep.platform + '-' + Path(c['path']).name + '.json', {'status': ep.status(c), 'log': ep.run("print(json.dumps(open(s,errors='replace').read()[-20000:]))", c['path'] + '/daemon.log')})
                except Exception as error:i.write_json('failure-' + ep.platform + '-' + Path(c.get('path', 'x')).name + '.json', {'error': repr(error)})
    finally:
        errors = []
        for step in ([j.cleanup] if j else []) + [i.cleanup]:
            try:step()
            except Exception as e:errors.append({'reason': str(e), 'trace': traceback.format_exc()})
        if errors:i.write_json('cleanup-failure.json', errors);code = 1
        i.write_json('result.json', {'passed': code == 0, 'exit': code, 'scope': 'FS2-B Task 2 reconciliation', 'phases': a.phase or Reconciliation.PHASES, 'complete_gate': not a.phase, 'evidence_records': len(evidence)})
    print(json.dumps({'exit': code, 'output': str(i.output)}));return code
if __name__ == '__main__':sys.exit(main())
