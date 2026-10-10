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
    def set_file(self, path, data, label='api-file', mode=420):
        def mutate(t):
            old = next((e for e in t['entries'] if e['path'] == path), None)
            parent = t['root']['id'] if '/' not in path else next(e['id'] for e in t['entries'] if e['path'] == path.rsplit('/', 1)[0])
            fresh = file_entry(path, parent, data);fresh['mode'] = mode
            if old:old['content'] = fresh['content']
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
        assert missing['error'] == 'absent_alternative', missing
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
        resolved = self.ok(lep, lc, 'sync', 'resolve', '--conflicts', ids, '--expected-head', advanced['head'], '--select', 'candidate')
        progress = resolved['progress'];assert progress['state'] == 'Shared' and progress['resolution']['conflicts'] == ids.split(','), progress
        final = self.head();assert final == progress['shared_receipt']['head']
        view, files, _ = self.tree()
        expect = {p: plan[lep.platform][p] for p in ['reports/notes.txt', 'reports/live', 'reports/new.txt', 'reports/' + lep.platform + '-extra.txt']}
        expect.update({'reports/' + wep.platform + '-extra.txt': plan[wep.platform]['reports/' + wep.platform + '-extra.txt'], 'reports/race-one.txt': b'unrelated advance one', 'reports/race-two.txt': b'unrelated advance two'})
        for path, data in expect.items():assert self.body(view, files[path]) == data, path
        after = self.conflicts('loser');assert all(x['state'] == 'resolved' for x in after if x['id'] in ids.split(',')), after
        # The original alternatives remain addressable and exportable after resolution.
        dest = lc['path'] + '/export-after';self.ok(lep, lc, 'sync', 'conflicts', 'export', '--conflict', text['summary']['id'], '--alternative', next(a['id'] for a in text['alternatives'] if a['side'] == 'candidate'), '--destination', dest)
        assert bytes.fromhex(lep.run("print(json.dumps(open(s,'rb').read().hex()))", dest + '/reports/notes.txt')) == plan[lep.platform]['reports/notes.txt']
        links = self.sql("SELECT count(*) FROM conflict_resolutions WHERE operation='" + progress['resolution']['operation'] + "';");assert links == str(len(mine)), links
        parents = json.loads(self.sql("SELECT convert_from(descriptor,'UTF8') FROM revisions WHERE revision=(SELECT revision FROM branches WHERE name='main');"))['parents']
        assert len(parents) == 2, parents
        # The loser's held state clears and both native folders converge on the resolution.
        status = lep.status(lc);held = next(p for p in status['status']['submissions'] if p['operation'] == loser['operation'])
        assert held['resolved_by']['operation'] == progress['resolution']['operation'], held
        observed = {lep.platform: self.ready_files(lep, lc, expect, final, 25), wep.platform: self.ready_files(wep, wc, expect, final, 25)}
        later = self.set_file('reports/after-resolution.txt', b'incoming resumes', 'after-resolution')
        for ep, c in [(lep, lc), (wep, wc)]:self.ready_files(ep, c, {'reports/after-resolution.txt': b'incoming resumes'}, later['head'], 20)
        for ep, c, _ in clients:ep.stop(c)
        self.record(lep.platform, 'explicit-and-delayed-resolution', stale_cli=stale, raced=raced, recorded_resolutions=recorded, resolution=progress, final_head=final, conflicts_after=after, resolved_link=held['resolved_by'], observed=observed, incoming_after=later)
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
        # (b) The worker's private candidate edits an identity that is then moved out of its
        # scope: integration is denied, the private receipt is retained (re-authorized on read).
        target = self.set_file('reports/move-me.txt', b'move me v0', 'move-seed');view, r = self.view('worker')
        e = next(e for e in r['tree']['entries'] if e['path'] == 'reports/move-me.txt');e['content'] = file_entry('x', e['parent'], b'worker edit before move')['content']
        request, private = self.worker_candidate(copy.deepcopy(view), r, [b'worker edit before move'])
        def move(t):
            e = next(e for e in t['entries'] if e['path'] == 'reports/move-me.txt');e['path'] = 'secret/move-me.txt';e['parent'] = next(x['id'] for x in t['entries'] if x['path'] == 'secret')
        moved = self.publish_tree(move, label='move-out-of-scope')
        stale = self.stage_request(view, copy.deepcopy(r), [b'worker edit before move'])
        self.expect('stale-view-submission-denied', 'POST', self.root + '/candidates', 404, {'code': 'not_found'}, body=stale, actor='worker')
        integration = self.integrate_request(private, {'head': moved['head']})
        self.expect('moved-out-of-scope-denied', 'POST', self.root + '/integrations', 404, {'code': 'not_found'}, body=integration, actor='worker')
        assert self.head() == moved['head'] and self.sql("SELECT count(*) FROM conflicts WHERE integration='" + integration['operation'] + "';") == '0'
        assert self.sql("SELECT count(*) FROM operations WHERE operation='" + integration['operation'] + "';") == '0'
        self.expect('moved-private-current-rights', 'GET', self.op_path(request), 404, actor='worker')
        assert self.sql("SELECT count(*) FROM operations WHERE operation='" + request['operation'] + "' AND kind='candidate';") == '1'
        def back(t):
            e = next(e for e in t['entries'] if e['path'] == 'secret/move-me.txt');e['path'] = 'reports/move-me.txt';e['parent'] = next(x['id'] for x in t['entries'] if x['path'] == 'reports')
        self.publish_tree(back, label='move-back-into-scope')
        self.expect('moved-private-retained', 'GET', self.op_path(request), 200, private, actor='worker')
        # (c) A collision with an entry the worker cannot read is denied without disclosure.
        view, r = self.view('worker');reports = next(e['id'] for e in r['tree']['entries'] if e['path'] == 'reports')
        collide = self.set_file('reports/hidden-x', b'unreadable to the worker', 'hidden-collision', mode=0)
        r['tree']['entries'].append(file_entry('reports/hidden-x', reports, b'worker claim'));request, private = self.worker_candidate(view, r, [b'worker claim'])
        integration = self.integrate_request(private, {'head': collide['head']})
        listed = self.conflicts('worker')
        self.expect('hidden-collision-denied', 'POST', self.root + '/integrations', 404, {'code': 'not_found'}, body=integration, actor='worker')
        assert self.sql("SELECT count(*) FROM conflicts WHERE integration='" + integration['operation'] + "';") == '0' and self.conflicts('worker') == listed
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
