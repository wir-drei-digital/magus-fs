"""Two sandbox containers, independent disk state, exact serialized save evidence."""
import hashlib
import json
import math
import secrets
import statistics
import time
from collections import Counter
from service_protocol import identity, file_entry, GROUP, REPLICA, WORKER
from service_storage import NS, ALICE, object_id


def distribution(rows, key):
    values = sorted(row[key] * 1000 for row in rows)
    return {'n': len(rows), 'p50_ms': statistics.median(values),
            'p95_ms': values[math.ceil(.95 * len(values)) - 1],
            'p99_ms': values[math.ceil(.99 * len(values)) - 1], 'max_ms': max(values),
            'errors': sum(bool(row.get('error') or row.get('timeout')) for row in rows),
            'transient_read_errors': sum(len(row.get('transient_errors', [])) for row in rows),
            'over_500ms': sum(value > 500 for value in values)}


WATCH = '''import errno,hashlib,json,os,sys,time
s=json.loads(sys.argv[1]);body=bytes.fromhex(s['body']);deadline=time.monotonic()+float(s.get('deadline_seconds',25));errors=[];reads=0
open(s['marker']+'-ready','w').write('ready')
while time.monotonic()<deadline:
 try:
  value=open('/shared/b/reports/bench','rb').read();reads+=1
  if value==body:
   row={'fresh_read_ns':time.monotonic_ns(),'sha256':hashlib.sha256(value).hexdigest(),'reads':reads,'transient_errors':errors};break
 except OSError as e:
  errors.append({'errno':e.errno,'monotonic_ns':time.monotonic_ns()})
  if len(errors)==1:open(s['marker']+'-first-error','w').write(json.dumps(errors[0]))
  if e.errno not in [errno.ENOENT,errno.ESTALE,errno.EIO,errno.EACCES]:
   row={'error':'unexpected read errno','errno':e.errno,'transient_errors':errors};break
 time.sleep(.005)
else:row={'timeout':True,'reads':reads,'transient_errors':errors}
open(s['marker']+'-result','w').write(json.dumps(row))
'''
WRITE = '''import json,os,sys,time
s=json.load(sys.stdin);path=s['path'];target=path+'.save' if s['atomic'] else path
start=time.monotonic_ns()
with open(target,'wb') as f:f.write(bytes.fromhex(s['body']));f.flush();os.fsync(f.fileno())
if s['atomic']:os.replace(target,path)
print(json.dumps({'save_started_ns':start,'save_finished_ns':time.monotonic_ns()}))
'''


def acceptance_type(Profile, DiskLazy, TraceMac, infra, image, report, save, validate_receipts):
    class Separate:
        def __init__(self, journey):
            self.i = infra
            self.left = DiskLazy(journey, 'acceptance-sender')
            # Retain partial setup ownership if second creation fails.
            self.right = None
            journey.lazy = self
            self.right = DiskLazy(journey, 'acceptance-receiver')
            assert self.left.daemon != self.right.daemon
            infra.write_json('sandbox-pair.json', {'sender': self.left.daemon, 'receiver': self.right.daemon,
                                                 'uid': 1001, 'gid': 1001, 'disk_state': 'separate owned VM volumes'})

        @property
        def mounts(self):
            return self.left.mounts + (self.right.mounts if self.right else [])

        def endpoint(self, name):
            return self.right if name == 'b' else self.left

        def start(self, name, **kw):
            infra.write_json('sandbox-mount-intent-'+name+'.json', {'container':self.endpoint(name).daemon,'mount':name})
            result = self.endpoint(name).start(name, **kw)
            infra.write_json('sandbox-mount-ownership.json', {label:{'container':endpoint.daemon,'mounts':endpoint.mounts} for label,endpoint in [('sender',self.left),('receiver',self.right)]})
            return result

        def status(self, name):
            return self.endpoint(name).status(name)

        def execute(self, code, settings=None, **kw):
            return self.endpoint(settings if isinstance(settings, str) else '').execute(code, settings, **kw)

        def read(self, path):
            return self.endpoint(path.split('/')[0]).read(path)

        def cleanup(self):
            for label, endpoint in [('sender', self.left), ('receiver', self.right)]:
                if endpoint:
                    endpoint.cleanup()
                    for filename in ['mount-cleanup.json', 'kernel-mount-cleanup.json', 'mount-ownership.json', 'linux-native-commands.json']:
                        path = infra.output / filename
                        if path.exists(): (infra.output / (label + '-' + filename)).write_bytes(path.read_bytes())

    class Acceptance(Profile):
        def background(self, name):
            view, revision = self.view()
            revision['tree']['entries'] = [entry for entry in revision['tree']['entries']
                                          if entry['path'] == 'reports' or entry['path'] == 'reports/bench']
            bodies = []
            if name == '64MiB':
                chunks = [hashlib.sha256(('acceptance background ' + str(n)).encode()).digest() * 8192 for n in range(256)]
                large = file_entry('large', self.tree_root['id'], b'')
                large['content']['version'] = {'size': 64 * 1024 * 1024,
                    'extents': [{'kind': 'chunk', 'object': object_id(body), 'object_size': len(body), 'offset': 0, 'length': len(body)} for body in chunks]}
                revision['tree']['entries'].append(large)
                bodies = chunks
            elif name == '500-files':
                # Ordinary synthetic ICM-like files with distinct bodies/identities.
                for n in range(500):
                    body = (f'# Synthetic note {n}\nOwned latency fixture.\n'.encode() * 20)[:1024]
                    revision['tree']['entries'].append(file_entry(f'note-{n:03d}.md', self.tree_root['id'], body)); bodies.append(body)
            _, receipt = self.candidate(view, revision, 'alice', bodies)
            shared = self.expect('acceptance-' + name, 'POST', self.root + '/integrations', 200,
                                 body=self.integrate_request(receipt, view))
            self.settle(expected_head=shared['head'])
            if name == '64MiB':
                digest = hashlib.sha256(b''.join(bodies)).hexdigest()
                for client in ['a', 'b']:
                    found = self.lazy.execute("import json,hashlib,sys;name=json.load(sys.stdin);print(json.dumps(hashlib.sha256(open('/shared/'+name+'/large','rb').read()).hexdigest()))", client, user='1001:1001')
                    assert found == digest
                report.setdefault('background_hashes', {})[name] = digest
            if name == '500-files':
                expected = [hashlib.sha256(body).hexdigest() for body in bodies]
                for client in ['a', 'b']:
                    found = self.lazy.execute("import hashlib,json,sys;name=json.load(sys.stdin);print(json.dumps([hashlib.sha256(open('/shared/'+name+'/note-%03d.md'%n,'rb').read()).hexdigest() for n in range(500)]))", client, user='1001:1001')
                    assert found == expected, '500-file warm ordinary-read hash mismatch'
                report.setdefault('background_hashes', {})[name] = {'files':500,'sha256':expected,'both_mounted_caches_fully_hydrated':True}
            save()

        def observe(self, body, tag):
            marker = '/tmp/latency-acceptance-' + tag
            endpoint = self.lazy.right
            pid = endpoint.execute("import json,subprocess,sys;code,s=json.load(sys.stdin);p=subprocess.Popen(['python3','-c',code,json.dumps(s)],stdout=open(s['marker']+'-log','w'),stderr=subprocess.STDOUT);print(json.dumps(p.pid))",
                                   [WATCH, {'body': body.hex(), 'marker': marker, 'deadline_seconds':25}], user='1001:1001')
            endpoint.holders.append(pid)
            infra.write_json('receiver-observer-ownership.json', {'container': endpoint.daemon, 'pids': endpoint.holders})
            self.until(lambda: endpoint.execute("import json,os,sys;print(json.dumps(os.path.exists(json.load(sys.stdin)+'-ready')))", marker), 5)
            return marker, pid

        def sample(self, route, pattern, background, number, size, mac=None, client=None):
            before = self.settle(mac, client) if mac else self.settle()
            owner = before['mac'] if mac else before['a']
            prior = {p['operation'] for p in owner['status']['submissions']}
            tag = f'{route}-{pattern}-{background}-{number}'
            body = (hashlib.sha256(tag.encode()).digest() + b'.' * size)[:size]
            marker, pid = self.observe(body, tag)
            attempt = {'route': route, 'pattern': pattern, 'background': background, 'number': number, 'size': size,
                       'before_binding': owner['status']['binding']}
            report.setdefault('raw_attempts', []).append(attempt); save()
            host_start = time.monotonic()
            try:
                settings = {'body': body.hex(), 'atomic': pattern == 'atomic',
                            'path': client['root'] + '/reports/bench' if mac else '/shared/a/reports/bench'}
                written = mac.run(WRITE.replace("s=json.load(sys.stdin);", ""), settings) if mac else self.lazy.left.execute(WRITE, settings, user='1001:1001')
                attempt.update(written)
                endpoint = self.lazy.right
                self.until(lambda: endpoint.execute("import os,json,sys;print(json.dumps(os.path.exists(json.load(sys.stdin)+'-result')))", marker), 27)
                observed = endpoint.execute("import json,sys;print(open(json.load(sys.stdin)+'-result').read())", marker)
                attempt.update(observed)
                assert not observed.get('timeout') and not observed.get('error'), 'ordinary fresh read failed'
                assert observed['sha256'] == hashlib.sha256(body).hexdigest()
                after = self.settle(mac, client) if mac else self.settle()
                final_owner = after['mac'] if mac else after['a']
                submissions = [p for p in final_owner['status']['submissions'] if p['operation'] not in prior]
                assert len(submissions) == 1 and submissions[0]['shared_receipt'], 'exact single save receipt missing'
                progress = submissions[0]
                validate_receipts(progress, owner['status']['binding'], client['replica'] if mac else REPLICA)
                attempt.update(operation=progress['operation'], revision=progress['local_revision'], private_receipt=progress['private_receipt'],
                               shared_receipt=progress['shared_receipt'], request=progress['request'], integration=progress['integration'])
                if mac:
                    head = progress['shared_receipt']['head']; revision = after['b']['status']['binding']['view']['revision']
                    assert after['b']['status']['binding']['view']['head'] == head and after['b']['live']['applied']
                    peer_log = self.lazy.execute("import json;print(json.dumps(open('/private/b/daemon.log').read()))", 'b')
                    service_log = infra.docker('exec', infra.service, 'cat', '/tmp/service.log', evidence=False).stdout
                    def exact(log, stage):
                        return [dict(field.split('=', 1) for field in line.split()[1:]) for line in log.splitlines()
                                if line.startswith('latency ') and f'stage={stage} ' in line and f'head={head}' in line]
                    applied = [e for e in exact(peer_log, 'applied') if e['revision'] == revision]
                    committed = [e for e in exact(service_log, 'shared_committed') if e['operation'] == progress['shared_receipt']['operation']]
                    assert applied and len(committed) == 1, 'native exact Shared/Applied stage binding missing'
                    attempt.update(peer_projected_revision=revision, peer_shared_head=head, applied_events=applied,
                                   committed_events=committed, seconds=time.monotonic() - host_start,
                                   timing='host-observed save through exact receipt/Applied/read upper bound; no host/VM clock subtraction')
                else:
                    attempt.update(self.stages(attempt, progress, after)); attempt['seconds'] = attempt['save_to_exact_applied_and_read']
                attempt['target_pass'] = attempt['seconds'] <= .5
            except Exception as error:
                attempt.update(error=str(error), seconds=time.monotonic() - host_start, target_pass=False)
                report['failures'].append({'workload': tag, 'error': str(error)})
                save()
                # The failed sample remains raw. Unsafe/nonsettled state fails the cohort;
                # successful but slow samples continue and remain in the full distribution.
                raise
            finally:
                if 'seconds' in attempt:
                    rows = [r for r in report['raw_attempts'] if r['route'] == route and r['pattern'] == pattern and r['background'] == background and 'seconds' in r]
                    report['phases'][f'{route}-{pattern}-{background}'] = {'rows': rows, 'distribution': distribution(rows, 'seconds')}
                save()
                if self.lazy.right.execute("import json,os,sys;print(json.dumps(not os.path.exists('/proc/'+str(json.load(sys.stdin)))))", pid):
                    self.lazy.right.holders.remove(pid)
            return attempt

        def run(self):
            report['kind'] = 'final frozen-source acceptance cohort'
            report['sample_requirement'] = '100 per route/save pattern, stratified 34 tiny / 33 64MiB / 33 synthetic500-file'
            infra.start_service(); self.wait()
            authority = {'principal': ALICE, 'uid': 1001, 'gid': 1001, 'primary_group': GROUP, 'groups': [GROUP], 'dac_override': False, 'ownership_transfer': False}
            self.tokens['alice'] = secrets.token_hex(32)
            parent_expiry = int(time.time()) + 7200
            infra.provision([{'namespace': NS, 'principal': ALICE, 'replica': REPLICA, 'token': self.tokens['alice'],
                'expires': parent_expiry, 'actions': ['admin', 'read', 'write', 'integrate', 'history'], 'branches': ['main'],
                'prefixes': [''], 'authority': authority, 'root_policy': self.tree_root}])
            directory = {'path': 'reports', 'id': identity('entry'), 'parent': self.tree_root['id'], 'owner': ALICE, 'group': GROUP, 'mode': 0o755, 'content': {'kind': 'directory'}}
            initial = b'initial acceptance input'
            upload, rid = self.stage(self.descriptor([directory, file_entry('reports/bench', directory['id'], initial)]), bodies=[initial])
            self.expect('acceptance-seed', 'POST', self.root + '/seed', 200, body={'branch': 'main', 'revision': rid, 'upload': upload})
            self.expect('acceptance-parent-preflight', 'GET', self.root + '/changes?branch=main&after=0&limit=128', 200)
            grant = self.expect('acceptance-peer-grant', 'POST', self.root + '/grants', 200, body={'delegate': {'replica': WORKER, 'expires': parent_expiry-3600, 'actions': ['read', 'write', 'history', 'integrate'], 'branches': ['main'], 'prefixes': ['']}})
            self.tokens['worker'] = grant['token']
            self.lazy = Separate(self); self.lazy.start('a'); self.lazy.start('b', actor='worker')
            policies={};profiles={}
            for actor,name,replica in [('alice','a',REPLICA),('worker','b',WORKER)]:
                digest=hashlib.sha256(self.tokens[actor].encode()).hexdigest()
                sql="SELECT json_build_object('replica',c.replica,'principal',c.principal,'expires',extract(epoch FROM c.expires)::bigint,'actions',g.actions,'branches',g.branches,'prefixes',g.prefixes) FROM credentials c JOIN grants g ON g.credential=c.id WHERE c.token_hash='"+digest+"';"
                policy=json.loads(infra.sql(sql));policies[name]=policy
                assert policy['replica']==replica and policy['principal']==ALICE and policy['branches']==['main'] and policy['prefixes']==['']
                assert set(policy['actions'])==({'admin','read','write','integrate','history'} if name=='a' else {'read','write','integrate','history'})
                profile=self.lazy.execute("import json,hashlib,sys;from pathlib import Path;name=json.load(sys.stdin);p=json.loads(Path('/private/'+name+'/profile').read_text());print(json.dumps({'namespace':p['namespace'],'replica':p['replica'],'principal':p['publication_principal'],'token_sha256':hashlib.sha256(Path(p['token_file']).read_bytes()).hexdigest()}))",name)
                assert profile.pop('token_sha256')==digest and profile['namespace']==NS and profile['replica']==replica and profile['principal']==ALICE
                profiles[name]=profile
            assert policies['a']['expires']==parent_expiry and policies['b']['expires']==parent_expiry-3600
            infra.write_json('credential-preflight-audit.json',{'verified':True,'before_timers':True,'actual_profile_tokens_match_chosen_credentials':True,'policies':policies,'profiles':profiles})
            mac = TraceMac(self, 'macos', image); self.endpoints.append(mac)
            for background, count in [('tiny', 34), ('64MiB', 33), ('500-files', 33)]:
                if background != 'tiny': self.background(background)
                client = None
                for route in ['mounted', 'native']:
                    if route == 'native':
                        client = mac.create('acceptance-' + background); mac.start(client); self.until(lambda: mac.ready(client), 60); self.settle(mac, client)
                    for pattern in ['in-place', 'atomic']:
                        rows = []
                        for n in range(count):
                            size = [24, 1024, 16384][n % 3]
                            rows.append(self.sample(route, pattern, background, n, size, mac if route == 'native' else None, client if route == 'native' else None))
                            report['phases'][f'{route}-{pattern}-{background}'] = {'rows': rows, 'distribution': distribution(rows, 'seconds')}; save()
                        print(route, pattern, background, json.dumps(distribution(rows, 'seconds')), flush=True)
                mac.stop(client)
            report['aggregates'] = {}
            for route in ['mounted', 'native']:
                for pattern in ['in-place', 'atomic']:
                    rows = [r for r in report['raw_attempts'] if r['route'] == route and r['pattern'] == pattern]
                    assert len(rows) == 100
                    report['aggregates'][route + '-' + pattern] = {'distribution': distribution(rows, 'seconds'),
                        'sizes': dict(Counter(r['size'] for r in rows)), 'backgrounds': dict(Counter(r['background'] for r in rows)),
                        'p95_target_pass': distribution(rows, 'seconds')['p95_ms'] <= 500}
            report['boundaries'] = 'not-run within timed acceptance; current frozen-source pooled diagnostic runs focused boundaries separately'
            save()
    return Acceptance
