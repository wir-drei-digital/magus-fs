"""Owned FS3 fixtures and explicit harness-only immutable-image bridge."""
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'tests/fs2'))
from infra import OwnedInfra, InfrastructureUnavailable
from provenance import sources
from latency_acceptance import acceptance_s3_capacity
from connected import Lazy


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class PhaseInfra(OwnedInfra):
    def create(self, kind, suffix, args):
        return super().create(kind, suffix, acceptance_s3_capacity('acceptance', kind, suffix, args))


def allowed_source_changes(changed, old_fixture, new_fixture):
    if any(p != 'tests/fs2/connected.py' and not p.startswith('tests/fs3/') for p in changed):
        return False
    if 'tests/fs2/connected.py' not in changed:
        return old_fixture == new_fixture
    # Exact reviewed optional principal/group/metadata mappings extension only.
    return (hashlib.sha256(old_fixture.encode()).hexdigest(),
            hashlib.sha256(new_fixture.encode()).hexdigest()) == (
                'fdddbd5a673b35491b204b6f154c16920f1b0482398df11f4bfdf88003f2398c',
                '54450c5d94633b77f8185b615a60a58a90eabbd60b0503b0c64c7855d99df433')


def source_bridge(infra, image):
    """Compare actual image sources/binaries, allowing ONLY named harness additions.

    This does not weaken FS2's strict final-image verifier. The old image retains
    its own source tree; host-side FS3 and the optional Lazy identity argument are
    separately recorded inputs. No changed runtime input can use this bridge.
    """
    if not re.fullmatch('sha256:[0-9a-f]{64}', image):
        raise ValueError('immutable image SHA required')
    inspected = infra.inspect('container', infra.service)
    if inspected['Image'] != image:
        raise AssertionError('actual service image differs')
    current = sources()
    script = "import sys,json,hashlib;from pathlib import Path;sys.path.insert(0,'/src/tests/fs2');from provenance import sources;names=['magus-fs','magus-fs-client-faults','magus-fs-service','magus-fs-service-faults','client_probe'];print(json.dumps({'source':sources(),'fixture':Path('/src/tests/fs2/connected.py').read_text(),'binaries':{n:hashlib.sha256((Path('/usr/local/bin')/n).read_bytes()).hexdigest() for n in names}}))"
    actual = json.loads(infra.docker('exec', infra.service, 'python3', '-c', script, evidence=False).stdout)
    changed = {p: {'image': actual['source'].get(p), 'current': current.get(p)}
               for p in sorted(set(current) | set(actual['source'])) if current.get(p) != actual['source'].get(p)}
    if not allowed_source_changes(changed, actual['fixture'], (ROOT/'tests/fs2/connected.py').read_text()):
        raise AssertionError('non-harness image source difference: '+str(changed))
    head = infra.run(['git', 'rev-parse', 'HEAD']).stdout.strip()
    infra.write_json('source-bridge.json', {'head': head, 'current': current, 'image_source': actual['source'],
                     'differences': changed, 'image': image, 'binaries': actual['binaries'],
                     'contract': 'FS3 harness-only bridge; runtime inputs byte-identical'})
    diff = difflib.unified_diff(actual['fixture'].splitlines(True), (ROOT/'tests/fs2/connected.py').read_text().splitlines(True), fromfile='image/tests/fs2/connected.py', tofile='current/tests/fs2/connected.py')
    (infra.output / 'fixture-diff.patch').write_text(''.join(diff))
    return ({'verified': True, 'head': head, 'manifest_sha256': digest(current), 'bridge': 'source-bridge.json'},
            {'verified': True, 'image': image, 'sha256': actual['binaries']})


class RecordedLazy(Lazy):
    """Reuse the real mount implementation; keep per-container evidence files."""
    def __init__(self, journey, suffix):
        self.label = suffix
        super().__init__(journey, suffix)

    def execute(self, code, settings=None, user='0:0', check=True):
        try:
            return super().execute(code, settings, user, check)
        finally:
            self.i.write_json(self.label+'-commands.json', self.commands)

    def cleanup(self):
        super().cleanup()
        for name in ('mount-cleanup.json', 'kernel-mount-cleanup.json'):
            self.i.write_json(self.label+'-'+name, json.loads((self.i.output/name).read_text()))


def restart_retained(endpoint, name, shutdown_seconds=60):
    """Normal unmount, bounded owner exit, then reopen the exact retained journal.

    The fixture shutdown budget covers offline transport cancellation; it does not
    change publication/network deadlines. Already unmounted/exited owned attempts
    can resume without trying to unmount a nonexistent mount.
    """
    return endpoint.execute("""import json,os,sys,time,subprocess,sqlite3
from pathlib import Path
sys.path.insert(0,'/src/tests/fs2');from connected import kernel_mount_present
s=json.load(sys.stdin);control='/private/'+s['name'];mount='/shared/'+s['name'];pid=int(Path(control+'/pid').read_text())
started=time.monotonic();was_mounted=kernel_mount_present(mount,Path('/proc/self/mountinfo').read_text())
if was_mounted:subprocess.run(['fusermount3','-u',mount],check=True)
deadline=started+s['shutdown_seconds']
while Path('/proc/'+str(pid)).exists():
 assert time.monotonic()<deadline,'owned mount owner exit deadline'
 time.sleep(.05)
assert not kernel_mount_present(mount,Path('/proc/self/mountinfo').read_text())
if os.path.exists(mount):os.rmdir(mount)
db=sqlite3.connect(control+'/state/journal.sqlite');working=json.loads(db.execute('SELECT value FROM working').fetchone()[0]);db.close()
log=open(control+'/daemon.log','a');p=subprocess.Popen(['magus-fs','mount','--state',control+'/state','--revision',working['head'],'--mountpoint',mount,'--mode','private'],stdout=log,stderr=log)
Path(control+'/pid').write_text(str(p.pid));deadline=time.monotonic()+10
while not kernel_mount_present(mount,Path('/proc/self/mountinfo').read_text()):
 assert p.poll() is None,(p.poll(),Path(control+'/daemon.log').read_text())
 assert time.monotonic()<deadline,'retained mount startup deadline'
 time.sleep(.05)
print(json.dumps({'old_pid':pid,'pid':p.pid,'normal_unmount_required':was_mounted,'shutdown_seconds':s['shutdown_seconds'],'elapsed_seconds':time.monotonic()-started,'retained_revision':working['head'],'kernel_mounted':True}))""", {'name':name,'shutdown_seconds':shutdown_seconds})


def compose_evidence(earlier, continuation):
    """Validate an explicit failed-run/continuation composition from raw artifacts.

    Only the predecessor's individually passed cases are imported; its failed
    lifecycle result stays immutable. Continuation must own and clean the exact
    resource set. This helper never resumes processes or changes prior results.
    """
    import copy
    from qualification import normalize
    earlier, continuation = Path(earlier), Path(continuation)
    old = json.loads((earlier/'result.json').read_text())
    result = copy.deepcopy(json.loads((continuation/'result.json').read_text()))
    a = json.loads((earlier/'source-bridge.json').read_text())
    b = json.loads((continuation/'source-bridge.json').read_text())
    differences = sorted(p for p in set(a['current']) | set(b['current']) if a['current'].get(p) != b['current'].get(p))
    def resource_ids(rows):
        return sorted((r['kind'],r['name'],r['id']) for r in rows)
    old_owned = json.loads((earlier/'ownership.json').read_text())
    transferred = json.loads((continuation/'ownership-transfer.json').read_text())
    cleaned = json.loads((continuation/'cleanup.json').read_text())
    owned_ok = (old_owned['owner'] == transferred['owner']
                and resource_ids(old_owned['resources']) == resource_ids(transferred['resources']) == resource_ids(cleaned['resources'])
                and cleaned['ok'] is True and all(r.get('removed') is True for r in cleaned['resources']))
    for name in ('a1','a2','b','readonly','peer'):
        absence = json.loads((continuation/(name+'-kernel-mount-cleanup.json')).read_text())
        owned_ok = owned_ok and absence['verified'] is True and not any(absence['remaining'].values())
    for row in result['assertions']:
        row['provenance'] = [str((continuation/p).resolve()) for p in row['provenance']]
        assert all(Path(p).is_file() for p in row['provenance']), 'missing raw assertion artifact'
    composition = result['measurements']['composition']
    composition.update(continuation_result_sha256=hashlib.sha256((continuation/'result.json').read_bytes()).hexdigest(),
        owned_cleanup_verified=owned_ok,
        source_chain={'verified':a['image']==b['image'] and a['binaries']==b['binaries'],
            'earlier_image':a['image'],'earlier_binaries':a['binaries'],'differences':differences,
            'earlier_manifest_sha256':digest(a['current']),'current_manifest_sha256':digest(b['current']),
            'earlier_bridge_sha256':hashlib.sha256((earlier/'source-bridge.json').read_bytes()).hexdigest(),
            'continuation_bridge_sha256':hashlib.sha256((continuation/'source-bridge.json').read_bytes()).hexdigest()})
    assert {r['case'] for r in old['assertions']} == set(composition['unchanged_passed_cases'])
    assert set(composition['remaining_cases']) == {'revoked-reconnect','unaffected-peer'}
    return normalize(result)
