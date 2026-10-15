"""Package boundary tests: removing validation makes these reject cases fail."""
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
try:
 import package
except ImportError:
 package=None

class PackagingTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
 def api(self):
  self.assertIsNotNone(package,'package verification interface is missing')
  return package
 def fixture(self,extra=None):
  p=self.api(); binary=b'\x7fELF'+b'\x02\x01'+bytes(12)+b'\xb7\x00'+bytes(100)
  files={'bin/magus-fs':binary,'LICENSE':b'MIT terms','THIRD_PARTY_NOTICES.md':b'actual notices','fs3-qualification.md':b'runbook'}
  if extra:files.update(extra)
  archive=self.root/'client.tar.gz';p.write_archive(archive,files)
  row={'archive':archive.name,'sha256':p.sha(archive.read_bytes()),'platform':'aarch64-unknown-linux-gnu','binary':'bin/magus-fs','binary_sha256':p.sha(binary),'members':{n:p.sha(b) for n,b in files.items()},'role':'client'}
  source={'Cargo.lock':p.sha(b'locked')}
  manifest={'schema':1,'source':{'head':'a'*40,'manifest':source,'manifest_sha256':p.canonical_sha(source)},'licenses':{n:p.sha(files[n]) for n in ('LICENSE','THIRD_PARTY_NOTICES.md')},'packages':[row]}
  path=self.root/'manifest.json';path.write_text(json.dumps(manifest));return p,path,manifest,row,files
 def test_deterministic_archive(self):
  p,path,m,row,files=self.fixture();second=self.root/'second.tar.gz';p.write_archive(second,dict(reversed(list(files.items()))));self.assertEqual(second.read_bytes(),(self.root/row['archive']).read_bytes())
 def test_clean_prefix_exact_bytes(self):
  p,path,m,row,files=self.fixture();prefix=self.root/'install';p.install(path,row['platform'],'client',prefix);self.assertEqual((prefix/'bin/magus-fs').read_bytes(),files['bin/magus-fs'])
 def reject(self,edit):
  p,path,m,row,files=self.fixture();edit(p,m,row,files);path.write_text(json.dumps(m))
  with self.assertRaises((ValueError,FileExistsError)):p.install(path,row['platform'],'client',self.root/'install')
 def test_checksum_mismatch(self):self.reject(lambda p,m,r,f:r.update(sha256='0'*64))
 def test_source_digest_mismatch(self):self.reject(lambda p,m,r,f:m['source']['manifest'].update({'Cargo.lock':'0'*64}))
 def test_binary_hash_independent(self):self.reject(lambda p,m,r,f:r.update(binary_sha256='0'*64))
 def test_unsupported_architecture(self):self.reject(lambda p,m,r,f:r.update(platform='x86_64-unknown-linux-gnu'))
 def test_missing_notice(self):
  def edit(p,m,r,f):
   del f['THIRD_PARTY_NOTICES.md'];(self.root/r['archive']).unlink();p.write_archive(self.root/r['archive'],f);r['sha256']=p.sha((self.root/r['archive']).read_bytes());r['members'].pop('THIRD_PARTY_NOTICES.md')
  self.reject(edit)
 def test_fault_marker(self):
  def edit(p,m,r,f):
   f[r['binary']]+=b'MAGUS_TEST_TRANSFER_LOG';(self.root/r['archive']).unlink();p.write_archive(self.root/r['archive'],f);r['sha256']=p.sha((self.root/r['archive']).read_bytes());r['binary_sha256']=p.sha(f[r['binary']]);r['members'][r['binary']]=r['binary_sha256']
  self.reject(edit)
 def test_existing_or_interrupted_prefix_never_overwritten(self):
  p,path,m,r,f=self.fixture();prefix=self.root/'interrupted';prefix.mkdir();(prefix/'partial').write_text('retained')
  with self.assertRaises(FileExistsError):p.install(path,r['platform'],'client',prefix)
  p.install(path,r['platform'],'client',self.root/'retry');self.assertEqual((prefix/'partial').read_text(),'retained')
 def test_escape_and_link_entries(self):
  for name,kind in [('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('bin/link',tarfile.SYMTYPE),('bin/hard',tarfile.LNKTYPE)]:
   with self.subTest(name=name):
    p,path,m,r,f=self.fixture()
    with tarfile.open(self.root/r['archive'],'w:gz') as tf:
     t=tarfile.TarInfo(name);t.type=kind;t.linkname='/tmp/outside';tf.addfile(t,io.BytesIO(b''))
    r['sha256']=p.sha((self.root/r['archive']).read_bytes());path.write_text(json.dumps(m))
    with self.assertRaises(ValueError):p.install(path,r['platform'],'client',self.root/'bad')
    (self.root/r['archive']).unlink()
 def test_license_bridge_rejects_dependency_change(self):
  p=self.api();old=b'[package]\nname = "x"\n';self.assertTrue(p.license_only(old,old+b'license = "MIT"\n'));self.assertFalse(p.license_only(old,old+b'license = "MIT"\n[dependencies]\nx="1"\n'))

class RunnerTests(unittest.TestCase):
 def test_missing_or_blocked_provider_never_passes_all(self):
  spec=importlib.util.spec_from_file_location('fs3_runner',ROOT/'tests/fs3/run.py')
  self.assertTrue(Path(spec.origin).exists(),'aggregate runner is missing')
  mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
  phases={p:{'phase':p,'status':'passed','failures':[],'blocked':[]} for p in ('isolation','scale','packaging')}
  self.assertNotEqual(mod.aggregate(phases)['status'],'passed')
  phases['provider']={'phase':'provider','status':'blocked','failures':[],'blocked':['no actual provider']}
  self.assertEqual(mod.aggregate(phases)['status'],'blocked')

if __name__=='__main__':unittest.main()

class PhasePackagingTests(unittest.TestCase):
 def test_claim_without_native_or_service_proof_fails(self):
  from qualification import normalize
  self.assertEqual(normalize({'schema':1,'phase':'packaging','status':'passed','failures':[],'blocked':[],'measurements':{},'cleanup':{'ok':True,'mounts_absent':True,'resources_removed':True,'provenance':['cleanup.json']}})['status'],'failed')

class NativeEvidenceTests(unittest.TestCase):
 def test_native_service_completeness(self):
  path=ROOT/'tests/fs3/packaging.py';self.assertTrue(path.exists(),'native package validator missing')
  spec=importlib.util.spec_from_file_location('fs3_package_phase',path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
  m={'manifest_sha256':'a'*64,'installs':[{'platform':platform,'attempt':attempt,'binary_sha256':'b'*64,'kernel_mounted':True,'read_sha256':'c'*64,'expected_sha256':'c'*64,'write_sha256':'d'*64,'written_sha256':'d'*64,'normal_unmount':True,'owner_stopped':True,'state_preserved':True,'prefix_removed':True,'provenance':'raw.json'} for platform in ('aarch64-apple-darwin','aarch64-unknown-linux-gnu') for attempt in (1,2)],'service':{'default_binary':True,'sha256':'e'*64,'health':200,'stopped':True,'provenance':'service.json'},'interrupted_prefix_retained':True}
  self.assertEqual(mod.validate_packaging(m),[])
  for key in ('kernel_mounted','normal_unmount','owner_stopped','state_preserved'):
   import copy
   bad=copy.deepcopy(m);bad['installs'][0][key]=False;self.assertTrue(mod.validate_packaging(bad),key)
  m['service']['default_binary']=False;self.assertTrue(mod.validate_packaging(m))

class FrozenBuildTests(unittest.TestCase):
 def test_unknown_image_is_not_qualified_by_hash_self_consistency(self):
  self.assertTrue(hasattr(package,'verify_frozen'),'frozen release verification missing')
  with self.assertRaises(ValueError):package.verify_frozen('sha256:'+'0'*64,{}, {})

class HelperImportTests(unittest.TestCase):
 def test_native_helper_import_restores_module_search_path(self):
  import packaging as phase
  self.assertTrue(hasattr(phase,'native_helpers'),'scoped native helper loader missing')
  before=list(sys.path);phase.native_helpers();self.assertEqual(sys.path,before)

class MetadataBridgeTests(unittest.TestCase):
 def test_reviewed_license_metadata_is_allowed_but_dependency_change_is_not(self):
  from common import allowed_source_changes
  old={'Cargo.toml':'39aaeb4f910b372f9529783cd3c9700b5c8b21840247fb9459e7d7b01a3fc7a2'}
  changed={n:{'image':h,'current':hashlib.sha256((ROOT/n).read_bytes()).hexdigest()} for n,h in old.items()}
  self.assertTrue(allowed_source_changes(changed,'same','same'))
  changed['Cargo.toml']['current']='0'*64;self.assertFalse(allowed_source_changes(changed,'same','same'))

class StartupOrderingTests(unittest.TestCase):
 def test_provisioning_finishes_before_service_migrations_start(self):
  import packaging as phase
  from unittest.mock import patch
  self.assertTrue(hasattr(phase,'initialize_service'),'serialized fixture startup missing')
  class Infra:
   started=False
   def provision(self,rows):self.assert_not_started()
   def assert_not_started(self):
    if self.started:raise RuntimeError('concurrent migration startup')
   def start_service(self):self.started=True
  i=Infra()
  class Journey:
   def __init__(self,infra):infra.assert_not_started();self.tokens={'alice':'test-only'};self.tree_root={}
   def wait(self):assert i.started
  with patch('service_protocol.Journey',Journey),patch('scale.owner_record',return_value={'token':'unique-owner'}):
   phase.initialize_service(i,'test-image')
  self.assertTrue(i.started)

class InterruptedWriteTests(unittest.TestCase):
 setUp=PackagingTests.setUp
 api=PackagingTests.api
 fixture=PackagingTests.fixture
 def test_interruption_during_real_extraction_preserves_partial_and_retry(self):
  from unittest.mock import patch
  p,path,m,r,files=self.fixture();prefix=self.root/'interrupted';original=Path.open
  def interrupted(target,*args,**kwargs):
   if target==prefix/'THIRD_PARTY_NOTICES.md':raise InterruptedError('simulated interrupted extraction')
   return original(target,*args,**kwargs)
  with patch.object(Path,'open',interrupted):
   with self.assertRaises(InterruptedError):p.install(path,r['platform'],'client',prefix)
  self.assertEqual((prefix/'LICENSE').read_bytes(),files['LICENSE'])
  with self.assertRaises(FileExistsError):p.install(path,r['platform'],'client',prefix)
  p.install(path,r['platform'],'client',self.root/'fresh');self.assertEqual((self.root/'fresh'/r['binary']).read_bytes(),files[r['binary']])

class CrossClientTests(unittest.TestCase):
 def fixture(self):
  binary=b'\x7fELF\x02\x01'+bytes(12)+b'\x3e\x00'+bytes(100)
  source={'Cargo.lock':'a'*64};licenses={'LICENSE':'b'*64,'THIRD_PARTY_NOTICES.md':'c'*64}
  proof={'exit':0,'platform':'x86_64-unknown-linux-gnu','profile':'release',
   'compiler':'rustc 1.92.0 (verified)','toolchain_image':'sha256:'+'d'*64,
   'source':source,'source_manifest_sha256':package.canonical_sha(source),
   'binary_sha256':package.sha(binary),'licenses':licenses,
   'argv':['cargo','build','--locked','--release','-p','magus-fs','--bin','magus-fs','--target','x86_64-unknown-linux-gnu']}
  return proof,binary,source,licenses
 def test_amd64_client_target_without_new_local_native_requirement(self):
  self.assertEqual(package.PLATFORMS,('aarch64-apple-darwin','aarch64-unknown-linux-gnu'))
  p,b,s,l=self.fixture();package.binary_check(b,p['platform'])
 def test_verified_cross_client(self):
  self.assertTrue(hasattr(package,'verify_client_build'))
  p,b,s,l=self.fixture();package.verify_client_build(p,b,s,l)
 def test_wrong_target_source_binary_notice_and_features_rejected(self):
  self.assertTrue(hasattr(package,'verify_client_build'))
  for key,value in [('platform','aarch64-unknown-linux-gnu'),('source',{}),
      ('binary_sha256','0'*64),('licenses',{}),('argv',['cargo','build','--features','test-faults'])]:
   p,b,s,l=self.fixture();p[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):package.verify_client_build(p,b,s,l)
