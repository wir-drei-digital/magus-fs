"""Native subprocess journeys; no mounts or privileged ownership changes."""
import ctypes
import struct
import time
import hashlib
import http.server
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("MAGUS_FS_BIN", ROOT / "target/debug/magus-fs"))
P = "principal:" + "1" * 32
G = "group:" + "1" * 32

def operation(n):
    return "operation:" + format(n, "032x")

class CLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fs1-task4-", dir="/private/tmp" if os.uname().sysname == "Darwin" else "/tmp")
        self.addCleanup(self.temp.cleanup)
        self.d = Path(self.temp.name)
        self.root = self.d / "tree"
        self.root.mkdir()
        (self.root / "empty").mkdir()
        (self.root / "run").write_bytes(b"#!/bin/sh\nprintf 'hello'\n")
        (self.root / "run").chmod(0o755)
        (self.root / "binary").write_bytes(bytes(range(256))*2400)
        (self.root / "omit").mkdir()
        (self.root / "omit/secret").write_bytes(b"excluded")
        self.state = self.d / "state"
        self.config = self.d / "config.json"
        self.config.write_text(json.dumps({"replica": {"replica": "replica:" + "1"*32, "authorities": [{"principal":P,"uid":os.geteuid(),"primary_group":G,"gid":self.root.stat().st_gid,"groups":[G],"dac_override":False,"ownership_transfer":True}], "content_roots":[str(self.root)], "cache_bytes":32*1024*1024}, "root": str(self.root), "policy": {"included_roots":["."],"excluded_prefixes":["omit"]}, "creation_umask":18}))

    def call(self, command, *args, state=None, code=0, env=None):
        argv = [str(BIN), command, "--state", str(state or self.state), *map(str,args)]
        r = subprocess.run(argv, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode,code,(argv,r.stdout,r.stderr))
        lines=r.stdout.splitlines()
        self.assertEqual(len(lines),1,r.stdout)
        v=json.loads(lines[0])
        self.assertEqual(v["ok"],code==0)
        return v

    def init(self):
        return self.call("init","--config",self.config)

    def capture(self,n=1):
        return self.call("capture","--root",self.root,"--operation-id",operation(n))["revision"]

    def test_native_offline_history_and_materialization(self):
        self.init()
        self.assertEqual(self.call("status")["uncaptured"],"unknown")
        first=self.capture()
        desc=self.call("history")["revisions"][0]["descriptor"]
        self.assertEqual(desc["coverage"],["binary","empty","run"])
        target=self.d/"output"
        self.call("materialize","--revision",first,"--destination",target)
        self.assertTrue((target/"empty").is_dir())
        self.assertFalse((target/"omit").exists())
        for name in ["run","binary"]:
            self.assertEqual(hashlib.sha256((target/name).read_bytes()).hexdigest(),hashlib.sha256((self.root/name).read_bytes()).hexdigest())
            a=(target/name).stat(); b=(self.root/name).stat()
            self.assertEqual(stat.S_IMODE(a.st_mode),stat.S_IMODE(b.st_mode))
            self.assertEqual((a.st_uid,a.st_gid),(b.st_uid,b.st_gid))
        (self.root/"run").write_bytes(b"offline edited\n")
        second=self.capture(2)
        self.assertNotEqual(first,second)
        history=self.call("history")["revisions"]
        self.assertEqual([x["revision"] for x in history],[first,second])
        self.assertEqual(history[1]["descriptor"]["parents"],[first])
        self.call("materialize","--revision",first,"--destination",self.d/"old")
        self.call("materialize","--revision",second,"--destination",self.d/"new")
        self.assertNotEqual((self.d/"old/run").read_bytes(),(self.d/"new/run").read_bytes())
        self.assertEqual(self.call("status")["uncaptured"],"unknown")
        print(json.dumps({"evidence":"native_journey","first":first,"second":second,"sha256":{x:hashlib.sha256((target/x).read_bytes()).hexdigest() for x in ["binary","run"]},"uid":os.geteuid(),"gid":self.root.stat().st_gid}))

    def test_lazy_bootstrap_fetches_zero_bodies(self):
        self.init(); rev=self.capture()
        descriptor=self.call("history")["revisions"][0]["canonical_descriptor"]
        manifest=self.d/"revision.json"; manifest.write_text(descriptor)
        counts=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(inner):
                counts.append(inner.path); inner.send_response(404); inner.end_headers()
            def log_message(self,*args): pass
        server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            source="http://127.0.0.1:"+str(server.server_port)
            self.call("init","--config",self.config,"--revision-manifest",manifest,"--source",source,state=self.d/"lazy")
            status=self.call("status",state=self.d/"lazy")
            self.assertEqual(status["missing_bytes"],352281)
            self.assertEqual(status["ready_mode"],"on_demand")
            self.assertEqual(status["captured_revision"],rev)
            self.assertEqual(counts,[])
        finally:
            server.shutdown();server.server_close();thread.join()
        print(json.dumps({"evidence":"lazy_bootstrap","requests":counts,"missing_bytes":status["missing_bytes"]}))

    def test_materialized_output_recaptures_without_stripping_host_metadata(self):
        lib=ctypes.CDLL(None,use_errno=True)
        original=None
        if os.uname().sysname=="Darwin":
            original=ctypes.create_string_buffer(1024)
            n=lib.getxattr(str(self.root/"run").encode(),b"com.apple.provenance",original,1024,0,0)
            self.assertGreater(n,0)
            original=original.raw[:n]
        self.init(); first=self.capture()
        if original is not None:
            after=ctypes.create_string_buffer(1024)
            n=lib.getxattr(str(self.root/"run").encode(),b"com.apple.provenance",after,1024,0,0)
            self.assertEqual(after.raw[:n],original)
        target=self.d/"roundtrip"
        result=self.call("materialize","--revision",first,"--destination",target)
        native=result["recovery"][-1]["native_metadata"]
        self.assertEqual(result["recovery"][-1]["content_device"],target.stat().st_dev)
        self.assertEqual(result["recovery"][-1]["content_inode"],target.stat().st_ino)
        if os.uname().sysname == "Darwin":
            self.assertTrue(native)
            self.assertTrue(all(x["name"]=="com.apple.provenance" for x in native))
        config=json.loads(self.config.read_text())
        config["root"]=str(target);config["replica"]["content_roots"]=[str(target)]
        second_config=self.d/"second-config.json";second_config.write_text(json.dumps(config))
        self.call("init","--config",second_config,state=self.d/"recapture")
        captured=self.call("capture","--root",target,"--operation-id",operation(20),state=self.d/"recapture")
        self.assertTrue(captured["revision"])
        self.assertEqual((target/"binary").read_bytes(),(self.root/"binary").read_bytes())
        print(json.dumps({"evidence":"ordinary_roundtrip_host_metadata","source":self.call("capture","--root",self.root,"--operation-id",operation(1))["native_metadata"],"destination":native,"source_provenance_preserved":original is not None}))

    def test_unsupported_inventory_and_segment_selection(self):
        self.init();first=self.capture()
        (self.root/"omitted").write_bytes(b"included sibling prefix")
        os.symlink("/does-not-exist",self.root/"symlink")
        os.link(self.root/"run",self.root/"hard")
        os.mkfifo(self.root/"fifo")
        (self.root/"e\u0301").mkdir();os.symlink("outside",self.root/"e\u0301"/"nested-link")
        out=self.call("capture","--root",self.root,"--operation-id",operation(2),code=1)
        self.assertEqual(out["error"],"unsupported_entries")
        for text in ["symlink","hardlink","special_file","non_utf8_non_nfc", "nested-link"]:
            self.assertIn(text,out["details"])
        self.assertEqual(self.call("status")["captured_revision"],first)

    def test_case_collision_refused_even_on_case_sensitive_host(self):
        self.init()
        if os.uname().sysname == "Darwin": return
        (self.root/"CASE").write_bytes(b"a");(self.root/"case").write_bytes(b"b")
        out=self.call("capture","--root",self.root,"--operation-id",operation(1),code=1)
        self.assertEqual(out["error"],"unsupported_entries")
        self.assertIn("case_fold_collision",out["details"])

    def test_arbitrary_xattr_and_extended_acl_inventory(self):
        self.init();self.capture()
        lib=ctypes.CDLL(None,use_errno=True)
        file=str(self.root/"run").encode()
        name=b"user.fs1"; value=b"unsupported"
        if os.uname().sysname=="Darwin":
            rc=lib.setxattr(file,name,value,len(value),0,0)
        else:
            rc=lib.setxattr(file,name,value,len(value),0)
        self.assertEqual(rc,0,ctypes.get_errno())
        out=self.call("capture","--root",self.root,"--operation-id",operation(2),code=1)
        self.assertEqual(out["error"],"unsupported_entries");self.assertIn("user.fs1",out["details"])
        if os.uname().sysname=="Darwin":
            import pwd
            user=pwd.getpwuid(os.geteuid()).pw_name
            r=subprocess.run(["chmod","+a","user:"+user+" deny write",str(self.root/"run")],capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr)
        else:
            acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,uid) for tag,perm,uid in [(1,7,0xffffffff),(2,4,12345),(4,5,0xffffffff),(16,5,0xffffffff),(32,5,0xffffffff)])
            rc=lib.setxattr(file,b"system.posix_acl_access",acl,len(acl),0)
            self.assertEqual(rc,0,ctypes.get_errno())
        out=self.call("capture","--root",self.root,"--operation-id",operation(3),code=1)
        self.assertIn("acl",out["details"])
        print(json.dumps({"evidence":"unsupported_metadata","error":out["error"],"inventory":out["details"]}))

    def test_scan_barriers_and_failed_capture_retry(self):
        if os.environ.get("MAGUS_TEST_FEATURES")!="test-faults":
            env=os.environ.copy();env.update(MAGUS_TEST_FAULT_POINT="capture-hashed",MAGUS_TEST_FAULT_ACTION="EIO")
            self.init();self.call("capture","--root",self.root,"--operation-id",operation(30),env=env)
            return
        self.init();first=self.capture()
        for scenario,point in [("file","capture-observed"),("rename","capture-hashed"),("directory","capture-hashed"),("symlink","capture-observed")]:
            marker=self.d/("marker-"+scenario)
            env=os.environ.copy();env.update(MAGUS_TEST_FAULT_POINT=point,MAGUS_TEST_FAULT_ACTION="barrier",MAGUS_TEST_FAULT_MARKER=str(marker))
            argv=[str(BIN),"capture","--state",str(self.state),"--root",str(self.root),"--operation-id",operation(40+len(scenario))]
            process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
            try:
                for attempt in range(1,4):
                    observed=Path(str(marker)+"."+str(attempt));release=Path(str(observed)+".release")
                    deadline=time.monotonic()+12
                    while not observed.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                    self.assertTrue(observed.exists(),scenario)
                    if scenario=="file":(self.root/"run").write_bytes(("changed"+str(attempt)).encode())
                    elif scenario=="rename":os.rename(self.root/("run" if attempt%2 else "renamed"),self.root/("renamed" if attempt%2 else "run"))
                    elif scenario=="directory":(self.root/("new-dir"+str(attempt))).mkdir()
                    else:
                        os.rename(self.root/"run",self.root/"held-file");os.symlink("held-file",self.root/"run")
                    release.write_text("release")
                    if scenario=="symlink":break
                stdout,stderr=process.communicate(timeout=15)
            finally:
                if process.poll() is None:process.kill();process.communicate()
            self.assertEqual(process.returncode,1,(stdout,stderr))
            self.assertIn(json.loads(stdout)["error"],["unstable_capture","unsupported_entries"])
            self.assertEqual(self.call("status")["captured_revision"],first)
            print(json.dumps({"evidence":"scan_barrier","scenario":scenario,"point":point,"pid":process.pid,"reaped":process.poll() is not None,"result":json.loads(stdout)["error"]}))
            if scenario=="rename":os.rename(self.root/"renamed",self.root/"run")
            if scenario=="symlink":(self.root/"run").unlink();os.rename(self.root/"held-file",self.root/"run")
        env=os.environ.copy();env.update(MAGUS_TEST_FAULT_POINT="db-commit",MAGUS_TEST_FAULT_ACTION="EIO")
        self.call("capture","--root",self.root,"--operation-id",operation(70),code=1,env=env)
        self.assertEqual(self.call("status")["captured_revision"],first)
        retried=self.call("capture","--root",self.root,"--operation-id",operation(70))["revision"]
        self.assertNotEqual(retried,first)
        (self.root/"run").write_bytes(b"another native generation")
        self.assertEqual(self.call("capture","--root",self.root,"--operation-id",operation(70),code=1)["error"],"operation_mismatch")

    def test_checkpoint_and_private_owner_boundary(self):
        self.init();first=self.capture()
        checkpoint=self.call("checkpoint","--operation-id",operation(90),"--expected-generation",1)["revision"]
        self.assertEqual(self.call("checkpoint","--operation-id",operation(90),"--expected-generation",1)["revision"],checkpoint)
        self.assertNotEqual(checkpoint,first)
        self.assertEqual(self.call("history")["revisions"][-1]["descriptor"]["parents"],[first])
        out=self.call("capture","--root",self.root,"--operation-id",operation(91))["revision"]
        self.assertNotEqual(out,checkpoint)
        status=self.call("status");self.assertEqual(status["captured_revision"],out)
        self.assertEqual(status["ready_mode"],"full")
        self.call("init","--config",self.config,"--revision-manifest",self.d/"missing","--source","http://localhost:1234",state=self.d/"hostnames",code=2)
        self.assertFalse((self.d/"hostnames").exists())

    def test_manifest_replacement_cannot_write_an_unowned_file(self):
        if os.environ.get("MAGUS_TEST_FEATURES")!="test-faults":return
        self.init();revision=self.capture()
        marker=self.d/"material-marker";victim=self.d/"unowned-file";victim.write_bytes(b"must remain exact")
        env=os.environ.copy();env.update(MAGUS_TEST_FAULT_POINT="materialize-publish",MAGUS_TEST_FAULT_ACTION="barrier",MAGUS_TEST_FAULT_MARKER=str(marker))
        argv=[str(BIN),"materialize","--state",str(self.state),"--revision",revision,"--destination",str(self.d/"safe-out")]
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        try:
            observed=Path(str(marker)+".1");deadline=time.monotonic()+12
            while not observed.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(observed.exists())
            stage=list(self.d.glob(".magus-stage-*"))[0]
            prepared=json.loads((stage/"ownership.json").read_text())
            self.assertEqual(prepared["status"],"prepared")
            self.assertEqual(prepared["content_inode"],(stage/"content").stat().st_ino)
            (stage/"ownership.json").unlink();os.symlink(victim,stage/"ownership.json")
            Path(str(marker)+".1.release").write_text("release")
            stdout,stderr=process.communicate(timeout=15)
        finally:
            if process.poll() is None:process.kill();process.communicate()
        self.assertEqual(process.returncode,0,(stdout,stderr))
        self.assertEqual(victim.read_bytes(),b"must remain exact")
        self.assertFalse((stage/"ownership.json").is_symlink())
        print(json.dumps({"evidence":"safe_manifest_replacement","pid":process.pid,"reaped":True,"unowned_sha256":hashlib.sha256(victim.read_bytes()).hexdigest()}))

    def test_inherited_staging_acl_blocks_before_hydration(self):
        self.init();self.capture()
        descriptor=self.call("history")["revisions"][0]["canonical_descriptor"]
        manifest=self.d/"acl-revision.json";manifest.write_text(descriptor)
        lazy=self.d/"acl-lazy"
        self.call("init","--config",self.config,"--revision-manifest",manifest,"--source","file://"+str(self.state/"objects"),state=lazy)
        self.assertEqual(self.call("status",state=lazy)["resident_verified_bytes"],0)
        parent=self.d/"acl-target-parent";parent.mkdir()
        if os.uname().sysname=="Darwin":
            import pwd
            user=pwd.getpwuid(os.geteuid()).pw_name
            r=subprocess.run(["chmod","+a","user:"+user+" allow read,write,execute,file_inherit,directory_inherit",str(parent)],capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr)
        else:
            lib=ctypes.CDLL(None,use_errno=True)
            acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,uid) for tag,perm,uid in [(1,7,0xffffffff),(2,4,12345),(4,5,0xffffffff),(16,5,0xffffffff),(32,5,0xffffffff)])
            rc=lib.setxattr(str(parent).encode(),b"system.posix_acl_default",acl,len(acl),0)
            self.assertEqual(rc,0,ctypes.get_errno())
        out=self.call("materialize","--revision",self.call("status",state=lazy)["captured_revision"],"--destination",parent/"out",state=lazy,code=1)
        self.assertEqual(out["error"],"unsupported_entries")
        status=self.call("status",state=lazy)
        self.assertEqual(status["resident_verified_bytes"],0)
        self.assertEqual(status["materializations"][0]["status"],"failed")
        self.assertFalse((parent/"out").exists())
        print(json.dumps({"evidence":"inherited_staging_acl","resident_verified_bytes":status["resident_verified_bytes"],"result":out["error"]}))

    def test_manifest_write_failure_retains_native_ownership_proof(self):
        if os.environ.get("MAGUS_TEST_FEATURES")!="test-faults":return
        self.init();revision=self.capture()
        env=os.environ.copy();env.update(MAGUS_TEST_FAULT_POINT="materialize-manifest",MAGUS_TEST_FAULT_ACTION="EIO")
        self.call("materialize","--revision",revision,"--destination",self.d/"manifest-failed",code=1,env=env)
        recovery=self.call("status")["materializations"]
        self.assertEqual(len(recovery),1)
        self.assertEqual(recovery[0]["status"],"failed")
        self.assertEqual(recovery[0]["error"],"io_error")
        actual=Path(recovery[0]["staging"]).stat()
        self.assertEqual((actual.st_dev,actual.st_ino),(recovery[0]["device"],recovery[0]["inode"]))
        self.assertFalse((self.d/"manifest-failed").exists())
        print(json.dumps({"evidence":"manifest_write_failure","owned_device":actual.st_dev,"owned_inode":actual.st_ino,"recovery_status":recovery[0]["status"]}))

    def test_init_missing_selected_root_creates_no_control_storage(self):
        config=json.loads(self.config.read_text());config["replica"]["content_roots"]=[]
        invalid=self.d/"invalid-config.json";invalid.write_text(json.dumps(config))
        state=self.root/"control"
        out=self.call("init","--config",invalid,state=state,code=2)
        self.assertEqual(out["error"],"config_mismatch")
        self.assertFalse(state.exists())

    def test_staging_inside_selected_content_has_no_side_effects(self):
        self.init();revision=self.capture()
        before=set(os.listdir(self.root))
        out=self.call("materialize","--revision",revision,"--destination",self.root/"nested-copy",code=1)
        self.assertEqual(out["error"],"storage_overlap")
        self.assertEqual(set(os.listdir(self.root)),before)
        self.assertEqual(self.call("status")["materializations"],[])

    def test_failure_json_and_existing_destination(self):
        self.call("init","--config",self.config,"--fault", "EIO",code=2)
        self.init();rev=self.capture()
        self.call("materialize","--revision",rev,"--destination",self.root,code=1)
        self.call("capture","--root",self.root,"--operation-id",operation(1))
        (self.root/"run").write_bytes(b"changed")
        self.assertEqual(self.call("capture","--root",self.root,"--operation-id",operation(1),code=1)["error"],"operation_mismatch")

if __name__ == "__main__": unittest.main()
