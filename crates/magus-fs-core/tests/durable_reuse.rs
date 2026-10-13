mod support;
use magus_fs_core::*;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};
use support::*;
fn store() -> (tempfile::TempDir, std::path::PathBuf, ObjectStore) {
    let d = scratch();
    let p = d.path().join("objects");
    let s = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    (d, p, s)
}
#[test]
fn unchanged_verified_chunks_skip_staging_but_cross_barriers() {
    let (_d, _p, s) = store();
    let id = s.install(b"abc").unwrap();
    let before = s.work();
    for _ in 0..3 {
        assert_eq!(s.install(b"abc").unwrap(), id);
    }
    let after = s.work();
    assert_eq!(after.stages, before.stages);
    assert_eq!(after.staged_bytes, before.staged_bytes);
    assert_eq!(after.file_syncs - before.file_syncs, 3);
    assert_eq!(after.directory_syncs - before.directory_syncs, 3);
}
#[test]
fn new_chunks_cross_durable_barriers() {
    let (_d, _p, s) = store();
    s.install(b"abc").unwrap();
    let w = s.work();
    assert_eq!(w.stages, 1);
    assert_eq!(w.staged_bytes, 3);
    assert_eq!(w.file_syncs, 1);
    assert_eq!(w.directory_syncs, 2);
}
#[test]
fn changed_identity_or_corruption_cannot_reuse() {
    let (_d, p, s) = store();
    let id = s.install(b"abc").unwrap();
    let path = p.join(id.as_str());
    fs::write(&path, b"xyz").unwrap();
    assert!(matches!(s.install(b"abc"), Err(FsError::CorruptObject)));
    fs::remove_file(&path).unwrap();
    symlink("missing", &path).unwrap();
    assert!(s.install(b"abc").is_err());
    fs::remove_file(&path).unwrap();
    s.install(b"abc").unwrap();
    let before = s.work();
    let old = fs::File::open(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"abc").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(&path).unwrap().ino()
    );
    s.install(b"abc").unwrap();
    assert!(s.work().file_syncs > before.file_syncs);
    fs::write(&path, b"a").unwrap();
    assert!(s.install(b"abc").is_err());
}
#[test]
fn restart_partial_install_uses_slow_path() {
    let (_d, p, s) = store();
    let id = s.install(b"abc").unwrap();
    drop(s);
    fs::write(p.join(".stage-interrupted"), b"partial").unwrap();
    let s = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    s.install(b"abc").unwrap();
    assert!(s.work().file_syncs > 0);
    assert!(s.work().directory_syncs > 0);
    assert_eq!(s.read_verified(&id).unwrap(), b"abc");
    assert_eq!(fs::read(p.join(".stage-interrupted")).unwrap(), b"partial");
}
fn native(
    cache: u64,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Replica,
    CapturePolicy,
) {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    let mut c = config();
    c.cache_bytes = cache;
    c.authorities.truncate(1);
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = fs::metadata(&root).unwrap().gid();
    c.content_roots = vec![root.clone()];
    let r = Replica::open(d.path().join("state"), c).unwrap();
    let p = CapturePolicy {
        included_roots: vec![".".into()],
        excluded_prefixes: vec![],
    };
    r.configure_native(NativeConfig {
        root: root.clone(),
        policy: p.clone(),
        creation_umask: 0o022,
    })
    .unwrap();
    (d, root, r, p)
}
#[test]
fn capture_reuses_content_but_syncs_each_closure_file_with_bounded_inventory() {
    let (_d, root, r, p) = native(32 * 1024 * 1024);
    let mut bytes = vec![];
    for i in 0..8 {
        bytes.extend(vec![i; 262144]);
    }
    fs::write(root.join("big"), bytes).unwrap();
    fs::write(root.join("edit"), b"first").unwrap();
    r.capture(&root, p.clone(), OperationId::random().unwrap(), actor())
        .unwrap();
    let b = r.object_work().unwrap();
    fs::write(root.join("edit"), b"next!").unwrap();
    r.capture(&root, p, OperationId::random().unwrap(), actor())
        .unwrap();
    let a = r.object_work().unwrap();
    assert_eq!(a.stages - b.stages, 1);
    assert_eq!(a.staged_bytes - b.staged_bytes, 5);
    assert_eq!(a.file_syncs - b.file_syncs, 10);
    assert_eq!(a.directory_syncs - b.directory_syncs, 3);
    assert_eq!(a.verified_bytes - b.verified_bytes, 4_194_314);
    assert!(
        a.inventories - b.inventories <= 3,
        "capture rescanned per chunk: {:?} -> {:?}",
        b,
        a
    );
}
#[test]
fn quota_and_gc_preserve_backpressure() {
    let (_d, root, r, p) = native(6);
    fs::write(root.join("a"), b"abc").unwrap();
    r.capture(&root, p.clone(), OperationId::random().unwrap(), actor())
        .unwrap();
    fs::write(root.join("a"), b"abcdefg").unwrap();
    assert!(matches!(
        r.capture(&root, p, OperationId::random().unwrap(), actor()),
        Err(FsError::Backpressure)
    ));
}

#[test]
fn links_keep_verified_barriers_and_unsafe_modes_are_rejected() {
    let (_d, p, s) = store();
    let id = s.install(b"abc").unwrap();
    let path = p.join(id.as_str());
    fs::hard_link(&path, p.join("other-link")).unwrap();
    let before = s.work();
    s.install(b"abc").unwrap();
    assert!(s.work().file_syncs > before.file_syncs);
    let before = s.work();
    s.install(b"abc").unwrap();
    assert!(
        s.work().file_syncs > before.file_syncs,
        "nlink2 still requires verified file barriers"
    );
    fs::remove_file(p.join("other-link")).unwrap();
    s.install(b"abc").unwrap();
    let before = s.work();
    s.install(b"abc").unwrap();
    assert_eq!(s.work().file_syncs - before.file_syncs, 1);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(s.install(b"abc"), Err(FsError::UnsafeStorage)));
}
#[cfg(feature = "test-faults")]
#[test]
fn durability_fault_child() {
    if std::env::var_os("TASK2_DURABILITY_CHILD").is_none() {
        return;
    }
    let (_d, p, s) = store();
    let id = s.install(b"abc").unwrap();
    std::env::set_var("MAGUS_TEST_FAULT_POINT", "object-sync");
    std::env::set_var("MAGUS_TEST_FAULT_ACTION", "EIO");
    assert!(
        s.install(b"abc").is_err(),
        "existing bytes still require a file barrier"
    );
    fs::write(p.join(id.as_str()), b"abc").unwrap();
    assert!(
        s.install(b"abc").is_err(),
        "same-byte truncate/rewrite must not skip a barrier"
    );
    assert!(s.install(b"new").is_err());
    drop(s);
    let s = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    assert!(s.install(b"abc").is_err());
    std::env::remove_var("MAGUS_TEST_FAULT_POINT");
    s.install(b"abc").unwrap();
    assert!(s.work().file_syncs > 0);
}
#[cfg(feature = "test-faults")]
#[test]
fn new_and_reopened_objects_cannot_acknowledge_failed_barriers() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "durability_fault_child", "--nocapture"])
        .env("TASK2_DURABILITY_CHILD", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}
#[cfg(feature = "test-faults")]
#[test]
fn capture_external_child() {
    let Ok(state) = std::env::var("TASK2_CAPTURE_STATE") else {
        return;
    };
    let r = Replica::reopen(state).unwrap();
    let n = r.native_config().unwrap().unwrap();
    let op = OperationId::parse(std::env::var("TASK2_CAPTURE_OP").unwrap()).unwrap();
    let result = r.capture(&n.root, n.policy, op, actor());
    match std::env::var("TASK2_CAPTURE_EXPECT").unwrap().as_str() {
        "quota" => assert!(matches!(result, Err(FsError::Backpressure)), "{result:?}"),
        _ => assert!(result.is_err(), "{result:?}"),
    }
}
#[cfg(feature = "test-faults")]
#[test]
fn external_changes_reconcile_before_capture_acknowledgement() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for change in ["quota", "corrupt", "missing"] {
        let (d, root, r, p) = native(32);
        fs::write(root.join("a"), b"abc").unwrap();
        let base = r
            .capture(&root, p, OperationId::random().unwrap(), actor())
            .unwrap();
        fs::write(root.join("b"), b"def").unwrap();
        drop(r);
        let marker = d.path().join("barrier");
        let op = OperationId::random().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "capture_external_child", "--nocapture"])
            .env("TASK2_CAPTURE_STATE", d.path().join("state"))
            .env("TASK2_CAPTURE_OP", op.as_str())
            .env("TASK2_CAPTURE_EXPECT", change)
            .env("MAGUS_TEST_FAULT_POINT", "capture-hashed")
            .env("MAGUS_TEST_FAULT_ACTION", "barrier")
            .env("MAGUS_TEST_FAULT_MARKER", &marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let ready = marker.with_extension("1");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !ready.exists() {
            child.kill().ok();
            panic!("no barrier: {:?}", child.wait_with_output().unwrap());
        }
        let object = d
            .path()
            .join("state/objects")
            .join(ObjectId::for_bytes(b"abc").unwrap().as_str());
        match change {
            "quota" => {
                let stage = d.path().join("state/objects/.stage-external");
                fs::write(&stage, vec![0; 33]).unwrap();
                fs::set_permissions(stage, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "corrupt" => fs::write(object, b"xyz").unwrap(),
            _ => fs::remove_file(object).unwrap(),
        }
        fs::write(marker.with_extension("1.release"), b"").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{change}: {output:?}");
        // Direct journal inspection avoids falsely claiming deep status can succeed with corrupt bytes.
        let db = rusqlite::Connection::open(d.path().join("state/journal.sqlite")).unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM operations WHERE operation=?",
                [op.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "failed");
        let result: Option<String> = db
            .query_row(
                "SELECT result FROM operations WHERE operation=?",
                [op.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(result.is_none());
        let working: Vec<u8> = db
            .query_row("SELECT value FROM working WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(String::from_utf8(working).unwrap().contains(base.as_str()));
    }
}

#[test]
fn mmap_corruption_is_verified_before_reuse() {
    use std::os::fd::AsRawFd;
    let (_d, p, s) = store();
    let id = s.install(b"abc").unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(p.join(id.as_str()))
        .unwrap();
    // SAFETY: map three bytes from the live three-byte file; unmap before closing it.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            3,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    unsafe { std::ptr::copy_nonoverlapping(b"xyz".as_ptr(), mapping.cast::<u8>(), 3) };
    let result = s.install(b"abc");
    assert_eq!(unsafe { libc::munmap(mapping, 3) }, 0);
    assert!(matches!(result, Err(FsError::CorruptObject)), "{result:?}");
}
