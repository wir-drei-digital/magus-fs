mod support;
use magus_fs_core::*;
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use support::*;
fn fixture() -> (tempfile::TempDir, Replica, NativeConfig, RevisionId) {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"before").unwrap();
    let mut c = config();
    c.authorities.truncate(1);
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = fs::metadata(&root).unwrap().gid();
    c.content_roots = vec![root.clone()];
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let n = NativeConfig {
        root,
        policy: CapturePolicy {
            included_roots: vec![".".into()],
            excluded_prefixes: vec![],
        },
        creation_umask: 0o022,
    };
    rep.configure_native(n.clone()).unwrap();
    let base = rep
        .capture(
            &n.root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    (d, rep, n, base)
}
fn incoming(d: &std::path::Path, rep: &Replica, base: &RevisionId, create: bool) -> RevisionId {
    let mut r = rep.revision(base).unwrap();
    r.parents = vec![base.clone()];
    r.operation = OperationId::random().unwrap();
    if create {
        add_file(&mut r, "new", b"incoming");
    } else {
        r.tree.entries[0].content = EntryContent::File {
            version: FileVersion {
                size: 8,
                extents: vec![Extent::Chunk {
                    object: ObjectId::for_bytes(b"incoming").unwrap(),
                    object_size: 8,
                    offset: 0,
                    length: 8,
                }],
            },
        };
    }
    import(rep, &r, local(d, b"incoming"))
}
#[test]
fn rescan_captures_in_place_and_atomic_save_without_echo() {
    let (_d, rep, n, base) = fixture();
    assert_eq!(
        rep.capture_native_changes(OperationId::random().unwrap(), actor())
            .unwrap(),
        None
    );
    fs::write(n.root.join("a"), b"edited").unwrap();
    let edit = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&base).unwrap().tree.entries[0].id,
        rep.revision(&edit).unwrap().tree.entries[0].id
    );
    assert_eq!(
        rep.capture_native_changes(OperationId::random().unwrap(), actor())
            .unwrap(),
        None
    );
    let old = fs::File::open(n.root.join("a")).unwrap();
    fs::write(n.root.join("save"), b"saved").unwrap();
    fs::rename(n.root.join("save"), n.root.join("a")).unwrap();
    let saved = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_ne!(
        rep.revision(&edit).unwrap().tree.entries[0].id,
        rep.revision(&saved).unwrap().tree.entries[0].id
    );
    drop(old);
}
#[test]
fn exchange_retains_old_fd_and_canonical_identity_without_echo() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    let mut old = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let ino = old.metadata().unwrap().ino();
    let status = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(
        matches!(status, NativeApplyStatus::Ready { .. }),
        "{status:?}"
    );
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"incoming");
    assert_ne!(ino, fs::metadata(n.root.join("a")).unwrap().ino());
    let mut bytes = vec![];
    old.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"before");
    assert_eq!(
        rep.capture_native_changes(OperationId::random().unwrap(), actor())
            .unwrap(),
        None
    );
    old.seek(SeekFrom::Start(0)).unwrap();
    old.write_all(b"late!!").unwrap();
    old.sync_all().unwrap();
    let status = rep.scan_native_status().unwrap();
    assert!(!matches!(status.status, NativeApplyStatus::Ready { .. }));
    assert_eq!(status.displacements.len(), 1);
    assert!(!status.displacements[0].versions.is_empty());
    assert_eq!(
        fs::read(&status.displacements[0].retained_path).unwrap(),
        b"late!!"
    );
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"incoming");
    fs::write(n.root.join("a"), b"subsequent").unwrap();
    let edit = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&edit).unwrap().tree.entries[0].id,
        rep.revision(&next).unwrap().tree.entries[0].id
    );
}
#[test]
fn missing_file_uses_no_replace_install() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, true);
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::Ready { .. }), "{s:?}");
    assert_eq!(fs::read(n.root.join("new")).unwrap(), b"incoming");
}
#[test]
fn dirty_collision_retains_incoming_and_never_overwrites() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    fs::write(n.root.join("a"), b"dirty!").unwrap();
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::Pending { .. }), "{s:?}");
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"dirty!");
    assert_eq!(rep.status().unwrap().head, Some(base));
    assert_eq!(
        rep.scan_native_status().unwrap().incoming_revision,
        Some(next)
    );
}
#[test]
fn structural_or_readonly_parent_work_is_retained_blocked() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    fs::set_permissions(&n.root, fs::Permissions::from_mode(0o555)).unwrap();
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::ApplyBlocked { .. }));
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
    fs::set_permissions(&n.root, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(feature = "test-faults")]
#[test]
fn native_apply_child() {
    let Ok(state) = std::env::var("FS2_NATIVE_CHILD_STATE") else {
        return;
    };
    let rep = Replica::reopen(state).unwrap();
    let r = RevisionId::parse(std::env::var("FS2_NATIVE_CHILD_REV").unwrap()).unwrap();
    let op = OperationId::parse(std::env::var("FS2_NATIVE_CHILD_OP").unwrap()).unwrap();
    let result = rep
        .apply_native_revision(&r, rep.status().unwrap().generation, op, actor())
        .unwrap();
    println!("{}", serde_json::to_string(&result).unwrap());
}
#[cfg(feature = "test-faults")]
fn interrupted(point: &str, race: Option<&str>, create: bool) {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, create);
    let generation = rep.status().unwrap().generation;
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let op = OperationId::random().unwrap();
    drop(rep);
    let marker = d.path().join("barrier");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_apply_child", "--nocapture"])
        .env("FS2_NATIVE_CHILD_STATE", d.path().join("state"))
        .env("FS2_NATIVE_CHILD_REV", next.as_str())
        .env("FS2_NATIVE_CHILD_OP", op.as_str())
        .env("MAGUS_TEST_FAULT_POINT", point)
        .env("MAGUS_TEST_FAULT_ACTION", "barrier")
        .env("MAGUS_TEST_FAULT_MARKER", &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = marker.with_extension("1");
    while !ready.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready.exists() {
        child.kill().ok();
        panic!("no barrier: {:?}", child.wait_with_output().unwrap());
    }
    if let Some(race) = race {
        match race {
            "held" => {
                held.write_all(b"late!!").unwrap();
                held.sync_all().unwrap();
            }
            "replace" => {
                fs::write(n.root.join("editor-save"), b"racing-editor").unwrap();
                fs::rename(
                    n.root.join("editor-save"),
                    n.root.join(if create { "new" } else { "a" }),
                )
                .unwrap();
            }
            "move" => {
                fs::rename(&n.root, d.path().join("moved")).unwrap();
                fs::create_dir(&n.root).unwrap();
                fs::write(n.root.join("a"), b"unowned").unwrap();
            }
            "symlink" => {
                fs::rename(&n.root, d.path().join("moved")).unwrap();
                std::os::unix::fs::symlink(d.path().join("moved"), &n.root).unwrap();
            }
            _ => panic!("bad race"),
        };
        fs::write(marker.with_extension("1.release"), b"go").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{out:?}");
    } else {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    let reopened = Replica::reopen(d.path().join("state"));
    if race == Some("symlink") {
        assert!(matches!(reopened, Err(FsError::UnsafeStorage)));
        assert_eq!(fs::read(d.path().join("moved/a")).unwrap(), b"before");
        return;
    }
    let rep = reopened.unwrap();
    if race == Some("held") {
        let immediate = rep.native_status().unwrap().unwrap();
        assert!(
            !matches!(immediate.status, NativeApplyStatus::Ready { .. }),
            "late write after verification must not become Ready: {immediate:?}"
        );
        let observed = rep.scan_native_status().unwrap();
        assert!(!matches!(observed.status, NativeApplyStatus::Ready { .. }));
        assert!(observed
            .displacements
            .iter()
            .any(|d| d.ambiguous && d.versions.iter().any(|v| fs::read(v).unwrap() == b"late!!")));
        assert_eq!(fs::read(n.root.join("a")).unwrap(), b"incoming");
        let enumeration = serde_json::to_value(&observed.displacements).unwrap();
        drop(rep);
        let rep = Replica::reopen(d.path().join("state")).unwrap();
        let retained = rep.native_status().unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&retained.displacements).unwrap(),
            enumeration
        );
        assert!(!matches!(retained.status, NativeApplyStatus::Ready { .. }));
        return;
    }
    if race.is_none() {
        let recovered = rep.recover_native_application(actor()).unwrap();
        assert!(recovered
            .iter()
            .any(|s| matches!(s, NativeApplyStatus::Ready { .. })));
    }
    let status = rep
        .apply_native_revision(&next, generation, op, actor())
        .unwrap();
    if race.is_none() {
        assert!(
            matches!(status, NativeApplyStatus::Ready { .. }),
            "{point}: {status:?}"
        );
        assert_eq!(
            fs::read(n.root.join(if create { "new" } else { "a" })).unwrap(),
            b"incoming"
        );
        assert_eq!(rep.status().unwrap().head, Some(next));
    } else if let Some(race) = race {
        assert!(
            !matches!(status, NativeApplyStatus::Ready { .. }),
            "{race:?}: {status:?}"
        );
        assert_eq!(rep.status().unwrap().head, Some(base));
        match race {
            "replace" => {
                if point == "native-before-exchange" && !create {
                    let s = rep.scan_native_status().unwrap();
                    assert!(s
                        .displacements
                        .iter()
                        .any(|v| fs::read(&v.retained_path).unwrap() == b"racing-editor"));
                } else {
                    assert_eq!(
                        fs::read(n.root.join(if create { "new" } else { "a" })).unwrap(),
                        b"racing-editor"
                    );
                }
            }
            "move" => assert_eq!(fs::read(n.root.join("a")).unwrap(), b"unowned"),
            _ => assert_eq!(fs::read(d.path().join("moved/a")).unwrap(), b"before"),
        }
    }
}
#[cfg(feature = "test-faults")]
#[test]
fn native_displaced_verified_gap_retains_late_write() {
    interrupted("native-displaced-verified", Some("held"), false);
}
#[cfg(feature = "test-faults")]
#[test]
fn native_crash_recovery_uses_original_intent() {
    for p in ["native-intent", "native-exchanged", "native-before-commit"] {
        interrupted(p, None, false);
        interrupted(p, None, true);
    }
}
#[cfg(feature = "test-faults")]
#[test]
fn native_racing_editor_preserves_every_generation() {
    interrupted("native-before-exchange", Some("replace"), false);
    interrupted("native-before-exchange", Some("replace"), true);
    interrupted("native-before-commit", Some("replace"), false);
}
#[cfg(feature = "test-faults")]
#[test]
fn native_parent_movement_and_symlink_fail_closed() {
    interrupted("native-before-exchange", Some("move"), false);
    interrupted("native-before-exchange", Some("symlink"), false);
}
#[test]
fn native_remote_fetch_does_not_hold_owner_mutex() {
    use std::{
        sync::{mpsc, Arc},
        time::{Duration, Instant},
    };
    struct Fetch(Replica);
    impl RemoteFetcher for Fetch {
        fn fetch(
            &self,
            _: &protocol::RemoteSourceId,
            _: &ObjectId,
            _: u64,
            _: Instant,
        ) -> Result<Vec<u8>, FsError> {
            let (tx, rx) = mpsc::channel();
            let rep = self.0.clone();
            std::thread::spawn(move || {
                tx.send(rep.status().is_ok()).ok();
            });
            if rx.recv_timeout(Duration::from_millis(200)) != Ok(true) {
                return Err(FsError::ReplicaBusy);
            }
            Ok(b"incoming".to_vec())
        }
    }
    let (_d, rep, _n, base) = fixture();
    let mut r = rep.revision(&base).unwrap();
    r.operation = OperationId::random().unwrap();
    r.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 8,
            extents: vec![Extent::Chunk {
                object: ObjectId::for_bytes(b"incoming").unwrap(),
                object_size: 8,
                offset: 0,
                length: 8,
            }],
        },
    };
    let next = import(
        &rep,
        &r,
        ChunkSource::Remote {
            source: protocol::RemoteSourceId::random().unwrap(),
        },
    );
    rep.set_remote_fetcher(Arc::new(Fetch(rep.clone())))
        .unwrap();
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::Ready { .. }), "{s:?}");
}
#[test]
fn revoked_remote_authority_blocks_core_native_capture_and_apply() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    rep.observe_remote_authority(None, 0).unwrap();
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(!matches!(s, NativeApplyStatus::Ready { .. }));
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
    fs::write(n.root.join("a"), b"private-local").unwrap();
    assert!(matches!(
        rep.capture_native_changes(OperationId::random().unwrap(), actor()),
        Err(FsError::PermissionDenied)
    ));
}
#[test]
fn retention_budget_charges_the_displaced_size() {
    let (d, old, n, original) = fixture();
    let mut r = old.revision(&original).unwrap();
    let config = old.configuration().unwrap();
    drop(old);
    let file = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    file.set_len(0).unwrap();
    file.set_len(512 * 1024 * 1024 + 1).unwrap();
    drop(file);
    r.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 512 * 1024 * 1024 + 1,
            extents: vec![Extent::Hole {
                length: 512 * 1024 * 1024 + 1,
            }],
        },
    };
    let rep = Replica::open(d.path().join("large-state"), config).unwrap();
    rep.configure_native(n.clone()).unwrap();
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let _workspace = rep.begin(&base, actor(), false).unwrap();
    rep.verify_native_baseline(actor()).unwrap();
    let next = incoming(d.path(), &rep, &base, false);
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::ApplyBlocked { .. }), "{s:?}");
    assert_eq!(
        fs::metadata(n.root.join("a")).unwrap().len(),
        512 * 1024 * 1024 + 1
    );
}
#[test]
fn directory_creation_applies_by_verified_root_exchange() {
    let (_d, rep, n, base) = fixture();
    let mut r = rep.revision(&base).unwrap();
    r.operation = OperationId::random().unwrap();
    r.tree.entries.push(Entry {
        path: "directory".into(),
        id: EntryId::random().unwrap(),
        parent: r.tree.root.id.clone(),
        owner: principal(1),
        group: group(1),
        mode: 0o755,
        content: EntryContent::Directory,
    });
    let next = import(&rep, &r, ChunkSource::Unavailable);
    let s = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::Ready { .. }), "{s:?}");
    assert!(n.root.join("directory").is_dir());
    assert_eq!(
        rep.scan_native_status().unwrap().incoming_revision,
        Some(next)
    );
}
#[test]
fn late_displacement_candidate_prevents_new_ready_claim() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    rep.apply_native_revision(
        &next,
        rep.status().unwrap().generation,
        OperationId::random().unwrap(),
        actor(),
    )
    .unwrap();
    held.write_all(b"late!!").unwrap();
    held.sync_all().unwrap();
    let status = rep.scan_native_status().unwrap();
    assert!(!status.displacements[0].versions.is_empty());
    let mut r = rep.revision(&next).unwrap();
    r.operation = OperationId::random().unwrap();
    let third = import(&rep, &r, ChunkSource::Unavailable);
    let result = rep
        .apply_native_revision(
            &third,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(
        !matches!(result, NativeApplyStatus::Ready { .. }),
        "{result:?}"
    );
    assert!(!rep.live_status().unwrap().applied);
    let enumeration = serde_json::to_value(&status.displacements).unwrap();
    let after = rep.native_status().unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&after.displacements).unwrap(),
        enumeration,
        "rejected apply must preserve immediate enumeration"
    );
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    let after = rep.native_status().unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&after.displacements).unwrap(),
        enumeration,
        "reopen must preserve enumeration without a scan"
    );
    assert!(after
        .displacements
        .iter()
        .any(|d| d.versions.iter().any(|p| fs::read(p).unwrap() == b"late!!")));
}
#[test]
fn old_apply_operation_cannot_claim_current_readiness() {
    let (d, rep, _n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    let op = OperationId::random().unwrap();
    let generation = rep.status().unwrap().generation;
    rep.apply_native_revision(&next, generation, op.clone(), actor())
        .unwrap();
    let mut r = rep.revision(&next).unwrap();
    r.operation = OperationId::random().unwrap();
    let third = import(&rep, &r, ChunkSource::Unavailable);
    rep.apply_native_revision(
        &third,
        rep.status().unwrap().generation,
        OperationId::random().unwrap(),
        actor(),
    )
    .unwrap();
    let replay = rep
        .apply_native_revision(&next, generation, op, actor())
        .unwrap();
    assert!(!matches!(replay, NativeApplyStatus::Ready { .. }));
    assert_eq!(rep.status().unwrap().head, Some(third));
}
#[test]
fn generation_budget_blocks_whole_batch_before_any_native_write() {
    let (d, rep, n, base) = fixture();
    let mut r = rep.revision(&base).unwrap();
    r.operation = OperationId::random().unwrap();
    for i in 0..129 {
        add_file(&mut r, &format!("f{i:03}"), b"incoming");
    }
    let next = import(&rep, &r, local(d.path(), b"incoming"));
    let result = rep
        .apply_native_revision(
            &next,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(result, NativeApplyStatus::ApplyBlocked { .. }));
    assert_eq!(fs::read_dir(&n.root).unwrap().count(), 1);
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
}
#[test]
fn native_view_never_retargets_a_registered_source() {
    use magus_fs_core::protocol::*;
    let (_d, rep, _n, base) = fixture();
    let binding = SyncBinding {
        id: NamespaceId::random().unwrap(),
        branch: BranchName::parse("main".into()).unwrap(),
        publication: PublicationMode::SharedLive,
        source: RemoteSourceId::random().unwrap(),
        view: ViewBinding {
            view: ViewId::random().unwrap(),
            head: HeadToken::random().unwrap(),
            revision: base,
        },
        transport_profile: "/private/tmp/native-test-profile".into(),
        transport_identity: TransportIdentity::for_bytes(b"native-test").unwrap(),
    };
    rep.configure_sync(binding.clone()).unwrap();
    let mut registered = binding.clone();
    registered.source = RemoteSourceId::random().unwrap();
    registered.view.view = ViewId::random().unwrap();
    rep.register_sync_source(registered.clone()).unwrap();
    let mut forged = registered;
    forged.view.head = HeadToken::random().unwrap();
    let s = rep
        .apply_native_view(
            forged,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(matches!(s, NativeApplyStatus::ApplyBlocked { .. }), "{s:?}");
    assert_eq!(rep.sync_status().unwrap().binding, Some(binding));
}
#[test]
fn interrupted_unrecorded_stage_bytes_force_backpressure() {
    let (d, rep, _n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    rep.apply_native_revision(
        &next,
        rep.status().unwrap().generation,
        OperationId::random().unwrap(),
        actor(),
    )
    .unwrap();
    let status = rep.scan_native_status().unwrap();
    let orphan = status.displacements[0]
        .retained_path
        .parent()
        .unwrap()
        .join("interrupted-copy");
    fs::write(&orphan, b"unclassified-retained-bytes").unwrap();
    let mut r = rep.revision(&next).unwrap();
    r.operation = OperationId::random().unwrap();
    let third = import(&rep, &r, ChunkSource::Unavailable);
    let result = rep
        .apply_native_revision(
            &third,
            rep.status().unwrap().generation,
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert!(
        matches!(result, NativeApplyStatus::ApplyBlocked { .. }),
        "{result:?}"
    );
    assert_eq!(fs::read(orphan).unwrap(), b"unclassified-retained-bytes");
}

// ---- FS2-B Task 1: structural root exchange, retained recovery and causality ----

fn content(bytes: &[u8]) -> EntryContent {
    EntryContent::File {
        version: FileVersion {
            size: bytes.len() as u64,
            extents: if bytes.is_empty() {
                vec![]
            } else {
                vec![Extent::Chunk {
                    object: ObjectId::for_bytes(bytes).unwrap(),
                    object_size: bytes.len() as u64,
                    offset: 0,
                    length: bytes.len() as u64,
                }]
            },
        },
    }
}
fn sources(d: &std::path::Path, bodies: &[&[u8]]) -> ChunkSource {
    let path = d.join(format!(
        "source-{}",
        &OperationId::random().unwrap().as_str()[10..]
    ));
    let store = ObjectStore::open(&path, ObjectLimits::default()).unwrap();
    for b in bodies {
        store.install(b).unwrap();
    }
    ChunkSource::Local { path }
}
fn next_of(rep: &Replica, from: &RevisionId) -> Revision {
    let mut r = rep.revision(from).unwrap();
    r.parents = vec![from.clone()];
    r.operation = OperationId::random().unwrap();
    r
}
fn put_dir(r: &mut Revision, path: &str, mode: u16) -> EntryId {
    let parent = parent_id(r, path);
    let id = EntryId::random().unwrap();
    r.tree.entries.push(Entry {
        path: path.into(),
        id: id.clone(),
        parent,
        owner: principal(1),
        group: group(1),
        mode,
        content: EntryContent::Directory,
    });
    id
}
fn put_file(r: &mut Revision, path: &str, bytes: &[u8]) -> EntryId {
    let parent = parent_id(r, path);
    let id = EntryId::random().unwrap();
    r.tree.entries.push(Entry {
        path: path.into(),
        id: id.clone(),
        parent,
        owner: principal(1),
        group: group(1),
        mode: 0o640,
        content: content(bytes),
    });
    id
}
fn parent_id(r: &Revision, path: &str) -> EntryId {
    match path.rsplit_once('/') {
        None => r.tree.root.id.clone(),
        Some((p, _)) => r
            .tree
            .entries
            .iter()
            .find(|e| e.path == p)
            .unwrap()
            .id
            .clone(),
    }
}
fn entry_mut<'a>(r: &'a mut Revision, path: &str) -> &'a mut Entry {
    r.tree.entries.iter_mut().find(|e| e.path == path).unwrap()
}
fn sorted(mut r: Revision) -> Revision {
    r.tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
    r
}
fn apply(rep: &Replica, next: &RevisionId) -> NativeApplyStatus {
    rep.apply_native_revision(
        next,
        rep.status().unwrap().generation,
        OperationId::random().unwrap(),
        actor(),
    )
    .unwrap()
}
fn ready(s: &NativeApplyStatus) -> bool {
    matches!(s, NativeApplyStatus::Ready { .. })
}
fn blocked_reason(s: &NativeApplyStatus) -> &str {
    match s {
        NativeApplyStatus::ApplyBlocked { reason } => reason,
        other => panic!("expected ApplyBlocked, got {other:?}"),
    }
}
fn mode_of(p: &std::path::Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}
fn no_echo(rep: &Replica) {
    assert_eq!(
        rep.capture_native_changes(OperationId::random().unwrap(), actor())
            .unwrap(),
        None,
        "a verified structural application must not echo as a local capture"
    );
}
fn sha(bytes: &[u8]) -> ObjectId {
    use sha2::Digest;
    ObjectId::parse(format!(
        "sha256:{}",
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .unwrap()
}

#[test]
fn structural_directory_and_namespace_matrix_uses_verified_root_exchange() {
    let (d, rep, n, base) = fixture();
    let root_ino = fs::metadata(&n.root).unwrap().ino();
    // Directory creation, nested file creation and a new sibling file.
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o750);
    put_file(&mut r, "d/x", b"nested-x");
    put_file(&mut r, "b", b"bee");
    let first = import(&rep, &sorted(r), sources(d.path(), &[b"nested-x", b"bee"]));
    let s = apply(&rep, &first);
    assert!(ready(&s), "{s:?}");
    assert_eq!(fs::read(n.root.join("d/x")).unwrap(), b"nested-x");
    assert_eq!(fs::read(n.root.join("b")).unwrap(), b"bee");
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
    assert_eq!(mode_of(&n.root.join("d")), 0o750);
    assert_ne!(fs::metadata(&n.root).unwrap().ino(), root_ino);
    let status = rep.scan_native_status().unwrap();
    assert!(ready(&status.status), "{status:?}");
    let root_displacement = status
        .displacements
        .iter()
        .find(|v| v.path.is_empty())
        .expect("displaced root is a retained, enumerated generation");
    assert_eq!(
        fs::metadata(&root_displacement.retained_path)
            .unwrap()
            .ino(),
        root_ino
    );
    assert_eq!(
        fs::read(root_displacement.retained_path.join("a")).unwrap(),
        b"before"
    );
    assert!(!root_displacement.retained_path.join("d").exists());
    no_echo(&rep);
    // Directory move with stable identities, file rename, deletion.
    let mut r = next_of(&rep, &first);
    let d_id = entry_mut(&mut r, "d").id.clone();
    let x_id = entry_mut(&mut r, "d/x").id.clone();
    let b_id = entry_mut(&mut r, "b").id.clone();
    entry_mut(&mut r, "d").path = "e".into();
    entry_mut(&mut r, "d/x").path = "e/x".into();
    entry_mut(&mut r, "b").path = "c".into();
    r.tree.entries.retain(|e| e.path != "a");
    let second = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &second);
    assert!(ready(&s), "{s:?}");
    assert!(!n.root.join("d").exists() && !n.root.join("a").exists() && !n.root.join("b").exists());
    assert_eq!(fs::read(n.root.join("e/x")).unwrap(), b"nested-x");
    assert_eq!(fs::read(n.root.join("c")).unwrap(), b"bee");
    no_echo(&rep);
    let head = rep.revision(&rep.status().unwrap().head.unwrap()).unwrap();
    let id_of = |p: &str| {
        head.tree
            .entries
            .iter()
            .find(|e| e.path == p)
            .unwrap()
            .id
            .clone()
    };
    assert_eq!((id_of("e"), id_of("e/x"), id_of("c")), (d_id, x_id, b_id));
    // Type replacement (file -> directory) and same-path new identity.
    let mut r = next_of(&rep, &second);
    let old_c = entry_mut(&mut r, "c").id.clone();
    r.tree.entries.retain(|e| e.path != "e/x" && e.path != "c");
    put_dir(&mut r, "e/x", 0o755);
    let new_c = put_file(&mut r, "c", b"replacement identity");
    let third = import(
        &rep,
        &sorted(r),
        sources(d.path(), &[b"replacement identity"]),
    );
    let s = apply(&rep, &third);
    assert!(ready(&s), "{s:?}");
    assert!(fs::metadata(n.root.join("e/x")).unwrap().is_dir());
    assert_eq!(fs::read(n.root.join("c")).unwrap(), b"replacement identity");
    no_echo(&rep);
    // Entry identity is preserved for later in-place native edits.
    fs::write(n.root.join("c"), b"later in-place edit").unwrap();
    let edit = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    let edited = rep.revision(&edit).unwrap();
    let c = edited.tree.entries.iter().find(|e| e.path == "c").unwrap();
    assert_eq!(c.id, new_c);
    assert_ne!(c.id, old_c);
    // The first native edit of a path the application just installed cannot prove its base.
    assert_eq!(edited.provenance, UNKNOWN_CAUSALITY_PROVENANCE);
    assert!(
        rep.scan_native_status()
            .unwrap()
            .displacements
            .iter()
            .filter(|v| v.path.is_empty())
            .count()
            >= 3
    );
}

#[test]
fn root_and_directory_modes_apply_and_verify() {
    let (d, rep, n, base) = fixture();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "ro", 0o755);
    put_file(&mut r, "ro/f", b"inside readonly");
    let first = import(&rep, &sorted(r), sources(d.path(), &[b"inside readonly"]));
    assert!(ready(&apply(&rep, &first)));
    let mut r = next_of(&rep, &first);
    r.tree.root.mode = 0o750;
    entry_mut(&mut r, "ro").mode = 0o555;
    entry_mut(&mut r, "a").mode = 0o600;
    let second = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &second);
    assert!(ready(&s), "{s:?}");
    assert_eq!(mode_of(&n.root), 0o750);
    assert_eq!(mode_of(&n.root.join("ro")), 0o555);
    assert_eq!(mode_of(&n.root.join("a")), 0o600);
    assert_eq!(fs::read(n.root.join("ro/f")).unwrap(), b"inside readonly");
    no_echo(&rep);
    fs::set_permissions(n.root.join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
}

fn alternate_gid() -> u32 {
    let mut groups = vec![0 as libc::gid_t; 256];
    let n = unsafe { libc::getgroups(256, groups.as_mut_ptr()) };
    assert!(n >= 0);
    let egid = unsafe { libc::getegid() };
    *groups[..n as usize]
        .iter()
        .find(|g| **g != egid)
        .expect("the qualification user must belong to a second group")
}
fn ownership_fixture() -> (tempfile::TempDir, Replica, NativeConfig, RevisionId) {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"before").unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = fs::metadata(&root).unwrap().gid();
    let mut c = config();
    c.authorities = vec![
        Authority {
            principal: principal(1),
            uid,
            primary_group: group(1),
            gid,
            groups: vec![group(1), group(2), group(3)],
            dac_override: false,
            ownership_transfer: true,
        },
        Authority {
            principal: principal(2),
            uid: 54322,
            primary_group: group(2),
            gid: alternate_gid(),
            groups: vec![group(2)],
            dac_override: false,
            ownership_transfer: false,
        },
        Authority {
            principal: principal(3),
            uid: 54321,
            primary_group: group(3),
            gid: 54321,
            groups: vec![group(3)],
            dac_override: false,
            ownership_transfer: false,
        },
    ];
    c.content_roots = vec![root.clone()];
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let n = NativeConfig {
        root,
        policy: CapturePolicy {
            included_roots: vec![".".into()],
            excluded_prefixes: vec![],
        },
        creation_umask: 0o022,
    };
    rep.configure_native(n.clone()).unwrap();
    let base = rep
        .capture(
            &n.root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    (d, rep, n, base)
}
#[test]
fn mapped_group_ownership_applies_and_unmappable_owner_blocks_without_loss() {
    let (_d, rep, n, base) = ownership_fixture();
    let mut r = next_of(&rep, &base);
    entry_mut(&mut r, "a").group = group(2);
    let regrouped = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &regrouped);
    assert!(ready(&s), "{s:?}");
    assert_eq!(
        fs::metadata(n.root.join("a")).unwrap().gid(),
        alternate_gid()
    );
    no_echo(&rep);
    let root_ino = fs::metadata(&n.root).unwrap().ino();
    let mut r = next_of(&rep, &regrouped);
    let e = entry_mut(&mut r, "a");
    e.owner = principal(3);
    e.group = group(3);
    let foreign = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &foreign);
    assert_eq!(blocked_reason(&s), "mapping_blocked");
    assert_eq!(fs::metadata(&n.root).unwrap().ino(), root_ino);
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
    assert_eq!(rep.status().unwrap().head, Some(regrouped));
    assert_eq!(
        rep.scan_native_status().unwrap().incoming_revision,
        Some(foreign)
    );
    no_echo(&rep);
}

#[test]
fn readonly_root_parent_blocks_structural_work_without_loss() {
    let (d, rep, n, base) = fixture();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    let next = import(&rep, &sorted(r), ChunkSource::Unavailable);
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let s = apply(&rep, &next);
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(blocked_reason(&s), "readonly_parent");
    assert!(!n.root.join("d").exists());
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
    // A later attempt after the parent becomes writable is not blocked by the refused one.
    let s = apply(&rep, &next);
    assert!(ready(&s), "{s:?}");
}

fn excluded_fixture() -> (tempfile::TempDir, Replica, NativeConfig, RevisionId) {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"before").unwrap();
    fs::create_dir(root.join("cache")).unwrap();
    fs::write(root.join("cache/blob"), b"local-only opaque bytes").unwrap();
    fs::set_permissions(root.join("cache/blob"), fs::Permissions::from_mode(0o604)).unwrap();
    let mut c = config();
    c.authorities.truncate(1);
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = fs::metadata(&root).unwrap().gid();
    c.content_roots = vec![root.clone()];
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let n = NativeConfig {
        root,
        policy: CapturePolicy {
            included_roots: vec![".".into()],
            excluded_prefixes: vec!["cache".into()],
        },
        creation_umask: 0o022,
    };
    rep.configure_native(n.clone()).unwrap();
    let base = rep
        .capture(
            &n.root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    (d, rep, n, base)
}
#[test]
fn capture_excluded_local_entries_survive_and_unsupported_or_colliding_entries_block() {
    let (d, rep, n, base) = excluded_fixture();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    let next = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &next);
    assert!(ready(&s), "{s:?}");
    assert_eq!(
        fs::read(n.root.join("cache/blob")).unwrap(),
        b"local-only opaque bytes"
    );
    assert_eq!(mode_of(&n.root.join("cache/blob")), 0o604);
    no_echo(&rep);
    // A symlink in the opaque local area is never followed or copied.
    std::os::unix::fs::symlink("/etc", n.root.join("cache/link")).unwrap();
    let root_ino = fs::metadata(&n.root).unwrap().ino();
    let mut r = next_of(&rep, &next);
    put_dir(&mut r, "e", 0o755);
    let unsupported = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &unsupported);
    assert_eq!(blocked_reason(&s), "unsupported_local_entry");
    assert_eq!(fs::metadata(&n.root).unwrap().ino(), root_ino);
    fs::remove_file(n.root.join("cache/link")).unwrap();
    // An unreadable local-only subtree blocks instead of being dropped.
    fs::create_dir(n.root.join("cache/sealed")).unwrap();
    fs::set_permissions(
        n.root.join("cache/sealed"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let s = apply(&rep, &unsupported);
    fs::set_permissions(
        n.root.join("cache/sealed"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(blocked_reason(&s), "unreadable_local_entry");
    assert_eq!(fs::metadata(&n.root).unwrap().ino(), root_ino);
    fs::remove_dir(n.root.join("cache/sealed")).unwrap();
    // An incoming managed path cannot collide with a preserved local-only entry.
    let mut r = next_of(&rep, &next);
    put_dir(&mut r, "cache", 0o755);
    let colliding = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let s = apply(&rep, &colliding);
    assert_eq!(blocked_reason(&s), "local_entry_collision");
    assert_eq!(fs::metadata(&n.root).unwrap().ino(), root_ino);
    assert_eq!(
        fs::read(n.root.join("cache/blob")).unwrap(),
        b"local-only opaque bytes"
    );
    let _ = d;
}

#[test]
fn held_descriptor_and_cwd_writes_land_in_retained_root_and_become_recovery_records() {
    use std::ffi::CString;
    let (d, rep, n, base) = fixture();
    let mut held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let cwd = fs::File::open(&n.root).unwrap();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    entry_mut(&mut r, "a").content = content(b"incoming");
    let next = import(&rep, &sorted(r), sources(d.path(), &[b"incoming"]));
    let s = apply(&rep, &next);
    assert!(ready(&s), "{s:?}");
    assert!(rep.list_native_recovery(actor()).unwrap().is_empty());
    held.seek(SeekFrom::Start(0)).unwrap();
    held.write_all(b"stale RAM write").unwrap();
    held.sync_all().unwrap();
    let leaf = CString::new("cwd-created").unwrap();
    let fd = unsafe {
        libc::openat(
            std::os::fd::AsRawFd::as_raw_fd(&cwd),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o640,
        )
    };
    assert!(fd >= 0);
    let mut created = unsafe { <fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    created.write_all(b"written through old cwd").unwrap();
    created.sync_all().unwrap();
    drop(created);
    // The installed root is unaffected by old-root descriptors.
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"incoming");
    assert!(!n.root.join("cwd-created").exists());
    let status = rep.scan_native_status().unwrap();
    assert!(
        matches!(&status.status, NativeApplyStatus::Pending { reason } if reason == "late_displaced_write"),
        "{status:?}"
    );
    assert!(!rep.live_status().unwrap().applied);
    let root = status
        .displacements
        .iter()
        .find(|v| v.path.is_empty())
        .unwrap();
    assert!(root.ambiguous);
    let records = rep.list_native_recovery(actor()).unwrap();
    assert_eq!(records.len(), 2, "{records:?}");
    let by_path = |p: &str| records.iter().find(|r| r.source_path == p).unwrap().clone();
    let stale = by_path("a");
    let cwd_record = by_path("cwd-created");
    assert_eq!(stale.observed_digest, sha(b"stale RAM write"));
    assert_eq!(cwd_record.observed_digest, sha(b"written through old cwd"));
    for record in [&stale, &cwd_record] {
        assert_eq!(record.original_base, base);
        assert_eq!(record.causal_coverage, RecoveryCausality::Unknown);
    }
    // Restart preserves the records; a changed retained version becomes a new immutable record.
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert_eq!(
        serde_json::to_value(rep.list_native_recovery(actor()).unwrap()).unwrap(),
        serde_json::to_value(&records).unwrap()
    );
    assert!(!ready(&rep.native_status().unwrap().unwrap().status));
    held.seek(SeekFrom::Start(0)).unwrap();
    held.write_all(b"STALE RAM WRITE").unwrap();
    held.sync_all().unwrap();
    rep.scan_native_status().unwrap();
    let after = rep.list_native_recovery(actor()).unwrap();
    assert_eq!(after.len(), 3);
    for old in &records {
        assert!(after
            .iter()
            .any(|r| serde_json::to_value(r).unwrap() == serde_json::to_value(old).unwrap()));
    }
    assert!(after
        .iter()
        .any(|r| r.source_path == "a" && r.observed_digest == sha(b"STALE RAM WRITE")));
    // Explicit capture creates an attributed, unpublished revision linked to the original base.
    let head = rep.status().unwrap().head;
    let generation = rep.status().unwrap().generation;
    err(
        rep.capture_native_recovery(
            stale.id.clone(),
            sha(b"other bytes"),
            OperationId::random().unwrap(),
            actor(),
        ),
        "operation_mismatch",
    );
    let op = OperationId::random().unwrap();
    let captured = rep
        .capture_native_recovery(
            stale.id.clone(),
            stale.observed_digest.clone(),
            op.clone(),
            actor(),
        )
        .unwrap();
    assert_eq!(
        rep.capture_native_recovery(stale.id.clone(), stale.observed_digest.clone(), op, actor())
            .unwrap(),
        captured
    );
    let revision = rep.revision(&captured).unwrap();
    assert_eq!(revision.parents, vec![base.clone()]);
    assert_eq!(revision.provenance, UNKNOWN_CAUSALITY_PROVENANCE);
    assert_eq!(revision.coverage, vec!["a".to_string()]);
    let a = revision
        .tree
        .entries
        .iter()
        .find(|e| e.path == "a")
        .unwrap();
    assert_eq!(
        a.id,
        rep.revision(&base).unwrap().tree.entries[0].id,
        "recovery keeps the displaced entry identity"
    );
    assert_eq!(a.content, content(b"stale RAM write"));
    assert_eq!(rep.status().unwrap().head, head, "never auto-adopted");
    assert_eq!(rep.status().unwrap().generation, generation);
    assert!(rep.pending_submissions().unwrap().is_empty());
    assert_eq!(
        serde_json::to_value(rep.list_native_recovery(actor()).unwrap()).unwrap(),
        serde_json::to_value(&after).unwrap(),
        "capture never rewrites source records"
    );
    // Export writes a fresh explicit destination only.
    let out = d.path().join("exported-alternative");
    rep.export_native_recovery(
        cwd_record.id.clone(),
        cwd_record.observed_digest.clone(),
        &out,
        actor(),
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"written through old cwd");
    err(
        rep.export_native_recovery(
            cwd_record.id.clone(),
            cwd_record.observed_digest.clone(),
            &out,
            actor(),
        ),
        "already_exists",
    );
    drop(held);
}

#[test]
fn tampered_retained_version_requires_a_new_record() {
    let (d, rep, n, base) = fixture();
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let next = incoming(d.path(), &rep, &base, false);
    assert!(ready(&apply(&rep, &next)));
    held.write_all(b"late!!").unwrap();
    held.sync_all().unwrap();
    rep.scan_native_status().unwrap();
    let record = rep.list_native_recovery(actor()).unwrap().remove(0);
    assert_eq!(record.source_path, "a");
    assert_eq!(record.causal_coverage, RecoveryCausality::Unknown);
    let version = rep.scan_native_status().unwrap().displacements[0].versions[0].clone();
    fs::write(&version, b"tampered").unwrap();
    err(
        rep.capture_native_recovery(
            record.id.clone(),
            record.observed_digest.clone(),
            OperationId::random().unwrap(),
            actor(),
        ),
        "generation_mismatch",
    );
}

#[test]
fn stale_ram_save_after_application_is_unknown_causality() {
    let (d, rep, n, _) = fixture();
    fs::write(n.root.join("untouched"), b"u").unwrap();
    let base = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    let mut r = next_of(&rep, &base);
    entry_mut(&mut r, "a").content = content(b"incoming");
    let next = import(&rep, &sorted(r), sources(d.path(), &[b"incoming"]));
    assert!(ready(&apply(&rep, &next)));
    // An editor that loaded the old bytes saves them back atomically.
    fs::write(n.root.join(".a.swp"), b"before").unwrap();
    fs::rename(n.root.join(".a.swp"), n.root.join("a")).unwrap();
    let stale = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&stale).unwrap().provenance,
        UNKNOWN_CAUSALITY_PROVENANCE
    );
    // A subsequent edit after a local capture, or of an untouched path, keeps native provenance.
    fs::write(n.root.join("untouched"), b"edited later").unwrap();
    let later = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&later).unwrap().provenance,
        "native_scan_delete_create"
    );
}

#[test]
fn journal_upgrades_additively_and_newer_schema_fails_closed() {
    let (d, rep, _n, base) = fixture();
    drop(rep);
    let db = rusqlite::Connection::open(d.path().join("state/journal.sqlite")).unwrap();
    db.execute_batch(
        "DROP TABLE native_recovery_captures; DROP TABLE native_recovery; PRAGMA user_version=1;",
    )
    .unwrap();
    drop(db);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert_eq!(rep.status().unwrap().head, Some(base));
    assert!(rep.list_native_recovery(actor()).unwrap().is_empty());
    drop(rep);
    let db = rusqlite::Connection::open(d.path().join("state/journal.sqlite")).unwrap();
    let version: u32 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
    db.pragma_update(None, "user_version", 3).unwrap();
    drop(db);
    err(
        Replica::reopen(d.path().join("state")),
        "unsupported_schema",
    );
}

fn nested_fixture() -> (tempfile::TempDir, Replica, NativeConfig, RevisionId) {
    let d = scratch();
    let parent = d.path().join("p");
    fs::create_dir(&parent).unwrap();
    let root = parent.join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"before").unwrap();
    let mut c = config();
    c.authorities.truncate(1);
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = fs::metadata(&root).unwrap().gid();
    c.content_roots = vec![root.clone()];
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let n = NativeConfig {
        root,
        policy: CapturePolicy {
            included_roots: vec![".".into()],
            excluded_prefixes: vec![],
        },
        creation_umask: 0o022,
    };
    rep.configure_native(n.clone()).unwrap();
    let base = rep
        .capture(
            &n.root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    (d, rep, n, base)
}

#[cfg(feature = "test-faults")]
fn structural_interrupted(point: &str, race: Option<&str>) {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (d, rep, n, base) = nested_fixture();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    put_file(&mut r, "d/x", b"structural incoming");
    let next = import(
        &rep,
        &sorted(r),
        sources(d.path(), &[b"structural incoming"]),
    );
    let generation = rep.status().unwrap().generation;
    let root_ino = fs::metadata(&n.root).unwrap().ino();
    let op = OperationId::random().unwrap();
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    drop(rep);
    let marker = d.path().join("barrier");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_apply_child", "--nocapture"])
        .env("FS2_NATIVE_CHILD_STATE", d.path().join("state"))
        .env("FS2_NATIVE_CHILD_REV", next.as_str())
        .env("FS2_NATIVE_CHILD_OP", op.as_str())
        .env("MAGUS_TEST_FAULT_POINT", point)
        .env("MAGUS_TEST_FAULT_ACTION", "barrier")
        .env("MAGUS_TEST_FAULT_MARKER", &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready_marker = marker.with_extension("1");
    while !ready_marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready_marker.exists() {
        child.kill().ok();
        panic!(
            "no barrier {point}: {:?}",
            child.wait_with_output().unwrap()
        );
    }
    let parent = n.root.parent().unwrap().to_path_buf();
    match race {
        None => {
            child.kill().unwrap();
            child.wait().unwrap();
            let rep = Replica::reopen(d.path().join("state")).unwrap();
            let recovered = rep.recover_native_application(actor()).unwrap();
            assert!(recovered.iter().any(ready), "{point}: {recovered:?}");
            let s = rep
                .apply_native_revision(&next, generation, op, actor())
                .unwrap();
            assert!(ready(&s), "{point}: {s:?}");
            assert_eq!(rep.status().unwrap().head, Some(next));
            assert_eq!(
                fs::read(n.root.join("d/x")).unwrap(),
                b"structural incoming"
            );
            let status = rep.scan_native_status().unwrap();
            assert!(ready(&status.status), "{point}: {status:?}");
            drop(held);
            let root = status
                .displacements
                .iter()
                .find(|v| v.path.is_empty())
                .unwrap();
            assert_eq!(fs::metadata(&root.retained_path).unwrap().ino(), root_ino);
            no_echo(&rep);
        }
        Some(race) => {
            match race {
                "root-moved" => {
                    fs::rename(&n.root, parent.join("moved")).unwrap();
                    fs::create_dir(&n.root).unwrap();
                    fs::write(n.root.join("a"), b"unowned").unwrap();
                }
                "root-symlink" => {
                    fs::rename(&n.root, parent.join("moved")).unwrap();
                    std::os::unix::fs::symlink(parent.join("moved"), &n.root).unwrap();
                }
                "parent-moved" => {
                    fs::rename(&parent, d.path().join("p-moved")).unwrap();
                    fs::create_dir(&parent).unwrap();
                    fs::create_dir(&n.root).unwrap();
                    fs::write(n.root.join("a"), b"unowned").unwrap();
                }
                "held-write" => {
                    held.write_all(b"racing held-descriptor write").unwrap();
                    held.sync_all().unwrap();
                }
                "installed-write" => {
                    fs::write(n.root.join("d/x"), b"racing pathname write").unwrap();
                }
                _ => panic!("bad race"),
            }
            fs::write(marker.with_extension("1.release"), b"go").unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{out:?}");
            let printed: NativeApplyStatus = serde_json::from_str(
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .find(|l| l.starts_with('{'))
                    .unwrap(),
            )
            .unwrap();
            assert!(!ready(&printed), "{race}: {printed:?}");
            match race {
                "root-moved" => {
                    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"unowned");
                    assert!(!n.root.join("d").exists());
                    assert_eq!(fs::read(parent.join("moved/a")).unwrap(), b"before");
                }
                "root-symlink" => {
                    assert_eq!(fs::read(parent.join("moved/a")).unwrap(), b"before");
                    assert!(!parent.join("moved/d").exists());
                }
                "parent-moved" => {
                    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"unowned");
                    assert!(!n.root.join("d").exists());
                    assert_eq!(
                        fs::read(d.path().join("p-moved/tree/a")).unwrap(),
                        b"before"
                    );
                }
                "held-write" => {
                    // The racing write is retained in the displaced root and becomes ambiguous.
                    let rep = Replica::reopen(d.path().join("state")).unwrap();
                    let status = rep.scan_native_status().unwrap();
                    assert!(!ready(&status.status));
                    let root = status
                        .displacements
                        .iter()
                        .find(|v| v.path.is_empty())
                        .unwrap();
                    assert!(root.ambiguous);
                    assert_eq!(
                        fs::read(root.retained_path.join("a")).unwrap(),
                        b"racing held-descriptor write"
                    );
                    assert!(rep
                        .list_native_recovery(actor())
                        .unwrap()
                        .iter()
                        .any(|r| r.observed_digest == sha(b"racing held-descriptor write")));
                    assert_ne!(rep.status().unwrap().head, Some(next));
                    assert_eq!(
                        fs::read(n.root.join("d/x")).unwrap(),
                        b"structural incoming"
                    );
                }
                "installed-write" => {
                    let rep = Replica::reopen(d.path().join("state")).unwrap();
                    assert!(!ready(&rep.scan_native_status().unwrap().status));
                    assert_ne!(rep.status().unwrap().head, Some(next));
                    assert_eq!(
                        fs::read(n.root.join("d/x")).unwrap(),
                        b"racing pathname write"
                    );
                    let status = rep.scan_native_status().unwrap();
                    let root = status
                        .displacements
                        .iter()
                        .find(|v| v.path.is_empty())
                        .unwrap();
                    assert_eq!(fs::read(root.retained_path.join("a")).unwrap(), b"before");
                }
                _ => unreachable!(),
            }
        }
    }
}
#[cfg(feature = "test-faults")]
#[test]
fn structural_crash_recovery_uses_durable_phases_and_inode_identities() {
    for point in [
        "native-root-before-exchange",
        "native-root-exchanged",
        "native-root-verified",
        "native-before-commit",
    ] {
        structural_interrupted(point, None);
    }
}
#[cfg(feature = "test-faults")]
#[test]
fn structural_nofollow_root_and_parent_races_fail_closed() {
    structural_interrupted("native-root-before-exchange", Some("root-moved"));
    structural_interrupted("native-root-before-exchange", Some("root-symlink"));
    structural_interrupted("native-root-before-exchange", Some("parent-moved"));
}
#[cfg(feature = "test-faults")]
#[test]
fn structural_racing_write_after_exchange_retains_both_roots() {
    structural_interrupted("native-root-exchanged", Some("held-write"));
    structural_interrupted("native-root-exchanged", Some("installed-write"));
}

#[test]
fn unrelated_capture_after_application_keeps_stale_save_unknown() {
    let (d, rep, n, _) = fixture();
    fs::write(n.root.join("b"), b"b0").unwrap();
    let base = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    let mut r = next_of(&rep, &base);
    entry_mut(&mut r, "a").content = content(b"incoming");
    let next = import(&rep, &sorted(r), sources(d.path(), &[b"incoming"]));
    assert!(ready(&apply(&rep, &next)));
    // An unrelated save is captured first; it must not clear the applied path's status.
    fs::write(n.root.join("b"), b"b1").unwrap();
    let unrelated = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&unrelated).unwrap().provenance,
        "native_scan_delete_create"
    );
    fs::write(n.root.join(".a.swp"), b"before").unwrap();
    fs::rename(n.root.join(".a.swp"), n.root.join("a")).unwrap();
    let stale = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&stale).unwrap().provenance,
        UNKNOWN_CAUSALITY_PROVENANCE
    );
    // Once that native change is captured, later edits of the path have a local base.
    fs::write(n.root.join("a"), b"edited after the captured stale save").unwrap();
    let later = rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .unwrap();
    assert_eq!(
        rep.revision(&later).unwrap().provenance,
        "native_scan_delete_create"
    );
}

#[cfg(feature = "test-faults")]
#[test]
fn native_scan_child() {
    let Ok(state) = std::env::var("FS2_NATIVE_SCAN_CHILD_STATE") else {
        return;
    };
    let rep = Replica::reopen(state).unwrap();
    println!("{:?}", rep.scan_native_status().map(|s| s.status));
}
#[cfg(feature = "test-faults")]
fn killed_between_version_copy_and_save(structural: bool) {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (d, rep, n, base) = fixture();
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let mut r = next_of(&rep, &base);
    entry_mut(&mut r, "a").content = content(b"incoming");
    if structural {
        put_dir(&mut r, "d", 0o755);
    }
    let next = import(&rep, &sorted(r), sources(d.path(), &[b"incoming"]));
    assert!(ready(&apply(&rep, &next)));
    held.write_all(b"late!!").unwrap();
    held.sync_all().unwrap();
    drop(rep);
    let marker = d.path().join("barrier");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_scan_child", "--nocapture"])
        .env("FS2_NATIVE_SCAN_CHILD_STATE", d.path().join("state"))
        .env("MAGUS_TEST_FAULT_POINT", "native-version-copied")
        .env("MAGUS_TEST_FAULT_ACTION", "barrier")
        .env("MAGUS_TEST_FAULT_MARKER", &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.with_extension("1").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.with_extension("1").exists(), "no copy barrier");
    child.kill().unwrap();
    child.wait().unwrap();
    // The restarted owner must neither wedge on the orphaned copy nor lose the record.
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    let status = rep.scan_native_status().unwrap();
    assert!(!ready(&status.status), "{status:?}");
    let records = rep.list_native_recovery(actor()).unwrap();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].observed_digest, sha(b"late!!"));
    rep.scan_native_status().unwrap();
    assert_eq!(rep.list_native_recovery(actor()).unwrap().len(), 1);
    rep.capture_native_recovery(
        records[0].id.clone(),
        records[0].observed_digest.clone(),
        OperationId::random().unwrap(),
        actor(),
    )
    .unwrap();
    assert!(rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .is_ok());
    drop(held);
}
#[cfg(feature = "test-faults")]
#[test]
fn crash_between_version_copy_and_intent_save_recovers() {
    killed_between_version_copy_and_save(false);
    killed_between_version_copy_and_save(true);
}

#[test]
fn replaced_unverified_root_is_never_captured_or_applied() {
    let (d, rep, n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    let generation = rep.status().unwrap().generation;
    fs::rename(&n.root, d.path().join("moved")).unwrap();
    fs::create_dir(&n.root).unwrap();
    fs::write(n.root.join("unowned"), b"unowned replacement").unwrap();
    assert_eq!(
        rep.capture_native_changes(OperationId::random().unwrap(), actor())
            .unwrap(),
        None,
        "a replaced root pathname must not become a mass delete/create capture"
    );
    assert_eq!(rep.status().unwrap().head, Some(base.clone()));
    assert_eq!(rep.status().unwrap().generation, generation);
    let status = rep.scan_native_status().unwrap();
    assert_eq!(blocked_reason(&status.status), "bound_root_changed");
    assert_eq!(blocked_reason(&apply(&rep, &next)), "bound_root_changed");
    assert_eq!(
        fs::read(n.root.join("unowned")).unwrap(),
        b"unowned replacement"
    );
    assert_eq!(fs::read(d.path().join("moved/a")).unwrap(), b"before");
    // Restoring the verified root resumes ordinary capture.
    fs::remove_file(n.root.join("unowned")).unwrap();
    fs::remove_dir(&n.root).unwrap();
    fs::rename(d.path().join("moved"), &n.root).unwrap();
    fs::write(n.root.join("a"), b"after restore").unwrap();
    assert!(rep
        .capture_native_changes(OperationId::random().unwrap(), actor())
        .unwrap()
        .is_some());
}

#[test]
fn local_only_late_writes_are_reported_separately_and_never_managed() {
    use std::ffi::CString;
    let (d, rep, n, base) = excluded_fixture();
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("cache/blob"))
        .unwrap();
    let cache = fs::File::open(n.root.join("cache")).unwrap();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    let next = import(&rep, &sorted(r), ChunkSource::Unavailable);
    assert!(ready(&apply(&rep, &next)));
    held.write_all(b"SQLITE WAL STYLE WRITE").unwrap();
    held.sync_all().unwrap();
    let leaf = CString::new("new-cache-file").unwrap();
    let fd = unsafe {
        libc::openat(
            std::os::fd::AsRawFd::as_raw_fd(&cache),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    assert!(fd >= 0);
    unsafe { libc::close(fd) };
    for _ in 0..3 {
        let status = rep.scan_native_status().unwrap();
        assert!(ready(&status.status), "{status:?}");
        let root = status
            .displacements
            .iter()
            .find(|v| v.path.is_empty())
            .unwrap();
        assert!(!root.ambiguous && root.versions.is_empty(), "{root:?}");
        assert_eq!(
            root.local_only_changes,
            vec!["cache/blob".to_string(), "cache/new-cache-file".to_string()]
        );
    }
    assert!(rep.list_native_recovery(actor()).unwrap().is_empty());
    assert!(rep.live_status().unwrap().applied);
    // A later structural application is not blocked by local-only activity.
    let mut r = next_of(&rep, &next);
    put_dir(&mut r, "e", 0o755);
    let later = import(&rep, &sorted(r), ChunkSource::Unavailable);
    assert!(ready(&apply(&rep, &later)));
    // Recovery capture refuses paths outside the bound capture policy.
    let copy = d.path().join("forged-copy");
    fs::write(&copy, b"x").unwrap();
    drop(rep);
    let db = rusqlite::Connection::open(d.path().join("state/journal.sqlite")).unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let record = serde_json::json!({"id":id,"operation":OperationId::random().unwrap(),"original_base":base,"source_path":"cache/blob","observed_generation":0,"observed_digest":sha(b"x"),"causal_coverage":"Unknown"});
    db.execute(
        "INSERT INTO native_recovery VALUES(?,?,?,?)",
        rusqlite::params![
            id,
            record["operation"].as_str().unwrap(),
            serde_json::to_vec(&record).unwrap(),
            copy.to_str().unwrap()
        ],
    )
    .unwrap();
    drop(db);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    err(
        rep.capture_native_recovery(
            NativeRecoveryId::parse(id).unwrap(),
            sha(b"x"),
            OperationId::random().unwrap(),
            actor(),
        ),
        "invalid_path",
    );
}

#[test]
fn recovery_capture_uses_current_authority_not_historical_metadata() {
    let (d, rep, n, base) = fixture();
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let next = incoming(d.path(), &rep, &base, false);
    assert!(ready(&apply(&rep, &next)));
    held.write_all(b"late!!").unwrap();
    held.sync_all().unwrap();
    rep.scan_native_status().unwrap();
    let record = rep.list_native_recovery(actor()).unwrap().remove(0);
    // Current authority narrows the path after the application.
    let mut narrowed = next_of(&rep, &next);
    entry_mut(&mut narrowed, "a").mode = 0o000;
    let narrowed = import(&rep, &sorted(narrowed), ChunkSource::Unavailable);
    rep.observe_remote_authority(
        Some(&narrowed),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    err(
        rep.capture_native_recovery(
            record.id.clone(),
            record.observed_digest.clone(),
            OperationId::random().unwrap(),
            actor(),
        ),
        "permission_denied",
    );
    // Revocation also denies; export of the owner's own retained bytes is unaffected.
    rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
        .unwrap();
    err(
        rep.capture_native_recovery(
            record.id.clone(),
            record.observed_digest.clone(),
            OperationId::random().unwrap(),
            actor(),
        ),
        "permission_denied",
    );
}

#[test]
fn explicit_release_frees_unambiguous_retention_and_refuses_ambiguity() {
    let (d, rep, n, base) = fixture();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    let first = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let op = OperationId::random().unwrap();
    let s = rep
        .apply_native_revision(
            &first,
            rep.status().unwrap().generation,
            op.clone(),
            actor(),
        )
        .unwrap();
    assert!(ready(&s), "{s:?}");
    let retained = rep.scan_native_status().unwrap().displacements[0]
        .retained_path
        .clone();
    assert!(retained.exists());
    let freed = rep.release_native_retention(op.clone(), actor()).unwrap();
    assert!(freed >= b"before".len() as u64);
    assert!(!retained.exists(), "released displaced root is removed");
    assert!(rep.scan_native_status().unwrap().displacements.is_empty());
    assert!(ready(&rep.scan_native_status().unwrap().status));
    assert_eq!(fs::read(n.root.join("a")).unwrap(), b"before");
    // Releasing twice is a no-op; never automatic.
    assert_eq!(rep.release_native_retention(op, actor()).unwrap(), 0);
    // Unresolved ambiguity is never released.
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let mut r = next_of(&rep, &first);
    put_dir(&mut r, "e", 0o755);
    let second = import(&rep, &sorted(r), ChunkSource::Unavailable);
    let op = OperationId::random().unwrap();
    assert!(ready(
        &rep.apply_native_revision(
            &second,
            rep.status().unwrap().generation,
            op.clone(),
            actor()
        )
        .unwrap()
    ));
    held.write_all(b"late!!").unwrap();
    held.sync_all().unwrap();
    rep.scan_native_status().unwrap();
    err(
        rep.release_native_retention(op, actor()),
        "dirty_working_state",
    );
    let _ = d;
}

#[test]
fn retained_root_rescans_are_stat_gated() {
    let (d, rep, n, base) = fixture();
    let mut held = fs::OpenOptions::new()
        .write(true)
        .open(n.root.join("a"))
        .unwrap();
    let mut r = next_of(&rep, &base);
    put_dir(&mut r, "d", 0o755);
    let next = import(&rep, &sorted(r), ChunkSource::Unavailable);
    assert!(ready(&apply(&rep, &next)));
    rep.scan_native_status().unwrap();
    let before = retained_hash_bytes_this_thread();
    for _ in 0..3 {
        assert!(ready(&rep.scan_native_status().unwrap().status));
    }
    assert_eq!(
        retained_hash_bytes_this_thread(),
        before,
        "unchanged retained roots are not re-hashed every scan"
    );
    held.write_all(b"late size-changing write").unwrap();
    held.sync_all().unwrap();
    let status = rep.scan_native_status().unwrap();
    assert!(!ready(&status.status), "{status:?}");
    assert!(retained_hash_bytes_this_thread() > before);
    let _ = (d, n);
}

#[test]
fn explicit_release_frees_a_verified_displaced_file_generation() {
    let (d, rep, _n, base) = fixture();
    let next = incoming(d.path(), &rep, &base, false);
    let op = OperationId::random().unwrap();
    assert!(ready(
        &rep.apply_native_revision(&next, rep.status().unwrap().generation, op.clone(), actor())
            .unwrap()
    ));
    let retained = rep.scan_native_status().unwrap().displacements[0]
        .retained_path
        .clone();
    assert_eq!(fs::read(&retained).unwrap(), b"before");
    assert_eq!(rep.release_native_retention(op, actor()).unwrap(), 6);
    assert!(!retained.exists());
    assert!(rep.scan_native_status().unwrap().displacements.is_empty());
    // A later application is admitted normally after release.
    let mut r = next_of(&rep, &next);
    entry_mut(&mut r, "a").content = content(b"third!!!");
    let third = import(&rep, &sorted(r), sources(d.path(), &[b"third!!!"]));
    assert!(ready(&apply(&rep, &third)));
}
