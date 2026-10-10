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
fn unsupported_directory_creation_is_retained_without_modification() {
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
    assert!(matches!(s, NativeApplyStatus::ApplyBlocked { .. }));
    assert!(!n.root.join("directory").exists());
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
