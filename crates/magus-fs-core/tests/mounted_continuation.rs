mod support;
use magus_fs_core::{protocol::*, *};
use support::*;

fn binding(base: RevisionId) -> SyncBinding {
    SyncBinding {
        id: NamespaceId::random().unwrap(),
        branch: BranchName::parse("main".into()).unwrap(),
        publication: PublicationMode::SharedLive,
        source: RemoteSourceId::random().unwrap(),
        view: ViewBinding {
            view: ViewId::random().unwrap(),
            head: HeadToken::random().unwrap(),
            revision: base,
        },
        transport_profile: "/private/tmp/synthetic-profile.json".into(),
        transport_identity: TransportIdentity::for_bytes(b"fixture").unwrap(),
    }
}

// Catches a second capture silently replacing the original unadmitted operation.
#[test]
fn checkpoint_admission_crash_replays_original() {
    let (d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let h = w.create("draft", 0o600).unwrap();
    w.write(&h, 0, b"first").unwrap();
    let operation = OperationId::random().unwrap();
    let revision = w
        .checkpoint(&operation, w.generation().unwrap(), attr())
        .unwrap();
    w.write(&h, 0, b"later").unwrap();
    err(
        w.checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        ),
        "checkpoint_waiting",
    );
    drop(h);
    drop(w);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert!(matches!(
        rep.checkpoint_readiness().unwrap(),
        CheckpointReadiness::Waiting { .. }
    ));
    assert_eq!(rep.revision(&revision).unwrap().operation, operation);
    let w = rep.begin_live(&revision, actor(), false).unwrap();
    let h = w.open("draft", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 5).unwrap(), b"later");
    err(
        w.checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        ),
        "checkpoint_waiting",
    );
}

#[test]
fn isolated_binding_cannot_enable_mounted_policy() {
    let (_d, rep, w, base) = setup();
    let mut b = binding(base);
    b.publication = PublicationMode::Isolated;
    rep.configure_sync(b.clone()).unwrap();
    err(
        rep.enable_mounted_collaboration(&w, &b, actor()),
        "unsupported_mode",
    );
}

#[test]
fn mounted_owner_requires_same_writable_live_actor() {
    let (_d, rep, w, base) = setup();
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    let ro = rep.begin_live(&base, actor(), true).unwrap();
    err(
        rep.enable_mounted_collaboration(&ro, &b, actor()),
        "read_only",
    );
    err(ro.create("denied", 0o600), "read_only");
    let pinned = rep.begin(&base, actor(), true).unwrap();
    err(
        rep.enable_mounted_collaboration(&pinned, &b, actor()),
        "read_only",
    );
    let (_other_dir, _other, other_owner, _) = setup();
    err(
        rep.enable_mounted_collaboration(&other_owner, &b, actor()),
        "config_mismatch",
    );
    err(
        rep.enable_mounted_collaboration(&w, &b, Actor::new(principal(2))),
        "permission_denied",
    );
    assert_eq!(
        rep.checkpoint_readiness().unwrap(),
        CheckpointReadiness::Ready
    );
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
}

fn published(rep: &Replica, b: &SyncBinding, revision: &RevisionId) -> SharedReceipt {
    let operation = rep.revision(revision).unwrap().operation;
    rep.enqueue_submission(PendingSubmission {
        operation: operation.clone(),
        local_revision: revision.clone(),
        original_view: b.view.view.clone(),
        original_head: b.view.head.clone(),
        expected_local_generation: rep.status().unwrap().generation,
    })
    .unwrap();
    let mut progress = rep.sync_status().unwrap().submissions.remove(0);
    let private = PrivateReceipt {
        receipt: ReceiptId::random().unwrap(),
        operation: operation.clone(),
        replica: config().replica,
        submitted_revision: revision.clone(),
        original_view: b.view.view.clone(),
        original_head: b.view.head.clone(),
    };
    let integration = IntegrationRequest {
        operation: OperationId::random().unwrap(),
        replica: config().replica,
        candidate_receipt: private.receipt.clone(),
        expected_head: b.view.head.clone(),
        branch: b.branch.clone(),
    };
    let shared = SharedReceipt {
        receipt: ReceiptId::random().unwrap(),
        operation: integration.operation.clone(),
        replica: config().replica,
        submitted_revision: revision.clone(),
        branch: b.branch.clone(),
        head: HeadToken::random().unwrap(),
    };
    let request = CandidateRequest {
        operation: operation.clone(),
        replica: config().replica,
        original_view: b.view.view.clone(),
        original_head: b.view.head.clone(),
        revision: revision.clone(),
        upload: UploadId::random().unwrap(),
    };
    progress.request_digest = Some(
        RevisionId::parse(
            ObjectId::for_bytes(&serde_json::to_vec(&request).unwrap())
                .unwrap()
                .as_str(),
        )
        .unwrap(),
    );
    progress.request = Some(request);
    progress.private_receipt = Some(private);
    progress.integration = Some(integration);
    progress.shared_receipt = Some(shared.clone());
    progress.state = SubmissionState::Shared;
    rep.record_sync_progress(&operation, SubmissionState::Queued, progress)
        .unwrap();
    shared
}

fn incoming(rep: &Replica, b: &SyncBinding, r: &Revision, receipt: &SharedReceipt) -> SyncBinding {
    let mut descriptor = r.clone();
    descriptor.parents.clear();
    descriptor.operation = OperationId::random().unwrap();
    let mut next = b.clone();
    next.source = RemoteSourceId::random().unwrap();
    next.view = ViewBinding {
        view: ViewId::random().unwrap(),
        head: receipt.head.clone(),
        revision: import(rep, &descriptor, ChunkSource::Unavailable),
    };
    rep.register_sync_source(next.clone()).unwrap();
    rep.observe_remote_authority(
        Some(&next.view.revision),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    next
}

#[test]
fn own_base_preserves_dirty_epoch_orphans_requests() {
    let (d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let h = w.create("draft", 0o600).unwrap();
    w.write(&h, 0, b"first").unwrap();
    let r1 = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let receipt = published(&rep, &b, &r1);
    w.write(&h, 0, b"later").unwrap();
    let orphan = w.create("orphan", 0o600).unwrap();
    w.write(&orphan, 0, b"held").unwrap();
    w.unlink("orphan").unwrap();
    let next = incoming(&rep, &b, &rep.revision(&r1).unwrap(), &receipt);
    let db = rusqlite::Connection::open(database(d.path())).unwrap();
    let before: Vec<u8> = db
        .query_row("SELECT value FROM working", [], |r| r.get(0))
        .unwrap();
    let queue: Vec<u8> = db
        .query_row("SELECT record FROM sync_queue", [], |r| r.get(0))
        .unwrap();
    let fence = ContinuationFence {
        generation: w.generation().unwrap(),
        head: r1,
        binding: b,
        authority_generation: rep.live_status().unwrap().authority_generation,
        credential_stamp: ObjectId::for_bytes(b"current").unwrap(),
        capability_generation: 0,
    };
    let capabilities = CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    };
    let prepared = rep
        .prepare_continuation(&next, None, &fence, &capabilities, actor())
        .unwrap();
    assert!(matches!(
        rep.commit_continuation(prepared, &fence, &capabilities)
            .unwrap(),
        ContinuationOutcome::OwnBaseAdvanced
    ));
    let after: Vec<u8> = db
        .query_row("SELECT value FROM working", [], |r| r.get(0))
        .unwrap();
    let before: serde_json::Value = serde_json::from_slice(&before).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&after).unwrap();
    for field in ["tree", "orphans", "umask", "epoch"] {
        assert_eq!(before[field], after[field], "{field}");
    }
    assert_eq!(after["dirty"], true);
    assert_eq!(after["applied"], false);
    assert_eq!(
        db.query_row("SELECT record FROM sync_queue", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        queue
    );
    assert_eq!(w.read(&h, 0, 5).unwrap(), b"later");
    assert_eq!(w.read(&orphan, 0, 4).unwrap(), b"held");
    assert!(matches!(
        rep.checkpoint_readiness().unwrap(),
        CheckpointReadiness::Ready
    ));
}

#[test]
fn disjoint_atomic_delta_preserves_foreign_sibling() {
    let (_d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let old = w.create("target", 0o600).unwrap();
    w.write(&old, 0, b"first").unwrap();
    let r1 = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let receipt = published(&rep, &b, &r1);
    let temporary = w.create("temporary", 0o600).unwrap();
    w.write(&temporary, 0, b"replacement").unwrap();
    w.rename("temporary", "target").unwrap();
    let replacement_id = w.handle_attributes(&temporary).unwrap().id;
    let mut remote = rep.revision(&r1).unwrap();
    add_file(&mut remote, "foreign", b"");
    let mut foreign_receipt = receipt.clone();
    foreign_receipt.head = HeadToken::random().unwrap();
    let next = incoming(&rep, &b, &remote, &foreign_receipt);
    let fence = ContinuationFence {
        generation: w.generation().unwrap(),
        head: r1.clone(),
        binding: b,
        authority_generation: rep.live_status().unwrap().authority_generation,
        credential_stamp: ObjectId::for_bytes(b"current").unwrap(),
        capability_generation: 0,
    };
    let capabilities = CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    };
    // Mixed-version discovery can provide current P without inclusion capability.
    // It must retain W and the admitted request, not invent a new candidate/base.
    let frozen = rep.sync_status().unwrap().submissions;
    let before_generation = w.generation().unwrap();
    let unsupported = rep
        .prepare_continuation(&next, None, &fence, &capabilities, actor())
        .unwrap();
    assert!(matches!(
        rep.commit_continuation(unsupported, &fence, &capabilities)
            .unwrap(),
        ContinuationOutcome::Blocked { .. }
    ));
    assert_eq!(w.generation().unwrap(), before_generation);
    assert_eq!(w.read(&temporary, 0, 20).unwrap(), b"replacement");
    assert_eq!(rep.sync_status().unwrap().submissions, frozen);
    let proof = ContinuationProofV1 {
        format: CONTINUATION_PROOF_FORMAT.into(),
        namespace: next.id.clone(),
        request: ContinuationRequestV1 { receipt },
        principal: principal(1),
        published_revision: r1,
        current_revision: revision_id(&remote).unwrap(),
        view: next.view.clone(),
        descriptor_digest: next.view.revision.clone(),
        complete_projection: true,
    };
    let prepared = rep
        .prepare_continuation(&next, Some(&proof), &fence, &capabilities, actor())
        .unwrap();
    assert!(matches!(
        rep.commit_continuation(prepared, &fence, &capabilities)
            .unwrap(),
        ContinuationOutcome::DirtyReconciled { .. }
    ));
    assert_eq!(w.read(&temporary, 0, 20).unwrap(), b"replacement");
    assert_eq!(w.lookup("target").unwrap().id, replacement_id);
    assert!(w.lookup("foreign").is_ok());
    assert!(w.lookup("temporary").is_err());
    assert!(!rep.live_status().unwrap().applied);
    assert!(matches!(
        rep.checkpoint_readiness().unwrap(),
        CheckpointReadiness::Waiting { .. }
    ));
    let snapshot = rep.pending_visibility().unwrap().unwrap();
    w.rename("target", "intermediate").unwrap();
    w.rename("intermediate", "final").unwrap();
    err(
        rep.complete_visibility(&snapshot, &capabilities),
        "generation_mismatch",
    );
    let latest = rep.pending_visibility().unwrap().unwrap();
    assert!(latest.entries.iter().any(|e| e.path == "intermediate"));
    let changed_capabilities = CapabilitySnapshot {
        generation: 1,
        complete: true,
        pinned: Default::default(),
    };
    err(
        rep.complete_visibility(&latest, &changed_capabilities),
        "generation_mismatch",
    );
    rep.complete_visibility(&latest, &capabilities).unwrap();
    assert!(rep.pending_visibility().unwrap().is_none());
    assert!(!rep.live_status().unwrap().applied);
}

#[test]
fn same_identity_or_slot_overlap_retains_conflict() {
    let (d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let old = w.create("target", 0o600).unwrap();
    w.write(&old, 0, b"first").unwrap();
    let r1 = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let receipt = published(&rep, &b, &r1);
    let temporary = w.create("temporary", 0o600).unwrap();
    w.write(&temporary, 0, b"replacement").unwrap();
    w.rename("temporary", "target").unwrap();
    let old_epoch = old.epoch();
    drop(old);
    let replacement_id = w.handle_attributes(&temporary).unwrap().id;
    let mut remote = rep.revision(&r1).unwrap();
    remote.tree.entries[0].mode = 0o640;
    let mut foreign_receipt = receipt.clone();
    foreign_receipt.head = HeadToken::random().unwrap();
    let next = incoming(&rep, &b, &remote, &foreign_receipt);
    let fence = ContinuationFence {
        generation: w.generation().unwrap(),
        head: r1.clone(),
        binding: b,
        authority_generation: rep.live_status().unwrap().authority_generation,
        credential_stamp: ObjectId::for_bytes(b"current").unwrap(),
        capability_generation: 0,
    };
    let capabilities = CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    };
    let proof = ContinuationProofV1 {
        format: CONTINUATION_PROOF_FORMAT.into(),
        namespace: next.id.clone(),
        request: ContinuationRequestV1 { receipt },
        principal: principal(1),
        published_revision: r1,
        current_revision: revision_id(&remote).unwrap(),
        view: next.view.clone(),
        descriptor_digest: next.view.revision.clone(),
        complete_projection: true,
    };
    let prepared = rep
        .prepare_continuation(&next, Some(&proof), &fence, &capabilities, actor())
        .unwrap();
    let outcome = rep
        .commit_continuation(prepared, &fence, &capabilities)
        .unwrap();
    let ContinuationOutcome::Blocked { recovery } = outcome else {
        panic!("overlap must retain recovery")
    };
    assert_eq!(w.lookup("target").unwrap().id, replacement_id);
    assert_eq!(w.read(&temporary, 0, 20).unwrap(), b"replacement");
    assert_eq!(rep.local_work_recovery().unwrap()[0].operation, recovery);
    let export = d.path().join("export");
    rep.export_local_work(&recovery, &export, actor()).unwrap();
    assert_eq!(
        std::fs::read(export.join("target")).unwrap(),
        b"replacement"
    );
    let adoption = rep
        .use_current_remote(&recovery, &next, &fence, actor())
        .unwrap();
    assert!(!rep.live_status().unwrap().applied);
    assert_ne!(adoption.epoch, old_epoch);
    assert_ne!(w.lookup("target").unwrap().id, replacement_id);
    drop(temporary);
    drop(w);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert_eq!(rep.local_work_recovery().unwrap()[0].operation, recovery);
    assert!(matches!(
        rep.checkpoint_readiness().unwrap(),
        CheckpointReadiness::Waiting { .. }
    ));
    let gc = rep.prune(true).unwrap();
    assert!(!gc
        .evictable
        .contains(&ObjectId::for_bytes(b"replacement").unwrap()));
}

#[test]
fn prepared_proof_rotation_is_rejected() {
    let (_d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let h = w.create("draft", 0o600).unwrap();
    let r1 = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let receipt = published(&rep, &b, &r1);
    w.write(&h, 0, b"later").unwrap();
    let next = incoming(&rep, &b, &rep.revision(&r1).unwrap(), &receipt);
    let mut fence = ContinuationFence {
        generation: w.generation().unwrap(),
        head: r1,
        binding: b,
        authority_generation: rep.live_status().unwrap().authority_generation,
        credential_stamp: ObjectId::for_bytes(b"current").unwrap(),
        capability_generation: 0,
    };
    let capabilities = CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    };
    let prepared = rep
        .prepare_continuation(&next, None, &fence, &capabilities, actor())
        .unwrap();
    fence.credential_stamp = ObjectId::for_bytes(b"rotated").unwrap();
    err(
        rep.commit_continuation(prepared, &fence, &capabilities),
        "generation_mismatch",
    );
    fence.credential_stamp = ObjectId::for_bytes(b"current").unwrap();
    let prepared = rep
        .prepare_continuation(&next, None, &fence, &capabilities, actor())
        .unwrap();
    rep.observe_remote_authority(None, fence.authority_generation)
        .unwrap();
    err(
        rep.commit_continuation(prepared, &fence, &capabilities),
        "generation_mismatch",
    );
    assert!(rep.status().unwrap().dirty);
}

#[cfg(feature = "test-faults")]
#[test]
fn continuation_crash_child() {
    let Ok(parent) = std::env::var("TASK3_CRASH_PARENT") else {
        return;
    };
    let point = std::env::var("TASK3_CRASH_POINT").unwrap();
    let (d, rep, w, base) = setup();
    std::fs::write(
        std::path::Path::new(&parent).join("state-path"),
        d.path().join("state").to_str().unwrap(),
    )
    .unwrap();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let handle = w.create("target", 0o600).unwrap();
    w.write(&handle, 0, b"first").unwrap();
    let r1 = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let receipt = published(&rep, &b, &r1);
    w.write(&handle, 0, b"later").unwrap();
    let mut remote = rep.revision(&r1).unwrap();
    add_file(&mut remote, "foreign", b"");
    let mut foreign_receipt = receipt.clone();
    foreign_receipt.head = HeadToken::random().unwrap();
    if point.starts_with("recovery") {
        remote.tree.entries[0].mode = 0o640;
    }
    let next = incoming(&rep, &b, &remote, &foreign_receipt);
    let fence = ContinuationFence {
        generation: w.generation().unwrap(),
        head: r1.clone(),
        binding: b,
        authority_generation: rep.live_status().unwrap().authority_generation,
        credential_stamp: ObjectId::for_bytes(b"current").unwrap(),
        capability_generation: 0,
    };
    let capabilities = CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    };
    let proof = ContinuationProofV1 {
        format: CONTINUATION_PROOF_FORMAT.into(),
        namespace: next.id.clone(),
        request: ContinuationRequestV1 { receipt },
        principal: principal(1),
        published_revision: r1.clone(),
        current_revision: revision_id(&remote).unwrap(),
        view: next.view.clone(),
        descriptor_digest: next.view.revision.clone(),
        complete_projection: true,
    };
    std::fs::write(
        std::path::Path::new(&parent).join("heads"),
        serde_json::to_vec(&(r1, next.view.revision.clone())).unwrap(),
    )
    .unwrap();
    if point.starts_with("continuation") {
        // This child process has no concurrent threads mutating its environment.
        unsafe {
            std::env::set_var("MAGUS_TEST_FAULT_POINT", &point);
        }
    }
    let prepared = rep
        .prepare_continuation(&next, Some(&proof), &fence, &capabilities, actor())
        .unwrap();
    let outcome = rep
        .commit_continuation(prepared, &fence, &capabilities)
        .unwrap();
    if point.starts_with("recovery") {
        let ContinuationOutcome::Blocked { recovery } = outcome else {
            panic!("expected retained conflict")
        };
        unsafe {
            std::env::set_var("MAGUS_TEST_FAULT_POINT", &point);
        }
        rep.use_current_remote(&recovery, &next, &fence, actor())
            .unwrap();
    } else if point == "visibility-before-clear" {
        unsafe {
            std::env::set_var("MAGUS_TEST_FAULT_POINT", &point);
        }
        rep.complete_visibility(&rep.pending_visibility().unwrap().unwrap(), &capabilities)
            .unwrap();
    }
    panic!("fault did not pause");
}

#[cfg(feature = "test-faults")]
#[test]
fn visibility_recovery_schema_and_gc() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for point in [
        "continuation-before-commit",
        "continuation-after-commit",
        "visibility-before-clear",
        "recovery-before-commit",
        "recovery-after-commit",
    ] {
        let parent = scratch();
        let marker = parent.path().join("paused");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "continuation_crash_child", "--nocapture"])
            .env("TASK3_CRASH_PARENT", parent.path())
            .env("TASK3_CRASH_POINT", point)
            .env("MAGUS_TEST_FAULT_ACTION", "pause")
            .env("MAGUS_TEST_FAULT_MARKER", &marker)
            .env_remove("MAGUS_TEST_FAULT_POINT")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !marker.exists() && Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before {point}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let reached = marker.exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(reached, "fault deadline {point}");
        let state = std::fs::read_to_string(parent.path().join("state-path")).unwrap();
        let (original, incoming): (RevisionId, RevisionId) =
            serde_json::from_slice(&std::fs::read(parent.path().join("heads")).unwrap()).unwrap();
        let rep = Replica::reopen(&state).unwrap();
        let status = rep.status().unwrap();
        let committed = point.ends_with("after-commit") || point == "visibility-before-clear";
        assert_eq!(
            status.head,
            Some(if committed { incoming } else { original }),
            "{point}"
        );
        assert!(!rep.live_status().unwrap().applied);
        assert_eq!(
            rep.pending_visibility().unwrap().is_some(),
            committed,
            "{point}"
        );
        assert!(!rep
            .prune(true)
            .unwrap()
            .evictable
            .contains(&ObjectId::for_bytes(b"later").unwrap()));
        let db = rusqlite::Connection::open(std::path::Path::new(&state).join("journal.sqlite"))
            .unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            8
        );
        drop(db);
        drop(rep);
        std::fs::remove_dir_all(std::path::Path::new(&state).parent().unwrap()).unwrap();
    }
}

#[test]
fn denied_authority_retains_durable_local_work() {
    let (d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let h = w.create("draft", 0o600).unwrap();
    w.write(&h, 0, b"retained").unwrap();
    rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
        .unwrap();
    assert!(matches!(
        rep.checkpoint_readiness().unwrap(),
        CheckpointReadiness::Blocked { .. }
    ));
    let recovery = rep.local_work_recovery().unwrap();
    assert_eq!(recovery.len(), 1);
    err(
        rep.export_local_work(
            &recovery[0].operation,
            &d.path().join("denied-export"),
            actor(),
        ),
        "permission_denied",
    );
    drop(h);
    drop(w);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert_eq!(
        rep.local_work_recovery().unwrap()[0].operation,
        recovery[0].operation
    );
    assert!(!rep
        .prune(true)
        .unwrap()
        .evictable
        .contains(&ObjectId::for_bytes(b"retained").unwrap()));
}

#[test]
fn multiple_admitted_candidates_are_never_retargeted() {
    let (_d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    let h = w.create("draft", 0o600).unwrap();
    for body in [b"first".as_slice(), b"second".as_slice()] {
        w.write(&h, 0, body).unwrap();
        let operation = OperationId::random().unwrap();
        let revision = w
            .checkpoint(&operation, w.generation().unwrap(), attr())
            .unwrap();
        rep.enqueue_submission(PendingSubmission {
            operation,
            local_revision: revision,
            original_view: b.view.view.clone(),
            original_head: b.view.head.clone(),
            expected_local_generation: w.generation().unwrap(),
        })
        .unwrap();
    }
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let frozen = rep.pending_submissions().unwrap();
    assert_eq!(frozen.len(), 2);
    w.write(&h, 0, b"later").unwrap();
    err(
        w.checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        ),
        "checkpoint_waiting",
    );
    assert_eq!(rep.pending_submissions().unwrap(), frozen);
    assert_eq!(w.read(&h, 0, 5).unwrap(), b"later");
}

#[test]
fn core_handles_and_unknown_accounting_block_foreign_affected_entries() {
    let (_d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    rep.enable_mounted_collaboration(&w, &b, actor()).unwrap();
    let foreign = w.create("foreign", 0o600).unwrap();
    w.write(&foreign, 0, b"old").unwrap();
    let r1 = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let receipt = published(&rep, &b, &r1);
    let local = w.create("local-new", 0o600).unwrap();
    w.write(&local, 0, b"later").unwrap();
    let mut remote = rep.revision(&r1).unwrap();
    remote.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 0,
            extents: vec![],
        },
    };
    let mut foreign_receipt = receipt.clone();
    foreign_receipt.head = HeadToken::random().unwrap();
    let next = incoming(&rep, &b, &remote, &foreign_receipt);
    let fence = ContinuationFence {
        generation: w.generation().unwrap(),
        head: r1.clone(),
        binding: b,
        authority_generation: rep.live_status().unwrap().authority_generation,
        credential_stamp: ObjectId::for_bytes(b"current").unwrap(),
        capability_generation: 0,
    };
    let mut caps = CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    };
    let proof = ContinuationProofV1 {
        format: CONTINUATION_PROOF_FORMAT.into(),
        namespace: next.id.clone(),
        request: ContinuationRequestV1 { receipt },
        principal: principal(1),
        published_revision: r1,
        current_revision: revision_id(&remote).unwrap(),
        view: next.view.clone(),
        descriptor_digest: next.view.revision.clone(),
        complete_projection: true,
    };
    let p = rep
        .prepare_continuation(&next, Some(&proof), &fence, &caps, actor())
        .unwrap();
    assert!(matches!(
        rep.commit_continuation(p, &fence, &caps).unwrap(),
        ContinuationOutcome::Blocked { .. }
    ));
    assert_eq!(
        rep.local_work_recovery().unwrap()[0].reason,
        "mapping_blocked"
    );
    drop(foreign);
    caps.complete = false;
    let p = rep
        .prepare_continuation(&next, Some(&proof), &fence, &caps, actor())
        .unwrap();
    assert!(matches!(
        rep.commit_continuation(p, &fence, &caps).unwrap(),
        ContinuationOutcome::Blocked { .. }
    ));
    caps.complete = true;
    let p = rep
        .prepare_continuation(&next, Some(&proof), &fence, &caps, actor())
        .unwrap();
    assert!(matches!(
        rep.commit_continuation(p, &fence, &caps).unwrap(),
        ContinuationOutcome::DirtyReconciled { .. }
    ));
    assert_eq!(w.read(&local, 0, 5).unwrap(), b"later");
    // A later current ancestor denial still governs this local-new identity.
    let mut denied = remote;
    denied.tree.root.mode = 0o555;
    let denied_id = import(&rep, &denied, ChunkSource::Unavailable);
    rep.observe_remote_authority(
        Some(&denied_id),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    err(w.create("another-local-new", 0o600), "permission_denied");
    assert!(!rep.live_status().unwrap().applied);
}
