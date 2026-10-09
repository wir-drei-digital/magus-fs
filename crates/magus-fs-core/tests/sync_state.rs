mod support;
use magus_fs_core::{protocol::*, *};
use support::*;

fn binding(base: RevisionId) -> SyncBinding {
    SyncBinding {
        id: NamespaceId::random().unwrap(),
        branch: BranchName::parse("main".into()).unwrap(),
        publication: PublicationMode::default(),
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
fn pending(rep: &Replica, b: &SyncBinding, revision: RevisionId) -> PendingSubmission {
    PendingSubmission {
        operation: rep.revision(&revision).unwrap().operation,
        local_revision: revision,
        original_view: b.view.view.clone(),
        original_head: b.view.head.clone(),
        expected_local_generation: rep.status().unwrap().generation,
    }
}
#[test]
fn enqueue_is_immutable_durable_and_defaults_private() {
    let (d, rep, w, base) = setup();
    let b = binding(base);
    assert_eq!(b.publication, PublicationMode::Isolated);
    rep.configure_sync(b.clone()).unwrap();
    let h = w.create("report", 0o600).unwrap();
    w.write(&h, 0, b"retained candidate").unwrap();
    let rev = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let p = pending(&rep, &b, rev.clone());
    rep.enqueue_submission(p.clone()).unwrap();
    let first = rep.sync_status().unwrap().submissions.remove(0);
    rep.enqueue_submission(p.clone()).unwrap();
    assert_eq!(first, rep.sync_status().unwrap().submissions.remove(0));
    let mut different = p.clone();
    different.original_head = HeadToken::random().unwrap();
    err(rep.enqueue_submission(different), "operation_mismatch");
    w.write(&h, 0, b"later dirty state").unwrap();
    assert_eq!(
        rep.sync_status().unwrap().submissions[0].local_revision,
        rev
    );
    drop(h);
    drop(w);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert_eq!(rep.pending_submissions().unwrap(), vec![p]);
    assert_eq!(rep.sync_status().unwrap().submissions[0], first);
    assert_eq!(rep.prune(true).unwrap().protected_bytes, 35);
}
#[test]
fn uncertain_ack_cannot_be_claimed_as_receipt_or_applied() {
    let (_d, rep, _w, base) = setup();
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    let p = pending(&rep, &b, base);
    rep.enqueue_submission(p.clone()).unwrap();
    let mut next = rep.sync_status().unwrap().submissions.remove(0);
    next.state = SubmissionState::Uncertain;
    rep.record_sync_progress(&p.operation, SubmissionState::Queued, next.clone())
        .unwrap();
    next.state = SubmissionState::PrivateRemote;
    err(
        rep.record_sync_progress(&p.operation, SubmissionState::Uncertain, next.clone()),
        "invalid_descriptor",
    );
    next.state = SubmissionState::Uncertain;
    next.applied_revision = Some(p.local_revision);
    err(
        rep.record_sync_progress(&p.operation, SubmissionState::Uncertain, next),
        "unsupported_mode",
    );
}
#[test]
fn queue_pressure_is_atomic_and_retains_originals() {
    let (_d, rep, _w, base) = setup();
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    for _ in 0..128 {
        let mut child = rep.revision(&base).unwrap();
        child.parents = vec![base.clone()];
        child.operation = OperationId::random().unwrap();
        let id = import(&rep, &child, ChunkSource::Unavailable);
        rep.enqueue_submission(pending(&rep, &b, id)).unwrap();
    }
    let mut child = rep.revision(&base).unwrap();
    child.parents = vec![base];
    child.operation = OperationId::random().unwrap();
    let id = import(&rep, &child, ChunkSource::Unavailable);
    err(
        rep.enqueue_submission(pending(&rep, &b, id)),
        "backpressure",
    );
    assert_eq!(rep.pending_submissions().unwrap().len(), 128);
}

#[test]
fn remote_descriptor_is_opaque_and_unverified_bytes_never_cache() {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Instant,
    };
    struct Bad {
        calls: AtomicUsize,
    }
    impl RemoteFetcher for Bad {
        fn fetch(
            &self,
            _source: &RemoteSourceId,
            _id: &ObjectId,
            _size: u64,
            _deadline: Instant,
        ) -> Result<Vec<u8>, FsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(b"bad".to_vec())
        }
    }
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "data", b"correct");
    let source = ChunkSource::Remote {
        source: RemoteSourceId::random().unwrap(),
    };
    let id = import(&rep, &r, source);
    let bad = Arc::new(Bad {
        calls: AtomicUsize::new(0),
    });
    rep.set_remote_fetcher(bad.clone()).unwrap();
    let w = rep.begin(&id, actor(), true).unwrap();
    let h = w.open("data", OpenMode::Read).unwrap();
    for _ in 0..2 {
        err(w.read(&h, 0, 7), "corrupt_object");
    }
    assert_eq!(bad.calls.load(Ordering::SeqCst), 2);
    assert_eq!(rep.status().unwrap().resident_bytes, 0);
}
#[test]
fn denial_preserves_uncertain_outcome_until_exact_receipt() {
    let (_d, rep, _w, base) = setup();
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    let p = pending(&rep, &b, base);
    rep.enqueue_submission(p.clone()).unwrap();
    let mut next = rep.sync_status().unwrap().submissions.remove(0);
    next.state = SubmissionState::Uncertain;
    next.remote_outcome_unknown = true;
    rep.record_sync_progress(&p.operation, SubmissionState::Queued, next.clone())
        .unwrap();
    next.state = SubmissionState::Denied;
    next.error = Some("invalid_credential".into());
    next.remote_outcome_unknown = false;
    err(
        rep.record_sync_progress(&p.operation, SubmissionState::Uncertain, next),
        "invalid_descriptor",
    );
}

#[test]
fn candidate_must_reuse_checkpoint_operation_without_mutating_queue() {
    let (_d, rep, w, base) = setup();
    let b = binding(base);
    rep.configure_sync(b.clone()).unwrap();
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let mut wrong = pending(&rep, &b, id.clone());
    wrong.operation = OperationId::random().unwrap();
    err(rep.enqueue_submission(wrong), "operation_mismatch");
    assert!(rep.pending_submissions().unwrap().is_empty());
    rep.enqueue_submission(pending(&rep, &b, id)).unwrap();
}
#[test]
fn failed_queue_protects_refetchable_base_after_new_checkpoint_and_restart() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "data", b"original");
    let base = import(&rep, &r, local(d.path(), b"original"));
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("data", OpenMode::ReadWrite).unwrap();
    assert_eq!(w.read(&h, 0, 8).unwrap(), b"original");
    w.write(&h, 0, b"candidate").unwrap();
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let pending = pending(&rep, &b, id);
    rep.enqueue_submission(pending.clone()).unwrap();
    let mut p = rep.sync_status().unwrap().submissions.remove(0);
    p.state = SubmissionState::Failed;
    p.error = Some("denied".into());
    rep.record_sync_progress(&pending.operation, SubmissionState::Queued, p)
        .unwrap();
    w.write(&h, 0, b"later edit").unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    drop(h);
    drop(w);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert!(!rep
        .prune(true)
        .unwrap()
        .evictable
        .contains(&ObjectId::for_bytes(b"original").unwrap()));
}
#[test]
fn callback_reentry_is_rejected_without_deadlock() {
    use std::{sync::Arc, time::Instant};
    struct Reentry(std::sync::Weak<Replica>);
    impl RemoteFetcher for Reentry {
        fn fetch(
            &self,
            _: &RemoteSourceId,
            _: &ObjectId,
            _: u64,
            _: Instant,
        ) -> Result<Vec<u8>, FsError> {
            self.0.upgrade().unwrap().status()?;
            Ok(vec![])
        }
    }
    let d = scratch();
    let rep = Arc::new(Replica::open(d.path().join("state"), config()).unwrap());
    let mut r = revision();
    add_file(&mut r, "data", b"x");
    let id = import(
        &rep,
        &r,
        ChunkSource::Remote {
            source: RemoteSourceId::random().unwrap(),
        },
    );
    rep.set_remote_fetcher(Arc::new(Reentry(Arc::downgrade(&rep))))
        .unwrap();
    let w = rep.begin(&id, actor(), true).unwrap();
    let h = w.open("data", OpenMode::Read).unwrap();
    err(w.read(&h, 0, 1), "replica_busy");
}
#[test]
fn authoritative_stale_integration_retains_private_receipt_and_resolves_outcome() {
    let (_d, rep, _w, base) = setup();
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    let pending = pending(&rep, &b, base);
    rep.enqueue_submission(pending.clone()).unwrap();
    let mut p = rep.sync_status().unwrap().submissions.remove(0);
    p.private_receipt = Some(PrivateReceipt {
        receipt: ReceiptId::random().unwrap(),
        operation: p.operation.clone(),
        replica: config().replica,
        submitted_revision: p.local_revision.clone(),
        original_view: b.view.view,
        original_head: b.view.head.clone(),
    });
    p.state = SubmissionState::PrivateRemote;
    rep.record_sync_progress(&p.operation, SubmissionState::Queued, p.clone())
        .unwrap();
    p.integration = Some(IntegrationRequest {
        operation: OperationId::random().unwrap(),
        replica: config().replica,
        candidate_receipt: p.private_receipt.as_ref().unwrap().receipt.clone(),
        expected_head: b.view.head,
        branch: b.branch,
    });
    p.state = SubmissionState::Uncertain;
    p.remote_outcome_unknown = true;
    rep.record_sync_progress(&p.operation, SubmissionState::PrivateRemote, p.clone())
        .unwrap();
    p.state = SubmissionState::Failed;
    p.error = Some("stale_head".into());
    p.remote_outcome_unknown = false;
    rep.record_sync_progress(&p.operation, SubmissionState::Uncertain, p.clone())
        .unwrap();
    assert_eq!(rep.sync_status().unwrap().submissions[0], p);
}

#[test]
fn staged_ancestry_allows_128_descendants_without_counting_issued_base() {
    let (_d, rep, _w, base) = setup();
    let b = binding(base.clone());
    rep.configure_sync(b.clone()).unwrap();
    let mut current = base.clone();
    for _ in 0..128 {
        let mut child = rep.revision(&base).unwrap();
        child.parents = vec![current];
        child.operation = OperationId::random().unwrap();
        current = import(&rep, &child, ChunkSource::Unavailable);
    }
    rep.enqueue_submission(pending(&rep, &b, current.clone()))
        .unwrap();
    let mut child = rep.revision(&current).unwrap();
    child.parents = vec![current];
    child.operation = OperationId::random().unwrap();
    let extra = import(&rep, &child, ChunkSource::Unavailable);
    err(
        rep.enqueue_submission(pending(&rep, &b, extra)),
        "limit_exceeded",
    );
    assert_eq!(rep.pending_submissions().unwrap().len(), 1);
}

#[test]
fn shared_live_private_receipt_remains_pending_for_queue_pressure() {
    let (_d, rep, _w, base) = setup();
    let mut b = binding(base.clone());
    b.publication = PublicationMode::SharedLive;
    rep.configure_sync(b.clone()).unwrap();
    for _ in 0..128 {
        let mut child = rep.revision(&base).unwrap();
        child.parents = vec![base.clone()];
        child.operation = OperationId::random().unwrap();
        let id = import(&rep, &child, ChunkSource::Unavailable);
        rep.enqueue_submission(pending(&rep, &b, id)).unwrap();
    }
    let mut p = rep.sync_status().unwrap().submissions.remove(0);
    p.private_receipt = Some(PrivateReceipt {
        receipt: ReceiptId::random().unwrap(),
        operation: p.operation.clone(),
        replica: config().replica,
        submitted_revision: p.local_revision.clone(),
        original_view: b.view.view.clone(),
        original_head: b.view.head.clone(),
    });
    p.state = SubmissionState::PrivateRemote;
    rep.record_sync_progress(&p.operation, SubmissionState::Queued, p.clone())
        .unwrap();
    assert_eq!(rep.pending_submissions().unwrap().len(), 128);
    let mut child = rep.revision(&base).unwrap();
    child.parents = vec![base];
    child.operation = OperationId::random().unwrap();
    let id = import(&rep, &child, ChunkSource::Unavailable);
    err(
        rep.enqueue_submission(pending(&rep, &b, id)),
        "backpressure",
    );
    assert_eq!(rep.sync_status().unwrap().submissions.len(), 128);
}
