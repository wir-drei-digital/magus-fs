//! Focused FS3 conjunction: content pressure cannot destroy an uncertain request.
mod support;
use magus_fs_core::{protocol::*, *};
use support::*;

#[test]
fn pressure_preserves_frozen_submission_base_and_dirty_bytes_across_restart() {
    let mut observations = vec![];
    for state in [
        SubmissionState::Queued,
        SubmissionState::Failed,
        SubmissionState::Uncertain,
    ] {
        let d = scratch();
        let mut cfg = config();
        cfg.cache_bytes = 12;
        let rep = Replica::open(d.path().join("state"), cfg).unwrap();
        let mut r = revision();
        add_file(&mut r, "data", b"base");
        let base = import(&rep, &r, local(d.path(), b"base"));
        let binding = SyncBinding {
            id: NamespaceId::random().unwrap(),
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::Isolated,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision: base.clone(),
            },
            transport_profile: "/private/tmp/fs3-synthetic-profile.json".into(),
            transport_identity: TransportIdentity::for_bytes(b"fixture").unwrap(),
        };
        rep.configure_sync(binding.clone()).unwrap();
        let w = rep.begin(&base, actor(), false).unwrap();
        let h = w.open("data", OpenMode::ReadWrite).unwrap();
        assert_eq!(w.read(&h, 0, 4).unwrap(), b"base");
        w.write(&h, 0, b"send").unwrap();
        let revision = w
            .checkpoint(
                &OperationId::random().unwrap(),
                w.generation().unwrap(),
                attr(),
            )
            .unwrap();
        rep.enqueue_submission(PendingSubmission {
            operation: rep.revision(&revision).unwrap().operation,
            local_revision: revision,
            original_view: binding.view.view.clone(),
            original_head: binding.view.head.clone(),
            expected_local_generation: w.generation().unwrap(),
        })
        .unwrap();
        let mut frozen = rep.sync_status().unwrap().submissions.remove(0);
        let request = CandidateRequest {
            operation: frozen.operation.clone(),
            replica: config().replica,
            original_view: binding.view.view.clone(),
            original_head: binding.view.head.clone(),
            revision: frozen.local_revision.clone(),
            upload: UploadId::random().unwrap(),
        };
        frozen.request_digest = Some(
            RevisionId::parse(
                ObjectId::for_bytes(&serde_json::to_vec(&request).unwrap())
                    .unwrap()
                    .as_str(),
            )
            .unwrap(),
        );
        frozen.request = Some(request);
        rep.record_sync_progress(&frozen.operation, SubmissionState::Queued, frozen.clone())
            .unwrap();
        if state != SubmissionState::Queued {
            frozen.state = state;
            frozen.error = Some("synthetic_retention_probe".into());
            frozen.remote_outcome_unknown = state == SubmissionState::Uncertain;
            rep.record_sync_progress(&frozen.operation, SubmissionState::Queued, frozen.clone())
                .unwrap();
        }
        w.write(&h, 0, b"edit").unwrap();
        let before = rep.status().unwrap();
        let mut objects_before = vec![];
        for body in [b"base", b"send", b"edit"] {
            let id = ObjectId::for_bytes(body).unwrap();
            assert_eq!(
                rep.sync_object(
                    &id,
                    4,
                    std::time::Instant::now() + std::time::Duration::from_secs(1)
                )
                .unwrap(),
                body
            );
            objects_before.push(id);
        }
        assert_eq!(before.resident_bytes, 12);
        err(w.write(&h, 0, b"more"), "backpressure");
        assert_eq!(w.generation().unwrap(), before.generation);
        assert_eq!(w.read(&h, 0, 4).unwrap(), b"edit");
        assert!(rep.prune(true).unwrap().evictable.is_empty());
        drop(h);
        drop(w);
        drop(rep);
        let rep = Replica::reopen(d.path().join("state")).unwrap();
        assert_eq!(rep.sync_status().unwrap().submissions[0], frozen);
        assert_eq!(rep.status().unwrap().pinned, before.pinned);
        let dry = rep.prune(true).unwrap();
        assert!(dry.evictable.is_empty());
        assert_eq!(rep.apply_prune(&dry.token).unwrap().reclaimed_bytes, 0);
        let w = rep.begin(&base, actor(), false).unwrap();
        assert_eq!(
            w.read(&w.open("data", OpenMode::Read).unwrap(), 0, 4)
                .unwrap(),
            b"edit"
        );
        let mut objects = vec![];
        for body in [b"base", b"send", b"edit"] {
            let id = ObjectId::for_bytes(body).unwrap();
            let actual = rep
                .sync_object(
                    &id,
                    4,
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                )
                .unwrap();
            assert_eq!(actual, body);
            objects.push(id);
        }
        observations.push(serde_json::json!({"state":state,"quota_bytes":12,"resident_before":before.resident_bytes,
            "resident_after":rep.status().unwrap().resident_bytes,"generation":before.generation,"pressure_error":"backpressure",
            "frozen_before":frozen,"frozen_after":rep.sync_status().unwrap().submissions[0],"objects_before":objects_before,"verified_objects":objects,
            "prune":dry,"pins_before":before.pinned,"pins_after":rep.status().unwrap().pinned,"restart_verified":true}));
        drop(w);
        drop(rep);
        // Simulate an already over-budget cache through the object-store API,
        // with the journal owner stopped. Reopen must neither admit nor delete it.
        let cache =
            ObjectStore::open(d.path().join("state/objects"), ObjectLimits::default()).unwrap();
        cache.install(b"more").unwrap();
        err(Replica::reopen(d.path().join("state")), "backpressure");
        for body in [b"base", b"send", b"edit"] {
            assert_eq!(
                cache
                    .read_verified(&ObjectId::for_bytes(body).unwrap())
                    .unwrap(),
                body
            );
        }
        observations.last_mut().unwrap()["overbudget_reopen_error"] =
            serde_json::json!("backpressure");
    }
    println!(
        "FS3_CACHE_OBSERVATIONS {}",
        serde_json::to_string(&observations).unwrap()
    );
}
