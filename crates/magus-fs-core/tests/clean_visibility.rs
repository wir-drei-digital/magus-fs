mod support;
use magus_fs_core::{protocol::*, *};
use support::*;
fn caps() -> CapabilitySnapshot {
    CapabilitySnapshot {
        generation: 0,
        complete: true,
        pinned: Default::default(),
    }
}
fn stamp() -> ObjectId {
    ObjectId::for_bytes(b"credential").unwrap()
}
fn fixture() -> (tempfile::TempDir, Replica, Workspace, Revision, SyncBinding) {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"old");
    add_file(&mut r, "unchanged", b"old");
    let id = import(&rep, &r, local(d.path(), b"old"));
    let w = rep.begin_live(&id, actor(), false).unwrap();
    let b = SyncBinding {
        id: NamespaceId::random().unwrap(),
        branch: BranchName::parse("main".into()).unwrap(),
        publication: PublicationMode::SharedLive,
        source: RemoteSourceId::random().unwrap(),
        view: ViewBinding {
            view: ViewId::random().unwrap(),
            head: HeadToken::random().unwrap(),
            revision: id,
        },
        transport_profile: "/private/tmp/synthetic-profile.json".into(),
        transport_identity: TransportIdentity::for_bytes(b"service").unwrap(),
    };
    rep.configure_sync(b.clone()).unwrap();
    rep.observe_remote_authority(Some(&b.view.revision), 0)
        .unwrap();
    (d, rep, w, r, b)
}
fn next(rep: &Replica, r: &mut Revision, b: &mut SyncBinding) {
    r.operation = OperationId::random().unwrap();
    b.view.revision = import(rep, r, ChunkSource::Unavailable);
    b.view.view = ViewId::random().unwrap();
    b.view.head = HeadToken::random().unwrap();
    b.source = RemoteSourceId::random().unwrap();
    rep.observe_remote_authority(
        Some(&b.view.revision),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
}
fn prepare(rep: &Replica, b: &SyncBinding) -> PreparedCleanVerification {
    rep.prepare_clean_verification(
        b,
        rep.scheduling_snapshot().unwrap().generation,
        actor(),
        &stamp(),
        &caps(),
    )
    .unwrap()
}
fn complete(rep: &Replica, p: PreparedCleanVerification) {
    rep.adopt_prepared_clean(&p).unwrap();
    rep.complete_clean_verification(p, &stamp(), &caps())
        .unwrap();
}
#[test]
fn clean_chain_requires_full_seed() {
    let (_d, rep, _w, mut r, mut b) = fixture();
    rep.acknowledge_adoption(&b.view.revision, rep.live_status().unwrap().epoch)
        .unwrap();
    next(&rep, &mut r, &mut b);
    let p = prepare(&rep, &b);
    assert_eq!(p.mode(), VerificationMode::Full);
    complete(&rep, p);
    r.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 0,
            extents: vec![],
        },
    };
    next(&rep, &mut r, &mut b);
    let p = prepare(&rep, &b);
    assert_eq!(p.mode(), VerificationMode::Affected);
    assert!(p.present().iter().any(|e| e.path == "a"));
    assert!(!p.present().iter().any(|e| e.path == "unchanged"));
    complete(&rep, p);
    assert!(rep.live_status().unwrap().applied);
}
#[test]
fn stale_completion_never_acknowledges_mutation_or_denial() {
    for denial in [false, true] {
        let (_d, rep, w, mut r, mut b) = fixture();
        next(&rep, &mut r, &mut b);
        let p = prepare(&rep, &b);
        rep.adopt_prepared_clean(&p).unwrap();
        if denial {
            rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
                .unwrap();
        } else {
            w.create("local", 0o600).unwrap();
        }
        assert!(rep
            .complete_clean_verification(p, &stamp(), &caps())
            .is_err());
        assert!(!rep.live_status().unwrap().applied);
    }
}
#[test]
fn obligations_cover_atomic_slots_and_ancestors() {
    let (_d, rep, _w, mut r, mut b) = fixture();
    add_file(&mut r, "temporary", b"old");
    next(&rep, &mut r, &mut b);
    complete(&rep, prepare(&rep, &b));
    let old_target = r.tree.entries.remove(0).id;
    let replacement = r
        .tree
        .entries
        .iter_mut()
        .find(|e| e.path == "temporary")
        .unwrap();
    replacement.path = "a".into();
    let replacement_id = replacement.id.clone();
    next(&rep, &mut r, &mut b);
    let p = prepare(&rep, &b);
    assert_eq!(p.mode(), VerificationMode::Affected);
    assert!(p.present().iter().any(|e| e.path.is_empty()));
    assert!(p
        .present()
        .iter()
        .any(|e| e.id == replacement_id && e.path == "a"));
    assert!(!p.present().iter().any(|e| e.id == old_target));
    assert_eq!(p.absent(), &["temporary".to_string()]);
}
#[test]
fn unsupported_changes_and_capabilities_use_full() {
    for case in 0..5 {
        let (_d, rep, _w, mut r, mut b) = fixture();
        next(&rep, &mut r, &mut b);
        complete(&rep, prepare(&rep, &b));
        let mut c = caps();
        match case {
            0 => add_file(&mut r, "new", b"old"),
            1 => r.tree.root.mode = 0o700,
            2 => r.tree.entries[0].mode = 0o600,
            3 => c.complete = false,
            _ => {
                c.pinned.insert(r.tree.entries[0].id.clone());
                r.tree.entries[0].content = EntryContent::File {
                    version: FileVersion {
                        size: 0,
                        extents: vec![],
                    },
                };
            }
        }
        next(&rep, &mut r, &mut b);
        let p = rep
            .prepare_clean_verification(
                &b,
                rep.scheduling_snapshot().unwrap().generation,
                actor(),
                &stamp(),
                &c,
            )
            .unwrap();
        assert_eq!(p.mode(), VerificationMode::Full, "case {case}");
    }
}
#[test]
fn stale_capability_and_credential_completion_never_ack() {
    for credential in [false, true] {
        let (_d, rep, _w, mut r, mut b) = fixture();
        next(&rep, &mut r, &mut b);
        let p = prepare(&rep, &b);
        rep.adopt_prepared_clean(&p).unwrap();
        let mut c = caps();
        let mut s = stamp();
        if credential {
            s = ObjectId::for_bytes(b"rotated").unwrap()
        } else {
            c.generation += 1;
        }
        err(
            rep.complete_clean_verification(p, &s, &c),
            "generation_mismatch",
        );
        assert!(!rep.live_status().unwrap().applied);
    }
}
#[test]
fn mutation_revert_and_restart_break_chain() {
    for reopen in [false, true] {
        let (d, rep, w, mut r, mut b) = fixture();
        next(&rep, &mut r, &mut b);
        complete(&rep, prepare(&rep, &b));
        if reopen {
            drop(w);
            drop(rep);
            let rep = Replica::reopen(d.path().join("state")).unwrap();
            next(&rep, &mut r, &mut b);
            assert_eq!(prepare(&rep, &b).mode(), VerificationMode::Full);
        } else {
            w.chmod("a", 0o600).unwrap();
            w.chmod("a", 0o640).unwrap();
            w.checkpoint(
                &OperationId::random().unwrap(),
                w.generation().unwrap(),
                attr(),
            )
            .unwrap();
            next(&rep, &mut r, &mut b);
            assert_eq!(prepare(&rep, &b).mode(), VerificationMode::Full);
        }
    }
}
#[test]
fn same_id_corruption_never_prepares_or_completes() {
    for target in [false, true] {
        let (d, rep, _w, mut r, mut b) = fixture();
        next(&rep, &mut r, &mut b);
        complete(&rep, prepare(&rep, &b));
        let baseline = b.view.revision.clone();
        next(&rep, &mut r, &mut b);
        let prepared = if target {
            Some(prepare(&rep, &b))
        } else {
            None
        };
        if let Some(p) = &prepared {
            rep.adopt_prepared_clean(p).unwrap();
        }
        let corrupt = if target { &b.view.revision } else { &baseline };
        let db = rusqlite::Connection::open(database(d.path())).unwrap();
        let mut invalid = r.clone();
        invalid.operation = OperationId::random().unwrap();
        db.execute(
            "UPDATE revisions SET descriptor=? WHERE id=?",
            rusqlite::params![encode_revision(&invalid).unwrap(), corrupt.as_str()],
        )
        .unwrap();
        if let Some(p) = prepared {
            assert!(rep
                .complete_clean_verification(p, &stamp(), &caps())
                .is_err());
            assert!(!rep.live_status().unwrap().applied);
        } else {
            assert!(rep
                .prepare_clean_verification(
                    &b,
                    rep.scheduling_snapshot().unwrap().generation,
                    actor(),
                    &stamp(),
                    &caps()
                )
                .is_err());
        }
    }
}
#[test]
fn superseding_adoption_and_intervening_denial_break_chain() {
    let (_d, rep, _w, mut r, mut b) = fixture();
    next(&rep, &mut r, &mut b);
    complete(&rep, prepare(&rep, &b));
    rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
        .unwrap();
    next(&rep, &mut r, &mut b);
    let p = prepare(&rep, &b);
    assert_eq!(p.mode(), VerificationMode::Full);
    rep.adopt_prepared_clean(&p).unwrap();
    next(&rep, &mut r, &mut b);
    rep.adopt_remote_view(
        b.clone(),
        rep.scheduling_snapshot().unwrap().generation,
        actor(),
    )
    .unwrap();
    err(
        rep.complete_clean_verification(p, &stamp(), &caps()),
        "generation_mismatch",
    );
    assert!(!rep.live_status().unwrap().applied);
}
