mod support;
use magus_fs_core::*;
use support::*;
fn fixture() -> (tempfile::TempDir, Replica, Workspace, RevisionId) {
    let d = scratch();
    let mut c = config();
    c.history_administrators = vec![principal(1)];
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"old");
    r.tree.entries[0].mode = 0o644;
    let base = import(&rep, &r, local(d.path(), b"old"));
    let w = rep.begin(&base, actor(), false).unwrap();
    (d, rep, w, base)
}
#[test]
fn restored_bytes_are_a_new_attributed_revision_with_current_metadata_and_preserved_head() {
    let (_d, rep, w, old) = fixture();
    let h = w.open("a", OpenMode::Write).unwrap();
    w.write(&h, 0, b"new").unwrap();
    w.chmod("a", 0o600).unwrap();
    let later = w.create("later", 0o600).unwrap();
    w.write(&later, 0, b"keep").unwrap();
    let replaced = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let op = OperationId::random().unwrap();
    let restored = rep.restore_revision(&old, &op, false, actor()).unwrap();
    let r = rep.revision(&restored).unwrap();
    assert_eq!(r.parents, vec![replaced.clone(), old.clone()]);
    assert_eq!(r.principal, principal(1));
    assert_eq!(r.operation, op);
    assert_eq!(
        r.tree.entries.iter().find(|e| e.path == "a").unwrap().mode,
        0o600
    );
    assert!(r.tree.entries.iter().any(|e| e.path == "later"));
    assert_eq!(
        w.read(&w.open("a", OpenMode::Read).unwrap(), 0, 10)
            .unwrap(),
        b"old"
    );
    assert_eq!(
        rep.restore_revision(&old, &op, false, actor()).unwrap(),
        restored
    );
    err(
        rep.restore_revision(&old, &op, true, actor()),
        "operation_mismatch",
    );
    assert!(rep.history().unwrap().contains(&replaced));
}
#[test]
fn deleted_history_needs_scoped_revocable_grant_separate_from_creation() {
    let (d, rep, w, old) = fixture();
    let id = w.lookup("a").unwrap().id;
    w.unlink("a").unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    err(
        rep.restore_revision(&old, &OperationId::random().unwrap(), false, actor()),
        "permission_denied",
    );
    let grant = RetainedHistoryGrant {
        principal: principal(1),
        revision: old.clone(),
        entries: vec![id.clone()],
    };
    err(
        rep.set_retained_history_grants(vec![grant.clone()], Actor::new(principal(2))),
        "permission_denied",
    );
    err(
        rep.set_retained_history_grants(vec![grant.clone(), grant.clone()], actor()),
        "invalid_descriptor",
    );
    rep.set_retained_history_grants(vec![grant.clone()], actor())
        .unwrap();
    err(
        rep.begin(&old, actor(), true)
            .unwrap()
            .open("a", OpenMode::Read),
        "permission_denied",
    );
    rep.set_retained_history_grants(vec![], actor()).unwrap();
    err(
        rep.export(&old, d.path().join("denied"), actor()),
        "permission_denied",
    );
    rep.set_retained_history_grants(vec![grant], actor())
        .unwrap();
    w.chmod("", 0o500).unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    err(
        rep.restore_revision(&old, &OperationId::random().unwrap(), false, actor()),
        "permission_denied",
    );
    w.chmod("", 0o700).unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    drop(w);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    let restored = rep
        .restore_revision(&old, &OperationId::random().unwrap(), false, actor())
        .unwrap();
    let e = &rep.revision(&restored).unwrap().tree.entries[0];
    assert_eq!(e.mode, 0o644);
    assert_eq!(e.owner, principal(1));
    assert_ne!(e.id, id);
    assert_eq!(
        rep.restore_provenance(&restored)
            .unwrap()
            .unwrap()
            .recreated
            .get(&id),
        Some(&e.id)
    );
}
#[test]
fn present_revocation_and_explicit_metadata_use_current_authority() {
    let (_d, rep, w, old) = fixture();
    let id = w.lookup("a").unwrap().id;
    rep.set_retained_history_grants(
        vec![RetainedHistoryGrant {
            principal: principal(1),
            revision: old.clone(),
            entries: vec![id],
        }],
        actor(),
    )
    .unwrap();
    w.chmod("a", 0).unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    err(
        rep.restore_revision(&old, &OperationId::random().unwrap(), true, actor()),
        "permission_denied",
    );
    w.chmod("a", 0o600).unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    let restored = rep
        .restore_revision(&old, &OperationId::random().unwrap(), true, actor())
        .unwrap();
    assert_eq!(rep.revision(&restored).unwrap().tree.entries[0].mode, 0o644);
    w.chown("a", principal(2), group(1)).unwrap();
    w.chmod("", 0o777).unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    err(
        rep.restore_revision(&old, &OperationId::random().unwrap(), false, actor()),
        "permission_denied",
    );
    err(
        rep.restore_revision(
            &old,
            &OperationId::random().unwrap(),
            true,
            Actor::new(principal(2)),
        ),
        "permission_denied",
    );
    err(
        rep.restore_revision(
            &old,
            &OperationId::random().unwrap(),
            false,
            Actor::new(principal(99)),
        ),
        "unknown_principal",
    );
}
#[test]
fn initialization_rejects_unknown_or_duplicate_history_administrators() {
    for admins in [vec![principal(99)], vec![principal(1), principal(1)]] {
        let d = scratch();
        let mut c = config();
        c.history_administrators = admins;
        err(Replica::open(d.path().join("state"), c), "config_mismatch");
    }
}
#[test]
fn deleted_identity_recreation_preserves_replacement_handle_and_denies_sibling_export() {
    let (d, rep, w, old) = fixture();
    let old_id = w.lookup("a").unwrap().id;
    let mut source = rep.revision(&old).unwrap();
    add_file(&mut source, "sibling", b"old");
    source.operation = OperationId::random().unwrap();
    let source_id = import(&rep, &source, ChunkSource::Unavailable);
    w.unlink("a").unwrap();
    let handle = w.create("a", 0o600).unwrap();
    w.write(&handle, 0, b"replacement").unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    rep.set_retained_history_grants(
        vec![RetainedHistoryGrant {
            principal: principal(1),
            revision: source_id.clone(),
            entries: vec![old_id.clone()],
        }],
        actor(),
    )
    .unwrap();
    err(
        rep.export(&source_id, d.path().join("denied-sibling"), actor()),
        "permission_denied",
    );
    rep.set_retained_history_grants(
        vec![RetainedHistoryGrant {
            principal: principal(1),
            revision: old.clone(),
            entries: vec![old_id],
        }],
        actor(),
    )
    .unwrap();
    let restored = rep
        .restore_revision(&old, &OperationId::random().unwrap(), false, actor())
        .unwrap();
    assert_ne!(
        rep.revision(&restored).unwrap().tree.entries[0].id,
        *handle.entry_id()
    );
    assert_eq!(w.read(&handle, 0, 20).unwrap(), b"replacement");
    assert_eq!(
        w.read(&w.open("a", OpenMode::Read).unwrap(), 0, 20)
            .unwrap(),
        b"old"
    );
}
#[test]
fn source_path_cycle_fails_without_displacing_a_present_source_identity() {
    let (_d, rep, w, old) = fixture();
    let b = w.create("b", 0o600).unwrap();
    w.write(&b, 0, b"other").unwrap();
    let both = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    w.rename("a", "temp").unwrap();
    w.rename("b", "a").unwrap();
    w.rename("temp", "b").unwrap();
    let swapped = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    err(
        rep.restore_revision(&both, &OperationId::random().unwrap(), false, actor()),
        "target_collision",
    );
    assert_eq!(rep.status().unwrap().head, Some(swapped));
    assert!(rep.history().unwrap().contains(&old));
}
#[test]
fn v2_import_checks_source_membership_and_fresh_id_mapping_against_both_parents() {
    let (_d, rep, w, old) = fixture();
    let old_id = w.lookup("a").unwrap().id;
    w.unlink("a").unwrap();
    w.checkpoint(
        &OperationId::random().unwrap(),
        w.generation().unwrap(),
        attr(),
    )
    .unwrap();
    rep.set_retained_history_grants(
        vec![RetainedHistoryGrant {
            principal: principal(1),
            revision: old.clone(),
            entries: vec![old_id.clone()],
        }],
        actor(),
    )
    .unwrap();
    let id = rep
        .restore_revision(&old, &OperationId::random().unwrap(), false, actor())
        .unwrap();
    let r = rep.revision(&id).unwrap();
    assert_eq!(r.format, RESTORE_FORMAT);
    for damage in [
        "missing_mapping",
        "wrong_source",
        "wrong_kind",
        "missing_parent",
    ] {
        let mut changed = r.clone();
        changed.operation = OperationId::random().unwrap();
        match damage {
            "missing_mapping" => changed.restoration.as_mut().unwrap().recreated.clear(),
            "wrong_source" => {
                let mapping = &mut changed.restoration.as_mut().unwrap().recreated;
                let fresh = mapping.remove(&old_id).unwrap();
                mapping.insert(EntryId::random().unwrap(), fresh);
            }
            "wrong_kind" => changed.tree.entries[0].content = EntryContent::Directory,
            _ => {
                let missing = RevisionId::parse(format!("sha256:{}", "0".repeat(64))).unwrap();
                changed.parents[0] = missing;
            }
        }
        err(
            rep.import_revision(
                ImportDescriptor {
                    expected: revision_id(&changed).unwrap(),
                    bytes: encode_revision(&changed).unwrap(),
                },
                ChunkSource::Unavailable,
            ),
            if damage == "missing_parent" {
                "not_found"
            } else {
                "invalid_descriptor"
            },
        );
    }
}
