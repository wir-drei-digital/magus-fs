mod support;
use magus_fs_core::*;
use support::*;
fn pair() -> (tempfile::TempDir, Replica, Workspace, Revision) {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"old");
    let id = import(&rep, &r, local(d.path(), b"old"));
    let w = rep.begin_live(&id, actor(), false).unwrap();
    (d, rep, w, r)
}
fn changed(rep: &Replica, d: &std::path::Path, r: &Revision) -> RevisionId {
    let mut next = r.clone();
    next.operation = OperationId::random().unwrap();
    let mut f = revision();
    add_file(&mut f, "a", b"new-longer");
    next.tree.entries[0].content = f.tree.entries[0].content.clone();
    import(rep, &next, local(d, b"new-longer"))
}
#[test]
fn adoption_pins_old_bytes_and_size_but_new_opens_advance() {
    let (d, rep, w, r) = pair();
    let held = w.open("a", OpenMode::ReadWrite).unwrap();
    let next = changed(&rep, d.path(), &r);
    let adopted = rep
        .adopt_remote_revision(&next, w.generation().unwrap(), actor())
        .unwrap();
    assert_ne!(held.epoch(), adopted.epoch);
    assert_eq!(w.read(&held, 0, 99).unwrap(), b"old");
    let fresh = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(fresh.epoch(), adopted.epoch);
    assert_eq!(w.read(&fresh, 0, 99).unwrap(), b"new-longer");
    assert_eq!(
        w.handle_attributes(&held).unwrap().content,
        r.tree.entries[0].content
    );
    assert!(!rep.live_status().unwrap().applied);
    rep.acknowledge_adoption(&next, adopted.epoch).unwrap();
    assert!(rep.live_status().unwrap().applied);
}
#[test]
fn stale_mutations_fail_before_any_side_effect() {
    let (d, rep, w, r) = pair();
    let held = w.open("a", OpenMode::ReadWrite).unwrap();
    let next = changed(&rep, d.path(), &r);
    rep.adopt_remote_revision(&next, w.generation().unwrap(), actor())
        .unwrap();
    let generation = w.generation().unwrap();
    let size = rep.status().unwrap().resident_bytes;
    err(w.write(&held, 0, b"bad"), "stale_handle");
    err(w.truncate(&held, 0), "stale_handle");
    err(w.chmod_handle(&held, 0), "stale_handle");
    err(
        w.chown_handle(&held, principal(2), group(1)),
        "stale_handle",
    );
    assert_eq!(w.generation().unwrap(), generation);
    assert_eq!(rep.status().unwrap().resident_bytes, size);
}
#[test]
fn dirty_and_stale_generation_retain_the_local_tree() {
    let (d, rep, w, r) = pair();
    let next = changed(&rep, d.path(), &r);
    err(
        rep.adopt_remote_revision(&next, 42, actor()),
        "generation_mismatch",
    );
    let held = w.open("a", OpenMode::ReadWrite).unwrap();
    w.write(&held, 0, b"mine").unwrap();
    err(
        rep.adopt_remote_revision(&next, w.generation().unwrap(), actor()),
        "dirty_working_state",
    );
    assert_eq!(held.epoch(), w.epoch().unwrap());
    assert_eq!(w.read(&held, 0, 99).unwrap(), b"mine");
}
#[test]
fn old_epoch_reads_recheck_current_rights_and_identity() {
    let (d, rep, w, mut r) = pair();
    let held = w.open("a", OpenMode::Read).unwrap();
    r.tree.entries[0].mode = 0;
    r.operation = OperationId::random().unwrap();
    let next = import(&rep, &r, local(d.path(), b"old"));
    rep.adopt_remote_revision(&next, w.generation().unwrap(), actor())
        .unwrap();
    err(w.read(&held, 0, 99), "permission_denied");
    r.tree.entries.clear();
    r.operation = OperationId::random().unwrap();
    let next = import(&rep, &r, ChunkSource::Unavailable);
    rep.adopt_remote_revision(&next, w.generation().unwrap(), actor())
        .unwrap();
    err(w.handle_attributes(&held), "permission_denied");
}
#[test]
fn old_epoch_object_is_protected_until_last_handle_release() {
    let (d, rep, w, r) = pair();
    let held = w.open("a", OpenMode::Read).unwrap();
    w.read(&held, 0, 99).unwrap();
    let next = changed(&rep, d.path(), &r);
    rep.adopt_remote_revision(&next, w.generation().unwrap(), actor())
        .unwrap();
    assert!(!rep
        .prune(true)
        .unwrap()
        .evictable
        .contains(&ObjectId::for_bytes(b"old").unwrap()));
    drop(held);
    assert!(rep
        .prune(true)
        .unwrap()
        .evictable
        .contains(&ObjectId::for_bytes(b"old").unwrap()));
}

#[test]
fn pending_authority_revocation_denies_cached_reads_without_overwriting_dirty_bytes() {
    let (d, rep, w, mut r) = pair();
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    w.write(&h, 0, b"mine").unwrap();
    r.tree.entries[0].mode = 0;
    r.operation = OperationId::random().unwrap();
    let remote = import(&rep, &r, local(d.path(), b"old"));
    rep.observe_remote_authority(
        Some(&remote),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    err(w.read(&h, 0, 99), "permission_denied");
    err(w.write(&h, 0, b"bad"), "permission_denied");
    assert!(rep.status().unwrap().dirty);
    r.tree.entries[0].mode = 0o640;
    r.operation = OperationId::random().unwrap();
    let remote = import(&rep, &r, local(d.path(), b"old"));
    rep.observe_remote_authority(
        Some(&remote),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    assert_eq!(w.read(&h, 0, 99).unwrap(), b"mine");
    rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
        .unwrap();
    err(w.read(&h, 0, 99), "permission_denied");
    err(w.lookup("a"), "permission_denied");
}

#[test]
fn pending_parent_rights_govern_local_creates_without_erasing_private_content() {
    let (d, rep, w, mut r) = pair();
    let local = w.create("private", 0o600).unwrap();
    w.write(&local, 0, b"private").unwrap();
    r.tree.root.mode = 0o555;
    r.operation = OperationId::random().unwrap();
    let remote = import(&rep, &r, local_source(d.path()));
    rep.observe_remote_authority(
        Some(&remote),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    assert_eq!(w.read(&local, 0, 99).unwrap(), b"private");
    err(w.create("forbidden", 0o600), "permission_denied");
    err(w.unlink("private"), "permission_denied");
    r.tree.root.mode = 0;
    r.operation = OperationId::random().unwrap();
    let remote = import(&rep, &r, ChunkSource::Unavailable);
    rep.observe_remote_authority(
        Some(&remote),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    err(w.read(&local, 0, 99), "permission_denied");
}
fn local_source(d: &std::path::Path) -> ChunkSource {
    local(d, b"old")
}

#[test]
fn stale_authority_observation_cannot_undo_a_newer_revocation() {
    let (_d, rep, _w, r) = pair();
    let id = revision_id(&r).unwrap();
    let generation = rep.live_status().unwrap().authority_generation;
    rep.observe_remote_authority(Some(&id), generation).unwrap();
    let current = rep.live_status().unwrap().authority_generation;
    rep.observe_remote_authority(None, current).unwrap();
    err(
        rep.observe_remote_authority(Some(&id), generation),
        "generation_mismatch",
    );
    assert!(!rep.live_status().unwrap().authorized);
}

#[test]
fn pending_authority_governs_handle_metadata_and_remote_removed_identities() {
    let (d, rep, w, mut r) = pair();
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    w.write(&h, 0, b"mine").unwrap();
    let generation = rep.live_status().unwrap().authority_generation;
    rep.observe_remote_authority(None, generation).unwrap();
    err(w.chmod_handle(&h, 0o777), "permission_denied");
    r.tree.entries[0].owner = principal(2);
    r.operation = OperationId::random().unwrap();
    let remote = import(&rep, &r, local(d.path(), b"old"));
    rep.observe_remote_authority(
        Some(&remote),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    err(w.chmod_handle(&h, 0o777), "permission_denied");
    err(w.chmod("a", 0o777), "permission_denied");
    r.tree.entries.clear();
    r.operation = OperationId::random().unwrap();
    let remote = import(&rep, &r, ChunkSource::Unavailable);
    rep.observe_remote_authority(
        Some(&remote),
        rep.live_status().unwrap().authority_generation,
    )
    .unwrap();
    err(w.rename("a", "moved"), "permission_denied");
    err(w.unlink("a"), "permission_denied");
    assert!(rep.status().unwrap().dirty);
}
