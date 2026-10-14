mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn profile_counts_genuine_metadata_from_another_thread() {
    let (_d, rep, w, base) = setup();
    rep.observe_remote_authority(Some(&base), rep.live_status().unwrap().authority_generation)
        .unwrap();
    rep.set_metadata_profile_enabled(true).unwrap();
    let profile = rep.begin_metadata_profile(&base).unwrap();
    std::thread::spawn(move || w.lookup("").unwrap())
        .join()
        .unwrap();
    let profile = profile.finish();
    assert_eq!(profile.callback_count, 1);
    assert_eq!(profile.load_count, 1);
    assert!(profile.decoded_bytes > 0);
    assert_eq!(profile.copy_count, 0);
    assert!(profile.cpu_inclusive_ns.contains_key("decode"));
}

fn remote_fixture() -> (tempfile::TempDir, Replica, Workspace, Revision, RevisionId) {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    let directory = Entry {
        id: EntryId::random().unwrap(),
        path: "remote".into(),
        parent: r.tree.root.id.clone(),
        owner: principal(1),
        group: group(1),
        mode: 0o755,
        content: EntryContent::Directory,
    };
    add_file(&mut r, "remote/file", b"");
    r.tree.entries[0].parent = directory.id.clone();
    r.tree.entries.push(directory);
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let w = rep.begin_live(&base, actor(), false).unwrap();
    observe(&rep, &base);
    rep.set_metadata_profile_enabled(true).unwrap();
    (d, rep, w, r, base)
}
fn observe(rep: &Replica, id: &RevisionId) {
    rep.observe_remote_authority(Some(id), rep.live_status().unwrap().authority_generation)
        .unwrap();
}
#[test]
fn one_verified_authority_per_metadata_operation() {
    let (_d, rep, w, mut r, base) = remote_fixture();
    let entry = w.lookup("remote/file").unwrap();
    r.operation = OperationId::random().unwrap();
    r.tree
        .entries
        .iter_mut()
        .find(|e| e.path == "remote/file")
        .unwrap()
        .mode = 0o600;
    let authority = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &authority);
    let profile = rep.begin_metadata_profile(&authority).unwrap();
    let projected = w.native_attributes(&entry).unwrap();
    assert_eq!(projected.mode, 0o600);
    assert_eq!(projected.owner, principal(1));
    assert_eq!(projected.group, group(1));
    assert_eq!(projected.id, entry.id);
    assert_eq!(projected.content, entry.content);
    let loads = profile.finish().load_count;
    assert_eq!(
        loads, 1,
        "one locked native-attributes operation must verify authority once"
    );
    let next = rep.begin_metadata_profile(&base).unwrap();
    w.native_attributes(&entry).unwrap();
    assert_eq!(
        next.finish().load_count,
        1,
        "a fresh operation must verify again"
    );
}
#[test]
fn nested_local_metadata_reuses_authority_and_denies_ancestor() {
    let (_d, rep, w, mut r, base) = remote_fixture();
    w.mkdir("remote/local", 0o755).unwrap();
    w.mkdir("remote/local/deep", 0o755).unwrap();
    let h = w.create("remote/local/deep/file", 0o640).unwrap();
    drop(h);
    let entry = w.lookup("remote/local/deep/file").unwrap();
    let profile = rep.begin_metadata_profile(&base).unwrap();
    let projected = w.native_attributes(&entry).unwrap();
    assert_eq!(projected.id, entry.id);
    assert_eq!(projected.mode, 0o640);
    let profile = profile.finish();
    assert_eq!(profile.load_count, 1);
    assert_eq!(
        profile.revision_load_count, 1,
        "the local base is the same verified authority descriptor in this operation"
    );
    r.operation = OperationId::random().unwrap();
    r.tree
        .entries
        .iter_mut()
        .find(|e| e.path == "remote")
        .unwrap()
        .mode = 0;
    let denied = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &denied);
    err(w.native_attributes(&entry), "permission_denied");
    err(w.lookup("remote/local/deep/file"), "permission_denied");
}
#[test]
fn fresh_operation_detects_descriptor_corruption() {
    let (d, _rep, w, mut r, base) = remote_fixture();
    let entry = w.lookup("remote/file").unwrap();
    w.native_attributes(&entry).unwrap();
    r.tree.root.mode = 0o700;
    let bytes = encode_revision(&r).unwrap();
    let db = rusqlite::Connection::open(database(d.path())).unwrap();
    db.execute(
        "UPDATE revisions SET descriptor=? WHERE id=?",
        rusqlite::params![bytes, base.as_str()],
    )
    .unwrap();
    let result = w.native_attributes(&entry);
    assert!(
        matches!(
            result,
            Err(FsError::CorruptObject) | Err(FsError::InvalidDescriptor)
        ),
        "fresh authority corruption must fail closed: {result:?}"
    );
}
#[test]
fn authority_change_and_actor_switch_do_not_reuse_context() {
    let (_d, rep, w, mut r, base) = remote_fixture();
    let entry = w.lookup("remote/file").unwrap();
    w.native_attributes(&entry).unwrap();
    let other = rep
        .begin_live(&base, Actor::new(principal(3)), false)
        .unwrap();
    r.operation = OperationId::random().unwrap();
    r.tree.root.mode = 0o700;
    let restricted = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &restricted);
    w.native_attributes(&entry).unwrap();
    err(other.native_attributes(&entry), "permission_denied");
    r.operation = OperationId::random().unwrap();
    r.tree.entries.clear();
    let revoked = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &revoked);
    err(w.native_attributes(&entry), "permission_denied");
    err(w.lookup_identity(&entry.id), "permission_denied");
}
#[test]
fn historical_attributes_keep_current_denial() {
    let (_d, rep, w, _r, base) = remote_fixture();
    let historical = rep.begin(&base, actor(), true).unwrap();
    let entry = historical.lookup("remote/file").unwrap();
    historical.native_attributes(&entry).unwrap();
    w.chmod("remote", 0).unwrap();
    err(historical.native_attributes(&entry), "permission_denied");
    err(historical.lookup("remote/file"), "permission_denied");
}
#[test]
fn cached_authority_still_observes_serialized_denial_and_actor() {
    let (_d, rep, w, mut r, base) = remote_fixture();
    r.tree.root.mode = 0o700;
    let restricted = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &restricted);
    let other = rep
        .begin_live(&base, Actor::new(principal(3)), false)
        .unwrap();
    let mut result = w.lookup("remote/file").unwrap();
    result.mode = 0;
    assert_eq!(w.lookup("remote/file").unwrap().mode, 0o640);
    err(other.lookup("remote/file"), "permission_denied");
    // Returning to an earlier cached identity does not restore another actor's grant.
    r.operation = OperationId::random().unwrap();
    let next = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &next);
    observe(&rep, &restricted);
    err(other.lookup("remote/file"), "permission_denied");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b = barrier.clone();
    let reader = std::thread::spawn(move || {
        b.wait();
        err(w.lookup("remote/file"), "permission_denied");
    });
    rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
        .unwrap();
    barrier.wait();
    reader.join().unwrap();
}
#[test]
fn base_and_authority_are_independently_verified() {
    let (d, rep, w, mut r, base) = remote_fixture();
    w.mkdir("remote/local", 0o755).unwrap();
    r.operation = OperationId::random().unwrap();
    let authority = import(&rep, &r, ChunkSource::Unavailable);
    observe(&rep, &authority);
    w.lookup("remote/local").unwrap();
    let db = rusqlite::Connection::open(database(d.path())).unwrap();
    db.execute(
        "UPDATE revisions SET descriptor=? WHERE id=?",
        rusqlite::params![b"{".to_vec(), base.as_str()],
    )
    .unwrap();
    err(w.lookup("remote/local"), "invalid_descriptor");
}
#[test]
fn disabled_profile_stays_empty_on_cache_hits() {
    let (_d, rep, w, _r, base) = remote_fixture();
    rep.set_metadata_profile_enabled(false).unwrap();
    let window = rep.begin_metadata_profile(&base).unwrap();
    assert!(!window.is_enabled());
    w.lookup("").unwrap();
    w.lookup("").unwrap();
    let p = window.finish();
    assert_eq!(p.raw_bytes, 0);
    assert_eq!(p.descriptor_hits, 0);
    assert!(p.cpu_exclusive_ns.is_empty());
}
