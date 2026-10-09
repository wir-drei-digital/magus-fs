mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn explicit_prune_token_revalidates_new_roots_and_reports_reclaimed_objects() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"remote");
    let base = import(&rep, &r, local(d.path(), b"remote"));
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 6).unwrap(), b"remote");
    drop(h);
    let report = rep.prune(true).unwrap();
    assert_eq!(report.candidate_bytes, 6);
    assert_eq!(report.reachable_bytes, 6);
    assert_eq!(report.pinned_bytes, 0);
    err(rep.prune(false), "prune_token_required");
    rep.pin(&base, true).unwrap();
    err(rep.apply_prune(&report.token), "stale_prune_token");
    assert_eq!(rep.prune(true).unwrap().pinned_bytes, 6);
    rep.pin(&base, false).unwrap();
    let report = rep.prune(true).unwrap();
    let mut other = r.clone();
    other.operation = OperationId::random().unwrap();
    import(&rep, &other, ChunkSource::Unavailable);
    err(rep.apply_prune(&report.token), "stale_prune_token");
    let report = rep.prune(true).unwrap();
    let applied = rep.apply_prune(&report.token).unwrap();
    assert_eq!(applied.reclaimed_bytes, 6);
    assert_eq!(
        applied.reclaimed,
        vec![ObjectId::for_bytes(b"remote").unwrap()]
    );
}
#[test]
fn expired_remote_source_keeps_candidate_bytes_and_returns_base_unavailable() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"retain");
    let base = import(&rep, &r, local(d.path(), b"retain"));
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    w.read(&h, 0, 6).unwrap();
    drop(h);
    let report = rep.prune(true).unwrap();
    std::fs::remove_file(
        d.path()
            .join("source")
            .join(ObjectId::for_bytes(b"retain").unwrap().as_str()),
    )
    .unwrap();
    err(rep.apply_prune(&report.token), "base_unavailable");
    assert_eq!(
        w.read(&w.open("a", OpenMode::Read).unwrap(), 0, 6).unwrap(),
        b"retain"
    );
    assert_eq!(rep.status().unwrap().resident_bytes, 6);
}
#[test]
fn source_alias_of_own_cache_is_not_an_independent_copy() {
    let (d, rep, w, _) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"only copy").unwrap();
    drop(h);
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let r = rep.revision(&id).unwrap();
    import(
        &rep,
        &r,
        ChunkSource::Local {
            path: d.path().join("state/objects"),
        },
    );
    let report = rep.prune(true).unwrap();
    err(rep.apply_prune(&report.token), "base_unavailable");
    assert_eq!(
        w.read(&w.open("a", OpenMode::Read).unwrap(), 0, 99)
            .unwrap(),
        b"only copy"
    );
}
#[test]
fn recovery_pin_protects_ancestry_closure() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut old = revision();
    add_file(&mut old, "a", b"old");
    let first = import(&rep, &old, local(d.path(), b"old"));
    let w = rep.begin(&first, actor(), false).unwrap();
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    w.read(&h, 0, 3).unwrap();
    w.write(&h, 0, b"new").unwrap();
    drop(h);
    let second = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    rep.pin(&second, true).unwrap();
    let report = rep.prune(true).unwrap();
    assert_eq!(report.pinned_bytes, 6);
    assert!(report.evictable.is_empty());
}
