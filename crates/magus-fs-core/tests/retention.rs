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
    w.write(&h, 0, b"new").unwrap();
    drop(h);
    let second = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    assert_eq!(rep.status().unwrap().resident_bytes, 3);
    rep.pin(&second, true).unwrap();
    assert_eq!(rep.status().unwrap().resident_bytes, 6);
    std::fs::rename(d.path().join("source"), d.path().join("offline-source")).unwrap();
    let archive = d.path().join("archive");
    rep.export(&second, &archive, actor()).unwrap();
    assert_eq!(verify_archive(&archive).unwrap().revisions, 2);
    let report = rep.prune(true).unwrap();
    assert_eq!(report.pinned_bytes, 6);
    assert!(report.evictable.is_empty());
}

#[test]
fn incomplete_ancestry_pin_fails_without_changing_prior_pins_or_working_state() {
    for failure in ["quota", "missing", "corrupt"] {
        let d = scratch();
        let mut cfg = config();
        if failure == "quota" {
            cfg.cache_bytes = 3;
        }
        let rep = Replica::open(d.path().join("state"), cfg).unwrap();
        let empty = import(&rep, &revision(), ChunkSource::Unavailable);
        rep.pin(&empty, true).unwrap();
        let mut old = revision();
        add_file(&mut old, "a", b"old");
        let first = import(&rep, &old, local(d.path(), b"old"));
        let w = rep.begin(&first, actor(), false).unwrap();
        let h = w.open("a", OpenMode::ReadWrite).unwrap();
        w.write(&h, 0, b"new").unwrap();
        drop(h);
        let second = w
            .checkpoint(
                &OperationId::random().unwrap(),
                w.generation().unwrap(),
                attr(),
            )
            .unwrap();
        let source = d
            .path()
            .join("source")
            .join(ObjectId::for_bytes(b"old").unwrap().as_str());
        match failure {
            "missing" => std::fs::remove_file(source).unwrap(),
            "corrupt" => std::fs::write(source, b"bad").unwrap(),
            _ => (),
        }
        let before = rep.status().unwrap();
        err(
            rep.pin(&second, true),
            match failure {
                "quota" => "backpressure",
                "missing" => "base_unavailable",
                _ => "corrupt_object",
            },
        );
        let after = rep.status().unwrap();
        assert_eq!(after.pinned, vec![empty]);
        assert_eq!(before.head, after.head);
        assert_eq!(before.generation, after.generation);
        assert_eq!(
            w.read(&w.open("a", OpenMode::Read).unwrap(), 0, 3).unwrap(),
            b"new"
        );
        drop(w);
        drop(rep);
        assert_eq!(
            Replica::reopen(d.path().join("state"))
                .unwrap()
                .status()
                .unwrap()
                .pinned,
            before.pinned
        );
    }
}
