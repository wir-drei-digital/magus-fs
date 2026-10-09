mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn effective_pragmas_schema_owner_and_control_boundary() {
    let (d, rep, w, _) = setup();
    let p = rep.pragmas().unwrap();
    println!("sqlite={p:?}");
    assert_eq!(p.journal_mode, "wal");
    assert_eq!(p.synchronous, 2);
    assert_eq!(p.foreign_keys, 1);
    assert_eq!(p.busy_timeout, 5000);
    if cfg!(target_os = "macos") {
        assert_eq!(p.fullfsync, 1);
    }
    err(
        Replica::open(d.path().join("state"), config()),
        "replica_busy",
    );
    let mut c = config();
    c.content_roots = vec![d.path().join("state")];
    err(
        Replica::open(d.path().join("state/nested"), c),
        "storage_overlap",
    );
    drop(w);
    drop(rep);
    let db = rusqlite::Connection::open(database(d.path())).unwrap();
    db.pragma_update(None, "user_version", 999).unwrap();
    drop(db);
    err(
        Replica::open(d.path().join("state"), config()),
        "unsupported_schema",
    );
}
#[test]
fn import_checks_identity_canonical_format_and_retains_lazy_inventory() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "x", b"uncached");
    let mut descriptor = encode_revision(&r).unwrap();
    descriptor.push(b'\n');
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: revision_id(&r).unwrap(),
                bytes: descriptor,
            },
            ChunkSource::Unavailable,
        ),
        "invalid_descriptor",
    );
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: RevisionId::parse(format!("sha256:{}", "0".repeat(64))).unwrap(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        ),
        "corrupt_object",
    );
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let w = rep.begin(&base, actor(), false).unwrap();
    assert_eq!(w.list("").unwrap().len(), 1);
    let s = rep.status().unwrap();
    assert_eq!(s.resident_bytes, 0);
    assert_eq!(s.missing_bytes, 8);
    assert!(!s.full_ready);
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: base,
                bytes: br#"{"format":"fs0"}"#.to_vec(),
            },
            ChunkSource::Unavailable,
        ),
        "unsupported_format",
    );
}
#[test]
fn checkpoint_is_atomic_idempotent_and_metadata_bound() {
    let (_d, rep, w, base) = setup();
    let h = w.create("a", 0o666).unwrap();
    w.write(&h, 0, b"old").unwrap();
    let op = OperationId::random().unwrap();
    let generation = w.generation().unwrap();
    let id = w.checkpoint(&op, generation, attr()).unwrap();
    assert_eq!(w.checkpoint(&op, generation, attr()).unwrap(), id);
    let mut changed = attr();
    changed.captured_at_ns += 1;
    err(w.checkpoint(&op, generation, changed), "operation_mismatch");
    w.chmod("a", 0o600).unwrap();
    err(w.checkpoint(&op, generation, attr()), "operation_mismatch");
    let second = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    assert_ne!(id, second);
    assert_eq!(rep.history().unwrap().len(), 3);
    let old = rep.revision(&id).unwrap();
    assert_eq!(old.tree.entries[0].mode, 0o644);
    let initial = rep.revision(&base).unwrap();
    assert!(initial.tree.entries.is_empty());
}
#[test]
fn unsafe_database_symlink_is_refused() {
    use std::os::unix::fs::symlink;
    let (d, rep, w, _) = setup();
    drop(w);
    drop(rep);
    std::fs::rename(database(d.path()), d.path().join("saved")).unwrap();
    symlink(d.path().join("saved"), database(d.path())).unwrap();
    err(
        Replica::open(d.path().join("state"), config()),
        "unsafe_storage",
    );
}
#[test]
fn import_refuses_resident_object_length_lies_and_does_not_register_revision() {
    let (_d, rep, w, _) = setup();
    let h = w.create("local", 0o600).unwrap();
    w.write(&h, 0, b"abcdefgh").unwrap();
    let before = rep.history().unwrap();
    let mut r = revision();
    add_file(&mut r, "bad", b"abcdefgh");
    if let EntryContent::File { version } = &mut r.tree.entries[0].content {
        version.size = 9;
        if let Extent::Chunk {
            object_size,
            length,
            ..
        } = &mut version.extents[0]
        {
            *object_size = 9;
            *length = 9
        }
    }
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: revision_id(&r).unwrap(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        ),
        "corrupt_object",
    );
    assert_eq!(rep.history().unwrap(), before);
}
#[test]
fn source_group_mapping_is_unambiguous() {
    let d = scratch();
    let mut c = config();
    c.authorities[1].gid = 999;
    err(Replica::open(d.path().join("state"), c), "config_mismatch");
}
#[test]
fn replacing_the_control_path_refuses_further_workspace_operations() {
    use std::os::unix::fs::PermissionsExt;
    let (d, rep, w, _) = setup();
    w.create("a", 0o600).unwrap();
    std::fs::rename(d.path().join("state"), d.path().join("moved")).unwrap();
    std::fs::create_dir(d.path().join("state")).unwrap();
    std::fs::set_permissions(
        d.path().join("state"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    err(w.lookup("a"), "unsafe_storage");
    err(rep.status(), "unsafe_storage");
}

#[test]
fn reimport_upgrades_source_without_unavailable_downgrade_and_persists() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"abc");
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let source = local(d.path(), b"abc");
    assert_eq!(import(&rep, &r, source), base);
    import(&rep, &r, ChunkSource::Unavailable);
    assert_eq!(rep.history().unwrap().len(), 1);
    drop(rep);
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 3).unwrap(), b"abc");
}

#[test]
fn cross_revision_source_replacement_repairs_stale_source_with_size_consistency() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"abc");
    let base = import(
        &rep,
        &r,
        ChunkSource::Local {
            path: d.path().join("expired"),
        },
    );
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    err(w.read(&h, 0, 3), "base_unavailable");
    let mut bad = r.clone();
    bad.operation = OperationId::random().unwrap();
    if let EntryContent::File { version } = &mut bad.tree.entries[0].content {
        version.size = 2;
        if let Extent::Chunk {
            object_size,
            length,
            ..
        } = &mut version.extents[0]
        {
            *object_size = 2;
            *length = 2
        }
    }
    let source = local(d.path(), b"abc");
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: revision_id(&bad).unwrap(),
                bytes: encode_revision(&bad).unwrap(),
            },
            source.clone(),
        ),
        "corrupt_object",
    );
    assert_eq!(rep.history().unwrap(), vec![base.clone()]);
    err(w.read(&h, 0, 3), "base_unavailable");
    let mut newer = r.clone();
    newer.operation = OperationId::random().unwrap();
    newer.parents = vec![base];
    newer.tree.entries[0].mode = 0o600;
    import(&rep, &newer, source);
    assert_eq!(rep.status().unwrap().resident_bytes, 0);
    assert_eq!(w.read(&h, 0, 3).unwrap(), b"abc");
}
