mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn fsync_working_bytes_reopen_without_inventing_revision_or_resetting_dirty_state() {
    let (d, rep, w, base) = setup();
    let h = w.create("a", 0o666).unwrap();
    w.write(&h, 0, b"durable").unwrap();
    w.fsync().unwrap();
    drop(h);
    drop(w);
    drop(rep);
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 99).unwrap(), b"durable");
    assert!(rep.status().unwrap().dirty);
    assert_eq!(rep.history().unwrap().len(), 1);
    let other = import(&rep, &revision(), ChunkSource::Unavailable);
    err(rep.begin(&other, actor(), false), "base_mismatch");
}
#[test]
fn rename_replacement_and_open_unlinked_keep_entry_identity() {
    let (_d, _rep, w, _) = setup();
    let a = w.create("a", 0o600).unwrap();
    w.write(&a, 0, b"first").unwrap();
    let id = w.lookup("a").unwrap().id;
    let b = w.create("b", 0o600).unwrap();
    w.write(&b, 0, b"second").unwrap();
    w.rename("a", "b").unwrap();
    assert_eq!(w.lookup("b").unwrap().id, id);
    assert_eq!(w.read(&b, 0, 20).unwrap(), b"second");
    assert_eq!(w.read(&a, 0, 20).unwrap(), b"first");
    w.unlink("b").unwrap();
    w.write(&a, 0, b"FIRST").unwrap();
    assert_eq!(w.read(&a, 0, 20).unwrap(), b"FIRST");
    let new = w.create("b", 0o600).unwrap();
    assert_ne!(w.lookup("b").unwrap().id, id);
    assert_eq!(w.read(&new, 0, 99).unwrap(), b"");
}
#[test]
fn append_truncate_holes_and_old_revision_bytes() {
    let (_d, rep, w, _) = setup();
    let h = w.create("a", 0o666).unwrap();
    w.write(&h, 0, b"abc").unwrap();
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let append = w.open("a", OpenMode::Append).unwrap();
    w.write(&append, 0, b"de").unwrap();
    w.truncate(&h, 8).unwrap();
    assert_eq!(w.read(&h, 0, 99).unwrap(), b"abcde\0\0\0");
    w.write(&h, 7, b"z").unwrap();
    w.truncate(&h, 4).unwrap();
    assert_eq!(w.read(&h, 0, 99).unwrap(), b"abcd");
    let old = rep.begin(&id, actor(), true).unwrap();
    let oh = old.open("a", OpenMode::Read).unwrap();
    assert_eq!(old.read(&oh, 0, 99).unwrap(), b"abc");
}
#[test]
fn partial_uncached_overwrite_keeps_references_and_missing_is_never_zero() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"abcdefgh");
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    w.write(&h, 2, b"XY").unwrap();
    assert_eq!(w.read(&h, 2, 2).unwrap(), b"XY");
    let start = std::time::Instant::now();
    err(w.read(&h, 0, 8), "base_unavailable");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let rev = rep.revision(&id).unwrap();
    if let EntryContent::File { version } = &rev.tree.entries[0].content {
        assert_eq!(version.extents.len(), 3)
    } else {
        panic!()
    }
    w.write(&h, 0, b"12345678").unwrap();
    assert_eq!(w.read(&h, 0, 99).unwrap(), b"12345678");
}
#[test]
fn cache_verification_pinning_eviction_and_quota_keep_acknowledged_data() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"abcdefgh");
    let base = import(&rep, &r, local(d.path(), b"abcdefgh"));
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 8).unwrap(), b"abcdefgh");
    assert!(rep.prune(true).unwrap().evictable.is_empty());
    drop(h);
    rep.pin(&base, true).unwrap();
    assert!(rep.prune(false).unwrap().evictable.is_empty());
    rep.pin(&base, false).unwrap();
    assert_eq!(rep.prune(true).unwrap().evictable.len(), 1);
    rep.prune(false).unwrap();
    assert_eq!(rep.status().unwrap().resident_bytes, 0);
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    let block = vec![1; 262144];
    for i in 0..128u64 {
        let mut bytes = block.clone();
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        w.write(&h, i * 262144, &bytes).unwrap();
    }
    err(w.write(&h, 128 * 262144, b"overflow"), "backpressure");
    assert_eq!(w.read(&h, 127 * 262144, 8).unwrap(), 127u64.to_le_bytes());
}
#[test]
fn corrupt_and_oversized_source_bytes_are_never_published() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    for payload in [b"XXXXXXXX".to_vec(), vec![b'X'; 40]] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            assert!(conn.read(&mut request).unwrap() > 0);
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = conn.write_all(&payload);
        });
        let d = scratch();
        let rep = Replica::open(d.path().join("state"), config()).unwrap();
        let mut r = revision();
        add_file(&mut r, "a", b"abcdefgh");
        let base = import(&rep, &r, ChunkSource::Http { base_url: url });
        let w = rep.begin(&base, actor(), false).unwrap();
        let h = w.open("a", OpenMode::Read).unwrap();
        err(w.read(&h, 0, 8), "corrupt_object");
        assert_eq!(rep.status().unwrap().resident_bytes, 0);
        server.join().unwrap();
    }
}
#[test]
fn http_stall_is_bounded_and_local_corruption_propagates() {
    use std::{
        net::TcpListener,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (_conn, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(4700));
    });
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"abcdefgh");
    let base = import(&rep, &r, ChunkSource::Http { base_url: url });
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    let start = Instant::now();
    err(w.read(&h, 0, 8), "base_unavailable");
    assert!(start.elapsed() < Duration::from_secs(5));
    server.join().unwrap();
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let base = import(&rep, &r, local(d.path(), b"abcdefgh"));
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    w.read(&h, 0, 8).unwrap();
    let object = ObjectId::for_bytes(b"abcdefgh").unwrap();
    std::fs::write(
        d.path().join("state/objects").join(object.as_str()),
        b"corrupt!",
    )
    .unwrap();
    err(w.read(&h, 0, 8), "corrupt_object");
    err(rep.status(), "corrupt_object");
}
#[test]
fn extent_backpressure_preserves_previous_tree_and_does_not_install_bytes() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"x");
    if let EntryContent::File { version } = &mut r.tree.entries[0].content {
        let chunk = version.extents[0].clone();
        version.extents = (0..50000)
            .flat_map(|_| [chunk.clone(), Extent::Hole { length: 2 }])
            .collect();
        version.size = 150000;
    }
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    let before = w.lookup("a").unwrap();
    err(w.write(&h, 2, b"y"), "backpressure");
    assert_eq!(w.lookup("a").unwrap(), before);
    assert_eq!(rep.status().unwrap().resident_bytes, 0);
}
#[test]
fn negative_authority_and_foreign_handles_do_not_mutate_state() {
    let (_d, rep, w, base) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"abc").unwrap();
    let other = rep.begin(&base, actor(), false).unwrap();
    err(other.read(&h, 0, 3), "stale_handle");
    err(other.write(&h, 0, b"bad"), "stale_handle");
    assert_eq!(w.read(&h, 0, 3).unwrap(), b"abc");
    let ro = rep.begin(&base, actor(), true).unwrap();
    err(ro.write(&h, 0, b"bad"), "read_only");
    err(ro.truncate(&h, 0), "read_only");
    err(ro.rename("a", "b"), "read_only");
    err(
        ro.checkpoint(&OperationId::random().unwrap(), 0, attr()),
        "read_only",
    );
}
#[test]
fn one_read_shares_a_single_deadline_across_multiple_missing_chunks() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for byte in [b'a', b'b'] {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            assert!(conn.read(&mut request).unwrap() > 0);
            std::thread::sleep(Duration::from_millis(2600));
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n");
            let _ = conn.write_all(&[byte]);
        }
    });
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"a");
    if let EntryContent::File { version } = &mut r.tree.entries[0].content {
        version.size = 2;
        version.extents.push(Extent::Chunk {
            object: ObjectId::for_bytes(b"b").unwrap(),
            object_size: 1,
            offset: 0,
            length: 1,
        });
    }
    let base = import(&rep, &r, ChunkSource::Http { base_url: url });
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    let start = Instant::now();
    let result = w.read(&h, 0, 2);
    let elapsed = start.elapsed();
    server.join().unwrap();
    err(result, "base_unavailable");
    assert!(elapsed < Duration::from_secs(5));
}
#[test]
fn missing_local_source_is_not_created_by_a_read() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"a");
    let path = d.path().join("absent-source");
    let base = import(&rep, &r, ChunkSource::Local { path: path.clone() });
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    err(w.read(&h, 0, 1), "base_unavailable");
    assert!(!path.exists());
}
#[test]
fn interrupted_staging_bytes_count_toward_the_total_quota() {
    use std::os::unix::fs::PermissionsExt;
    let (d, rep, w, _) = setup();
    drop(w);
    drop(rep);
    let path = d.path().join("state/objects").join(format!(
        ".stage-{}",
        OperationId::random().unwrap().as_str()
    ));
    let file = std::fs::File::create(&path).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    file.set_len(32 * 1024 * 1024 + 1).unwrap();
    file.sync_all().unwrap();
    drop(file);
    err(
        Replica::open(d.path().join("state"), config()),
        "backpressure",
    );
    assert!(path.exists());
}
#[test]
fn hostname_sources_are_rejected_before_registration_or_dns() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let r = revision();
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: revision_id(&r).unwrap(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Http {
                base_url: "http://localhost:12345/objects".into(),
            },
        ),
        "invalid_source",
    );
    assert!(rep.history().unwrap().is_empty());
}
#[test]
fn missing_source_preserves_underlying_error_context() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"a");
    let base = import(
        &rep,
        &r,
        ChunkSource::Local {
            path: d.path().join("missing"),
        },
    );
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    let e = w.read(&h, 0, 1).unwrap_err();
    assert_eq!(e.code(), "base_unavailable");
    assert!(std::error::Error::source(&e).is_some());
}
#[test]
fn numeric_ipv6_immutable_source_works_without_dns() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut req = [0; 4096];
        assert!(conn.read(&mut req).unwrap() > 0);
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\na")
            .unwrap();
    });
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"a");
    let base = import(&rep, &r, ChunkSource::Http { base_url: url });
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 1).unwrap(), b"a");
    server.join().unwrap();
}
#[test]
fn concurrent_unlink_cannot_invalidate_a_successfully_created_handle() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let (_d, _rep, w, _) = setup();
    let quit = Arc::new(AtomicBool::new(false));
    let worker = w.clone();
    let done = quit.clone();
    let remover = std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            match worker.unlink("race") {
                Ok(()) => {}
                Err(e) if e.code() == "not_found" => {}
                Err(e) => panic!("unlink: {e}"),
            };
            std::thread::yield_now();
        }
    });
    let mut stale = 0;
    let mut created = 0;
    for _ in 0..100 {
        match w.create("race", 0o600) {
            Ok(h) => {
                created += 1;
                if let Err(e) = w.write(&h, 0, b"valid handle") {
                    if e.code() == "stale_handle" {
                        stale += 1
                    } else {
                        panic!("write: {e}")
                    }
                }
            }
            Err(e) if e.code() == "already_exists" => {}
            Err(e) => panic!("create: {e}"),
        };
        std::thread::yield_now();
    }
    quit.store(true, Ordering::Relaxed);
    remover.join().unwrap();
    assert!(created > 0);
    assert_eq!(stale, 0);
}

#[test]
fn explicit_prune_recovers_small_quota_after_repeated_uncheckpointed_overwrites() {
    let d = scratch();
    let mut c = config();
    c.cache_bytes = 6;
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let base = import(&rep, &revision(), ChunkSource::Unavailable);
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"old").unwrap();
    drop(h);
    for n in 0..12u8 {
        let h = w.open("a", OpenMode::ReadWrite).unwrap();
        let bytes = [n, 42, 99];
        w.write(&h, 0, &bytes).unwrap();
        assert!(rep.prune(true).unwrap().evictable.is_empty());
        err(w.write(&h, 0, b"xxx"), "backpressure");
        drop(h);
        let dry = rep.prune(true).unwrap();
        assert_eq!(dry.reclaimable_bytes, 3);
        assert_eq!(dry.evictable.len(), 1);
        assert_eq!(rep.status().unwrap().resident_bytes, 6);
        rep.prune(false).unwrap();
        assert_eq!(rep.status().unwrap().resident_bytes, 3);
        let h = w.open("a", OpenMode::Read).unwrap();
        assert_eq!(w.read(&h, 0, 3).unwrap(), bytes);
        drop(h);
    }
}

#[test]
fn unreachable_garbage_pruning_retains_committed_local_history() {
    let (d, rep, w, base) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"old").unwrap();
    let old = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    w.write(&h, 0, b"mid").unwrap();
    w.write(&h, 0, b"new").unwrap();
    drop(h);
    let report = rep.prune(true).unwrap();
    assert_eq!(report.evictable, vec![ObjectId::for_bytes(b"mid").unwrap()]);
    rep.prune(false).unwrap();
    assert_eq!(rep.status().unwrap().resident_bytes, 6);
    drop(w);
    drop(rep);
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let historical = rep.begin(&old, actor(), true).unwrap();
    let h = historical.open("a", OpenMode::Read).unwrap();
    assert_eq!(historical.read(&h, 0, 3).unwrap(), b"old");
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 3).unwrap(), b"new");
    assert!(rep.prune(true).unwrap().evictable.is_empty());
    assert_eq!(rep.history().unwrap(), vec![base, old]);
}

#[test]
fn unreachable_unlinked_local_bytes_wait_for_last_handle_close() {
    let (_d, rep, w, _) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"abc").unwrap();
    w.unlink("a").unwrap();
    assert!(rep.prune(true).unwrap().evictable.is_empty());
    assert_eq!(w.read(&h, 0, 3).unwrap(), b"abc");
    drop(h);
    assert_eq!(rep.prune(false).unwrap().reclaimable_bytes, 3);
    assert_eq!(rep.status().unwrap().resident_bytes, 0);
}
#[test]
fn adapter_identity_lookup_and_handle_attributes_do_not_resurrect_or_leak_unsearchable_children() {
    let (_d, rep, w, _base) = setup();
    assert_eq!(rep.configuration().unwrap(), config());
    let h = w.create("held", 0o600).unwrap();
    w.write(&h, 0, b"held bytes").unwrap();
    let id = w.lookup("held").unwrap().id;
    w.rename("held", "moved").unwrap();
    assert_eq!(w.lookup_identity(&id).unwrap().path, "moved");
    w.unlink("moved").unwrap();
    err(w.lookup_identity(&id), "not_found");
    assert_eq!(w.handle_attributes(&h).unwrap().id, id);
    w.mkdir("directory", 0o700).unwrap();
    w.create("directory/child", 0o600).unwrap();
    w.chmod("directory", 0o400).unwrap();
    let names = w.directory_entries("directory").unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].0, "child");
    assert!(!names[0].2);
    err(w.lookup_identity(&names[0].1), "permission_denied");
    err(w.lookup("directory/child"), "permission_denied");
}
