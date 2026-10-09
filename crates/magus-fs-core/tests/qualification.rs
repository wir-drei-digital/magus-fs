//! Direct disk-backed observations consumed by the combined native qualification.
mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn retention_observations() {
    let d = scratch();
    let path = d.path().to_path_buf();
    let mut cfg = config();
    cfg.cache_bytes = 11;
    let rep = Replica::open(path.join("state"), cfg).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"abcdefgh");
    let base = import(&rep, &r, local(&path, b"abcdefgh"));
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    assert_eq!(w.read(&h, 0, 8).unwrap(), b"abcdefgh");
    assert!(rep.prune(true).unwrap().evictable.is_empty());
    drop(h);
    rep.pin(&base, true).unwrap();
    let pinned = rep.prune(true).unwrap();
    assert_eq!(pinned.pinned_bytes, 8);
    assert!(pinned.evictable.is_empty());
    rep.pin(&base, false).unwrap();
    let dry = rep.prune(true).unwrap();
    let applied = rep.apply_prune(&dry.token).unwrap();
    assert_eq!(applied.reclaimed_bytes, 8);
    let h = w.open("a", OpenMode::ReadWrite).unwrap();
    assert_eq!(w.read(&h, 0, 8).unwrap(), b"abcdefgh");
    w.write(&h, 0, b"ACK").unwrap();
    let generation = w.generation().unwrap();
    let quota = w.write(&h, 0, b"overflow").unwrap_err();
    assert_eq!(quota.code(), "backpressure");
    assert_eq!(w.generation().unwrap(), generation);
    assert_eq!(w.read(&h, 0, 3).unwrap(), b"ACK");
    drop(h);
    let head = w
        .checkpoint(&OperationId::random().unwrap(), generation, attr())
        .unwrap();
    let dry = rep.prune(true).unwrap();
    let object = ObjectId::for_bytes(b"abcdefgh").unwrap();
    std::fs::remove_file(path.join("source").join(object.as_str())).unwrap();
    let last = rep.apply_prune(&dry.token).unwrap_err();
    assert_eq!(last.code(), "base_unavailable");
    assert_eq!(rep.status().unwrap().head, Some(head));
    let ack = ObjectId::for_bytes(b"ACK").unwrap();
    std::fs::write(path.join("state/objects").join(ack.as_str()), b"BAD").unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    let corruption = w.read(&h, 0, 3).unwrap_err();
    assert_eq!(corruption.code(), "corrupt_object");
    assert_eq!(
        std::fs::read(path.join("state/objects").join(ack.as_str())).unwrap(),
        b"BAD"
    );
    drop(h);
    drop(w);
    drop(rep);
    d.close().unwrap();
    assert!(!path.exists());
    println!(
        "FS1_OBSERVATION {}",
        serde_json::json!({"quota_error":quota.code(),"generation_unchanged":generation,"corruption_error":corruption.code(),"last_copy_error":last.code(),"pinned_bytes":pinned.pinned_bytes,"reclaimed_bytes":applied.reclaimed_bytes,"ack_bytes":"ACK","cleanup_absent":!path.exists()})
    );
}
