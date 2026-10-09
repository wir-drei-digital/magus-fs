mod support;
use magus_fs_core::*;
use std::{fs, os::unix::fs::MetadataExt};
use support::*;
fn mapped() -> ReplicaConfig {
    let mut c = config();
    c.authorities.truncate(1);
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = unsafe { libc::getegid() };
    c
}
#[test]
fn bytes_empty_directories_and_exact_mapped_metadata() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), mapped()).unwrap();
    let mut r = revision();
    r.tree.entries.push(Entry {
        path: "empty".into(),
        id: EntryId::random().unwrap(),
        parent: r.tree.root.id.clone(),
        owner: principal(1),
        group: group(1),
        mode: 0o550,
        content: EntryContent::Directory,
    });
    add_file(&mut r, "run", b"#!/bin/sh\n");
    r.tree.entries[1].mode = 0o751;
    let id = import(&rep, &r, local(d.path(), b"#!/bin/sh\n"));
    let dest = d.path().join("full");
    let out = rep
        .materialize(&id, &dest, MaterializationMapping { actor: actor() })
        .unwrap();
    assert_eq!(out.verified_bytes, 10);
    assert_eq!(fs::read(dest.join("run")).unwrap(), b"#!/bin/sh\n");
    assert!(dest.join("empty").is_dir());
    let m = fs::metadata(dest.join("run")).unwrap();
    assert_eq!(m.mode() & 0o777, 0o751);
    assert_eq!(m.uid(), unsafe { libc::geteuid() });
    assert_eq!(m.gid(), unsafe { libc::getegid() });
    err(
        rep.materialize(&id, &dest, MaterializationMapping { actor: actor() }),
        "already_exists",
    );
}
#[test]
fn destination_overlap_and_symlink_ancestors_refused() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), mapped()).unwrap();
    let r = revision();
    let id = import(&rep, &r, ChunkSource::Unavailable);
    err(
        rep.materialize(
            &id,
            d.path().join("state/out"),
            MaterializationMapping { actor: actor() },
        ),
        "storage_overlap",
    );
    std::os::unix::fs::symlink(d.path(), d.path().join("alias")).unwrap();
    err(
        rep.materialize(
            &id,
            d.path().join("alias/out"),
            MaterializationMapping { actor: actor() },
        ),
        "unsafe_storage",
    );
}
#[test]
fn missing_body_preserves_owned_failed_stage_and_no_destination() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), mapped()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"absent");
    let id = import(&rep, &r, ChunkSource::Unavailable);
    let dest = d.path().join("out");
    err(
        rep.materialize(&id, &dest, MaterializationMapping { actor: actor() }),
        "base_unavailable",
    );
    assert!(!dest.exists());
    let stages: Vec<_> = fs::read_dir(d.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".magus-stage-"))
        .collect();
    assert_eq!(stages.len(), 1);
    assert!(fs::read_to_string(stages[0].path().join("ownership.json"))
        .unwrap()
        .contains("failed"));
}
#[test]
fn current_authority_revocation_denies_historical_output() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), mapped()).unwrap();
    let mut r = revision();
    add_file(&mut r, "a", b"bytes");
    let id = import(&rep, &r, local(d.path(), b"bytes"));
    let w = rep.begin(&id, actor(), false).unwrap();
    w.chmod("a", 0).unwrap();
    err(
        rep.materialize(
            &id,
            d.path().join("out"),
            MaterializationMapping { actor: actor() },
        ),
        "permission_denied",
    );
}

#[test]
fn invalid_portable_collision_rejected_before_target_writes() {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), mapped()).unwrap();
    let mut r = revision();
    add_file(&mut r, "CASE", b"x");
    add_file(&mut r, "case", b"x");
    err(
        rep.import_revision(
            ImportDescriptor {
                expected: RevisionId::parse(format!("sha256:{}", "0".repeat(64))).unwrap(),
                bytes: serde_json::to_vec(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        ),
        "invalid_tree",
    );
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
}
#[test]
fn exact_foreign_uid_fails_without_privilege_and_preserves_stage() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let d = scratch();
    let mut c = mapped();
    c.authorities[0].uid = unsafe { libc::geteuid() } + 10000;
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let r = revision();
    let id = import(&rep, &r, ChunkSource::Unavailable);
    err(
        rep.materialize(
            &id,
            d.path().join("out"),
            MaterializationMapping { actor: actor() },
        ),
        "mapping_blocked",
    );
    let recovery = rep.materialization_recovery().unwrap();
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0].status, "failed");
    assert_eq!(recovery[0].error.as_deref(), Some("mapping_blocked"));
    assert!(!d.path().join("out").exists());
}

#[test]
fn actual_native_case_and_normalization_control_aliases_refused() {
    let d = scratch();
    let state = d.path().join("Éstate");
    let rep = Replica::open(&state, mapped()).unwrap();
    let id = import(&rep, &revision(), ChunkSource::Unavailable);
    let aliases = [d.path().join("éSTATE"), d.path().join("E\u{301}state")];
    let mut tested = 0;
    for alias in aliases {
        if let Ok(metadata) = fs::metadata(&alias) {
            if metadata.ino() == fs::metadata(&state).unwrap().ino() {
                tested += 1;
                err(
                    rep.materialize(
                        &id,
                        alias.join("out"),
                        MaterializationMapping { actor: actor() },
                    ),
                    "storage_overlap",
                );
            }
        }
    }
    if cfg!(target_os = "macos") {
        assert_eq!(
            tested, 2,
            "qualification requires actual case/normalization aliases"
        );
    }
    println!("native_aliases_checked={tested}");
}

#[test]
fn historical_content_uses_current_root_directory_file_and_group_metadata() {
    let d = scratch();
    let mut c = mapped();
    let inherited = fs::metadata(d.path()).unwrap().gid();
    let old_gid = c.authorities[0].gid;
    let new_gid = if inherited != old_gid {
        inherited
    } else {
        old_gid + 10000
    };
    let mut other = c.authorities[0].clone();
    other.uid += 10000;
    other.principal = principal(2);
    other.primary_group = group(2);
    other.gid = new_gid;
    other.groups = vec![group(2)];
    c.authorities[0].groups.push(group(2));
    c.authorities.push(other);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    let mut r = revision();
    let dir = EntryId::random().unwrap();
    r.tree.entries.push(Entry {
        path: "dir".into(),
        id: dir.clone(),
        parent: r.tree.root.id.clone(),
        owner: principal(1),
        group: group(1),
        mode: 0o755,
        content: EntryContent::Directory,
    });
    add_file(&mut r, "dir/file", b"historical");
    r.tree.entries[1].parent = dir;
    r.tree.entries[1].mode = 0o644;
    let id = import(&rep, &r, local(d.path(), b"historical"));
    let w = rep.begin(&id, actor(), false).unwrap();
    for path in ["", "dir", "dir/file"] {
        w.chown(path, principal(1), group(2)).unwrap();
        w.chmod(path, if path == "dir/file" { 0o600 } else { 0o700 })
            .unwrap();
    }
    let handle = w.open("dir/file", OpenMode::Write).unwrap();
    w.write(&handle, 0, b"current!!!").unwrap();
    let dest = d.path().join("out");
    let result = rep.materialize(&id, &dest, MaterializationMapping { actor: actor() });
    if unsafe { libc::geteuid() } != 0 && inherited == old_gid {
        err(result, "mapping_blocked");
        assert!(!dest.exists());
        return;
    }
    assert_eq!(result.unwrap().revision, id);
    assert_eq!(fs::read(dest.join("dir/file")).unwrap(), b"historical");
    for path in ["", "dir", "dir/file"] {
        let metadata = fs::metadata(dest.join(path)).unwrap();
        assert_eq!(
            metadata.mode() & 0o777,
            if path == "dir/file" { 0o600 } else { 0o700 }
        );
        assert_eq!(metadata.gid(), new_gid);
    }
    assert_eq!(rep.status().unwrap().head, Some(id));
}
