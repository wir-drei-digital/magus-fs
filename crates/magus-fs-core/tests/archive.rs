mod support;
use magus_fs_core::*;
use std::{fs, os::unix::fs::PermissionsExt};
use support::*;
fn mapped() -> ReplicaConfig {
    let mut c = config();
    c.authorities.truncate(1);
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = unsafe { libc::getegid() };
    c
}
fn fixture() -> (tempfile::TempDir, Replica, RevisionId) {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), mapped()).unwrap();
    let mut r = revision();
    add_file(&mut r, "run", b"#!/bin/sh\n");
    r.tree.entries[0].mode = 0o755;
    let first = import(&rep, &r, local(d.path(), b"#!/bin/sh\n"));
    let w = rep.begin(&first, actor(), false).unwrap();
    let h = w.create("._ordinary", 0o644).unwrap();
    w.write(&h, 0, b"visible sidecar").unwrap();
    let second = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    (d, rep, second)
}
#[test]
fn closure_export_is_independent_and_offline_policy_is_explicit() {
    let (d, rep, id) = fixture();
    let path = d.path().join("archive");
    let manifest = rep.export(&id, &path, actor()).unwrap();
    assert_eq!(manifest.revision, id);
    assert_eq!(verify_archive(&path).unwrap().revisions, 2);
    drop(rep);
    fs::rename(d.path().join("state"), d.path().join("inaccessible")).unwrap();
    let policy = ArchiveRestorePolicy {
        authorities: mapped().authorities,
        actor: actor(),
        owner: principal(1),
        group: group(1),
        file_mode: 0o600,
        directory_mode: 0o700,
        entries: vec![ArchiveMetadata {
            path: "run".into(),
            owner: principal(1),
            group: group(1),
            mode: 0o700,
        }],
    };
    let result = restore_archive(&path, d.path().join("output"), policy).unwrap();
    assert_eq!(result.source_revision, id);
    assert!(!result.head_changed);
    assert_eq!(
        fs::read(d.path().join("output/._ordinary")).unwrap(),
        b"visible sidecar"
    );
    assert_eq!(
        fs::read(d.path().join("output/run")).unwrap(),
        b"#!/bin/sh\n"
    );
    assert_eq!(
        fs::metadata(d.path().join("output/run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!d.path().join("output/archive.json").exists());
}
#[test]
fn verifier_refuses_missing_corrupt_extra_links_and_malicious_manifest() {
    for damage in [
        "missing",
        "corrupt",
        "extra",
        "hardlink",
        "symlink",
        "fifo",
        "traversal",
        "size",
        "duplicate",
        "reference",
    ] {
        let (d, rep, id) = fixture();
        let path = d.path().join("archive");
        rep.export(&id, &path, actor()).unwrap();
        let object = fs::read_dir(path.join("objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        match damage {
            "missing" => fs::remove_file(&object).unwrap(),
            "corrupt" => fs::write(&object, b"wrong").unwrap(),
            "extra" => fs::write(path.join("extra"), b"not listed").unwrap(),
            "hardlink" => fs::hard_link(&object, d.path().join("external-link")).unwrap(),
            "symlink" => {
                fs::remove_file(&object).unwrap();
                std::os::unix::fs::symlink(d.path().join("absent"), &object).unwrap();
            }
            "fifo" => {
                fs::remove_file(&object).unwrap();
                let name = std::ffi::CString::new(object.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => {
                let mut m: serde_json::Value =
                    serde_json::from_slice(&fs::read(path.join("archive.json")).unwrap()).unwrap();
                if damage == "duplicate" {
                    let v = m["members"][0].clone();
                    m["members"].as_array_mut().unwrap().push(v);
                } else if damage == "size" {
                    m["members"][0]["length"] = serde_json::json!(u64::MAX);
                } else if damage == "reference" {
                    m["revision"] = serde_json::json!(format!("sha256:{}", "0".repeat(64)));
                } else {
                    m["members"][0]["path"] = serde_json::json!("../escaped");
                }
                fs::write(path.join("archive.json"), serde_json::to_vec(&m).unwrap()).unwrap();
            }
        }
        assert!(verify_archive(&path).is_err(), "{damage}");
    }
}
#[test]
fn export_never_uses_historical_modes_to_override_current_revocation() {
    let (d, rep, id) = fixture();
    let w = rep.begin(&id, actor(), false).unwrap();
    w.chmod("run", 0).unwrap();
    err(
        rep.export(&id, d.path().join("archive"), actor()),
        "permission_denied",
    );
    assert!(!d.path().join("archive").exists());
}
#[test]
fn invalid_offline_policy_cannot_publish_a_destination() {
    let (d, rep, id) = fixture();
    let path = d.path().join("archive");
    rep.export(&id, &path, actor()).unwrap();
    for kind in [
        "unknown_path",
        "duplicate",
        "wrong_group",
        "unknown_actor",
        "unsupported_mode",
    ] {
        let mut policy = ArchiveRestorePolicy {
            authorities: mapped().authorities,
            actor: actor(),
            owner: principal(1),
            group: group(1),
            file_mode: 0o600,
            directory_mode: 0o700,
            entries: vec![],
        };
        match kind {
            "unknown_path" => policy.entries.push(ArchiveMetadata {
                path: "absent".into(),
                owner: principal(1),
                group: group(1),
                mode: 0o600,
            }),
            "duplicate" => {
                let m = ArchiveMetadata {
                    path: "run".into(),
                    owner: principal(1),
                    group: group(1),
                    mode: 0o600,
                };
                policy.entries = vec![m.clone(), m];
            }
            "wrong_group" => policy.group = group(99),
            "unknown_actor" => policy.actor = Actor::new(principal(99)),
            _ => policy.file_mode = 0o4600,
        }
        let out = d.path().join(kind);
        assert!(restore_archive(&path, &out, policy).is_err());
        assert!(!out.exists());
    }
}
