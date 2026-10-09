mod support;
use magus_fs_core::*;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};
use support::*;
fn native_config(root: &std::path::Path) -> (ReplicaConfig, NativeConfig) {
    let mut c = config();
    c.authorities[0].uid = unsafe { libc::geteuid() };
    c.authorities[0].gid = fs::metadata(root).unwrap().gid();
    c.authorities.truncate(1);
    c.content_roots = vec![root.into()];
    (
        c,
        NativeConfig {
            root: root.into(),
            policy: CapturePolicy {
                included_roots: vec![".".into()],
                excluded_prefixes: vec!["omit".into()],
            },
            creation_umask: 0o022,
        },
    )
}
#[test]
fn native_capture_persists_selection_and_proves_identity() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("empty")).unwrap();
    fs::create_dir(root.join("omit")).unwrap();
    fs::write(root.join("omit/x"), b"ignored").unwrap();
    fs::write(root.join("a"), b"first").unwrap();
    let (c, n) = native_config(&root);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    let first = rep
        .capture(
            &root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    let t = rep.revision(&first).unwrap().tree;
    let id = t.entries.iter().find(|e| e.path == "a").unwrap().id.clone();
    assert_eq!(t.entries.len(), 2);
    drop(rep);
    let rep = Replica::reopen(d.path().join("state")).unwrap();
    assert_eq!(rep.native_config().unwrap(), Some(n.clone()));
    fs::write(root.join("a"), b"second").unwrap();
    let second = rep
        .capture(
            &root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    let t = rep.revision(&second).unwrap().tree;
    assert_eq!(t.entries.iter().find(|e| e.path == "a").unwrap().id, id);
    // Hold the removed inode open to eliminate possible inode reuse in this assertion.
    let old = fs::File::open(root.join("a")).unwrap();
    fs::remove_file(root.join("a")).unwrap();
    fs::write(root.join("a"), b"second").unwrap();
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(root.join("a")).unwrap().ino()
    );
    let third = rep
        .capture(&root, n.policy, OperationId::random().unwrap(), actor())
        .unwrap();
    assert_ne!(
        rep.revision(&third)
            .unwrap()
            .tree
            .entries
            .iter()
            .find(|e| e.path == "a")
            .unwrap()
            .id,
        id
    );
}
#[test]
fn captures_reject_unsupported_inventory_without_advancing() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    let (c, n) = native_config(&root);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    let first = rep
        .capture(
            &root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    symlink("outside", root.join("link")).unwrap();
    fs::write(root.join("a"), b"same").unwrap();
    fs::hard_link(root.join("a"), root.join("b")).unwrap();
    let e = rep
        .capture(&root, n.policy, OperationId::random().unwrap(), actor())
        .unwrap_err();
    assert_eq!(e.code(), "unsupported_entries");
    assert_eq!(rep.status().unwrap().head, Some(first));
    assert!(format!("{e:?}").contains("link"));
    assert!(format!("{e:?}").contains("hardlink"));
}
#[test]
fn root_readonly_policy_does_not_change_control_modes() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
    let (c, n) = native_config(&root);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    let rev = rep
        .capture(&root, n.policy, OperationId::random().unwrap(), actor())
        .unwrap();
    assert_eq!(rep.revision(&rev).unwrap().tree.root.mode, 0o555);
    assert_eq!(
        fs::metadata(d.path().join("state")).unwrap().mode() & 0o777,
        0o700
    );
}
#[test]
fn dirty_work_and_unobserved_renames_are_conservative() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"x").unwrap();
    let (c, n) = native_config(&root);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    let first = rep
        .capture(
            &root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    let id = rep.revision(&first).unwrap().tree.entries[0].id.clone();
    fs::rename(root.join("a"), root.join("b")).unwrap();
    let second = rep
        .capture(
            &root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        )
        .unwrap();
    assert_ne!(rep.revision(&second).unwrap().tree.entries[0].id, id);
    let w = rep.begin(&second, actor(), false).unwrap();
    w.create("dirty", 0o600).unwrap();
    err(
        rep.capture(&root, n.policy, OperationId::random().unwrap(), actor()),
        "dirty_working_state",
    );
    assert!(rep.status().unwrap().dirty);
}

#[test]
fn unmapped_owner_and_policy_roots_fail_without_head() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    let (mut c, mut n) = native_config(&root);
    c.authorities[0].gid = fs::metadata(&root).unwrap().gid() + 42;
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    err(
        rep.capture(
            &root,
            n.policy.clone(),
            OperationId::random().unwrap(),
            actor(),
        ),
        "mapping_blocked",
    );
    assert!(rep.status().unwrap().head.is_none());
    drop(rep);
    let (c, _) = native_config(&root);
    let rep = Replica::open(d.path().join("other"), c).unwrap();
    n.policy.included_roots = vec!["missing".into()];
    rep.configure_native(n.clone()).unwrap();
    err(
        rep.capture(&root, n.policy, OperationId::random().unwrap(), actor()),
        "not_found",
    );
}

#[test]
fn initial_capture_honors_logical_root_authority() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("private"),
        b"must not enter cache before authorization",
    )
    .unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let (mut c, n) = native_config(&root);
    let mut other = c.authorities[0].clone();
    other.principal = principal(2);
    other.uid += 10000;
    other.ownership_transfer = false;
    c.authorities.push(other);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    err(
        rep.capture(
            &root,
            n.policy,
            OperationId::random().unwrap(),
            Actor::new(principal(2)),
        ),
        "permission_denied",
    );
    assert!(rep.history().unwrap().is_empty());
    assert!(
        ObjectStore::open_existing(d.path().join("state/objects"), ObjectLimits::default())
            .unwrap()
            .inventory()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_read_denial_is_not_reported_as_namespace_instability() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("private"), b"denied").unwrap();
    fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o0)).unwrap();
    let (c, n) = native_config(&root);
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    err(
        rep.capture(&root, n.policy, OperationId::random().unwrap(), actor()),
        "permission_denied",
    );
    assert!(rep.history().unwrap().is_empty());
}

#[test]
fn overlapping_inclusions_have_one_effective_frontier() {
    let d = scratch();
    let root = d.path().join("tree");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("a/empty")).unwrap();
    fs::write(root.join("other"), b"unselected").unwrap();
    let (c, mut n) = native_config(&root);
    n.policy.included_roots = vec!["a".into(), "a/empty".into()];
    n.policy.excluded_prefixes = vec![];
    let rep = Replica::open(d.path().join("state"), c).unwrap();
    rep.configure_native(n.clone()).unwrap();
    let id = rep
        .capture(&root, n.policy, OperationId::random().unwrap(), actor())
        .unwrap();
    let rev = rep.revision(&id).unwrap();
    assert_eq!(rev.coverage, vec!["a"]);
    assert_eq!(rev.tree.entries.len(), 2);
}

#[test]
fn captured_metadata_transfer_obeys_current_root_and_file_authority() {
    for root_change in [true, false] {
        let d = scratch();
        let root = d.path().join("tree");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"same").unwrap();
        let (mut c, n) = native_config(&root);
        let old_gid = fs::metadata(&root).unwrap().gid();
        let process_gid = unsafe { libc::getegid() };
        let new_gid = if process_gid != old_gid {
            process_gid
        } else if unsafe { libc::geteuid() } == 0 {
            old_gid + 10000
        } else {
            continue;
        };
        let mut other = c.authorities[0].clone();
        other.uid += 10000;
        other.principal = principal(2);
        other.primary_group = group(2);
        other.gid = new_gid;
        other.groups = vec![group(2)];
        c.authorities.push(other);
        c.authorities[0].ownership_transfer = !root_change;
        if root_change {
            c.authorities[0].groups.push(group(2));
        }
        let rep = Replica::open(d.path().join("state"), c).unwrap();
        rep.configure_native(n.clone()).unwrap();
        let head = rep
            .capture(
                &root,
                n.policy.clone(),
                OperationId::random().unwrap(),
                actor(),
            )
            .unwrap();
        let path = if root_change {
            root.clone()
        } else {
            root.join("file")
        };
        let file = fs::File::open(path).unwrap();
        use std::os::fd::AsRawFd;
        assert_eq!(
            unsafe { libc::fchown(file.as_raw_fd(), libc::uid_t::MAX, new_gid) },
            0
        );
        err(
            rep.capture(&root, n.policy, OperationId::random().unwrap(), actor()),
            "permission_denied",
        );
        assert_eq!(rep.status().unwrap().head, Some(head));
    }
}
