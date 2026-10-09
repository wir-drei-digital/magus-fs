mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn owner_group_other_forged_ids_and_fixed_mapping() {
    let (_d, rep, w, base) = setup();
    w.create("a", 0o660).unwrap();
    w.chmod("a", 0o640).unwrap();
    assert_eq!(w.lookup("a").unwrap().mode, 0o640);
    let group = rep.begin(&base, Actor::new(principal(2)), false).unwrap();
    assert!(group.open("a", OpenMode::Read).is_ok());
    err(group.open("a", OpenMode::ReadWrite), "permission_denied");
    err(group.chmod("a", 0o777), "permission_denied");
    let other = rep.begin(&base, Actor::new(principal(3)), false).unwrap();
    err(other.open("a", OpenMode::Read), "permission_denied");
    err(
        rep.begin(&base, Actor::new(principal(999)), false),
        "unknown_principal",
    );
    assert_eq!(rep.actor_for_uid(1002).unwrap(), Actor::new(principal(2)));
    err(rep.actor_for_uid(999), "unknown_principal");
    w.chmod("a", 0).unwrap();
    err(w.open("a", OpenMode::Read), "permission_denied");
    err(w.chmod("a", 0o4755), "unsupported_mode");
    err(
        group.chown("a", principal(2), group_id()),
        "permission_denied",
    );
    w.chown("a", principal(2), group_id()).unwrap();
}
fn group_id() -> GroupId {
    support::group(1)
}
#[test]
fn directory_search_listing_parent_checks_and_readonly_file_unlink() {
    let (_d, rep, w, base) = setup();
    w.mkdir("d", 0o777).unwrap();
    w.create("d/a", 0o600).unwrap();
    w.chmod("d", 0o400).unwrap();
    assert_eq!(w.list("d").unwrap(), vec!["a"]);
    err(w.lookup("d/a"), "permission_denied");
    w.chmod("d", 0o100).unwrap();
    assert!(w.lookup("d/a").is_ok());
    err(w.list("d"), "permission_denied");
    w.chmod("d", 0o700).unwrap();
    w.chmod("d/a", 0o400).unwrap();
    w.unlink("d/a").unwrap();
    w.mkdir("dest", 0o700).unwrap();
    w.create("src", 0o600).unwrap();
    w.chmod("dest", 0o500).unwrap();
    err(w.rename("src", "dest/a"), "permission_denied");
    assert!(w.lookup("src").is_ok());
    let _ = rep.begin(&base, actor(), false).unwrap();
}
#[test]
fn readonly_denial_precedes_confined_root_override_and_current_authority() {
    let (_d, rep, w, _base) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"private").unwrap();
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let ro = rep.begin(&id, Actor::new(principal(4)), true).unwrap();
    err(ro.open("a", OpenMode::ReadWrite), "read_only");
    err(ro.chmod("a", 0o777), "read_only");
    err(ro.unlink("a"), "read_only");
    err(ro.mkdir("x", 0o777), "read_only");
    err(ro.chown("a", principal(4), support::group(1)), "read_only");
    let old = rep.begin(&id, actor(), true).unwrap();
    w.chmod("a", 0).unwrap();
    err(old.open("a", OpenMode::Read), "permission_denied");
}
#[test]
fn write_only_handles_and_append_do_not_require_or_grant_read_access() {
    let (_d, _rep, w, _) = setup();
    let _created = w.create("a", 0o200).unwrap();
    let h = w.open("a", OpenMode::Write).unwrap();
    w.write(&h, 0, b"a").unwrap();
    err(w.read(&h, 0, 1), "permission_denied");
    let append = w.open("a", OpenMode::Append).unwrap();
    w.write(&append, 0, b"b").unwrap();
    w.chmod("a", 0o600).unwrap();
    err(w.read(&h, 0, 2), "permission_denied");
    let read = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&read, 0, 2).unwrap(), b"ab");
}

#[test]
fn historical_lookup_list_and_open_follow_current_grants_and_revocations() {
    let (_d, rep, w, _) = setup();
    w.mkdir("dir", 0o700).unwrap();
    let h = w.create("dir/file", 0o600).unwrap();
    w.write(&h, 0, b"history").unwrap();
    drop(h);
    w.chmod("dir/file", 0).unwrap();
    w.chmod("dir", 0).unwrap();
    w.chmod("", 0).unwrap();
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let old = rep.begin(&id, actor(), true).unwrap();
    err(old.lookup("dir/file"), "permission_denied");
    err(old.list("dir"), "permission_denied");
    err(old.open("dir/file", OpenMode::Read), "permission_denied");
    w.chmod("", 0o700).unwrap();
    w.chmod("dir", 0o700).unwrap();
    w.chmod("dir/file", 0o600).unwrap();
    assert_eq!(old.lookup("dir/file").unwrap().mode, 0);
    assert_eq!(old.list("dir").unwrap(), vec!["file"]);
    let old_handle = old.open("dir/file", OpenMode::Read).unwrap();
    assert_eq!(old.read(&old_handle, 0, 7).unwrap(), b"history");
    w.chmod("dir", 0).unwrap();
    err(old.lookup("dir/file"), "permission_denied");
    err(old.list("dir"), "permission_denied");
    err(old.open("dir/file", OpenMode::Read), "permission_denied");
    err(old.read(&old_handle, 0, 7), "permission_denied");
    w.chmod("dir", 0o700).unwrap();
    w.unlink("dir/file").unwrap();
    err(old.lookup("dir/file"), "permission_denied");
    err(old.open("dir/file", OpenMode::Read), "permission_denied");
    w.unlink("dir").unwrap();
    err(old.list("dir"), "permission_denied");
}

#[test]
fn historical_traversal_authorizes_current_renamed_identity_path() {
    let (_d, rep, w, _) = setup();
    w.mkdir("past", 0o700).unwrap();
    w.mkdir("current", 0o700).unwrap();
    let h = w.create("past/file", 0o600).unwrap();
    w.write(&h, 0, b"old").unwrap();
    drop(h);
    w.chmod("past", 0).unwrap();
    let id = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    w.chmod("past", 0o700).unwrap();
    w.rename("past/file", "current/file").unwrap();
    w.unlink("past").unwrap();
    let old = rep.begin(&id, actor(), true).unwrap();
    assert!(old.lookup("past/file").is_ok());
    let h = old.open("past/file", OpenMode::Read).unwrap();
    assert_eq!(old.read(&h, 0, 3).unwrap(), b"old");
    w.chmod("current", 0).unwrap();
    err(old.lookup("past/file"), "permission_denied");
    err(old.open("past/file", OpenMode::Read), "permission_denied");
}

#[test]
fn retained_nfs_identity_does_not_grant_data_or_mutation_authority() {
    let (_d, rep, w, base) = setup();
    w.mkdir("d", 0o700).unwrap();
    let created = w.create("d/secret", 0).unwrap();
    let id = created.entry_id().clone();
    let retained = w.retain_identity(&id).unwrap();
    err(w.read(&retained, 0, 1), "permission_denied");
    err(w.write(&retained, 0, b"no"), "permission_denied");
    err(w.check_access_identity(&id, 4), "permission_denied");
    w.chmod("d", 0o400).unwrap();
    err(w.retain_identity(&id), "permission_denied");
    w.chmod("d", 0o700).unwrap();
    w.chmod("d/secret", 0o600).unwrap();
    w.write(&retained, 0, b"allowed").unwrap();
    w.unlink("d/secret").unwrap();
    assert_eq!(w.read(&retained, 0, 99).unwrap(), b"allowed");
    err(w.retain_identity(&id), "not_found");
    let old = rep.begin(&base, actor(), true).unwrap();
    err(
        old.check_access_identity(&old.lookup("").unwrap().id, 2),
        "read_only",
    );
}

#[test]
fn nfs_queries_follow_current_parent_and_historical_authority() {
    let (_d, rep, w, _) = setup();
    w.mkdir("d", 0o700).unwrap();
    let h = w.create("d/a", 0o600).unwrap();
    w.write(&h, 0, b"old").unwrap();
    let id = h.entry_id().clone();
    let revision = w
        .checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    let old = rep.begin(&revision, actor(), true).unwrap();
    let retained = old.retain_identity(&id).unwrap();
    w.chmod("d/a", 0o400).unwrap();
    assert!(w.check_remove_identity(&id).is_ok());
    w.chmod("d", 0o500).unwrap();
    err(w.check_remove_identity(&id), "permission_denied");
    w.chmod("d/a", 0).unwrap();
    err(old.check_access_identity(&id, 4), "permission_denied");
    err(old.read(&retained, 0, 3), "permission_denied");
    w.chmod("d/a", 0o400).unwrap();
    assert_eq!(old.read(&retained, 0, 3).unwrap(), b"old");
    err(old.write(&retained, 0, b"no"), "read_only");
    err(old.chmod_handle(&retained, 0o777), "read_only");
    err(old.check_remove_identity(&id), "read_only");
    err(w.read(&retained, 0, 3), "stale_handle");
}
