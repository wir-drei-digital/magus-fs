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
