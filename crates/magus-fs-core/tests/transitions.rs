mod support;
use magus_fs_core::*;
use support::*;
fn scope() -> TransitionScope {
    TransitionScope {
        read_prefixes: vec!["".into()],
        write_prefixes: vec!["".into()],
        read_only: false,
    }
}
#[test]
fn transition_checks_scope_permissions_and_identity_metadata() {
    let mut r = revision();
    add_file(&mut r, "a", b"old");
    let mut candidate = r.tree.clone();
    candidate.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 0,
            extents: vec![],
        },
    };
    let authorities = config().authorities;
    let delta =
        authorize_tree_transition(&r.tree, &candidate, &authorities[0], &authorities, &scope())
            .unwrap();
    assert_eq!(delta.operations.len(), 1);
    let mut limited = scope();
    limited.write_prefixes = vec!["other".into()];
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[0], &authorities, &limited),
        "permission_denied",
    );
    limited = scope();
    limited.read_only = true;
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[3], &authorities, &limited),
        "read_only",
    );
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[1], &authorities, &scope()),
        "permission_denied",
    );
    candidate = r.tree.clone();
    candidate.entries[0].mode = 0o777;
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[1], &authorities, &scope()),
        "permission_denied",
    );
    candidate = r.tree.clone();
    candidate.entries[0].owner = principal(999);
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[0], &authorities, &scope()),
        "unknown_principal",
    );
    candidate = r.tree.clone();
    candidate.entries[0].id = EntryId::random().unwrap();
    candidate.entries[0].owner = principal(2);
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[0], &authorities, &scope()),
        "permission_denied",
    );
}
#[test]
fn destination_checks_cannot_be_bypassed_by_candidate_mode_changes() {
    let mut r = revision();
    add_file(&mut r, "a", b"");
    r.tree.root.mode = 0o500;
    let mut candidate = r.tree.clone();
    candidate.root.mode = 0o700;
    candidate.entries[0].path = "b".into();
    let authorities = config().authorities;
    err(
        authorize_tree_transition(&r.tree, &candidate, &authorities[0], &authorities, &scope()),
        "permission_denied",
    );
}
#[test]
fn historical_read_requires_present_identity_current_path_and_ancestors() {
    let mut r = revision();
    add_file(&mut r, "a", b"old");
    let authorities = config().authorities;
    assert!(authorize_tree_read(&r.tree, &r.tree.entries[0].id, &authorities[0]).is_ok());
    r.tree.root.mode = 0;
    err(
        authorize_tree_read(&r.tree, &r.tree.entries[0].id, &authorities[0]),
        "permission_denied",
    );
    r.tree.root.mode = 0o755;
    r.tree.entries[0].mode = 0;
    err(
        authorize_tree_read(&r.tree, &r.tree.entries[0].id, &authorities[0]),
        "permission_denied",
    );
    err(
        authorize_tree_read(&r.tree, &EntryId::random().unwrap(), &authorities[0]),
        "permission_denied",
    );
}
