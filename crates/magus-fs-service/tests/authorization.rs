use magus_fs_core::*;
use magus_fs_service::{auth, views};
fn fixture() -> (Revision, Authority) {
    let p = PrincipalId::parse(format!("principal:{:032x}", 1)).unwrap();
    let g = GroupId::parse(format!("group:{:032x}", 1)).unwrap();
    let a = Authority {
        principal: p.clone(),
        uid: 1001,
        gid: 1001,
        primary_group: g.clone(),
        groups: vec![g.clone()],
        dac_override: false,
        ownership_transfer: false,
    };
    let root = Root {
        id: EntryId::random().unwrap(),
        owner: p.clone(),
        group: g.clone(),
        mode: 0o755,
    };
    let entries = ["reports", "secret"]
        .into_iter()
        .map(|path| Entry {
            path: path.into(),
            id: EntryId::random().unwrap(),
            parent: root.id.clone(),
            owner: p.clone(),
            group: g.clone(),
            mode: 0o700,
            content: EntryContent::Directory,
        })
        .collect();
    (
        Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            principal: p,
            captured_at_ns: 0,
            coverage: vec!["".into()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree { root, entries },
        },
        a,
    )
}
#[test]
fn scoped_projection_has_distinct_identity_and_lift_preserves_unseen_siblings() {
    let (full, a) = fixture();
    let projected = views::project(&full, &full.tree, &a, &["reports".into()]).unwrap();
    assert_eq!(projected.tree.entries.len(), 1);
    assert_eq!(projected.tree.entries[0].path, "reports");
    assert!(projected.parents.is_empty());
    assert_ne!(
        revision_id(&full).unwrap(),
        revision_id(&projected).unwrap()
    );
    let mut edit = projected.clone();
    edit.parents = vec![revision_id(&projected).unwrap()];
    edit.tree.entries.clear();
    let lifted = views::lift(&full, &projected, &edit).unwrap();
    assert_eq!(lifted.tree.entries.len(), 1);
    assert_eq!(lifted.tree.entries[0].path, "secret");
    assert_eq!(lifted.parents, vec![revision_id(&full).unwrap()]);
}
#[test]
fn destructive_operations_on_hidden_descendants_and_restore_fail_closed() {
    let (mut full, a) = fixture();
    let mut hidden = full.tree.entries[1].clone();
    hidden.path = "reports/hidden".into();
    hidden.parent = full.tree.entries[0].id.clone();
    hidden.mode = 0;
    full.tree.entries.push(hidden);
    full.tree.entries.remove(1);
    let projected = views::project(&full, &full.tree, &a, &["reports".into()]).unwrap();
    assert_eq!(projected.tree.entries.len(), 1);
    let mut edit = projected.clone();
    edit.tree.entries.clear();
    assert_eq!(
        views::lift(&full, &projected, &edit).unwrap_err().code,
        "not_found"
    );
    edit = projected.clone();
    edit.format = RESTORE_FORMAT.into();
    assert_eq!(
        views::lift(&full, &projected, &edit).unwrap_err().code,
        "unsupported_operation"
    );
}
#[test]
fn delegation_depth_bound_is_checked_before_token_insertion() {
    assert!(auth::check_child_depth(7).is_ok());
    assert_eq!(
        auth::check_child_depth(8).unwrap_err().code,
        "delegation_depth"
    );
}

#[test]
fn projection_prunes_entire_denied_ancestor_chain_and_keeps_readable_sibling() {
    let (mut full, a) = fixture();
    full.tree.entries[0].path = "d".into();
    full.tree.entries[0].mode = 0o111;
    let mut sub = full.tree.entries[1].clone();
    sub.id = EntryId::random().unwrap();
    sub.path = "d/sub".into();
    sub.parent = full.tree.entries[0].id.clone();
    let mut leaf = sub.clone();
    leaf.id = EntryId::random().unwrap();
    leaf.path = "d/sub/leaf".into();
    leaf.parent = sub.id.clone();
    leaf.content = EntryContent::File {
        version: FileVersion {
            size: 0,
            extents: vec![],
        },
    };
    full.tree.entries.insert(0, leaf);
    full.tree.entries.push(sub);
    let projected = views::project(&full, &full.tree, &a, &["".into()]).unwrap();
    assert_eq!(projected.tree.entries.len(), 1);
    assert_eq!(projected.tree.entries[0].path, "secret");
    assert!(revision_id(&projected).is_ok());
}
