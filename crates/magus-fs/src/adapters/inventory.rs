use magus_fs_core::{EntryId, Tree};
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct Inventory {
    pub current: usize,
    pub remembered: usize,
    pub removed: usize,
    pub stale_epoch: usize,
}
/// Current counts unique tree identities including root. Remembered/removed count
/// allocated inode slots (identity + epoch), including root and retained epochs.
/// Removal is identity absence, not rename or an old epoch of a surviving file.
/// Stale epochs count only surviving files; directories (including root) are
/// epoch-independent in State::inode. Snapshot is taken before notifications.
pub(super) fn inventory<'a>(
    enabled: bool,
    tree: impl FnOnce() -> &'a Tree,
    remembered: &[(EntryId, u64)],
    epoch: u64,
) -> Option<Inventory> {
    if !enabled {
        return None;
    }
    let tree = tree();
    let mut current = std::collections::BTreeMap::new();
    current.insert(&tree.root.id, true);
    for entry in &tree.entries {
        current.insert(
            &entry.id,
            matches!(entry.content, magus_fs_core::EntryContent::Directory),
        );
    }
    let removed = remembered
        .iter()
        .filter(|(id, _)| !current.contains_key(id))
        .count();
    let stale_epoch = remembered
        .iter()
        .filter(|(id, inode_epoch)| current.get(id) == Some(&false) && *inode_epoch != epoch)
        .count();
    Some(Inventory {
        current: current.len(),
        remembered: remembered.len(),
        removed,
        stale_epoch,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use magus_fs_core::Entry;
    fn fixture() -> (Tree, Vec<Entry>, Vec<(EntryId, u64)>) {
        let root = magus_fs_core::Root {
            id: EntryId::random().unwrap(),
            owner: magus_fs_core::PrincipalId::random().unwrap(),
            group: magus_fs_core::GroupId::random().unwrap(),
            mode: 493,
        };
        let file = Entry {
            path: "file".into(),
            id: EntryId::random().unwrap(),
            parent: root.id.clone(),
            owner: root.owner.clone(),
            group: root.group.clone(),
            mode: 420,
            content: magus_fs_core::EntryContent::File {
                version: magus_fs_core::FileVersion {
                    size: 0,
                    extents: vec![],
                },
            },
        };
        let root_entry = Entry {
            path: String::new(),
            id: root.id.clone(),
            parent: root.id.clone(),
            content: magus_fs_core::EntryContent::Directory,
            ..file.clone()
        };
        let remembered = vec![
            (root.id.clone(), 1),
            (file.id.clone(), 1),
            (file.id.clone(), 2),
        ];
        (
            Tree {
                entries: vec![file.clone()],
                root,
            },
            vec![file.clone(), file, root_entry],
            remembered,
        )
    }
    #[test]
    fn unchanged_root_and_epoch_inventory() {
        let (tree, _adoption, remembered) = fixture();
        assert_eq!(
            inventory(true, || &tree, &remembered, 2),
            Some(Inventory {
                current: 2,
                remembered: 3,
                removed: 0,
                stale_epoch: 1
            })
        );
    }
    #[test]
    fn rename_preserves_identity_but_replacement_removes_old_inodes() {
        let (mut tree, _adoption, remembered) = fixture();
        tree.entries[0].path = "renamed".into();
        assert_eq!(
            inventory(true, || &tree, &remembered, 2).unwrap().removed,
            0
        );
        tree.entries[0].path = "file".into();
        tree.entries[0].id = EntryId::random().unwrap();
        assert_eq!(
            inventory(true, || &tree, &remembered, 2).unwrap().removed,
            2
        );
    }
    #[test]
    fn disabled_inventory_never_visits_tree() {
        let (_, _adoption, remembered) = fixture();
        assert_eq!(
            inventory(
                false,
                || panic!("disabled diagnostic tree traversal"),
                &remembered,
                2
            ),
            None
        );
    }
}
