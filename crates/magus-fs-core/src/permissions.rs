use crate::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    principal: PrincipalId,
}
impl Actor {
    pub fn new(principal: PrincipalId) -> Self {
        Self { principal }
    }
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    pub principal: PrincipalId,
    pub uid: u32,
    pub primary_group: GroupId,
    pub gid: u32,
    pub groups: Vec<GroupId>,
    pub dac_override: bool,
    pub ownership_transfer: bool,
}

pub(crate) fn authority<'a>(
    config: &'a ReplicaConfig,
    actor: &Actor,
) -> Result<&'a Authority, FsError> {
    config
        .authorities
        .iter()
        .find(|a| &a.principal == actor.principal())
        .ok_or(FsError::UnknownPrincipal)
}
pub(crate) fn mutation(read_only: bool) -> Result<(), FsError> {
    if read_only {
        Err(FsError::ReadOnly)
    } else {
        Ok(())
    }
}
pub(crate) fn access(a: &Authority, entry: &Entry, bits: u16) -> Result<(), FsError> {
    if a.dac_override {
        return Ok(());
    }
    let shift = if a.principal == entry.owner {
        6
    } else if a.groups.contains(&entry.group) {
        3
    } else {
        0
    };
    if (entry.mode >> shift) & bits == bits {
        Ok(())
    } else {
        Err(FsError::PermissionDenied)
    }
}
pub(crate) fn mode(mode: u16) -> Result<(), FsError> {
    if mode & !0o777 != 0 {
        Err(FsError::UnsupportedMode)
    } else {
        Ok(())
    }
}
pub(crate) fn root_entry(tree: &Tree) -> Entry {
    Entry {
        path: String::new(),
        id: tree.root.id.clone(),
        parent: tree.root.id.clone(),
        owner: tree.root.owner.clone(),
        group: tree.root.group.clone(),
        mode: tree.root.mode,
        content: EntryContent::Directory,
    }
}
pub(crate) fn entry(tree: &Tree, path: &str) -> Result<Entry, FsError> {
    if path.is_empty() {
        Ok(root_entry(tree))
    } else {
        tree.entries
            .iter()
            .find(|e| e.path == path)
            .cloned()
            .ok_or(FsError::NotFound)
    }
}
pub(crate) fn parent(path: &str) -> &str {
    path.rsplit_once('/').map(|p| p.0).unwrap_or("")
}
pub(crate) fn traversal(tree: &Tree, path: &str, a: &Authority) -> Result<(), FsError> {
    if path.is_empty() {
        return Ok(());
    }
    crate::paths::validate_path(path)?;
    access(a, &root_entry(tree), 1)?;
    let mut offset = 0;
    for component in path.split('/').take(path.split('/').count() - 1) {
        offset += component.len();
        let e = entry(tree, &path[..offset])?;
        if e.content != EntryContent::Directory {
            return Err(FsError::NotDirectory);
        }
        access(a, &e, 1)?;
        offset += 1;
    }
    Ok(())
}
pub(crate) fn parent_write(tree: &Tree, path: &str, a: &Authority) -> Result<Entry, FsError> {
    if path.is_empty() {
        return Err(FsError::InvalidPath);
    }
    traversal(tree, path, a)?;
    let p = entry(tree, parent(path))?;
    if p.content != EntryContent::Directory {
        return Err(FsError::NotDirectory);
    }
    access(a, &p, 3)?;
    Ok(p)
}

pub(crate) fn ownership_change(
    config: &ReplicaConfig,
    authority: &Authority,
    owner: &PrincipalId,
    group: &GroupId,
) -> Result<(), FsError> {
    if !authority.ownership_transfer || !authority.groups.contains(group) {
        return Err(FsError::PermissionDenied);
    }
    if !config
        .authorities
        .iter()
        .any(|a| &a.principal == owner && a.groups.contains(group))
    {
        return Err(FsError::UnknownPrincipal);
    }
    Ok(())
}
