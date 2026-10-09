//! Pure logical authorization. Native UID/GID never identify remote actors.
use crate::{permissions as p, *};
use std::collections::BTreeMap;
#[derive(Clone, Debug)]
pub struct TransitionScope {
    pub read_prefixes: Vec<String>,
    pub write_prefixes: Vec<String>,
    pub read_only: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionKind {
    Create,
    Remove,
    Move,
    Content,
    Metadata,
}
#[derive(Clone, Debug)]
pub struct AuthorizedOperation {
    pub kind: TransitionKind,
    pub old: Option<EntryId>,
    pub new: Option<EntryId>,
}
#[derive(Clone, Debug)]
pub struct AuthorizedDelta {
    pub operations: Vec<AuthorizedOperation>,
}
fn within(path: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|s| s.starts_with('/'))
}
fn scoped(path: &str, prefixes: &[String]) -> Result<(), FsError> {
    if prefixes.iter().any(|p| within(path, p)) {
        Ok(())
    } else {
        Err(FsError::PermissionDenied)
    }
}
/// Checks current identity, current path traversal and file read/directory list+search.
pub fn authorize_tree_read(tree: &Tree, id: &EntryId, a: &Authority) -> Result<Entry, FsError> {
    let e = if id == &tree.root.id {
        p::root_entry(tree)
    } else {
        tree.entries
            .iter()
            .find(|e| &e.id == id)
            .cloned()
            .ok_or(FsError::PermissionDenied)?
    };
    p::traversal(tree, &e.path, a)?;
    p::access(
        a,
        &e,
        if e.content == EntryContent::Directory {
            5
        } else {
            4
        },
    )?;
    Ok(e)
}
/// Validates a complete transition; callers overlay projected edits on the full
/// base first. Existing permissions are always taken from the trusted base.
pub fn authorize_tree_transition(
    base: &Tree,
    candidate: &Tree,
    a: &Authority,
    configured: &[Authority],
    scope: &TransitionScope,
) -> Result<AuthorizedDelta, FsError> {
    p::mutation(scope.read_only)?;
    validate_tree(base)?;
    validate_tree(candidate)?;
    if !configured.contains(a) {
        return Err(FsError::UnknownPrincipal);
    }
    for prefix in scope.read_prefixes.iter().chain(&scope.write_prefixes) {
        if !prefix.is_empty() {
            crate::paths::validate_path(prefix)?;
        }
    }
    if base.root.id != candidate.root.id {
        return Err(FsError::PermissionDenied);
    }
    let mut old = base
        .entries
        .iter()
        .map(|e| (e.id.clone(), e.clone()))
        .collect::<BTreeMap<_, _>>();
    old.insert(base.root.id.clone(), p::root_entry(base));
    let mut new = candidate
        .entries
        .iter()
        .map(|e| (e.id.clone(), e.clone()))
        .collect::<BTreeMap<_, _>>();
    new.insert(candidate.root.id.clone(), p::root_entry(candidate));
    // New parents may be created in the transition; existing parents retain their
    // original metadata even if the candidate attempts to grant itself access.
    let mut destination = candidate.clone();
    destination.root = base.root.clone();
    for e in &mut destination.entries {
        if let Some(previous) = old.get(&e.id) {
            e.owner = previous.owner.clone();
            e.group = previous.group.clone();
            e.mode = previous.mode;
        }
    }
    let mut operations = vec![];
    for (id, before) in &old {
        let after = new.get(id);
        if after == Some(before) {
            continue;
        }
        scoped(&before.path, &scope.read_prefixes)?;
        scoped(&before.path, &scope.write_prefixes)?;
        p::traversal(base, &before.path, a)?;
        let mut push = |kind| {
            operations.push(AuthorizedOperation {
                kind,
                old: Some(id.clone()),
                new: after.map(|e| e.id.clone()),
            })
        };
        match after {
            None => {
                p::parent_write(base, &before.path, a)?;
                push(TransitionKind::Remove);
            }
            Some(after) => {
                scoped(&after.path, &scope.read_prefixes)?;
                scoped(&after.path, &scope.write_prefixes)?;
                if before.path != after.path || before.parent != after.parent {
                    p::parent_write(base, &before.path, a)?;
                    p::parent_write(&destination, &after.path, a)?;
                    push(TransitionKind::Move);
                }
                if std::mem::discriminant(&before.content) != std::mem::discriminant(&after.content)
                {
                    return Err(FsError::PermissionDenied);
                }
                if before.content != after.content {
                    p::access(a, before, 2)?;
                    push(TransitionKind::Content);
                }
                if before.mode != after.mode
                    || before.owner != after.owner
                    || before.group != after.group
                {
                    p::mode(after.mode)?;
                    if before.mode != after.mode && before.owner != a.principal {
                        return Err(FsError::PermissionDenied);
                    }
                    if before.owner != after.owner || before.group != after.group {
                        if !a.ownership_transfer || !a.groups.contains(&after.group) {
                            return Err(FsError::PermissionDenied);
                        }
                        if !configured
                            .iter()
                            .any(|a| a.principal == after.owner && a.groups.contains(&after.group))
                        {
                            return Err(FsError::UnknownPrincipal);
                        }
                    }
                    push(TransitionKind::Metadata);
                }
            }
        }
    }
    for (id, after) in &new {
        if !old.contains_key(id) {
            scoped(&after.path, &scope.read_prefixes)?;
            scoped(&after.path, &scope.write_prefixes)?;
            p::mode(after.mode)?;
            if after.owner != a.principal || after.group != a.primary_group {
                return Err(FsError::PermissionDenied);
            }
            p::parent_write(&destination, &after.path, a)?;
            operations.push(AuthorizedOperation {
                kind: TransitionKind::Create,
                old: None,
                new: Some(id.clone()),
            });
        }
    }
    Ok(AuthorizedDelta { operations })
}
