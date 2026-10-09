use crate::*;
use caseless::Caseless;
use std::collections::{HashMap, HashSet};
use unicode_normalization::{is_nfc, UnicodeNormalization};

pub(crate) fn validate_path(path: &str) -> Result<(), FsError> {
    if path.is_empty()
        || path.len() > 4096
        || !is_nfc(path)
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':'))
    {
        return Err(FsError::InvalidPath);
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.len() > 255 {
            return Err(FsError::InvalidPath);
        }
    }
    Ok(())
}
pub fn validate_tree(tree: &Tree) -> Result<(), FsError> {
    if tree.entries.len() > MAX_ENTRIES {
        return Err(FsError::LimitExceeded);
    }
    if tree.root.mode > 0o777 {
        return Err(FsError::InvalidTree);
    }
    let mut paths = HashMap::new();
    let mut ids = HashSet::new();
    let mut folded = HashSet::new();
    let mut objects = HashMap::new();
    ids.insert(&tree.root.id);
    for entry in &tree.entries {
        validate_path(&entry.path)?;
        let fold: String = entry.path.nfd().default_case_fold().nfc().collect();
        if !ids.insert(&entry.id)
            || paths.insert(entry.path.as_str(), entry).is_some()
            || !folded.insert(fold)
            || entry.mode > 0o777
        {
            return Err(FsError::InvalidTree);
        }
        if let EntryContent::File { version } = &entry.content {
            if version.size > MAX_FILE || version.extents.len() > MAX_EXTENTS {
                return Err(FsError::LimitExceeded);
            }
            let mut total = 0u64;
            for extent in &version.extents {
                let length = match extent {
                    Extent::Hole { length } => *length,
                    Extent::Chunk {
                        object,
                        object_size,
                        offset,
                        length,
                    } => {
                        if *object_size > MAX_CHUNK
                            || offset.checked_add(*length).ok_or(FsError::InvalidTree)?
                                > *object_size
                        {
                            return Err(FsError::InvalidTree);
                        }
                        if let Some(previous) = objects.insert(object, *object_size) {
                            if previous != *object_size {
                                return Err(FsError::InvalidTree);
                            }
                        }
                        *length
                    }
                };
                if length == 0 {
                    return Err(FsError::InvalidTree);
                }
                total = total.checked_add(length).ok_or(FsError::InvalidTree)?;
                if total > version.size {
                    return Err(FsError::InvalidTree);
                }
            }
            if total != version.size {
                return Err(FsError::InvalidTree);
            }
        }
    }
    // Every parent must be the exact path prefix, so edges strictly shorten paths: cycles are impossible.
    for entry in &tree.entries {
        match entry.path.rsplit_once('/') {
            None => {
                if entry.parent != tree.root.id {
                    return Err(FsError::InvalidTree);
                }
            }
            Some((parent, _)) => {
                let parent = paths.get(parent).ok_or(FsError::InvalidTree)?;
                if parent.id != entry.parent || parent.content != EntryContent::Directory {
                    return Err(FsError::InvalidTree);
                }
            }
        }
    }
    Ok(())
}
