use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::{self, Write},
};

fn validate_revision(r: &Revision) -> Result<(), FsError> {
    let _span = crate::metadata_profile::Span::begin("validation");
    if ![FORMAT, RESTORE_FORMAT].contains(&r.format.as_str())
        || r.hash != HASH
        || r.layout != LAYOUT
    {
        return Err(FsError::UnsupportedFormat);
    }
    if (r.format == RESTORE_FORMAT) != r.restoration.is_some() {
        return Err(FsError::InvalidDescriptor);
    }
    if let Some(p) = &r.restoration {
        if !r.parents.contains(&p.source_revision) || p.recreated.len() > MAX_ENTRIES {
            return Err(FsError::InvalidDescriptor);
        }
        let mut destinations = HashSet::new();
        let output_ids = r.tree.entries.iter().map(|e| &e.id).collect::<HashSet<_>>();
        for (source, destination) in &p.recreated {
            if source == destination
                || !destinations.insert(destination)
                || !output_ids.contains(destination)
            {
                return Err(FsError::InvalidDescriptor);
            }
        }
    }
    validate_tree(&r.tree)?;
    if r.parents.len() > MAX_ENTRIES || r.coverage.len() > MAX_ENTRIES {
        return Err(FsError::LimitExceeded);
    }
    if r.parents.iter().collect::<HashSet<_>>().len() != r.parents.len()
        || r.coverage.is_empty()
        || !matches!(
            r.provenance.as_str(),
            "explicit"
                | "native_scan_delete_create"
                | "engine_observed"
                | crate::UNKNOWN_CAUSALITY_PROVENANCE
        )
    {
        return Err(FsError::InvalidDescriptor);
    }
    let mut seen = HashSet::new();
    for path in &r.coverage {
        if !path.is_empty() {
            crate::paths::validate_path(path)?;
        }
        if !seen.insert(path) {
            return Err(FsError::InvalidDescriptor);
        }
    }
    Ok(())
}
#[derive(Serialize)]
struct CanonicalTree<'a> {
    root: &'a Root,
    entries: Vec<&'a Entry>,
}
#[derive(Serialize)]
struct CanonicalRevision<'a> {
    format: &'a str,
    hash: &'a str,
    layout: &'a str,
    parents: &'a [RevisionId],
    operation: &'a OperationId,
    replica: &'a ReplicaId,
    principal: &'a PrincipalId,
    captured_at_ns: u64,
    coverage: Vec<&'a str>,
    provenance: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    restoration: &'a Option<RestoreProvenance>,
    tree: CanonicalTree<'a>,
}
struct BoundedOutput(Vec<u8>);
impl Write for BoundedOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > MAX_DESCRIPTOR - self.0.len() {
            return Err(io::Error::other("limit_exceeded"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn encode_revision(r: &Revision) -> Result<Vec<u8>, FsError> {
    validate_revision(r)?;
    let mut entries: Vec<_> = r.tree.entries.iter().collect();
    entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    let mut coverage: Vec<_> = r.coverage.iter().map(String::as_str).collect();
    coverage.sort_unstable();
    let view = CanonicalRevision {
        format: &r.format,
        hash: &r.hash,
        layout: &r.layout,
        parents: &r.parents,
        operation: &r.operation,
        replica: &r.replica,
        principal: &r.principal,
        captured_at_ns: r.captured_at_ns,
        coverage,
        provenance: &r.provenance,
        restoration: &r.restoration,
        tree: CanonicalTree {
            root: &r.tree.root,
            entries,
        },
    };
    let mut out = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut out, &view).map_err(|_| FsError::LimitExceeded)?;
    Ok(out.0)
}
fn input_bounds(bytes: &[u8]) -> Result<(), FsError> {
    if bytes.len() > MAX_DESCRIPTOR {
        return Err(FsError::LimitExceeded);
    }
    let mut depth = 0u32;
    let mut string = false;
    let mut escaped = false;
    for &b in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 16 {
                        return Err(FsError::LimitExceeded);
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or(FsError::InvalidDescriptor)?,
                _ => {}
            }
        }
    }
    if string || depth != 0 {
        return Err(FsError::InvalidDescriptor);
    }
    Ok(())
}
pub fn decode_revision(bytes: &[u8]) -> Result<Revision, FsError> {
    let _span = crate::metadata_profile::Span::begin("decode");
    crate::metadata_profile::count("bytes", bytes.len() as u64);
    input_bounds(bytes)?;
    #[derive(Deserialize)]
    struct Header<'a> {
        format: Option<&'a str>,
        hash: Option<&'a str>,
        layout: Option<&'a str>,
    }
    let header: Header<'_> =
        serde_json::from_slice(bytes).map_err(|_| FsError::InvalidDescriptor)?;
    if !matches!(header.format, Some(FORMAT | RESTORE_FORMAT))
        || header.hash != Some(HASH)
        || header.layout != Some(LAYOUT)
    {
        return Err(FsError::UnsupportedFormat);
    }
    let mut r: Revision = serde_json::from_slice(bytes).map_err(|_| FsError::InvalidDescriptor)?;
    validate_revision(&r)?;
    r.tree.entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    r.coverage.sort_unstable();
    Ok(r)
}
pub fn revision_id(revision: &Revision) -> Result<RevisionId, FsError> {
    let _span = crate::metadata_profile::Span::begin("hash");
    RevisionId::digest(&encode_revision(revision)?)
}

/// Contextual v2 validation. The decoder validates shape; import/archive validate real parents.
pub fn validate_restoration_parents(
    restored: &Revision,
    source: &Revision,
    replaced: &Revision,
) -> Result<(), FsError> {
    let provenance = restored
        .restoration
        .as_ref()
        .ok_or(FsError::InvalidDescriptor)?;
    if restored.format != RESTORE_FORMAT
        || revision_id(source)? != provenance.source_revision
        || restored.parents.first() != Some(&revision_id(replaced)?)
        || !restored.parents.contains(&provenance.source_revision)
        || source.tree.root.id != replaced.tree.root.id
        || restored.tree.root.id != replaced.tree.root.id
    {
        return Err(FsError::InvalidDescriptor);
    }
    let source_ids = source
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<std::collections::BTreeMap<_, _>>();
    let replaced_ids = replaced
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<std::collections::BTreeMap<_, _>>();
    let output_ids = restored
        .tree
        .entries
        .iter()
        .map(|e| (&e.id, e))
        .collect::<std::collections::BTreeMap<_, _>>();
    let recreated = source_ids
        .keys()
        .filter(|id| !replaced_ids.contains_key(*id))
        .copied()
        .collect::<HashSet<_>>();
    if recreated != provenance.recreated.keys().collect::<HashSet<_>>() {
        return Err(FsError::InvalidDescriptor);
    }
    let all_source_ids = source_ids.keys().copied().collect::<HashSet<_>>();
    for (id, entry) in source_ids {
        let target = provenance.recreated.get(id).unwrap_or(id);
        if target != id
            && (replaced_ids.contains_key(target)
                || all_source_ids.contains(target)
                || target == &source.tree.root.id)
        {
            return Err(FsError::InvalidDescriptor);
        }
        let output = output_ids.get(target).ok_or(FsError::InvalidDescriptor)?;
        let expected_parent = provenance
            .recreated
            .get(&entry.parent)
            .unwrap_or(&entry.parent);
        if output.path != entry.path
            || output.content != entry.content
            || &output.parent != expected_parent
        {
            return Err(FsError::InvalidDescriptor);
        }
    }
    Ok(())
}
