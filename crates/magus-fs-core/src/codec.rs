use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::{self, Write},
};

fn validate_revision(r: &Revision) -> Result<(), FsError> {
    if r.format != FORMAT || r.hash != HASH || r.layout != LAYOUT {
        return Err(FsError::UnsupportedFormat);
    }
    validate_tree(&r.tree)?;
    if r.parents.len() > MAX_ENTRIES || r.coverage.len() > MAX_ENTRIES {
        return Err(FsError::LimitExceeded);
    }
    if r.parents.iter().collect::<HashSet<_>>().len() != r.parents.len()
        || r.coverage.is_empty()
        || !matches!(
            r.provenance.as_str(),
            "explicit" | "native_scan_delete_create" | "engine_observed"
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
    input_bounds(bytes)?;
    #[derive(Deserialize)]
    struct Header<'a> {
        format: Option<&'a str>,
        hash: Option<&'a str>,
        layout: Option<&'a str>,
    }
    let header: Header<'_> =
        serde_json::from_slice(bytes).map_err(|_| FsError::InvalidDescriptor)?;
    if header.format != Some(FORMAT) || header.hash != Some(HASH) || header.layout != Some(LAYOUT) {
        return Err(FsError::UnsupportedFormat);
    }
    let mut r: Revision = serde_json::from_slice(bytes).map_err(|_| FsError::InvalidDescriptor)?;
    validate_revision(&r)?;
    r.tree.entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    r.coverage.sort_unstable();
    Ok(r)
}
pub fn revision_id(revision: &Revision) -> Result<RevisionId, FsError> {
    RevisionId::digest(&encode_revision(revision)?)
}
