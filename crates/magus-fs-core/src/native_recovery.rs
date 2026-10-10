//! Retained native alternatives: immutable records and explicit, unpublished capture.
//!
//! A record links retained bytes to the original application operation, base, logical path and
//! generation. The retained file is an owner-private copy; its location is never a selector.
use crate::{
    capture::directory,
    engine::{from_json, json, lock, Core},
    objects::{name, open_at},
    permissions as perm, *,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
crate::protocol::opaque_id!(NativeRecoveryId);
/// Fixed provenance token for revisions whose native causal base is unknown. A candidate with
/// this provenance must never be merged as a base-aware edit; it requires explicit recovery.
pub const UNKNOWN_CAUSALITY_PROVENANCE: &str = "native_unknown_causality";
/// Listings are bounded; retained generations are independently capped at 128.
pub const MAX_RECOVERY_LISTING: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryCausality {
    RecordedBase,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecoveryRecord {
    pub id: NativeRecoveryId,
    pub operation: OperationId,
    pub original_base: RevisionId,
    pub source_path: String,
    pub observed_generation: u64,
    pub observed_digest: ObjectId,
    pub causal_coverage: RecoveryCausality,
}
/// Linkage of one owner-private retained copy to its original application.
pub(crate) struct Retained<'a> {
    pub(crate) operation: &'a OperationId,
    pub(crate) original_base: &'a RevisionId,
    pub(crate) source_path: &'a str,
    pub(crate) observed_generation: u64,
    pub(crate) digest_hex: &'a str,
    pub(crate) copy: &'a Path,
    pub(crate) causal_coverage: RecoveryCausality,
}
/// Durable immutable record for an owner-private retained copy; idempotent per copy.
pub(crate) fn record(core: &Core, r: Retained<'_>) -> Result<(), FsError> {
    let retained = r.copy.to_str().ok_or(FsError::UnsafeStorage)?;
    if core
        .journal
        .db
        .query_row(
            "SELECT 1 FROM native_recovery WHERE operation=? AND retained=?",
            params![r.operation.as_str(), retained],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Ok(());
    }
    let value = NativeRecoveryRecord {
        id: NativeRecoveryId::random()?,
        operation: r.operation.clone(),
        original_base: r.original_base.clone(),
        source_path: r.source_path.into(),
        observed_generation: r.observed_generation,
        observed_digest: ObjectId::parse(format!("sha256:{}", r.digest_hex))?,
        causal_coverage: r.causal_coverage,
    };
    core.journal.guard()?;
    core.journal.db.execute(
        "INSERT INTO native_recovery VALUES(?,?,?,?)",
        params![
            value.id.as_str(),
            r.operation.as_str(),
            json(&value)?,
            retained
        ],
    )?;
    Ok(())
}
fn load(core: &Core, id: &NativeRecoveryId) -> Result<(NativeRecoveryRecord, PathBuf), FsError> {
    let (bytes, retained) = core
        .journal
        .db
        .query_row(
            "SELECT record,retained FROM native_recovery WHERE id=?",
            [id.as_str()],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(FsError::NotFound)?;
    Ok((from_json(&bytes)?, PathBuf::from(retained)))
}
/// Bases and captured revisions of recovery records are GC roots.
pub(crate) fn roots(core: &Core) -> Result<Vec<RevisionId>, FsError> {
    let mut out = vec![];
    for bytes in core
        .journal
        .db
        .prepare("SELECT record FROM native_recovery")?
        .query_map([], |r| r.get::<_, Vec<u8>>(0))?
    {
        out.push(from_json::<NativeRecoveryRecord>(&bytes?)?.original_base);
    }
    for id in core
        .journal
        .db
        .prepare("SELECT revision FROM native_recovery_captures")?
        .query_map([], |r| r.get::<_, String>(0))?
    {
        out.push(RevisionId::parse(id?)?);
    }
    Ok(out)
}
/// Read the owner-private retained copy through no-follow descriptors and verify its digest.
fn retained_bytes(path: &Path, expected: &ObjectId) -> Result<Vec<u8>, FsError> {
    let parent = directory(path.parent().ok_or(FsError::UnsafeStorage)?)?;
    let mut file = open_at(
        parent.as_raw_fd(),
        &name(path.file_name().ok_or(FsError::UnsafeStorage)?)?,
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    let m = file.metadata()?;
    if !m.is_file() || m.len() > MAX_FILE {
        return Err(FsError::GenerationMismatch);
    }
    let mut bytes = vec![];
    (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if &digest(&bytes)? != expected {
        return Err(FsError::GenerationMismatch);
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> Result<ObjectId, FsError> {
    ObjectId::parse(format!(
        "sha256:{}",
        crate::model::hex(&Sha256::digest(bytes))
    ))
}
impl Replica {
    /// At most 128 immutable records, oldest first. Selection is by opaque id only.
    pub fn list_native_recovery(&self, actor: Actor) -> Result<Vec<NativeRecoveryRecord>, FsError> {
        let core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        let rows = core
            .journal
            .db
            .prepare("SELECT record FROM native_recovery ORDER BY rowid LIMIT ?")?
            .query_map([MAX_RECOVERY_LISTING as i64], |r| r.get::<_, Vec<u8>>(0))?
            .map(|r| from_json(&r?))
            .collect();
        rows
    }
    /// Create a new attributed local revision from exactly the selected retained bytes. The
    /// working head, queue and source record are unchanged; nothing is integrated.
    pub fn capture_native_recovery(
        &self,
        id: NativeRecoveryId,
        expected_digest: ObjectId,
        operation: OperationId,
        actor: Actor,
    ) -> Result<RevisionId, FsError> {
        let mut core = lock(&self.core)?;
        let authority = perm::authority(&core.config, &actor)?.clone();
        let (record, retained) = load(&core, &id)?;
        if let Some((prior_id, prior_digest, revision)) = core
            .journal
            .db
            .query_row(
                "SELECT id,digest,revision FROM native_recovery_captures WHERE operation=?",
                [operation.as_str()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if prior_id != id.as_str() || prior_digest != expected_digest.as_str() {
                return Err(FsError::OperationMismatch);
            }
            return RevisionId::parse(revision);
        }
        if expected_digest != record.observed_digest {
            return Err(FsError::OperationMismatch);
        }
        // Capture-excluded paths are opaque local content, never managed recovery candidates.
        let policy = crate::native_apply::configuration(&core)?.policy;
        if record.source_path.is_empty() || !policy.selected(&record.source_path) {
            return Err(FsError::InvalidPath);
        }
        let bytes = retained_bytes(&retained, &record.observed_digest)?;
        let base = core.revision(&record.original_base)?;
        let mut tree = base.tree.clone();
        let mut extents = vec![];
        let mut objects = BTreeMap::new();
        for chunk in bytes.chunks(262144) {
            let object = ObjectId::for_bytes(chunk)?;
            objects.insert(object.clone(), chunk.len() as u64);
            extents.push(Extent::Chunk {
                object,
                object_size: chunk.len() as u64,
                offset: 0,
                length: chunk.len() as u64,
            });
        }
        if extents.len() > MAX_EXTENTS {
            return Err(FsError::LimitExceeded);
        }
        let content = EntryContent::File {
            version: FileVersion {
                size: bytes.len() as u64,
                extents,
            },
        };
        match tree
            .entries
            .iter_mut()
            .find(|e| e.path == record.source_path)
        {
            Some(e) if e.content == EntryContent::Directory => return Err(FsError::IsDirectory),
            Some(e) => e.content = content,
            None => {
                crate::paths::validate_path(&record.source_path)?;
                let parent = perm::entry(&tree, perm::parent(&record.source_path))?;
                if parent.content != EntryContent::Directory {
                    return Err(FsError::NotDirectory);
                }
                tree.entries.push(Entry {
                    path: record.source_path.clone(),
                    id: EntryId::random()?,
                    parent: parent.id,
                    owner: actor.principal().clone(),
                    group: authority.primary_group.clone(),
                    mode: 0o644,
                    content,
                });
                tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
            }
        }
        validate_tree(&tree)?;
        crate::capture::authorize_capture(&core.config, &actor, Some(&base.tree), &tree)?;
        let revision = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![record.original_base.clone()],
            operation: operation.clone(),
            replica: core.config.replica.clone(),
            principal: actor.principal().clone(),
            captured_at_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| FsError::InvalidDescriptor)?
                .as_nanos()
                .try_into()
                .map_err(|_| FsError::LimitExceeded)?,
            coverage: vec![record.source_path.clone()],
            provenance: match record.causal_coverage {
                RecoveryCausality::Unknown => UNKNOWN_CAUSALITY_PROVENANCE,
                RecoveryCausality::RecordedBase => "native_scan_delete_create",
            }
            .into(),
            restoration: None,
            tree,
        };
        let descriptor = encode_revision(&revision)?;
        let revision_id = revision_id(&revision)?;
        core.reserve(&objects)?;
        for chunk in bytes.chunks(262144) {
            core.objects.install(chunk)?;
        }
        for object in objects.keys() {
            core.objects.sync_object(object)?;
        }
        core.journal.guard()?;
        let tx = core
            .journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO revisions VALUES(?,?)",
            params![revision_id.as_str(), descriptor],
        )?;
        tx.execute(
            "INSERT INTO native_recovery_captures VALUES(?,?,?,?)",
            params![
                operation.as_str(),
                id.as_str(),
                expected_digest.as_str(),
                revision_id.as_str()
            ],
        )?;
        tx.commit()?;
        Ok(revision_id)
    }
    /// Write the verified retained bytes to a fresh destination. Never overwrites.
    pub fn export_native_recovery(
        &self,
        id: NativeRecoveryId,
        expected_digest: ObjectId,
        destination: &Path,
        actor: Actor,
    ) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        crate::capture::absolute_native(destination)?;
        // Exports never enter owner-private state; the parent walk below is no-follow.
        if destination.starts_with(&core.journal.path) {
            return Err(FsError::StorageOverlap);
        }
        let (record, retained) = load(&core, &id)?;
        if expected_digest != record.observed_digest {
            return Err(FsError::OperationMismatch);
        }
        let bytes = retained_bytes(&retained, &record.observed_digest)?;
        let parent = directory(destination.parent().ok_or(FsError::InvalidPath)?)?;
        let leaf = name(destination.file_name().ok_or(FsError::InvalidPath)?)?;
        let mut out = match open_at(
            parent.as_raw_fd(),
            &leaf,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        ) {
            Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(FsError::AlreadyExists)
            }
            other => other?,
        };
        out.write_all(&bytes)?;
        out.sync_all()?;
        parent.sync_all()?;
        let mut check = vec![];
        open_at(parent.as_raw_fd(), &leaf, libc::O_RDONLY)?.read_to_end(&mut check)?;
        if digest(&check)? != record.observed_digest {
            return Err(FsError::UnstableCapture);
        }
        Ok(())
    }
}
