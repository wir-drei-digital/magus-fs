//! `sync conflicts list|show|export` and `sync resolve` (collaboration-v1). Conflicts are
//! immutable service records; alternatives are exported only through freshly authorized
//! pinned views into a new destination; a resolution is a complete replacement candidate
//! based on the expected current head, never a replay against a newer head.
use super::{
    controller::SyncController,
    transport::{Failure, Transport},
};
use magus_fs_core::{protocol::*, *};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Failure>;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn transport(rep: &Replica) -> Result<(Transport, SyncBinding, ReplicaConfig)> {
    let binding = rep.sync_status()?.binding.ok_or(FsError::ConfigMismatch)?;
    let config = rep.configuration()?;
    Ok((Transport::new(binding.clone(), &config)?, binding, config))
}

pub(crate) fn list(rep: &Replica, cursor: Option<&str>) -> Result<Value> {
    let (t, _, _) = transport(rep)?;
    let path = match cursor {
        Some(c) => format!("/conflicts?cursor={c}"),
        None => "/conflicts".into(),
    };
    let page: ConflictPage = t.json("GET", &path, (), deadline())?;
    if page.items.len() > MAX_PAGE_ITEMS {
        return Err(FsError::LimitExceeded.into());
    }
    Ok(json!({"ok":true,"page":page}))
}

pub(crate) fn show(rep: &Replica, conflict: &ConflictId) -> Result<Value> {
    let (t, _, _) = transport(rep)?;
    let detail: ConflictDetail = t.json(
        "GET",
        &format!("/conflicts/{}", conflict.as_str()),
        (),
        deadline(),
    )?;
    Ok(json!({"ok":true,"conflict":detail}))
}

/// Writes the authorized projection of one alternative beneath a new private directory.
pub(crate) fn export(
    rep: &Replica,
    conflict: &ConflictId,
    alternative: &AlternativeId,
    destination: &Path,
) -> Result<Value> {
    let (t, binding, config) = transport(rep)?;
    let view: ViewBinding = t.json(
        "GET",
        &format!(
            "/conflicts/{}/alternatives/{}",
            conflict.as_str(),
            alternative.as_str()
        ),
        (),
        deadline(),
    )?;
    let bytes = t.bytes(
        "GET",
        &format!("/views/{}/descriptor", view.view.as_str()),
        vec![],
        MAX_DESCRIPTOR,
        deadline(),
        false,
    )?;
    let revision = decode_revision(&bytes)?;
    if revision_id(&revision)? != view.revision || !revision.parents.is_empty() {
        return Err(FsError::InvalidDescriptor.into());
    }
    let mut pinned = binding;
    pinned.view = view.clone();
    pinned.source = RemoteSourceId::random()?;
    let source = Transport::new(pinned.clone(), &config)?;
    // A fresh destination only: never overwrite or follow an existing path.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(destination)
        .map_err(FsError::Io)?;
    let mut manifest = vec![];
    let mut total = 0_u64;
    let mut chunks: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
    let mut entries = revision.tree.entries.clone();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    for entry in entries {
        let target = destination.join(&entry.path);
        match &entry.content {
            EntryContent::Directory => {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&target)
                    .map_err(FsError::Io)?;
                manifest.push(json!({"path":entry.path,"entry":entry.id,"kind":"directory"}));
            }
            EntryContent::File { version } => {
                total = total
                    .checked_add(version.size)
                    .filter(|t| *t <= 512 * 1024 * 1024)
                    .ok_or(FsError::LimitExceeded)?;
                let mut body = Vec::with_capacity(version.size as usize);
                for extent in &version.extents {
                    match extent {
                        Extent::Chunk {
                            object,
                            object_size,
                            offset,
                            length,
                        } => {
                            if !chunks.contains_key(object) {
                                let bytes = source.fetch(
                                    &pinned.source,
                                    object,
                                    *object_size,
                                    deadline(),
                                )?;
                                chunks.insert(object.clone(), bytes);
                            }
                            let chunk = &chunks[object];
                            body.extend_from_slice(
                                chunk
                                    .get(*offset as usize..(*offset + *length) as usize)
                                    .ok_or(FsError::CorruptObject)?,
                            );
                        }
                        Extent::Hole { length } => body.resize(body.len() + *length as usize, 0),
                    }
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&target)
                    .map_err(FsError::Io)?;
                file.write_all(&body).map_err(FsError::Io)?;
                file.sync_all().map_err(FsError::Io)?;
                manifest.push(
                    json!({"path":entry.path,"entry":entry.id,"kind":"file","size":body.len()}),
                );
            }
        }
    }
    Ok(json!({"ok":true,"destination":destination,"view":view,"entries":manifest}))
}

/// Reconciliation of an explicit selection never reads content (opaque policy).
struct NoContent;
impl MergeContent for NoContent {
    fn read(&self, _: &FileVersion) -> std::result::Result<Vec<u8>, FsError> {
        Err(FsError::UnsupportedMode)
    }
    fn generated(&self, _: &[u8]) -> std::result::Result<FileVersion, FsError> {
        Err(FsError::UnsupportedMode)
    }
}

/// `sync resolve`: select base/current/candidate for every retained conflict of one local
/// candidate, as a complete replacement based on the expected (current) head.
pub(crate) fn resolve(
    rep: &Replica,
    conflicts: Vec<ConflictId>,
    expected_head: HeadToken,
    prefer: Side,
    operation: Option<OperationId>,
) -> Result<Value> {
    let status = rep.sync_status()?;
    // An interrupted resolution resumes with its frozen operation/target, never rebuilt.
    if let Some(op) = &operation {
        if let Some(existing) = status.submissions.iter().find(|p| &p.operation == op) {
            let target = existing
                .resolves
                .as_ref()
                .ok_or(FsError::OperationMismatch)?;
            if target.conflicts != conflicts || target.expected_head != expected_head {
                return Err(FsError::OperationMismatch.into());
            }
            let controller = SyncController::new(rep)?;
            let progress = controller.run_resolution(&existing.local_revision)?;
            return Ok(outcome(&controller, progress));
        }
    }
    let (t, active, config) = transport(rep)?;
    let mut receipts = BTreeSet::new();
    for id in &conflicts {
        let detail: ConflictDetail = t.json(
            "GET",
            &format!("/conflicts/{}", id.as_str()),
            (),
            deadline(),
        )?;
        if detail.summary.state != ConflictState::Open {
            return Err(Failure {
                code: "already_resolved",
                retryable: false,
            });
        }
        if detail.expected_head != expected_head {
            // Revalidate against the newer head instead of replaying an old decision.
            return Err(Failure {
                code: "stale_head",
                retryable: false,
            });
        }
        receipts.insert(detail.summary.receipt);
    }
    if receipts.len() != 1 {
        // One original candidate per resolution; its conflicts are resolved together.
        return Err(FsError::UnsupportedMode.into());
    }
    let receipt = receipts.into_iter().next().ok_or(FsError::NotFound)?;
    let record = status
        .submissions
        .iter()
        .find(|p| {
            p.resolves.is_none()
                && p.private_receipt
                    .as_ref()
                    .is_some_and(|r| r.receipt == receipt)
        })
        .ok_or(FsError::NotFound)?;
    let candidate = rep.revision(&record.local_revision)?;
    let base = rep.revision(&rep.submission_binding(&record.operation)?.view.revision)?;
    let view: ViewBinding = t.json(
        "POST",
        "/views",
        json!({"branch":active.branch}),
        deadline(),
    )?;
    if view.head != expected_head {
        return Err(Failure {
            code: "stale_head",
            retryable: false,
        });
    }
    let bytes = t.bytes(
        "GET",
        &format!("/views/{}/descriptor", view.view.as_str()),
        vec![],
        MAX_DESCRIPTOR,
        deadline(),
        false,
    )?;
    if !decode_revision(&bytes)?.parents.is_empty() {
        return Err(FsError::InvalidDescriptor.into());
    }
    let mut next = active.clone();
    next.source = RemoteSourceId::random()?;
    next.view = view;
    rep.register_sync_source(next.clone())?;
    rep.import_revision(
        ImportDescriptor {
            expected: next.view.revision.clone(),
            bytes,
        },
        ChunkSource::Remote {
            source: next.source.clone(),
        },
    )?;
    super::live::install_sources(rep, None)?;
    let current = rep.revision(&next.view.revision)?;
    let tree = resolve_trees(
        &base.tree,
        &current.tree,
        &candidate.tree,
        &MergePolicy::opaque(),
        &NoContent,
        prefer,
    )
    .map_err(|_| Failure {
        code: "invalid_resolution",
        retryable: false,
    })?;
    let actor = super::publication_actor(rep, rep.actor_for_uid(unsafe { libc::geteuid() })?)?;
    let operation = match operation {
        Some(op) => op,
        None => OperationId::random()?,
    };
    let replacement = Revision {
        format: FORMAT.into(),
        hash: HASH.into(),
        layout: LAYOUT.into(),
        parents: vec![next.view.revision.clone()],
        operation: operation.clone(),
        replica: config.replica.clone(),
        principal: actor.principal().clone(),
        captured_at_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        coverage: vec!["".into()],
        provenance: "explicit".into(),
        restoration: None,
        tree,
    };
    let encoded = encode_revision(&replacement)?;
    let id = rep.import_revision(
        ImportDescriptor {
            expected: revision_id(&replacement)?,
            bytes: encoded,
        },
        ChunkSource::Unavailable,
    )?;
    rep.enqueue_resolution(
        PendingSubmission {
            operation,
            local_revision: id.clone(),
            original_view: next.view.view.clone(),
            original_head: next.view.head.clone(),
            expected_local_generation: rep.status()?.generation,
        },
        next,
        ResolutionTarget {
            conflicts,
            expected_head,
            receipts: vec![receipt],
        },
    )?;
    let controller = SyncController::new(rep)?;
    let progress = controller.run_resolution(&id)?;
    Ok(outcome(&controller, progress))
}
fn outcome(controller: &SyncController, progress: SyncProgress) -> Value {
    let shared = progress.shared_receipt.is_some();
    json!({"ok":shared,"error":if shared {None} else {progress.error.clone().or(Some("durability_unmet".into()))},"progress":progress,"counters":controller.counters()})
}
