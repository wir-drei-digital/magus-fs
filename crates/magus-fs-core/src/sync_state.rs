//! Durable revision-scoped publication state, owned by the replica's existing journal.
use crate::{
    engine::{from_json, json, lock},
    protocol::*,
    *,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Instant,
};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TransportIdentity(String);
impl TransportIdentity {
    pub fn for_bytes(bytes: &[u8]) -> Result<Self, FsError> {
        Ok(Self(ObjectId::for_bytes(bytes)?.as_str().to_owned()))
    }
}
impl TryFrom<String> for TransportIdentity {
    type Error = FsError;
    fn try_from(s: String) -> Result<Self, FsError> {
        ObjectId::parse(&s)?;
        Ok(Self(s))
    }
}
impl From<TransportIdentity> for String {
    fn from(s: TransportIdentity) -> String {
        s.0
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum PublicationMode {
    #[default]
    Isolated,
    SharedLive,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncBinding {
    /// Remote namespace, for the single active binding of this replica.
    pub id: NamespaceId,
    pub branch: BranchName,
    #[serde(default)]
    pub publication: PublicationMode,
    pub source: RemoteSourceId,
    pub view: ViewBinding,
    pub transport_profile: PathBuf,
    pub transport_identity: TransportIdentity,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSubmission {
    pub operation: OperationId,
    pub local_revision: RevisionId,
    pub original_view: ViewId,
    pub original_head: HeadToken,
    pub expected_local_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SubmissionState {
    Queued,
    Preparing,
    Uncertain,
    Retryable,
    Denied,
    Failed,
    PrivateRemote,
    Shared,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DurabilityLevel {
    Local,
    PrivateRemote,
    Shared,
    Applied,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRequest {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub candidate_receipt: ReceiptId,
    pub expected_head: HeadToken,
    pub branch: BranchName,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub original_view: ViewId,
    pub original_head: HeadToken,
    pub revision: RevisionId,
    pub upload: UploadId,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProgress {
    pub operation: OperationId,
    pub local_revision: RevisionId,
    pub private_receipt: Option<PrivateReceipt>,
    pub shared_receipt: Option<SharedReceipt>,
    pub applied_revision: Option<RevisionId>,
    pub remote_outcome_unknown: bool,
    pub state: SubmissionState,
    pub error: Option<String>,
    pub request: Option<CandidateRequest>,
    pub request_digest: Option<RevisionId>,
    pub integration: Option<IntegrationRequest>,
    /// Integration attempts that definitively returned `stale_head`, replaced in order by a
    /// newer attempt against a newer destination head. The candidate itself never changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded: Vec<IntegrationRequest>,
    /// Immutable intent of an explicit resolution replacement candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<ResolutionTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<ResolutionRequest>,
    /// A shared resolution replaced this candidate's retained conflicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<ResolvedBy>,
}
/// Bound on superseded integration attempts per candidate.
pub const MAX_SUPERSEDED_INTEGRATIONS: usize = 32;
/// Definitive service outcomes that end an uncertain integration/resolution attempt.
pub const DEFINITIVE_OUTCOMES: &[&str] = &[
    "stale_head",
    "conflicted",
    "already_resolved",
    "incomplete_resolution",
    "invalid_resolution",
];
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionTarget {
    pub conflicts: Vec<ConflictId>,
    pub expected_head: HeadToken,
    /// Original candidate receipts whose conflicts this replacement resolves.
    pub receipts: Vec<ReceiptId>,
    /// A later local revision (descending from those candidates) whose content, paths and
    /// metadata were used as the candidate side; it and its unpublished ancestors are
    /// covered by the resolution too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RevisionId>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBy {
    pub operation: OperationId,
    pub conflicts: Vec<ConflictId>,
    pub receipt: SharedReceipt,
}
impl SyncProgress {
    pub fn reached(&self, level: DurabilityLevel) -> bool {
        match level {
            DurabilityLevel::Local => true,
            DurabilityLevel::PrivateRemote => self.private_receipt.is_some(),
            DurabilityLevel::Shared => self.shared_receipt.is_some(),
            DurabilityLevel::Applied => self.applied_revision.is_some(),
        }
    }
}
/// Durable incoming progress and safe diagnostics in the existing single-owner journal.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingRecovery {
    pub cursor: i64,
    pub needs_snapshot: bool,
    pub discovery_error: Option<String>,
    pub acknowledgement_error: Option<String>,
}
fn safe_incoming_code(code: &str) -> &str {
    match code {
        "invalid_credential"
        | "denied"
        | "cursor_expired"
        | "invalid_cursor"
        | "base_unavailable"
        | "conflict"
        | "conflicted"
        | "backend_unavailable"
        | "backpressure"
        | "transport"
        | "deadline"
        | "invalid_source"
        | "permission_denied"
        | "stale_handle"
        | "generation_mismatch"
        | "dirty_working_state"
        | "replica_busy"
        | "limit_exceeded"
        | "corrupt_object"
        | "io" => code,
        _ => "invalid_response",
    }
}
fn incoming(core: &crate::engine::Core) -> Result<IncomingRecovery, FsError> {
    core.journal
        .db
        .query_row(
            "SELECT record FROM incoming_recovery WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|b| from_json(&b))
        .transpose()
        .map(|v| v.unwrap_or_default())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncStatus {
    pub binding: Option<SyncBinding>,
    pub submissions: Vec<SyncProgress>,
    pub incoming: IncomingRecovery,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub pending: PendingSubmission,
    pub binding: SyncBinding,
    pub digest: RevisionId,
    pub progress: SyncProgress,
}
impl Record {
    pub(crate) fn unresolved(&self) -> bool {
        // A resolution replacement is not working-tree work, and a resolved candidate's
        // retained conflicts were replaced by an explicit shared resolution.
        if self.progress.resolves.is_some() || self.progress.resolved_by.is_some() {
            return false;
        }
        match self.progress.state {
            SubmissionState::Shared => false,
            SubmissionState::PrivateRemote => {
                self.binding.publication == PublicationMode::SharedLive
            }
            _ => true,
        }
    }
}
impl crate::engine::Core {
    pub(crate) fn sync_records(&self) -> Result<Vec<Record>, FsError> {
        let bytes = self
            .journal
            .db
            .prepare("SELECT record FROM sync_queue ORDER BY rowid")?
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        bytes.iter().map(|b| from_json(b)).collect()
    }
    /// The issued base is retained independently and is not charged to staged admission.
    fn sync_staged_closure(
        &self,
        candidate: &RevisionId,
        base: &RevisionId,
    ) -> Result<BTreeMap<ObjectId, u64>, FsError> {
        let mut current = candidate.clone();
        let mut seen = BTreeSet::new();
        let mut descriptor_bytes = 0;
        let mut objects = BTreeMap::new();
        while current != *base {
            if !seen.insert(current.clone()) || seen.len() > 128 {
                return Err(FsError::LimitExceeded);
            }
            let revision = self.revision(&current)?;
            descriptor_bytes += encode_revision(&revision)?.len();
            if descriptor_bytes > 64 * 1024 * 1024 {
                return Err(FsError::LimitExceeded);
            }
            for (id, size) in crate::cache::closure(&revision.tree) {
                if objects.insert(id, size).is_some_and(|old| old != size) {
                    return Err(FsError::CorruptObject);
                }
            }
            if revision.parents.len() != 1 {
                return Err(FsError::BaseMismatch);
            }
            current = revision.parents[0].clone();
        }
        if objects.values().sum::<u64>() > 512 * 1024 * 1024 {
            return Err(FsError::LimitExceeded);
        }
        Ok(objects)
    }
    pub(crate) fn sync_roots(&self) -> Result<BTreeSet<ObjectId>, FsError> {
        let mut roots = BTreeSet::new();
        let imports = self
            .journal
            .db
            .prepare("SELECT source,revision FROM recovery_imports")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        for (source, revision) in imports {
            for id in [source, revision] {
                roots.extend(self.recovery_closure(&RevisionId::parse(id)?)?.into_keys());
            }
        }
        for record in self.sync_records()? {
            roots.extend(
                self.sync_staged_closure(
                    &record.pending.local_revision,
                    &record.binding.view.revision,
                )?
                .into_keys(),
            );
            roots.extend(
                self.recovery_closure(&record.binding.view.revision)?
                    .into_keys(),
            );
        }
        Ok(roots)
    }
}
impl Replica {
    pub fn configure_sync(&self, binding: SyncBinding) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        core.revision(&binding.view.revision)?;
        if !binding.transport_profile.is_absolute() {
            return Err(FsError::InvalidPath);
        }
        if let Some(old) = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let old: SyncBinding = from_json(&old)?;
            if old == binding {
                return Ok(());
            }
            // Active view advancement belongs to Tasks4/5. Never retarget an opaque source.
            return Err(FsError::ConfigMismatch);
        }
        core.journal.db.execute(
            "INSERT INTO sync_sources VALUES(?,?)",
            params![binding.source.as_str(), json(&binding)?],
        )?;
        core.journal
            .db
            .execute("INSERT INTO sync_binding VALUES(1,?)", [json(&binding)?])?;
        Ok(())
    }
    pub fn register_sync_source(&self, binding: SyncBinding) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        let active: SyncBinding = from_json(&core.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        if binding.id != active.id
            || binding.branch != active.branch
            || binding.publication != active.publication
            || binding.transport_identity != active.transport_identity
            || binding.transport_profile != active.transport_profile
        {
            return Err(FsError::ConfigMismatch);
        }
        if let Some(bytes) = core
            .journal
            .db
            .query_row(
                "SELECT binding FROM sync_sources WHERE id=?",
                [binding.source.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            return if from_json::<SyncBinding>(&bytes)? == binding {
                Ok(())
            } else {
                Err(FsError::ConfigMismatch)
            };
        }
        core.journal.db.execute(
            "INSERT INTO sync_sources VALUES(?,?)",
            params![binding.source.as_str(), json(&binding)?],
        )?;
        Ok(())
    }
    pub fn submission_binding(&self, operation: &OperationId) -> Result<SyncBinding, FsError> {
        lock(&self.core)?
            .sync_records()?
            .into_iter()
            .find(|r| &r.pending.operation == operation)
            .map(|r| r.binding)
            .ok_or(FsError::NotFound)
    }
    pub fn sync_sources(&self) -> Result<Vec<SyncBinding>, FsError> {
        let core = lock(&self.core)?;
        let bytes = core
            .journal
            .db
            .prepare("SELECT binding FROM sync_sources ORDER BY id")?
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut result: Vec<SyncBinding> = bytes
            .iter()
            .map(|b| from_json(b))
            .collect::<Result<_, _>>()?;
        // Upgrade existing Task3 journals without changing the original identity.
        if let Some(bytes) = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let active: SyncBinding = from_json(&bytes)?;
            if !result.iter().any(|b| b.source == active.source) {
                result.push(active);
            }
        }
        Ok(result)
    }
    pub fn enqueue_submission(&self, pending: PendingSubmission) -> Result<(), FsError> {
        let mut core = lock(&self.core)?;
        let digest = RevisionId::digest(&json(&pending)?)?;
        if let Some(bytes) = core
            .journal
            .db
            .query_row(
                "SELECT record FROM sync_queue WHERE operation=?",
                [pending.operation.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let old: Record = from_json(&bytes)?;
            return if old.digest == digest {
                Ok(())
            } else {
                Err(FsError::OperationMismatch)
            };
        }
        let records = core.sync_records()?;
        if records.iter().filter(|r| r.unresolved()).count() >= 128 {
            return Err(FsError::Backpressure);
        }
        let bytes = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(FsError::ConfigMismatch)?;
        let binding: SyncBinding = from_json(&bytes)?;
        if pending.original_view != binding.view.view || pending.original_head != binding.view.head
        {
            return Err(FsError::BaseMismatch);
        }
        if core.working.as_ref().map(|w| w.generation) != Some(pending.expected_local_generation) {
            return Err(FsError::GenerationMismatch);
        }
        let submitted = core.revision(&pending.local_revision)?;
        if submitted.operation != pending.operation || submitted.replica != core.config.replica {
            return Err(FsError::OperationMismatch);
        }
        core.sync_staged_closure(&pending.local_revision, &binding.view.revision)?;
        let progress = SyncProgress {
            operation: pending.operation.clone(),
            local_revision: pending.local_revision.clone(),
            private_receipt: None,
            shared_receipt: None,
            applied_revision: None,
            remote_outcome_unknown: false,
            state: SubmissionState::Queued,
            error: None,
            request: None,
            request_digest: None,
            integration: None,
            superseded: vec![],
            resolves: None,
            resolution: None,
            resolved_by: None,
        };
        let record = Record {
            pending: pending.clone(),
            binding,
            digest,
            progress,
        };
        let tx = core.journal.db.transaction()?;
        tx.execute(
            "INSERT INTO sync_queue VALUES(?,?)",
            params![pending.operation.as_str(), json(&record)?],
        )?;
        tx.commit()?;
        crate::faults::hit("sync-enqueued")?;
        Ok(())
    }
    /// Queues an explicit resolution replacement candidate based on a newer authorized view
    /// of the bound branch. It never changes the working tree or the active binding.
    pub fn enqueue_resolution(
        &self,
        pending: PendingSubmission,
        binding: SyncBinding,
        target: ResolutionTarget,
    ) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        if target.conflicts.is_empty()
            || target.conflicts.len() > MAX_RESOLUTION_CONFLICTS
            || target.receipts.is_empty()
            || target.expected_head != binding.view.head
        {
            return Err(FsError::InvalidDescriptor);
        }
        if let Some(source) = &target.source {
            core.revision(source)?;
        }
        let digest = RevisionId::digest(&json(&(&pending, &binding, &target))?)?;
        if let Some(bytes) = core
            .journal
            .db
            .query_row(
                "SELECT record FROM sync_queue WHERE operation=?",
                [pending.operation.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let old: Record = from_json(&bytes)?;
            return if old.digest == digest {
                Ok(())
            } else {
                Err(FsError::OperationMismatch)
            };
        }
        let active: SyncBinding = from_json(&core.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        let registered = core
            .journal
            .db
            .query_row(
                "SELECT binding FROM sync_sources WHERE id=?",
                [binding.source.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| from_json::<SyncBinding>(&b))
            .transpose()?;
        if registered.as_ref() != Some(&binding)
            || binding.id != active.id
            || binding.branch != active.branch
            || binding.transport_profile != active.transport_profile
            || binding.transport_identity != active.transport_identity
            || pending.original_view != binding.view.view
            || pending.original_head != binding.view.head
        {
            return Err(FsError::ConfigMismatch);
        }
        let submitted = core.revision(&pending.local_revision)?;
        if submitted.operation != pending.operation
            || submitted.replica != core.config.replica
            || submitted.parents != vec![binding.view.revision.clone()]
            || submitted.provenance == crate::UNKNOWN_CAUSALITY_PROVENANCE
        {
            return Err(FsError::OperationMismatch);
        }
        core.sync_staged_closure(&pending.local_revision, &binding.view.revision)?;
        let progress = SyncProgress {
            operation: pending.operation.clone(),
            local_revision: pending.local_revision.clone(),
            private_receipt: None,
            shared_receipt: None,
            applied_revision: None,
            remote_outcome_unknown: false,
            state: SubmissionState::Queued,
            error: None,
            request: None,
            request_digest: None,
            integration: None,
            superseded: vec![],
            resolves: Some(target),
            resolution: None,
            resolved_by: None,
        };
        let operation = pending.operation.as_str().to_owned();
        let record = json(&Record {
            pending,
            binding,
            digest,
            progress,
        })?;
        core.journal.db.execute(
            "INSERT INTO sync_queue VALUES(?,?)",
            params![operation, record],
        )?;
        Ok(())
    }
    /// After a shared resolution, links every local candidate whose receipt it resolved, and
    /// those candidates' unpublished local ancestors (whose content those candidates carried).
    pub fn mark_resolved(&self, resolution: &OperationId) -> Result<Vec<OperationId>, FsError> {
        let core = lock(&self.core)?;
        let records = core.sync_records()?;
        let source = records
            .iter()
            .find(|r| &r.pending.operation == resolution)
            .ok_or(FsError::NotFound)?;
        let (Some(target), Some(request), Some(receipt)) = (
            &source.progress.resolves,
            &source.progress.resolution,
            &source.progress.shared_receipt,
        ) else {
            return Err(FsError::InvalidDescriptor);
        };
        let link = ResolvedBy {
            operation: request.operation.clone(),
            conflicts: target.conflicts.clone(),
            receipt: receipt.clone(),
        };
        let mut covered = BTreeSet::new();
        let mut bases = BTreeSet::new();
        for r in &records {
            if r.progress.resolves.is_none()
                && r.progress
                    .private_receipt
                    .as_ref()
                    .is_some_and(|p| target.receipts.contains(&p.receipt))
            {
                bases.insert(r.binding.view.revision.clone());
                let mut current = r.pending.local_revision.clone();
                let mut seen = 0;
                while current != r.binding.view.revision && seen < 128 {
                    covered.insert(current.clone());
                    let revision = core.revision(&current)?;
                    let [parent] = revision.parents.as_slice() else {
                        break;
                    };
                    current = parent.clone();
                    seen += 1;
                }
            }
        }
        if let Some(source) = &target.source {
            let mut current = source.clone();
            for _ in 0..128 {
                if bases.contains(&current) {
                    break;
                }
                covered.insert(current.clone());
                let revision = core.revision(&current)?;
                let [parent] = revision.parents.as_slice() else {
                    break;
                };
                current = parent.clone();
            }
        }
        let mut marked = vec![];
        let mut updates = vec![];
        for mut r in records {
            if r.progress.resolves.is_some()
                || r.progress.resolved_by.is_some()
                || r.progress.shared_receipt.is_some()
                || !covered.contains(&r.pending.local_revision)
            {
                continue;
            }
            r.progress.resolved_by = Some(link.clone());
            updates.push((json(&r)?, r.pending.operation.clone()));
        }
        // All links of one resolution commit together.
        let tx = core.journal.db.unchecked_transaction()?;
        for (record, operation) in updates {
            tx.execute(
                "UPDATE sync_queue SET record=? WHERE operation=?",
                params![record, operation.as_str()],
            )?;
            marked.push(operation);
        }
        tx.commit()?;
        Ok(marked)
    }
    pub fn pending_submissions(&self) -> Result<Vec<PendingSubmission>, FsError> {
        Ok(lock(&self.core)?
            .sync_records()?
            .into_iter()
            .filter(|r| r.unresolved())
            .map(|r| r.pending)
            .collect())
    }
    pub fn sync_status(&self) -> Result<SyncStatus, FsError> {
        let core = lock(&self.core)?;
        let binding = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| from_json(&b))
            .transpose()?;
        Ok(SyncStatus {
            incoming: incoming(&core)?,
            binding,
            submissions: core
                .sync_records()?
                .into_iter()
                .map(|r| r.progress)
                .collect(),
        })
    }
    pub fn record_sync_progress(
        &self,
        operation: &OperationId,
        expected_state: SubmissionState,
        update: SyncProgress,
    ) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        let bytes = core
            .journal
            .db
            .query_row(
                "SELECT record FROM sync_queue WHERE operation=?",
                [operation.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(FsError::NotFound)?;
        let mut r: Record = from_json(&bytes)?;
        let old = &r.progress;
        if old.state != expected_state {
            return Err(FsError::GenerationMismatch);
        }
        if old.remote_outcome_unknown
            && !update.remote_outcome_unknown
            && update.private_receipt == old.private_receipt
            && update.shared_receipt == old.shared_receipt
            && !((old.integration.is_some() || old.resolution.is_some())
                && update.state == SubmissionState::Failed
                && update
                    .error
                    .as_deref()
                    .is_some_and(|e| DEFINITIVE_OUTCOMES.contains(&e)))
        {
            return Err(FsError::InvalidDescriptor);
        }
        // Only a definitive stale attempt may be superseded, in order, by a fresh operation.
        let superseding = old.integration.is_some()
            && old.integration != update.integration
            && old.state == SubmissionState::Failed
            && old.error.as_deref() == Some("stale_head")
            && !old.remote_outcome_unknown
            && update.superseded.len() == old.superseded.len() + 1
            && update.superseded.len() <= MAX_SUPERSEDED_INTEGRATIONS
            && update.superseded[..old.superseded.len()] == old.superseded[..]
            && update.superseded.last() == old.integration.as_ref()
            && update.integration.as_ref().is_none_or(|next| {
                next.operation != r.pending.operation
                    && update
                        .superseded
                        .iter()
                        .all(|o| o.operation != next.operation)
            });
        if (!superseding && old.superseded != update.superseded)
            || old.resolves != update.resolves
            || old.resolved_by != update.resolved_by
            || old.resolution.is_some() && old.resolution != update.resolution
        {
            return Err(FsError::OperationMismatch);
        }
        if update.applied_revision.is_some() {
            return Err(FsError::UnsupportedMode);
        }
        if &update.operation != operation
            || update.local_revision != r.pending.local_revision
            || old.request.is_some() && old.request != update.request
            || old.request_digest.is_some() && old.request_digest != update.request_digest
            || old.integration.is_some() && old.integration != update.integration && !superseding
            || old.private_receipt.is_some() && old.private_receipt != update.private_receipt
            || old.shared_receipt.is_some() && old.shared_receipt != update.shared_receipt
        {
            return Err(FsError::OperationMismatch);
        }
        if let Some(req) = &update.request {
            if req.operation != r.pending.operation
                || req.replica != core.config.replica
                || req.revision != r.pending.local_revision
                || req.original_view != r.pending.original_view
                || req.original_head != r.pending.original_head
                || update.request_digest != Some(RevisionId::digest(&json(req)?)?)
            {
                return Err(FsError::OperationMismatch);
            }
        } else if update.request_digest.is_some() {
            return Err(FsError::InvalidDescriptor);
        }
        if let Some(receipt) = &update.private_receipt {
            if receipt.operation != r.pending.operation
                || receipt.replica != core.config.replica
                || receipt.submitted_revision != r.pending.local_revision
                || receipt.original_view != r.pending.original_view
                || receipt.original_head != r.pending.original_head
            {
                return Err(FsError::OperationMismatch);
            }
        }
        if let Some(req) = &update.integration {
            let receipt = update
                .private_receipt
                .as_ref()
                .ok_or(FsError::InvalidDescriptor)?;
            if req.operation == r.pending.operation
                || req.replica != core.config.replica
                || req.candidate_receipt != receipt.receipt
                || req.branch != r.binding.branch
            {
                return Err(FsError::OperationMismatch);
            }
        }
        if let Some(req) = &update.resolution {
            let receipt = update
                .private_receipt
                .as_ref()
                .ok_or(FsError::InvalidDescriptor)?;
            let target = update.resolves.as_ref().ok_or(FsError::InvalidDescriptor)?;
            if req.operation == r.pending.operation
                || req.replica != core.config.replica
                || req.replacement != receipt.receipt
                || req.conflicts != target.conflicts
                || req.expected_head != target.expected_head
                || update.integration.is_some()
            {
                return Err(FsError::OperationMismatch);
            }
        }
        if let Some(receipt) = &update.shared_receipt {
            let (operation, replica) = match (&update.integration, &update.resolution) {
                (Some(i), None) => (&i.operation, &i.replica),
                (None, Some(x)) => (&x.operation, &x.replica),
                _ => return Err(FsError::InvalidDescriptor),
            };
            if &receipt.operation != operation
                || &receipt.replica != replica
                || receipt.submitted_revision != r.pending.local_revision
                || receipt.branch != r.binding.branch
            {
                return Err(FsError::OperationMismatch);
            }
        }
        if matches!(
            update.state,
            SubmissionState::PrivateRemote | SubmissionState::Shared
        ) && update.private_receipt.is_none()
            || update.state == SubmissionState::Shared && update.shared_receipt.is_none()
        {
            return Err(FsError::InvalidDescriptor);
        }
        if update.error.as_ref().is_some_and(|e| {
            e.len() > 64 || !e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        }) {
            return Err(FsError::InvalidDescriptor);
        }
        r.progress = update;
        core.journal.db.execute(
            "UPDATE sync_queue SET record=? WHERE operation=?",
            params![json(&r)?, operation.as_str()],
        )?;
        Ok(())
    }
    /// Verified read for the trusted controller; never exposes an unverified cache body.
    pub fn sync_object(
        &self,
        id: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError> {
        lock(&self.core)?.fetch(id, size, deadline)
    }
}

impl Replica {
    pub fn incoming_recovery(&self) -> Result<IncomingRecovery, FsError> {
        {
            let core = lock(&self.core)?;
            incoming(&core)
        }
    }
    pub fn record_incoming_recovery(&self, mut value: IncomingRecovery) -> Result<(), FsError> {
        if value.cursor < 0 {
            return Err(FsError::InvalidDescriptor);
        }
        value.discovery_error = value
            .discovery_error
            .map(|s| safe_incoming_code(&s).to_owned());
        value.acknowledgement_error = value
            .acknowledgement_error
            .map(|s| safe_incoming_code(&s).to_owned());
        let core = lock(&self.core)?;
        core.journal.guard()?;
        core.journal.db.execute("INSERT INTO incoming_recovery VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET record=excluded.record",[json(&value)?])?;
        Ok(())
    }
    pub fn record_incoming_acknowledgement(&self, error: Option<&FsError>) -> Result<(), FsError> {
        let mut value = self.incoming_recovery()?;
        value.acknowledgement_error = error.map(|e| e.code().to_owned());
        self.record_incoming_recovery(value)
    }
}
