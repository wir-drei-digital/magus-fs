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
}
impl SyncProgress {
    pub fn reached(&self, level: DurabilityLevel) -> bool {
        match level {
            DurabilityLevel::Local => true,
            DurabilityLevel::PrivateRemote => self.private_receipt.is_some(),
            DurabilityLevel::Shared => self.shared_receipt.is_some(),
            DurabilityLevel::Applied => false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncStatus {
    pub binding: Option<SyncBinding>,
    pub submissions: Vec<SyncProgress>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub pending: PendingSubmission,
    pub binding: SyncBinding,
    pub digest: RevisionId,
    pub progress: SyncProgress,
}
impl Record {
    fn unresolved(&self) -> bool {
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
        core.journal
            .db
            .execute("INSERT INTO sync_binding VALUES(1,?)", [json(&binding)?])?;
        Ok(())
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
            && !(old.integration.is_some()
                && update.state == SubmissionState::Failed
                && update.error.as_deref() == Some("stale_head"))
        {
            return Err(FsError::InvalidDescriptor);
        }
        if update.applied_revision.is_some() {
            return Err(FsError::UnsupportedMode);
        }
        if &update.operation != operation
            || update.local_revision != r.pending.local_revision
            || old.request.is_some() && old.request != update.request
            || old.request_digest.is_some() && old.request_digest != update.request_digest
            || old.integration.is_some() && old.integration != update.integration
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
        if let Some(receipt) = &update.shared_receipt {
            let req = update
                .integration
                .as_ref()
                .ok_or(FsError::InvalidDescriptor)?;
            if receipt.operation != req.operation
                || receipt.replica != req.replica
                || receipt.submitted_revision != r.pending.local_revision
                || receipt.branch != req.branch
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
