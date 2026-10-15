use super::transport::{self, Failure, Transport};
use magus_fs_core::{protocol::*, *};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak},
    time::{Duration, Instant},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    upload: UploadId,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Uploaded {
    object: ObjectId,
    size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadStatus {
    upload: UploadId,
    objects: Vec<Uploaded>,
}
impl UploadStatus {
    fn validated(self, expected: &UploadId) -> Result<BTreeMap<ObjectId, u64>, FsError> {
        if &self.upload != expected {
            return Err(FsError::InvalidDescriptor);
        }
        if self.objects.len() > 4096 {
            return Err(FsError::LimitExceeded);
        }
        let mut completed = BTreeMap::new();
        let mut total = 0_u64;
        for object in self.objects {
            if object.size > MAX_CHUNK {
                return Err(FsError::LimitExceeded);
            }
            total = total
                .checked_add(object.size)
                .ok_or(FsError::LimitExceeded)?;
            if total > 512 * 1024 * 1024 {
                return Err(FsError::LimitExceeded);
            }
            if completed.insert(object.object, object.size).is_some() {
                return Err(FsError::InvalidDescriptor);
            }
        }
        Ok(completed)
    }
}
/// Process-local publication execution ownership, shared by every controller for a replica.
/// Incoming view advancement must acquire this gate too. Never hold Core's mutex while waiting.
pub(crate) struct SyncExecution {
    active: Mutex<()>,
    pub(crate) publisher: Arc<super::wakeup::Wakeup>,
    pub(crate) incoming: Arc<super::wakeup::Wakeup>,
}
impl SyncExecution {
    pub(crate) fn for_replica(replica: &ReplicaId) -> Result<Arc<Self>, FsError> {
        static OWNERS: OnceLock<Mutex<BTreeMap<ReplicaId, Weak<SyncExecution>>>> = OnceLock::new();
        let mut owners = OWNERS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| FsError::ReplicaBusy)?;
        owners.retain(|_, owner| owner.strong_count() > 0);
        if let Some(owner) = owners.get(replica).and_then(Weak::upgrade) {
            return Ok(owner);
        }
        let owner = Arc::new(Self {
            active: Mutex::new(()),
            publisher: Arc::default(),
            incoming: Arc::default(),
        });
        owners.insert(replica.clone(), Arc::downgrade(&owner));
        Ok(owner)
    }
    /// None means local scheduling exhausted the deadline; journal state is untouched.
    pub(crate) fn acquire(&self, deadline: Instant) -> Result<Option<MutexGuard<'_, ()>>, FsError> {
        while Instant::now() < deadline {
            match self.active.try_lock() {
                Ok(guard) => return Ok(Some(guard)),
                Err(TryLockError::Poisoned(_)) => return Err(FsError::ReplicaBusy),
                Err(TryLockError::WouldBlock) => std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ),
            }
        }
        Ok(None)
    }
}
/// Caller holds SyncExecution. Admit a prior engine checkpoint before replacing its head.
/// Core generation/queue transactions reject interleaved writes without losing the capture.
/// Unbound snapshots keep their existing checkpoint semantics; no network runs here.
pub(crate) fn admit_engine_checkpoint(rep: &Replica) -> Result<(), FsError> {
    let sync = rep.sync_status()?;
    let Some(binding) = sync.binding else {
        return Ok(());
    };
    let snapshot = rep.scheduling_snapshot()?;
    let Some(head) = snapshot.head else {
        return Ok(());
    };
    if head == binding.view.revision || sync.submissions.iter().any(|p| p.local_revision == head) {
        return match rep.checkpoint_readiness()? {
            CheckpointReadiness::Ready => Ok(()),
            CheckpointReadiness::Waiting { .. } => Err(FsError::CheckpointWaiting),
            CheckpointReadiness::Blocked { .. } => Err(FsError::CheckpointBlocked),
        };
    }
    let revision = rep.revision(&head)?;
    // Issued projections and foreign revisions are not local saves. In particular,
    // reconnect must not echo an adopted revision as a fresh private submission.
    if revision.replica != rep.configuration()?.replica
        || revision.parents.is_empty()
        || revision.provenance != "engine_observed"
    {
        return Ok(());
    }
    // Only a novel eligible local checkpoint pays full body verification. Neither
    // a metadata snapshot nor eligibility is authority to admit unchecked bytes.
    let status = rep.status()?;
    if status.head.as_ref() != Some(&head) || status.generation != snapshot.generation {
        return Err(FsError::GenerationMismatch);
    }
    enqueue_submission(
        rep,
        PendingSubmission {
            operation: revision.operation,
            local_revision: head,
            original_view: binding.view.view,
            original_head: binding.view.head,
            expected_local_generation: status.generation,
        },
    )
}
pub(crate) fn enqueue_submission(rep: &Replica, pending: PendingSubmission) -> Result<(), FsError> {
    let config = rep.configuration()?;
    let owner = SyncExecution::for_replica(&config.replica)?;
    let operation = pending.operation.clone();
    let revision = pending.local_revision.clone();
    rep.enqueue_submission(pending)?;
    super::wakeup::trace(
        "admitted",
        config.replica.as_str(),
        operation.as_str(),
        revision.as_str(),
        "-",
    );
    owner.publisher.notify();
    Ok(())
}
pub struct SyncController {
    rep: Replica,
    transport: Transport,
    execution: Arc<SyncExecution>,
}
impl SyncController {
    pub fn new(rep: &Replica) -> Result<Self, FsError> {
        let binding = rep.sync_status()?.binding.ok_or(FsError::ConfigMismatch)?;
        let config = rep.configuration()?;
        let execution = SyncExecution::for_replica(&config.replica)?;
        let transport = Transport::new(binding, &config)?;
        super::live::install_sources(rep, None)?;
        Ok(Self {
            rep: rep.clone(),
            transport,
            execution,
        })
    }
    fn save(&self, p: &SyncProgress, next: SyncProgress) -> Result<SyncProgress, FsError> {
        self.rep
            .record_sync_progress(&p.operation, p.state, next.clone())?;
        Ok(next)
    }
    fn get(&self, revision: &RevisionId) -> Result<SyncProgress, FsError> {
        self.rep
            .sync_status()?
            .submissions
            .into_iter()
            .find(|p| &p.local_revision == revision)
            .ok_or(FsError::NotFound)
    }
    pub(crate) fn wakeup(&self) -> Arc<super::wakeup::Wakeup> {
        self.execution.publisher.clone()
    }
    pub fn tick(&self) -> Result<SyncProgress, FsError> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let gate_started = Instant::now();
        let _execution = self
            .execution
            .acquire(deadline)?
            .ok_or(FsError::Backpressure)?;
        let gate_wait = gate_started.elapsed();
        // A shared resolution whose local links were interrupted (e.g. owner crash) is
        // completed idempotently so its resolved candidates stop blocking application.
        for p in self.rep.sync_status()?.submissions {
            if p.resolves.is_some() && p.shared_receipt.is_some() {
                self.rep.mark_resolved(&p.operation)?;
            }
        }
        let p = self
            .rep
            .sync_status()?
            .submissions
            .into_iter()
            .find(|p| {
                p.resolved_by.is_none()
                    && (matches!(
                        p.state,
                        SubmissionState::Queued
                            | SubmissionState::Preparing
                            | SubmissionState::Retryable
                            | SubmissionState::Uncertain
                    ) || p.state == SubmissionState::PrivateRemote
                        && (p.resolves.is_some()
                            || self.transport.binding.publication == PublicationMode::SharedLive
                                && !held(p)))
            })
            .ok_or(FsError::NotFound)?;
        if std::env::var_os("MAGUS_LATENCY_TRACE").is_some() {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "latency_wait stage=publisher_execution operation={} revision={} wait_ns={}",
                p.operation.as_str(),
                p.local_revision.as_str(),
                gate_wait.as_nanos()
            );
        }
        self.target_tick(p, deadline)
    }
    fn target_tick(&self, p: SyncProgress, deadline: Instant) -> Result<SyncProgress, FsError> {
        let mut transport = Transport::new(
            self.rep.submission_binding(&p.operation)?,
            &self.rep.configuration()?,
        )?;
        transport.counters = self.transport.counters.clone();
        Self {
            rep: self.rep.clone(),
            transport,
            execution: self.execution.clone(),
        }
        .run_target(p, deadline)
    }
    fn run_target(&self, mut p: SyncProgress, deadline: Instant) -> Result<SyncProgress, FsError> {
        for attempt in 0..3 {
            if attempt > 0 {
                self.transport.counters.lock().unwrap().retries += 1;
                std::thread::sleep(
                    Duration::from_millis(if attempt == 1 { 100 } else { 300 })
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            if Instant::now() >= deadline {
                break;
            }
            let attempt_result = self.attempt(p.clone(), deadline).and_then(|result| {
                if p.private_receipt.is_none()
                    && result.private_receipt.is_some()
                    && result.shared_receipt.is_none()
                    && !held(&result)
                    && (result.resolves.is_some()
                        || self.transport.binding.publication == PublicationMode::SharedLive)
                    && Instant::now() < deadline
                {
                    self.attempt(result, deadline)
                } else {
                    Ok(result)
                }
            });
            match attempt_result {
                Ok(result) => return Ok(result),
                Err(error) => {
                    // Reload: the attempt may have durably crossed the uncertain boundary.
                    p = self.get(&p.local_revision)?;
                    // A local competing writer is scheduling contention, never remote failure.
                    if error.code == "generation_mismatch" {
                        return Ok(p);
                    }
                    let mut next = p.clone();
                    next.error = Some(error.code.into());
                    let decided = p.integration.is_some() || p.resolution.is_some();
                    next.state = if decided && DEFINITIVE_OUTCOMES.contains(&error.code) {
                        next.remote_outcome_unknown = false;
                        SubmissionState::Failed
                    } else if ["invalid_credential", "denied"].contains(&error.code) {
                        SubmissionState::Denied
                    } else if p.remote_outcome_unknown {
                        SubmissionState::Uncertain
                    } else if error.retryable {
                        SubmissionState::Retryable
                    } else {
                        SubmissionState::Failed
                    };
                    p = self.save(&p, next)?;
                    // Shared-live publication restarts a definitively stale attempt against the
                    // current destination head: the service merges against the recorded base.
                    if p.can_retry_stale_integration(self.transport.binding.publication) {
                        if let Some(stale) = p.integration.clone() {
                            let mut next = p.clone();
                            next.superseded.push(stale);
                            next.integration = None;
                            next.state = SubmissionState::PrivateRemote;
                            p = self.save(&p, next)?;
                            continue;
                        }
                    }
                    if !error.retryable {
                        break;
                    }
                }
            }
        }
        Ok(p)
    }
    fn request_deadline(deadline: Instant) -> Instant {
        deadline.min(Instant::now() + Duration::from_secs(10))
    }
    fn attempt(&self, mut p: SyncProgress, deadline: Instant) -> Result<SyncProgress, Failure> {
        let binding = &self.transport.binding;
        if p.remote_outcome_unknown {
            let operation = p
                .integration
                .as_ref()
                .filter(|_| p.private_receipt.is_some())
                .map(|i| &i.operation)
                .unwrap_or(&p.operation);
            let path = format!(
                "/operations/{}/{}",
                self.rep.configuration()?.replica.as_str(),
                operation.as_str()
            );
            match self
                .transport
                .json::<Value>("GET", &path, (), Self::request_deadline(deadline))
            {
                Ok(value) => return self.receipt(p, value),
                Err(e) if e.code == "denied" => {} // Exact replay is also currently reauthorized by service.
                Err(e) => return Err(e),
            }
        }
        if p.private_receipt.is_some() {
            if p.shared_receipt.is_some() {
                return Ok(p);
            }
            if let Some(target) = p.resolves.clone() {
                return self.resolution(p, target, deadline);
            }
            if p.integration.is_none() && binding.publication == PublicationMode::Isolated {
                return Ok(p);
            }
            if p.integration.is_none() {
                // Ruling R6: native content of unknown causal base never integrates
                // automatically, not even as a fast-forward, nor through a descendant whose
                // unpublished ancestry (after its bound view) contains it; it stays private.
                if self
                    .rep
                    .unknown_causality_since(&p.local_revision, &binding.view.revision)?
                {
                    if p.error.as_deref() != Some(UNKNOWN_CAUSALITY) {
                        let mut next = p.clone();
                        next.error = Some(UNKNOWN_CAUSALITY.into());
                        p = self.save(&p, next)?;
                    }
                    return Ok(p);
                }
                // A superseded (stale) attempt is retried against the current head.
                let head = if p.superseded.is_empty() {
                    binding.view.head.clone()
                } else {
                    self.current_head(deadline)?
                };
                p = self.integration(p, head)?;
            }
            let mut next = p.clone();
            next.state = SubmissionState::Uncertain;
            next.remote_outcome_unknown = true;
            next.error = None;
            p = self.save(&p, next)?;
            let value = self.transport.json(
                "POST",
                "/integrations",
                p.integration.as_ref().unwrap(),
                deadline,
            )?;
            fault("sync-lost-ack")?;
            return self.receipt(p, value);
        }
        if p.request.is_none() {
            let upload: Upload = self.transport.json(
                "POST",
                "/uploads",
                json!({}),
                Self::request_deadline(deadline),
            )?;
            let mut next = p.clone();
            let config = self.rep.configuration()?;
            next.request = Some(CandidateRequest {
                operation: p.operation.clone(),
                replica: config.replica,
                original_view: binding.view.view.clone(),
                original_head: binding.view.head.clone(),
                revision: p.local_revision.clone(),
                upload: upload.upload,
            });
            next.request_digest = Some(RevisionId::parse(
                ObjectId::for_bytes(
                    &serde_json::to_vec(next.request.as_ref().unwrap())
                        .map_err(|_| FsError::InvalidDescriptor)?,
                )?
                .as_str(),
            )?);
            next.state = SubmissionState::Preparing;
            p = self.save(&p, next)?;
            fault("sync-upload-created")?;
        }
        let request = p.request.as_ref().unwrap();
        // Uncertain requests replay only their frozen POST. Never rebuild their upload session.
        if p.state != SubmissionState::Uncertain {
            let status: UploadStatus = self
                .transport
                .upload_listing(&request.upload, Self::request_deadline(deadline))?;
            let completed = status.validated(&request.upload)?;
            let base = self.rep.revision(&binding.view.revision)?;
            let base_objects = objects(&base);
            let mut revisions = vec![];
            let mut current = p.local_revision.clone();
            let mut seen = BTreeSet::new();
            let mut bytes = 0;
            let mut needed = BTreeMap::new();
            while current != binding.view.revision {
                if !seen.insert(current.clone()) || seen.len() > 128 {
                    return Err(FsError::LimitExceeded.into());
                }
                let revision = self.rep.revision(&current)?;
                let encoded = encode_revision(&revision)?;
                bytes += encoded.len();
                if bytes > 64 * 1024 * 1024 || revision.parents.len() != 1 {
                    return Err(FsError::LimitExceeded.into());
                }
                for (id, size) in objects(&revision) {
                    if !base_objects.contains_key(&id)
                        && needed.insert(id, size).is_some_and(|old| old != size)
                    {
                        return Err(FsError::CorruptObject.into());
                    }
                }
                current = revision.parents[0].clone();
                revisions.push((revision_id(&revision)?, encoded));
            }
            if needed.len() > 4096 || needed.values().sum::<u64>() > 512 * 1024 * 1024 {
                return Err(FsError::LimitExceeded.into());
            }
            for (id, size) in needed {
                if let Some(old) = completed.get(&id) {
                    if *old != size {
                        return Err(FsError::CorruptObject.into());
                    }
                    continue;
                }
                let body = self
                    .rep
                    .sync_object(&id, size, Self::request_deadline(deadline))?;
                self.transport.bytes(
                    "PUT",
                    &format!(
                        "/uploads/{}/objects/{}",
                        request.upload.as_str(),
                        id.as_str()
                    ),
                    body,
                    MAX_CONTROL,
                    Self::request_deadline(deadline),
                    true,
                )?;
                self.transport
                    .counters
                    .lock()
                    .unwrap()
                    .logical_unique_upload_bytes += size;
            }
            for (id, bytes) in revisions.into_iter().rev() {
                self.transport.bytes(
                    "PUT",
                    &format!(
                        "/uploads/{}/revisions/{}",
                        request.upload.as_str(),
                        id.as_str()
                    ),
                    bytes,
                    MAX_CONTROL,
                    Self::request_deadline(deadline),
                    false,
                )?;
            }
        }
        let mut next = p.clone();
        next.state = SubmissionState::Uncertain;
        next.remote_outcome_unknown = true;
        next.error = None;
        p = self.save(&p, next)?;
        fault("sync-before-send")?;
        let value =
            self.transport
                .json("POST", "/candidates", p.request.as_ref().unwrap(), deadline)?;
        fault("sync-lost-ack")?;
        let p = self.receipt(p, value)?;
        if binding.publication == PublicationMode::SharedLive {
            self.attempt(p, deadline)
        } else {
            Ok(p)
        }
    }
    fn receipt(&self, p: SyncProgress, value: Value) -> Result<SyncProgress, Failure> {
        let mut next = p.clone();
        if p.private_receipt.is_some() {
            next.shared_receipt =
                Some(serde_json::from_value(value).map_err(|_| FsError::InvalidDescriptor)?);
            next.state = SubmissionState::Shared;
        } else {
            next.private_receipt =
                Some(serde_json::from_value(value).map_err(|_| FsError::InvalidDescriptor)?);
            next.state = SubmissionState::PrivateRemote;
        }
        next.error = None;
        next.remote_outcome_unknown = false;
        let saved = self.save(&p, next)?;
        super::wakeup::trace(
            if saved.shared_receipt.is_some() {
                "shared_receipt"
            } else {
                "private_receipt"
            },
            self.transport.replica.as_str(),
            saved.operation.as_str(),
            saved.local_revision.as_str(),
            saved
                .shared_receipt
                .as_ref()
                .map(|r| r.head.as_str())
                .unwrap_or("-"),
        );
        Ok(saved)
    }
    fn current_head(&self, deadline: Instant) -> Result<HeadToken, Failure> {
        let view: ViewBinding = self.transport.json(
            "POST",
            "/views",
            json!({"branch":self.transport.binding.branch}),
            Self::request_deadline(deadline),
        )?;
        Ok(view.head)
    }
    /// Explicit resolution replacement: its private receipt is resolved together with every
    /// named conflict against the target head; the original alternatives stay immutable.
    fn resolution(
        &self,
        mut p: SyncProgress,
        target: ResolutionTarget,
        deadline: Instant,
    ) -> Result<SyncProgress, Failure> {
        if p.resolution.is_none() {
            let mut next = p.clone();
            next.resolution = Some(ResolutionRequest {
                operation: OperationId::random()?,
                replica: self.rep.configuration()?.replica,
                conflicts: target.conflicts,
                expected_head: target.expected_head,
                replacement: p
                    .private_receipt
                    .as_ref()
                    .ok_or(FsError::NotFound)?
                    .receipt
                    .clone(),
            });
            next.state = SubmissionState::Preparing;
            p = self.save(&p, next)?;
        }
        let mut next = p.clone();
        next.state = SubmissionState::Uncertain;
        next.remote_outcome_unknown = true;
        next.error = None;
        p = self.save(&p, next)?;
        let value = self.transport.json(
            "POST",
            "/resolutions",
            p.resolution.as_ref().unwrap(),
            deadline,
        )?;
        fault("sync-lost-ack")?;
        let p = self.receipt(p, value)?;
        self.rep.mark_resolved(&p.operation)?;
        Ok(p)
    }
    fn integration(
        &self,
        p: SyncProgress,
        expected_head: HeadToken,
    ) -> Result<SyncProgress, FsError> {
        let mut p = p;
        if let Some(old) = p.integration.clone() {
            if old.expected_head == expected_head
                && !matches!(
                    p.error.as_deref(),
                    Some("dependency_changed" | "recompute_required")
                )
            {
                return Ok(p);
            }
            // Only a definitively stale attempt may be replaced, and it stays on record.
            if p.state != SubmissionState::Failed
                || !matches!(
                    p.error.as_deref(),
                    Some("stale_head" | "dependency_changed" | "recompute_required")
                )
                || p.superseded.len() >= MAX_SUPERSEDED_INTEGRATIONS
            {
                return Err(FsError::OperationMismatch);
            }
            let mut next = p.clone();
            next.superseded.push(old);
            next.integration = None;
            next.state = SubmissionState::PrivateRemote;
            p = self.save(&p, next)?;
        }
        let mut next = p.clone();
        next.integration = Some(IntegrationRequest {
            operation: OperationId::random()?,
            replica: self.rep.configuration()?.replica,
            candidate_receipt: p
                .private_receipt
                .as_ref()
                .ok_or(FsError::NotFound)?
                .receipt
                .clone(),
            expected_head,
            branch: self.transport.binding.branch.clone(),
        });
        next.state = SubmissionState::Preparing;
        self.save(&p, next)
    }
    pub fn integrate(
        &self,
        revision: &RevisionId,
        expected_head: HeadToken,
    ) -> Result<SyncProgress, FsError> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let _execution = self
            .execution
            .acquire(deadline)?
            .ok_or(FsError::Backpressure)?;
        let p = self.integration(self.get(revision)?, expected_head)?;
        self.target_tick(p, deadline)
    }
    /// Runs an explicit resolution replacement record to its shared outcome or a bounded,
    /// definitive failure under the replica's execution gate.
    pub fn run_resolution(&self, revision: &RevisionId) -> Result<SyncProgress, FsError> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let _execution = self
            .execution
            .acquire(deadline)?
            .ok_or(FsError::Backpressure)?;
        let p = self.get(revision)?;
        if p.resolves.is_none() {
            return Err(FsError::OperationMismatch);
        }
        if p.shared_receipt.is_some() {
            // A lost local link after the shared outcome is completed idempotently.
            self.rep.mark_resolved(&p.operation)?;
            return Ok(p);
        }
        self.target_tick(p, deadline)
    }
    pub fn drain(
        &self,
        revision: &RevisionId,
        level: DurabilityLevel,
        deadline: Instant,
    ) -> Result<SyncProgress, FsError> {
        let mut p = self.get(revision)?;
        if level == DurabilityLevel::Applied {
            // Incoming adoption needs the same gate: never hold it while awaiting native ACK.
            if !p.reached(DurabilityLevel::Shared) {
                p = self.drain(revision, DurabilityLevel::Shared, deadline)?;
            }
            while !p.reached(level) && Instant::now() < deadline {
                std::thread::sleep(
                    Duration::from_millis(100)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
                p = self.get(revision)?;
            }
            return Ok(p);
        }
        let deadline = deadline.min(Instant::now() + Duration::from_secs(60));
        if p.reached(level) {
            return Ok(p);
        }
        let Some(_execution) = self.execution.acquire(deadline)? else {
            return self.get(revision);
        };
        p = self.get(revision)?;
        while !p.reached(level) && Instant::now() < deadline {
            if matches!(p.state, SubmissionState::Denied | SubmissionState::Failed)
                || level == DurabilityLevel::Shared && held(&p)
                || level == DurabilityLevel::Shared
                    && p.private_receipt.is_some()
                    && p.integration.is_none()
                    && self.transport.binding.publication == PublicationMode::Isolated
            {
                break;
            }
            p = self.target_tick(p, deadline)?;
            if !p.reached(level) {
                std::thread::sleep(
                    Duration::from_millis(100)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
        Ok(p)
    }
    pub fn counters(&self) -> Value {
        json!(*self.transport.counters.lock().unwrap())
    }
}
fn objects(r: &Revision) -> BTreeMap<ObjectId, u64> {
    let mut result = BTreeMap::new();
    for entry in &r.tree.entries {
        if let EntryContent::File { version } = &entry.content {
            for extent in &version.extents {
                if let Extent::Chunk {
                    object,
                    object_size,
                    ..
                } = extent
                {
                    result.insert(object.clone(), *object_size);
                }
            }
        }
    }
    result
}
/// Error code for a private candidate held because its native causal base is unknown.
pub(crate) const UNKNOWN_CAUSALITY: &str = "unknown_causality";
/// Held private by Ruling R6 until explicit integration or recovery.
pub(crate) fn held(p: &SyncProgress) -> bool {
    p.state == SubmissionState::PrivateRemote
        && p.integration.is_none()
        && p.resolved_by.is_none()
        && p.error.as_deref() == Some(UNKNOWN_CAUSALITY)
}
#[cfg(not(feature = "test-faults"))]
fn fault(_: &str) -> Result<(), FsError> {
    Ok(())
}
#[cfg(feature = "test-faults")]
fn fault(point: &str) -> Result<(), FsError> {
    if std::env::var("MAGUS_TEST_FAULT_POINT").ok().as_deref() == Some(point) {
        let marker = std::env::var_os("MAGUS_TEST_FAULT_MARKER").ok_or(FsError::InvalidPath)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)?;
        use std::io::Write;
        file.write_all(point.as_bytes())?;
        file.sync_all()?;
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
pub fn install_source(rep: &Replica) -> Result<(), FsError> {
    if rep.sync_status()?.binding.is_some() {
        SyncController::new(rep)?;
    }
    Ok(())
}
pub fn attach(
    rep: &Replica,
    profile: &Path,
    branch: BranchName,
    publication: PublicationMode,
) -> Result<Value, FsError> {
    let config = rep.configuration()?;
    let (p, identity, _, _) = transport::load(profile, &config.content_roots)?;
    if p.replica != config.replica {
        return Err(FsError::ConfigMismatch);
    }
    if rep.sync_status()?.binding.is_some() {
        return Err(FsError::ConfigMismatch);
    }
    if rep.status()?.head.is_some() {
        return Err(FsError::DirtyWorkingState);
    }
    // Temporary request binding has no content authority until the returned view is checked.
    let mut binding = SyncBinding {
        id: p.namespace,
        branch: branch.clone(),
        publication,
        source: RemoteSourceId::random()?,
        view: ViewBinding {
            view: ViewId::random()?,
            head: HeadToken::random()?,
            revision: RevisionId::parse(ObjectId::for_bytes(b"unbound")?.as_str())?,
        },
        transport_profile: profile.into(),
        transport_identity: identity,
    };
    let t = Transport::new(binding.clone(), &config)?;
    binding.view = t
        .json(
            "POST",
            "/views",
            json!({"branch":branch}),
            Instant::now() + Duration::from_secs(10),
        )
        // Admission and transport failure do not establish an authority denial.
        .map_err(|error| match error.code {
            "invalid_credential" | "denied" => FsError::PermissionDenied,
            "backpressure" => FsError::Backpressure,
            _ => FsError::InvalidSource,
        })?;
    let bytes = t
        .bytes(
            "GET",
            &format!("/views/{}/descriptor", binding.view.view.as_str()),
            vec![],
            MAX_DESCRIPTOR,
            Instant::now() + Duration::from_secs(10),
            false,
        )
        .map_err(|_| FsError::InvalidSource)?;
    if !decode_revision(&bytes)?.parents.is_empty() {
        return Err(FsError::InvalidDescriptor);
    }
    rep.import_revision(
        ImportDescriptor {
            expected: binding.view.revision.clone(),
            bytes,
        },
        ChunkSource::Remote {
            source: binding.source.clone(),
        },
    )?;
    rep.configure_sync(binding.clone())?;
    rep.begin(
        &binding.view.revision,
        rep.actor_for_uid(unsafe { libc::geteuid() })?,
        false,
    )?;
    Ok(
        json!({"ok":true,"binding":binding,"counters":*t.counters.lock().unwrap(),"applied_revision":null}),
    )
}

/// Trusted profile configuration selects attribution; no workload/control request may supply it.
pub(crate) fn publication_actor(rep: &Replica, fallback: Actor) -> Result<Actor, FsError> {
    match rep.sync_status()?.binding {
        Some(binding) => {
            Transport::new(binding, &rep.configuration()?)?.publication_actor(fallback)
        }
        None => Ok(fallback),
    }
}

#[cfg(test)]
mod upload_tests {
    use super::*;
    #[test]
    fn replica_execution_is_shared_and_deadline_does_not_release_another_attempt() {
        let replica = ReplicaId::random().unwrap();
        let first = SyncExecution::for_replica(&replica).unwrap();
        let second = SyncExecution::for_replica(&replica).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let publisher_epoch = second.publisher.epoch();
        let incoming_epoch = second.incoming.epoch();
        first.publisher.notify();
        assert_ne!(publisher_epoch, second.publisher.epoch());
        assert_eq!(
            incoming_epoch,
            second.incoming.epoch(),
            "publisher and incoming are independent"
        );
        let guard = first
            .acquire(Instant::now() + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let started = Instant::now();
        assert!(second
            .acquire(started + Duration::from_millis(20))
            .unwrap()
            .is_none());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(second.active.try_lock().is_err());
        let other = SyncExecution::for_replica(&ReplicaId::random().unwrap()).unwrap();
        let other_epoch = other.publisher.epoch();
        first.publisher.notify();
        assert_eq!(
            other_epoch,
            other.publisher.epoch(),
            "replica wakeups are isolated"
        );
        assert!(other
            .acquire(Instant::now() + Duration::from_secs(1))
            .unwrap()
            .is_some());
        drop(guard);
        assert!(second
            .acquire(Instant::now() + Duration::from_secs(1))
            .unwrap()
            .is_some());
    }
    #[test]
    fn upload_listing_accepts_4096_bounded_entries_and_rejects_invalid_shapes() {
        let upload = UploadId::random().unwrap();
        let objects: Vec<Value> = (0_u64..4096)
            .map(|i| {
                json!({
                    "object":ObjectId::for_bytes(&i.to_le_bytes()).unwrap(), "size":128*1024
                })
            })
            .collect();
        let value = json!({"upload":upload,"objects":objects});
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() > MAX_CONTROL);
        assert!(bytes.len() <= transport::MAX_UPLOAD_LIST_RESPONSE);
        let decode = |v| {
            serde_json::from_value::<UploadStatus>(v)
                .unwrap()
                .validated(&upload)
        };
        assert_eq!(decode(value.clone()).unwrap().len(), 4096);
        let mut too_many = value.clone();
        too_many["objects"]
            .as_array_mut()
            .unwrap()
            .push(objects[0].clone());
        assert!(matches!(decode(too_many), Err(FsError::LimitExceeded)));
        let mut oversized = value.clone();
        oversized["objects"][0]["size"] = json!(MAX_CHUNK + 1);
        assert!(matches!(decode(oversized), Err(FsError::LimitExceeded)));
        let mut total = value.clone();
        total["objects"][0]["size"] = json!(128 * 1024 + 1);
        assert!(matches!(decode(total), Err(FsError::LimitExceeded)));
        let mut duplicate = value.clone();
        duplicate["objects"][1] = objects[0].clone();
        assert!(matches!(decode(duplicate), Err(FsError::InvalidDescriptor)));
        let mut extra = value.clone();
        extra["objects"][0]["extra"] = json!(true);
        assert!(serde_json::from_value::<UploadStatus>(extra).is_err());
        let mut wrong = value;
        wrong["upload"] = json!(UploadId::random().unwrap());
        assert!(matches!(decode(wrong), Err(FsError::InvalidDescriptor)));
    }
}
