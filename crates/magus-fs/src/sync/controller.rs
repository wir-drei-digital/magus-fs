use super::transport::{self, Failure, Transport};
use magus_fs_core::{protocol::*, *};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
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
pub struct SyncController {
    rep: Replica,
    transport: Transport,
}
impl SyncController {
    pub fn new(rep: &Replica) -> Result<Self, FsError> {
        let binding = rep.sync_status()?.binding.ok_or(FsError::ConfigMismatch)?;
        let transport = Transport::new(binding, &rep.configuration()?)?;
        rep.set_remote_fetcher(Arc::new(transport.clone()))?;
        Ok(Self {
            rep: rep.clone(),
            transport,
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
    pub fn tick(&self) -> Result<SyncProgress, FsError> {
        let p = self
            .rep
            .sync_status()?
            .submissions
            .into_iter()
            .find(|p| {
                matches!(
                    p.state,
                    SubmissionState::Queued
                        | SubmissionState::Preparing
                        | SubmissionState::Retryable
                        | SubmissionState::Uncertain
                ) || p.state == SubmissionState::PrivateRemote
                    && self.transport.binding.publication == PublicationMode::SharedLive
            })
            .ok_or(FsError::NotFound)?;
        self.target_tick(p, Instant::now() + Duration::from_secs(60))
    }
    fn target_tick(&self, mut p: SyncProgress, deadline: Instant) -> Result<SyncProgress, FsError> {
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
            match self.attempt(p.clone(), deadline) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    // Reload: the attempt may have durably crossed the uncertain boundary.
                    p = self.get(&p.local_revision)?;
                    let mut next = p.clone();
                    next.error = Some(error.code.into());
                    next.state = if error.code == "stale_head" && p.integration.is_some() {
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
            if p.integration.is_none() && binding.publication == PublicationMode::Isolated {
                return Ok(p);
            }
            if p.integration.is_none() {
                p = self.integration(p, binding.view.head.clone())?;
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
        Ok(self.save(&p, next)?)
    }
    fn integration(
        &self,
        p: SyncProgress,
        expected_head: HeadToken,
    ) -> Result<SyncProgress, FsError> {
        if let Some(old) = &p.integration {
            if old.expected_head != expected_head {
                return Err(FsError::OperationMismatch);
            }
            return Ok(p);
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
        let p = self.integration(self.get(revision)?, expected_head)?;
        self.target_tick(p, Instant::now() + Duration::from_secs(60))
    }
    pub fn drain(
        &self,
        revision: &RevisionId,
        level: DurabilityLevel,
        deadline: Instant,
    ) -> Result<SyncProgress, FsError> {
        let mut p = self.get(revision)?;
        if level == DurabilityLevel::Applied {
            return Err(FsError::UnsupportedMode);
        }
        let deadline = deadline.min(Instant::now() + Duration::from_secs(60));
        while !p.reached(level) && Instant::now() < deadline {
            if matches!(p.state, SubmissionState::Denied | SubmissionState::Failed)
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
        .map_err(|_| FsError::PermissionDenied)?;
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

#[cfg(test)]
mod upload_tests {
    use super::*;
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
