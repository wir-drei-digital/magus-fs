//! Authenticated incoming discovery. The execution gate never holds Core across HTTP.
use super::transport::Transport;
use super::{controller::SyncExecution, transport::Failure};
use magus_fs_core::{protocol::*, *};
use serde_json::json;
use std::time::Duration;
use std::{collections::BTreeMap, sync::Arc, time::Instant};
struct Sources(BTreeMap<RemoteSourceId, Transport>);
impl RemoteFetcher for Sources {
    fn fetch(
        &self,
        source: &RemoteSourceId,
        object: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError> {
        self.0
            .get(source)
            .ok_or(FsError::InvalidSource)?
            .fetch(source, object, size, deadline)
    }
}
pub(super) fn install_sources(rep: &Replica, extra: Option<SyncBinding>) -> Result<(), FsError> {
    let config = rep.configuration()?;
    let mut bindings = rep.sync_sources()?;
    if let Some(extra) = extra {
        bindings.push(extra);
    }
    let mut sources = BTreeMap::new();
    for binding in bindings {
        sources.insert(binding.source.clone(), Transport::new(binding, &config)?);
    }
    rep.set_remote_fetcher(Arc::new(Sources(sources)))
}
pub(crate) struct Incoming {
    rep: Replica,
    execution: Arc<SyncExecution>,
    cursor: i64,
    credential: Option<ObjectId>,
    needs_refresh: bool,
    pending_source: Option<SyncBinding>,
}
impl Incoming {
    pub fn new(rep: &Replica) -> Result<Self, FsError> {
        Ok(Self {
            rep: rep.clone(),
            execution: SyncExecution::for_replica(&rep.configuration()?.replica)?,
            cursor: rep.incoming_recovery()?.cursor,
            credential: None,
            needs_refresh: true,
            pending_source: None,
        })
    }
    pub(crate) fn wakeup(&self) -> Arc<super::wakeup::Wakeup> {
        self.execution.incoming.clone()
    }
    /// A native consumer that cleared readiness must reverify even an unchanged head.
    pub fn request_refresh(&mut self) {
        self.needs_refresh = true;
    }
    /// Poll the durable log even without hints. Refresh metadata also detects grant changes.
    pub fn poll<T>(
        &mut self,
        apply: impl FnOnce(SyncBinding, u64) -> Result<T, FsError>,
    ) -> Result<Option<T>, FsError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let Some(_gate) = self
            .execution
            .acquire(Instant::now() + Duration::from_millis(50))?
        else {
            return Ok(None);
        };
        let prepared = (|| -> Result<_, FsError> {
            let binding = self
                .rep
                .sync_status()?
                .binding
                .ok_or(FsError::ConfigMismatch)?;
            let transport = Transport::new(binding.clone(), &self.rep.configuration()?)?;
            let credential = transport.credential_stamp()?;
            let authority_generation = self.rep.live_status()?.authority_generation;
            Ok((binding, transport, credential, authority_generation))
        })();
        let (binding, transport, credential, authority_generation) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let mut recovery = self.rep.incoming_recovery()?;
                recovery.discovery_error = Some(error.code().into());
                self.rep.record_incoming_recovery(recovery)?;
                return Err(error);
            }
        };
        if self.credential.as_ref() != Some(&credential) {
            self.needs_refresh = true;
            self.pending_source = None;
        }
        let refreshed = self.needs_refresh;
        let result = (|| -> Result<Option<T>, Failure> {
            let response: Result<ChangePage, Failure> = transport.json(
                "GET",
                &format!(
                    "/changes?branch={}&after={}&limit=128",
                    binding.branch.as_str(),
                    self.cursor
                ),
                (),
                deadline,
            );
            let page = match response {
                Ok(page) => page,
                Err(error) if matches!(error.code, "cursor_expired" | "invalid_cursor") => {
                    self.needs_refresh = true;
                    let mut recovery = self.rep.incoming_recovery()?;
                    recovery.needs_snapshot = true;
                    recovery.discovery_error = Some(error.code.into());
                    self.rep.record_incoming_recovery(recovery)?;
                    transport.json(
                        "GET",
                        &format!("/changes?branch={}&snapshot=true", binding.branch.as_str()),
                        (),
                        deadline,
                    )?
                }
                Err(error) => return Err(error),
            };
            super::wakeup::trace(
                "discovered",
                transport.replica.as_str(),
                "-",
                "-",
                page.events.last().map(|e| e.head.as_str()).unwrap_or("-"),
            );
            self.cursor = page.cursor;
            let mut recovery = self.rep.incoming_recovery()?;
            recovery.cursor = self.cursor;
            self.rep.record_incoming_recovery(recovery)?;
            let view: ViewBinding =
                transport.json("POST", "/views", json!({"branch":binding.branch}), deadline)?;
            if !refreshed
                && !self.needs_refresh
                && binding.view.revision == view.revision
                && binding.view.head == view.head
            {
                self.rep
                    .observe_remote_authority(Some(&view.revision), authority_generation)?;
                return Ok(None);
            }
            let bytes = transport.bytes(
                "GET",
                &format!("/views/{}/descriptor", view.view.as_str()),
                vec![],
                MAX_DESCRIPTOR,
                deadline,
                false,
            )?;
            if !decode_revision(&bytes)?.parents.is_empty() {
                return Err(FsError::InvalidDescriptor.into());
            }
            let mut next = binding.clone();
            next.source = RemoteSourceId::random()?;
            next.view = view;
            if let Some(existing) = self.rep.sync_sources()?.into_iter().find(|b| {
                !refreshed && b.view.revision == next.view.revision && b.view.head == next.view.head
            }) {
                next = existing;
            }
            if refreshed {
                if let Some(pending) = &self.pending_source {
                    if pending.view.revision == next.view.revision
                        && pending.view.head == next.view.head
                    {
                        next = pending.clone();
                    }
                }
            }
            self.rep.register_sync_source(next.clone())?;
            self.pending_source = Some(next.clone());
            self.rep.import_revision(
                ImportDescriptor {
                    expected: next.view.revision.clone(),
                    bytes,
                },
                ChunkSource::Remote {
                    source: next.source.clone(),
                },
            )?;
            self.rep
                .observe_remote_authority(Some(&next.view.revision), authority_generation)?;
            self.credential = Some(credential);
            // Private publication still observes authority, but never adopts shared bytes.
            if binding.publication == PublicationMode::Isolated {
                self.needs_refresh = false;
                self.pending_source = None;
                return Ok(None);
            }
            let generation = self.rep.status()?.generation;
            install_sources(&self.rep, Some(next.clone()))?;
            match apply(next, generation) {
                Ok(adoption) => {
                    self.needs_refresh = false;
                    self.pending_source = None;
                    Ok(Some(adoption))
                }
                Err(FsError::DirtyWorkingState | FsError::GenerationMismatch) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })();
        match result {
            Ok(v) => {
                let mut recovery = self.rep.incoming_recovery()?;
                recovery.cursor = self.cursor;
                recovery.needs_snapshot = false;
                recovery.discovery_error = None;
                self.rep.record_incoming_recovery(recovery)?;
                Ok(v)
            }
            Err(e) => {
                let mut recovery = self.rep.incoming_recovery()?;
                recovery.cursor = self.cursor;
                recovery.discovery_error = Some(e.code.into());
                self.rep.record_incoming_recovery(recovery)?;
                if matches!(e.code, "invalid_credential" | "denied") {
                    self.rep
                        .observe_remote_authority(None, authority_generation)?;
                    self.needs_refresh = true;
                }
                if matches!(e.code, "invalid_cursor" | "cursor_expired") {
                    self.cursor = 0;
                }
                Err(if e.retryable {
                    FsError::InvalidSource
                } else {
                    FsError::PermissionDenied
                })
            }
        }
    }
}

pub(crate) fn subscribe(
    rep: Replica,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering;
        while !stop.load(Ordering::Relaxed) {
            if let Ok(status) = rep.sync_status() {
                if let Some(binding) = status.binding {
                    if let Ok(config) = rep.configuration() {
                        if let Ok(transport) = Transport::new(binding, &config) {
                            if let Ok(owner) = SyncExecution::for_replica(&config.replica) {
                                let _ = transport.hints(&stop, &|| owner.incoming.notify());
                            }
                        }
                    }
                }
            }
            for _ in 0..10 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    })
}

#[derive(Clone)]
pub(crate) struct MountedPrepared {
    pub binding: SyncBinding,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub proof: Option<ContinuationProofV1>,
    pub credential_stamp: ObjectId,
    pub authority_generation: u64,
}
pub(crate) enum MountedIncoming {
    Clean(Adoption),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Continued(ContinuationOutcome),
}
impl Incoming {
    /// Snapshot ownership, release it for HTTP, then compare every local fence again.
    pub(crate) fn poll_mounted(
        &mut self,
        apply: impl FnOnce(MountedPrepared) -> Result<MountedIncoming, FsError>,
    ) -> Result<Option<MountedIncoming>, FsError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (binding, transport, credential, generation, head, authority, receipt, dirty, ready) = {
            let Some(_gate) = self
                .execution
                .acquire(Instant::now() + Duration::from_millis(50))?
            else {
                return Ok(None);
            };
            let sync = self.rep.sync_status()?;
            let binding = sync.binding.ok_or(FsError::ConfigMismatch)?;
            let transport = Transport::new(binding.clone(), &self.rep.configuration()?)?;
            let credential = transport.credential_stamp()?;
            let snapshot = self.rep.scheduling_snapshot()?;
            let head = snapshot.head.ok_or(FsError::BaseMismatch)?;
            let matching: Vec<_> = sync
                .submissions
                .iter()
                .filter(|p| p.local_revision == head)
                .collect();
            let receipt = if matching.len() == 1 {
                matching[0].shared_receipt.clone()
            } else {
                None
            };
            let ready = receipt.is_some() || head == binding.view.revision;
            (
                binding,
                transport,
                credential,
                snapshot.generation,
                head,
                self.rep.live_status()?.authority_generation,
                receipt,
                snapshot.dirty,
                ready,
            )
        };
        let discovered = (|| -> Result<_, Failure> {
            if dirty {
                if let Some(receipt) = receipt {
                    match super::continuation::fetch_proof(
                        &transport,
                        &ContinuationRequestV1 { receipt },
                        deadline,
                    ) {
                        Ok(response) => {
                            return Ok((
                                response.proof.view.clone(),
                                encode_revision(&response.descriptor)?,
                                Some(response.proof),
                            ))
                        }
                        Err(error)
                            if matches!(
                                error.code,
                                "continuation_evidence_unavailable"
                                    | "continuation_evidence_limit"
                                    | "continuation_not_descendant"
                                    | "continuation_scope_unsupported"
                                    | "continuation_capability_unavailable"
                            ) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            let view: ViewBinding =
                transport.json("POST", "/views", json!({"branch":binding.branch}), deadline)?;
            let bytes = transport.bytes(
                "GET",
                &format!("/views/{}/descriptor", view.view.as_str()),
                vec![],
                MAX_DESCRIPTOR,
                deadline,
                false,
            )?;
            let descriptor = decode_revision(&bytes)?;
            if !descriptor.parents.is_empty() || revision_id(&descriptor)? != view.revision {
                return Err(FsError::InvalidDescriptor.into());
            }
            Ok((view, bytes, None))
        })();
        let Some(_gate) = self
            .execution
            .acquire(Instant::now() + Duration::from_millis(50))?
        else {
            return Ok(None);
        };
        let snapshot = self.rep.scheduling_snapshot()?;
        if self.rep.sync_status()?.binding.as_ref() != Some(&binding)
            || snapshot.generation != generation
            || snapshot.head.as_ref() != Some(&head)
            || self.rep.live_status()?.authority_generation != authority
            || transport.credential_stamp()? != credential
        {
            return Err(FsError::GenerationMismatch);
        }
        let (view, bytes, proof) = match discovered {
            Ok(result) => result,
            Err(error) => {
                if matches!(error.code, "denied" | "invalid_credential") {
                    self.rep.observe_remote_authority(None, authority)?;
                }
                let mut recovery = self.rep.incoming_recovery()?;
                recovery.discovery_error = Some(error.code.into());
                self.rep.record_incoming_recovery(recovery)?;
                return Err(if error.retryable {
                    FsError::InvalidSource
                } else {
                    FsError::PermissionDenied
                });
            }
        };
        let mut next = binding.clone();
        next.source = RemoteSourceId::random()?;
        next.view = view;
        if let Some(existing) = self
            .rep
            .sync_sources()?
            .into_iter()
            .find(|b| b.view == next.view)
        {
            next = existing;
        }
        self.rep.register_sync_source(next.clone())?;
        self.rep.import_revision(
            ImportDescriptor {
                expected: next.view.revision.clone(),
                bytes,
            },
            ChunkSource::Remote {
                source: next.source.clone(),
            },
        )?;
        self.rep
            .observe_remote_authority(Some(&next.view.revision), authority)?;
        install_sources(&self.rep, Some(next.clone()))?;
        self.credential = Some(credential.clone());
        if !ready || next == binding {
            return Ok(None);
        }
        if transport.credential_stamp()? != credential {
            return Err(FsError::GenerationMismatch);
        }
        apply(MountedPrepared {
            binding: next,
            proof,
            credential_stamp: credential,
            authority_generation: self.rep.live_status()?.authority_generation,
        })
        .map(Some)
    }
}
