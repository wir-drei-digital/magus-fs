//! Authenticated incoming discovery. The execution gate never holds Core across HTTP.
use super::transport::Transport;
#[cfg(target_os = "linux")]
use super::{controller::SyncExecution, transport::Failure};
use magus_fs_core::{protocol::*, *};
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub(crate) struct Incoming {
    rep: Replica,
    execution: Arc<SyncExecution>,
    cursor: i64,
    credential: Option<ObjectId>,
    needs_refresh: bool,
    pending_source: Option<SyncBinding>,
}
#[cfg(target_os = "linux")]
impl Incoming {
    pub fn new(rep: &Replica) -> Result<Self, FsError> {
        Ok(Self {
            rep: rep.clone(),
            execution: SyncExecution::for_replica(&rep.configuration()?.replica)?,
            cursor: 0,
            credential: None,
            needs_refresh: true,
            pending_source: None,
        })
    }
    /// Poll the durable log even without hints. Refresh metadata also detects grant changes.
    pub fn poll(
        &mut self,
        apply: impl FnOnce(SyncBinding, u64) -> Result<Adoption, FsError>,
    ) -> Result<Option<Adoption>, FsError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let Some(_gate) = self
            .execution
            .acquire(Instant::now() + Duration::from_millis(50))?
        else {
            return Ok(None);
        };
        let binding = self
            .rep
            .sync_status()?
            .binding
            .ok_or(FsError::ConfigMismatch)?;
        let transport = Transport::new(binding.clone(), &self.rep.configuration()?)?;
        let credential = transport.credential_stamp()?;
        if self.credential.as_ref() != Some(&credential) {
            self.needs_refresh = true;
            self.pending_source = None;
        }
        let refreshed = self.needs_refresh;
        let authority_generation = self.rep.live_status()?.authority_generation;
        let result = (|| -> Result<Option<Adoption>, Failure> {
            let page: ChangePage = transport.json(
                "GET",
                &format!(
                    "/changes?branch={}&after={}&limit=128",
                    binding.branch.as_str(),
                    self.cursor
                ),
                (),
                deadline,
            )?;
            self.cursor = page.cursor;
            let view: ViewBinding =
                transport.json("POST", "/views", json!({"branch":binding.branch}), deadline)?;
            if !refreshed
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
            Ok(v) => Ok(v),
            Err(e) => {
                if matches!(e.code, "invalid_credential" | "denied") {
                    self.rep
                        .observe_remote_authority(None, authority_generation)?;
                    self.needs_refresh = true;
                }
                if matches!(e.code, "invalid_cursor" | "expired_cursor") {
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

#[cfg(target_os = "linux")]
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
                            let _ = transport.hints(&stop);
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
