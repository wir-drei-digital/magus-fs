//! Native events only schedule scans. Core owns capture, recovery, application and queue state.
use super::SyncExecution;
use magus_fs_core::*;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
pub(crate) struct NativeWatch {
    rep: Replica,
    actor: Actor,
    execution: Arc<SyncExecution>,
    hint: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
    _watcher: RecommendedWatcher,
    next_scan: Instant,
    hinted_at: Option<Instant>,
}
impl NativeWatch {
    pub fn new(rep: &Replica, actor: Actor) -> Result<Self, FsError> {
        let native = rep.native_config()?.ok_or(FsError::ConfigMismatch)?;
        rep.verify_native_baseline(actor.clone())?;
        let hint = Arc::new(AtomicBool::new(true));
        let overflow = Arc::new(AtomicBool::new(false));
        let h = hint.clone();
        let o = overflow.clone();
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                // Fault builds qualify complete hint omission while retaining the real watcher.
                #[cfg(feature = "test-faults")]
                if std::env::var_os("MAGUS_TEST_DROP_NATIVE_HINTS").is_some() {
                    return;
                }
                if event.as_ref().is_err() || event.as_ref().is_ok_and(|e| e.need_rescan()) {
                    o.store(true, Ordering::Release);
                }
                h.store(true, Ordering::Release);
            })
            .map_err(|_| FsError::InvalidSource)?;
        watcher
            .watch(&native.root, RecursiveMode::Recursive)
            .map_err(|_| FsError::InvalidSource)?;
        Ok(Self {
            rep: rep.clone(),
            actor,
            execution: SyncExecution::for_replica(&rep.configuration()?.replica)?,
            hint,
            overflow,
            _watcher: watcher,
            next_scan: Instant::now(),
            hinted_at: None,
        })
    }
    pub fn tick(&mut self) -> Result<(), FsError> {
        let now = Instant::now();
        if self.hint.swap(false, Ordering::AcqRel) && self.hinted_at.is_none() {
            self.hinted_at = Some(now);
        }
        if now >= self.next_scan
            || self.overflow.swap(false, Ordering::AcqRel)
            || self
                .hinted_at
                .is_some_and(|t| now.duration_since(t) >= Duration::from_millis(100))
        {
            self.scan()?;
            self.next_scan = Instant::now() + Duration::from_secs(2);
            self.hinted_at = None;
        }
        Ok(())
    }
    pub fn scan(&mut self) -> Result<Option<RevisionId>, FsError> {
        let Some(_gate) = self
            .execution
            .acquire(Instant::now() + Duration::from_millis(50))?
        else {
            return Ok(None);
        };
        self.rep.recover_native_application(self.actor.clone())?;
        self.rep.scan_native_status()?;
        // Admit the exact previous capture before observing another generation. A crash between
        // capture and enqueue must not lose its operation or silently move it onto a new base.
        self.admit()?;
        let changed = self
            .rep
            .capture_native_changes(OperationId::random()?, self.actor.clone())?;
        self.admit()?;
        Ok(changed)
    }
    fn admit(&self) -> Result<(), FsError> {
        let status = self.rep.sync_status()?;
        let binding = status.binding.ok_or(FsError::ConfigMismatch)?;
        let Some(head) = self.rep.status()?.head else {
            return Ok(());
        };
        if head == binding.view.revision
            || status.submissions.iter().any(|p| p.local_revision == head)
        {
            return Ok(());
        }
        let revision = self.rep.revision(&head)?;
        self.rep.enqueue_submission(PendingSubmission {
            operation: revision.operation,
            local_revision: head,
            original_view: binding.view.view,
            original_head: binding.view.head,
            expected_local_generation: self.rep.status()?.generation,
        })
    }
}

pub(crate) fn serve(rep: &Replica) -> Result<(), FsError> {
    let actor = super::publication_actor(rep, rep.actor_for_uid(unsafe { libc::geteuid() })?)?;
    let mut watch = NativeWatch::new(rep, actor.clone())?;
    let watch_rep = rep.clone();
    std::thread::spawn(move || loop {
        if let Err(e) = watch.tick() {
            let _ = watch_rep.record_native_error(&e);
        }
        std::thread::sleep(Duration::from_millis(50));
    });
    let publisher = super::SyncController::new(rep)?;
    std::thread::spawn(move || loop {
        let _ = publisher.tick();
        std::thread::sleep(Duration::from_secs(1));
    });
    let _hints = super::subscribe(rep.clone(), Arc::new(AtomicBool::new(false)));
    let mut incoming = super::Incoming::new(rep)?;
    loop {
        if let Err(e) = incoming.poll(|binding, generation| {
            rep.apply_native_view(binding, generation, OperationId::random()?, actor.clone())
        }) {
            incoming.request_refresh();
            rep.record_native_error(&e)?;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use magus_fs_core::protocol::*;
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};
    #[test]
    fn omitted_events_and_restart_admit_original_capture_without_echo() {
        let root = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "fs2-watch-{}",
            RemoteSourceId::random().unwrap().as_str()
        ));
        fs::create_dir(&root).unwrap();
        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("a"), b"old").unwrap();
        let principal = PrincipalId::random().unwrap();
        let group = GroupId::random().unwrap();
        let replica = ReplicaId::random().unwrap();
        let actor = Actor::new(principal.clone());
        let rep = Replica::open(
            root.join("state"),
            ReplicaConfig {
                replica,
                authorities: vec![Authority {
                    principal,
                    uid: unsafe { libc::geteuid() },
                    gid: fs::metadata(&tree).unwrap().gid(),
                    primary_group: group.clone(),
                    groups: vec![group],
                    dac_override: false,
                    ownership_transfer: false,
                }],
                content_roots: vec![tree.clone()],
                cache_bytes: 1024 * 1024,
                history_administrators: vec![],
                retained_history_grants: vec![],
            },
        )
        .unwrap();
        let policy = CapturePolicy {
            included_roots: vec![".".into()],
            excluded_prefixes: vec![],
        };
        rep.configure_native(NativeConfig {
            root: tree.clone(),
            policy: policy.clone(),
            creation_umask: 0o022,
        })
        .unwrap();
        let base = rep
            .capture(&tree, policy, OperationId::random().unwrap(), actor.clone())
            .unwrap();
        let binding = SyncBinding {
            id: NamespaceId::random().unwrap(),
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::SharedLive,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision: base.clone(),
            },
            transport_profile: root.join("profile"),
            transport_identity: TransportIdentity::for_bytes(b"profile").unwrap(),
        };
        rep.configure_sync(binding.clone()).unwrap();
        let mut watch = NativeWatch::new(&rep, actor.clone()).unwrap();
        assert!(watch.scan().unwrap().is_none());
        fs::write(tree.join("a"), b"changed without a delivered event").unwrap();
        let changed = watch
            .scan()
            .unwrap()
            .expect("periodic rescan must capture omitted events");
        let pending = rep.pending_submissions().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].local_revision, changed);
        assert_eq!(pending[0].original_head, binding.view.head);
        assert!(watch.scan().unwrap().is_none());
        assert_eq!(rep.pending_submissions().unwrap().len(), 1);
        drop(watch);
        fs::write(tree.join("a"), b"captured before owner interruption").unwrap();
        let operation = OperationId::random().unwrap();
        let frozen = rep
            .capture_native_changes(operation.clone(), actor.clone())
            .unwrap()
            .unwrap();
        drop(rep);
        let rep = Replica::reopen(root.join("state")).unwrap();
        let mut watch = NativeWatch::new(&rep, actor).unwrap();
        watch.scan().unwrap();
        let pending = rep.pending_submissions().unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|p| p.operation == operation
            && p.local_revision == frozen
            && p.original_head == binding.view.head));
        rep.record_native_error(&FsError::UnstableCapture).unwrap();
        assert!(matches!(
            rep.native_status().unwrap().unwrap().status,
            NativeApplyStatus::Unstable { .. }
        ));
        drop(watch);
        drop(rep);
        fs::remove_dir_all(root).unwrap();
    }
}
