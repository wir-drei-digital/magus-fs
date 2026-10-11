//! Mounted saves are observed in the engine; never rescan the owner's mount.
use super::SyncExecution;
use magus_fs_core::*;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) struct MountedCapture {
    rep: Replica,
    execution: Arc<SyncExecution>,
    observed: Option<(u64, Instant)>,
}
impl MountedCapture {
    pub(crate) fn new(rep: &Replica) -> Result<Self, FsError> {
        Ok(Self {
            rep: rep.clone(),
            execution: SyncExecution::for_replica(&rep.configuration()?.replica)?,
            observed: None,
        })
    }
    /// Admission always precedes another capture, including after owner restart.
    fn admit(&self) -> Result<(), FsError> {
        super::admit_engine_checkpoint(&self.rep)
    }
    /// The callback takes only the short adapter lock for checkpoint; no HTTP runs here.
    pub(crate) fn tick(
        &mut self,
        capture: impl FnOnce(&OperationId, u64) -> Result<RevisionId, FsError>,
    ) -> Result<Option<RevisionId>, FsError> {
        let execution = self.execution.clone();
        let Some(_gate) = execution.acquire(Instant::now() + Duration::from_millis(50))? else {
            return Ok(None);
        };
        self.admit()?;
        let status = self.rep.status()?;
        if !status.dirty {
            self.observed = None;
            return Ok(None);
        }
        let now = Instant::now();
        match self.observed {
            Some((generation, since)) if generation == status.generation => {
                if now.duration_since(since) < Duration::from_millis(100) {
                    return Ok(None);
                }
            }
            _ => {
                self.observed = Some((status.generation, now));
                return Ok(None);
            }
        }
        let revision = capture(&OperationId::random()?, status.generation)?;
        self.observed = None;
        self.admit()?;
        Ok(Some(revision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magus_fs_core::protocol::*;
    use std::fs;

    #[test]
    fn stable_generation_and_restart_preserve_original_capture_without_bootstrap_echo() {
        let dir = std::path::PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "mounted-{}",
            OperationId::random().unwrap().as_str()
        ));
        fs::create_dir(&dir).unwrap();
        let tree = dir.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("file"), b"old").unwrap();
        let principal = PrincipalId::random().unwrap();
        let group = GroupId::random().unwrap();
        let actor = Actor::new(principal.clone());
        let rep = Replica::open(
            dir.join("state"),
            ReplicaConfig {
                replica: ReplicaId::random().unwrap(),
                authorities: vec![Authority {
                    principal,
                    uid: unsafe { libc::geteuid() },
                    gid: std::os::unix::fs::MetadataExt::gid(&fs::metadata(&tree).unwrap()),
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
        rep.configure_native(NativeConfig {
            root: tree.clone(),
            policy: CapturePolicy {
                included_roots: vec![".".into()],
                excluded_prefixes: vec![],
            },
            creation_umask: 0o022,
        })
        .unwrap();
        let base = rep
            .capture(
                &tree,
                CapturePolicy {
                    included_roots: vec![".".into()],
                    excluded_prefixes: vec![],
                },
                OperationId::random().unwrap(),
                actor.clone(),
            )
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
            transport_profile: dir.join("profile"),
            transport_identity: TransportIdentity::for_bytes(b"profile").unwrap(),
        };
        rep.configure_sync(binding.clone()).unwrap();
        let ws = rep.begin_live(&base, actor.clone(), false).unwrap();
        let mut capture = MountedCapture::new(&rep).unwrap();
        let checkpoint = |operation: &OperationId, generation| {
            ws.checkpoint(
                operation,
                generation,
                Attribution {
                    captured_at_ns: 0,
                    coverage: vec!["".into()],
                    provenance: "engine_observed".into(),
                },
            )
        };
        assert!(capture.tick(checkpoint).unwrap().is_none());
        assert!(
            rep.pending_submissions().unwrap().is_empty(),
            "bootstrap must not publish"
        );
        let h = ws.open("file", OpenMode::Write).unwrap();
        ws.write(&h, 0, b"first").unwrap();
        assert!(capture.tick(checkpoint).unwrap().is_none());
        std::thread::sleep(Duration::from_millis(110));
        ws.write(&h, 0, b"later").unwrap();
        assert!(
            capture.tick(checkpoint).unwrap().is_none(),
            "new generation restarts debounce"
        );
        std::thread::sleep(Duration::from_millis(110));
        let first = capture.tick(checkpoint).unwrap().unwrap();
        assert_eq!(rep.pending_submissions().unwrap().len(), 1);
        assert!(capture.tick(checkpoint).unwrap().is_none());
        assert_eq!(rep.pending_submissions().unwrap()[0].local_revision, first);
        ws.write(&h, 0, b"restart").unwrap();
        let operation = OperationId::random().unwrap();
        let frozen = checkpoint(&operation, rep.status().unwrap().generation).unwrap();
        drop(capture);
        drop(h);
        drop(ws);
        drop(rep);
        let rep = Replica::reopen(dir.join("state")).unwrap();
        let mut capture = MountedCapture::new(&rep).unwrap();
        capture
            .tick(|_, _| panic!("clean captured work must be admitted without recapture"))
            .unwrap();
        let pending = rep.pending_submissions().unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|p| p.operation == operation
            && p.local_revision == frozen
            && p.original_view == binding.view.view
            && p.original_head == binding.view.head));
        drop(capture);
        drop(rep);
        fs::remove_dir_all(dir).unwrap();
    }
}
