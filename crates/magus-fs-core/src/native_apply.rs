//! Full-folder application. Every displaced writable generation remains separate from content.
use crate::{
    capture::{directory, Observation, Scan, ScanRecord},
    engine::{from_json, json, lock, Core, Working},
    native_recovery::{record, RecoveryCausality, Retained},
    native_root::{RootIntent, RootPhase},
    objects::{name, open_at},
    permissions as perm, *,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{File, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::PathBuf,
    time::{Duration, Instant},
};
pub(crate) const RETAIN_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const RETAIN_GENERATIONS: usize = 128;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeApplyStatus {
    Ready { revision: RevisionId },
    Pending { reason: String },
    Unstable { reason: String },
    ApplyBlocked { reason: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeDisplacement {
    pub operation: OperationId,
    pub path: String,
    pub retained_path: PathBuf,
    pub versions: Vec<PathBuf>,
    pub ambiguous: bool,
    /// Capture-excluded (local-only) paths changed in a retained root: retained opaque bytes,
    /// reported separately, never managed ambiguity or recovery candidates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_only_changes: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeStatus {
    pub status: NativeApplyStatus,
    pub incoming_revision: Option<RevisionId>,
    pub displacements: Vec<NativeDisplacement>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FileIntent {
    path: String,
    stage: String,
    expected: Option<Observation>,
    installed: Observation,
    old_entry: Option<Entry>,
    entry: Entry,
    exchanged: bool,
    versions: Vec<PathBuf>,
    last_displaced: Option<Observation>,
    last_displaced_hash: Option<String>,
    ambiguous: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Intent {
    pub(crate) operation: OperationId,
    pub(crate) revision: RevisionId,
    pub(crate) generation: u64,
    pub(crate) base: RevisionId,
    pub(crate) binding: Option<SyncBinding>,
    pub(crate) actor: Actor,
    pub(crate) stage: PathBuf,
    pub(crate) stage_identity: Option<Observation>,
    pub(crate) before: ScanRecord,
    pub(crate) files: Vec<FileIntent>,
    pub(crate) status: NativeApplyStatus,
    /// Structural application by verified root exchange (journal schema 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) root: Option<RootIntent>,
}
impl Intent {
    /// The intent holds an applied or possibly applied native mutation.
    fn mutating(&self) -> bool {
        !self.files.is_empty()
            || self
                .root
                .as_ref()
                .is_some_and(|r| r.phase != RootPhase::Abandoned)
    }
    fn ambiguous(&self) -> bool {
        self.files.iter().any(|f| f.ambiguous) || self.root.as_ref().is_some_and(|r| r.ambiguous)
    }
}
/// The configured root pathname no longer names the verified bound root (or a no-follow walk
/// fails). Nothing at such a pathname is captured or mutated until a verified rebind or an
/// explicit operator capture (`magus-fs capture`) establishes a new baseline.
pub(crate) fn root_replaced(core: &Core, n: &NativeConfig) -> Result<bool, FsError> {
    let Ok(previous) = baseline(core) else {
        return Ok(false);
    };
    let Some(verified) = previous.observations.get("") else {
        return Ok(false);
    };
    Ok(match directory(&n.root) {
        Ok(dir) => !verified.same_identity(&observation(&dir)?),
        Err(FsError::Io(e)) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        Err(_) => true,
    })
}
fn mark_root_replaced(core: &Core) -> Result<(), FsError> {
    let mut status: NativeStatus = core
        .journal
        .db
        .query_row(
            "SELECT record FROM native_status WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|b| from_json(&b))
        .transpose()?
        .unwrap_or(NativeStatus {
            status: pending("unverified"),
            incoming_revision: None,
            displacements: vec![],
        });
    status.status = blocked("bound_root_changed");
    status_save(core, &status)
}
/// Immutable records for every journaled retained version, created only after the version
/// itself is durable in the intent. Idempotent, so an interruption between the two repairs.
pub(crate) fn records_for_versions(core: &Core, r: &Intent) -> Result<(), FsError> {
    let mut versions: Vec<(&str, &std::path::Path)> = r
        .files
        .iter()
        .flat_map(|f| {
            f.versions
                .iter()
                .map(move |v| (f.path.as_str(), v.as_path()))
        })
        .collect();
    if let Some(root) = &r.root {
        versions.extend(
            root.versions
                .iter()
                .map(|v| (v.path.as_str(), v.version.as_path())),
        );
    }
    if versions.is_empty() {
        return Ok(());
    }
    let stage = stage_open(r)?;
    for (path, version) in versions {
        let leaf = version
            .file_name()
            .and_then(|l| l.to_str())
            .ok_or(FsError::UnsafeStorage)?;
        let digest = native_hash(&mut open_file(&stage, leaf)?)?;
        record(
            core,
            Retained {
                operation: &r.operation,
                original_base: &r.base,
                source_path: path,
                observed_generation: r.generation,
                digest_hex: &digest,
                copy: version,
                causal_coverage: RecoveryCausality::Unknown,
            },
        )?;
    }
    Ok(())
}
fn clear_applied(core: &mut Core) -> Result<(), FsError> {
    if let Some(w) = &core.working {
        if w.applied {
            let mut w = w.clone();
            w.applied = false;
            core.journal
                .db
                .execute("UPDATE working SET value=? WHERE singleton=1", [json(&w)?])?;
            core.working = Some(w);
        }
    }
    Ok(())
}
/// Retained bytes and generations charged by one intent (A file generations plus any root).
pub(crate) fn usage(r: &Intent) -> (u64, usize) {
    let mut bytes = 0u64;
    let mut generations = 0usize;
    for f in &r.files {
        if f.expected.is_some() {
            generations += 1 + f.versions.len();
            if let Ok(m) = std::fs::symlink_metadata(r.stage.join(&f.stage)) {
                bytes = bytes.saturating_add(m.len());
            }
            for p in &f.versions {
                if let Ok(m) = std::fs::symlink_metadata(p) {
                    bytes = bytes.saturating_add(m.len());
                }
            }
        }
    }
    if let Some(root) = &r.root {
        let (b, g) = root.usage();
        bytes = bytes.saturating_add(b);
        generations += g;
    }
    (bytes, generations)
}
pub(crate) fn authority_revision(core: &Core) -> Result<Option<RevisionId>, FsError> {
    match core
        .journal
        .db
        .query_row(
            "SELECT revision FROM live_authority WHERE singleton=1",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
    {
        Some(None) => Err(FsError::PermissionDenied),
        Some(Some(id)) => RevisionId::parse(id).map(Some),
        None => Ok(None),
    }
}
pub(crate) fn authorize_native_capture(
    core: &Core,
    actor: &Actor,
    new: &Tree,
) -> Result<(), FsError> {
    let Some(id) = authority_revision(core)? else {
        return Ok(());
    };
    let authority = core.revision(&id)?;
    let mut old = core.working()?.tree.clone();
    old.root = authority.tree.root.clone();
    for e in &mut old.entries {
        if let Some(current) = authority.tree.entries.iter().find(|c| c.id == e.id) {
            e.mode = current.mode;
            e.owner = current.owner.clone();
            e.group = current.group.clone();
        } else if core.remote_entries.contains(&e.id) {
            return Err(FsError::PermissionDenied);
        }
    }
    crate::capture::authorize_capture(&core.config, actor, Some(&old), new)
}
/// A historical tree with every entry's mode/owner/group replaced by current authority (the
/// authenticated remote projection, else the current working tree). An identity once known
/// remotely but absent now is denied; revoked authority is denied. Old metadata never authorizes.
pub(crate) fn current_authority_overlay(core: &Core, historical: &Tree) -> Result<Tree, FsError> {
    let authority = authority_revision(core)?
        .map(|id| core.revision(&id))
        .transpose()?;
    let working = &core.working()?.tree;
    let mut tree = historical.clone();
    tree.root = authority
        .as_ref()
        .map(|a| a.tree.root.clone())
        .unwrap_or_else(|| working.root.clone());
    for e in &mut tree.entries {
        let current = authority
            .as_ref()
            .and_then(|a| a.tree.entries.iter().find(|c| c.id == e.id))
            .or_else(|| working.entries.iter().find(|c| c.id == e.id));
        if let Some(current) = current {
            e.mode = current.mode;
            e.owner = current.owner.clone();
            e.group = current.group.clone();
        } else if core.remote_entries.contains(&e.id) {
            return Err(FsError::PermissionDenied);
        }
    }
    Ok(tree)
}
pub(crate) fn configuration(core: &Core) -> Result<NativeConfig, FsError> {
    from_json(&core.journal.db.query_row(
        "SELECT configuration FROM native WHERE singleton=1",
        [],
        |r| r.get::<_, Vec<u8>>(0),
    )?)
}
pub(crate) fn baseline(core: &Core) -> Result<ScanRecord, FsError> {
    from_json(
        &core
            .journal
            .db
            .query_row("SELECT scan FROM native WHERE singleton=1", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })?,
    )
}
pub(crate) fn records(core: &Core) -> Result<Vec<Intent>, FsError> {
    core.journal
        .db
        .prepare("SELECT record FROM native_apply ORDER BY rowid")?
        .query_map([], |r| r.get::<_, Vec<u8>>(0))?
        .map(|r| from_json(&r?))
        .collect()
}
pub(crate) fn save(core: &Core, r: &Intent) -> Result<(), FsError> {
    core.journal.guard()?;
    core.journal.db.execute(
        "INSERT OR REPLACE INTO native_apply VALUES(?,?)",
        params![r.operation.as_str(), json(r)?],
    )?;
    Ok(())
}
fn displacements(rows: &[Intent]) -> Vec<NativeDisplacement> {
    rows.iter()
        .flat_map(|r| {
            r.files
                .iter()
                .filter(|f| f.expected.is_some() && f.exchanged)
                .map(|f| NativeDisplacement {
                    operation: r.operation.clone(),
                    path: f.path.clone(),
                    retained_path: r.stage.join(&f.stage),
                    versions: f.versions.clone(),
                    ambiguous: f.ambiguous,
                    local_only_changes: vec![],
                })
                .chain(r.root.iter().filter(|x| x.exchanged()).map(|x| {
                    // The displaced root is a whole retained generation at the empty path.
                    NativeDisplacement {
                        operation: r.operation.clone(),
                        path: String::new(),
                        retained_path: x.retained_path(),
                        versions: x.versions.iter().map(|v| v.version.clone()).collect(),
                        ambiguous: x.ambiguous,
                        local_only_changes: x.local_changes.clone(),
                    }
                }))
        })
        .collect()
}
fn status_save(core: &Core, s: &NativeStatus) -> Result<(), FsError> {
    // Every status transition exposes the current durable intents, including failed preflight.
    let mut s = s.clone();
    s.displacements = displacements(&records(core)?);
    core.journal.db.execute(
        "INSERT OR REPLACE INTO native_status VALUES(1,?)",
        [json(&s)?],
    )?;
    Ok(())
}
pub(crate) fn blocked(reason: &str) -> NativeApplyStatus {
    NativeApplyStatus::ApplyBlocked {
        reason: reason.into(),
    }
}
pub(crate) fn pending(reason: &str) -> NativeApplyStatus {
    NativeApplyStatus::Pending {
        reason: reason.into(),
    }
}
fn observation(file: &File) -> Result<Observation, FsError> {
    Ok(Observation::metadata(&file.metadata()?))
}
pub(crate) fn native_hash(file: &mut File) -> Result<String, FsError> {
    let before = observation(file)?;
    if before.size > RETAIN_BYTES || !file.metadata()?.is_file() {
        return Err(FsError::Backpressure);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut remaining = before.size;
    while remaining > 0 {
        if Instant::now() >= deadline {
            return Err(FsError::UnstableCapture);
        }
        let n = (remaining as usize).min(buffer.len());
        file.read_exact(&mut buffer[..n])?;
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if observation(file)? != before {
        return Err(FsError::UnstableCapture);
    }
    Ok(crate::model::hex(&hash.finalize()))
}
pub(crate) fn same_generation(a: &Observation, b: &Observation) -> bool {
    a.same_identity(b)
        && a.size == b.size
        && a.mtime == b.mtime
        && a.mtime_ns == b.mtime_ns
        && a.uid == b.uid
        && a.gid == b.gid
        && a.mode == b.mode
        && a.nlink == b.nlink
}
fn open_file(parent: &File, leaf: &str) -> Result<File, FsError> {
    open_at(
        parent.as_raw_fd(),
        &name(OsStr::new(leaf))?,
        libc::O_RDONLY | libc::O_NONBLOCK,
    )
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
fn metadata_matches(core: &Core, file: &File, entry: &Entry) -> Result<(), FsError> {
    let m = file.metadata()?;
    let owner = core
        .config
        .authorities
        .iter()
        .find(|a| a.principal == entry.owner)
        .ok_or(FsError::MappingBlocked)?;
    let group = core
        .config
        .authorities
        .iter()
        .find(|a| a.primary_group == entry.group)
        .ok_or(FsError::MappingBlocked)?;
    if m.uid() != owner.uid || m.gid() != group.gid || m.mode() & 0o7777 != entry.mode as u32 {
        return Err(FsError::MappingBlocked);
    }
    if !crate::capture::metadata_inventory(file, &entry.path)?
        .0
        .is_empty()
    {
        return Err(FsError::UnsafeStorage);
    }
    Ok(())
}
pub(crate) fn verify_file(core: &Core, file: &mut File, entry: &Entry) -> Result<(), FsError> {
    verify_file_generation(core, file, entry).map(|_| ())
}
fn verify_file_generation(
    core: &Core,
    file: &mut File,
    entry: &Entry,
) -> Result<(Observation, String), FsError> {
    let mut hash = Sha256::new();
    let before = observation(file)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let EntryContent::File { version } = &entry.content else {
        return Err(FsError::InvalidTree);
    };
    if !file.metadata()?.is_file() || before.nlink != 1 || before.size != version.size {
        return Err(FsError::UnstableCapture);
    }
    metadata_matches(core, file, entry)?;
    file.seek(SeekFrom::Start(0))?;
    for extent in &version.extents {
        if Instant::now() >= deadline {
            return Err(FsError::UnstableCapture);
        }
        match extent {
            Extent::Chunk {
                object,
                object_size,
                offset,
                length,
            } => {
                let bytes = core.objects.read_verified(object)?;
                if bytes.len() as u64 != *object_size {
                    return Err(FsError::CorruptObject);
                }
                let mut found = vec![0; *length as usize];
                file.read_exact(&mut found)?;
                hash.update(&found);
                if found != bytes[*offset as usize..(*offset + *length) as usize] {
                    return Err(FsError::UnstableCapture);
                }
            }
            Extent::Hole { length } => {
                let mut left = *length;
                let mut b = [0; 8192];
                while left > 0 {
                    if Instant::now() >= deadline {
                        return Err(FsError::UnstableCapture);
                    }
                    let n = left.min(8192) as usize;
                    file.read_exact(&mut b[..n])?;
                    hash.update(&b[..n]);
                    if b[..n].iter().any(|v| *v != 0) {
                        return Err(FsError::UnstableCapture);
                    }
                    left -= n as u64;
                }
            }
        }
    }
    if observation(file)? != before {
        return Err(FsError::UnstableCapture);
    }
    Ok((before, crate::model::hex(&hash.finalize())))
}
pub(crate) fn scan_tree(core: &Core, n: &NativeConfig, tree: &Tree) -> Result<ScanRecord, FsError> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut scan = Scan::observe(&n.root, &n.policy, deadline)?;
    if !scan.unsupported.is_empty() || scan.nodes.len() != tree.entries.len() + 1 {
        return Err(FsError::UnstableCapture);
    }
    metadata_matches(core, &scan.nodes[""].file, &perm::root_entry(tree))?;
    for e in &tree.entries {
        if Instant::now() >= deadline {
            return Err(FsError::UnstableCapture);
        }
        let node = scan
            .nodes
            .get_mut(&e.path)
            .ok_or(FsError::UnstableCapture)?;
        match e.content {
            EntryContent::Directory => {
                if !node.file.metadata()?.is_dir() {
                    return Err(FsError::UnstableCapture);
                }
                metadata_matches(core, &node.file, e)?;
            }
            _ => verify_file(core, &mut node.file, e)?,
        }
    }
    let observations = scan.observations();
    if Scan::observe(&n.root, &n.policy, deadline)?.observations() != observations {
        return Err(FsError::UnstableCapture);
    }
    Ok(ScanRecord {
        observations,
        ids: std::iter::once((String::new(), tree.root.id.clone()))
            .chain(tree.entries.iter().map(|e| (e.path.clone(), e.id.clone())))
            .collect(),
        diagnostics: scan.diagnostics,
    })
}
fn verify_ancestry(n: &NativeConfig, before: &ScanRecord, path: &str) -> Result<File, FsError> {
    let mut current = String::new();
    let mut dir = directory(&n.root)?;
    let expected = before.observations.get("").ok_or(FsError::UnsafeStorage)?;
    if !expected.same_identity(&observation(&dir)?) {
        return Err(FsError::UnsafeStorage);
    }
    for part in perm::parent(path).split('/').filter(|s| !s.is_empty()) {
        dir = open_at(
            dir.as_raw_fd(),
            &name(OsStr::new(part))?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        if !current.is_empty() {
            current.push('/')
        }
        current.push_str(part);
        let actual = observation(&dir)?;
        if !before
            .observations
            .get(&current)
            .is_some_and(|o| o.same_identity(&actual))
        {
            return Err(FsError::UnsafeStorage);
        }
    }
    Ok(dir)
}
pub(crate) fn rename_atomic(
    stage: &File,
    from: &str,
    parent: &File,
    to: &str,
    exchange: bool,
) -> Result<(), FsError> {
    let from = name(OsStr::new(from))?;
    let to = name(OsStr::new(to))?;
    #[cfg(target_os = "linux")]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            stage.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            if exchange {
                libc::RENAME_EXCHANGE
            } else {
                libc::RENAME_NOREPLACE
            },
        )
    };
    #[cfg(target_os = "macos")]
    let rc = unsafe {
        libc::renameatx_np(
            stage.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            if exchange {
                libc::RENAME_SWAP
            } else {
                libc::RENAME_EXCL
            },
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    stage.sync_all()?;
    Ok(())
}
pub(crate) fn stage_open(r: &Intent) -> Result<File, FsError> {
    let d = directory(&r.stage)?;
    let actual = observation(&d)?;
    if !r
        .stage_identity
        .as_ref()
        .is_some_and(|o| o.same_identity(&actual))
    {
        return Err(FsError::UnsafeStorage);
    }
    Ok(d)
}
#[derive(Clone, Copy)]
enum NativeHydration {
    Baseline,
    Incoming,
}
impl NativeHydration {
    fn closure_deadline(self, started: Instant) -> Instant {
        let seconds = match self {
            Self::Baseline => 60,
            Self::Incoming => 30,
        };
        started + Duration::from_secs(seconds)
    }
    fn fetch_deadline(self, started: Instant, now: Instant) -> Instant {
        self.closure_deadline(started)
            .min(now + Duration::from_millis(4500))
    }
}

impl Replica {
    fn prefetch_native(
        &self,
        revision: &RevisionId,
        source: Option<protocol::RemoteSourceId>,
        hydration: NativeHydration,
    ) -> Result<(), FsError> {
        let (objects, source, fetcher) = {
            let core = lock(&self.core)?;
            let source = match source {
                Some(source) => ChunkSource::Remote { source },
                None => core
                    .journal
                    .db
                    .query_row(
                        "SELECT source FROM revision_sources WHERE revision=?",
                        [revision.as_str()],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                    .optional()?
                    .map(|bytes| from_json(&bytes))
                    .transpose()?
                    .unwrap_or(ChunkSource::Unavailable),
            };
            (
                crate::cache::closure(&core.revision(revision)?.tree),
                source,
                core.remote_fetcher.clone(),
            )
        };
        let started = Instant::now();
        for (id, size) in objects {
            {
                let mut core = lock(&self.core)?;
                match core.objects.read_verified(&id) {
                    Ok(b) => {
                        if b.len() as u64 != size {
                            return Err(FsError::CorruptObject);
                        }
                        continue;
                    }
                    Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
                core.reserve(&std::collections::BTreeMap::from([(id.clone(), size)]))?;
            }
            let bytes = match &source {
                ChunkSource::Remote { source } => crate::remote_source::fetch(
                    fetcher.as_deref().ok_or(FsError::InvalidSource)?,
                    source,
                    &id,
                    size,
                    hydration.fetch_deadline(started, Instant::now()),
                )?,
                _ => source.fetch(&id, size, hydration.closure_deadline(started))?,
            };
            if bytes.len() as u64 != size || ObjectId::for_bytes(&bytes)? != id {
                return Err(FsError::CorruptObject);
            }
            let core = lock(&self.core)?;
            core.objects.install(&bytes)?;
            core.objects.sync_object(&id)?;
        }
        Ok(())
    }
    /// Reconcile exact retained operations after process restart. No unowned path is removed.
    pub fn recover_native_application(
        &self,
        actor: Actor,
    ) -> Result<Vec<NativeApplyStatus>, FsError> {
        let pending = {
            let core = lock(&self.core)?;
            perm::authority(&core.config, &actor)?;
            records(&core)?
                .into_iter()
                .filter(|r| {
                    !matches!(r.status, NativeApplyStatus::Ready { .. })
                        && r.stage_identity.is_some()
                        && r.actor == actor
                        && r.root
                            .as_ref()
                            .is_none_or(|x| x.phase != RootPhase::Abandoned)
                })
                .collect::<Vec<_>>()
        };
        let mut out = vec![];
        for r in pending {
            out.push(self.apply_native(
                &r.revision,
                r.generation,
                r.operation,
                r.actor,
                r.binding,
            )?);
        }
        Ok(out)
    }
    /// Bootstrap a full folder only when every current byte and mapped metadata already matches.
    pub fn verify_native_baseline(&self, actor: Actor) -> Result<(), FsError> {
        let revision = {
            let core = lock(&self.core)?;
            perm::authority(&core.config, &actor)?;
            core.working()?.head.clone()
        };
        self.prefetch_native(&revision, None, NativeHydration::Baseline)?;
        let core = lock(&self.core)?;
        let n = configuration(&core)?;
        if core.working()?.head != revision {
            return Err(FsError::GenerationMismatch);
        }
        if core.journal.db.query_row(
            "SELECT scan IS NOT NULL FROM native WHERE singleton=1",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        let scan = scan_tree(&core, &n, &core.working()?.tree)?;
        core.journal
            .db
            .execute("UPDATE native SET scan=? WHERE singleton=1", [json(&scan)?])?;
        Ok(())
    }

    /// Rescans independently of event delivery. Only changed observed generations are captured.
    pub fn capture_native_changes(
        &self,
        operation: OperationId,
        actor: Actor,
    ) -> Result<Option<RevisionId>, FsError> {
        let n = self.native_config()?.ok_or(FsError::ConfigMismatch)?;
        {
            let mut core = lock(&self.core)?;
            authority_revision(&core)?;
            if root_replaced(&core, &n)? {
                mark_root_replaced(&core)?;
                clear_applied(&mut core)?;
                return Ok(None);
            }
            let previous = baseline(&core)?;
            let observed =
                Scan::observe(&n.root, &n.policy, Instant::now() + Duration::from_secs(30))?;
            if observed.observations() == previous.observations
                && observed.unsupported.is_empty()
                && scan_tree(&core, &n, &core.working()?.tree).is_ok()
            {
                return Ok(None);
            }
            if records(&core)?
                .iter()
                .any(|r| !matches!(r.status, NativeApplyStatus::Ready { .. }) && r.mutating())
            {
                return Err(FsError::DirtyWorkingState);
            }
        }
        self.capture(&n.root, n.policy, operation, actor).map(Some)
    }
    /// Persist a safe code from the native owner scheduler; never journal transport details.
    pub fn record_native_error(&self, error: &FsError) -> Result<(), FsError> {
        let mut core = lock(&self.core)?;
        let mut status: NativeStatus = core
            .journal
            .db
            .query_row(
                "SELECT record FROM native_status WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| from_json(&b))
            .transpose()?
            .unwrap_or(NativeStatus {
                status: pending("unverified"),
                incoming_revision: None,
                displacements: vec![],
            });
        status.status = if matches!(error, FsError::UnstableCapture) {
            NativeApplyStatus::Unstable {
                reason: error.code().into(),
            }
        } else if matches!(
            error,
            FsError::Backpressure | FsError::DirtyWorkingState | FsError::GenerationMismatch
        ) {
            pending(error.code())
        } else {
            blocked(error.code())
        };
        if let Some(w) = &core.working {
            let mut w = w.clone();
            w.applied = false;
            core.journal
                .db
                .execute("UPDATE working SET value=? WHERE singleton=1", [json(&w)?])?;
            core.working = Some(w);
        }
        status_save(&core, &status)
    }
    pub fn native_status(&self) -> Result<Option<NativeStatus>, FsError> {
        let core = lock(&self.core)?;
        core.journal
            .db
            .query_row(
                "SELECT record FROM native_status WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| from_json(&b))
            .transpose()
    }
    pub fn scan_native_status(&self) -> Result<NativeStatus, FsError> {
        let mut core = lock(&self.core)?;
        let n = configuration(&core)?;
        let mut rows = records(&core)?;
        let mut status: NativeStatus = core
            .journal
            .db
            .query_row(
                "SELECT record FROM native_status WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| from_json(&b))
            .transpose()?
            .unwrap_or(NativeStatus {
                status: pending("unverified"),
                incoming_revision: None,
                displacements: vec![],
            });
        let mut bytes = 0u64;
        let mut generations = 0usize;
        for r in &rows {
            let (b, g) = usage(r);
            bytes = bytes.saturating_add(b);
            generations += g;
        }
        for r in &mut rows {
            if bytes > RETAIN_BYTES || generations > RETAIN_GENERATIONS {
                status.status = blocked("displacement_backpressure");
                continue;
            }
            if r.root.as_ref().is_some_and(RootIntent::exchanged) {
                match crate::native_root::rescan(&core, &n.policy, r)? {
                    crate::native_root::Rescan::Unchanged => {}
                    crate::native_root::Rescan::Changed => {
                        if !matches!(status.status, NativeApplyStatus::ApplyBlocked { .. }) {
                            status.status = pending("late_displaced_write");
                        }
                    }
                    crate::native_root::Rescan::Missing => {
                        status.status = blocked("retained_generation_missing")
                    }
                    crate::native_root::Rescan::Backpressure => {
                        status.status = blocked("displacement_backpressure")
                    }
                    crate::native_root::Rescan::Unstable => {
                        status.status = NativeApplyStatus::Unstable {
                            reason: "displaced_write_unstable".into(),
                        }
                    }
                }
            }
            if r.stage_identity.is_none() && r.files.is_empty() {
                continue;
            }
            let stage = match stage_open(r) {
                Ok(s) => s,
                Err(_) => {
                    status.status = blocked("retained_stage_identity");
                    continue;
                }
            };
            for f in &mut r.files {
                if f.expected.is_none() || !f.exchanged {
                    continue;
                }
                let mut displaced = match open_file(&stage, &f.stage) {
                    Ok(d) => d,
                    Err(_) => {
                        status.status = blocked("retained_generation_missing");
                        continue;
                    }
                };
                let observed = observation(&displaced)?;
                let hash = match native_hash(&mut displaced) {
                    Ok(h) => h,
                    Err(_) => {
                        status.status = blocked("displacement_backpressure_or_unstable");
                        continue;
                    }
                };
                let changed = f.last_displaced.as_ref().is_none_or(|o| o != &observed)
                    || f.last_displaced_hash.as_ref() != Some(&hash);
                if changed {
                    f.ambiguous = true;
                    status.status = pending("late_displaced_write");
                    if generations >= RETAIN_GENERATIONS
                        || bytes.saturating_add(observed.size) > RETAIN_BYTES
                    {
                        status.status = blocked("displacement_backpressure");
                        continue;
                    }
                    let version = format!("{}-version-{}", f.stage, f.versions.len());
                    // The next version leaf is owner-private; an orphan from an interrupted copy
                    // (never journaled) is reused and truncated rather than wedging scans.
                    let mut copy = open_at(
                        stage.as_raw_fd(),
                        &name(OsStr::new(&version))?,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    )?;
                    displaced.seek(SeekFrom::Start(0))?;
                    std::io::copy(&mut (&mut displaced).take(observed.size), &mut copy)?;
                    copy.sync_all()?;
                    stage.sync_all()?;
                    crate::faults::capture_barrier("native-version-copied", 1)?;
                    f.versions.push(r.stage.join(version));
                    generations += 1;
                    bytes = bytes.saturating_add(observed.size);
                    if observation(&displaced)? == observed {
                        f.last_displaced = Some(observed);
                        f.last_displaced_hash = Some(hash)
                    } else {
                        status.status = NativeApplyStatus::Unstable {
                            reason: "displaced_write_unstable".into(),
                        };
                    }
                }
            }
            save(&core, r)?;
            records_for_versions(&core, r)?;
        }
        if let Ok(previous) = baseline(&core) {
            match Scan::observe(&n.root, &n.policy, Instant::now() + Duration::from_secs(30)) {
                Ok(scan)
                    if scan.observations() == previous.observations
                        && scan.unsupported.is_empty()
                        && scan_tree(&core, &n, &core.working()?.tree).is_ok() => {}
                Ok(_) => {
                    if !matches!(status.status, NativeApplyStatus::ApplyBlocked { .. }) {
                        status.status = pending("native_changed");
                    }
                }
                Err(_) => {
                    status.status = NativeApplyStatus::Unstable {
                        reason: "native_scan_unstable".into(),
                    }
                }
            }
        }
        if authority_revision(&core).is_err() {
            status.status = blocked("permission_denied")
        }
        if root_replaced(&core, &n)? {
            status.status = blocked("bound_root_changed");
        }
        status.displacements = displacements(&rows);
        if !matches!(status.status, NativeApplyStatus::Ready { .. }) {
            if let Some(w) = &core.working {
                let mut w = w.clone();
                w.applied = false;
                core.journal
                    .db
                    .execute("UPDATE working SET value=? WHERE singleton=1", [json(&w)?])?;
                core.working = Some(w);
            }
        }
        status_save(&core, &status)?;
        Ok(status)
    }
    pub fn apply_native_revision(
        &self,
        revision: &RevisionId,
        expected_generation: u64,
        operation: OperationId,
        actor: Actor,
    ) -> Result<NativeApplyStatus, FsError> {
        self.apply_native(revision, expected_generation, operation, actor, None)
    }
    pub fn apply_native_view(
        &self,
        binding: SyncBinding,
        expected_generation: u64,
        operation: OperationId,
        actor: Actor,
    ) -> Result<NativeApplyStatus, FsError> {
        self.apply_native(
            &binding.view.revision.clone(),
            expected_generation,
            operation,
            actor,
            Some(binding),
        )
    }
    fn apply_native(
        &self,
        revision: &RevisionId,
        generation: u64,
        operation: OperationId,
        actor: Actor,
        binding: Option<SyncBinding>,
    ) -> Result<NativeApplyStatus, FsError> {
        let mut core = lock(&self.core)?;
        let n = configuration(&core)?;
        perm::authority(&core.config, &actor)?;
        let old = core.working()?.clone();
        let target = core.revision(revision)?;
        let before = baseline(&core)?;
        let mut status = NativeStatus {
            status: pending("apply_pending"),
            incoming_revision: Some(revision.clone()),
            displacements: vec![],
        };
        core.journal.db.execute(
            "INSERT OR IGNORE INTO native_incoming VALUES(?)",
            [revision.as_str()],
        )?;
        let all = records(&core)?;
        if let Some(existing) = all.iter().find(|r| r.operation == operation) {
            if existing.revision != *revision
                || existing.generation != generation
                || existing.actor != actor
                || existing.binding != binding
            {
                return Err(FsError::OperationMismatch);
            }
            let completed = matches!(existing.status, NativeApplyStatus::Ready { .. });
            if completed && old.head != *revision {
                return Ok(pending("superseded_application"));
            }
            status_save(&core, &status)?;
            let mut r = existing.clone();
            let result = finish(&mut core, &n, &mut r);
            status.status = match result {
                Ok(s) => s,
                Err(e) => blocked(e.code()),
            };
            // Historical completion remains immutable when current-path verification later fails.
            if !completed {
                r.status = status.status.clone();
            }
            save(&core, &r)?;
            status_save(&core, &status)?;
            return Ok(status.status);
        }
        status_save(&core, &status)?;
        let preflight = (|| -> Result<bool, FsError> {
            if root_replaced(&core, &n)? {
                return Err(FsError::UnsafeStorage);
            }
            if authority_revision(&core)?.is_some_and(|id| id != *revision) {
                return Err(FsError::PermissionDenied);
            }
            if old.generation != generation {
                return Err(FsError::GenerationMismatch);
            }
            if old.dirty {
                return Err(FsError::DirtyWorkingState);
            }
            if all.iter().any(|r| {
                (!matches!(r.status, NativeApplyStatus::Ready { .. }) && r.mutating())
                    || r.ambiguous()
            }) {
                return Err(FsError::DirtyWorkingState);
            }
            // A preparation/copy interrupted before its record was committed is retained too.
            // Unknown files are never omitted from quota by trusting only the saved file list.
            for retained in &all {
                if retained.stage_identity.is_none() {
                    match std::fs::symlink_metadata(&retained.stage) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        _ => return Err(FsError::Backpressure),
                    }
                }
                let stage = stage_open(retained)?;
                let actual = crate::capture::names(&stage)?
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>();
                let mut allowed = std::collections::BTreeSet::new();
                let mut required = std::collections::BTreeSet::new();
                use std::os::unix::ffi::OsStrExt;
                for file in &retained.files {
                    allowed.insert(file.stage.as_bytes().to_vec());
                    // An interrupted, never-journaled copy of the next version is our own.
                    allowed.insert(
                        format!("{}-version-{}", file.stage, file.versions.len()).into_bytes(),
                    );
                    if file.expected.is_some() && file.exchanged {
                        required.insert(file.stage.as_bytes().to_vec());
                    }
                    for version in &file.versions {
                        let leaf = version.file_name().ok_or(FsError::UnsafeStorage)?;
                        allowed.insert(leaf.as_bytes().to_vec());
                        required.insert(leaf.as_bytes().to_vec());
                    }
                }
                if let Some(root) = &retained.root {
                    allowed.insert(format!("root-version-{}", root.versions.len()).into_bytes());
                }
                for version in retained.root.iter().flat_map(|x| &x.versions) {
                    let leaf = version.version.file_name().ok_or(FsError::UnsafeStorage)?;
                    allowed.insert(leaf.as_bytes().to_vec());
                    required.insert(leaf.as_bytes().to_vec());
                }
                if !actual.is_subset(&allowed) || !required.is_subset(&actual) {
                    return Err(FsError::Backpressure);
                }
            }
            let active: Option<SyncBinding> = core
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
            match (&active, &binding) {
                (Some(a), Some(b)) => {
                    if a.id != b.id
                        || a.branch != b.branch
                        || a.publication != b.publication
                        || a.transport_profile != b.transport_profile
                        || a.transport_identity != b.transport_identity
                        || a.source == b.source
                    {
                        return Err(FsError::ConfigMismatch);
                    }
                    if let Some(bytes) = core
                        .journal
                        .db
                        .query_row(
                            "SELECT binding FROM sync_sources WHERE id=?",
                            [b.source.as_str()],
                            |r| r.get::<_, Vec<u8>>(0),
                        )
                        .optional()?
                    {
                        if from_json::<SyncBinding>(&bytes)? != *b {
                            return Err(FsError::ConfigMismatch);
                        }
                    }
                    let records = core.sync_records()?;
                    if records.iter().any(|r| r.unresolved())
                        || old.head != a.view.revision
                            && !records
                                .iter()
                                .any(|r| r.pending.local_revision == old.head && !r.unresolved())
                    {
                        return Err(FsError::DirtyWorkingState);
                    }
                }
                (None, None) => {}
                _ => return Err(FsError::ConfigMismatch),
            }
            if target.tree.root.id != old.tree.root.id {
                return Err(FsError::UnsupportedMode);
            }
            // Regular-file creation/exchange keeps A's per-file path; any namespace, directory,
            // deletion, identity, type or metadata change uses the verified root exchange.
            let structural = target.tree.root != old.tree.root
                || old.tree.entries.iter().any(|e| {
                    target
                        .tree
                        .entries
                        .iter()
                        .find(|v| v.path == e.path)
                        .is_none_or(|new| {
                            new.id != e.id
                                || new.parent != e.parent
                                || new.owner != e.owner
                                || new.group != e.group
                                || new.mode != e.mode
                                || (e.content == EntryContent::Directory)
                                    != (new.content == EntryContent::Directory)
                                || matches!(e.content, EntryContent::Directory)
                                    && new.content != e.content
                        })
                })
                || target.tree.entries.iter().any(|e| {
                    !old.tree.entries.iter().any(|v| v.path == e.path)
                        && (e.content == EntryContent::Directory
                            || !before.observations.contains_key(perm::parent(&e.path)))
                });
            if !structural {
                for entry in &target.tree.entries {
                    if old.tree.entries.iter().find(|e| e.path == entry.path) != Some(entry) {
                        let parent = verify_ancestry(&n, &before, &entry.path)?;
                        if parent.metadata()?.mode() & 0o222 == 0 {
                            return Err(FsError::ReadOnly);
                        }
                    }
                }
            }
            let scan = Scan::observe(&n.root, &n.policy, Instant::now() + Duration::from_secs(30))?;
            if scan.observations() != before.observations
                || !scan.unsupported.is_empty()
                || scan_tree(&core, &n, &old.tree).is_err()
            {
                return Err(FsError::DirtyWorkingState);
            }
            crate::capture::authorize_capture(&core.config, &actor, Some(&old.tree), &target.tree)?;
            Ok(structural)
        })();
        let structural = match preflight {
            Ok(structural) => structural,
            Err(FsError::UnsafeStorage) if root_replaced(&core, &n)? => {
                status.status = blocked("bound_root_changed");
                status_save(&core, &status)?;
                return Ok(status.status);
            }
            Err(e) => {
                status.status = match e {
                    FsError::DirtyWorkingState | FsError::GenerationMismatch => pending(e.code()),
                    _ => blocked(e.code()),
                };
                status_save(&core, &status)?;
                return Ok(status.status);
            }
        };
        // The immutable revision/source is selected while owned; HTTP runs without Core's mutex.
        drop(core);
        self.prefetch_native(
            revision,
            binding.as_ref().map(|b| b.source.clone()),
            NativeHydration::Incoming,
        )?;
        let mut core = lock(&self.core)?;
        if core.working()?.generation != generation
            || core.working()?.head != old.head
            || Scan::observe(&n.root, &n.policy, Instant::now() + Duration::from_secs(30))?
                .observations()
                != before.observations
        {
            status.status = pending("native_changed");
            status_save(&core, &status)?;
            return Ok(status.status);
        }
        let mut r = Intent {
            operation: operation.clone(),
            revision: revision.clone(),
            generation,
            base: old.head.clone(),
            binding,
            actor,
            stage: core.journal.path.join(format!(
                "native-{}",
                operation.as_str().trim_start_matches("operation:")
            )),
            stage_identity: None,
            before,
            files: vec![],
            status: pending("staging"),
            root: None,
        };
        let result = (|| -> Result<NativeApplyStatus, FsError> {
            let retained = all
                .iter()
                .map(usage)
                .fold((0u64, 0usize), |a, b| (a.0.saturating_add(b.0), a.1 + b.1));
            let count: usize = all
                .iter()
                .map(|r| r.files.len() + r.files.iter().map(|f| f.versions.len()).sum::<usize>())
                .sum();
            let existing: u64 = all
                .iter()
                .flat_map(|r| {
                    r.files
                        .iter()
                        .map(move |f| r.stage.join(&f.stage))
                        .chain(r.files.iter().flat_map(|f| f.versions.clone()))
                })
                .filter_map(|p| std::fs::symlink_metadata(p).ok())
                .map(|m| m.len())
                .sum();
            let changed: Vec<_> = target
                .tree
                .entries
                .iter()
                .filter(|e| old.tree.entries.iter().find(|o| o.path == e.path) != Some(e))
                .cloned()
                .collect();
            let needed: u64 = changed
                .iter()
                .map(|e| match &e.content {
                    EntryContent::File { version } => version
                        .size
                        .max(r.before.observations.get(&e.path).map_or(0, |o| o.size)),
                    _ => 0,
                })
                .sum();
            if !structural
                && (count + changed.len() > RETAIN_GENERATIONS
                    || existing.saturating_add(needed) > RETAIN_BYTES)
            {
                return Ok(blocked("displacement_backpressure"));
            }
            save(&core, &r)?;
            let state = directory(&core.journal.path)?;
            let stage_leaf = r.stage.file_name().ok_or(FsError::InvalidPath)?;
            if unsafe { libc::mkdirat(state.as_raw_fd(), name(stage_leaf)?.as_ptr(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            state.sync_all()?;
            let stage = directory(&r.stage)?;
            r.stage_identity = Some(observation(&stage)?);
            save(&core, &r)?;
            if structural {
                return crate::native_root::prepare(&mut core, &n, &mut r, &target, retained);
            }
            for (i, e) in changed.into_iter().enumerate() {
                let parent = verify_ancestry(&n, &r.before, &e.path)?;
                let m = parent.metadata()?;
                if m.dev() != stage.metadata()?.dev() {
                    return Ok(blocked("cross_device"));
                }
                if m.mode() & 0o222 == 0 {
                    return Ok(blocked("readonly_parent"));
                }
                let filename = format!("generation-{i}");
                let mut file = open_at(
                    stage.as_raw_fd(),
                    &name(OsStr::new(&filename))?,
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                )?;
                let EntryContent::File { version } = &e.content else {
                    return Ok(blocked("structural_operation"));
                };
                for extent in &version.extents {
                    match extent {
                        Extent::Chunk {
                            object,
                            offset,
                            length,
                            ..
                        } => {
                            let bytes = core.objects.read_verified(object)?;
                            file.write_all(&bytes[*offset as usize..(*offset + *length) as usize])?
                        }
                        Extent::Hole { length } => {
                            file.seek(SeekFrom::Current(
                                (*length).try_into().map_err(|_| FsError::LimitExceeded)?,
                            ))?;
                        }
                    }
                }
                file.set_len(version.size)?;
                let uid = core
                    .config
                    .authorities
                    .iter()
                    .find(|a| a.principal == e.owner)
                    .ok_or(FsError::MappingBlocked)?
                    .uid;
                let gid = core
                    .config
                    .authorities
                    .iter()
                    .find(|a| a.primary_group == e.group)
                    .ok_or(FsError::MappingBlocked)?
                    .gid;
                if (file.metadata()?.uid() != uid || file.metadata()?.gid() != gid)
                    && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
                {
                    return Err(FsError::MappingBlocked);
                }
                file.set_permissions(Permissions::from_mode(e.mode as u32))?;
                file.sync_all()?;
                verify_file(&core, &mut file, &e)?;
                r.files.push(FileIntent {
                    path: e.path.clone(),
                    stage: filename,
                    expected: r.before.observations.get(&e.path).cloned(),
                    installed: observation(&file)?,
                    old_entry: old.tree.entries.iter().find(|o| o.path == e.path).cloned(),
                    entry: e,
                    exchanged: false,
                    versions: vec![],
                    last_displaced: None,
                    last_displaced_hash: None,
                    ambiguous: false,
                });
            }
            stage.sync_all()?;
            r.status = pending("intent");
            save(&core, &r)?;
            crate::faults::capture_barrier("native-intent", 1)?;
            finish(&mut core, &n, &mut r)
        })();
        status.status = match result {
            Ok(s) => s,
            Err(e) => blocked(e.code()),
        };
        r.status = status.status.clone();
        save(&core, &r)?;
        status_save(&core, &status)?;
        Ok(status.status)
    }
}
fn finish(core: &mut Core, n: &NativeConfig, r: &mut Intent) -> Result<NativeApplyStatus, FsError> {
    if authority_revision(core)?.is_some_and(|id| id != r.revision) {
        return Ok(blocked("permission_denied"));
    }
    if matches!(r.status, NativeApplyStatus::Ready { .. }) && r.ambiguous() {
        return Ok(pending("retained_candidate"));
    }
    if matches!(r.status, NativeApplyStatus::Ready { .. }) {
        let scan = scan_tree(core, n, &core.revision(&r.revision)?.tree)?;
        if scan.observations != baseline(core)?.observations {
            return Ok(pending("native_changed"));
        }
        return Ok(r.status.clone());
    }
    if authority_revision(core)?.is_some_and(|id| id != r.revision) {
        return Ok(blocked("permission_denied"));
    }
    let old = core.working()?.clone();
    if old.generation != r.generation || old.head != r.base {
        return Ok(pending("generation_mismatch"));
    }
    if r.root.is_some() {
        return crate::native_root::finish(core, n, r);
    }
    let stage = stage_open(r)?;
    for i in 0..r.files.len() {
        let f = r.files[i].clone();
        let parent = verify_ancestry(n, &r.before, &f.path)?;
        let current = open_file(&parent, leaf(&f.path));
        let already = current
            .as_ref()
            .ok()
            .and_then(|d| observation(d).ok())
            .is_some_and(|o| f.installed.same_identity(&o));
        if !already {
            if f.exchanged {
                return Ok(blocked("unowned_target_replacement"));
            }
            let staged = open_file(&stage, &f.stage)?;
            if !f.installed.same_identity(&observation(&staged)?) {
                return Ok(blocked("ambiguous_exchange"));
            }
            // Hold the expected inode across exchange so an editor cannot recycle its identity.
            let _expected_guard;
            if let Some(expected) = &f.expected {
                let mut current = current?;
                if !same_generation(expected, &observation(&current)?) {
                    return Ok(pending("native_changed"));
                }
                verify_file(
                    core,
                    &mut current,
                    f.old_entry.as_ref().ok_or(FsError::InvalidTree)?,
                )?;
                _expected_guard = Some(current);
            } else if current.is_ok() {
                return Ok(pending("native_created"));
            }
            crate::faults::capture_barrier("native-before-exchange", 1)?;
            verify_ancestry(n, &r.before, &f.path)?;
            rename_atomic(
                &stage,
                &f.stage,
                &parent,
                leaf(&f.path),
                f.expected.is_some(),
            )?;
            crate::faults::capture_barrier("native-exchanged", 1)?;
        }
        r.files[i].exchanged = true;
        save(core, r)?;
        verify_ancestry(n, &r.before, &f.path)?;
        let mut target = open_file(&parent, leaf(&f.path))?;
        if !f.installed.same_identity(&observation(&target)?) {
            return Ok(blocked("unowned_target_replacement"));
        }
        verify_file(core, &mut target, &f.entry)?;
        if let Some(expected) = &f.expected {
            r.files[i].ambiguous = true;
            save(core, r)?;
            let mut displaced = open_file(&stage, &f.stage)?;
            let verified = verify_file_generation(
                core,
                &mut displaced,
                f.old_entry.as_ref().ok_or(FsError::InvalidTree)?,
            );
            let (observed, hash) = match verified {
                Ok(pair) if same_generation(expected, &pair.0) => pair,
                _ => return Ok(blocked("unexpected_displacement")),
            };
            crate::faults::capture_barrier("native-displaced-verified", 1)?;
            // Never adopt a later observation/hash as the verified canonical baseline.
            // A write after this check still differs from the saved verified digest on rescan.
            if observation(&displaced)? != observed || native_hash(&mut displaced)? != hash {
                return Ok(pending("late_displaced_write"));
            }
            r.files[i].ambiguous = false;
            r.files[i].last_displaced = Some(observed);
            r.files[i].last_displaced_hash = Some(hash);
            save(core, r)?;
        }
    }
    let remote = core.revision(&r.revision)?;
    let scan = scan_tree(core, n, &remote.tree)?;
    // Unchanged paths must keep their original generations; changed paths must be exactly ours.
    for (path, observed) in &scan.observations {
        if let Some(f) = r.files.iter().find(|f| &f.path == path) {
            if !f.installed.same_identity(observed) {
                return Ok(blocked("unowned_target_replacement"));
            }
        } else if !r
            .before
            .observations
            .get(path)
            .is_some_and(|o| o.same_identity(observed))
        {
            return Ok(blocked("native_identity_changed"));
        }
    }
    commit(core, n, r, old, remote.tree, scan)
}
/// Commit a verified application: native baseline, working revision, binding and any matching
/// applied receipt in one SQLite transaction.
pub(crate) fn commit(
    core: &mut Core,
    n: &NativeConfig,
    r: &mut Intent,
    old: Working,
    tree: Tree,
    scan: ScanRecord,
) -> Result<NativeApplyStatus, FsError> {
    let mut next = old.clone();
    next.tree = tree;
    next.head = r.revision.clone();
    next.base = r.revision.clone();
    next.generation = old
        .generation
        .checked_add(1)
        .ok_or(FsError::LimitExceeded)?;
    next.epoch = old.epoch.checked_add(1).ok_or(FsError::LimitExceeded)?;
    next.applied = true;
    next.remote_source = r.binding.as_ref().map(|b| b.source.clone());
    crate::faults::capture_barrier("native-before-commit", 1)?;
    if scan_tree(core, n, &next.tree)?.observations != scan.observations {
        return Ok(pending("native_changed"));
    }
    r.status = NativeApplyStatus::Ready {
        revision: r.revision.clone(),
    };
    let mut queues = core.sync_records()?;
    let base = core.revision(&r.base)?.tree;
    let applied = applied_paths(core)?;
    let tx = core.journal.db.transaction()?;
    if let Some(b) = &r.binding {
        tx.execute(
            "INSERT OR IGNORE INTO sync_sources VALUES(?,?)",
            params![b.source.as_str(), json(b)?],
        )?;
        tx.execute(
            "UPDATE sync_binding SET value=? WHERE singleton=1",
            [json(b)?],
        )?;
        for q in &mut queues {
            if q.progress
                .shared_receipt
                .as_ref()
                .is_some_and(|s| s.head == b.view.head)
            {
                q.progress.applied_revision = Some(r.revision.clone());
                tx.execute(
                    "UPDATE sync_queue SET record=? WHERE operation=?",
                    params![json(q)?, q.pending.operation.as_str()],
                )?;
            }
        }
    }
    tx.execute("UPDATE native SET scan=? WHERE singleton=1", [json(&scan)?])?;
    // Record installed regular files by the durable application, not by name or time.
    for e in &next.tree.entries {
        if e.content != EntryContent::Directory
            && base.entries.iter().find(|o| o.id == e.id) != Some(e)
        {
            if let Some(observed) = scan.observations.get(&e.path) {
                tx.execute(
                    "INSERT OR REPLACE INTO native_applied VALUES(?,?)",
                    params![e.path, json(observed)?],
                )?;
            }
        }
    }
    for (path, _) in &applied {
        if !next
            .tree
            .entries
            .iter()
            .any(|e| &e.path == path && e.content != EntryContent::Directory)
        {
            tx.execute("DELETE FROM native_applied WHERE path=?", [path])?;
        }
    }
    tx.execute(
        "UPDATE working SET value=? WHERE singleton=1",
        [json(&next)?],
    )?;
    tx.execute(
        "UPDATE native_apply SET record=? WHERE operation=?",
        params![json(r)?, r.operation.as_str()],
    )?;
    tx.commit()?;
    core.retain_epoch(old);
    core.working = Some(next);
    Ok(r.status.clone())
}

impl Core {
    pub(crate) fn native_roots(&self) -> Result<std::collections::BTreeSet<ObjectId>, FsError> {
        let mut out = std::collections::BTreeSet::new();
        for id in self
            .journal
            .db
            .prepare("SELECT revision FROM native_incoming")?
            .query_map([], |r| r.get::<_, String>(0))?
        {
            out.extend(crate::cache::object_set(
                &self.revision(&RevisionId::parse(id?)?)?.tree,
            ));
        }
        for r in records(self)? {
            out.extend(crate::cache::object_set(&self.revision(&r.base)?.tree));
        }
        // Retained recovery bases and explicitly captured recovery revisions.
        for id in crate::native_recovery::roots(self)? {
            out.extend(crate::cache::object_set(&self.revision(&id)?.tree));
        }
        Ok(out)
    }
}
/// Regular files installed by native applications whose next native change has not yet been
/// captured. Any later change of their native generation has unknown causality: an editor may
/// save bytes it read before the application. An unchanged re-observation never clears a row;
/// only a capture recording a change of that path (or a later application) does.
pub(crate) fn applied_paths(core: &Core) -> Result<Vec<(String, Observation)>, FsError> {
    core.journal
        .db
        .prepare("SELECT path,observation FROM native_applied ORDER BY path")?
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .map(|row| {
            let (path, bytes) = row?;
            Ok((path, from_json(&bytes)?))
        })
        .collect()
}
