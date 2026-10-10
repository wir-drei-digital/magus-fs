//! Structural native application by verified root exchange.
//!
//! A complete new root is staged beside the bound root, on the same filesystem, and exchanged
//! with it by the OS atomic directory exchange primitive. The displaced root is never removed or
//! overwritten: it is verified against its pre-exchange observations, retained, enumerated and
//! rescanned for writes through descriptors or working directories that still reference it.
//! Journal phases: Staging -> Prepared -> Exchanged -> Verified -> Ready (or Abandoned before any
//! exchange). Recovery inspects both inode identities against the durable phase.
use crate::{
    capture::{directory, metadata_inventory, names, Observation},
    engine::Core,
    native_apply::{
        self as na, blocked, pending, Intent, NativeApplyStatus, RETAIN_BYTES, RETAIN_GENERATIONS,
    },
    objects::{name, open_at},
    *,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{File, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RootPhase {
    Staging,
    Prepared,
    Exchanged,
    Verified,
    Abandoned,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) observation: Observation,
    pub(crate) digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RootVersion {
    pub(crate) path: String,
    pub(crate) version: PathBuf,
    pub(crate) digest: String,
    pub(crate) size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RootIntent {
    pub(crate) phase: RootPhase,
    pub(crate) parent: PathBuf,
    pub(crate) parent_identity: Observation,
    pub(crate) root_leaf: String,
    pub(crate) stage_leaf: String,
    /// The complete original root (managed and capture-excluded local-only entries).
    pub(crate) original: BTreeMap<String, Snapshot>,
    pub(crate) local: Vec<String>,
    /// Identities this operation created in the staged root ("" is the staged root itself).
    pub(crate) staged: BTreeMap<String, Observation>,
    /// Last observation of the displaced root; late changes are copied before replacing it.
    pub(crate) displaced: BTreeMap<String, Snapshot>,
    pub(crate) versions: Vec<RootVersion>,
    pub(crate) ambiguous: bool,
    pub(crate) staged_bytes: u64,
}
impl RootIntent {
    pub(crate) fn exchanged(&self) -> bool {
        matches!(self.phase, RootPhase::Exchanged | RootPhase::Verified)
    }
    pub(crate) fn retained_path(&self) -> PathBuf {
        self.parent.join(&self.stage_leaf)
    }
    /// Charged retained bytes and generations: the displaced or abandoned root plus versions.
    pub(crate) fn usage(&self) -> (u64, usize) {
        let versions: u64 = self.versions.iter().map(|v| v.size).sum();
        let tree = if self.exchanged() {
            self.displaced
                .values()
                .filter(|s| s.digest.is_some())
                .map(|s| s.observation.size)
                .sum()
        } else if self.staged.is_empty() {
            0
        } else {
            self.staged_bytes
        };
        let generations = usize::from(self.exchanged() || !self.staged.is_empty());
        (
            tree.saturating_add(versions),
            generations + self.versions.len(),
        )
    }
}
pub(crate) enum Halt {
    Block(&'static str),
    Fs(FsError),
}
impl From<FsError> for Halt {
    fn from(e: FsError) -> Self {
        Halt::Fs(e)
    }
}
type Step<T> = Result<T, Halt>;

fn unchanged(a: &Snapshot, b: &Snapshot) -> bool {
    na::same_generation(&a.observation, &b.observation)
        && a.observation.names == b.observation.names
        && a.digest == b.digest
}
fn same(a: &Option<Observation>, b: &Observation) -> bool {
    a.as_ref().is_some_and(|a| a.same_identity(b))
}
fn errno_is(e: &FsError, codes: &[i32]) -> bool {
    matches!(e, FsError::Io(io) if io.raw_os_error().is_some_and(|c| codes.contains(&c)))
}
fn child(path: &str, leaf: &str) -> String {
    if path.is_empty() {
        leaf.into()
    } else {
        format!("{path}/{leaf}")
    }
}
fn leaf(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
fn beneath(p: &str, prefix: &str) -> bool {
    p == prefix || p.strip_prefix(prefix).is_some_and(|s| s.starts_with('/'))
}
/// No-follow lstat of a name within a held directory.
fn identity_at(parent: &File, leaf: &str) -> Result<Option<Observation>, FsError> {
    let n = name(OsStr::new(leaf))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: n is NUL terminated, parent is a live descriptor, stat is written on success.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            n.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e.into())
        };
    }
    let stat = unsafe { stat.assume_init() };
    #[cfg(target_os = "macos")]
    let mode = stat.st_mode as u32;
    #[cfg(not(target_os = "macos"))]
    let mode = stat.st_mode;
    Ok(Some(Observation {
        dev: stat.st_dev as u64,
        ino: stat.st_ino,
        kind: mode & (libc::S_IFMT as u32),
        size: stat.st_size as u64,
        mtime: 0,
        mtime_ns: 0,
        ctime: 0,
        ctime_ns: 0,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode,
        nlink: stat.st_nlink as u64,
        names: vec![],
    }))
}
fn open_dir(parent: &File, leaf: &str) -> Result<File, FsError> {
    open_at(
        parent.as_raw_fd(),
        &name(OsStr::new(leaf))?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
}
/// Walk a relative directory path from a held directory, never following links.
fn open_rel(base: &File, path: &str) -> Result<File, FsError> {
    let mut dir = open_dir(base, ".")?;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir = open_dir(&dir, part)?;
    }
    Ok(dir)
}
fn mkdir(parent: &File, leaf: &str) -> Result<(), FsError> {
    let n = name(OsStr::new(leaf))?;
    // SAFETY: n is NUL terminated and parent is live.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Complete no-follow inventory of a root. Strict mode (before exchange) blocks entries that
/// cannot be preserved exactly; tolerant mode (retained-root rescans) reports them instead.
struct Inventory {
    root_dev: u64,
    strict: bool,
    deadline: Instant,
    entries: BTreeMap<String, Snapshot>,
    unsupported: Vec<String>,
}
impl Inventory {
    fn take(root: File, strict: bool) -> Step<Self> {
        let mut inv = Self {
            root_dev: root.metadata().map_err(FsError::from)?.dev(),
            strict,
            deadline: Instant::now() + Duration::from_secs(30),
            entries: BTreeMap::new(),
            unsupported: vec![],
        };
        inv.visit("", root)?;
        Ok(inv)
    }
    fn unsupported(&mut self, path: String) -> Step<()> {
        if self.strict {
            return Err(Halt::Block("unsupported_local_entry"));
        }
        self.unsupported.push(path);
        Ok(())
    }
    fn visit(&mut self, path: &str, mut file: File) -> Step<()> {
        if Instant::now() >= self.deadline {
            return Err(FsError::UnstableCapture.into());
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(FsError::LimitExceeded.into());
        }
        let m = file.metadata().map_err(FsError::from)?;
        if m.dev() != self.root_dev {
            return Err(Halt::Block("cross_device"));
        }
        let mut info = Observation::metadata(&m);
        if info.mode & 0o7000 != 0 || !metadata_inventory(&file, path)?.0.is_empty() {
            self.unsupported(path.into())?;
        }
        let digest = if m.is_dir() {
            info.names = names(&file).map_err(|e| self.unreadable(e))?;
            for raw in info.names.clone() {
                let Ok(part) = String::from_utf8(raw.clone()) else {
                    self.unsupported(format!("{path}/<non-utf8>"))?;
                    continue;
                };
                let next = child(path, &part);
                if crate::paths::validate_path(&next).is_err() {
                    self.unsupported(next)?;
                    continue;
                }
                let Some(kind) = identity_at(&file, &part)? else {
                    return Err(FsError::UnstableCapture.into());
                };
                let is_dir = kind.kind == libc::S_IFDIR as u32;
                if !is_dir && kind.kind != libc::S_IFREG as u32 {
                    self.unsupported(next)?;
                    continue;
                }
                let opened = open_at(
                    file.as_raw_fd(),
                    &name(OsStr::from_bytes(&raw))?,
                    libc::O_RDONLY | libc::O_NONBLOCK | if is_dir { libc::O_DIRECTORY } else { 0 },
                );
                let opened = match opened {
                    Ok(f) => f,
                    Err(e) if errno_is(&e, &[libc::EACCES, libc::EPERM]) => {
                        if self.strict {
                            return Err(Halt::Block("unreadable_local_entry"));
                        }
                        self.unsupported.push(next);
                        continue;
                    }
                    Err(_) => return Err(FsError::UnstableCapture.into()),
                };
                if opened.metadata().map_err(FsError::from)?.is_dir() != is_dir {
                    return Err(FsError::UnstableCapture.into());
                }
                self.visit(&next, opened)?;
            }
            None
        } else if m.is_file() {
            if info.nlink > 1 {
                self.unsupported(path.into())?;
            }
            Some(na::native_hash(&mut file)?)
        } else {
            self.unsupported(path.into())?;
            None
        };
        self.entries.insert(
            path.into(),
            Snapshot {
                observation: info,
                digest,
            },
        );
        Ok(())
    }
    fn unreadable(&self, e: FsError) -> Halt {
        if self.strict && errno_is(&e, &[libc::EACCES, libc::EPERM]) {
            Halt::Block("unreadable_local_entry")
        } else {
            Halt::Fs(e)
        }
    }
}

fn ids(core: &Core, owner: &PrincipalId, group: &GroupId) -> Result<(u32, u32), FsError> {
    let uid = core
        .config
        .authorities
        .iter()
        .find(|a| &a.principal == owner)
        .ok_or(FsError::MappingBlocked)?
        .uid;
    let gid = core
        .config
        .authorities
        .iter()
        .find(|a| &a.primary_group == group)
        .ok_or(FsError::MappingBlocked)?
        .gid;
    Ok((uid, gid))
}
/// POSIX ownership change rule for the owner process, refused before any staging work. The
/// group a new entry inherits from the bound parent (BSD semantics) needs no change.
fn chown_possible(uid: u32, gid: u32, inherited: u32) -> bool {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return true;
    }
    if uid != euid {
        return false;
    }
    let egid = unsafe { libc::getegid() };
    if gid == inherited {
        return true;
    }
    let mut groups = vec![0 as libc::gid_t; 1024];
    let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    gid == egid || (n > 0 && groups[..n as usize].contains(&(gid as libc::gid_t)))
}
fn own(file: &File, uid: u32, gid: u32, mode: u32) -> Result<(), FsError> {
    let m = file.metadata()?;
    if (m.uid() != uid || m.gid() != gid)
        && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
    {
        return Err(FsError::MappingBlocked);
    }
    file.set_permissions(Permissions::from_mode(mode))?;
    Ok(())
}
fn write_version(core: &Core, file: &mut File, version: &FileVersion) -> Result<(), FsError> {
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
    Ok(())
}

/// Stage, journal and exchange a complete new root. Called with the private stage directory
/// already created and the intent saved; `existing` is the current retained usage.
pub(crate) fn prepare(
    core: &mut Core,
    n: &NativeConfig,
    r: &mut Intent,
    target: &Revision,
    existing: (u64, usize),
) -> Result<NativeApplyStatus, FsError> {
    let result = stage(core, n, r, target, existing);
    match result {
        Ok(()) => finish(core, n, r),
        Err(halt) => {
            if let Some(root) = &mut r.root {
                root.phase = RootPhase::Abandoned;
            }
            na::save(core, r)?;
            Ok(match halt {
                Halt::Block(reason) => blocked(reason),
                Halt::Fs(e @ (FsError::DirtyWorkingState | FsError::GenerationMismatch)) => {
                    pending(e.code())
                }
                Halt::Fs(FsError::UnstableCapture) => pending("native_changed"),
                Halt::Fs(e) => blocked(e.code()),
            })
        }
    }
}
fn stage(
    core: &mut Core,
    n: &NativeConfig,
    r: &mut Intent,
    target: &Revision,
    existing: (u64, usize),
) -> Step<()> {
    let root_leaf = n
        .root
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(Halt::Block("unsafe_root"))?
        .to_string();
    let parent_path = n.root.parent().ok_or(Halt::Block("unsafe_root"))?;
    let parent = directory(parent_path).map_err(|_| Halt::Block("bound_parent_changed"))?;
    let root = open_dir(&parent, &root_leaf).map_err(|_| Halt::Block("bound_root_changed"))?;
    let root_observation = Observation::metadata(&root.metadata().map_err(FsError::from)?);
    if !r
        .before
        .observations
        .get("")
        .is_some_and(|o| o.same_identity(&root_observation))
    {
        return Err(Halt::Block("bound_root_changed"));
    }
    if parent.metadata().map_err(FsError::from)?.dev() != root_observation.dev {
        return Err(Halt::Block("cross_device"));
    }
    let original = Inventory::take(root, true)?.entries;
    for (path, observed) in &r.before.observations {
        let current = original.get(path).ok_or(FsError::DirtyWorkingState)?;
        if !na::same_generation(observed, &current.observation)
            || observed.names != current.observation.names
        {
            return Err(FsError::DirtyWorkingState.into());
        }
    }
    let local: Vec<String> = original
        .keys()
        .filter(|p| !r.before.observations.contains_key(*p))
        .cloned()
        .collect();
    let targets: BTreeMap<&str, &Entry> = target
        .tree
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    for path in &local {
        let top = !local.iter().any(|p| p != path && beneath(path, p));
        if targets.keys().any(|t| beneath(t, path)) {
            return Err(Halt::Block("local_entry_collision"));
        }
        let parent = crate::permissions::parent(path);
        if top
            && !parent.is_empty()
            && targets
                .get(parent)
                .is_none_or(|e| e.content != EntryContent::Directory)
        {
            return Err(Halt::Block("local_entry_collision"));
        }
    }
    for t in targets.keys() {
        if !n.policy.selected(t) {
            return Err(Halt::Block("local_entry_collision"));
        }
    }
    let inherited = parent.metadata().map_err(FsError::from)?.gid();
    let root_entry = crate::permissions::root_entry(&target.tree);
    for e in std::iter::once(&root_entry).chain(&target.tree.entries) {
        let (uid, gid) = ids(core, &e.owner, &e.group)?;
        if !chown_possible(uid, gid, inherited) {
            return Err(FsError::MappingBlocked.into());
        }
    }
    for path in &local {
        let o = &original[path].observation;
        if !chown_possible(o.uid, o.gid, inherited) {
            return Err(FsError::MappingBlocked.into());
        }
    }
    let original_bytes: u64 = original
        .values()
        .filter(|s| s.digest.is_some())
        .map(|s| s.observation.size)
        .sum();
    let staged_bytes: u64 = target
        .tree
        .entries
        .iter()
        .map(|e| match &e.content {
            EntryContent::File { version } => version.size,
            EntryContent::Directory => 0,
        })
        .chain(local.iter().filter_map(|p| {
            original[p]
                .digest
                .as_ref()
                .map(|_| original[p].observation.size)
        }))
        .sum();
    if existing.1 + 1 > RETAIN_GENERATIONS
        || existing
            .0
            .saturating_add(original_bytes)
            .saturating_add(staged_bytes)
            > RETAIN_BYTES
    {
        return Err(Halt::Block("displacement_backpressure"));
    }
    let stage_leaf = format!(
        ".{}.magus-{}",
        root_leaf,
        r.operation.as_str().trim_start_matches("operation:")
    );
    r.root = Some(RootIntent {
        phase: RootPhase::Staging,
        parent: parent_path.to_path_buf(),
        parent_identity: Observation::metadata(&parent.metadata().map_err(FsError::from)?),
        root_leaf,
        stage_leaf: stage_leaf.clone(),
        displaced: original.clone(),
        original,
        local: local.clone(),
        staged: BTreeMap::new(),
        versions: vec![],
        ambiguous: false,
        staged_bytes,
    });
    na::save(core, r)?;
    match mkdir(&parent, &stage_leaf) {
        Ok(()) => {}
        Err(e) if errno_is(&e, &[libc::EACCES, libc::EPERM, libc::EROFS]) => {
            return Err(Halt::Block("readonly_parent"))
        }
        Err(e) => return Err(e.into()),
    }
    parent.sync_all().map_err(FsError::from)?;
    let staged = open_dir(&parent, &stage_leaf)?;
    let mut created = BTreeMap::new();
    created.insert(
        String::new(),
        Observation::metadata(&staged.metadata().map_err(FsError::from)?),
    );
    r.root.as_mut().unwrap().staged = created.clone();
    na::save(core, r)?;
    // Managed content first (parents sort before children), then opaque local-only entries.
    let original_root = open_dir(&parent, &r.root.as_ref().unwrap().root_leaf)?;
    let mut entries: Vec<&Entry> = target.tree.entries.iter().collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    for e in &entries {
        let dir = open_rel(&staged, crate::permissions::parent(&e.path))?;
        let file = match &e.content {
            EntryContent::Directory => {
                mkdir(&dir, leaf(&e.path))?;
                open_dir(&dir, leaf(&e.path))?
            }
            EntryContent::File { version } => {
                let mut f = open_at(
                    dir.as_raw_fd(),
                    &name(OsStr::new(leaf(&e.path)))?,
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                )?;
                write_version(core, &mut f, version)?;
                f.sync_all().map_err(FsError::from)?;
                f
            }
        };
        created.insert(
            e.path.clone(),
            Observation::metadata(&file.metadata().map_err(FsError::from)?),
        );
    }
    let snapshot = r.root.as_ref().unwrap().original.clone();
    for path in &local {
        let dir = open_rel(&staged, crate::permissions::parent(path))?;
        let source = &snapshot[path];
        let file = if source.digest.is_none() {
            mkdir(&dir, leaf(path))?;
            open_dir(&dir, leaf(path))?
        } else {
            let from_dir = open_rel(&original_root, crate::permissions::parent(path))?;
            let mut from = open_at(
                from_dir.as_raw_fd(),
                &name(OsStr::new(leaf(path)))?,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )?;
            let observed = Observation::metadata(&from.metadata().map_err(FsError::from)?);
            if !na::same_generation(&observed, &source.observation) {
                return Err(FsError::UnstableCapture.into());
            }
            let mut to = open_at(
                dir.as_raw_fd(),
                &name(OsStr::new(leaf(path)))?,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            )?;
            std::io::copy(&mut (&mut from).take(observed.size), &mut to).map_err(FsError::from)?;
            to.sync_all().map_err(FsError::from)?;
            if source.digest.as_deref() != Some(na::native_hash(&mut to)?.as_str()) {
                return Err(FsError::UnstableCapture.into());
            }
            to
        };
        created.insert(
            path.clone(),
            Observation::metadata(&file.metadata().map_err(FsError::from)?),
        );
    }
    // Metadata deepest first so restrictive directory modes never block their children.
    let mut all: Vec<String> = created.keys().filter(|p| !p.is_empty()).cloned().collect();
    all.sort_by(|a, b| b.cmp(a));
    for path in &all {
        let dir = open_rel(&staged, crate::permissions::parent(path))?;
        let (uid, gid, mode, is_dir) = match targets.get(path.as_str()) {
            Some(e) => {
                let (uid, gid) = ids(core, &e.owner, &e.group)?;
                (
                    uid,
                    gid,
                    e.mode as u32,
                    e.content == EntryContent::Directory,
                )
            }
            None => {
                let o = &snapshot[path].observation;
                (
                    o.uid,
                    o.gid,
                    o.mode & 0o777,
                    snapshot[path].digest.is_none(),
                )
            }
        };
        let file = if is_dir {
            open_dir(&dir, leaf(path))?
        } else {
            open_at(
                dir.as_raw_fd(),
                &name(OsStr::new(leaf(path)))?,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )?
        };
        own(&file, uid, gid, mode)?;
        if !is_dir {
            if let Some(e) = targets.get(path.as_str()) {
                let mut f = file;
                na::verify_file(core, &mut f, e)?;
            }
        } else {
            file.sync_all().map_err(FsError::from)?;
        }
    }
    let (uid, gid) = ids(core, &target.tree.root.owner, &target.tree.root.group)?;
    own(&staged, uid, gid, target.tree.root.mode as u32)?;
    staged.sync_all().map_err(FsError::from)?;
    parent.sync_all().map_err(FsError::from)?;
    let root = r.root.as_mut().unwrap();
    root.staged = created;
    root.phase = RootPhase::Prepared;
    na::save(core, r)?;
    Ok(())
}

/// Continue a structural intent from its durable phase. Never removes or overwrites any root.
pub(crate) fn finish(
    core: &mut Core,
    n: &NativeConfig,
    r: &mut Intent,
) -> Result<NativeApplyStatus, FsError> {
    let mut ri = r.root.clone().ok_or(FsError::InvalidDescriptor)?;
    if ri.phase == RootPhase::Abandoned {
        return Ok(r.status.clone());
    }
    let abandon = |core: &mut Core, r: &mut Intent, reason: &str| -> Result<_, FsError> {
        if let Some(root) = &mut r.root {
            root.phase = RootPhase::Abandoned;
        }
        na::save(core, r)?;
        Ok(blocked(reason))
    };
    let parent = match directory(&ri.parent) {
        Ok(p) if Observation::metadata(&p.metadata()?).same_identity(&ri.parent_identity) => p,
        _ if !ri.exchanged() => return abandon(core, r, "bound_parent_changed"),
        _ => return ambiguous(core, r, "ambiguous_root_exchange"),
    };
    let original = ri.original[""].observation.clone();
    let staged_root = ri.staged.get("").cloned();
    let at_root = identity_at(&parent, &ri.root_leaf)?;
    let at_stage = identity_at(&parent, &ri.stage_leaf)?;
    if ri.phase == RootPhase::Staging {
        // Interrupted while populating the stage: nothing was exchanged.
        return abandon(
            core,
            r,
            if same(&at_root, &original) {
                "interrupted_staging"
            } else {
                "bound_root_changed"
            },
        );
    }
    let staged_root = staged_root.ok_or(FsError::InvalidDescriptor)?;
    if ri.phase == RootPhase::Prepared {
        if same(&at_root, &original) && same(&at_stage, &staged_root) {
            crate::faults::capture_barrier("native-root-before-exchange", 1)?;
            match exchange(core, &ri) {
                Ok(()) => {}
                Err(Halt::Block(reason)) => return abandon(core, r, reason),
                Err(Halt::Fs(FsError::UnstableCapture)) => {
                    abandon(core, r, "native_changed")?;
                    return Ok(pending("native_changed"));
                }
                Err(Halt::Fs(e)) => return abandon(core, r, e.code()),
            }
            ri.phase = RootPhase::Exchanged;
            r.root = Some(ri.clone());
            na::save(core, r)?;
            crate::faults::capture_barrier("native-root-exchanged", 1)?;
        } else if same(&at_root, &staged_root) && same(&at_stage, &original) {
            ri.phase = RootPhase::Exchanged;
            r.root = Some(ri.clone());
            na::save(core, r)?;
        } else if same(&at_stage, &staged_root) {
            return abandon(core, r, "bound_root_changed");
        } else {
            return ambiguous(core, r, "ambiguous_root_exchange");
        }
    } else {
        let at_root = identity_at(&parent, &ri.root_leaf)?;
        let at_stage = identity_at(&parent, &ri.stage_leaf)?;
        if !same(&at_stage, &original) {
            return ambiguous(core, r, "ambiguous_root_exchange");
        }
        if !same(&at_root, &staged_root) {
            return ambiguous(core, r, "unowned_target_replacement");
        }
    }
    // The displaced root must still be exactly the verified original.
    match rescan(core, r)? {
        Rescan::Unchanged => {}
        Rescan::Missing => return ambiguous(core, r, "retained_generation_missing"),
        Rescan::Backpressure => return ambiguous(core, r, "displacement_backpressure"),
        Rescan::Changed | Rescan::Unstable => return ambiguous(core, r, "ambiguous_root_exchange"),
    }
    let ri = r.root.clone().ok_or(FsError::InvalidDescriptor)?;
    let displaced_matches = ri.displaced.len() == ri.original.len()
        && ri
            .original
            .iter()
            .all(|(p, s)| ri.displaced.get(p).is_some_and(|d| unchanged(s, d)));
    if !displaced_matches {
        return ambiguous(core, r, "ambiguous_root_exchange");
    }
    // The installed root must be exactly our staged identities and target content.
    let remote = core.revision(&r.revision)?;
    let scan = match na::scan_tree(core, n, &remote.tree) {
        Ok(scan) => scan,
        Err(_) => return ambiguous(core, r, "unowned_target_replacement"),
    };
    for (path, observed) in &scan.observations {
        if !ri
            .staged
            .get(path)
            .is_some_and(|o| o.same_identity(observed))
        {
            return ambiguous(core, r, "unowned_target_replacement");
        }
    }
    let installed = match Inventory::take(open_dir(&parent, &ri.root_leaf)?, false) {
        Ok(i) => i.entries,
        Err(Halt::Fs(e)) => return Err(e),
        Err(Halt::Block(reason)) => return ambiguous(core, r, reason),
    };
    for path in &ri.local {
        let (Some(now), Some(was), Some(id)) = (
            installed.get(path),
            ri.original.get(path),
            ri.staged.get(path),
        ) else {
            return ambiguous(core, r, "unowned_target_replacement");
        };
        if !now.observation.same_identity(id)
            || now.digest != was.digest
            || now.observation.mode != was.observation.mode
            || now.observation.uid != was.observation.uid
            || now.observation.gid != was.observation.gid
        {
            return ambiguous(core, r, "unowned_target_replacement");
        }
    }
    if ri.phase != RootPhase::Verified {
        if let Some(root) = &mut r.root {
            root.phase = RootPhase::Verified;
        }
        na::save(core, r)?;
        crate::faults::capture_barrier("native-root-verified", 1)?;
    }
    let old = core.working()?.clone();
    na::commit(core, n, r, old, remote.tree, scan)
}
fn ambiguous(core: &Core, r: &mut Intent, reason: &str) -> Result<NativeApplyStatus, FsError> {
    if let Some(root) = &mut r.root {
        root.ambiguous = true;
    }
    na::save(core, r)?;
    Ok(blocked(reason))
}
/// Re-verify the bound parent, root, stage and original inventory immediately before exchange.
fn exchange(core: &Core, ri: &RootIntent) -> Step<()> {
    let _ = core;
    let parent = directory(&ri.parent).map_err(|_| Halt::Block("bound_parent_changed"))?;
    if !Observation::metadata(&parent.metadata().map_err(FsError::from)?)
        .same_identity(&ri.parent_identity)
    {
        return Err(Halt::Block("bound_parent_changed"));
    }
    let root = open_dir(&parent, &ri.root_leaf).map_err(|_| Halt::Block("bound_root_changed"))?;
    if !Observation::metadata(&root.metadata().map_err(FsError::from)?)
        .same_identity(&ri.original[""].observation)
    {
        return Err(Halt::Block("bound_root_changed"));
    }
    let stage =
        open_dir(&parent, &ri.stage_leaf).map_err(|_| Halt::Block("retained_stage_identity"))?;
    if !Observation::metadata(&stage.metadata().map_err(FsError::from)?)
        .same_identity(&ri.staged[""])
    {
        return Err(Halt::Block("retained_stage_identity"));
    }
    let now = Inventory::take(root, true)?.entries;
    if now.len() != ri.original.len()
        || !ri
            .original
            .iter()
            .all(|(p, s)| now.get(p).is_some_and(|n| unchanged(s, n)))
    {
        return Err(FsError::UnstableCapture.into());
    }
    match na::rename_atomic(&parent, &ri.stage_leaf, &parent, &ri.root_leaf, true) {
        Ok(()) => Ok(()),
        Err(e) if errno_is(&e, &[libc::EXDEV]) => Err(Halt::Block("cross_device")),
        Err(e) if errno_is(&e, &[libc::EACCES, libc::EPERM, libc::EROFS]) => {
            Err(Halt::Block("readonly_parent"))
        }
        Err(e)
            if errno_is(
                &e,
                &[libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS],
            ) =>
        {
            Err(Halt::Block("exchange_unsupported"))
        }
        Err(e) => Err(e.into()),
    }
}
pub(crate) enum Rescan {
    Unchanged,
    Changed,
    Missing,
    Backpressure,
    Unstable,
}
/// Compare the retained displaced root with its last observation. Every changed or new regular
/// file is copied into owner-private storage with an immutable unknown-causality record before
/// the observation advances; removals and unsupported additions only mark ambiguity.
pub(crate) fn rescan(core: &Core, r: &mut Intent) -> Result<Rescan, FsError> {
    let Some(ri) = r.root.clone() else {
        return Ok(Rescan::Unchanged);
    };
    let parent = match directory(&ri.parent) {
        Ok(p) => p,
        Err(_) => return Ok(Rescan::Missing),
    };
    let displaced = match open_dir(&parent, &ri.stage_leaf) {
        Ok(d)
            if Observation::metadata(&d.metadata()?)
                .same_identity(&ri.original[""].observation) =>
        {
            d
        }
        _ => return Ok(Rescan::Missing),
    };
    let held = open_dir(&displaced, ".")?;
    let inventory = match Inventory::take(displaced, false) {
        Ok(i) => i,
        Err(Halt::Fs(FsError::Backpressure)) => return Ok(Rescan::Backpressure),
        Err(Halt::Fs(FsError::UnstableCapture)) => return Ok(Rescan::Unstable),
        Err(Halt::Fs(e)) => return Err(e),
        Err(Halt::Block(_)) => return Ok(Rescan::Unstable),
    };
    let mut changed = !inventory.unsupported.is_empty();
    let mut next = ri.clone();
    let (mut bytes, mut generations) = (0u64, 0usize);
    for row in na::records(core)? {
        let (b, g) = na::usage(&row);
        bytes = bytes.saturating_add(b);
        generations += g;
    }
    let stage = na::stage_open(r)?;
    for (path, now) in &inventory.entries {
        let previous = ri.displaced.get(path);
        if previous.is_some_and(|p| unchanged(p, now)) {
            continue;
        }
        changed = true;
        let Some(digest) = &now.digest else {
            next.displaced.insert(path.clone(), now.clone());
            continue;
        };
        if generations + 1 > RETAIN_GENERATIONS
            || bytes.saturating_add(now.observation.size) > RETAIN_BYTES
        {
            r.root = Some(next);
            return Ok(Rescan::Backpressure);
        }
        let leaf_name = format!("root-version-{}", next.versions.len());
        let dir = open_rel(&held, crate::permissions::parent(path))?;
        let mut source = open_at(
            dir.as_raw_fd(),
            &name(OsStr::new(leaf(path)))?,
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?;
        if !Observation::metadata(&source.metadata()?).same_identity(&now.observation) {
            r.root = Some(next);
            return Ok(Rescan::Unstable);
        }
        let mut copy = open_at(
            stage.as_raw_fd(),
            &name(OsStr::new(&leaf_name))?,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        )?;
        std::io::copy(&mut (&mut source).take(now.observation.size), &mut copy)?;
        copy.sync_all()?;
        stage.sync_all()?;
        crate::faults::capture_barrier("native-version-copied", 1)?;
        let copied = na::native_hash(&mut copy)?;
        let version = r.stage.join(&leaf_name);
        next.versions.push(RootVersion {
            path: path.clone(),
            version: version.clone(),
            digest: copied.clone(),
            size: copy.metadata()?.len(),
        });
        generations += 1;
        bytes = bytes.saturating_add(now.observation.size);
        if &copied != digest
            || !na::same_generation(
                &Observation::metadata(&source.metadata()?),
                &now.observation,
            )
        {
            r.root = Some(next);
            return Ok(Rescan::Unstable);
        }
        next.displaced.insert(path.clone(), now.clone());
    }
    let present: BTreeSet<&String> = inventory.entries.keys().collect();
    let removed: Vec<String> = ri
        .displaced
        .keys()
        .filter(|p| !present.contains(p))
        .cloned()
        .collect();
    for path in removed {
        changed = true;
        next.displaced.remove(&path);
    }
    if changed {
        next.ambiguous = true;
    }
    r.root = Some(next);
    na::save(core, r)?;
    na::records_for_versions(core, r)?;
    Ok(if changed {
        Rescan::Changed
    } else {
        Rescan::Unchanged
    })
}
/// Current verified bound-root identity for watcher rebinding (dev, inode).
pub(crate) fn bound_identity(core: &Core) -> Result<Option<(u64, u64)>, FsError> {
    Ok(na::baseline(core)
        .ok()
        .and_then(|b| b.observations.get("").map(|o| (o.dev, o.ino))))
}
impl Replica {
    /// The verified native root identity. A watcher rebinds only when this changes.
    pub fn native_root_identity(&self) -> Result<Option<(u64, u64)>, FsError> {
        let core = crate::engine::lock(&self.core)?;
        bound_identity(&core)
    }
}
