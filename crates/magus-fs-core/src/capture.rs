//! Explicit native generations. Native paths are always traversed through no-follow descriptors.
use crate::{
    engine::{from_json, json, lock, Working},
    objects::{name, open_at},
    permissions as perm, *,
};
use caseless::Caseless;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{CStr, OsStr},
    fs::{File, Metadata},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use unicode_normalization::UnicodeNormalization;

#[cfg(target_os = "macos")]
const TYPE_MASK: u32 = libc::S_IFMT as u32;
#[cfg(not(target_os = "macos"))]
const TYPE_MASK: u32 = libc::S_IFMT;
#[cfg(target_os = "macos")]
const DIRECTORY_KIND: u32 = libc::S_IFDIR as u32;
#[cfg(not(target_os = "macos"))]
const DIRECTORY_KIND: u32 = libc::S_IFDIR;
#[cfg(target_os = "macos")]
const FILE_KIND: u32 = libc::S_IFREG as u32;
#[cfg(not(target_os = "macos"))]
const FILE_KIND: u32 = libc::S_IFREG;
#[cfg(target_os = "macos")]
const SYMLINK_KIND: u32 = libc::S_IFLNK as u32;
#[cfg(not(target_os = "macos"))]
const SYMLINK_KIND: u32 = libc::S_IFLNK;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePolicy {
    pub included_roots: Vec<String>,
    pub excluded_prefixes: Vec<String>,
}
impl CapturePolicy {
    pub fn validate(&self) -> Result<(), FsError> {
        if self.included_roots.is_empty()
            || self.included_roots.len() + self.excluded_prefixes.len() > MAX_ENTRIES
        {
            return Err(FsError::InvalidPath);
        }
        for p in self.included_roots.iter().chain(&self.excluded_prefixes) {
            if p != "." {
                crate::paths::validate_path(p)?;
            }
        }
        Ok(())
    }
    fn selected(&self, p: &str) -> bool {
        self.included_roots
            .iter()
            .any(|r| r == "." || beneath(p, r) || beneath(r, p))
            && !self
                .excluded_prefixes
                .iter()
                .any(|r| r == "." || beneath(p, r))
    }
    fn coverage(&self, tree: &Tree) -> Vec<String> {
        fn visit(path: &str, policy: &CapturePolicy, tree: &Tree, out: &mut Vec<String>) {
            let subdivide = policy.excluded_prefixes.iter().any(|e| {
                if path.is_empty() {
                    true
                } else {
                    e != path && beneath(e, path)
                }
            });
            if !subdivide {
                out.push(path.into());
                return;
            }
            let children: Vec<_> = tree
                .entries
                .iter()
                .filter(|e| perm::parent(&e.path) == path)
                .collect();
            if children.is_empty() {
                out.push(path.into());
            } else {
                for entry in children {
                    visit(&entry.path, policy, tree, out);
                }
            }
        }
        let mut out = vec![];
        for root in &self.included_roots {
            let path = if root == "." { "" } else { root };
            if !self
                .excluded_prefixes
                .iter()
                .any(|e| e == "." || beneath(path, e))
            {
                visit(path, self, tree, &mut out);
            }
        }
        out.sort();
        out.dedup();
        let mut frontier: Vec<String> = vec![];
        for path in out {
            if !frontier
                .iter()
                .any(|parent| parent.is_empty() || beneath(&path, parent))
            {
                frontier.push(path);
            }
        }
        let mut out = frontier;
        if out.is_empty() {
            out.push(String::new());
        }
        out
    }
}
fn beneath(p: &str, prefix: &str) -> bool {
    p == prefix || p.strip_prefix(prefix).is_some_and(|s| s.starts_with('/'))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    pub root: PathBuf,
    pub policy: CapturePolicy,
    pub creation_umask: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedEntry {
    pub path: String,
    pub reason: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Observation {
    dev: u64,
    ino: u64,
    kind: u32,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    names: Vec<Vec<u8>>,
}
impl Observation {
    fn metadata(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            kind: m.mode() & TYPE_MASK,
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            nlink: m.nlink(),
            names: vec![],
        }
    }
    fn same_identity(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino && self.kind == other.kind
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct ScanRecord {
    observations: BTreeMap<String, Observation>,
    ids: BTreeMap<String, EntryId>,
    diagnostics: Vec<NativeMetadataDisposition>,
}
#[derive(Clone, Serialize, Deserialize)]
struct CaptureAttempt {
    scan: ScanRecord,
    head: Option<RevisionId>,
    generation: u64,
}
struct Observed {
    info: Observation,
    file: File,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMetadataDisposition {
    pub path: String,
    pub name: String,
    pub value_bytes: u64,
    pub disposition: String,
}
struct Scan {
    nodes: BTreeMap<String, Observed>,
    unsupported: Vec<UnsupportedEntry>,
    diagnostics: Vec<NativeMetadataDisposition>,
    deadline: Instant,
}

pub(crate) fn absolute_native(path: &Path) -> Result<(), FsError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::RootDir))
    {
        return Err(FsError::UnsafeStorage);
    }
    Ok(())
}
pub(crate) fn directory(path: &Path) -> Result<File, FsError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::RootDir))
    {
        return Err(FsError::UnsafeStorage);
    }
    let mut f = open_at(
        libc::AT_FDCWD,
        &name(OsStr::new("/"))?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    for c in path.components() {
        if let Component::Normal(n) = c {
            f = open_at(f.as_raw_fd(), &name(n)?, libc::O_RDONLY | libc::O_DIRECTORY)?;
        }
    }
    Ok(f)
}
pub(crate) fn names(dir: &File) -> Result<Vec<Vec<u8>>, FsError> {
    let copy = open_at(
        dir.as_raw_fd(),
        &name(OsStr::new("."))?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    use std::os::fd::IntoRawFd;
    let fd = copy.into_raw_fd();
    // SAFETY: fdopendir assumes ownership on success; the stream is closed below.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::last_os_error().into());
    }
    let mut result = vec![];
    loop {
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let e = std::io::Error::last_os_error();
            unsafe { libc::closedir(stream) };
            if e.raw_os_error() != Some(0) {
                return Err(e.into());
            }
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            result.push(bytes.to_vec());
            if result.len() > MAX_ENTRIES {
                unsafe { libc::closedir(stream) };
                return Err(FsError::LimitExceeded);
            }
        }
    }
    result.sort();
    Ok(result)
}
pub(crate) fn metadata_inventory(
    file: &File,
    path: &str,
) -> Result<(Vec<UnsupportedEntry>, Vec<NativeMetadataDisposition>), FsError> {
    #[cfg(target_os = "linux")]
    let size = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
    #[cfg(target_os = "macos")]
    let size = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
    if size < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(e.into());
        }
    }
    if size > MAX_DESCRIPTOR as isize {
        return Err(FsError::LimitExceeded);
    }
    let mut unsupported = vec![];
    let mut diagnostics = vec![];
    if size > 0 {
        let mut bytes = vec![0; size as usize];
        #[cfg(target_os = "linux")]
        let count =
            unsafe { libc::flistxattr(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        #[cfg(target_os = "macos")]
        let count = unsafe {
            libc::flistxattr(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0)
        };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for attr in bytes[..count as usize]
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
        {
            let n = std::ffi::CString::new(attr).map_err(|_| FsError::InvalidPath)?;
            #[cfg(target_os = "linux")]
            let length =
                unsafe { libc::fgetxattr(file.as_raw_fd(), n.as_ptr(), std::ptr::null_mut(), 0) };
            #[cfg(target_os = "macos")]
            let length = unsafe {
                libc::fgetxattr(file.as_raw_fd(), n.as_ptr(), std::ptr::null_mut(), 0, 0, 0)
            };
            if length < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let label = String::from_utf8_lossy(attr).into_owned();
            if cfg!(target_os = "macos") && attr == b"com.apple.provenance" {
                diagnostics.push(NativeMetadataDisposition {
                    path: path.into(),
                    name: label,
                    value_bytes: length as u64,
                    disposition: "host_local_nonportable_observed_only".into(),
                });
            } else {
                unsupported.push(UnsupportedEntry {
                    path: path.into(),
                    reason: format!("unsupported_xattr:{label};value_bytes:{length}"),
                });
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
            fn acl_get_entry(
                acl: *mut libc::c_void,
                entry_id: libc::c_int,
                entry: *mut *mut libc::c_void,
            ) -> libc::c_int;
            fn acl_free(p: *mut libc::c_void) -> libc::c_int;
        }
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        if !acl.is_null() {
            let mut entry = std::ptr::null_mut();
            let n = unsafe { acl_get_entry(acl, 0, &mut entry) };
            unsafe { acl_free(acl) };
            if n == 0 {
                unsupported.push(UnsupportedEntry {
                    path: path.into(),
                    reason: "extended_acl".into(),
                });
            }
        }
        use std::os::macos::fs::MetadataExt;
        if file.metadata()?.st_flags() != 0 {
            unsupported.push(UnsupportedEntry {
                path: path.into(),
                reason: "file_flags".into(),
            });
        }
    }
    Ok((unsupported, diagnostics))
}
impl Scan {
    fn observe(root: &Path, policy: &CapturePolicy, deadline: Instant) -> Result<Self, FsError> {
        let file = directory(root)?;
        let mut result = Self {
            nodes: BTreeMap::new(),
            unsupported: vec![],
            diagnostics: vec![],
            deadline,
        };
        result.visit("", file, policy)?;
        Ok(result)
    }
    fn visit(&mut self, path: &str, file: File, policy: &CapturePolicy) -> Result<(), FsError> {
        if Instant::now() >= self.deadline {
            return Err(FsError::UnstableCapture);
        }
        if self.nodes.len() >= MAX_ENTRIES {
            return Err(FsError::LimitExceeded);
        }
        let mut info = Observation::metadata(&file.metadata()?);
        let (unsupported, diagnostics) = metadata_inventory(&file, path)?;
        self.unsupported.extend(unsupported);
        self.diagnostics.extend(diagnostics);
        if info.mode & 0o7000 != 0 {
            self.unsupported.push(UnsupportedEntry {
                path: path.into(),
                reason: "special_mode".into(),
            });
        }
        if info.kind == FILE_KIND && info.nlink > 1 {
            self.unsupported.push(UnsupportedEntry {
                path: path.into(),
                reason: "hardlink".into(),
            });
        }
        if info.kind == DIRECTORY_KIND {
            info.names = names(&file)?;
            let mut folded = BTreeMap::<String, String>::new();
            for raw in &info.names {
                if Instant::now() >= self.deadline {
                    return Err(FsError::UnstableCapture);
                }
                let part = String::from_utf8(raw.clone());
                let display = String::from_utf8_lossy(raw);
                let child = if path.is_empty() {
                    display.into_owned()
                } else {
                    format!("{path}/{display}")
                };
                if !policy.selected(&child) {
                    continue;
                }
                if part.is_err() || crate::paths::validate_path(&child).is_err() {
                    self.unsupported.push(UnsupportedEntry {
                        path: child.clone(),
                        reason: format!(
                            "non_utf8_non_nfc_or_nonportable_name;component_hex:{}",
                            crate::model::hex(raw)
                        ),
                    });
                }
                let fold: String = child.nfd().default_case_fold().nfc().collect();
                if let Some(previous) = folded.insert(fold, child.clone()) {
                    self.unsupported.push(UnsupportedEntry {
                        path: child.clone(),
                        reason: format!("case_fold_collision:{previous}"),
                    });
                }
                let leaf = name(OsStr::from_bytes(raw))?;
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: output stat is initialized only on success, leaf and parent remain live.
                if unsafe {
                    libc::fstatat(
                        file.as_raw_fd(),
                        leaf.as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(FsError::UnstableCapture);
                }
                let stat = unsafe { stat.assume_init() };
                #[cfg(target_os = "macos")]
                let native_mode = stat.st_mode as u32;
                #[cfg(not(target_os = "macos"))]
                let native_mode = stat.st_mode;
                let kind = native_mode & TYPE_MASK;
                if kind != DIRECTORY_KIND && kind != FILE_KIND {
                    self.unsupported.push(UnsupportedEntry {
                        path: child,
                        reason: if kind == SYMLINK_KIND {
                            "symlink"
                        } else {
                            "special_file"
                        }
                        .into(),
                    });
                    continue;
                }
                let opened = open_at(
                    file.as_raw_fd(),
                    &leaf,
                    libc::O_RDONLY
                        | libc::O_NONBLOCK
                        | if kind == DIRECTORY_KIND {
                            libc::O_DIRECTORY
                        } else {
                            0
                        },
                )
                .map_err(|e| match e {
                    FsError::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
                        FsError::PermissionDenied
                    }
                    FsError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
                        FsError::UnstableCapture
                    }
                    FsError::UnsafeStorage => FsError::UnstableCapture,
                    other => other,
                })?;
                if opened.metadata()?.mode() & TYPE_MASK != kind {
                    return Err(FsError::UnstableCapture);
                }
                self.visit(&child, opened, policy)?;
            }
        }
        self.nodes.insert(path.into(), Observed { info, file });
        Ok(())
    }
    fn observations(&self) -> BTreeMap<String, Observation> {
        self.nodes
            .iter()
            .map(|(p, o)| (p.clone(), o.info.clone()))
            .collect()
    }
}
fn mapped(config: &ReplicaConfig, info: &Observation) -> Result<(PrincipalId, GroupId), FsError> {
    let owner = config
        .authorities
        .iter()
        .find(|a| a.uid == info.uid)
        .ok_or(FsError::MappingBlocked)?;
    let group = config
        .authorities
        .iter()
        .find(|a| a.gid == info.gid)
        .ok_or(FsError::MappingBlocked)?;
    Ok((owner.principal.clone(), group.primary_group.clone()))
}
fn authorize_capture(
    config: &ReplicaConfig,
    actor: &Actor,
    old: Option<&Tree>,
    new: &Tree,
) -> Result<(), FsError> {
    let a = perm::authority(config, actor)?;
    if let Some(old) = old {
        perm::access(a, &perm::root_entry(old), 5)?;
        if old.root != new.root && old.root.owner != *actor.principal() {
            return Err(FsError::PermissionDenied);
        }
        if old.root.owner != new.root.owner || old.root.group != new.root.group {
            perm::ownership_change(config, a, &new.root.owner, &new.root.group)?;
        }
        for entry in &old.entries {
            perm::traversal(old, &entry.path, a)?;
            perm::access(
                a,
                entry,
                if entry.content == EntryContent::Directory {
                    5
                } else {
                    4
                },
            )?;
            let replacement = new.entries.iter().find(|e| e.id == entry.id);
            if replacement != Some(entry) {
                perm::parent_write(old, &entry.path, a)?;
                if let Some(replacement) = replacement {
                    if entry.content != replacement.content
                        && entry.content != EntryContent::Directory
                    {
                        perm::access(a, entry, 2)?;
                    }
                    if (entry.mode != replacement.mode
                        || entry.owner != replacement.owner
                        || entry.group != replacement.group)
                        && entry.owner != *actor.principal()
                    {
                        return Err(FsError::PermissionDenied);
                    }
                    if entry.owner != replacement.owner || entry.group != replacement.group {
                        perm::ownership_change(config, a, &replacement.owner, &replacement.group)?;
                    }
                }
            }
        }
        for entry in &new.entries {
            if !old.entries.iter().any(|e| e.id == entry.id) {
                let parent = perm::parent(&entry.path);
                if perm::entry(old, parent).is_ok() {
                    perm::parent_write(old, &entry.path, a)?;
                }
            }
        }
    }
    if old.is_none() {
        perm::access(a, &perm::root_entry(new), 5)?;
        for e in &new.entries {
            perm::traversal(new, &e.path, a)?;
            perm::access(
                a,
                e,
                if e.content == EntryContent::Directory {
                    5
                } else {
                    4
                },
            )?;
        }
    }
    Ok(())
}
impl Replica {
    pub fn configure_native(&self, config: NativeConfig) -> Result<(), FsError> {
        absolute_native(&config.root)?;
        config.policy.validate()?;
        if config.creation_umask != 0o022 {
            return Err(FsError::ConfigMismatch);
        }
        let core = lock(&self.core)?;
        core.journal.check_content_path(&config.root)?;
        let prior: Option<Vec<u8>> = core
            .journal
            .db
            .query_row(
                "SELECT configuration FROM native WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let bytes = json(&config)?;
        if let Some(prior) = prior {
            if prior != bytes {
                return Err(FsError::ConfigMismatch);
            }
        } else {
            core.journal
                .db
                .execute("INSERT INTO native VALUES(1,?,NULL)", [bytes])?;
        }
        Ok(())
    }
    pub fn native_config(&self) -> Result<Option<NativeConfig>, FsError> {
        let core = lock(&self.core)?;
        let bytes: Option<Vec<u8>> = core
            .journal
            .db
            .query_row(
                "SELECT configuration FROM native WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        bytes.map(|b| from_json(&b)).transpose()
    }
    pub fn reopen(state: impl AsRef<Path>) -> Result<Self, FsError> {
        let (journal, config) = crate::journal::Journal::reopen(state.as_ref())?;
        Self::from_journal(state.as_ref(), config, journal)
    }
    pub fn native_metadata_diagnostics(&self) -> Result<Vec<NativeMetadataDisposition>, FsError> {
        let core = lock(&self.core)?;
        let bytes: Option<Vec<u8>> = core
            .journal
            .db
            .query_row("SELECT scan FROM native WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .optional()?
            .flatten();
        Ok(bytes
            .map(|b| from_json::<ScanRecord>(&b))
            .transpose()?
            .map(|s| s.diagnostics)
            .unwrap_or_default())
    }
    pub fn capture(
        &self,
        root: impl AsRef<Path>,
        policy: CapturePolicy,
        operation: OperationId,
        actor: Actor,
    ) -> Result<RevisionId, FsError> {
        let root = root.as_ref();
        absolute_native(root)?;
        policy.validate()?;
        let mut core = lock(&self.core)?;
        core.journal.check_content_path(root)?;
        let config: NativeConfig = from_json(&core.journal.db.query_row(
            "SELECT configuration FROM native WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        if config.root != root || config.policy != policy {
            return Err(FsError::ConfigMismatch);
        }
        perm::authority(&core.config, &actor)?;
        if core.working.as_ref().is_some_and(|w| w.dirty) {
            return Err(FsError::DirtyWorkingState);
        }
        let prior: Option<Vec<u8>> =
            core.journal
                .db
                .query_row("SELECT scan FROM native WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
        let prior = prior.map(|b| from_json::<ScanRecord>(&b)).transpose()?;
        let attempted: Option<Vec<u8>> = core
            .journal
            .db
            .query_row(
                "SELECT record FROM capture_attempts WHERE operation=?",
                [operation.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        let attempted = attempted
            .map(|b| from_json::<CaptureAttempt>(&b))
            .transpose()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        for attempt in 1..=3 {
            if Instant::now() >= deadline {
                break;
            }
            let mut scan = match Scan::observe(root, &policy, deadline) {
                Err(FsError::UnstableCapture) => continue,
                result => result?,
            };
            for included in &policy.included_roots {
                if included != "."
                    && !scan.nodes.contains_key(included)
                    && !policy
                        .excluded_prefixes
                        .iter()
                        .any(|e| e == "." || beneath(included, e))
                {
                    return Err(FsError::NotFound);
                }
            }
            if !scan.unsupported.is_empty() {
                return Err(FsError::UnsupportedEntries(scan.unsupported));
            }
            crate::faults::capture_barrier("capture-observed", attempt)?;
            let observations = scan.observations();
            if attempted
                .as_ref()
                .is_some_and(|a| a.scan.observations != observations)
            {
                return Err(FsError::OperationMismatch);
            }
            let trustworthy_root = prior.as_ref().is_some_and(|p| {
                p.observations
                    .get("")
                    .is_some_and(|o| o.same_identity(&observations[""]))
            });
            let mut ids = BTreeMap::new();
            for (path, observation) in &observations {
                let old = prior.as_ref().filter(|_| trustworthy_root).and_then(|p| {
                    p.observations
                        .get(path)
                        .filter(|o| o.same_identity(observation))
                        .and_then(|_| p.ids.get(path))
                });
                let old = old.filter(|id| {
                    core.working.as_ref().is_some_and(|w| {
                        if path.is_empty() {
                            &w.tree.root.id == *id
                        } else {
                            w.tree
                                .entries
                                .iter()
                                .any(|e| &e.id == *id && &e.path == path)
                        }
                    })
                });
                let old = attempted
                    .as_ref()
                    .and_then(|a| a.scan.ids.get(path))
                    .or(old);
                ids.insert(
                    path.clone(),
                    match old {
                        Some(id) => id.clone(),
                        None => EntryId::random()?,
                    },
                );
            }
            let root_info = &observations[""];
            let (owner, group) = mapped(&core.config, root_info)?;
            let mut tree = Tree {
                root: Root {
                    id: ids[""].clone(),
                    owner,
                    group,
                    mode: (root_info.mode & 0o777) as u16,
                },
                entries: vec![],
            };
            let authority = perm::authority(&core.config, &actor)?.clone();
            let authority_root = core
                .working
                .as_ref()
                .map(|w| perm::root_entry(&w.tree))
                .unwrap_or_else(|| perm::root_entry(&tree));
            perm::access(&authority, &authority_root, 5)?;
            let mut changed = false;
            for (path, node) in &mut scan.nodes {
                if path.is_empty() {
                    continue;
                }
                let (owner, group) = mapped(&core.config, &node.info)?;
                let preview = Entry {
                    path: path.clone(),
                    id: ids[path].clone(),
                    parent: ids[perm::parent(path)].clone(),
                    owner: owner.clone(),
                    group: group.clone(),
                    mode: (node.info.mode & 0o777) as u16,
                    content: if node.info.kind == DIRECTORY_KIND {
                        EntryContent::Directory
                    } else {
                        EntryContent::File {
                            version: FileVersion {
                                size: 0,
                                extents: vec![],
                            },
                        }
                    },
                };
                let current = core
                    .working
                    .as_ref()
                    .and_then(|w| w.tree.entries.iter().find(|e| e.id == preview.id));
                if let Some(current) = current {
                    perm::traversal(
                        &core.working.as_ref().ok_or(FsError::BaseMismatch)?.tree,
                        &current.path,
                        &authority,
                    )?;
                    perm::access(
                        &authority,
                        current,
                        if node.info.kind == DIRECTORY_KIND {
                            5
                        } else {
                            4
                        },
                    )?;
                } else {
                    perm::traversal(&tree, path, &authority)?;
                    perm::access(
                        &authority,
                        &preview,
                        if node.info.kind == DIRECTORY_KIND {
                            5
                        } else {
                            4
                        },
                    )?;
                }
                let content = if node.info.kind == DIRECTORY_KIND {
                    EntryContent::Directory
                } else {
                    if node.info.size > MAX_FILE {
                        return Err(FsError::LimitExceeded);
                    }
                    let mut extents = vec![];
                    let mut remaining = node.info.size;
                    while remaining > 0 {
                        if Instant::now() >= deadline {
                            return Err(FsError::UnstableCapture);
                        }
                        let length = remaining.min(262144) as usize;
                        let mut bytes = vec![0; length];
                        if node.file.read_exact(&mut bytes).is_err() {
                            changed = true;
                            break;
                        }
                        let object = ObjectId::for_bytes(&bytes)?;
                        core.reserve(&BTreeMap::from([(object.clone(), length as u64)]))?;
                        core.objects.install(&bytes)?;
                        extents.push(Extent::Chunk {
                            object,
                            object_size: length as u64,
                            offset: 0,
                            length: length as u64,
                        });
                        remaining -= length as u64;
                        if extents.len() > MAX_EXTENTS {
                            return Err(FsError::LimitExceeded);
                        }
                    }
                    EntryContent::File {
                        version: FileVersion {
                            size: node.info.size,
                            extents,
                        },
                    }
                };
                let (owner, group) = mapped(&core.config, &node.info)?;
                tree.entries.push(Entry {
                    path: path.clone(),
                    id: ids[path].clone(),
                    parent: ids[perm::parent(path)].clone(),
                    owner,
                    group,
                    mode: (node.info.mode & 0o777) as u16,
                    content,
                });
            }
            crate::faults::capture_barrier("capture-hashed", attempt)?;
            let validation = Scan::observe(root, &policy, deadline);
            if changed
                || validation.as_ref().map_or(true, |s| {
                    s.observations() != observations || !s.unsupported.is_empty()
                })
                || Instant::now() >= deadline
            {
                continue;
            }
            validate_tree(&tree)?;
            authorize_capture(
                &core.config,
                &actor,
                core.working.as_ref().map(|w| &w.tree),
                &tree,
            )?;
            let digest =
                RevisionId::digest(&json(&(root, &policy, &actor, &tree, &observations))?)?;
            let existing = core
                .journal
                .db
                .query_row(
                    "SELECT digest,result FROM operations WHERE operation=?",
                    [operation.as_str()],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
                )
                .optional()?;
            if let Some((prior, result)) = existing {
                if prior != digest.as_str() {
                    return Err(FsError::OperationMismatch);
                }
                if let Some(id) = result {
                    return RevisionId::parse(id);
                }
            }
            if let Some(attempted) = &attempted {
                if attempted.head != core.working.as_ref().map(|w| w.head.clone())
                    || attempted.generation
                        != core.working.as_ref().map(|w| w.generation).unwrap_or(0)
                {
                    return Err(FsError::OperationMismatch);
                }
            }
            let revision = Revision {
                format: FORMAT.into(),
                hash: HASH.into(),
                layout: LAYOUT.into(),
                parents: core
                    .working
                    .as_ref()
                    .map(|w| vec![w.head.clone()])
                    .unwrap_or_default(),
                operation: operation.clone(),
                replica: core.config.replica.clone(),
                principal: actor.principal().clone(),
                captured_at_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| FsError::InvalidDescriptor)?
                    .as_nanos()
                    .try_into()
                    .map_err(|_| FsError::LimitExceeded)?,
                coverage: policy.coverage(&tree),
                provenance: "native_scan_delete_create".into(),
                tree,
            };
            let descriptor = encode_revision(&revision)?;
            let id = revision_id(&revision)?;
            let next = Working {
                base: core
                    .working
                    .as_ref()
                    .map(|w| w.base.clone())
                    .unwrap_or(id.clone()),
                head: id.clone(),
                generation: core
                    .working
                    .as_ref()
                    .map(|w| w.generation)
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(FsError::LimitExceeded)?,
                dirty: false,
                umask: 0o022,
                tree: revision.tree.clone(),
                orphans: vec![],
            };
            let scan_record = ScanRecord {
                observations,
                ids,
                diagnostics: scan.diagnostics,
            };
            let attempt_record = CaptureAttempt {
                scan: scan_record.clone(),
                head: core.working.as_ref().map(|w| w.head.clone()),
                generation: core.working.as_ref().map(|w| w.generation).unwrap_or(0),
            };
            core.journal.guard()?;
            let tx = core
                .journal
                .db
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("INSERT INTO operations VALUES(?,?,'pending',NULL,NULL,?) ON CONFLICT(operation) DO UPDATE SET state='pending',error=NULL",params![operation.as_str(),digest.as_str(),&descriptor])?;
            tx.execute(
                "INSERT OR REPLACE INTO capture_attempts VALUES(?,?)",
                params![operation.as_str(), json(&attempt_record)?],
            )?;
            tx.commit()?;
            let result = (|| {
                for (object, _) in crate::cache::closure(&revision.tree) {
                    core.objects.sync_object(&object)?;
                }
                crate::faults::hit("before-transaction")?;
                let tx = core
                    .journal
                    .db
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                tx.execute(
                    "INSERT INTO revisions VALUES(?,?)",
                    params![id.as_str(), descriptor],
                )?;
                tx.execute("INSERT OR REPLACE INTO working VALUES(1,?)", [json(&next)?])?;
                tx.execute(
                    "UPDATE native SET scan=? WHERE singleton=1",
                    [json(&scan_record)?],
                )?;
                tx.execute(
                    "UPDATE operations SET state='committed',result=?,error=NULL WHERE operation=?",
                    params![id.as_str(), operation.as_str()],
                )?;
                crate::faults::hit("db-commit")?;
                tx.commit()?;
                core.working = Some(next);
                crate::faults::hit("after-commit")?;
                Ok(id.clone())
            })();
            if let Err(e) = &result {
                core.failed(&operation, e)?;
            }
            return result;
        }
        Err(FsError::UnstableCapture)
    }
}
