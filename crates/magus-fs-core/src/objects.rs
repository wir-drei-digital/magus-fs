use crate::*;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Debug)]
pub struct ObjectLimits {
    pub max_chunk_size: u64,
    pub content_roots: Vec<PathBuf>,
}
impl Default for ObjectLimits {
    fn default() -> Self {
        Self {
            max_chunk_size: MAX_CHUNK,
            content_roots: vec![],
        }
    }
}
/// A private, fd-anchored immutable chunk directory. No content tree may overlap it.
pub struct ObjectStore {
    dir: File,
    limits: ObjectLimits,
    work: ObjectWorkCounters,
}

/// Cumulative local object work, for opt-in latency diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectWork {
    pub verified_bytes: u64,
    pub staged_bytes: u64,
    pub stages: u64,
    pub file_syncs: u64,
    pub directory_syncs: u64,
    pub inventories: u64,
}
#[derive(Default)]
struct ObjectWorkCounters {
    verified_bytes: AtomicU64,
    staged_bytes: AtomicU64,
    stages: AtomicU64,
    file_syncs: AtomicU64,
    directory_syncs: AtomicU64,
    inventories: AtomicU64,
}
impl ObjectStore {
    pub fn work(&self) -> ObjectWork {
        ObjectWork {
            verified_bytes: self.work.verified_bytes.load(Ordering::Relaxed),
            staged_bytes: self.work.staged_bytes.load(Ordering::Relaxed),
            stages: self.work.stages.load(Ordering::Relaxed),
            file_syncs: self.work.file_syncs.load(Ordering::Relaxed),
            directory_syncs: self.work.directory_syncs.load(Ordering::Relaxed),
            inventories: self.work.inventories.load(Ordering::Relaxed),
        }
    }
    fn sync_file(&self, file: &File) -> Result<(), FsError> {
        self.work.file_syncs.fetch_add(1, Ordering::Relaxed);
        file.sync_all()?;
        Ok(())
    }
    fn sync_directory(&self) -> Result<(), FsError> {
        self.work.directory_syncs.fetch_add(1, Ordering::Relaxed);
        self.dir.sync_all()?;
        Ok(())
    }
}

pub(crate) fn name(value: &OsStr) -> Result<CString, FsError> {
    CString::new(value.as_bytes()).map_err(|_| FsError::UnsafeStorage)
}
fn syscall_error() -> FsError {
    let e = std::io::Error::last_os_error();
    if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        FsError::UnsafeStorage
    } else {
        FsError::Io(e)
    }
}
pub(crate) fn open_at(parent: RawFd, n: &std::ffi::CStr, flags: i32) -> Result<File, FsError> {
    // SAFETY: name is NUL terminated, parent is live (or AT_FDCWD), mode is supplied for O_CREAT.
    let fd = unsafe {
        libc::openat(
            parent,
            n.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(syscall_error());
    }
    // SAFETY: successful openat returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn absolute(path: &Path) -> Result<PathBuf, FsError> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if path
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(FsError::UnsafeStorage);
    }
    Ok(path)
}
fn root_fd() -> Result<File, FsError> {
    open_at(
        libc::AT_FDCWD,
        &name(OsStr::new("/"))?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
}
// Retain open ancestors so native identity cannot be recycled during a comparison.
struct NativePath {
    directories: Vec<File>,
    complete: bool,
}
fn identity(file: &File) -> Result<(u64, u64), FsError> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}
fn inspect_no_symlink(path: &Path) -> Result<NativePath, FsError> {
    let mut native = NativePath {
        directories: vec![root_fd()?],
        complete: true,
    };
    for c in path.components() {
        if let Component::Normal(n) = c {
            let dir = native.directories.last().ok_or(FsError::UnsafeStorage)?;
            match open_at(
                dir.as_raw_fd(),
                &name(n)?,
                libc::O_RDONLY | libc::O_DIRECTORY,
            ) {
                Ok(next) => native.directories.push(next),
                Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    native.complete = false;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(native)
}
fn refuse_native_overlap(storage: &NativePath, content: &NativePath) -> Result<(), FsError> {
    let storage_ids = storage
        .directories
        .iter()
        .map(identity)
        .collect::<Result<Vec<_>, _>>()?;
    let content_ids = content
        .directories
        .iter()
        .map(identity)
        .collect::<Result<Vec<_>, _>>()?;
    let storage_tip = storage_ids.last().ok_or(FsError::UnsafeStorage)?;
    let content_tip = content_ids.last().ok_or(FsError::UnsafeStorage)?;
    // An incomplete path's tip is only its nearest existing ancestor, not the intended root.
    if (storage.complete && content_ids.contains(storage_tip))
        || (content.complete && storage_ids.contains(content_tip))
    {
        return Err(FsError::StorageOverlap);
    }
    Ok(())
}
fn check_content_roots(storage: &NativePath, content_roots: &[PathBuf]) -> Result<(), FsError> {
    for content in content_roots {
        refuse_native_overlap(storage, &inspect_no_symlink(content)?)?;
    }
    Ok(())
}
fn remove_owned_empty_directory(
    parent: &File,
    leaf: &CString,
    owned: &File,
) -> Result<(), FsError> {
    let current = open_at(parent.as_raw_fd(), leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
    if identity(&current)? != identity(owned)? {
        return Err(FsError::UnsafeStorage);
    }
    // SAFETY: live parent/name; remove only the verified owned directory, and only if empty.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(syscall_error());
    }
    parent.sync_all()?;
    Ok(())
}
fn private(file: &File, dir: bool) -> Result<(), FsError> {
    let m = file.metadata()?;
    // SAFETY: geteuid takes no arguments and has no failure mode.
    let uid = unsafe { libc::geteuid() };
    if m.uid() != uid
        || m.permissions().mode() & 0o7777 != if dir { 0o700 } else { 0o600 }
        || (if dir { !m.is_dir() } else { !m.is_file() })
    {
        return Err(FsError::UnsafeStorage);
    }
    Ok(())
}
struct Stage<'a> {
    dir: &'a File,
    name: CString,
    present: bool,
}
impl Stage<'_> {
    fn remove(&mut self) -> Result<(), FsError> {
        if !self.present {
            return Ok(());
        }
        // SAFETY: both name and directory descriptor remain live; unlink only this owned staging name.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(syscall_error());
        }
        self.present = false;
        Ok(())
    }
}
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}
impl ObjectStore {
    pub(crate) fn check_content_path(&self, storage: &Path, content: &Path) -> Result<(), FsError> {
        self.assert_path(storage)?;
        let storage = inspect_no_symlink(&absolute(storage)?)?;
        let content = inspect_no_symlink(&absolute(content)?)?;
        refuse_native_overlap(&storage, &content)
    }
    pub(crate) fn create_owned(
        path: impl AsRef<Path>,
        limits: ObjectLimits,
    ) -> Result<Self, FsError> {
        Self::open_directory(path, limits, true)
    }
    pub fn open(path: impl AsRef<Path>, limits: ObjectLimits) -> Result<Self, FsError> {
        Self::open_directory(path, limits, false)
    }
    fn open_directory(
        path: impl AsRef<Path>,
        limits: ObjectLimits,
        require_new: bool,
    ) -> Result<Self, FsError> {
        if limits.max_chunk_size == 0 || limits.max_chunk_size > MAX_CHUNK {
            return Err(FsError::LimitExceeded);
        }
        let path = absolute(path.as_ref())?;
        if path == Path::new("/") {
            return Err(FsError::UnsafeStorage);
        }
        let content_roots = limits
            .content_roots
            .iter()
            .map(|p| absolute(p))
            .collect::<Result<Vec<_>, _>>()?;
        // Check known ancestry before creating anything, including a missing store below content.
        check_content_roots(&inspect_no_symlink(&path)?, &content_roots)?;
        let mut storage = NativePath {
            directories: vec![root_fd()?],
            complete: true,
        };
        let parts: Vec<_> = path
            .components()
            .filter_map(|c| {
                if let Component::Normal(n) = c {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        for (i, n) in parts.iter().enumerate() {
            let dir = storage.directories.last().ok_or(FsError::UnsafeStorage)?;
            let n = name(n)?;
            if i + 1 == parts.len() {
                // SAFETY: directory and name remain live. mkdirat never follows an existing leaf.
                let made = unsafe { libc::mkdirat(dir.as_raw_fd(), n.as_ptr(), 0o700) } == 0;
                if !made
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(syscall_error());
                }
                if require_new && !made {
                    return Err(FsError::AlreadyExists);
                }
                let child = open_at(dir.as_raw_fd(), &n, libc::O_RDONLY | libc::O_DIRECTORY)?;
                if made {
                    child.set_permissions(std::fs::Permissions::from_mode(0o700))?;
                }
                private(&child, true)?;
                // Resolve selected roots again: creating the leaf can make a formerly missing
                // case/normalization alias resolvable. Check the actual opened store ancestry.
                storage.directories.push(child);
                if let Err(error) = check_content_roots(&storage, &content_roots) {
                    if made {
                        let owned = storage.directories.last().ok_or(FsError::UnsafeStorage)?;
                        let parent = &storage.directories[storage.directories.len() - 2];
                        remove_owned_empty_directory(parent, &n, owned)?;
                    }
                    return Err(error);
                }
                let child = storage.directories.pop().ok_or(FsError::UnsafeStorage)?;
                child.sync_all()?;
                storage
                    .directories
                    .last()
                    .ok_or(FsError::UnsafeStorage)?
                    .sync_all()?;
                return Ok(Self {
                    dir: child,
                    limits,
                    work: ObjectWorkCounters::default(),
                });
            }
            let child = open_at(dir.as_raw_fd(), &n, libc::O_RDONLY | libc::O_DIRECTORY)?;
            storage.directories.push(child);
        }
        Err(FsError::UnsafeStorage)
    }
    fn read_file(
        &self,
        id: &ObjectId,
    ) -> Result<(Vec<u8>, File, crate::capture::Observation), FsError> {
        let mut file = open_at(
            self.dir.as_raw_fd(),
            &name(OsStr::new(id.as_str()))?,
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?;
        private(&file, false)?;
        let before = crate::capture::Observation::metadata(&file.metadata()?);
        let size = before.size;
        if size > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        // Bounded read also catches concurrent growth; no unverified range is returned.
        let mut bytes = Vec::with_capacity(size as usize);
        (&mut file)
            .take(self.limits.max_chunk_size + 1)
            .read_to_end(&mut bytes)?;
        self.work
            .verified_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        if bytes.len() as u64 > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        if crate::capture::Observation::metadata(&file.metadata()?) != before
            || bytes.len() as u64 != size
            || ObjectId::for_bytes(&bytes)? != *id
        {
            return Err(FsError::CorruptObject);
        }
        Ok((bytes, file, before))
    }
    pub fn read_verified(&self, id: &ObjectId) -> Result<Vec<u8>, FsError> {
        Ok(self.read_file(id)?.0)
    }
    pub fn install(&self, bytes: &[u8]) -> Result<ObjectId, FsError> {
        if bytes.len() as u64 > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        let id = ObjectId::for_bytes(bytes)?;
        match self.sync_object(&id) {
            Ok(()) => return Ok(id),
            Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.install_new(bytes, id)
    }
    /// Preparation is private to a Core-locked capture attempt. Existing content
    /// is verified, but this is NOT a durable acknowledgement. Capture must call
    /// sync_objects on the entire final closure before committing its journal.
    pub(crate) fn prepare_capture_chunk(&self, bytes: &[u8]) -> Result<ObjectId, FsError> {
        if bytes.len() as u64 > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        let id = ObjectId::for_bytes(bytes)?;
        match self.read_file(&id) {
            Ok((existing, _, _)) if existing.len() == bytes.len() => Ok(id),
            Ok(_) => Err(FsError::CorruptObject),
            Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                self.install_new(bytes, id)
            }
            Err(e) => Err(e),
        }
    }
    fn install_new(&self, bytes: &[u8], id: ObjectId) -> Result<ObjectId, FsError> {
        let destination = name(OsStr::new(id.as_str()))?;
        let stage_name = name(OsStr::new(&format!(
            ".stage-{}",
            OperationId::random()?.as_str()
        )))?;
        let mut file = open_at(
            self.dir.as_raw_fd(),
            &stage_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )?;
        let mut stage = Stage {
            dir: &self.dir,
            name: stage_name,
            present: true,
        };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        self.work.stages.fetch_add(1, Ordering::Relaxed);
        self.work
            .staged_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        file.write_all(bytes)?;
        crate::faults::hit("object-sync")?;
        self.sync_file(&file)?;
        // Verify the staged bytes through the same open file before publication.
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let mut check = Vec::with_capacity(bytes.len());
        (&mut file)
            .take(self.limits.max_chunk_size + 1)
            .read_to_end(&mut check)?;
        self.work
            .verified_bytes
            .fetch_add(check.len() as u64, Ordering::Relaxed);
        if ObjectId::for_bytes(&check)? != id {
            return Err(FsError::CorruptObject);
        }
        // SAFETY: live directory/name operands; hard linking is an atomic no-replace publication.
        let linked = unsafe {
            libc::linkat(
                self.dir.as_raw_fd(),
                stage.name.as_ptr(),
                self.dir.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        };
        if linked != 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                return Err(syscall_error());
            }
            let (_, existing, _) = self.read_file(&id)?;
            self.sync_file(&existing)?;
        }
        self.sync_directory()?;
        stage.remove()?;
        self.sync_directory()?;
        Ok(id)
    }
}

impl ObjectStore {
    pub(crate) fn directory(&self) -> &File {
        &self.dir
    }
    pub(crate) fn assert_path(&self, path: &Path) -> Result<(), FsError> {
        let native = inspect_no_symlink(&absolute(path)?)?;
        if !native.complete
            || identity(native.directories.last().ok_or(FsError::UnsafeStorage)?)?
                != identity(&self.dir)?
        {
            return Err(FsError::UnsafeStorage);
        }
        Ok(())
    }
    pub(crate) fn control_file(&self, leaf: &str, create: bool) -> Result<File, FsError> {
        let file = open_at(
            self.dir.as_raw_fd(),
            &name(OsStr::new(leaf))?,
            libc::O_RDWR | libc::O_NONBLOCK | if create { libc::O_CREAT } else { 0 },
        )?;
        private(&file, false)?;
        if file.metadata()?.nlink() != 1 {
            return Err(FsError::UnsafeStorage);
        }
        self.sync_file(&file)?;
        self.sync_directory()?;
        Ok(file)
    }
    /// Enumerate published chunks through the opened directory; stages and control files are excluded.
    pub fn inventory(&self) -> Result<Vec<(ObjectId, u64)>, FsError> {
        Ok(self.inventory_detail()?.0)
    }
    pub(crate) fn occupied_bytes(&self) -> Result<u64, FsError> {
        let (objects, staged) = self.inventory_detail()?;
        objects.iter().try_fold(staged, |total, (_, size)| {
            total.checked_add(*size).ok_or(FsError::Backpressure)
        })
    }
    pub(crate) fn inventory_detail(&self) -> Result<(Vec<(ObjectId, u64)>, u64), FsError> {
        self.work.inventories.fetch_add(1, Ordering::Relaxed);
        let directory = open_at(
            self.dir.as_raw_fd(),
            &name(OsStr::new("."))?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        use std::os::fd::IntoRawFd;
        let raw = directory.into_raw_fd();
        // SAFETY: fdopendir takes ownership of a fresh directory descriptor on success.
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe { libc::close(raw) };
            return Err(syscall_error());
        }
        struct Dir(*mut libc::DIR);
        impl Drop for Dir {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let stream = Dir(stream);
        let mut result = Vec::new();
        let mut staged = 0u64;
        loop {
            // SAFETY: stream is live and used only by this call. Clear errno to distinguish EOF.
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(0) {
                    return Err(e.into());
                }
                break;
            }
            let leaf = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if let Ok(id) = ObjectId::parse(leaf.to_string_lossy().into_owned()) {
                let f = open_at(
                    self.dir.as_raw_fd(),
                    leaf,
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )?;
                private(&f, false)?;
                let size = f.metadata()?.len();
                if size > self.limits.max_chunk_size {
                    return Err(FsError::LimitExceeded);
                }
                result.push((id, size));
            } else if leaf.to_bytes().starts_with(b".stage-") {
                let f = open_at(
                    self.dir.as_raw_fd(),
                    leaf,
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )?;
                private(&f, false)?;
                staged = staged
                    .checked_add(f.metadata()?.len())
                    .ok_or(FsError::Backpressure)?;
            }
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok((result, staged))
    }
    pub(crate) fn evict(&self, id: &ObjectId) -> Result<(), FsError> {
        let (_, file, _) = self.read_file(id)?;
        let _ = file;
        // SAFETY: validated object name and live directory; never traverses a pathname.
        if unsafe {
            libc::unlinkat(
                self.dir.as_raw_fd(),
                name(OsStr::new(id.as_str()))?.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(syscall_error());
        }
        self.sync_directory()?;
        Ok(())
    }
    /// Verify and sync a file without the directory barrier. A caller using this
    /// internal batch primitive must finish_object_sync before acknowledging.
    pub(crate) fn sync_object_file(&self, id: &ObjectId) -> Result<(), FsError> {
        private(&self.dir, true)?;
        let (_, file, before) = self.read_file(id)?;
        crate::faults::hit("object-sync")?;
        self.sync_file(&file)?;
        let current = open_at(
            self.dir.as_raw_fd(),
            &name(OsStr::new(id.as_str()))?,
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?;
        private(&current, false)?;
        if crate::capture::Observation::metadata(&file.metadata()?) != before
            || crate::capture::Observation::metadata(&current.metadata()?) != before
        {
            return Err(FsError::CorruptObject);
        }
        Ok(())
    }
    pub(crate) fn finish_object_sync(&self) -> Result<(), FsError> {
        private(&self.dir, true)?;
        self.sync_directory()
    }
    pub(crate) fn sync_objects<'a>(
        &self,
        objects: impl IntoIterator<Item = &'a ObjectId>,
    ) -> Result<(), FsError> {
        for id in objects {
            self.sync_object_file(id)?;
        }
        self.finish_object_sync()
    }
    pub(crate) fn sync_object(&self, id: &ObjectId) -> Result<(), FsError> {
        self.sync_objects(std::iter::once(id))
    }
}
impl ObjectStore {
    /// Open an existing source without creating a missing directory.
    pub fn open_existing(path: impl AsRef<Path>, limits: ObjectLimits) -> Result<Self, FsError> {
        if limits.max_chunk_size == 0 || limits.max_chunk_size > MAX_CHUNK {
            return Err(FsError::LimitExceeded);
        }
        let path = absolute(path.as_ref())?;
        let mut native = inspect_no_symlink(&path)?;
        if !native.complete {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        let roots = limits
            .content_roots
            .iter()
            .map(|p| absolute(p))
            .collect::<Result<Vec<_>, _>>()?;
        check_content_roots(&native, &roots)?;
        let dir = native.directories.pop().ok_or(FsError::UnsafeStorage)?;
        private(&dir, true)?;
        Ok(Self {
            dir,
            limits,
            work: ObjectWorkCounters::default(),
        })
    }
}

#[cfg(test)]
mod owned_directory_tests {
    use super::*;
    #[test]
    fn new_control_staging_never_claims_an_existing_private_directory() {
        let d = tempfile::Builder::new()
            .prefix("fs1-task4-owned-")
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .unwrap();
        let path = d.path().join("stage");
        let original = ObjectStore::open(&path, ObjectLimits::default()).unwrap();
        std::fs::write(path.join("user-file"), b"retain").unwrap();
        assert!(matches!(
            ObjectStore::create_owned(&path, ObjectLimits::default()),
            Err(FsError::AlreadyExists)
        ));
        assert_eq!(std::fs::read(path.join("user-file")).unwrap(), b"retain");
        drop(original);
    }
}
