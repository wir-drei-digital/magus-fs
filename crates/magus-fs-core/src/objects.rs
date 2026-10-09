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
}

fn name(value: &OsStr) -> Result<CString, FsError> {
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
fn open_at(parent: RawFd, n: &CString, flags: i32) -> Result<File, FsError> {
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
    pub fn open(path: impl AsRef<Path>, limits: ObjectLimits) -> Result<Self, FsError> {
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
                return Ok(Self { dir: child, limits });
            }
            let child = open_at(dir.as_raw_fd(), &n, libc::O_RDONLY | libc::O_DIRECTORY)?;
            storage.directories.push(child);
        }
        Err(FsError::UnsafeStorage)
    }
    fn read_file(&self, id: &ObjectId) -> Result<(Vec<u8>, File), FsError> {
        let mut file = open_at(
            self.dir.as_raw_fd(),
            &name(OsStr::new(id.as_str()))?,
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?;
        private(&file, false)?;
        let size = file.metadata()?.len();
        if size > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        // Bounded read also catches concurrent growth; no unverified range is returned.
        let mut bytes = Vec::with_capacity(size as usize);
        (&mut file)
            .take(self.limits.max_chunk_size + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        if ObjectId::for_bytes(&bytes)? != *id {
            return Err(FsError::CorruptObject);
        }
        Ok((bytes, file))
    }
    pub fn read_verified(&self, id: &ObjectId) -> Result<Vec<u8>, FsError> {
        Ok(self.read_file(id)?.0)
    }
    pub fn install(&self, bytes: &[u8]) -> Result<ObjectId, FsError> {
        if bytes.len() as u64 > self.limits.max_chunk_size {
            return Err(FsError::LimitExceeded);
        }
        let id = ObjectId::for_bytes(bytes)?;
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
        file.write_all(bytes)?;
        file.sync_all()?;
        // Verify the staged bytes through the same open file before publication.
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let mut check = Vec::with_capacity(bytes.len());
        (&mut file)
            .take(self.limits.max_chunk_size + 1)
            .read_to_end(&mut check)?;
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
            let (_, existing) = self.read_file(&id)?;
            existing.sync_all()?;
        }
        self.dir.sync_all()?;
        stage.remove()?;
        self.dir.sync_all()?;
        Ok(id)
    }
}
