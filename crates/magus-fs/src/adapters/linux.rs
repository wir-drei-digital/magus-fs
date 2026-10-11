//! Durable Linux FUSE transport. The shared engine is the only byte/namespace authority.
use fuser::*;
use magus_fs_core::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, FsError>;
fn errno(error: FsError) -> Errno {
    Errno::from_i32(match error {
        FsError::ReadOnly => libc::EROFS,
        FsError::PermissionDenied | FsError::UnknownPrincipal => libc::EACCES,
        FsError::NotFound => libc::ENOENT,
        FsError::AlreadyExists => libc::EEXIST,
        FsError::NotDirectory => libc::ENOTDIR,
        FsError::IsDirectory => libc::EISDIR,
        FsError::NotEmpty => libc::ENOTEMPTY,
        FsError::StaleHandle => libc::ESTALE,
        FsError::LimitExceeded => libc::EFBIG,
        FsError::Backpressure => libc::ENOSPC,
        FsError::UnsupportedMode => libc::EOPNOTSUPP,
        FsError::InvalidPath | FsError::InvalidTree => libc::EINVAL,
        FsError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
        _ => libc::EIO,
    })
}
#[cfg(feature = "test-faults")]
fn lookup_epoch_barrier(name: &OsStr, ino: INodeNo) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if std::env::var("MAGUS_TEST_LOOKUP_EPOCH_NAME")
        .ok()
        .as_deref()
        != name.to_str()
    {
        return;
    }
    let Ok(base) = std::env::var("MAGUS_TEST_LOOKUP_EPOCH_BARRIER") else {
        return;
    };
    if !Path::new(&format!("{base}.arm")).exists() {
        return;
    }
    let Ok(mut marker) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(format!("{base}.hit"))
    else {
        return;
    };
    let _ = write!(marker, "{}", ino.0);
    let _ = marker.sync_all();
    eprintln!("test_lookup_epoch_barrier inode={}", ino.0);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !Path::new(&format!("{base}.release")).exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn unsupported<T>() -> Result<T> {
    Err(FsError::UnsupportedMode)
}
#[derive(Clone)]
struct OpenFile {
    uid: u32,
    workspace: Workspace,
    handle: Handle,
    access: i32,
}
struct State {
    config: ReplicaConfig,
    workspaces: BTreeMap<u32, Workspace>,
    inodes: Vec<(EntryId, u64)>,
    epoch: u64,
    directories: BTreeSet<EntryId>,
    handles: BTreeMap<u64, OpenFile>,
    next_handle: u64,
}
impl State {
    fn ws(&self, req: &Request) -> Result<Workspace> {
        self.workspaces
            .get(&req.uid())
            .cloned()
            .ok_or(FsError::PermissionDenied)
    }
    fn identity(&self, ino: INodeNo) -> Result<&EntryId> {
        ino.0
            .checked_sub(1)
            .and_then(|n| self.inodes.get(n as usize))
            .map(|v| &v.0)
            .ok_or(FsError::StaleHandle)
    }
    fn inode(&mut self, id: &EntryId) -> INodeNo {
        if let Some(i) = self
            .inodes
            .iter()
            .position(|v| &v.0 == id && (v.1 == self.epoch || self.directories.contains(id)))
        {
            INodeNo(i as u64 + 1)
        } else {
            self.inodes.push((id.clone(), self.epoch));
            INodeNo(self.inodes.len() as u64)
        }
    }
    fn stale_inode(&self, ino: INodeNo) -> Result<bool> {
        let id = self.identity(ino)?;
        Ok(!self.directories.contains(id) && self.inodes[(ino.0 - 1) as usize].1 != self.epoch)
    }
    fn entry(&self, req: &Request, ino: INodeNo) -> Result<Entry> {
        let id = self.identity(ino)?;
        if self.stale_inode(ino)? {
            return Err(FsError::NotFound);
        }
        self.ws(req)?.lookup_identity(id)
    }
    fn child(&self, req: &Request, parent: INodeNo, name: &OsStr) -> Result<String> {
        let entry = self.entry(req, parent)?;
        if entry.content != EntryContent::Directory {
            return Err(FsError::NotDirectory);
        }
        let name = name.to_str().ok_or(FsError::InvalidPath)?;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(FsError::InvalidPath);
        }
        Ok(if entry.path.is_empty() {
            name.into()
        } else {
            format!("{}/{name}", entry.path)
        })
    }
    fn attr(&mut self, req: &Request, e: &Entry) -> Result<FileAttr> {
        let e = self.ws(req)?.native_attributes(e)?;
        if e.content == EntryContent::Directory {
            self.directories.insert(e.id.clone());
        }
        let uid = self
            .config
            .authorities
            .iter()
            .find(|a| a.principal == e.owner)
            .ok_or(FsError::MappingBlocked)?
            .uid;
        let gid = self
            .config
            .authorities
            .iter()
            .find(|a| a.primary_group == e.group)
            .ok_or(FsError::MappingBlocked)?
            .gid;
        let (size, kind) = match &e.content {
            EntryContent::Directory => (0, FileType::Directory),
            EntryContent::File { version } => (version.size, FileType::RegularFile),
        };
        Ok(FileAttr {
            ino: self.inode(&e.id),
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm: e.mode,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        })
    }
    fn held(&self, req: &Request, fh: FileHandle) -> Result<&OpenFile> {
        let file = self.handles.get(&fh.0).ok_or(FsError::StaleHandle)?;
        if file.uid != req.uid() {
            return Err(FsError::PermissionDenied);
        }
        Ok(file)
    }
    fn metadata_target(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: Option<FileHandle>,
    ) -> Result<(Entry, Option<OpenFile>)> {
        let file = if let Some(fh) = fh {
            self.held(req, fh)?
        } else {
            match self.entry(req, ino) {
                Ok(entry) => return Ok((entry, None)),
                Err(FsError::NotFound) => {
                    // Linux may omit fh for fstat/fchmod/fchown after unlink or replacement.
                    // Only a same-UID capability for this exact inode may supply the identity.
                    let id = self.identity(ino)?;
                    match self.handles.values().find(|file| {
                        file.uid == req.uid()
                            && file.handle.entry_id() == id
                            && file.handle.epoch() == self.inodes[(ino.0 - 1) as usize].1
                    }) {
                        Some(file) => file,
                        // Path getattr can straddle adoption too. Ask VFS to revalidate,
                        // while existing exact inode capabilities retain their epoch metadata.
                        None if self.stale_inode(ino)? => return Err(FsError::StaleHandle),
                        None => return Err(FsError::NotFound),
                    }
                }
                Err(error) => return Err(error),
            }
        };
        Ok((
            file.workspace.handle_attributes(&file.handle)?,
            Some(file.clone()),
        ))
    }
    fn reserve_handle(&mut self) -> Result<FileHandle> {
        let fh = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        Ok(FileHandle(fh))
    }
    fn register(
        &mut self,
        fh: FileHandle,
        req: &Request,
        workspace: Workspace,
        handle: Handle,
        flags: i32,
    ) {
        self.handles.insert(
            fh.0,
            OpenFile {
                uid: req.uid(),
                workspace,
                handle,
                access: flags & libc::O_ACCMODE,
            },
        );
    }
    fn open(&mut self, req: &Request, path: &str, flags: i32) -> Result<FileHandle> {
        let workspace = self.ws(req)?;
        let mode = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => OpenMode::Read,
            libc::O_WRONLY => OpenMode::Write,
            libc::O_RDWR => OpenMode::ReadWrite,
            _ => return Err(FsError::InvalidPath),
        };
        let fh = self.reserve_handle()?;
        let handle = workspace.open(path, mode)?;
        if flags & libc::O_TRUNC != 0 {
            workspace.truncate(&handle, 0)?;
        }
        self.register(fh, req, workspace, handle, flags);
        Ok(fh)
    }
}
struct Adapter {
    state: Arc<Mutex<State>>,
    read_only: bool,
}
impl Adapter {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> std::result::Result<T, Errno> {
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        f(&mut state).map_err(errno)
    }
    fn mutate<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> std::result::Result<T, Errno> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        self.with(f)
    }
    fn mutation_error(&self) -> Errno {
        if self.read_only {
            Errno::EROFS
        } else {
            Errno::EOPNOTSUPP
        }
    }
}
fn empty(reply: ReplyEmpty, result: std::result::Result<(), Errno>) {
    match result {
        Ok(()) => reply.ok(),
        Err(e) => reply.error(e),
    }
}
#[allow(clippy::too_many_arguments)]
impl Filesystem for Adapter {
    fn init(&mut self, _: &Request, cfg: &mut KernelConfig) -> std::io::Result<()> {
        // Direct I/O avoids stale page-cache authority and unintended source readahead.
        let _ = cfg.set_max_readahead(0);
        cfg.add_capabilities(InitFlags::FUSE_POSIX_LOCKS)
            .map_err(|_| std::io::Error::other("POSIX lock refusal cannot be negotiated"))?;
        Ok(())
    }
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.with(|s| {
            let path = s.child(req, parent, name)?;
            let e = s.ws(req)?.lookup(&path)?;
            s.attr(req, &e)
        }) {
            Ok(a) => {
                #[cfg(feature = "test-faults")]
                lookup_epoch_barrier(name, a.ino);
                reply.entry(&Duration::ZERO, &a, Generation(1))
            }
            Err(e) => reply.error(e),
        }
    }
    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.with(|s| {
            let (e, _) = s.metadata_target(req, ino, fh)?;
            let mut attr = s.attr(req, &e)?;
            attr.ino = ino;
            Ok(attr)
        }) {
            Ok(a) => reply.attr(&Duration::ZERO, &a),
            Err(e) => reply.error(e),
        }
    }
    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        match self.with(|s| {
            // LOOKUP and OPEN are separate kernel requests. An adopted file epoch
            // invalidates this inode, not the stable pathname. ESTALE lets VFS
            // repeat lookup; never bind a new handle to an old inode's epoch.
            if s.stale_inode(ino)? {
                return Err(FsError::StaleHandle);
            }
            let e = s.entry(req, ino)?;
            s.open(req, &e.path, flags.0)
        }) {
            Ok(h) => reply.opened(h, FopenFlags::FOPEN_DIRECT_IO),
            Err(e) => reply.error(e),
        }
    }
    fn read(
        &self,
        req: &Request,
        _: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.with(|s| {
            let f = s.held(req, fh)?;
            if f.access == libc::O_WRONLY {
                return Err(FsError::PermissionDenied);
            }
            f.workspace.read(&f.handle, offset, size as usize)
        }) {
            Ok(b) => reply.data(&b),
            Err(e) => reply.error(e),
        }
    }
    fn write(
        &self,
        req: &Request,
        _: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _: WriteFlags,
        flags: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.mutate(|s| {
            let f = s.held(req, fh)?;
            if f.access == libc::O_RDONLY {
                return Err(FsError::PermissionDenied);
            }
            f.workspace
                .write_with_append(&f.handle, offset, data, flags.0 & libc::O_APPEND != 0)
        }) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(e),
        }
    }
    fn flush(&self, req: &Request, _: INodeNo, fh: FileHandle, _: LockOwner, reply: ReplyEmpty) {
        empty(reply, self.with(|s| s.held(req, fh)?.workspace.fsync()))
    }
    fn fsync(&self, req: &Request, _: INodeNo, fh: FileHandle, _: bool, reply: ReplyEmpty) {
        empty(reply, self.with(|s| s.held(req, fh)?.workspace.fsync()))
    }
    fn release(
        &self,
        _: &Request,
        _: INodeNo,
        fh: FileHandle,
        _: OpenFlags,
        _: Option<LockOwner>,
        _: bool,
        reply: ReplyEmpty,
    ) {
        empty(
            reply,
            self.with(|s| {
                s.handles.remove(&fh.0).ok_or(FsError::StaleHandle)?;
                Ok(())
            }),
        )
    }
    fn opendir(&self, req: &Request, ino: INodeNo, _: OpenFlags, reply: ReplyOpen) {
        match self.with(|s| {
            let e = s.entry(req, ino)?;
            s.ws(req)?.list(&e.path)?;
            Ok(())
        }) {
            Ok(()) => reply.opened(FileHandle(0), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }
    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let result = self.with(|s| {
            let entry = s.entry(req, ino)?;
            let children = s.ws(req)?.directory_entries(&entry.path)?;
            let parent = s.inode(&entry.parent);
            let mut rows = vec![
                (ino, FileType::Directory, ".".to_string()),
                (parent, FileType::Directory, "..".to_string()),
            ];
            for (name, id, directory) in children {
                rows.push((
                    s.inode(&id),
                    if directory {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    },
                    name,
                ))
            }
            Ok(rows)
        });
        match result {
            Ok(rows) => {
                for (i, (ino, kind, name)) in rows.into_iter().enumerate().skip(offset as usize) {
                    if reply.add(ino, i as u64 + 1, kind, name) {
                        break;
                    }
                }
                reply.ok()
            }
            Err(e) => reply.error(e),
        }
    }
    fn fsyncdir(&self, req: &Request, _: INodeNo, _: FileHandle, _: bool, reply: ReplyEmpty) {
        empty(reply, self.with(|s| s.ws(req)?.fsync()))
    }
    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self.mutate(|s| {
            let p = s.child(req, parent, name)?;
            let w = s.ws(req)?;
            if !matches!(
                flags & libc::O_ACCMODE,
                libc::O_RDONLY | libc::O_WRONLY | libc::O_RDWR
            ) {
                return Err(FsError::InvalidPath);
            }
            let fh = s.reserve_handle()?;
            let h = w.create(&p, (mode & 0o7777) as u16)?;
            let e = w.handle_attributes(&h)?;
            let a = s.attr(req, &e)?;
            // Creation already established this capability under the engine lock.
            // Reopening its pathname would fail for restrictive initial modes.
            s.register(fh, req, w, h, flags);
            Ok((a, fh))
        }) {
            Ok((a, h)) => reply.created(
                &Duration::ZERO,
                &a,
                Generation(1),
                h,
                FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(e) => reply.error(e),
        }
    }
    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _: u32,
        reply: ReplyEntry,
    ) {
        match self.mutate(|s| {
            let p = s.child(req, parent, name)?;
            let w = s.ws(req)?;
            w.mkdir(&p, (mode & 0o7777) as u16)?;
            s.attr(req, &w.lookup(&p)?)
        }) {
            Ok(a) => reply.entry(&Duration::ZERO, &a, Generation(1)),
            Err(e) => reply.error(e),
        }
    }
    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        empty(
            reply,
            self.mutate(|s| {
                let p = s.child(req, parent, name)?;
                let w = s.ws(req)?;
                if w.lookup(&p)?.content == EntryContent::Directory {
                    return Err(FsError::IsDirectory);
                }
                w.unlink(&p)
            }),
        )
    }
    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        empty(
            reply,
            self.mutate(|s| {
                let p = s.child(req, parent, name)?;
                let w = s.ws(req)?;
                if w.lookup(&p)?.content != EntryContent::Directory {
                    return Err(FsError::NotDirectory);
                }
                w.unlink(&p)
            }),
        )
    }
    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        empty(
            reply,
            self.mutate(|s| {
                if !flags.is_empty() {
                    return unsupported();
                }
                let from = s.child(req, parent, name)?;
                let to = s.child(req, newparent, newname)?;
                s.ws(req)?.rename(&from, &to)
            }),
        )
    }
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _: Option<SystemTime>,
        fh: Option<FileHandle>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = self.mutate(|s| {
            // V1 has no portable timestamp/special-mode contract. Refuse combined mutations
            // rather than returning failure after a partially acknowledged transaction.
            if atime.is_some()
                || mtime.is_some()
                || flags.is_some()
                || usize::from(mode.is_some())
                    + usize::from(uid.is_some() || gid.is_some())
                    + usize::from(size.is_some())
                    > 1
            {
                return unsupported();
            }
            let w = s.ws(req)?;
            let (entry, file) = s.metadata_target(req, ino, fh)?;
            if let Some(size) = size {
                if let Some(file) = &file {
                    if file.access == libc::O_RDONLY {
                        return Err(FsError::PermissionDenied);
                    }
                    file.workspace.truncate(&file.handle, size)?;
                } else {
                    let h = w.open(&entry.path, OpenMode::Write)?;
                    w.truncate(&h, size)?;
                }
            } else if let Some(mode) = mode {
                if let Some(file) = &file {
                    file.workspace
                        .chmod_handle(&file.handle, (mode & 0o7777) as u16)?;
                } else {
                    w.chmod(&entry.path, (mode & 0o7777) as u16)?;
                }
            } else if uid.is_some() || gid.is_some() {
                let owner = if let Some(uid) = uid {
                    s.config
                        .authorities
                        .iter()
                        .find(|a| a.uid == uid)
                        .ok_or(FsError::MappingBlocked)?
                        .principal
                        .clone()
                } else {
                    entry.owner
                };
                let group = if let Some(gid) = gid {
                    s.config
                        .authorities
                        .iter()
                        .find(|a| a.gid == gid)
                        .ok_or(FsError::MappingBlocked)?
                        .primary_group
                        .clone()
                } else {
                    entry.group
                };
                if let Some(file) = &file {
                    file.workspace.chown_handle(&file.handle, owner, group)?;
                } else {
                    w.chown(&entry.path, owner, group)?;
                }
            }
            let changed = if let Some(file) = file {
                file.workspace.handle_attributes(&file.handle)?
            } else {
                s.entry(req, ino)?
            };
            s.attr(req, &changed)
        });
        match result {
            Ok(a) => reply.attr(&Duration::ZERO, &a),
            Err(e) => reply.error(e),
        }
    }
    fn symlink(&self, _: &Request, _: INodeNo, _: &OsStr, _: &Path, reply: ReplyEntry) {
        reply.error(self.mutation_error())
    }
    fn link(&self, _: &Request, _: INodeNo, _: INodeNo, _: &OsStr, reply: ReplyEntry) {
        reply.error(self.mutation_error())
    }
    fn mknod(&self, _: &Request, _: INodeNo, _: &OsStr, _: u32, _: u32, _: u32, reply: ReplyEntry) {
        reply.error(self.mutation_error())
    }
    fn setxattr(
        &self,
        _: &Request,
        _: INodeNo,
        _: &OsStr,
        _: &[u8],
        _: i32,
        _: u32,
        reply: ReplyEmpty,
    ) {
        reply.error(self.mutation_error())
    }
    fn removexattr(&self, _: &Request, _: INodeNo, _: &OsStr, reply: ReplyEmpty) {
        reply.error(self.mutation_error())
    }
    fn getxattr(&self, _: &Request, _: INodeNo, _: &OsStr, _: u32, reply: ReplyXattr) {
        reply.error(Errno::EOPNOTSUPP)
    }
    fn listxattr(&self, _: &Request, _: INodeNo, _: u32, reply: ReplyXattr) {
        reply.error(Errno::EOPNOTSUPP)
    }
    fn getlk(
        &self,
        _: &Request,
        _: INodeNo,
        _: FileHandle,
        _: LockOwner,
        _: u64,
        _: u64,
        _: i32,
        _: u32,
        reply: ReplyLock,
    ) {
        reply.error(Errno::EOPNOTSUPP)
    }
    fn setlk(
        &self,
        _: &Request,
        _: INodeNo,
        _: FileHandle,
        _: LockOwner,
        _: u64,
        _: u64,
        _: i32,
        _: u32,
        _: bool,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EOPNOTSUPP)
    }
}
pub fn mount(
    rep: Replica,
    state: &Path,
    revision: &RevisionId,
    mountpoint: &Path,
    read_only: bool,
) -> Result<()> {
    let config = rep.configuration()?;
    if !mountpoint.is_absolute() || !config.content_roots.contains(&mountpoint.to_path_buf()) {
        return Err(FsError::ConfigMismatch);
    }
    rep.check_content_path(mountpoint)?;
    let mut workspaces = BTreeMap::new();
    for a in &config.authorities {
        workspaces.insert(
            a.uid,
            if rep.sync_status()?.binding.is_some() {
                rep.begin_live(revision, rep.actor_for_uid(a.uid)?, read_only)?
            } else {
                rep.begin(revision, rep.actor_for_uid(a.uid)?, read_only)?
            },
        );
    }
    let root = rep.revision(revision)?.tree.root.id;
    let adapter = Adapter {
        state: Arc::new(Mutex::new(State {
            config,
            workspaces,
            directories: BTreeSet::from([root.clone()]),
            inodes: vec![(root, 0)],
            epoch: rep.live_status().map(|v| v.epoch).unwrap_or(0),
            handles: BTreeMap::new(),
            next_handle: 1,
        })),
        read_only,
    };
    let _control = super::control::Server::start(rep.clone(), state, read_only)?;
    std::fs::create_dir(mountpoint)?;
    rep.check_content_path(mountpoint)?;
    let mut cfg = Config::default();
    cfg.acl = SessionACL::All;
    cfg.mount_options = vec![
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoDev,
        MountOption::FSName("magus-fs1".into()),
        if read_only {
            MountOption::RO
        } else {
            MountOption::RW
        },
    ];
    let live_state = adapter.state.clone();
    let session = fuser::Session::new(adapter, mountpoint, &cfg)?;
    let notifier = session.notifier();
    let stop = Arc::new(AtomicBool::new(false));
    let binding = rep.sync_status()?.binding;
    let shared_live = binding
        .as_ref()
        .is_some_and(|b| b.publication == PublicationMode::SharedLive);
    // Capture and publication use separate bounded schedulers: slow HTTP must not
    // turn every ordinary filesystem save into a scan or block the adapter lock.
    let outgoing = if binding.is_some() && !read_only {
        let actor =
            crate::sync::publication_actor(&rep, rep.actor_for_uid(unsafe { libc::geteuid() })?)?;
        let workspace = rep.begin_live(revision, actor, false)?;
        let mut capture = crate::sync::mounted::MountedCapture::new(&rep)?;
        let publisher = crate::sync::SyncController::new(&rep)?;
        let capture_stop = stop.clone();
        let capture_state = live_state.clone();
        let capture_thread = std::thread::spawn(move || {
            while !capture_stop.load(Ordering::Relaxed) {
                match capture.tick(|operation, generation| {
                    let _state = capture_state.lock().map_err(|_| FsError::ReplicaBusy)?;
                    workspace.checkpoint(
                        operation,
                        generation,
                        Attribution {
                            captured_at_ns: 0,
                            coverage: vec!["".into()],
                            provenance: "engine_observed".into(),
                        },
                    )
                }) {
                    Ok(Some(revision)) => {
                        eprintln!("mounted_captured revision={}", revision.as_str())
                    }
                    Ok(None) => {}
                    Err(error) => eprintln!("mounted_capture_error code={}", error.code()),
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let publish_stop = stop.clone();
        let publish_thread = std::thread::spawn(move || {
            while !publish_stop.load(Ordering::Relaxed) {
                if let Err(error) = publisher.tick() {
                    if !matches!(error, FsError::NotFound) {
                        eprintln!("mounted_publication_error code={}", error.code());
                    }
                }
                for _ in 0..10 {
                    if publish_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        Some((capture_thread, publish_thread))
    } else {
        None
    };
    let incoming = if binding.is_some() {
        let stop = stop.clone();
        let rep = rep.clone();
        let mountpoint = mountpoint.to_path_buf();
        Some(std::thread::spawn(move || {
            let hints = crate::sync::subscribe(rep.clone(), stop.clone());
            let mut incoming = match crate::sync::Incoming::new(&rep) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut pending = rep
                .live_status()
                .ok()
                .filter(|_| shared_live)
                .and_then(|status| {
                    rep.revision(&status.revision).ok().map(|r| Adoption {
                        revision: status.revision,
                        epoch: status.epoch,
                        entries: r.tree.entries,
                    })
                });
            while !stop.load(Ordering::Relaxed) {
                let result = incoming.poll(|binding, generation| {
                    let mut state = live_state.lock().map_err(|_| FsError::ReplicaBusy)?;
                    let actor = Actor::new(state.config.authorities[0].principal.clone());
                    let adoption = rep.adopt_remote_view(binding, generation, actor)?;
                    state.epoch = adoption.epoch;
                    Ok(adoption)
                });
                match result {
                    Ok(Some(adoption)) => pending = Some(adoption),
                    Ok(None) => {}
                    Err(error) => eprintln!("live_discovery_error code={}", error.code()),
                }
                if let Some(adoption) = &pending {
                    let started = std::time::Instant::now();
                    let result = (|| -> Result<()> {
                        // Do not hold state while notifying: the kernel may issue callbacks.
                        let inodes = live_state
                            .lock()
                            .map_err(|_| FsError::ReplicaBusy)?
                            .inodes
                            .clone();
                        for (i, _) in inodes.iter().enumerate() {
                            notifier.inval_inode(INodeNo(i as u64 + 1), 0, 0)?;
                        }
                        for entry in &adoption.entries {
                            if entry.path.is_empty() {
                                continue;
                            }
                            for (i, (id, _)) in inodes
                                .iter()
                                .enumerate()
                                .filter(|(_, v)| v.0 == entry.parent)
                            {
                                let _ = id;
                                notifier.inval_entry(
                                    INodeNo(i as u64 + 1),
                                    OsStr::new(entry.path.rsplit('/').next().unwrap()),
                                )?;
                            }
                        }
                        let current = rep.revision(&adoption.revision)?;
                        // An ordinary kernel path walk verifies post-invalidation names and attrs.
                        for e in &current.tree.entries {
                            let observed = std::fs::metadata(mountpoint.join(&e.path))?;
                            match &e.content {
                                EntryContent::File { version }
                                    if observed.is_file() && observed.len() == version.size => {}
                                EntryContent::Directory if observed.is_dir() => {}
                                _ => return Err(FsError::StaleHandle),
                            }
                        }
                        for e in &adoption.entries {
                            if !e.path.is_empty()
                                && !current.tree.entries.iter().any(|v| v.path == e.path)
                                && mountpoint.join(&e.path).try_exists()?
                            {
                                return Err(FsError::StaleHandle);
                            }
                        }
                        rep.acknowledge_adoption(&adoption.revision, adoption.epoch)
                    })();
                    if let Err(error) = &result {
                        let _ = rep.record_incoming_acknowledgement(Some(error));
                        eprintln!("live_acknowledgement_error code={}", error.code());
                    }
                    if result.is_ok() {
                        let _ = rep.record_incoming_acknowledgement(None);
                        eprintln!(
                            "live_applied epoch={} revision={} invalidation_us={}",
                            adoption.epoch,
                            adoption.revision.as_str(),
                            started.elapsed().as_micros()
                        );
                        pending = None;
                    }
                }
                for _ in 0..10 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            let _ = hints.join();
        }))
    } else {
        None
    };
    let result = session.run();
    stop.store(true, Ordering::Relaxed);
    if let Some((capture, publish)) = outgoing {
        let _ = capture.join();
        let _ = publish.join();
    }
    if let Some(thread) = incoming {
        let _ = thread.join();
    }
    result?;
    // Leave the empty mountpoint for its owner. Never remove a pathname after daemon loss.
    Ok(())
}
