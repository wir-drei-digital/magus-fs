//! Linux FS0: an immutable manifest namespace and bounded, ephemeral private bytes.
//! Kernel DAC is supplemented by daemon checks. A view capability never follows UID 0.
use crate::{Entry, Probe, Result};
use fuser::*;
use std::{
    ffi::OsStr,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type IoResult<T> = std::result::Result<T, i32>;
struct State {
    probe: Probe,
    sizes: Vec<u64>,
}
pub struct FuseAdapter {
    entries: Vec<Entry>,
    state: Mutex<State>,
    writable: bool,
    digest: String,
}
impl FuseAdapter {
    pub fn connect(url: &str, writable: bool, expected: Option<&str>) -> Result<Self> {
        let probe = Probe::connect(url, writable)?;
        if expected.is_some_and(|x| x != probe.manifest_identity()) {
            return Err("expected manifest digest mismatch".into());
        }
        let mut entries = vec![Entry {
            path: String::new(),
            size: 0,
            mode: 0o755,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            directory: true,
            chunks: vec![],
        }];
        entries.extend(probe.manifest().entries.clone());
        // Every non-root entry must have a manifest directory parent.
        for e in entries.iter().skip(1) {
            let parent = Path::new(&e.path).parent().ok_or("entry parent missing")?;
            if !entries
                .iter()
                .any(|p| p.directory && Path::new(&p.path) == parent)
            {
                return Err("manifest parent directory missing".into());
            }
        }
        let sizes = entries.iter().map(|e| e.size).collect();
        Ok(Self {
            digest: probe.manifest_identity().to_owned(),
            entries,
            state: Mutex::new(State { probe, sizes }),
            writable,
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    fn entry(&self, ino: u64) -> IoResult<&Entry> {
        ino.checked_sub(1)
            .and_then(|n| self.entries.get(n as usize))
            .ok_or(libc::ESTALE)
    }
    fn allowed(e: &Entry, uid: u32, gid: u32, bits: u32) -> bool {
        if uid == 0 {
            return bits & 1 == 0 || e.directory || e.mode & 0o111 != 0;
        }
        let shift = if uid == e.uid {
            6
        } else if gid == e.gid {
            3
        } else {
            0
        };
        (e.mode >> shift) & bits == bits
    }
    fn authorize(&self, e: &Entry, uid: u32, gid: u32, bits: u32) -> IoResult<()> {
        let mut parent = Path::new(&e.path).parent();
        while let Some(path) = parent {
            let p = self
                .entries
                .iter()
                .find(|p| Path::new(&p.path) == path)
                .ok_or(libc::ENOENT)?;
            if !Self::allowed(p, uid, gid, 1) {
                return Err(libc::EACCES);
            }
            parent = path.parent();
        }
        if Self::allowed(e, uid, gid, bits) {
            Ok(())
        } else {
            Err(libc::EACCES)
        }
    }
    pub fn read_as(
        &self,
        ino: u64,
        uid: u32,
        gid: u32,
        offset: u64,
        size: usize,
    ) -> IoResult<Vec<u8>> {
        let e = self.entry(ino)?;
        if e.directory {
            return Err(libc::EISDIR);
        }
        self.authorize(e, uid, gid, 4)?;
        self.state
            .lock()
            .map_err(|_| libc::EIO)?
            .probe
            .read(&e.path, offset, size.min(1024 * 1024))
            .map_err(|_| libc::EIO)
    }
    pub fn write_as(
        &self,
        ino: u64,
        uid: u32,
        gid: u32,
        offset: u64,
        data: &[u8],
    ) -> IoResult<usize> {
        if !self.writable {
            return Err(libc::EROFS);
        }
        let e = self.entry(ino)?;
        if e.directory {
            return Err(libc::EISDIR);
        }
        self.authorize(e, uid, gid, 2)?;
        if e.mode & 0o222 == 0 {
            return Err(libc::EACCES);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(libc::EFBIG)?;
        if end > 67108864 {
            return Err(libc::EFBIG);
        }
        let mut state = self.state.lock().map_err(|_| libc::EIO)?;
        let size = state
            .probe
            .write(&e.path, offset, data)
            .map_err(|_| libc::EIO)?;
        if size != 0 {
            state.sizes[ino as usize - 1] = state.sizes[ino as usize - 1].max(end);
        }
        Ok(size)
    }
    fn attr(&self, ino: u64) -> IoResult<FileAttr> {
        let e = self.entry(ino)?;
        let size = self.state.lock().map_err(|_| libc::EIO)?.sizes[ino as usize - 1];
        Ok(FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: if e.directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: e.mode as u16,
            nlink: if e.directory { 2 } else { 1 },
            uid: e.uid,
            gid: e.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        })
    }
    fn mutation_error(&self) -> Errno {
        if self.writable {
            Errno::EOPNOTSUPP
        } else {
            Errno::EROFS
        }
    }
    pub fn config(writable: bool) -> Config {
        let mut cfg = Config::default();
        cfg.acl = SessionACL::All;
        cfg.mount_options = vec![
            MountOption::DefaultPermissions,
            MountOption::NoSuid,
            MountOption::NoDev,
            MountOption::FSName("magus-fs0".into()),
            if writable {
                MountOption::RW
            } else {
                MountOption::RO
            },
        ];
        cfg
    }
}
#[allow(clippy::too_many_arguments)]
impl Filesystem for FuseAdapter {
    fn init(&mut self, _: &Request, cfg: &mut KernelConfig) -> std::io::Result<()> {
        // A kernel may advertise a smaller ceiling (or zero readahead).
        if let Err(maximum) = cfg.set_max_readahead(262144) {
            if maximum != 0 {
                cfg.set_max_readahead(maximum)
                    .map_err(|_| std::io::Error::other("kernel readahead negotiation failed"))?;
            }
        }
        Ok(())
    }
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let found = (|| {
            let p = self.entry(parent.0)?;
            if !p.directory {
                return Err(libc::ENOTDIR);
            }
            self.authorize(p, req.uid(), req.gid(), 1)?;
            let name = name.to_str().ok_or(libc::EINVAL)?;
            if name.is_empty() || name.contains('/') || name.contains('\0') {
                return Err(libc::EINVAL);
            }
            let path = if name == "." {
                p.path.clone()
            } else if name == ".." {
                Path::new(&p.path)
                    .parent()
                    .unwrap_or(Path::new(""))
                    .to_string_lossy()
                    .into_owned()
            } else if p.path.is_empty() {
                name.to_owned()
            } else {
                format!("{}/{name}", p.path)
            };
            let ino = self
                .entries
                .iter()
                .position(|e| e.path == path)
                .ok_or(libc::ENOENT)? as u64
                + 1;
            self.attr(ino)
        })();
        match found {
            Ok(a) => reply.entry(&Duration::ZERO, &a, Generation(1)),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }
    fn getattr(&self, _: &Request, ino: INodeNo, _: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr(ino.0) {
            Ok(a) => reply.attr(&Duration::ZERO, &a),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }
    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let checked = (|| {
            let e = self.entry(ino.0)?;
            if e.directory {
                return Err(libc::EISDIR);
            }
            let bits = match flags.acc_mode() {
                OpenAccMode::O_RDONLY => 4,
                OpenAccMode::O_WRONLY => 2,
                OpenAccMode::O_RDWR => 6,
            };
            if bits & 2 != 0 && !self.writable {
                return Err(libc::EROFS);
            }
            self.authorize(e, req.uid(), req.gid(), bits)
        })();
        match checked {
            Ok(()) => reply.opened(FileHandle(ino.0), FopenFlags::empty()),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }
    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        _: FileHandle,
        offset: u64,
        size: u32,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.read_as(ino.0, req.uid(), req.gid(), offset, size as usize) {
            Ok(b) => reply.data(&b),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }
    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        _: FileHandle,
        offset: u64,
        data: &[u8],
        _: WriteFlags,
        flags: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if flags.0 & (libc::O_SYNC | libc::O_DSYNC) != 0 {
            reply.error(if self.writable {
                Errno::EOPNOTSUPP
            } else {
                Errno::EROFS
            });
            return;
        }
        match self.write_as(ino.0, req.uid(), req.gid(), offset, data) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(Errno::from_i32(e)),
        }
    }
    // FUSE close flush is not a durability request. fsync/fdatasync are explicitly unsupported.
    fn flush(&self, _: &Request, _: INodeNo, _: FileHandle, _: LockOwner, reply: ReplyEmpty) {
        reply.ok();
    }
    fn fsync(&self, _: &Request, _: INodeNo, _: FileHandle, _: bool, reply: ReplyEmpty) {
        let _ = self.state.lock().map(|s| s.probe.flush());
        reply.error(Errno::EOPNOTSUPP);
    }
    fn fsyncdir(&self, _: &Request, _: INodeNo, _: FileHandle, _: bool, reply: ReplyEmpty) {
        reply.error(Errno::EOPNOTSUPP);
    }
    fn opendir(&self, req: &Request, ino: INodeNo, _: OpenFlags, reply: ReplyOpen) {
        let checked = (|| {
            let e = self.entry(ino.0)?;
            if !e.directory {
                return Err(libc::ENOTDIR);
            }
            self.authorize(e, req.uid(), req.gid(), 5)
        })();
        match checked {
            Ok(()) => reply.opened(FileHandle(ino.0), FopenFlags::empty()),
            Err(e) => reply.error(Errno::from_i32(e)),
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
        let checked = (|| {
            let e = self.entry(ino.0)?;
            if !e.directory {
                return Err(libc::ENOTDIR);
            }
            self.authorize(e, req.uid(), req.gid(), 5)?;
            Ok(e)
        })();
        let e = match checked {
            Ok(e) => e,
            Err(e) => {
                reply.error(Errno::from_i32(e));
                return;
            }
        };
        let parent = Path::new(&e.path).parent().unwrap_or(Path::new(""));
        let parent_ino = self
            .entries
            .iter()
            .position(|e| Path::new(&e.path) == parent)
            .unwrap_or(0) as u64
            + 1;
        let mut children = vec![
            (ino.0, FileType::Directory, "."),
            (parent_ino, FileType::Directory, ".."),
        ];
        for (i, child) in self.entries.iter().enumerate().skip(1) {
            if Path::new(&child.path).parent() == Some(Path::new(&e.path)) {
                children.push((
                    i as u64 + 1,
                    if child.directory {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    },
                    child.path.rsplit('/').next().unwrap(),
                ));
            }
        }
        for (i, (id, kind, name)) in children.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(id), i as u64 + 1, kind, name) {
                break;
            }
        }
        reply.ok();
    }
    fn setattr(
        &self,
        _: &Request,
        _: INodeNo,
        _: Option<u32>,
        _: Option<u32>,
        _: Option<u32>,
        _: Option<u64>,
        _: Option<TimeOrNow>,
        _: Option<TimeOrNow>,
        _: Option<SystemTime>,
        _: Option<FileHandle>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        reply.error(self.mutation_error());
    }
    fn mknod(&self, _: &Request, _: INodeNo, _: &OsStr, _: u32, _: u32, _: u32, reply: ReplyEntry) {
        reply.error(self.mutation_error());
    }
    fn mkdir(&self, _: &Request, _: INodeNo, _: &OsStr, _: u32, _: u32, reply: ReplyEntry) {
        reply.error(self.mutation_error());
    }
    fn unlink(&self, _: &Request, _: INodeNo, _: &OsStr, reply: ReplyEmpty) {
        reply.error(self.mutation_error());
    }
    fn rmdir(&self, _: &Request, _: INodeNo, _: &OsStr, reply: ReplyEmpty) {
        reply.error(self.mutation_error());
    }
    fn symlink(&self, _: &Request, _: INodeNo, _: &OsStr, _: &Path, reply: ReplyEntry) {
        reply.error(self.mutation_error());
    }
    fn rename(
        &self,
        _: &Request,
        _: INodeNo,
        _: &OsStr,
        _: INodeNo,
        _: &OsStr,
        _: RenameFlags,
        reply: ReplyEmpty,
    ) {
        reply.error(self.mutation_error());
    }
    fn link(&self, _: &Request, _: INodeNo, _: INodeNo, _: &OsStr, reply: ReplyEntry) {
        reply.error(self.mutation_error());
    }
    fn create(
        &self,
        _: &Request,
        _: INodeNo,
        _: &OsStr,
        _: u32,
        _: u32,
        _: i32,
        reply: ReplyCreate,
    ) {
        reply.error(self.mutation_error());
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
        reply.error(self.mutation_error());
    }
    fn removexattr(&self, _: &Request, _: INodeNo, _: &OsStr, reply: ReplyEmpty) {
        reply.error(self.mutation_error());
    }
}

pub fn mount(
    url: &str,
    path: &Path,
    writable: bool,
    expected: Option<&str>,
    prepare: bool,
) -> Result<()> {
    use std::io::Write;
    if !path.is_absolute() {
        return Err("mountpoint must be an absolute new path".into());
    }
    let parent = path
        .parent()
        .ok_or("mountpoint parent missing")?
        .canonicalize()?;
    let path = parent.join(path.file_name().ok_or("mountpoint basename missing")?);
    let adapter = FuseAdapter::connect(url, writable, expected)?;
    std::fs::create_dir(&path)?;
    let cfg = FuseAdapter::config(writable);
    println!(
        "{}",
        serde_json::json!({"pid":std::process::id(),"mode":if writable{"private"}else{"ro"},"mountpoint":path,"manifest_digest":adapter.digest(),"hydrated_bytes":0,"durability":"unsupported: ephemeral FS0","namespace":"immutable manifest","mount_options":format!("{:?}",cfg),"prepare_only":prepare})
    );
    std::io::stdout().flush()?;
    if prepare {
        std::fs::remove_dir(path)?;
        return Ok(());
    }
    let result = fuser::mount(adapter, &path, &cfg);
    // fuser unmounts the session before return; never remove a live mounted path.
    if result.is_ok() {
        std::fs::remove_dir(path)?;
    }
    result?;
    Ok(())
}
