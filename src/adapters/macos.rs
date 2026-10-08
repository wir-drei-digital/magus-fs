//! Bounded fixed-principal FS0 candidate, not a multi-user NFS service.
use crate::{Entry, Probe, Result};
use async_trait::async_trait;
use nfsserve::{nfs::*, vfs::*};
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

struct Backing {
    files: Vec<File>,
    root: File,
    serial: Mutex<()>,
}
fn durable(file: &File) -> std::io::Result<()> {
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub struct NfsAdapter {
    probe: Mutex<Probe>,
    entries: Vec<Entry>,
    uid: u32,
    gid: u32,
    digest: String,
    backing: Option<Backing>,
    hydrated_bytes: u64,
}
impl NfsAdapter {
    pub fn connect(url: &str, expected: Option<&str>) -> Result<Self> {
        let probe = Probe::connect(url, false)?;
        if expected.is_some_and(|digest| digest != probe.manifest_identity()) {
            return Err("expected manifest digest mismatch".into());
        }
        // The process actor is fixed. AUTH_UNIX credentials are not an authentication boundary.
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let mut entries = vec![Entry {
            path: String::new(),
            size: 0,
            mode: 0o755,
            uid,
            gid,
            directory: true,
            chunks: vec![],
        }];
        entries.extend(probe.manifest().entries.clone());
        Ok(Self {
            digest: probe.manifest_identity().to_owned(),
            probe: Mutex::new(probe),
            entries,
            uid,
            gid,
            backing: None,
            hydrated_bytes: 0,
        })
    }
    pub fn enable_private(&mut self, root: &Path, resume: bool) -> Result<()> {
        if !root.is_absolute() {
            return Err("backing must be an absolute owned path".into());
        }
        if !resume {
            std::fs::create_dir(root)?;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.uid() != self.uid || metadata.mode() & 0o077 != 0 {
            return Err("backing must be an owned nonsymlink directory with mode0700".into());
        }
        let marker = root.join("manifest.json");
        let tree = root.join("tree");
        if resume {
            let stored: crate::Manifest = serde_json::from_reader(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&marker)?,
            )?;
            if stored.digest != self.digest || stored.canonical_digest() != self.digest {
                return Err("backing digest mismatch".into());
            }
        } else {
            std::fs::create_dir(&tree)?;
            for entry in self.entries.iter().skip(1).filter(|e| e.directory) {
                std::fs::create_dir(tree.join(&entry.path))?;
            }
            let mut probe = self.probe.lock().map_err(|_| "probe poisoned")?;
            for entry in self.entries.iter().skip(1).filter(|e| !e.directory) {
                if entry.uid != self.uid || entry.gid != self.gid {
                    return Err("private fixture ownership must match fixed principal".into());
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(tree.join(&entry.path))?;
                let mut offset = 0;
                while offset < entry.size {
                    let data = probe.read(&entry.path, offset, 262144)?;
                    if data.is_empty() {
                        return Err("unexpected hydration EOF".into());
                    }
                    file.write_all(&data)?;
                    offset += data.len() as u64;
                }
                file.set_permissions(std::fs::Permissions::from_mode(entry.mode))?;
                durable(&file)?;
            }
            self.hydrated_bytes = probe.fetched_bytes();
            for entry in self.entries.iter().filter(|e| e.directory) {
                File::open(tree.join(&entry.path))?.sync_all()?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&marker)?;
            file.write_all(&serde_json::to_vec(probe.manifest())?)?;
            durable(&file)?;
            File::open(root)?.sync_all()?;
        }
        let mut files = Vec::new();
        for entry in &self.entries {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(!entry.directory)
                .custom_flags(libc::O_NOFOLLOW);
            let file = options.open(tree.join(&entry.path))?;
            if file.metadata()?.is_dir() != entry.directory {
                return Err("backing entry type mismatch".into());
            }
            files.push(file);
        }
        self.backing = Some(Backing {
            files,
            root: File::open(root)?,
            serial: Mutex::new(()),
        });
        Ok(())
    }
    pub fn hydrated_bytes(&self) -> u64 {
        self.hydrated_bytes
    }
    fn current_entry(&self, id: fileid3) -> std::result::Result<Entry, nfsstat3> {
        let mut entry = self.entry(id)?.clone();
        if let Some(backing) = &self.backing {
            let metadata = backing.files[id as usize - 1]
                .metadata()
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            entry.mode = metadata.mode() & 0o7777;
            entry.size = metadata.len();
        }
        Ok(entry)
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    fn entry(&self, id: fileid3) -> std::result::Result<&Entry, nfsstat3> {
        id.checked_sub(1)
            .and_then(|n| self.entries.get(n as usize))
            .ok_or(nfsstat3::NFS3ERR_STALE)
    }
    fn allowed(&self, entry: &Entry, bits: u32) -> bool {
        let shift = if entry.uid == self.uid {
            6
        } else if entry.gid == self.gid {
            3
        } else {
            0
        };
        (entry.mode >> shift) & bits == bits
    }
    fn traversal(&self, entry: &Entry) -> std::result::Result<(), nfsstat3> {
        let mut path = std::path::Path::new(&entry.path).parent();
        while let Some(parent) = path {
            let parent = self
                .entries
                .iter()
                .find(|e| std::path::Path::new(&e.path) == parent)
                .ok_or(nfsstat3::NFS3ERR_NOENT)?;
            if !self.allowed(parent, 1) {
                return Err(nfsstat3::NFS3ERR_ACCES);
            }
            path = std::path::Path::new(&parent.path).parent();
        }
        Ok(())
    }
    fn attr(&self, id: fileid3) -> std::result::Result<fattr3, nfsstat3> {
        let entry = self.current_entry(id)?;
        let mut attr = fattr3 {
            ftype: if entry.directory {
                ftype3::NF3DIR
            } else {
                ftype3::NF3REG
            },
            mode: entry.mode,
            nlink: if entry.directory { 2 } else { 1 },
            uid: entry.uid,
            gid: entry.gid,
            size: entry.size,
            used: entry.size,
            fileid: id,
            fsid: 1,
            ..Default::default()
        };
        if let Some(backing) = &self.backing {
            let metadata = backing.files[id as usize - 1]
                .metadata()
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            attr.atime = nfstime3 {
                seconds: metadata.atime() as u32,
                nseconds: metadata.atime_nsec() as u32,
            };
            attr.mtime = nfstime3 {
                seconds: metadata.mtime() as u32,
                nseconds: metadata.mtime_nsec() as u32,
            };
            attr.ctime = nfstime3 {
                seconds: metadata.ctime() as u32,
                nseconds: metadata.ctime_nsec() as u32,
            };
        }
        Ok(attr)
    }
}
#[async_trait]
impl NFSFileSystem for NfsAdapter {
    fn capabilities(&self) -> VFSCapabilities {
        if self.backing.is_some() {
            VFSCapabilities::ReadWrite
        } else {
            VFSCapabilities::ReadOnly
        }
    }
    fn root_dir(&self) -> fileid3 {
        1
    }
    // Include immutable manifest identity in every handle; no per-open promises.
    fn id_to_fh(&self, id: fileid3) -> nfs_fh3 {
        let mut data = self.digest.as_bytes()[..32].to_vec();
        data.extend_from_slice(&id.to_be_bytes());
        nfs_fh3 { data }
    }
    fn fh_to_id(&self, fh: &nfs_fh3) -> std::result::Result<fileid3, nfsstat3> {
        if fh.data.len() != 40 || fh.data[..32] != self.digest.as_bytes()[..32] {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        let id = u64::from_be_bytes(fh.data[32..].try_into().unwrap());
        self.entry(id)?;
        Ok(id)
    }
    async fn lookup(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> std::result::Result<fileid3, nfsstat3> {
        let parent = self.entry(dirid)?;
        if !parent.directory {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }
        self.traversal(parent)?;
        if !self.allowed(parent, 1) {
            return Err(nfsstat3::NFS3ERR_ACCES);
        }
        let name = std::str::from_utf8(filename).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        if name == "." {
            return Ok(dirid);
        }
        if name == ".." {
            let path = std::path::Path::new(&parent.path)
                .parent()
                .unwrap_or(std::path::Path::new(""));
            return self
                .entries
                .iter()
                .position(|e| std::path::Path::new(&e.path) == path)
                .map(|n| n as u64 + 1)
                .ok_or(nfsstat3::NFS3ERR_NOENT);
        }
        if name.is_empty() || name.contains('/') || name.contains('\0') {
            return Err(nfsstat3::NFS3ERR_INVAL);
        }
        let path = if parent.path.is_empty() {
            name.to_owned()
        } else {
            format!("{}/{name}", parent.path)
        };
        self.entries
            .iter()
            .position(|e| e.path == path)
            .map(|n| n as u64 + 1)
            .ok_or(nfsstat3::NFS3ERR_NOENT)
    }
    async fn getattr(&self, id: fileid3) -> std::result::Result<fattr3, nfsstat3> {
        self.attr(id)
    }
    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> std::result::Result<(Vec<u8>, bool), nfsstat3> {
        let entry = self.current_entry(id)?;
        if entry.directory {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        self.traversal(&entry)?;
        if !self.allowed(&entry, 4) {
            return Err(nfsstat3::NFS3ERR_ACCES);
        }
        if let Some(backing) = &self.backing {
            let mut bytes = vec![0; (count as usize).min(1024 * 1024)];
            let length = backing.files[id as usize - 1]
                .read_at(&mut bytes, offset)
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            bytes.truncate(length);
            return Ok((bytes, offset.saturating_add(length as u64) >= entry.size));
        }
        // Probe uses bounded blocking HTTP. Run this adapter on a multithread runtime.
        let bytes = self
            .probe
            .lock()
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .read(&entry.path, offset, (count as usize).min(1024 * 1024))
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let eof = offset.saturating_add(bytes.len() as u64) >= entry.size;
        Ok((bytes, eof))
    }
    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> std::result::Result<ReadDirResult, nfsstat3> {
        let parent = self.entry(dirid)?;
        if !parent.directory {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }
        self.traversal(parent)?;
        if !self.allowed(parent, 5) {
            return Err(nfsstat3::NFS3ERR_ACCES);
        }
        let children: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(i, e)| {
                *i != 0
                    && (*i as u64 + 1) > start_after
                    && std::path::Path::new(&e.path).parent()
                        == Some(std::path::Path::new(&parent.path))
            })
            .collect();
        let end = children.len() <= max_entries;
        let entries = children
            .into_iter()
            .take(max_entries)
            .map(|(i, e)| {
                let id = i as u64 + 1;
                Ok(DirEntry {
                    fileid: id,
                    name: e.path.rsplit('/').next().unwrap().as_bytes().into(),
                    attr: self.attr(id)?,
                })
            })
            .collect::<std::result::Result<_, nfsstat3>>()?;
        Ok(ReadDirResult { entries, end })
    }
    async fn setattr(&self, id: fileid3, attr: sattr3) -> std::result::Result<fattr3, nfsstat3> {
        let backing = self.backing.as_ref().ok_or(nfsstat3::NFS3ERR_ROFS)?;
        let _guard = backing.serial.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let entry = self.current_entry(id)?;
        self.traversal(&entry)?;
        if entry.uid != self.uid {
            return Err(nfsstat3::NFS3ERR_PERM);
        }
        if !matches!(attr.uid, set_uid3::Void) || !matches!(attr.gid, set_gid3::Void) {
            return Err(nfsstat3::NFS3ERR_NOTSUPP);
        }
        if entry.directory
            || !matches!(attr.atime, set_atime::DONT_CHANGE)
            || !matches!(attr.mtime, set_mtime::DONT_CHANGE)
        {
            return Err(nfsstat3::NFS3ERR_NOTSUPP);
        }
        if let set_mode3::mode(mode) = attr.mode {
            if mode & !0o777 != 0 {
                return Err(nfsstat3::NFS3ERR_NOTSUPP);
            }
        }
        let file = &backing.files[id as usize - 1];
        if let set_size3::size(size) = attr.size {
            if entry.directory {
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }
            if !self.allowed(&entry, 2) {
                return Err(nfsstat3::NFS3ERR_ACCES);
            }
            if size > 67108864 {
                return Err(nfsstat3::NFS3ERR_FBIG);
            }
            file.set_len(size).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        }
        if let set_mode3::mode(mode) = attr.mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        }
        durable(file).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        backing.root.sync_all().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.attr(id)
    }
    async fn write(
        &self,
        id: fileid3,
        offset: u64,
        bytes: &[u8],
    ) -> std::result::Result<fattr3, nfsstat3> {
        let backing = self.backing.as_ref().ok_or(nfsstat3::NFS3ERR_ROFS)?;
        let _guard = backing.serial.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let entry = self.current_entry(id)?;
        self.traversal(&entry)?;
        if entry.directory {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        if !self.allowed(&entry, 2) {
            return Err(nfsstat3::NFS3ERR_ACCES);
        }
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > 67108864)
        {
            return Err(nfsstat3::NFS3ERR_FBIG);
        }
        let file = &backing.files[id as usize - 1];
        file.write_all_at(bytes, offset)
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        durable(file).map_err(|_| nfsstat3::NFS3ERR_IO)?;
        backing.root.sync_all().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        self.attr(id)
    }
    async fn create(
        &self,
        _: fileid3,
        _: &filename3,
        _: sattr3,
    ) -> std::result::Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }
    async fn create_exclusive(
        &self,
        _: fileid3,
        _: &filename3,
    ) -> std::result::Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }
    async fn mkdir(
        &self,
        _: fileid3,
        _: &filename3,
    ) -> std::result::Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }
    async fn remove(&self, _: fileid3, _: &filename3) -> std::result::Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }
    async fn rename(
        &self,
        _: fileid3,
        _: &filename3,
        _: fileid3,
        _: &filename3,
    ) -> std::result::Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }
    async fn symlink(
        &self,
        _: fileid3,
        _: &filename3,
        _: &nfspath3,
        _: &sattr3,
    ) -> std::result::Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }
    async fn readlink(&self, _: fileid3) -> std::result::Result<nfspath3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_INVAL)
    }
    async fn fsinfo(&self, id: fileid3) -> std::result::Result<fsinfo3, nfsstat3> {
        Ok(fsinfo3 {
            obj_attributes: post_op_attr::attributes(self.attr(id)?),
            rtmax: 1048576,
            rtpref: 65536,
            rtmult: 4096,
            wtmax: 1048576,
            wtpref: 65536,
            wtmult: 4096,
            dtpref: 65536,
            maxfilesize: 67108864,
            time_delta: nfstime3 {
                seconds: 1,
                nseconds: 0,
            },
            properties: 0,
        })
    }
}
