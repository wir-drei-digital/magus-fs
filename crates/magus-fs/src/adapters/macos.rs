//! Fixed configured actor over loopback NFS. Wire AUTH_UNIX is not authentication.
//! Issued file identities/generations are retained until the daemon exits: NFS has no CLOSE.
//! Attached mounts adopt accepted views as epochs: regular-file handles are epoch-qualified,
//! directory handles are stable. Old file handles read their epoch's bytes under current
//! authority; mutations through them fail NFS3ERR_STALE before any effect.
use async_trait::async_trait;
use magus_fs_core::*;
use nfsserve::{
    nfs::*,
    tcp::{NFSTcp, NFSTcpListener},
    vfs::*,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
/// Retained epoch bound: NFS clients never close handles, so every issued epoch stays rooted
/// for the daemon lifetime. Adoption beyond this bound is deferred and reported.
const MAX_RETAINED_EPOCHS: usize = 128;
/// Issued fileids are never reused within a daemon lifetime; adoption defers beyond this bound.
const MAX_ISSUED_FILEIDS: usize = 1 << 20;
type Result<T> = std::result::Result<T, FsError>;
fn error(e: FsError) -> nfsstat3 {
    match e {
        FsError::ReadOnly => nfsstat3::NFS3ERR_ROFS,
        FsError::PermissionDenied | FsError::UnknownPrincipal => nfsstat3::NFS3ERR_ACCES,
        FsError::NotFound => nfsstat3::NFS3ERR_NOENT,
        FsError::AlreadyExists => nfsstat3::NFS3ERR_EXIST,
        FsError::NotDirectory => nfsstat3::NFS3ERR_NOTDIR,
        FsError::IsDirectory => nfsstat3::NFS3ERR_ISDIR,
        FsError::NotEmpty => nfsstat3::NFS3ERR_NOTEMPTY,
        FsError::StaleHandle => nfsstat3::NFS3ERR_STALE,
        FsError::LimitExceeded => nfsstat3::NFS3ERR_FBIG,
        FsError::Backpressure => nfsstat3::NFS3ERR_NOSPC,
        FsError::UnsupportedMode => nfsstat3::NFS3ERR_NOTSUPP,
        FsError::InvalidPath | FsError::InvalidTree => nfsstat3::NFS3ERR_INVAL,
        FsError::Io(e) if e.raw_os_error() == Some(libc::ENOSPC) => nfsstat3::NFS3ERR_NOSPC,
        _ => nfsstat3::NFS3ERR_IO,
    }
}
#[derive(Clone, Copy)]
struct Times {
    atime: nfstime3,
    mtime: nfstime3,
    ctime: nfstime3,
}
fn now() -> nfstime3 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    nfstime3 {
        seconds: t.as_secs().min(u32::MAX as u64) as u32,
        nseconds: t.subsec_nanos(),
    }
}
/// NFS fileids: regular files are issued per (EntryId, epoch), directories once per EntryId.
/// Lookups are O(1); fileids are allocated only when a client operation names an entry.
struct FileIds {
    /// fileid - 1 -> (identity, issuing epoch).
    slots: Vec<(EntryId, u64)>,
    files: HashMap<(EntryId, u64), u64>,
    directories: HashMap<EntryId, u64>,
    epoch: u64,
}
impl FileIds {
    fn new(root: EntryId, epoch: u64) -> Self {
        Self {
            slots: vec![(root.clone(), epoch)],
            files: HashMap::new(),
            directories: HashMap::from([(root, 1)]),
            epoch,
        }
    }
    fn identity(&self, id: u64) -> Result<&EntryId> {
        id.checked_sub(1)
            .and_then(|n| self.slots.get(n as usize))
            .map(|v| &v.0)
            .ok_or(FsError::StaleHandle)
    }
    /// A file handle issued in an earlier adopted epoch.
    fn stale(&self, id: u64) -> Result<bool> {
        let identity = self.identity(id)?;
        Ok(!self.directories.contains_key(identity)
            && self.slots[(id - 1) as usize].1 != self.epoch)
    }
    /// The fileid already issued for this identity in the current epoch, without allocating.
    fn issued(&self, identity: &EntryId, directory: bool) -> Option<u64> {
        match self.directories.get(identity) {
            Some(id) => Some(*id),
            None if directory => None,
            None => self.files.get(&(identity.clone(), self.epoch)).copied(),
        }
    }
    fn issue(&mut self, identity: &EntryId, directory: bool) -> u64 {
        if let Some(id) = self.issued(identity, directory) {
            return id;
        }
        self.slots.push((identity.clone(), self.epoch));
        let id = self.slots.len() as u64;
        if directory {
            self.directories.insert(identity.clone(), id);
        } else {
            self.files.insert((identity.clone(), self.epoch), id);
        }
        id
    }
    fn len(&self) -> usize {
        self.slots.len()
    }
}
struct State {
    ws: Workspace,
    config: ReplicaConfig,
    ids: FileIds,
    held: BTreeMap<u64, Handle>,
    times: BTreeMap<u64, Times>,
    started: Times,
}
impl State {
    fn changed(&mut self, id: u64, data: bool) {
        let t = now();
        let times = self.times.entry(id).or_insert(self.started);
        times.ctime = t;
        if data {
            times.mtime = t;
        }
    }
    fn requested_times(&mut self, id: u64, a: &sattr3) {
        let t = now();
        let times = self.times.entry(id).or_insert(self.started);
        if matches!(a.atime, set_atime::SET_TO_SERVER_TIME) {
            times.atime = t;
        }
        if matches!(a.mtime, set_mtime::SET_TO_SERVER_TIME) {
            times.mtime = t;
        }
    }

    fn identity(&self, id: u64) -> Result<&EntryId> {
        self.ids.identity(id)
    }
    fn stale(&self, id: u64) -> Result<bool> {
        self.ids.stale(id)
    }
    fn id(&mut self, identity: &EntryId, directory: bool) -> u64 {
        self.ids.issue(identity, directory)
    }
    fn issue(&mut self, entry: &Entry) -> Result<u64> {
        let id = self.id(&entry.id, entry.content == EntryContent::Directory);
        if entry.content != EntryContent::Directory && !self.held.contains_key(&id) {
            self.held.insert(id, self.ws.retain_identity(&entry.id)?);
        }
        Ok(id)
    }
    fn entry(&self, id: u64) -> Result<Entry> {
        if self.stale(id)? {
            // An old epoch handle keeps its own bytes/size, subject to current authority.
            return self
                .ws
                .handle_attributes(self.held.get(&id).ok_or(FsError::StaleHandle)?);
        }
        match self.ws.lookup_identity(self.identity(id)?) {
            Ok(e) => Ok(e),
            // Only an already-issued exact capability can supply an unlinked identity.
            Err(FsError::NotFound) => self
                .ws
                .handle_attributes(self.held.get(&id).ok_or(FsError::NotFound)?),
            Err(e) => Err(e), // no permission-failure fallback
        }
    }
    fn handle(&mut self, id: u64) -> Result<Handle> {
        if self.stale(id)? {
            return self.held.get(&id).cloned().ok_or(FsError::StaleHandle);
        }
        let entry = self.entry(id)?;
        self.issue(&entry)?;
        self.held.get(&id).cloned().ok_or(FsError::IsDirectory)
    }
    /// Epochs still rooted by issued handles (NFS never releases them).
    fn retained_epochs(&self) -> usize {
        self.held
            .values()
            .map(Handle::epoch)
            .collect::<BTreeSet<_>>()
            .len()
    }
    /// Advance every directory's change time so client name caches revalidate.
    fn adopted(&mut self, epoch: u64) {
        self.ids.epoch = epoch;
        let directories: Vec<u64> = self.ids.directories.values().copied().collect();
        for id in directories {
            self.changed(id, true);
        }
    }
    fn child(&self, id: u64, name: &[u8]) -> Result<String> {
        let parent = self.entry(id)?;
        if parent.content != EntryContent::Directory {
            return Err(FsError::NotDirectory);
        }
        let name = std::str::from_utf8(name).map_err(|_| FsError::InvalidPath)?;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(FsError::InvalidPath);
        }
        Ok(if parent.path.is_empty() {
            name.into()
        } else {
            format!("{}/{name}", parent.path)
        })
    }
    fn attr(&self, id: u64, e: &Entry) -> Result<fattr3> {
        let e = self.ws.native_attributes(e)?;
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
            EntryContent::Directory => (0, ftype3::NF3DIR),
            EntryContent::File { version } => (version.size, ftype3::NF3REG),
        };
        // Session observations only: stable until a supported change, reset on daemon restart.
        let times = self.times.get(&id).copied().unwrap_or(self.started);
        Ok(fattr3 {
            ftype: kind,
            mode: e.mode as u32,
            nlink: if e.content == EntryContent::Directory {
                2
            } else {
                1
            },
            uid,
            gid,
            size,
            used: size,
            fsid: 1,
            fileid: id,
            atime: times.atime,
            mtime: times.mtime,
            ctime: times.ctime,
            ..Default::default()
        })
    }
    fn creation_mode(&self, attr: &sattr3, default: u16, actor_uid: u32) -> Result<u16> {
        let actor = self
            .config
            .authorities
            .iter()
            .find(|a| a.uid == actor_uid)
            .ok_or(FsError::UnknownPrincipal)?;
        if !matches!(attr.uid, set_uid3::Void)
            && !matches!(attr.uid,set_uid3::uid(v) if v==actor.uid)
        {
            return Err(FsError::PermissionDenied);
        }
        if !matches!(attr.gid, set_gid3::Void)
            && !matches!(attr.gid,set_gid3::gid(v) if v==actor.gid)
        {
            return Err(FsError::PermissionDenied);
        }
        if !matches!(attr.size, set_size3::Void | set_size3::size(0))
            || matches!(attr.atime, set_atime::SET_TO_CLIENT_TIME(_))
            || matches!(attr.mtime, set_mtime::SET_TO_CLIENT_TIME(_))
        {
            return Err(FsError::UnsupportedMode);
        }
        let mode = match attr.mode {
            set_mode3::Void => default,
            set_mode3::mode(v) => u16::try_from(v).map_err(|_| FsError::UnsupportedMode)?,
        };
        if mode & !0o777 != 0 {
            return Err(FsError::UnsupportedMode);
        }
        Ok(mode)
    }
}
struct Adapter {
    state: Arc<Mutex<State>>,
    read_only: bool,
    nonce: Vec<u8>,
    uid: u32,
}
impl Adapter {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> std::result::Result<T, nfsstat3> {
        let mut state = self.state.lock().map_err(|_| nfsstat3::NFS3ERR_IO)?;
        f(&mut state).map_err(error)
    }
    fn writable(&self) -> std::result::Result<(), nfsstat3> {
        if self.read_only {
            Err(nfsstat3::NFS3ERR_ROFS)
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl NFSFileSystem for Adapter {
    fn capabilities(&self) -> VFSCapabilities {
        if self.read_only {
            VFSCapabilities::ReadOnly
        } else {
            VFSCapabilities::ReadWrite
        }
    }
    fn root_dir(&self) -> u64 {
        1
    }
    fn id_to_fh(&self, id: u64) -> nfs_fh3 {
        let mut data = self.nonce.clone();
        data.extend_from_slice(&id.to_be_bytes());
        nfs_fh3 { data }
    }
    fn fh_to_id(&self, fh: &nfs_fh3) -> std::result::Result<u64, nfsstat3> {
        if fh.data.len() != self.nonce.len() + 8 || fh.data[..self.nonce.len()] != self.nonce {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        let id = u64::from_be_bytes(fh.data[self.nonce.len()..].try_into().unwrap());
        self.with(|s| {
            s.identity(id)?;
            Ok(id)
        })
    }
    async fn lookup(&self, dir: u64, name: &filename3) -> std::result::Result<u64, nfsstat3> {
        self.with(|s| {
            let parent = s.entry(dir)?;
            s.ws.check_access_identity(&parent.id, 1)?;
            let e = if name.as_ref() == b"." {
                parent
            } else if name.as_ref() == b".." {
                s.ws.lookup_identity(&parent.parent)?
            } else {
                s.ws.lookup(&s.child(dir, name)?)?
            };
            s.issue(&e)
        })
    }
    async fn getattr(&self, id: u64) -> std::result::Result<fattr3, nfsstat3> {
        self.with(|s| s.attr(id, &s.entry(id)?))
    }
    async fn access(&self, id: u64, requested: u32) -> std::result::Result<u32, nfsstat3> {
        self.with(|s| {
            let e = s.entry(id)?;
            let mut allowed = 0;
            for (bits, nfsbits) in [
                (4, 1),
                (
                    1,
                    if e.content == EntryContent::Directory {
                        2
                    } else {
                        32
                    },
                ),
                (
                    if e.content == EntryContent::Directory {
                        3
                    } else {
                        2
                    },
                    4 | 8,
                ),
            ] {
                if s.ws.check_access_identity(&e.id, bits).is_ok() {
                    allowed |= nfsbits;
                }
            }
            if s.ws.check_remove_identity(&e.id).is_ok() {
                allowed |= 16;
            }
            Ok(requested & allowed)
        })
    }
    async fn read(
        &self,
        id: u64,
        offset: u64,
        count: u32,
    ) -> std::result::Result<(Vec<u8>, bool), nfsstat3> {
        self.with(|s| {
            let h = s.handle(id)?;
            let bytes = s.ws.read(&h, offset, count as usize)?;
            let e = s.ws.handle_attributes(&h)?;
            let EntryContent::File { version } = e.content else {
                return Err(FsError::IsDirectory);
            };
            let eof = offset.saturating_add(bytes.len() as u64) >= version.size;
            Ok((bytes, eof))
        })
    }
    async fn write(
        &self,
        id: u64,
        offset: u64,
        data: &[u8],
    ) -> std::result::Result<fattr3, nfsstat3> {
        self.writable()?;
        self.with(|s| {
            let h = s.handle(id)?;
            s.ws.write(&h, offset, data)?;
            s.changed(id, true);
            s.attr(id, &s.ws.handle_attributes(&h)?)
        })
    }
    async fn setattr(&self, id: u64, a: sattr3) -> std::result::Result<fattr3, nfsstat3> {
        self.writable()?;
        self.with(|s| {
            if matches!(a.atime, set_atime::SET_TO_CLIENT_TIME(_))
                || matches!(a.mtime, set_mtime::SET_TO_CLIENT_TIME(_))
            {
                return Err(FsError::UnsupportedMode);
            }
            let groups = usize::from(matches!(a.mode, set_mode3::mode(_)))
                + usize::from(matches!(a.size, set_size3::size(_)))
                + usize::from(!matches!(a.uid, set_uid3::Void) || !matches!(a.gid, set_gid3::Void));
            if groups > 1 {
                return Err(FsError::UnsupportedMode);
            }
            let e = s.entry(id)?;
            let h = if e.content == EntryContent::Directory {
                None
            } else {
                Some(s.handle(id)?)
            };
            if let set_mode3::mode(v) = a.mode {
                let v = u16::try_from(v).map_err(|_| FsError::UnsupportedMode)?;
                if let Some(h) = &h {
                    s.ws.chmod_handle(h, v)?
                } else {
                    s.ws.chmod(&e.path, v)?
                }
            }
            if let set_size3::size(v) = a.size {
                s.ws.truncate(h.as_ref().ok_or(FsError::IsDirectory)?, v)?;
            }
            if !matches!(a.uid, set_uid3::Void) || !matches!(a.gid, set_gid3::Void) {
                let owner = match a.uid {
                    set_uid3::Void => e.owner.clone(),
                    set_uid3::uid(uid) => s
                        .config
                        .authorities
                        .iter()
                        .find(|a| a.uid == uid)
                        .ok_or(FsError::MappingBlocked)?
                        .principal
                        .clone(),
                };
                let group = match a.gid {
                    set_gid3::Void => e.group.clone(),
                    set_gid3::gid(gid) => s
                        .config
                        .authorities
                        .iter()
                        .find(|a| a.gid == gid)
                        .ok_or(FsError::MappingBlocked)?
                        .primary_group
                        .clone(),
                };
                if let Some(h) = &h {
                    s.ws.chown_handle(h, owner, group)?
                } else {
                    s.ws.chown(&e.path, owner, group)?
                }
            }
            if groups == 0
                && (!matches!(a.atime, set_atime::DONT_CHANGE)
                    || !matches!(a.mtime, set_mtime::DONT_CHANGE))
            {
                s.ws.check_server_time(&e.id, h.as_ref())?;
            }
            if groups != 0 {
                s.changed(id, matches!(a.size, set_size3::size(_)));
            }
            s.requested_times(id, &a);
            s.attr(id, &s.entry(id)?)
        })
    }
    async fn create(
        &self,
        dir: u64,
        name: &filename3,
        a: sattr3,
    ) -> std::result::Result<(u64, fattr3), nfsstat3> {
        self.writable()?;
        self.with(|s| {
            let mode = s.creation_mode(&a, 0o666, self.uid)?;
            let path = s.child(dir, name)?;
            let h = s.ws.create(&path, mode)?;
            let id = s.id(h.entry_id(), false);
            s.held.insert(id, h.clone());
            s.changed(id, true);
            s.requested_times(id, &a);
            s.changed(dir, true);
            Ok((id, s.attr(id, &s.ws.handle_attributes(&h)?)?))
        })
    }
    async fn create_exclusive(
        &self,
        _dir: u64,
        _name: &filename3,
    ) -> std::result::Result<u64, nfsstat3> {
        self.writable()?;
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
    async fn mkdir(
        &self,
        dir: u64,
        name: &filename3,
    ) -> std::result::Result<(u64, fattr3), nfsstat3> {
        self.mkdir_with_attrs(dir, name, sattr3::default()).await
    }
    async fn mkdir_with_attrs(
        &self,
        dir: u64,
        name: &filename3,
        a: sattr3,
    ) -> std::result::Result<(u64, fattr3), nfsstat3> {
        self.writable()?;
        self.with(|s| {
            let mode = s.creation_mode(&a, 0o777, self.uid)?;
            let path = s.child(dir, name)?;
            let identity = s.ws.mkdir(&path, mode)?;
            let id = s.id(&identity, true);
            s.changed(id, true);
            s.requested_times(id, &a);
            s.changed(dir, true);
            Ok((id, s.attr(id, &s.ws.lookup_identity(&identity)?)?))
        })
    }
    async fn remove(&self, dir: u64, name: &filename3) -> std::result::Result<(), nfsstat3> {
        self.writable()?;
        self.with(|s| {
            let path = s.child(dir, name)?;
            if s.ws.lookup(&path)?.content == EntryContent::Directory {
                return Err(FsError::IsDirectory);
            }
            s.ws.unlink(&path)?;
            s.changed(dir, true);
            Ok(())
        })
    }
    async fn remove_directory(
        &self,
        dir: u64,
        name: &filename3,
    ) -> std::result::Result<(), nfsstat3> {
        self.writable()?;
        self.with(|s| {
            let path = s.child(dir, name)?;
            if s.ws.lookup(&path)?.content != EntryContent::Directory {
                return Err(FsError::NotDirectory);
            }
            s.ws.unlink(&path)?;
            s.changed(dir, true);
            Ok(())
        })
    }
    async fn rename(
        &self,
        from: u64,
        name: &filename3,
        to: u64,
        new: &filename3,
    ) -> std::result::Result<(), nfsstat3> {
        self.writable()?;
        self.with(|s| {
            s.ws.rename(&s.child(from, name)?, &s.child(to, new)?)?;
            s.changed(from, true);
            s.changed(to, true);
            Ok(())
        })
    }
    async fn readdir(
        &self,
        dir: u64,
        after: u64,
        max: usize,
    ) -> std::result::Result<ReadDirResult, nfsstat3> {
        self.with(|s| {
            let parent = s.entry(dir)?;
            let children = s.ws.directory_entries(&parent.path)?;
            let mut entries = vec![];
            for (name, identity, directory) in children {
                let id = s.id(&identity, directory);
                if id <= after {
                    continue;
                }
                // Names-only directories may enumerate IDs; no capability or metadata until authorized.
                let attr = match s.ws.lookup_identity(&identity) {
                    Ok(e) => {
                        s.issue(&e)?;
                        s.attr(id, &e)?
                    }
                    Err(FsError::PermissionDenied) => fattr3::default(),
                    Err(e) => return Err(e),
                };
                entries.push(DirEntry {
                    fileid: id,
                    name: name.as_bytes().into(),
                    attr,
                });
            }
            entries.sort_by_key(|e| e.fileid);
            let end = entries.len() <= max;
            entries.truncate(max);
            Ok(ReadDirResult { entries, end })
        })
    }
    async fn symlink(
        &self,
        _: u64,
        _: &filename3,
        _: &nfspath3,
        _: &sattr3,
    ) -> std::result::Result<(u64, fattr3), nfsstat3> {
        self.writable()?;
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
    async fn readlink(&self, _: u64) -> std::result::Result<nfspath3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
}
pub fn mount(
    rep: Replica,
    state: &Path,
    revision: &RevisionId,
    mountpoint: &Path,
    read_only: bool,
) -> Result<()> {
    serve(rep, state, revision, mountpoint, read_only, false, 0)
}
pub fn prepare(
    rep: Replica,
    state: &Path,
    revision: &RevisionId,
    mountpoint: &Path,
    read_only: bool,
    port: u16,
) -> Result<()> {
    serve(rep, state, revision, mountpoint, read_only, true, port)
}
fn serve(
    rep: Replica,
    state: &Path,
    revision: &RevisionId,
    mountpoint: &Path,
    read_only: bool,
    prepare: bool,
    port: u16,
) -> Result<()> {
    let config = rep.configuration()?;
    if !mountpoint.is_absolute() || !config.content_roots.contains(&mountpoint.to_path_buf()) {
        return Err(FsError::ConfigMismatch);
    }
    rep.check_content_path(mountpoint)?;
    let uid = unsafe { libc::geteuid() };
    let actor = rep.actor_for_uid(uid)?;
    let binding = rep.sync_status()?.binding;
    let ws = if binding.is_some() {
        rep.begin_live(revision, actor.clone(), read_only)?
    } else {
        rep.begin(revision, actor.clone(), read_only)?
    };
    let root = ws.lookup("")?.id;
    let epoch = if binding.is_some() {
        rep.live_status()?.epoch
    } else {
        0
    };
    let t = now();
    let adapter = Adapter {
        state: Arc::new(Mutex::new(State {
            ws,
            config,
            ids: FileIds::new(root, epoch),
            held: BTreeMap::new(),
            times: BTreeMap::new(),
            started: Times {
                atime: t,
                mtime: t,
                ctime: t,
            },
        })),
        read_only,
        nonce: OperationId::random()?.as_str().as_bytes()[10..].to_vec(),
        uid,
    };
    let live_state = adapter.state.clone();
    let _control = super::control::Server::start(rep.clone(), state, read_only)?;
    std::fs::create_dir(mountpoint)?;
    rep.check_content_path(mountpoint)?;
    if binding.is_some() && !prepare {
        let rep = rep.clone();
        let mountpoint = mountpoint.to_path_buf();
        let shared_live = binding
            .as_ref()
            .is_some_and(|b| b.publication == PublicationMode::SharedLive);
        std::thread::spawn(move || live(rep, live_state, mountpoint, actor, shared_live));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener=NFSTcpListener::bind(&format!("127.0.0.1:{port}"),adapter).await.map_err(std::io::Error::other)?;
        let port=listener.get_listen_port();
        let options=format!("{},nosuid,nodev,locallocks,vers=3,tcp,rsize=65536,wsize=65536,actimeo=1,soft,timeo=10,retrans=2,port={port},mountport={port}",if read_only{"ro"}else{"rw"});
        let command=vec!["/sbin/mount_nfs".to_owned(),"-o".into(),options,"127.0.0.1:/".into(),mountpoint.to_string_lossy().into_owned()];
        println!("{}",serde_json::json!({"pid":std::process::id(),"port":port,"mountpoint":mountpoint,"mount_command":command,"prepare_only":prepare,"principal_uid":uid,"revision":revision,"read_only":read_only,"handle_retention":"entire mount lifetime","hydrated_bytes":0}));std::io::stdout().flush()?;
        if !prepare {std::thread::spawn(move||{let result=std::process::Command::new(&command[0]).args(&command[1..]).status();eprintln!("native mount result {result:?}; endpoint stays foreground for owned unmount/cleanup");});}
        listener.handle_forever().await.map_err(std::io::Error::other)?;Ok(())
    })
}
/// The kernel mount at `mountpoint` is NFS (the client path, not this process's state).
fn nfs_mounted(mountpoint: &Path) -> bool {
    let Ok(path) = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is NUL terminated and fs is written on success.
    if unsafe { libc::statfs(path.as_ptr(), fs.as_mut_ptr()) } != 0 {
        return false;
    }
    let fs = unsafe { fs.assume_init() };
    let kind = unsafe { std::ffi::CStr::from_ptr(fs.f_fstypename.as_ptr()) };
    let on = unsafe { std::ffi::CStr::from_ptr(fs.f_mntonname.as_ptr()) };
    kind.to_bytes() == b"nfs" && on.to_bytes() == mountpoint.as_os_str().as_encoded_bytes()
}
/// Acknowledge only after an ordinary kernel path walk through the NFS client observes the
/// adopted epoch: new fileids, kinds and sizes for current names and absence of removed names.
fn verify(
    rep: &Replica,
    state: &Mutex<State>,
    mountpoint: &Path,
    adoption: &Adoption,
) -> Result<()> {
    if !nfs_mounted(mountpoint) {
        return Err(FsError::StaleHandle);
    }
    let current = rep.revision(&adoption.revision)?;
    let expected = {
        let s = state.lock().map_err(|_| FsError::ReplicaBusy)?;
        let mut rows = vec![];
        for e in &current.tree.entries {
            // The fixed actor cannot observe names it may not traverse; skip, never guess.
            if s.ws.lookup(&e.path).is_err() {
                continue;
            }
            let directory = e.content == EntryContent::Directory;
            let size = match &e.content {
                EntryContent::File { version } => version.size,
                EntryContent::Directory => 0,
            };
            rows.push((e.path.clone(), directory, size, e.id.clone()));
        }
        rows
    };
    for (path, directory, size, identity) in &expected {
        // The kernel client's own LOOKUP issues the fileid; verification never allocates one.
        let m = std::fs::symlink_metadata(mountpoint.join(path))?;
        let issued = state
            .lock()
            .map_err(|_| FsError::ReplicaBusy)?
            .ids
            .issued(identity, *directory);
        if issued != Some(m.ino()) || m.is_dir() != *directory || (!directory && m.len() != *size) {
            return Err(FsError::StaleHandle);
        }
    }
    for e in &adoption.entries {
        if !e.path.is_empty()
            && !current.tree.entries.iter().any(|v| v.path == e.path)
            && std::fs::symlink_metadata(mountpoint.join(&e.path)).is_ok()
        {
            return Err(FsError::StaleHandle);
        }
    }
    Ok(())
}
fn live(rep: Replica, state: Arc<Mutex<State>>, mountpoint: PathBuf, actor: Actor, shared: bool) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _hints = crate::sync::subscribe(rep.clone(), stop);
    let Ok(mut incoming) = crate::sync::Incoming::new(&rep) else {
        return;
    };
    let mut pending = rep
        .live_status()
        .ok()
        .filter(|_| shared)
        .and_then(|status| {
            rep.revision(&status.revision).ok().map(|r| Adoption {
                revision: status.revision,
                epoch: status.epoch,
                entries: r.tree.entries,
            })
        });
    let mut pressure = false;
    loop {
        let result = incoming.poll(|binding, generation| {
            let mut s = state.lock().map_err(|_| FsError::ReplicaBusy)?;
            let retained = s.retained_epochs();
            let issued = s.ids.len();
            if retained >= MAX_RETAINED_EPOCHS || issued >= MAX_ISSUED_FILEIDS {
                if !pressure {
                    eprintln!(
                        "{}",
                        serde_json::json!({"live_pressure":{"retained_epochs":retained,"epoch_limit":MAX_RETAINED_EPOCHS,"issued_fileids":issued,"fileid_limit":MAX_ISSUED_FILEIDS,"adoption":"deferred"}})
                    );
                }
                pressure = true;
                // Deferred like dirty state: authority is still observed, bytes stay retained.
                return Err(FsError::DirtyWorkingState);
            }
            pressure = false;
            let adoption = rep.adopt_remote_view(binding, generation, actor.clone())?;
            s.adopted(adoption.epoch);
            Ok(adoption)
        });
        if let Ok(Some(adoption)) = result {
            pending = Some(adoption);
        }
        if let Some(adoption) = &pending {
            let started = Instant::now();
            if verify(&rep, &state, &mountpoint, adoption).is_ok()
                && rep
                    .acknowledge_adoption(&adoption.revision, adoption.epoch)
                    .is_ok()
            {
                let (epochs, issued) = state
                    .lock()
                    .map(|s| (s.retained_epochs(), s.ids.len()))
                    .unwrap_or_default();
                eprintln!(
                    "live_applied epoch={} revision={} client_verification_us={} retained_epochs={} issued_fileids={}",
                    adoption.epoch,
                    adoption.revision.as_str(),
                    started.elapsed().as_micros(),
                    epochs,
                    issued
                );
                pending = None;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_ids_are_epoch_qualified_directories_stable_and_lookup_never_allocates() {
        let root = EntryId::random().unwrap();
        let file = EntryId::random().unwrap();
        let dir = EntryId::random().unwrap();
        let mut ids = FileIds::new(root.clone(), 3);
        assert_eq!(ids.issued(&root, true), Some(1));
        assert_eq!(
            ids.issued(&file, false),
            None,
            "lookup without a client name"
        );
        assert_eq!(ids.len(), 1);
        let old = ids.issue(&file, false);
        let d = ids.issue(&dir, true);
        assert_eq!(ids.issue(&file, false), old);
        assert!(!ids.stale(old).unwrap());
        ids.epoch = 4;
        assert!(
            ids.stale(old).unwrap(),
            "old-epoch file handle is stale for mutation"
        );
        assert!(!ids.stale(d).unwrap() && !ids.stale(1).unwrap());
        assert_eq!(ids.issued(&file, false), None);
        let new = ids.issue(&file, false);
        assert_ne!(new, old);
        assert_eq!(
            ids.issue(&dir, true),
            d,
            "directory fileids are stable across epochs"
        );
        assert_eq!(ids.identity(old).unwrap(), &file);
        assert!(matches!(ids.identity(999), Err(FsError::StaleHandle)));
        assert_eq!(ids.len(), 4);
        // Repeated lookups across many entries stay O(1) per lookup and allocate nothing.
        for _ in 0..10_000 {
            assert_eq!(ids.issued(&file, false), Some(new));
        }
        assert_eq!(ids.len(), 4);
    }
}
