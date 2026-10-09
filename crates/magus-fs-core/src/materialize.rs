//! Owned staging manifests remain outside materialized content, including on failure.
use crate::{
    capture::{absolute_native, directory},
    engine::{json, lock},
    objects::{name, open_at},
    permissions as perm, *,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{File, Permissions},
    io::{Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Clone, Debug)]
pub struct MaterializationMapping {
    pub actor: Actor,
}
#[derive(Clone, Debug, Serialize)]
pub struct MaterializationResult {
    pub revision: RevisionId,
    pub destination: PathBuf,
    pub verified_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaterializationRecovery {
    pub id: OperationId,
    pub revision: RevisionId,
    pub destination: PathBuf,
    pub staging: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub content_device: Option<u64>,
    pub content_inode: Option<u64>,
    pub status: String,
    pub error: Option<String>,
    pub native_metadata: Vec<NativeMetadataDisposition>,
}
fn mkdir(parent: &File, leaf: &OsStr) -> Result<File, FsError> {
    let n = name(leaf)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    open_at(parent.as_raw_fd(), &n, libc::O_RDONLY | libc::O_DIRECTORY)
}
fn absent(parent: &File, leaf: &OsStr) -> Result<bool, FsError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let n = name(leaf)?;
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            n.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(false);
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(true)
    } else {
        Err(e.into())
    }
}
fn apply(
    file: &File,
    owner: &PrincipalId,
    group: &GroupId,
    mode: u16,
    config: &ReplicaConfig,
) -> Result<(), FsError> {
    let uid = config
        .authorities
        .iter()
        .find(|a| &a.principal == owner)
        .ok_or(FsError::MappingBlocked)?
        .uid;
    let gid = config
        .authorities
        .iter()
        .find(|a| &a.primary_group == group)
        .ok_or(FsError::MappingBlocked)?
        .gid;
    let meta = file.metadata()?;
    if (meta.uid() != uid || meta.gid() != gid)
        && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
    {
        return Err(FsError::MappingBlocked);
    }
    file.set_permissions(Permissions::from_mode(mode as u32))?;
    let actual = file.metadata()?;
    if actual.uid() != uid || actual.gid() != gid || actual.mode() & 0o7777 != mode as u32 {
        return Err(FsError::MappingBlocked);
    }
    file.sync_all()?;
    Ok(())
}
fn publish(source: &File, parent: &File, destination: &OsStr) -> Result<(), FsError> {
    let from = name(OsStr::new("content"))?;
    let to = name(destination)?;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            source.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.kind() == std::io::ErrorKind::AlreadyExists {
            FsError::AlreadyExists
        } else {
            e.into()
        });
    }
    parent.sync_all()?;
    source.sync_all()?;
    Ok(())
}
fn manifest(stage: &File, record: &MaterializationRecovery) -> Result<(), FsError> {
    crate::faults::hit("materialize-manifest")?;
    let (unsupported, _) = crate::capture::metadata_inventory(stage, "staging_control")?;
    if !unsupported.is_empty() {
        return Err(FsError::UnsupportedEntries(unsupported));
    }
    // Replacing a visible manifest never opens/truncates an attacker-swapped inode.
    let temp = format!(
        ".manifest-{}",
        OperationId::random()?
            .as_str()
            .trim_start_matches("operation:")
    );
    let leaf = name(OsStr::new(&temp))?;
    let mut out = open_at(
        stage.as_raw_fd(),
        &leaf,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    out.write_all(&json(record)?)?;
    out.sync_all()?;
    let destination = name(OsStr::new("ownership.json"))?;
    if unsafe {
        libc::renameat(
            stage.as_raw_fd(),
            leaf.as_ptr(),
            stage.as_raw_fd(),
            destination.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    stage.sync_all()?;
    Ok(())
}
impl Replica {
    pub fn materialization_recovery(&self) -> Result<Vec<MaterializationRecovery>, FsError> {
        let core = lock(&self.core)?;
        let mut statement = core
            .journal
            .db
            .prepare("SELECT manifest FROM materializations ORDER BY rowid")?;
        let mut out = vec![];
        for b in statement.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            out.push(crate::engine::from_json(&b?)?);
        }
        Ok(out)
    }
    pub fn materialize(
        &self,
        revision: &RevisionId,
        destination: impl AsRef<Path>,
        mapping: MaterializationMapping,
    ) -> Result<MaterializationResult, FsError> {
        let destination = destination.as_ref();
        absolute_native(destination)?;
        let mut core = lock(&self.core)?;
        core.journal.check_content_path(destination)?;
        let rev = core.revision(revision)?;
        validate_tree(&rev.tree)?;
        let a = perm::authority(&core.config, &mapping.actor)?;
        // Historical restoration is authorized by each identity's current path and metadata.
        let live = core.working.as_ref().map(|w| &w.tree).unwrap_or(&rev.tree);
        for e in
            std::iter::once(perm::root_entry(&rev.tree)).chain(rev.tree.entries.iter().cloned())
        {
            let current = if e.id == live.root.id {
                perm::root_entry(live)
            } else {
                live.entries
                    .iter()
                    .find(|v| v.id == e.id)
                    .cloned()
                    .ok_or(FsError::PermissionDenied)?
            };
            perm::traversal(live, &current.path, a)?;
            perm::access(
                a,
                &current,
                if e.content == EntryContent::Directory {
                    5
                } else {
                    4
                },
            )?;
        }
        let parent_path = destination.parent().ok_or(FsError::InvalidPath)?;
        let leaf = destination.file_name().ok_or(FsError::InvalidPath)?;
        let parent = directory(parent_path)?;
        if !absent(&parent, leaf)? {
            return Err(FsError::AlreadyExists);
        }
        let id = OperationId::random()?;
        let stage_leaf = format!(
            ".magus-stage-{}",
            id.as_str().trim_start_matches("operation:")
        );
        let stage_path = parent_path.join(&stage_leaf);
        core.journal.check_content_path(&stage_path)?;
        let mut content_roots = core.config.content_roots.clone();
        content_roots.push(destination.to_path_buf());
        let stage_store = ObjectStore::create_owned(
            &stage_path,
            ObjectLimits {
                content_roots,
                ..ObjectLimits::default()
            },
        )?;
        let stage = stage_store.directory().try_clone()?;
        stage.set_permissions(Permissions::from_mode(0o700))?;
        let metadata = stage.metadata()?;
        let mut record = MaterializationRecovery {
            id: id.clone(),
            revision: revision.clone(),
            destination: destination.into(),
            staging: stage_path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            content_device: None,
            content_inode: None,
            status: "staging".into(),
            error: None,
            native_metadata: vec![],
        };
        core.journal.db.execute(
            "INSERT INTO materializations VALUES(?,?)",
            params![id.as_str(), json(&record)?],
        )?;
        let result = (|| {
            parent.sync_all()?;
            manifest(&stage, &record)?;
            let root = mkdir(&stage, OsStr::new("content"))?;
            let mut directories = BTreeMap::from([(String::new(), root)]);
            let mut files = BTreeMap::new();
            let mut entries = rev.tree.entries.iter().collect::<Vec<_>>();
            entries.sort_by(|a, b| a.path.cmp(&b.path));
            // Create the entire target namespace before writing bytes. O_EXCL/mkdirat detects
            // additional target-specific aliases beyond the portable Unicode folding policy.
            for entry in &entries {
                let dir = &directories[perm::parent(&entry.path)];
                let name_leaf =
                    OsStr::new(entry.path.rsplit('/').next().ok_or(FsError::InvalidPath)?);
                if !absent(dir, name_leaf)? {
                    return Err(FsError::TargetCollision);
                }
                if entry.content == EntryContent::Directory {
                    directories.insert(entry.path.clone(), mkdir(dir, name_leaf)?);
                } else {
                    let file = open_at(
                        dir.as_raw_fd(),
                        &name(name_leaf)?,
                        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                    )?;
                    files.insert(entry.path.clone(), file);
                }
            }
            let mut verified_bytes = 0;
            let deadline = Instant::now() + Duration::from_millis(4500);
            for entry in &entries {
                if let EntryContent::File { version } = &entry.content {
                    let file = files.get_mut(&entry.path).ok_or(FsError::InvalidTree)?;
                    for extent in &version.extents {
                        match extent {
                            Extent::Hole { length } => {
                                file.seek(SeekFrom::Current(
                                    (*length).try_into().map_err(|_| FsError::LimitExceeded)?,
                                ))?;
                            }
                            Extent::Chunk {
                                object,
                                object_size,
                                offset,
                                length,
                            } => {
                                let bytes = core.fetch(object, *object_size, deadline)?;
                                file.write_all(
                                    &bytes[*offset as usize..(*offset + *length) as usize],
                                )?;
                            }
                        }
                    }
                    file.set_len(version.size)?;
                    // Read the actual stage back and compare every supported chunk slice/hole.
                    file.seek(SeekFrom::Start(0))?;
                    use std::io::Read;
                    for extent in &version.extents {
                        match extent {
                            Extent::Chunk {
                                object,
                                object_size,
                                offset,
                                length,
                            } => {
                                let mut observed = vec![0; *length as usize];
                                file.read_exact(&mut observed)?;
                                let expected = core.fetch(object, *object_size, deadline)?;
                                if observed
                                    != expected[*offset as usize..(*offset + *length) as usize]
                                {
                                    return Err(FsError::CorruptObject);
                                }
                            }
                            Extent::Hole { length } => {
                                let mut remaining = *length;
                                let mut bytes = [0; 8192];
                                while remaining > 0 {
                                    let n = remaining.min(8192) as usize;
                                    file.read_exact(&mut bytes[..n])?;
                                    if bytes[..n].iter().any(|b| *b != 0) {
                                        return Err(FsError::CorruptObject);
                                    }
                                    remaining -= n as u64;
                                }
                            }
                        }
                    }
                    apply(file, &entry.owner, &entry.group, entry.mode, &core.config)?;
                    verified_bytes += version.size;
                }
            }
            for entry in entries
                .iter()
                .rev()
                .filter(|e| e.content == EntryContent::Directory)
            {
                apply(
                    &directories[&entry.path],
                    &entry.owner,
                    &entry.group,
                    entry.mode,
                    &core.config,
                )?;
            }
            apply(
                &directories[""],
                &rev.tree.root.owner,
                &rev.tree.root.group,
                rev.tree.root.mode,
                &core.config,
            )?;
            for (path, file) in directories.iter().chain(files.iter()) {
                let (unsupported, diagnostics) = crate::capture::metadata_inventory(file, path)?;
                if !unsupported.is_empty() {
                    return Err(FsError::UnsupportedEntries(unsupported));
                }
                record.native_metadata.extend(diagnostics);
            }
            core.journal.check_content_path(destination)?;
            let current = directory(parent_path)?;
            let before = parent.metadata()?;
            let after = current.metadata()?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(FsError::UnsafeStorage);
            }
            stage_store.assert_path(&stage_path)?;
            let actual_stage = open_at(
                parent.as_raw_fd(),
                &name(OsStr::new(&stage_leaf))?,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let actual = actual_stage.metadata()?;
            if actual.dev() != record.device || actual.ino() != record.inode {
                return Err(FsError::UnsafeStorage);
            }
            let content = directories[""].metadata()?;
            record.content_device = Some(content.dev());
            record.content_inode = Some(content.ino());
            record.status = "prepared".into();
            manifest(&stage, &record)?;
            core.journal.db.execute(
                "UPDATE materializations SET manifest=? WHERE id=?",
                params![json(&record)?, id.as_str()],
            )?;
            crate::faults::capture_barrier("materialize-publish", 1)?;
            crate::faults::hit("materialize-publish")?;
            publish(&stage, &parent, leaf)?;
            Ok(MaterializationResult {
                revision: revision.clone(),
                destination: destination.into(),
                verified_bytes,
            })
        })();
        match &result {
            Ok(_) => record.status = "ready".into(),
            Err(e) => {
                record.status = "failed".into();
                record.error = Some(e.code().into());
            }
        }
        // Retain the fd-owned manifest even if its visible path was externally replaced.
        let manifest_result = manifest(&stage, &record);
        core.journal.db.execute(
            "UPDATE materializations SET manifest=? WHERE id=?",
            params![json(&record)?, id.as_str()],
        )?;
        manifest_result?;
        result
    }
}
