//! Independent plaintext archives. Archived metadata is evidence, never current authority.
use crate::{
    capture::{absolute_native, directory, names},
    engine::{json, lock, Core},
    objects::{name, open_at},
    permissions as perm, *,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const ARCHIVE_FORMAT: &str = "magus-fs-archive/v1";
pub(crate) const MAX_ARCHIVE_DESCRIPTORS: u64 = 64 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedHistoryGrant {
    pub principal: PrincipalId,
    pub revision: RevisionId,
    pub entries: Vec<EntryId>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMember {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub format: String,
    pub revision: RevisionId,
    pub members: Vec<ArchiveMember>,
}
#[derive(Debug, Serialize)]
pub struct Verification {
    pub revision: RevisionId,
    pub revisions: usize,
    pub objects: usize,
    pub verified_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMetadata {
    pub path: String,
    pub owner: PrincipalId,
    pub group: GroupId,
    pub mode: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRestorePolicy {
    pub authorities: Vec<Authority>,
    pub actor: Actor,
    pub owner: PrincipalId,
    pub group: GroupId,
    pub file_mode: u16,
    pub directory_mode: u16,
    #[serde(default)]
    pub entries: Vec<ArchiveMetadata>,
}
#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub source_revision: RevisionId,
    pub destination: PathBuf,
    pub verified_bytes: u64,
    pub head_changed: bool,
    pub derived_revision: RevisionId,
    pub recovery_state: PathBuf,
}
fn digest(bytes: &[u8]) -> String {
    crate::model::hex(&Sha256::digest(bytes))
}
fn member_path(kind: &str, id: &str) -> String {
    format!("{kind}/{}", id.trim_start_matches("sha256:"))
}
fn write_file(dir: &File, leaf: &str, bytes: &[u8]) -> Result<(), FsError> {
    let mut f = open_at(
        dir.as_raw_fd(),
        &name(OsStr::new(leaf))?,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    f.write_all(bytes)?;
    f.sync_all()?;
    dir.sync_all()?;
    Ok(())
}
fn read_file(dir: &File, leaf: &str, limit: u64) -> Result<Vec<u8>, FsError> {
    let mut f = open_at(
        dir.as_raw_fd(),
        &name(OsStr::new(leaf))?,
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?;
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(FsError::UnsafeStorage);
    }
    if m.len() > limit {
        return Err(FsError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(FsError::LimitExceeded);
    }
    if bytes.len() as u64 != m.len() {
        return Err(FsError::CorruptObject);
    }
    Ok(bytes)
}
fn child(dir: &File, leaf: &str) -> Result<File, FsError> {
    open_at(
        dir.as_raw_fd(),
        &name(OsStr::new(leaf))?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
}
fn exact_names(dir: &File, expected: BTreeSet<String>) -> Result<(), FsError> {
    let actual = names(dir)?
        .into_iter()
        .map(|n| String::from_utf8(n).map_err(|_| FsError::InvalidPath))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected {
        return Err(FsError::InvalidDescriptor);
    }
    Ok(())
}
struct VerifiedArchive {
    manifest: ArchiveManifest,
    revisions: BTreeMap<RevisionId, Revision>,
    objects: BTreeMap<ObjectId, u64>,
    object_dir: File,
    bytes: u64,
}
impl VerifiedArchive {
    fn open(path: &Path) -> Result<Self, FsError> {
        let root = directory(path)?;
        exact_names(
            &root,
            BTreeSet::from(["archive.json".into(), "revisions".into(), "objects".into()]),
        )?;
        let bytes = read_file(&root, "archive.json", MAX_DESCRIPTOR as u64)?;
        let manifest: ArchiveManifest =
            serde_json::from_slice(&bytes).map_err(|_| FsError::InvalidDescriptor)?;
        if manifest.format != ARCHIVE_FORMAT {
            return Err(FsError::UnsupportedFormat);
        }
        if manifest.members.len() > MAX_ENTRIES
            || serde_json::to_vec(&manifest).map_err(|_| FsError::InvalidDescriptor)? != bytes
        {
            return Err(FsError::InvalidDescriptor);
        }
        let revision_dir = child(&root, "revisions")?;
        let object_dir = child(&root, "objects")?;
        let mut revisions = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let mut revision_names = BTreeSet::new();
        let mut object_names = BTreeSet::new();
        let mut previous = None;
        let mut total = 0u64;
        let mut descriptors = 0u64;
        for member in &manifest.members {
            if previous.is_some_and(|p: &str| p >= member.path.as_str()) {
                return Err(FsError::InvalidDescriptor);
            }
            previous = Some(&member.path);
            let (kind, leaf) = member.path.split_once('/').ok_or(FsError::InvalidPath)?;
            let id = ObjectId::parse(format!("sha256:{leaf}"))?;
            if member.sha256 != leaf {
                return Err(FsError::CorruptObject);
            }
            let (dir, limit) = match kind {
                "objects" => (&object_dir, MAX_CHUNK),
                "revisions" => (&revision_dir, MAX_DESCRIPTOR as u64),
                _ => return Err(FsError::InvalidPath),
            };
            if member.length > limit {
                return Err(FsError::LimitExceeded);
            }
            if kind == "revisions" {
                descriptors = descriptors
                    .checked_add(member.length)
                    .ok_or(FsError::LimitExceeded)?;
                if descriptors > MAX_ARCHIVE_DESCRIPTORS {
                    return Err(FsError::LimitExceeded);
                }
            }
            let body = read_file(dir, leaf, member.length)?;
            if body.len() as u64 != member.length || digest(&body) != member.sha256 {
                return Err(FsError::CorruptObject);
            }
            total = total
                .checked_add(member.length)
                .ok_or(FsError::LimitExceeded)?;
            if kind == "objects" {
                object_names.insert(leaf.into());
                objects.insert(id, member.length);
            } else {
                let r = decode_revision(&body)?;
                if encode_revision(&r)? != body {
                    return Err(FsError::InvalidDescriptor);
                }
                let id = RevisionId::parse(format!("sha256:{leaf}"))?;
                if revision_id(&r)? != id {
                    return Err(FsError::CorruptObject);
                }
                revision_names.insert(leaf.into());
                revisions.insert(id, r);
            }
        }
        exact_names(&revision_dir, revision_names)?;
        exact_names(&object_dir, object_names)?;
        let mut pending = vec![manifest.revision.clone()];
        let mut reachable = BTreeSet::new();
        let mut required = BTreeMap::new();
        while let Some(id) = pending.pop() {
            if !reachable.insert(id.clone()) {
                continue;
            }
            let r = revisions.get(&id).ok_or(FsError::InvalidDescriptor)?;
            pending.extend(r.parents.iter().cloned());
            for (object, size) in crate::cache::closure(&r.tree) {
                if required
                    .insert(object, size)
                    .is_some_and(|prior| prior != size)
                {
                    return Err(FsError::CorruptObject);
                }
            }
        }
        for r in revisions.values() {
            if let Some(provenance) = &r.restoration {
                validate_restoration_parents(
                    r,
                    revisions
                        .get(&provenance.source_revision)
                        .ok_or(FsError::InvalidDescriptor)?,
                    revisions
                        .get(r.parents.first().ok_or(FsError::InvalidDescriptor)?)
                        .ok_or(FsError::InvalidDescriptor)?,
                )?;
            }
        }
        if reachable.len() != revisions.len() || required != objects {
            return Err(FsError::InvalidDescriptor);
        }
        Ok(Self {
            manifest,
            revisions,
            objects,
            object_dir,
            bytes: total,
        })
    }
    fn verification(&self) -> Verification {
        Verification {
            revision: self.manifest.revision.clone(),
            revisions: self.revisions.len(),
            objects: self.objects.len(),
            verified_bytes: self.bytes,
        }
    }
}
pub fn verify_archive(path: impl AsRef<Path>) -> Result<Verification, FsError> {
    Ok(VerifiedArchive::open(path.as_ref())?.verification())
}

pub(crate) fn history_access(
    core: &Core,
    revision: &RevisionId,
    r: &Revision,
    actor: &Actor,
) -> Result<(), FsError> {
    let a = perm::authority(&core.config, actor)?;
    let live = core.working.as_ref().map(|w| &w.tree).unwrap_or(&r.tree);
    for e in std::iter::once(perm::root_entry(&r.tree)).chain(r.tree.entries.iter().cloned()) {
        let current = if e.id == live.root.id {
            Some(perm::root_entry(live))
        } else {
            live.entries.iter().find(|v| v.id == e.id).cloned()
        };
        if let Some(current) = current {
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
        } else if !core.config.retained_history_grants.iter().any(|g| {
            &g.principal == actor.principal()
                && &g.revision == revision
                && g.entries.contains(&e.id)
        }) {
            return Err(FsError::PermissionDenied);
        }
    }
    Ok(())
}
impl Replica {
    pub fn export(
        &self,
        revision: &RevisionId,
        destination: impl AsRef<Path>,
        actor: Actor,
    ) -> Result<ArchiveManifest, FsError> {
        let destination = destination.as_ref();
        absolute_native(destination)?;
        let mut core = lock(&self.core)?;
        core.journal.check_content_path(destination)?;
        let mut pending = vec![revision.clone()];
        let mut revisions = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let mut descriptor_bytes = 0u64;
        while let Some(id) = pending.pop() {
            if revisions.contains_key(&id) {
                continue;
            }
            let r = core.revision(&id)?;
            history_access(&core, &id, &r, &actor)?;
            let bytes = encode_revision(&r)?;
            descriptor_bytes += bytes.len() as u64;
            if revisions.len() + objects.len() >= MAX_ENTRIES
                || descriptor_bytes > MAX_ARCHIVE_DESCRIPTORS
            {
                return Err(FsError::LimitExceeded);
            }
            pending.extend(r.parents.clone());
            for (id, size) in crate::cache::closure(&r.tree) {
                if objects.insert(id, size).is_some_and(|old| old != size) {
                    return Err(FsError::CorruptObject);
                }
            }
            revisions.insert(id, bytes);
        }
        if revisions.len() + objects.len() > MAX_ENTRIES {
            return Err(FsError::LimitExceeded);
        }
        // Exclusive, external archive directory. A failure leaves no archive.json completion marker.
        let store = ObjectStore::create_owned(
            destination,
            ObjectLimits {
                content_roots: core.config.content_roots.clone(),
                ..ObjectLimits::default()
            },
        )?;
        let root = store.directory();
        for leaf in ["revisions", "objects"] {
            if unsafe { libc::mkdirat(root.as_raw_fd(), name(OsStr::new(leaf))?.as_ptr(), 0o700) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let revdir = child(root, "revisions")?;
        let objdir = child(root, "objects")?;
        let mut members = vec![];
        for (id, bytes) in revisions {
            let path = member_path("revisions", id.as_str());
            write_file(&revdir, path.split('/').nth(1).unwrap(), &bytes)?;
            members.push(ArchiveMember {
                path,
                length: bytes.len() as u64,
                sha256: digest(&bytes),
            });
        }
        for (id, size) in objects {
            let bytes = core.fetch(&id, size, Instant::now() + Duration::from_millis(4500))?;
            let path = member_path("objects", id.as_str());
            write_file(&objdir, path.split('/').nth(1).unwrap(), &bytes)?;
            members.push(ArchiveMember {
                path,
                length: size,
                sha256: digest(&bytes),
            });
        }
        members.sort_by(|a, b| a.path.cmp(&b.path));
        let manifest = ArchiveManifest {
            format: ARCHIVE_FORMAT.into(),
            revision: revision.clone(),
            members,
        };
        store.assert_path(destination)?;
        core.journal.check_content_path(destination)?;
        write_file(root, "archive.json", &json(&manifest)?)?;
        verify_archive(destination)?;
        store.assert_path(destination)?;
        core.journal.check_content_path(destination)?;
        Ok(manifest)
    }
    pub fn set_retained_history_grants(
        &self,
        grants: Vec<RetainedHistoryGrant>,
        actor: Actor,
    ) -> Result<(), FsError> {
        let mut core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        if !core
            .config
            .history_administrators
            .contains(actor.principal())
        {
            return Err(FsError::PermissionDenied);
        }
        let mut seen = BTreeSet::new();
        for grant in &grants {
            perm::authority(&core.config, &Actor::new(grant.principal.clone()))?;
            let r = core.revision(&grant.revision)?;
            if grant.entries.is_empty() {
                return Err(FsError::InvalidDescriptor);
            }
            for id in &grant.entries {
                if !seen.insert((grant.principal.clone(), grant.revision.clone(), id.clone()))
                    || (*id != r.tree.root.id && !r.tree.entries.iter().any(|e| &e.id == id))
                {
                    return Err(FsError::InvalidDescriptor);
                }
            }
        }
        let mut config = core.config.clone();
        config.retained_history_grants = grants;
        let bytes = json(&config)?;
        let tx = core.journal.db.transaction()?;
        tx.execute(
            "UPDATE configuration SET value=? WHERE singleton=1",
            [bytes],
        )?;
        tx.commit()?;
        core.config = config;
        Ok(())
    }
}
pub fn restore_archive(
    path: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: ArchiveRestorePolicy,
) -> Result<RestoreResult, FsError> {
    let path = path.as_ref();
    let destination = destination.as_ref();
    absolute_native(destination)?;
    let archive = VerifiedArchive::open(path)?;
    let mut revision = archive.revisions[&archive.manifest.revision].clone();
    let mut config = ReplicaConfig {
        replica: ReplicaId::random()?,
        authorities: policy.authorities.clone(),
        content_roots: vec![destination.into(), path.into()],
        cache_bytes: archive.objects.values().sum::<u64>().max(1),
        history_administrators: vec![],
        retained_history_grants: vec![],
    };
    let a = perm::authority(&config, &policy.actor)?;
    perm::mode(policy.file_mode)?;
    perm::mode(policy.directory_mode)?;
    let mut overrides = BTreeMap::new();
    for e in &policy.entries {
        if !e.path.is_empty() {
            crate::paths::validate_path(&e.path)?;
        }
        perm::entry(&revision.tree, &e.path)?;
        perm::mode(e.mode)?;
        if overrides.insert(e.path.clone(), e).is_some() {
            return Err(FsError::InvalidDescriptor);
        }
    }
    let mut metadata = BTreeMap::new();
    for e in std::iter::once(perm::root_entry(&revision.tree))
        .chain(revision.tree.entries.iter().cloned())
    {
        let p = overrides
            .get(&e.path)
            .map(|m| (*m).clone())
            .unwrap_or(ArchiveMetadata {
                path: e.path.clone(),
                owner: policy.owner.clone(),
                group: policy.group.clone(),
                mode: if e.content == EntryContent::Directory {
                    policy.directory_mode
                } else {
                    policy.file_mode
                },
            });
        if p.owner != *policy.actor.principal() {
            perm::ownership_change(&config, a, &p.owner, &p.group)?;
        } else if !a.groups.contains(&p.group) {
            return Err(FsError::PermissionDenied);
        }
        if !config.authorities.iter().any(|v| v.principal == p.owner)
            || !config
                .authorities
                .iter()
                .any(|v| v.primary_group == p.group)
        {
            return Err(FsError::MappingBlocked);
        }
        let mut current = e.clone();
        current.owner = p.owner.clone();
        current.group = p.group.clone();
        current.mode = p.mode;
        // Destination policy must permit its actor to materialize the resulting view.
        perm::access(
            a,
            &current,
            if e.content == EntryContent::Directory {
                7
            } else {
                6
            },
        )?;
        metadata.insert(e.path, p);
    }
    let m = &metadata[""];
    revision.tree.root.owner = m.owner.clone();
    revision.tree.root.group = m.group.clone();
    revision.tree.root.mode = m.mode;
    for e in &mut revision.tree.entries {
        let m = &metadata[&e.path];
        e.owner = m.owner.clone();
        e.group = m.group.clone();
        e.mode = m.mode;
    }
    revision.parents.clear();
    revision.format = FORMAT.into();
    revision.restoration = None;
    revision.replica = config.replica.clone();
    revision.principal = policy.actor.principal().clone();
    revision.operation = OperationId::random()?;
    let state = destination
        .parent()
        .ok_or(FsError::InvalidPath)?
        .join(format!(
            ".magus-archive-recovery-{}",
            OperationId::random()?
                .as_str()
                .trim_start_matches("operation:")
        ));
    // Protect both archive and intended output from new control storage through native ancestry.
    let owned = ObjectStore::create_owned(
        &state,
        ObjectLimits {
            content_roots: config.content_roots.clone(),
            ..ObjectLimits::default()
        },
    )?;
    owned.assert_path(&state)?;
    // Replica owns all new recovery state, never the original journal/cache.
    config.content_roots.push(path.into());
    let rep = Replica::open(&state, config)?;
    {
        let core = lock(&rep.core)?;
        for (id, size) in &archive.objects {
            let body = read_file(
                &archive.object_dir,
                id.as_str().trim_start_matches("sha256:"),
                *size,
            )?;
            if body.len() as u64 != *size || ObjectId::for_bytes(&body)? != *id {
                return Err(FsError::CorruptObject);
            }
            core.objects.install(&body)?;
        }
    }
    let id = revision_id(&revision)?;
    rep.import_revision(
        ImportDescriptor {
            expected: id.clone(),
            bytes: encode_revision(&revision)?,
        },
        ChunkSource::Unavailable,
    )?;
    let result = rep.materialize(
        &id,
        destination,
        MaterializationMapping {
            actor: policy.actor,
        },
    )?;
    Ok(RestoreResult {
        source_revision: archive.manifest.revision,
        destination: result.destination,
        verified_bytes: result.verified_bytes,
        head_changed: false,
        derived_revision: id,
        recovery_state: state,
    })
}
