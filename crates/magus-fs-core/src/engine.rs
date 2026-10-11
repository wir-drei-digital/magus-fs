use crate::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaConfig {
    pub replica: ReplicaId,
    pub authorities: Vec<Authority>,
    pub content_roots: Vec<PathBuf>,
    pub cache_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history_administrators: Vec<PrincipalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_history_grants: Vec<RetainedHistoryGrant>,
}
#[derive(Clone, Debug)]
pub struct ImportDescriptor {
    pub expected: RevisionId,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    pub captured_at_ns: u64,
    pub coverage: Vec<String>,
    pub provenance: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Append,
}
/// Atomic working metadata for scheduling only; does not verify content or readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulingSnapshot {
    pub head: Option<RevisionId>,
    pub generation: u64,
    pub dirty: bool,
}
#[derive(Clone, Debug)]
pub struct ReplicaStatus {
    pub head: Option<RevisionId>,
    pub selected_base: Option<RevisionId>,
    pub generation: u64,
    pub dirty: bool,
    pub resident_bytes: u64,
    pub missing_bytes: u64,
    pub full_ready: bool,
    pub pinned: Vec<RevisionId>,
    pub operations: Vec<OperationStatus>,
}
#[derive(Clone, Debug)]
pub struct OperationStatus {
    pub operation: OperationId,
    pub state: String,
    pub error: Option<String>,
}
use crate::{cache, journal::Journal, permissions as perm};
use rusqlite::{params, OptionalExtension};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Working {
    #[serde(default)]
    pub(crate) epoch: u64,
    #[serde(default)]
    pub(crate) remote_source: Option<crate::protocol::RemoteSourceId>,
    #[serde(default)]
    pub(crate) applied: bool,
    pub(crate) base: RevisionId,
    pub(crate) head: RevisionId,
    pub(crate) generation: u64,
    pub(crate) dirty: bool,
    pub(crate) umask: u16,
    pub(crate) tree: Tree,
    pub(crate) orphans: Vec<Entry>,
}
pub(crate) struct Core {
    pub(crate) journal: Journal,
    pub(crate) objects: ObjectStore,
    pub(crate) config: ReplicaConfig,
    pub(crate) working: Option<Working>,
    handles: Vec<Weak<HandleData>>,
    pub(crate) epochs: BTreeMap<u64, Working>,
    /// Derived from committed authority history; rebuilt once on reopen.
    pub(crate) remote_entries: BTreeSet<EntryId>,
    pub(crate) remote_fetcher: Option<Arc<dyn RemoteFetcher>>,
}
#[derive(Clone)]
pub struct Replica {
    pub(crate) core: Arc<Mutex<Core>>,
}
#[derive(Clone)]
pub struct Workspace {
    core: Arc<Mutex<Core>>,
    actor: Actor,
    read_only: bool,
    view: Option<Revision>,
    token: OperationId,
}
struct HandleData {
    entry: Entry,
    mode: OpenMode,
    workspace: OperationId,
    generation: u64,
    epoch: u64,
}
#[derive(Clone)]
pub struct Handle {
    inner: Arc<HandleData>,
}
impl Handle {
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }
    pub fn entry_id(&self) -> &EntryId {
        &self.inner.entry.id
    }
    pub fn generation(&self) -> u64 {
        self.inner.generation
    }
}
pub(crate) fn lock(core: &Arc<Mutex<Core>>) -> Result<MutexGuard<'_, Core>, FsError> {
    if crate::remote_source::fetching() {
        return Err(FsError::ReplicaBusy);
    }
    let guard = core.lock().map_err(|_| FsError::ReplicaBusy)?;
    guard.journal.guard()?;
    Ok(guard)
}
pub(crate) fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, FsError> {
    let bytes = serde_json::to_vec(value).map_err(|_| FsError::InvalidDescriptor)?;
    if bytes.len() > MAX_DESCRIPTOR * 2 {
        return Err(FsError::LimitExceeded);
    }
    Ok(bytes)
}
pub(crate) fn from_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, FsError> {
    if bytes.len() > MAX_DESCRIPTOR * 2 {
        return Err(FsError::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| FsError::InvalidDescriptor)
}
impl Core {
    pub(crate) fn retain_epoch(&mut self, old: Working) {
        self.handles.retain(|h| h.strong_count() > 0);
        let live: BTreeSet<_> = self
            .handles
            .iter()
            .filter_map(Weak::upgrade)
            .map(|h| h.epoch)
            .collect();
        self.epochs.retain(|epoch, _| live.contains(epoch));
        if live.contains(&old.epoch) {
            self.epochs.insert(old.epoch, old);
        }
    }
    pub(crate) fn working(&self) -> Result<&Working, FsError> {
        self.working.as_ref().ok_or(FsError::BaseMismatch)
    }
    pub(crate) fn revision(&self, id: &RevisionId) -> Result<Revision, FsError> {
        let bytes = self
            .journal
            .db
            .query_row(
                "SELECT descriptor FROM revisions WHERE id=?",
                [id.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(FsError::NotFound)?;
        let r = decode_revision(&bytes)?;
        if revision_id(&r)? != *id {
            return Err(FsError::CorruptObject);
        }
        Ok(r)
    }
    fn save(&mut self, mut next: Working) -> Result<(), FsError> {
        validate_tree(&next.tree)?;
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        next.dirty = true;
        next.applied = false;
        self.handles.retain(|h| h.strong_count() > 0);
        let live: BTreeSet<_> = self
            .handles
            .iter()
            .filter_map(Weak::upgrade)
            .map(|h| h.entry.id.clone())
            .collect();
        next.orphans.retain(|e| live.contains(&e.id));
        let bytes = json(&next)?;
        self.journal.guard()?;
        let tx = self
            .journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("INSERT OR REPLACE INTO working VALUES(1,?)", [bytes])?;
        crate::faults::hit("db-commit")?;
        tx.commit()?;
        self.working = Some(next);
        Ok(())
    }
    pub(crate) fn source(&self, id: &ObjectId) -> Result<Option<(u64, ChunkSource)>, FsError> {
        let value = self
            .journal
            .db
            .query_row(
                "SELECT size,source FROM sources WHERE object=?",
                [id.as_str()],
                |r| Ok((r.get::<_, u32>(0)? as u64, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        value
            .map(|(size, b)| Ok((size, from_json(&b)?)))
            .transpose()
    }
    fn inventory(&mut self) -> Result<Vec<(ObjectId, u64)>, FsError> {
        let inventory = self.objects.inventory()?;
        for (id, size) in &inventory {
            if self.objects.read_verified(id)?.len() as u64 != *size {
                return Err(FsError::CorruptObject);
            }
        }
        let tx = self.journal.db.transaction()?;
        tx.execute("DELETE FROM cache", [])?;
        for (id, size) in &inventory {
            tx.execute(
                "INSERT INTO cache VALUES(?,?)",
                params![id.as_str(), *size as u32],
            )?;
        }
        tx.commit()?;
        Ok(inventory)
    }
    fn protected(&self) -> Result<BTreeSet<ObjectId>, FsError> {
        let mut protected = self.sync_roots()?;
        protected.extend(self.native_roots()?);
        if let Some(w) = &self.working {
            if w.dirty {
                protected.extend(cache::object_set(&w.tree));
            }
        }
        for h in self.handles.iter().filter_map(Weak::upgrade) {
            if let Some(epoch) = self.epochs.get(&h.epoch) {
                protected.extend(cache::object_set(&epoch.tree));
                for e in &epoch.orphans {
                    let mut ids = BTreeMap::new();
                    cache::entry_objects(e, &mut ids);
                    protected.extend(ids.into_keys());
                }
            }
            let mut ids = BTreeMap::new();
            cache::entry_objects(&h.entry, &mut ids);
            protected.extend(ids.into_keys());
            if let Some(w) = &self.working {
                if let Some(e) = w
                    .tree
                    .entries
                    .iter()
                    .chain(&w.orphans)
                    .find(|e| e.id == h.entry.id)
                {
                    let mut ids = BTreeMap::new();
                    cache::entry_objects(e, &mut ids);
                    protected.extend(ids.into_keys());
                }
            }
        }
        let mut statement = self.journal.db.prepare("SELECT revision FROM pins")?;
        let pins = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        protected.extend(self.pinned_closure(&pins)?);
        let mut statement = self
            .journal
            .db
            .prepare("SELECT candidate FROM operations WHERE state IN ('pending','failed')")?;
        for bytes in statement.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            protected.extend(cache::object_set(&decode_revision(&bytes?)?.tree));
        }
        // Pending and failed candidates remain independent roots even after further working edits.
        Ok(protected)
    }
    fn referenced(&self, protected: &BTreeSet<ObjectId>) -> Result<BTreeSet<ObjectId>, FsError> {
        let mut referenced = protected.clone();
        if let Some(working) = &self.working {
            referenced.extend(cache::object_set(&working.tree));
        }
        // All retained revisions are roots for local-only bytes, even when they are
        // neither the head nor pinned. Source registration alone is not a root.
        let mut statement = self.journal.db.prepare("SELECT id FROM revisions")?;
        for id in statement.query_map([], |row| row.get::<_, String>(0))? {
            referenced.extend(cache::object_set(
                &self.revision(&RevisionId::parse(id?)?)?.tree,
            ));
        }
        Ok(referenced)
    }
    pub(crate) fn recovery_closure(
        &self,
        selected: &RevisionId,
    ) -> Result<BTreeMap<ObjectId, u64>, FsError> {
        let mut pending = vec![selected.clone()];
        let mut seen = BTreeSet::new();
        let mut objects = BTreeMap::new();
        let mut descriptor_bytes = 0u64;
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let revision = self.revision(&id)?;
            descriptor_bytes += encode_revision(&revision)?.len() as u64;
            if seen.len() + objects.len() > MAX_ENTRIES
                || descriptor_bytes > crate::archive::MAX_ARCHIVE_DESCRIPTORS
            {
                return Err(FsError::LimitExceeded);
            }
            for (object, size) in cache::closure(&revision.tree) {
                if objects.insert(object, size).is_some_and(|old| old != size) {
                    return Err(FsError::CorruptObject);
                }
            }
            if seen.len() + objects.len() > MAX_ENTRIES {
                return Err(FsError::LimitExceeded);
            }
            pending.extend(revision.parents);
        }
        Ok(objects)
    }
    fn pinned_closure(&self, pins: &[String]) -> Result<BTreeSet<ObjectId>, FsError> {
        let mut pending = pins
            .iter()
            .map(|s| RevisionId::parse(s.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = BTreeSet::new();
        let mut objects = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if seen.insert(id.clone()) {
                let r = self.revision(&id)?;
                pending.extend(r.parents);
                objects.extend(cache::object_set(&r.tree));
            }
        }
        Ok(objects)
    }
    fn prune(&mut self, dry_run: bool) -> Result<PruneReport, FsError> {
        let protected = self.protected()?;
        let referenced = self.referenced(&protected)?;
        let inventory = self.inventory()?;
        let pins = self
            .journal
            .db
            .prepare("SELECT revision FROM pins ORDER BY revision")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let pinned = self.pinned_closure(&pins)?;
        let revisions = self
            .journal
            .db
            .prepare("SELECT id FROM revisions ORDER BY id")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let sources = self
            .journal
            .db
            .prepare("SELECT object,size,source FROM sources ORDER BY object")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let operation_roots=self.journal.db.prepare("SELECT operation,state FROM operations WHERE state IN ('pending','failed') ORDER BY operation")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<Result<Vec<_>,_>>()?;
        let handle_roots = self
            .handles
            .iter()
            .filter_map(Weak::upgrade)
            .map(|h| (h.entry.id.clone(), h.generation))
            .collect::<Vec<_>>();
        let token = RevisionId::digest(&json(&(
            self.working.as_ref().map(|w| w.generation),
            &inventory,
            &protected,
            &referenced,
            &revisions,
            &pins,
            &sources,
            &operation_roots,
            &handle_roots,
        ))?)?
        .as_str()
        .to_owned();
        let mut report = PruneReport {
            evictable: vec![],
            reclaimable_bytes: 0,
            reachable_bytes: 0,
            candidate_bytes: 0,
            pinned_bytes: 0,
            protected_bytes: 0,
            token,
            reclaimed: vec![],
            reclaimed_bytes: 0,
        };
        for (id, size) in &inventory {
            if referenced.contains(id) {
                report.reachable_bytes += size;
            }
            if pinned.contains(id) {
                report.pinned_bytes += size;
            }
            if protected.contains(id) {
                report.protected_bytes += size;
            }
            if !referenced.contains(id)
                || (!protected.contains(id)
                    && self
                        .source(id)?
                        .is_some_and(|(_, source)| source.refetchable()))
            {
                report.candidate_bytes += size;
                report.evictable.push(id.clone());
            }
        }
        report.reclaimable_bytes = report.candidate_bytes;
        if !dry_run {
            // Verify *every* still-referenced source before removing any candidate. A registered
            // but expired base is not a replacement copy. Keep all candidates on failure.
            for id in &report.evictable {
                if referenced.contains(id) {
                    let (size, source) = self
                        .source(id)?
                        .ok_or_else(|| cache::unavailable(id, SourceFailure::Missing))?;
                    if let ChunkSource::Local { path } = &source {
                        use std::os::unix::fs::MetadataExt;
                        let native = crate::capture::directory(path)
                            .map_err(|e| match e {
                                FsError::Io(e) => cache::unavailable(id, SourceFailure::Io(e)),
                                other => other,
                            })?
                            .metadata()?;
                        let own = self.objects.directory().metadata()?;
                        if native.dev() == own.dev() && native.ino() == own.ino() {
                            return Err(cache::unavailable(id, SourceFailure::Missing));
                        }
                    }
                    self.fetch_source(
                        &source,
                        id,
                        size,
                        Instant::now() + Duration::from_millis(4500),
                    )?;
                }
            }
            for id in &report.evictable {
                self.objects.evict(id)?;
                report.reclaimed.push(id.clone());
            }
            report.reclaimed_bytes = report.candidate_bytes;
            self.inventory()?;
        }
        Ok(report)
    }
    pub(crate) fn reserve(&mut self, objects: &BTreeMap<ObjectId, u64>) -> Result<(), FsError> {
        let inventory = self.objects.inventory()?;
        let existing: BTreeSet<_> = inventory.iter().map(|(id, _)| id.clone()).collect();
        let additional: u64 = objects
            .iter()
            .filter(|(id, _)| !existing.contains(*id))
            .map(|(_, size)| size)
            .sum();
        let resident = self.objects.occupied_bytes()?;
        if resident
            .checked_add(additional)
            .ok_or(FsError::Backpressure)?
            > self.config.cache_bytes
        {
            return Err(FsError::Backpressure);
        }
        Ok(())
    }
    fn fetch_source(
        &self,
        source: &ChunkSource,
        id: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError> {
        if let ChunkSource::Remote { source } = source {
            let fetcher = self
                .remote_fetcher
                .as_ref()
                .ok_or_else(|| cache::unavailable(id, SourceFailure::Missing))?;
            crate::remote_source::fetch(fetcher.as_ref(), source, id, size, deadline)
        } else {
            source.fetch(id, size, deadline)
        }
    }
    pub(crate) fn fetch_from(
        &mut self,
        source: &ChunkSource,
        id: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError> {
        match self.objects.read_verified(id) {
            Ok(bytes) => {
                if bytes.len() as u64 != size {
                    return Err(FsError::CorruptObject);
                }
                return Ok(bytes);
            }
            Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.reserve(&BTreeMap::from([(id.clone(), size)]))?;
        let bytes = self.fetch_source(source, id, size, deadline)?;
        self.objects.install(&bytes)?;
        self.journal.db.execute(
            "INSERT OR REPLACE INTO cache VALUES(?,?)",
            params![id.as_str(), size as u32],
        )?;
        Ok(bytes)
    }
    pub(crate) fn fetch(
        &mut self,
        id: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError> {
        match self.objects.read_verified(id) {
            Ok(bytes) => {
                if bytes.len() as u64 != size {
                    return Err(FsError::CorruptObject);
                }
                return Ok(bytes);
            }
            Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let (source_size, source) = self
            .source(id)?
            .ok_or_else(|| cache::unavailable(id, SourceFailure::Missing))?;
        if source_size != size {
            return Err(FsError::CorruptObject);
        }
        self.reserve(&BTreeMap::from([(id.clone(), size)]))?;
        let bytes = self.fetch_source(&source, id, size, deadline)?;
        self.objects.install(&bytes)?;
        self.journal.db.execute(
            "INSERT OR REPLACE INTO cache VALUES(?,?)",
            params![id.as_str(), size as u32],
        )?;
        Ok(bytes)
    }
    pub(crate) fn failed(&self, operation: &OperationId, error: &FsError) -> Result<(), FsError> {
        self.journal.db.execute(
            "UPDATE operations SET state='failed',error=? WHERE operation=? AND state!='committed'",
            params![error.code(), operation.as_str()],
        )?;
        Ok(())
    }
}
impl Replica {
    pub fn open(state: impl AsRef<Path>, config: ReplicaConfig) -> Result<Self, FsError> {
        if config.cache_bytes == 0 {
            return Err(FsError::Backpressure);
        }
        let mut principals = BTreeSet::new();
        let mut uids = BTreeSet::new();
        let mut gids = BTreeMap::new();
        let mut groups = BTreeMap::new();
        for a in &config.authorities {
            if !principals.insert(a.principal.clone())
                || !uids.insert(a.uid)
                || !a.groups.contains(&a.primary_group)
            {
                return Err(FsError::ConfigMismatch);
            }
            if let Some(gid) = groups.insert(a.primary_group.clone(), a.gid) {
                if gid != a.gid {
                    return Err(FsError::ConfigMismatch);
                }
            }
            if let Some(group) = gids.insert(a.gid, a.primary_group.clone()) {
                if group != a.primary_group {
                    return Err(FsError::ConfigMismatch);
                }
            }
        }
        let admins = config
            .history_administrators
            .iter()
            .collect::<BTreeSet<_>>();
        if admins.len() != config.history_administrators.len()
            || admins.iter().any(|p| !principals.contains(*p))
        {
            return Err(FsError::ConfigMismatch);
        }
        if principals.is_empty() {
            return Err(FsError::ConfigMismatch);
        }
        let journal = Journal::open(state.as_ref(), &config)?;
        Self::from_journal(state.as_ref(), config, journal)
    }
    pub(crate) fn from_journal(
        state: &Path,
        config: ReplicaConfig,
        journal: Journal,
    ) -> Result<Self, FsError> {
        let objects = ObjectStore::open(
            state.join("objects"),
            ObjectLimits {
                content_roots: config.content_roots.clone(),
                ..ObjectLimits::default()
            },
        )?;
        let value = journal
            .db
            .query_row("SELECT value FROM working WHERE singleton=1", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?;
        let working = value.map(|b| from_json::<Working>(&b)).transpose()?;
        if let Some(w) = &working {
            validate_tree(&w.tree)?;
            if w.umask != 0o022 {
                return Err(FsError::ConfigMismatch);
            }
        }
        let mut core = Core {
            journal,
            objects,
            config,
            working,
            handles: vec![],
            epochs: BTreeMap::new(),
            remote_entries: BTreeSet::new(),
            remote_fetcher: None,
        };
        let observations = core
            .journal
            .db
            .prepare(
                "SELECT DISTINCT revision FROM live_authority_history WHERE revision IS NOT NULL",
            )?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for id in observations {
            let tree = core.revision(&RevisionId::parse(id)?)?.tree;
            core.remote_entries.insert(tree.root.id);
            core.remote_entries
                .extend(tree.entries.into_iter().map(|e| e.id));
        }
        // Unlinked open handles die with their process; immutable bodies are retained until explicit pruning.
        if let Some(w) = &mut core.working {
            w.orphans.clear();
        }
        core.inventory()?;
        if core.objects.occupied_bytes()? > core.config.cache_bytes {
            return Err(FsError::Backpressure);
        }
        Ok(Self {
            core: Arc::new(Mutex::new(core)),
        })
    }
    pub fn import_revision(
        &self,
        descriptor: ImportDescriptor,
        source: ChunkSource,
    ) -> Result<RevisionId, FsError> {
        let r = decode_revision(&descriptor.bytes)?;
        let canonical = encode_revision(&r)?;
        if canonical != descriptor.bytes {
            return Err(FsError::InvalidDescriptor);
        }
        let id = revision_id(&r)?;
        if descriptor.expected != id {
            return Err(FsError::CorruptObject);
        }
        source.validate()?;
        let mut core = lock(&self.core)?;
        if let Some(provenance) = &r.restoration {
            validate_restoration_parents(
                &r,
                &core.revision(&provenance.source_revision)?,
                &core.revision(r.parents.first().ok_or(FsError::InvalidDescriptor)?)?,
            )?;
        }
        for (object, size) in cache::closure(&r.tree) {
            match core.objects.read_verified(&object) {
                Ok(bytes) => {
                    if bytes.len() as u64 != size {
                        return Err(FsError::CorruptObject);
                    }
                }
                Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        core.journal.guard()?;
        let tx = core
            .journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO revisions VALUES(?,?)",
            params![id.as_str(), canonical],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO revision_sources VALUES(?,?)",
            params![id.as_str(), json(&source)?],
        )?;
        for (object, size) in cache::closure(&r.tree) {
            let old = tx
                .query_row(
                    "SELECT size FROM sources WHERE object=?",
                    [object.as_str()],
                    |r| r.get::<_, u32>(0),
                )
                .optional()?;
            if old.is_some_and(|old| old as u64 != size) {
                return Err(FsError::CorruptObject);
            }
            // Explicit endpoint imports supersede stale endpoints. Unavailable only registers
            // a missing source; it must not erase an already configured endpoint.
            let statement = if source.refetchable() {
                "INSERT INTO sources VALUES(?,?,?) ON CONFLICT(object) DO UPDATE SET source=excluded.source"
            } else {
                "INSERT OR IGNORE INTO sources VALUES(?,?,?)"
            };
            tx.execute(
                statement,
                params![object.as_str(), size as u32, json(&source)?],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }
    pub fn begin(
        &self,
        base: &RevisionId,
        actor: Actor,
        read_only: bool,
    ) -> Result<Workspace, FsError> {
        let mut core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        let r = core.revision(base)?;
        if !read_only {
            if let Some(w) = &core.working {
                if &w.base != base && &w.head != base {
                    return Err(FsError::BaseMismatch);
                }
            } else {
                let w = Working {
                    epoch: 0,
                    remote_source: core
                        .journal
                        .db
                        .query_row(
                            "SELECT source FROM revision_sources WHERE revision=?",
                            [base.as_str()],
                            |r| r.get::<_, Vec<u8>>(0),
                        )
                        .optional()?
                        .map(|b| from_json::<ChunkSource>(&b))
                        .transpose()?
                        .and_then(|s| match s {
                            ChunkSource::Remote { source } => Some(source),
                            _ => None,
                        }),
                    applied: false,
                    base: base.clone(),
                    head: base.clone(),
                    generation: 0,
                    dirty: false,
                    umask: 0o022,
                    tree: r.tree.clone(),
                    orphans: vec![],
                };
                core.journal
                    .db
                    .execute("INSERT INTO working VALUES(1,?)", [json(&w)?])?;
                core.working = Some(w);
            }
        }
        Ok(Workspace {
            core: self.core.clone(),
            actor,
            read_only,
            view: read_only.then_some(r),
            token: OperationId::random()?,
        })
    }
    pub fn begin_live(
        &self,
        base: &RevisionId,
        actor: Actor,
        read_only: bool,
    ) -> Result<Workspace, FsError> {
        let mut ws = self.begin(base, actor, false)?;
        ws.read_only = read_only;
        let mut core = lock(&self.core)?;
        if core.working()?.remote_source.is_none() {
            if let Some(bytes) = core
                .journal
                .db
                .query_row(
                    "SELECT value FROM sync_binding WHERE singleton=1",
                    [],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?
            {
                let binding: SyncBinding = from_json(&bytes)?;
                let mut w = core.working()?.clone();
                w.remote_source = Some(binding.source);
                core.journal
                    .db
                    .execute("UPDATE working SET value=? WHERE singleton=1", [json(&w)?])?;
                core.working = Some(w);
            }
        }
        Ok(ws)
    }
    /// Inspect scheduling metadata under the owner lock without inventorying cached
    /// bodies. Callers must retain verification at capture/admission/use boundaries.
    pub fn scheduling_snapshot(&self) -> Result<SchedulingSnapshot, FsError> {
        let core = lock(&self.core)?;
        let working = core.working.as_ref();
        Ok(SchedulingSnapshot {
            head: working.map(|w| w.head.clone()),
            generation: working.map(|w| w.generation).unwrap_or(0),
            dirty: working.is_some_and(|w| w.dirty),
        })
    }
    pub fn status(&self) -> Result<ReplicaStatus, FsError> {
        let mut core = lock(&self.core)?;
        let inventory = core.inventory()?;
        let resident: BTreeMap<_, _> = inventory.into_iter().collect();
        let working = core.working.as_ref();
        let closure = working.map(|w| cache::closure(&w.tree)).unwrap_or_default();
        let missing_bytes = closure
            .iter()
            .filter(|(id, _)| !resident.contains_key(*id))
            .map(|(_, s)| s)
            .sum();
        let pinned = core
            .journal
            .db
            .prepare("SELECT revision FROM pins ORDER BY revision")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(RevisionId::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let operations = core
            .journal
            .db
            .prepare("SELECT operation,state,error FROM operations ORDER BY operation")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(operation, state, error)| {
                Ok(OperationStatus {
                    operation: OperationId::parse(operation)?,
                    state,
                    error,
                })
            })
            .collect::<Result<Vec<_>, FsError>>()?;
        Ok(ReplicaStatus {
            head: working.map(|w| w.head.clone()),
            selected_base: working.map(|w| w.base.clone()),
            generation: working.map(|w| w.generation).unwrap_or(0),
            dirty: working.is_some_and(|w| w.dirty),
            resident_bytes: resident.values().sum(),
            missing_bytes,
            full_ready: working.is_some() && missing_bytes == 0,
            pinned,
            operations,
        })
    }
    pub fn history(&self) -> Result<Vec<RevisionId>, FsError> {
        let core = lock(&self.core)?;
        let result = core
            .journal
            .db
            .prepare("SELECT id FROM revisions ORDER BY rowid")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        result.into_iter().map(RevisionId::parse).collect()
    }
    pub fn revision(&self, id: &RevisionId) -> Result<Revision, FsError> {
        lock(&self.core)?.revision(id)
    }
    pub fn pragmas(&self) -> Result<Pragmas, FsError> {
        lock(&self.core)?.journal.pragmas()
    }
    pub fn pin(&self, id: &RevisionId, pin: bool) -> Result<(), FsError> {
        let deadline = Instant::now() + Duration::from_millis(4500);
        let mut core = lock(&self.core)?;
        core.revision(id)?;
        if pin {
            let closure = core.recovery_closure(id)?;
            core.reserve(&closure)?;
            for (object, size) in closure {
                core.fetch(&object, size, deadline)?;
            }
            core.journal
                .db
                .execute("INSERT OR IGNORE INTO pins VALUES(?)", [id.as_str()])?;
        } else {
            core.journal
                .db
                .execute("DELETE FROM pins WHERE revision=?", [id.as_str()])?;
        }
        Ok(())
    }
    pub fn prune(&self, dry_run: bool) -> Result<PruneReport, FsError> {
        if !dry_run {
            return Err(FsError::PruneTokenRequired);
        }
        lock(&self.core)?.prune(true)
    }
    pub fn apply_prune(&self, token: &str) -> Result<PruneReport, FsError> {
        let mut core = lock(&self.core)?;
        let report = core.prune(true)?;
        if report.token != token {
            return Err(FsError::StalePruneToken);
        }
        core.prune(false)
    }
    /// Guarded immutable local authority configuration for native adapter mapping.
    pub fn configuration(&self) -> Result<ReplicaConfig, FsError> {
        Ok(lock(&self.core)?.config.clone())
    }
    /// Apply the same whole-control-root native identity boundary to a mount target.
    pub fn check_content_path(&self, path: &Path) -> Result<(), FsError> {
        lock(&self.core)?.journal.check_content_path(path)
    }
    pub fn actor_for_uid(&self, uid: u32) -> Result<Actor, FsError> {
        lock(&self.core)?
            .config
            .authorities
            .iter()
            .find(|a| a.uid == uid)
            .map(|a| Actor::new(a.principal.clone()))
            .ok_or(FsError::UnknownPrincipal)
    }
    pub fn integrity_check(&self) -> Result<String, FsError> {
        let core = lock(&self.core)?;
        Ok(core
            .journal
            .db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
    }
}
impl Workspace {
    fn tree(&self, core: &Core) -> Result<Tree, FsError> {
        Ok(match &self.view {
            Some(r) => r.tree.clone(),
            None => core.working()?.tree.clone(),
        })
    }
    fn actor<'a>(&self, core: &'a Core) -> Result<&'a Authority, FsError> {
        if self.view.is_none() {
            let authority = core
                .journal
                .db
                .query_row(
                    "SELECT revision FROM live_authority WHERE singleton=1",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?;
            if authority == Some(None) {
                return Err(FsError::PermissionDenied);
            }
        }
        perm::authority(&core.config, &self.actor)
    }
    fn access(&self, core: &Core, e: &Entry, bits: u16) -> Result<(), FsError> {
        let a = self.actor(core)?;
        if self.view.is_none() {
            if let Some(Some(id)) = core
                .journal
                .db
                .query_row(
                    "SELECT revision FROM live_authority WHERE singleton=1",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
            {
                let authority = core.revision(&RevisionId::parse(id)?)?;
                let current = if e.id == authority.tree.root.id {
                    Some(perm::root_entry(&authority.tree))
                } else {
                    authority
                        .tree
                        .entries
                        .iter()
                        .find(|v| v.id == e.id)
                        .cloned()
                };
                if let Some(current) = current {
                    perm::traversal(&authority.tree, &current.path, a)?;
                    perm::access(a, &current, bits)?;
                } else {
                    let base = core.revision(&core.working()?.base)?;
                    if core.remote_entries.contains(&e.id)
                        || base.tree.entries.iter().any(|v| v.id == e.id)
                    {
                        return Err(FsError::PermissionDenied);
                    }
                    // Locally created entries inherit current remote search authority
                    // through their nearest known parent; absence alone is not revocation.
                    let parent = if e.parent == core.working()?.tree.root.id {
                        perm::root_entry(&core.working()?.tree)
                    } else {
                        core.working()?
                            .tree
                            .entries
                            .iter()
                            .find(|p| p.id == e.parent)
                            .cloned()
                            .ok_or(FsError::PermissionDenied)?
                    };
                    self.access(core, &parent, 1)?;
                }
            }
        }
        if self.view.is_some() {
            if let Some(w) = &core.working {
                let current = if e.id == w.tree.root.id {
                    perm::root_entry(&w.tree)
                } else {
                    w.tree
                        .entries
                        .iter()
                        .find(|v| v.id == e.id)
                        .cloned()
                        .ok_or(FsError::PermissionDenied)?
                };
                perm::traversal(&w.tree, &current.path, a)?;
                return perm::access(a, &current, bits);
            }
        }
        perm::access(a, e, bits)
    }
    fn metadata_owner(&self, core: &Core, entry: &Entry) -> Result<PrincipalId, FsError> {
        self.access(core, entry, 0)?;
        if self.view.is_none() {
            if let Some(Some(id)) = core
                .journal
                .db
                .query_row(
                    "SELECT revision FROM live_authority WHERE singleton=1",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
            {
                let authority = core.revision(&RevisionId::parse(id)?)?;
                if entry.id == authority.tree.root.id {
                    return Ok(authority.tree.root.owner);
                }
                if let Some(e) = authority
                    .tree
                    .entries
                    .into_iter()
                    .find(|e| e.id == entry.id)
                {
                    return Ok(e.owner);
                }
            }
        }
        Ok(entry.owner.clone())
    }
    fn resolve_entry(&self, core: &Core, tree: &Tree, path: &str) -> Result<Entry, FsError> {
        if !path.is_empty() {
            crate::paths::validate_path(path)?;
        }
        // Historical names resolve identity; current ancestry and permissions authorize it.
        // An imported readonly view with no working branch uses its own authority tree.
        if self.view.is_none() || core.working.is_none() {
            perm::traversal(tree, path, self.actor(core)?)?;
        }
        let entry = perm::entry(tree, path)?;
        self.access(core, &entry, 0)?;
        Ok(entry)
    }
    fn current_access(&self, core: &Core, entry: &Entry, bits: u16) -> Result<(), FsError> {
        let tree = &core.working()?.tree;
        let current = tree
            .entries
            .iter()
            .find(|e| e.id == entry.id)
            .ok_or(FsError::PermissionDenied)?;
        perm::traversal(tree, &current.path, self.actor(core)?)?;
        self.access(core, current, bits)
    }
    fn writable_handle(&self, core: &Core, h: &Handle) -> Result<(), FsError> {
        if h.inner.workspace != self.token || h.inner.epoch != core.working()?.epoch {
            return Err(FsError::StaleHandle);
        }
        Ok(())
    }
    pub fn epoch(&self) -> Result<u64, FsError> {
        Ok(lock(&self.core)?.working()?.epoch)
    }
    fn handle_entry(&self, core: &Core, h: &Handle) -> Result<Entry, FsError> {
        if h.inner.workspace != self.token {
            return Err(FsError::StaleHandle);
        }
        if self.view.is_none() && h.inner.epoch != core.working()?.epoch {
            let entry = core
                .epochs
                .get(&h.inner.epoch)
                .ok_or(FsError::StaleHandle)?
                .tree
                .entries
                .iter()
                .chain(&core.epochs[&h.inner.epoch].orphans)
                .find(|e| e.id == h.inner.entry.id)
                .cloned()
                .ok_or(FsError::StaleHandle)?;
            self.current_access(core, &entry, 0)?;
            return Ok(entry);
        }
        if self.view.is_some() {
            Ok(h.inner.entry.clone())
        } else {
            core.working()?
                .tree
                .entries
                .iter()
                .chain(&core.working()?.orphans)
                .find(|e| e.id == h.inner.entry.id)
                .cloned()
                .ok_or(FsError::StaleHandle)
        }
    }
    fn handle(&self, core: &mut Core, e: Entry, mode: OpenMode) -> Result<Handle, FsError> {
        let inner = Arc::new(HandleData {
            entry: e,
            mode,
            workspace: self.token.clone(),
            generation: core.working.as_ref().map(|w| w.generation).unwrap_or(0),
            epoch: core.working.as_ref().map(|w| w.epoch).unwrap_or(0),
        });
        core.handles.push(Arc::downgrade(&inner));
        Ok(Handle { inner })
    }
    pub fn generation(&self) -> Result<u64, FsError> {
        Ok(lock(&self.core)?.working()?.generation)
    }
    /// Project a guarded native entry's permission fields without changing historical
    /// identity, pathname or content. Recheck current identity and traversal even for
    /// retained historical handles; deletion must never fall back to obsolete rights.
    /// Live entries (including already-guarded orphan handles) need no projection.
    pub fn native_attributes(&self, entry: &Entry) -> Result<Entry, FsError> {
        let core = lock(&self.core)?;
        let mut projected = entry.clone();
        if self.view.is_none() {
            self.access(&core, entry, 0)?;
            let remote = core
                .journal
                .db
                .query_row(
                    "SELECT revision FROM live_authority WHERE singleton=1",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            let authority = remote
                .map(|id| core.revision(&RevisionId::parse(id)?))
                .transpose()?;
            let tree = authority
                .as_ref()
                .map(|r| &r.tree)
                .unwrap_or(&core.working()?.tree);
            let current = if entry.id == tree.root.id {
                Some(perm::root_entry(tree))
            } else {
                tree.entries.iter().find(|e| e.id == entry.id).cloned()
            };
            if let Some(current) = current {
                projected.owner = current.owner;
                projected.group = current.group;
                projected.mode = current.mode;
            }
        }
        if let (Some(view), Some(working)) = (&self.view, &core.working) {
            let historical = perm::entry(&view.tree, &entry.path)?;
            if historical.id != entry.id {
                return Err(FsError::StaleHandle);
            }
            self.access(&core, &historical, 0)?;
            let current = if entry.id == working.tree.root.id {
                perm::root_entry(&working.tree)
            } else {
                working
                    .tree
                    .entries
                    .iter()
                    .find(|e| e.id == entry.id)
                    .cloned()
                    .ok_or(FsError::PermissionDenied)?
            };
            projected = historical;
            projected.owner = current.owner;
            projected.group = current.group;
            projected.mode = current.mode;
        }
        Ok(projected)
    }
    pub fn lookup(&self, path: &str) -> Result<Entry, FsError> {
        let core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        self.resolve_entry(&core, &tree, path)
    }
    pub fn list(&self, path: &str) -> Result<Vec<String>, FsError> {
        let core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let e = self.resolve_entry(&core, &tree, path)?;
        if e.content != EntryContent::Directory {
            return Err(FsError::NotDirectory);
        }
        self.access(&core, &e, 4)?;
        let mut names = tree
            .entries
            .iter()
            .filter(|e| perm::parent(&e.path) == path)
            .map(|e| e.path.rsplit('/').next().unwrap_or("").to_owned())
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }
    /// Readdir names, stable identities and kinds only; child attributes still require search.
    pub fn directory_entries(&self, path: &str) -> Result<Vec<(String, EntryId, bool)>, FsError> {
        let core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let entry = self.resolve_entry(&core, &tree, path)?;
        if entry.content != EntryContent::Directory {
            return Err(FsError::NotDirectory);
        }
        self.access(&core, &entry, 4)?;
        Ok(tree
            .entries
            .iter()
            .filter(|e| perm::parent(&e.path) == path)
            .map(|e| {
                (
                    e.path.rsplit('/').next().unwrap_or("").to_owned(),
                    e.id.clone(),
                    e.content == EntryContent::Directory,
                )
            })
            .collect())
    }
    /// Resolve an inode identity through its current path and current traversal authority.
    pub fn lookup_identity(&self, id: &EntryId) -> Result<Entry, FsError> {
        let core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let path = if &tree.root.id == id {
            ""
        } else {
            &tree
                .entries
                .iter()
                .find(|e| &e.id == id)
                .ok_or(FsError::NotFound)?
                .path
        };
        self.resolve_entry(&core, &tree, path)
    }
    /// NFS DELETE reports current writable/searchable parent authority, not file write mode.
    pub fn check_remove_identity(&self, id: &EntryId) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        let core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let entry = tree
            .entries
            .iter()
            .find(|e| &e.id == id)
            .ok_or(FsError::NotFound)?;
        self.resolve_entry(&core, &tree, &entry.path)?;
        let authority_tree = if self.view.is_some() {
            core.working.as_ref().map(|w| &w.tree).unwrap_or(&tree)
        } else {
            &tree
        };
        let current = authority_tree
            .entries
            .iter()
            .find(|e| &e.id == id)
            .ok_or(FsError::PermissionDenied)?;
        perm::parent_write(authority_tree, &current.path, self.actor(&core)?)?;
        Ok(())
    }
    /// NFS has no OPEN/CLOSE: retain an authorized identity without granting data rights.
    /// All handle operations independently recheck current authority and readonly state.
    pub fn retain_identity(&self, id: &EntryId) -> Result<Handle, FsError> {
        let mut core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let e = tree
            .entries
            .iter()
            .find(|e| &e.id == id)
            .ok_or(FsError::NotFound)?;
        let e = self.resolve_entry(&core, &tree, &e.path)?;
        if e.content == EntryContent::Directory {
            return Err(FsError::IsDirectory);
        }
        let mode = if self.read_only {
            OpenMode::Read
        } else {
            OpenMode::ReadWrite
        };
        self.handle(&mut core, e, mode)
    }
    /// Authoritative ACCESS query, including current permissions on historical identities.
    pub fn check_access_identity(&self, id: &EntryId, bits: u16) -> Result<(), FsError> {
        if bits & !7 != 0 {
            return Err(FsError::InvalidPath);
        }
        if bits & 2 != 0 {
            perm::mutation(self.read_only)?;
        }
        let core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let e = if &tree.root.id == id {
            perm::root_entry(&tree)
        } else {
            tree.entries
                .iter()
                .find(|e| &e.id == id)
                .cloned()
                .ok_or(FsError::NotFound)?
        };
        let e = self.resolve_entry(&core, &tree, &e.path)?;
        self.access(&core, &e, bits)
    }
    /// Authorize session-only timestamps without advancing durable working state.
    /// Retained handles preserve identity after unlink or replacement.
    pub fn check_server_time(&self, id: &EntryId, handle: Option<&Handle>) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        let core = lock(&self.core)?;
        let e = if let Some(handle) = handle {
            self.writable_handle(&core, handle)?;
            let entry = self.handle_entry(&core, handle)?;
            if &entry.id != id {
                return Err(FsError::NotFound);
            }
            entry
        } else {
            let tree = self.tree(&core)?;
            let entry = if &tree.root.id == id {
                perm::root_entry(&tree)
            } else {
                tree.entries
                    .iter()
                    .find(|e| &e.id == id)
                    .cloned()
                    .ok_or(FsError::NotFound)?
            };
            self.resolve_entry(&core, &tree, &entry.path)?
        };
        if self.metadata_owner(&core, &e)? == *self.actor.principal() {
            Ok(())
        } else {
            self.access(&core, &e, 2)
        }
    }
    /// Attributes through an existing open capability, including unlinked identities.
    pub fn handle_attributes(&self, handle: &Handle) -> Result<Entry, FsError> {
        let core = lock(&self.core)?;
        let entry = self.handle_entry(&core, handle)?;
        self.access(&core, &entry, 0)?;
        Ok(entry)
    }
    pub fn open(&self, path: &str, mode: OpenMode) -> Result<Handle, FsError> {
        if mode != OpenMode::Read {
            perm::mutation(self.read_only)?;
        }
        let mut core = lock(&self.core)?;
        let tree = self.tree(&core)?;
        let e = self.resolve_entry(&core, &tree, path)?;
        if e.content == EntryContent::Directory {
            return Err(FsError::IsDirectory);
        }
        self.access(
            &core,
            &e,
            match mode {
                OpenMode::Read => 4,
                OpenMode::ReadWrite => 6,
                OpenMode::Write | OpenMode::Append => 2,
            },
        )?;
        self.handle(&mut core, e, mode)
    }
    pub fn read(&self, handle: &Handle, offset: u64, length: usize) -> Result<Vec<u8>, FsError> {
        if matches!(handle.inner.mode, OpenMode::Write | OpenMode::Append) {
            return Err(FsError::PermissionDenied);
        }
        let deadline = Instant::now() + Duration::from_millis(4500);
        if length > MAX_CHUNK as usize {
            return Err(FsError::LimitExceeded);
        }
        let mut core = lock(&self.core)?;
        let e = self.handle_entry(&core, handle)?;
        if self.view.is_none() && handle.inner.epoch != core.working()?.epoch {
            self.current_access(&core, &e, 4)?;
        } else {
            self.access(&core, &e, 4)?;
        }
        let EntryContent::File { version } = e.content else {
            return Err(FsError::IsDirectory);
        };
        let end = offset.saturating_add(length as u64).min(version.size);
        if offset >= end {
            return Ok(vec![]);
        }
        let mut result = Vec::with_capacity((end - offset) as usize);
        let mut position = 0;
        for extent in &version.extents {
            let len = extent_len(extent);
            let from = offset.max(position);
            let to = end.min(position + len);
            if from < to {
                match extent {
                    Extent::Hole { .. } => result.resize(result.len() + (to - from) as usize, 0),
                    Extent::Chunk {
                        object,
                        object_size,
                        offset: object_offset,
                        ..
                    } => {
                        let base = if let Some(view) = &self.view {
                            revision_id(view)?
                        } else if handle.inner.epoch != core.working()?.epoch {
                            core.epochs[&handle.inner.epoch].base.clone()
                        } else {
                            core.working()?.base.clone()
                        };
                        let epoch_source = if self.view.is_some() {
                            None
                        } else if handle.inner.epoch == core.working()?.epoch {
                            core.working()?.remote_source.clone()
                        } else {
                            core.epochs
                                .get(&handle.inner.epoch)
                                .and_then(|w| w.remote_source.clone())
                        };
                        let source = core
                            .journal
                            .db
                            .query_row(
                                "SELECT source FROM revision_sources WHERE revision=?",
                                [base.as_str()],
                                |r| r.get::<_, Vec<u8>>(0),
                            )
                            .optional()?
                            .map(|b| from_json::<ChunkSource>(&b))
                            .transpose()?;
                        let source = if self.view.is_none() {
                            epoch_source
                                .map(|source| ChunkSource::Remote { source })
                                .or(source)
                        } else {
                            source
                        };
                        let bytes = if let Some(source @ ChunkSource::Remote { .. }) = source {
                            core.fetch_from(&source, object, *object_size, deadline)?
                        } else {
                            core.fetch(object, *object_size, deadline)?
                        };
                        let start = (object_offset + from - position) as usize;
                        result.extend_from_slice(&bytes[start..start + (to - from) as usize]);
                    }
                }
            }
            position += len;
            if position >= end {
                break;
            }
        }
        Ok(result)
    }
    pub fn write(&self, handle: &Handle, offset: u64, bytes: &[u8]) -> Result<usize, FsError> {
        self.write_with_append(handle, offset, bytes, handle.inner.mode == OpenMode::Append)
    }
    /// Native status flags may change after open. Resolve EOF and commit under the
    /// same lock while retaining the handle identity and current write authority.
    pub fn write_with_append(
        &self,
        handle: &Handle,
        offset: u64,
        bytes: &[u8],
        append: bool,
    ) -> Result<usize, FsError> {
        perm::mutation(self.read_only)?;
        if bytes.len() as u64 > MAX_CHUNK {
            return Err(FsError::LimitExceeded);
        }
        let mut core = lock(&self.core)?;
        self.writable_handle(&core, handle)?;
        if handle.inner.mode == OpenMode::Read {
            return Err(FsError::PermissionDenied);
        }
        let e = self.handle_entry(&core, handle)?;
        self.access(&core, &e, 2)?;
        let EntryContent::File { version } = &e.content else {
            return Err(FsError::IsDirectory);
        };
        let offset = if append { version.size } else { offset };
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(FsError::LimitExceeded)?;
        if end > MAX_FILE {
            return Err(FsError::LimitExceeded);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut middle = Vec::new();
        let mut objects = BTreeMap::new();
        for chunk in bytes.chunks(262144) {
            let object = ObjectId::for_bytes(chunk)?;
            objects.insert(object.clone(), chunk.len() as u64);
            middle.push(Extent::Chunk {
                object,
                object_size: chunk.len() as u64,
                offset: 0,
                length: chunk.len() as u64,
            });
        }
        let mut extents = slice_extents(version, 0, offset.min(version.size));
        if offset > version.size {
            extents.push(Extent::Hole {
                length: offset - version.size,
            });
        }
        extents.extend(middle);
        if end < version.size {
            extents.extend(slice_extents(version, end, version.size));
        }
        let mut changed = e.clone();
        changed.content = EntryContent::File {
            version: FileVersion {
                size: version.size.max(end),
                extents: normalize(extents)?,
            },
        };
        let mut next = core.working()?.clone();
        replace_entry(&mut next, changed)?;
        validate_tree(&next.tree)?;
        core.reserve(&objects)?;
        for chunk in bytes.chunks(262144) {
            core.objects.install(chunk)?;
        }
        core.save(next)?;
        Ok(bytes.len())
    }
    pub fn truncate(&self, handle: &Handle, size: u64) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        if size > MAX_FILE {
            return Err(FsError::LimitExceeded);
        }
        let mut core = lock(&self.core)?;
        self.writable_handle(&core, handle)?;
        if handle.inner.mode == OpenMode::Read {
            return Err(FsError::PermissionDenied);
        }
        let mut e = self.handle_entry(&core, handle)?;
        self.access(&core, &e, 2)?;
        let EntryContent::File { version } = &e.content else {
            return Err(FsError::IsDirectory);
        };
        let mut extents = slice_extents(version, 0, size.min(version.size));
        if size > version.size {
            extents.push(Extent::Hole {
                length: size - version.size,
            });
        }
        e.content = EntryContent::File {
            version: FileVersion {
                size,
                extents: normalize(extents)?,
            },
        };
        let mut next = core.working()?.clone();
        replace_entry(&mut next, e)?;
        core.save(next)
    }
    fn create_entry(
        &self,
        core: &mut Core,
        path: &str,
        mode: u16,
        directory: bool,
    ) -> Result<Entry, FsError> {
        perm::mutation(self.read_only)?;
        perm::mode(mode)?;
        let mut next = core.working()?.clone();
        let a = self.actor(core)?;
        let parent = perm::parent_write(&next.tree, path, a)?;
        self.access(core, &parent, 3)?;
        if perm::entry(&next.tree, path).is_ok() {
            return Err(FsError::AlreadyExists);
        }
        let e = Entry {
            path: path.into(),
            id: EntryId::random()?,
            parent: parent.id,
            owner: a.principal.clone(),
            group: a.primary_group.clone(),
            mode: mode & !next.umask,
            content: if directory {
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
        next.tree.entries.push(e.clone());
        core.save(next)?;
        Ok(e)
    }
    pub fn create(&self, path: &str, mode: u16) -> Result<Handle, FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        let e = self.create_entry(&mut core, path, mode, false)?;
        crate::faults::hit("after-create")?;
        self.handle(&mut core, e, OpenMode::ReadWrite)
    }
    pub fn mkdir(&self, path: &str, mode: u16) -> Result<EntryId, FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        Ok(self.create_entry(&mut core, path, mode, true)?.id)
    }
    pub fn rename(&self, from: &str, to: &str) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        let mut next = core.working()?.clone();
        let a = self.actor(&core)?;
        let from_parent = perm::parent_write(&next.tree, from, a)?;
        self.access(&core, &from_parent, 3)?;
        let parent = perm::parent_write(&next.tree, to, a)?;
        self.access(&core, &parent, 3)?;
        let e = perm::entry(&next.tree, from)?;
        self.access(&core, &e, 0)?;
        if from == to {
            return Ok(());
        }
        if to.starts_with(&format!("{from}/")) {
            return Err(FsError::InvalidPath);
        }
        if let Ok(replaced) = perm::entry(&next.tree, to) {
            self.access(&core, &replaced, 0)?;
            if (replaced.content == EntryContent::Directory)
                != (e.content == EntryContent::Directory)
            {
                return Err(FsError::IsDirectory);
            }
            if next
                .tree
                .entries
                .iter()
                .any(|e| e.path.starts_with(&format!("{to}/")))
            {
                return Err(FsError::NotEmpty);
            }
            next.tree.entries.retain(|v| v.id != replaced.id);
            next.orphans.push(replaced);
        }
        for moved in &mut next.tree.entries {
            if moved.path == from {
                moved.path = to.into();
                moved.parent = parent.id.clone();
            } else if let Some(suffix) = moved.path.strip_prefix(&format!("{from}/")) {
                moved.path = format!("{to}/{suffix}");
            }
        }
        core.save(next)
    }
    pub fn unlink(&self, path: &str) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        let mut next = core.working()?.clone();
        let parent = perm::parent_write(&next.tree, path, self.actor(&core)?)?;
        self.access(&core, &parent, 3)?;
        let e = perm::entry(&next.tree, path)?;
        self.access(&core, &e, 0)?;
        if next
            .tree
            .entries
            .iter()
            .any(|e| e.path.starts_with(&format!("{path}/")))
        {
            return Err(FsError::NotEmpty);
        }
        next.tree.entries.retain(|v| v.id != e.id);
        next.orphans.push(e);
        core.save(next)
    }
    pub fn chmod(&self, path: &str, mode: u16) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        perm::mode(mode)?;
        let mut core = lock(&self.core)?;
        let mut next = core.working()?.clone();
        perm::traversal(&next.tree, path, self.actor(&core)?)?;
        let mut e = perm::entry(&next.tree, path)?;
        if self.metadata_owner(&core, &e)? != *self.actor.principal() {
            return Err(FsError::PermissionDenied);
        }
        e.mode = mode;
        replace_entry(&mut next, e)?;
        core.save(next)
    }
    pub fn chown(&self, path: &str, owner: PrincipalId, group: GroupId) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        let mut next = core.working()?.clone();
        let a = self.actor(&core)?;
        perm::ownership_change(&core.config, a, &owner, &group)?;
        perm::traversal(&next.tree, path, a)?;
        let mut e = perm::entry(&next.tree, path)?;
        self.access(&core, &e, 0)?;
        e.owner = owner;
        e.group = group;
        replace_entry(&mut next, e)?;
        core.save(next)
    }
    /// Metadata through an existing capability does not re-resolve its former path.
    pub fn chmod_handle(&self, handle: &Handle, mode: u16) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        perm::mode(mode)?;
        let mut core = lock(&self.core)?;
        self.writable_handle(&core, handle)?;
        let mut entry = self.handle_entry(&core, handle)?;
        if self.metadata_owner(&core, &entry)? != *self.actor.principal() {
            return Err(FsError::PermissionDenied);
        }
        entry.mode = mode;
        let mut next = core.working()?.clone();
        replace_entry(&mut next, entry)?;
        core.save(next)
    }
    pub fn chown_handle(
        &self,
        handle: &Handle,
        owner: PrincipalId,
        group: GroupId,
    ) -> Result<(), FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        self.writable_handle(&core, handle)?;
        let mut entry = self.handle_entry(&core, handle)?;
        perm::ownership_change(&core.config, self.actor(&core)?, &owner, &group)?;
        self.access(&core, &entry, 0)?;
        entry.owner = owner;
        entry.group = group;
        let mut next = core.working()?.clone();
        replace_entry(&mut next, entry)?;
        core.save(next)
    }
    pub fn fsync(&self) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        core.journal.sync()
    }
    pub fn checkpoint(
        &self,
        operation: &OperationId,
        expected_generation: u64,
        attribution: Attribution,
    ) -> Result<RevisionId, FsError> {
        perm::mutation(self.read_only)?;
        let mut core = lock(&self.core)?;
        self.actor(&core)?;
        let working = core.working()?.clone();
        let mut tree = working.tree.clone();
        tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut attribution = attribution;
        attribution.coverage.sort();
        let digest = RevisionId::digest(&json(&(
            expected_generation,
            &self.actor,
            &attribution,
            &tree,
        ))?)?;
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
        if expected_generation != working.generation {
            return Err(FsError::GenerationMismatch);
        }
        let revision = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![working.head.clone()],
            operation: operation.clone(),
            replica: core.config.replica.clone(),
            principal: self.actor.principal().clone(),
            captured_at_ns: attribution.captured_at_ns,
            coverage: attribution.coverage,
            provenance: attribution.provenance,
            restoration: None,
            tree,
        };
        let descriptor = encode_revision(&revision)?;
        let id = revision_id(&revision)?;
        core.journal.guard()?;
        core.journal.db.execute("INSERT INTO operations VALUES(?,?,'pending',NULL,NULL,?) ON CONFLICT(operation) DO UPDATE SET state='pending',error=NULL",params![operation.as_str(),digest.as_str(),&descriptor])?;
        let result = (|| {
            for (object, size) in cache::closure(&revision.tree) {
                match core.objects.sync_object(&object) {
                    Ok(()) => {}
                    Err(FsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        if core.source(&object)?.is_none_or(|(s, _)| s != size) {
                            return Err(cache::unavailable(&object, SourceFailure::Missing));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            crate::faults::hit("before-transaction")?;
            let mut next = working;
            next.head = id.clone();
            next.generation = next
                .generation
                .checked_add(1)
                .ok_or(FsError::LimitExceeded)?;
            next.dirty = false;
            let tx = core
                .journal
                .db
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO revisions VALUES(?,?)",
                params![id.as_str(), descriptor],
            )?;
            tx.execute(
                "UPDATE working SET value=? WHERE singleton=1",
                [json(&next)?],
            )?;
            tx.execute(
                "UPDATE operations SET state='committed',result=?,error=NULL WHERE operation=?",
                params![id.as_str(), operation.as_str()],
            )?;
            crate::faults::hit("during-transaction")?;
            crate::faults::hit("db-commit")?;
            tx.commit()?;
            core.working = Some(next);
            crate::faults::hit("after-commit")?;
            Ok(id.clone())
        })();
        if let Err(e) = &result {
            core.failed(operation, e)?;
        }
        result
    }
}
fn replace_entry(working: &mut Working, entry: Entry) -> Result<(), FsError> {
    if entry.id == working.tree.root.id {
        working.tree.root = Root {
            id: entry.id,
            owner: entry.owner,
            group: entry.group,
            mode: entry.mode,
        };
        return Ok(());
    }
    let e = working
        .tree
        .entries
        .iter_mut()
        .chain(&mut working.orphans)
        .find(|e| e.id == entry.id)
        .ok_or(FsError::StaleHandle)?;
    *e = entry;
    Ok(())
}
fn extent_len(e: &Extent) -> u64 {
    match e {
        Extent::Chunk { length, .. } | Extent::Hole { length } => *length,
    }
}
fn slice_extents(version: &FileVersion, start: u64, end: u64) -> Vec<Extent> {
    let mut position = 0;
    let mut extents = Vec::new();
    for e in &version.extents {
        let len = extent_len(e);
        let from = start.max(position);
        let to = end.min(position + len);
        if from < to {
            extents.push(match e {
                Extent::Hole { .. } => Extent::Hole { length: to - from },
                Extent::Chunk {
                    object,
                    object_size,
                    offset,
                    ..
                } => Extent::Chunk {
                    object: object.clone(),
                    object_size: *object_size,
                    offset: offset + from - position,
                    length: to - from,
                },
            });
        }
        position += len;
        if position >= end {
            break;
        }
    }
    extents
}
fn normalize(extents: Vec<Extent>) -> Result<Vec<Extent>, FsError> {
    let mut result = Vec::new();
    for e in extents {
        match (result.last_mut(), &e) {
            (Some(Extent::Hole { length: a }), Extent::Hole { length: b }) => *a += b,
            (
                Some(Extent::Chunk {
                    object: a,
                    offset: ao,
                    length: al,
                    ..
                }),
                Extent::Chunk {
                    object: b,
                    offset: bo,
                    length: bl,
                    ..
                },
            ) if a == b && *ao + *al == *bo => *al += bl,
            _ => result.push(e),
        }
    }
    if result.len() > MAX_EXTENTS {
        return Err(FsError::Backpressure);
    }
    Ok(result)
}

fn restored_metadata(
    config: &ReplicaConfig,
    a: &Authority,
    current: &Entry,
    source: &Entry,
) -> Result<Entry, FsError> {
    let mut result = current.clone();
    if current.mode != source.mode {
        if current.owner != a.principal {
            return Err(FsError::PermissionDenied);
        }
        result.mode = source.mode;
    }
    if current.owner != source.owner || current.group != source.group {
        perm::ownership_change(config, a, &source.owner, &source.group)?;
        result.owner = source.owner.clone();
        result.group = source.group.clone();
    }
    Ok(result)
}
impl Replica {
    /// Restore source entries as an overlay; omitted current entries are never deletion authority.
    pub fn restore_revision(
        &self,
        source: &RevisionId,
        operation: &OperationId,
        restore_metadata: bool,
        actor: Actor,
    ) -> Result<RevisionId, FsError> {
        let mut core = lock(&self.core)?;
        let a = perm::authority(&core.config, &actor)?.clone();
        let source_revision = core.revision(source)?;
        crate::archive::history_access(&core, source, &source_revision, &actor)?;
        let digest = RevisionId::digest(&json(&("restore", source, restore_metadata, &actor))?)?;
        let existing = core
            .journal
            .db
            .query_row(
                "SELECT digest,result,candidate FROM operations WHERE operation=?",
                [operation.as_str()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((prior, result, _)) = &existing {
            if prior != digest.as_str() {
                return Err(FsError::OperationMismatch);
            }
            if let Some(result) = result {
                return RevisionId::parse(result.clone());
            }
        }
        let working = core.working()?.clone();
        if working.dirty {
            return Err(FsError::DirtyWorkingState);
        }
        if source_revision.tree.root.id != working.tree.root.id {
            return Err(FsError::BaseMismatch);
        }
        let mut next = working.clone();
        let mut mapping = BTreeMap::from([(
            source_revision.tree.root.id.clone(),
            next.tree.root.id.clone(),
        )]);
        let mut recreated = BTreeMap::new();
        let mut metadata = BTreeMap::new();
        let mut source_entries = source_revision.tree.entries.iter().collect::<Vec<_>>();
        source_entries.sort_by(|a, b| a.path.cmp(&b.path));
        for old in source_entries {
            let current = next.tree.entries.iter().find(|e| e.id == old.id).cloned();
            let mut entry = if let Some(current) = current {
                if (current.content == EntryContent::Directory)
                    != (old.content == EntryContent::Directory)
                {
                    return Err(FsError::TargetCollision);
                }
                perm::traversal(&next.tree, &current.path, &a)?;
                if old.content != EntryContent::Directory {
                    perm::access(&a, &current, 2)?;
                }
                if current.path != old.path {
                    perm::parent_write(&next.tree, &current.path, &a)?;
                    perm::parent_write(&next.tree, &old.path, &a)?;
                }
                current
            } else {
                perm::parent_write(&next.tree, &old.path, &a)?;
                let id = EntryId::random()?;
                recreated.insert(old.id.clone(), id.clone());
                Entry {
                    path: old.path.clone(),
                    id,
                    parent: mapping
                        .get(&old.parent)
                        .ok_or(FsError::InvalidTree)?
                        .clone(),
                    owner: a.principal.clone(),
                    group: a.primary_group.clone(),
                    mode: (if old.content == EntryContent::Directory {
                        0o777
                    } else {
                        0o666
                    }) & !working.umask,
                    content: old.content.clone(),
                }
            };
            if let Some(displaced) = next
                .tree
                .entries
                .iter()
                .find(|e| e.path == old.path && e.id != entry.id)
                .cloned()
            {
                perm::parent_write(&next.tree, &old.path, &a)?;
                if source_revision
                    .tree
                    .entries
                    .iter()
                    .any(|e| e.id == displaced.id)
                {
                    return Err(FsError::TargetCollision);
                }
                if (displaced.content == EntryContent::Directory)
                    != (old.content == EntryContent::Directory)
                    || next
                        .tree
                        .entries
                        .iter()
                        .any(|e| e.path.starts_with(&format!("{}/", old.path)))
                {
                    return Err(FsError::TargetCollision);
                }
                next.tree.entries.retain(|e| e.id != displaced.id);
                next.orphans.push(displaced);
            }
            let prior_path = entry.path.clone();
            if entry.content == EntryContent::Directory && prior_path != old.path {
                if old.path.starts_with(&format!("{prior_path}/")) {
                    return Err(FsError::InvalidPath);
                }
                for descendant in &mut next.tree.entries {
                    if let Some(suffix) = descendant.path.strip_prefix(&format!("{prior_path}/")) {
                        descendant.path = format!("{}/{suffix}", old.path);
                    }
                }
            }
            if restore_metadata {
                metadata.insert(
                    entry.id.clone(),
                    restored_metadata(&core.config, &a, &entry, old)?,
                );
            }
            entry.path = old.path.clone();
            entry.parent = mapping
                .get(&old.parent)
                .ok_or(FsError::InvalidTree)?
                .clone();
            entry.content = old.content.clone();
            mapping.insert(old.id.clone(), entry.id.clone());
            next.tree.entries.retain(|e| e.id != entry.id);
            next.tree.entries.push(entry);
        }
        if restore_metadata {
            let root = restored_metadata(
                &core.config,
                &a,
                &perm::root_entry(&next.tree),
                &perm::root_entry(&source_revision.tree),
            )?;
            next.tree.root.owner = root.owner;
            next.tree.root.group = root.group;
            next.tree.root.mode = root.mode;
            for e in &mut next.tree.entries {
                if let Some(m) = metadata.get(&e.id) {
                    e.owner = m.owner.clone();
                    e.group = m.group.clone();
                    e.mode = m.mode;
                }
            }
        }
        next.tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
        validate_tree(&next.tree)?;
        let mut parents = vec![working.head.clone()];
        if source != &working.head {
            parents.push(source.clone());
        }
        let revision = Revision {
            format: RESTORE_FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents,
            operation: operation.clone(),
            replica: core.config.replica.clone(),
            principal: actor.principal().clone(),
            captured_at_ns: 0,
            coverage: source_revision.coverage.clone(),
            provenance: "explicit".into(),
            restoration: Some(RestoreProvenance {
                source_revision: source.clone(),
                restore_metadata,
                recreated,
            }),
            tree: next.tree.clone(),
        };
        validate_restoration_parents(&revision, &source_revision, &core.revision(&working.head)?)?;
        let descriptor = encode_revision(&revision)?;
        let id = revision_id(&revision)?;
        // A retry after failed hydration may allocate fresh recreated IDs; no failed candidate is deleted.
        core.journal.db.execute("INSERT INTO operations VALUES(?,?,'pending',NULL,NULL,?) ON CONFLICT(operation) DO UPDATE SET state='pending',error=NULL,candidate=excluded.candidate",params![operation.as_str(),digest.as_str(),&descriptor])?;
        let result = (|| {
            for (object, size) in cache::closure(&revision.tree) {
                core.fetch(&object, size, Instant::now() + Duration::from_millis(4500))?;
                core.objects.sync_object(&object)?;
            }
            next.head = id.clone();
            next.generation = next
                .generation
                .checked_add(1)
                .ok_or(FsError::LimitExceeded)?;
            next.dirty = false;
            let tx = core
                .journal
                .db
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO revisions VALUES(?,?)",
                params![id.as_str(), descriptor],
            )?;
            tx.execute(
                "UPDATE working SET value=? WHERE singleton=1",
                [json(&next)?],
            )?;
            tx.execute(
                "UPDATE operations SET state='committed',result=?,error=NULL WHERE operation=?",
                params![id.as_str(), operation.as_str()],
            )?;
            crate::faults::hit("db-commit")?;
            tx.commit()?;
            core.working = Some(next);
            Ok(id)
        })();
        if let Err(e) = &result {
            core.failed(operation, e)?;
        }
        result
    }
    pub fn restore_provenance(
        &self,
        revision: &RevisionId,
    ) -> Result<Option<RestoreProvenance>, FsError> {
        Ok(lock(&self.core)?.revision(revision)?.restoration)
    }
}
