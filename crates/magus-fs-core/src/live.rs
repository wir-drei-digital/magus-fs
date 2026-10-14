//! Atomic incoming view adoption; native readiness is acknowledged separately.
use crate::{
    engine::{json, lock},
    permissions as perm, *,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Adoption {
    pub revision: RevisionId,
    pub epoch: u64,
    /// Both old and new names are invalidated, including their parent directories.
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveStatus {
    pub revision: RevisionId,
    pub epoch: u64,
    pub applied: bool,
    pub current_authority: Option<RevisionId>,
    pub authorized: bool,
    pub authority_generation: u64,
    pub pending_revision: Option<RevisionId>,
    pub pending_source: Option<crate::protocol::RemoteSourceId>,
}
impl Replica {
    /// A trusted discovery owner records authenticated metadata, or a definitive denial.
    /// Transient network errors must not call this with None.
    pub fn observe_remote_authority(
        &self,
        revision: Option<&RevisionId>,
        expected_generation: u64,
    ) -> Result<(), FsError> {
        let mut core = lock(&self.core)?;
        let generation: u64 = core.journal.db.query_row(
            "SELECT COALESCE(max(generation),0) FROM live_authority_history",
            [],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )?;
        if generation != expected_generation {
            return Err(FsError::GenerationMismatch);
        }
        let previous = core
            .journal
            .db
            .query_row(
                "SELECT revision FROM live_authority WHERE singleton=1",
                [],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?;
        if previous.as_ref().map(|v| v.as_deref()) == Some(revision.map(RevisionId::as_str)) {
            return Ok(());
        }

        let mut observed_entries = Vec::new();
        if let Some(id) = revision {
            let r = core.revision(id)?;
            if r.tree.root.id != core.working()?.tree.root.id {
                return Err(FsError::BaseMismatch);
            }
            observed_entries.push(r.tree.root.id);
            observed_entries.extend(r.tree.entries.into_iter().map(|e| e.id));
        }
        let next = generation.checked_add(1).ok_or(FsError::LimitExceeded)?;
        let retained = if revision.is_none() {
            core.mounted_recovery_record("current authority denied")?
        } else {
            None
        };
        let tx = core.journal.db.transaction()?;
        tx.execute(
            "INSERT INTO live_authority_history VALUES(?,?)",
            params![
                i64::try_from(next).map_err(|_| FsError::LimitExceeded)?,
                revision.map(RevisionId::as_str)
            ],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO live_authority VALUES(1,?)",
            [revision.map(RevisionId::as_str)],
        )?;
        if let Some((operation, bytes)) = retained {
            tx.execute(
                "INSERT INTO local_work_recovery VALUES(?,?)",
                params![operation.as_str(), bytes],
            )?;
        }
        tx.commit()?;
        core.remote_entries.extend(observed_entries);
        Ok(())
    }

    pub fn live_status(&self) -> Result<LiveStatus, FsError> {
        let core = lock(&self.core)?;
        let w = core.working()?;
        let authority = core
            .journal
            .db
            .query_row(
                "SELECT revision FROM live_authority WHERE singleton=1",
                [],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?;
        let authorized = authority != Some(None);
        let current_authority = authority.flatten().map(RevisionId::parse).transpose()?;
        let active: Option<SyncBinding> = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| crate::engine::from_json(&b))
            .transpose()?;
        let mut pending_source = None;
        if let Some(active) = active {
            let rowid = core
                .journal
                .db
                .query_row(
                    "SELECT rowid FROM sync_sources WHERE id=?",
                    [active.source.as_str()],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0);
            let rows = core
                .journal
                .db
                .prepare("SELECT binding FROM sync_sources WHERE rowid>? ORDER BY rowid DESC")?
                .query_map([rowid], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            for row in rows {
                let binding: SyncBinding = crate::engine::from_json(&row)?;
                if Some(&binding.view.revision) == current_authority.as_ref() {
                    pending_source = Some(binding.source);
                    break;
                }
            }
        }
        Ok(LiveStatus {
            revision: w.head.clone(),
            epoch: w.epoch,
            applied: w.applied && !w.dirty,
            pending_revision: current_authority.clone().filter(|id| id != &w.head),
            pending_source,
            current_authority,
            authorized,
            authority_generation: core.journal.db.query_row(
                "SELECT COALESCE(max(generation),0) FROM live_authority_history",
                [],
                |r| r.get::<_, i64>(0).map(|v| v as u64),
            )?,
        })
    }
    pub fn adopt_remote_revision(
        &self,
        revision: &RevisionId,
        expected_generation: u64,
        actor: Actor,
    ) -> Result<Adoption, FsError> {
        self.adopt(revision, expected_generation, actor, None)
    }
    pub fn adopt_remote_view(
        &self,
        binding: SyncBinding,
        expected_generation: u64,
        actor: Actor,
    ) -> Result<Adoption, FsError> {
        self.adopt(
            &binding.view.revision.clone(),
            expected_generation,
            actor,
            Some(binding),
        )
    }
    fn adopt(
        &self,
        revision: &RevisionId,
        expected_generation: u64,
        actor: Actor,
        binding: Option<SyncBinding>,
    ) -> Result<Adoption, FsError> {
        let mut core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        let old = core.working()?.clone();
        if old.generation != expected_generation {
            return Err(FsError::GenerationMismatch);
        }
        if old.dirty {
            return Err(FsError::DirtyWorkingState);
        }
        let active: Option<SyncBinding> = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| crate::engine::from_json(&b))
            .transpose()?;
        if let Some(active) = &active {
            let new = binding.as_ref().ok_or(FsError::ConfigMismatch)?;
            if new.id != active.id
                || new.branch != active.branch
                || new.publication != active.publication
                || new.transport_profile != active.transport_profile
                || new.transport_identity != active.transport_identity
                || new.source == active.source
            {
                return Err(FsError::ConfigMismatch);
            }
            let records = core.sync_records()?;
            if records.iter().any(|r| r.unresolved())
                || old.head != active.view.revision
                    && !records
                        .iter()
                        .any(|r| r.pending.local_revision == old.head && !r.unresolved())
            {
                return Err(FsError::DirtyWorkingState);
            }
            if let Some(bytes) = core
                .journal
                .db
                .query_row(
                    "SELECT binding FROM sync_sources WHERE id=?",
                    [new.source.as_str()],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?
            {
                if crate::engine::from_json::<SyncBinding>(&bytes)? != *new {
                    return Err(FsError::ConfigMismatch);
                }
            }
        } else if binding.is_some() {
            return Err(FsError::ConfigMismatch);
        }
        let remote = core.revision(revision)?;
        if remote.tree.root.id != old.tree.root.id {
            return Err(FsError::BaseMismatch);
        }
        let mut next = old.clone();
        next.epoch = old.epoch.checked_add(1).ok_or(FsError::LimitExceeded)?;
        next.generation = old
            .generation
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        next.remote_source = binding.as_ref().map(|b| b.source.clone());
        next.base = revision.clone();
        next.head = revision.clone();
        next.tree = remote.tree;
        next.orphans.clear();
        next.applied = false;
        let mut entries = old.tree.entries.clone();
        entries.extend(next.tree.entries.clone());
        entries.push(perm::root_entry(&next.tree));
        let visibility = core.current_visibility()?.map(|mut snapshot| {
            for entry in &entries {
                if !snapshot.entries.contains(entry) {
                    snapshot.entries.push(entry.clone());
                }
            }
            snapshot.tree = next.tree.clone();
            snapshot.generation = next.generation;
            snapshot
        });
        let tx = core.journal.db.transaction()?;
        if let Some(snapshot) = visibility {
            tx.execute(
                "UPDATE dirty_visibility SET record=? WHERE singleton=1",
                [json(&snapshot)?],
            )?;
        }
        if let (Some(active), Some(new)) = (&active, &binding) {
            tx.execute(
                "INSERT OR IGNORE INTO sync_sources VALUES(?,?)",
                params![active.source.as_str(), json(active)?],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO sync_sources VALUES(?,?)",
                params![new.source.as_str(), json(new)?],
            )?;
            tx.execute(
                "UPDATE sync_binding SET value=? WHERE singleton=1",
                [json(new)?],
            )?;
        }
        tx.execute(
            "UPDATE working SET value=? WHERE singleton=1",
            [json(&next)?],
        )?;
        tx.commit()?;
        core.retain_epoch(old);
        let epoch = next.epoch;
        core.working = Some(next);
        Ok(Adoption {
            revision: revision.clone(),
            epoch,
            entries,
        })
    }
    /// Only the native adapter calls this after notifier success and lookup verification.
    pub fn acknowledge_adoption(&self, revision: &RevisionId, epoch: u64) -> Result<(), FsError> {
        let mut core = lock(&self.core)?;
        let mut next = core.working()?.clone();
        if next.head != *revision || next.epoch != epoch || next.dirty {
            return Err(FsError::GenerationMismatch);
        }
        if core.current_visibility()?.is_some() {
            return Err(FsError::CheckpointWaiting);
        }
        next.applied = true;
        let binding: Option<SyncBinding> = core
            .journal
            .db
            .query_row(
                "SELECT value FROM sync_binding WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| crate::engine::from_json(&b))
            .transpose()?;
        let mut records = core.sync_records()?;
        let tx = core.journal.db.transaction()?;
        tx.execute(
            "UPDATE working SET value=? WHERE singleton=1",
            [json(&next)?],
        )?;
        if let Some(binding) = binding {
            for record in &mut records {
                if record
                    .progress
                    .shared_receipt
                    .as_ref()
                    .is_some_and(|r| r.head == binding.view.head)
                {
                    record.progress.applied_revision = Some(revision.clone());
                    tx.execute(
                        "UPDATE sync_queue SET record=? WHERE operation=?",
                        params![json(record)?, record.pending.operation.as_str()],
                    )?;
                }
            }
        }
        tx.commit()?;
        core.working = Some(next);
        Ok(())
    }
}
