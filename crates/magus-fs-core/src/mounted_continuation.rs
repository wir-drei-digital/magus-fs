//! Durable mounted-owner checkpoint sequencing.
use crate::{
    engine::{from_json, json, lock, Core},
    permissions as perm, *,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CheckpointReadiness {
    Ready,
    Waiting {
        reason: String,
        retry_after_ms: u64,
    },
    Blocked {
        reason: String,
        actions: Vec<String>,
    },
}
impl Replica {
    pub fn enable_mounted_collaboration(
        &self,
        owner: &Workspace,
        binding: &SyncBinding,
        actor: Actor,
    ) -> Result<(), FsError> {
        owner.validate_mounted_owner(self, &actor)?;
        let core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        if binding.publication != PublicationMode::SharedLive {
            return Err(FsError::UnsupportedMode);
        }
        core.working()?;
        let active: SyncBinding = from_json(&core.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        if active != *binding {
            return Err(FsError::ConfigMismatch);
        }
        let existing: Option<Vec<u8>> = core
            .journal
            .db
            .query_row(
                "SELECT policy FROM mounted_collaboration WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let owner: SyncBinding = from_json(&existing)?;
            if owner.id != binding.id
                || owner.branch != binding.branch
                || owner.publication != binding.publication
                || owner.transport_profile != binding.transport_profile
                || owner.transport_identity != binding.transport_identity
            {
                return Err(FsError::ConfigMismatch);
            }
        } else {
            core.journal.guard()?;
            core.journal.db.execute(
                "INSERT INTO mounted_collaboration VALUES(1,?)",
                [json(binding)?],
            )?;
        }
        Ok(())
    }
    pub fn checkpoint_readiness(&self) -> Result<CheckpointReadiness, FsError> {
        lock(&self.core)?.mounted_checkpoint_readiness()
    }
}
impl Core {
    pub(crate) fn mounted_checkpoint_readiness(&self) -> Result<CheckpointReadiness, FsError> {
        let enabled: bool = self.journal.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM mounted_collaboration)",
            [],
            |r| r.get(0),
        )?;
        if !enabled {
            return Ok(CheckpointReadiness::Ready);
        }
        if self.recoveries()?.iter().any(|r| !r.selected_remote) {
            return Ok(CheckpointReadiness::Blocked {
                reason: "retained local work requires recovery".into(),
                actions: vec![
                    "inspect/export local work".into(),
                    "use current remote".into(),
                ],
            });
        }
        if self
            .journal
            .db
            .query_row("SELECT EXISTS(SELECT 1 FROM dirty_visibility)", [], |r| {
                r.get::<_, bool>(0)
            })?
        {
            return Ok(CheckpointReadiness::Waiting {
                reason: "dirty visibility verification pending".into(),
                retry_after_ms: 100,
            });
        }
        let active: SyncBinding = from_json(&self.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        let records = self.sync_records()?;
        if records.iter().any(|r| {
            r.unresolved()
                && matches!(
                    r.progress.state,
                    SubmissionState::Denied | SubmissionState::Failed
                )
        }) {
            return Ok(CheckpointReadiness::Blocked {
                reason: "publication requires recovery".into(),
                actions: vec!["inspect local work".into()],
            });
        }
        if self.working()?.head != active.view.revision || records.iter().any(|r| r.unresolved()) {
            return Ok(CheckpointReadiness::Waiting {
                reason: "original checkpoint awaits admission or continuation".into(),
                retry_after_ms: 100,
            });
        }
        Ok(CheckpointReadiness::Ready)
    }
}

use crate::engine::Working;
use rusqlite::params;
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContinuationFence {
    pub generation: u64,
    pub head: RevisionId,
    pub binding: SyncBinding,
    pub authority_generation: u64,
    pub credential_stamp: ObjectId,
    pub capability_generation: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub generation: u64,
    pub complete: bool,
    pub pinned: BTreeSet<EntryId>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContinuationOutcome {
    AlreadyAdvanced,
    OwnBaseAdvanced,
    DirtyReconciled { visibility: OperationId },
    Blocked { recovery: OperationId },
}
pub struct PreparedContinuation {
    binding: SyncBinding,
    fence: ContinuationFence,
    capabilities: CapabilitySnapshot,
    actor: Actor,
    proof: Option<ContinuationProofV1>,
    next: Working,
    foreign: bool,
    blocked: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VisibilitySnapshot {
    pub operation: OperationId,
    pub generation: u64,
    pub authority_generation: u64,
    pub capability_generation: u64,
    pub tree: Tree,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalWorkRecovery {
    pub operation: OperationId,
    pub reason: String,
    pub entries: Vec<EntryId>,
    pub actions: Vec<String>,
}
impl Core {
    fn continuation_fence(
        &self,
        incoming: &SyncBinding,
        fence: &ContinuationFence,
        capabilities: &CapabilitySnapshot,
    ) -> Result<(), FsError> {
        let active: SyncBinding = from_json(&self.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        let enabled: bool = self.journal.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM mounted_collaboration)",
            [],
            |r| r.get(0),
        )?;
        if !enabled
            || active != fence.binding
            || active.publication != PublicationMode::SharedLive
            || incoming.id != active.id
            || incoming.branch != active.branch
            || incoming.publication != active.publication
            || incoming.transport_profile != active.transport_profile
            || incoming.transport_identity != active.transport_identity
        {
            return Err(FsError::ConfigMismatch);
        }
        let working = self.working()?;
        let authority: Option<String> = self
            .journal
            .db
            .query_row(
                "SELECT revision FROM live_authority WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let generation: u64 = self.journal.db.query_row(
            "SELECT COALESCE(max(generation),0) FROM live_authority_history",
            [],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )?;
        if fence.generation != working.generation
            || fence.head != working.head
            || fence.authority_generation != generation
            || fence.capability_generation != capabilities.generation
        {
            return Err(FsError::GenerationMismatch);
        }
        if authority.as_deref() != Some(incoming.view.revision.as_str()) {
            return Err(FsError::PermissionDenied);
        }
        let registered: SyncBinding = from_json(&self.journal.db.query_row(
            "SELECT binding FROM sync_sources WHERE id=?",
            [incoming.source.as_str()],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        if registered != *incoming {
            return Err(FsError::ConfigMismatch);
        }
        Ok(())
    }
    fn prepare_own(
        &self,
        incoming: &SyncBinding,
        fence: &ContinuationFence,
        capabilities: &CapabilitySnapshot,
        actor: &Actor,
        proof: Option<&ContinuationProofV1>,
    ) -> Result<(Working, bool), FsError> {
        self.continuation_fence(incoming, fence, capabilities)?;
        perm::authority(&self.config, actor)?;
        let working = self.working()?;
        if !working.dirty {
            return Err(FsError::DirtyWorkingState);
        }
        let records = self.sync_records()?;
        if records.iter().any(|r| r.unresolved()) {
            return Err(FsError::CheckpointBlocked);
        }
        let candidates: Vec<_> = records
            .iter()
            .filter(|r| r.pending.local_revision == working.head)
            .collect();
        if candidates.len() != 1 {
            return Err(FsError::CheckpointBlocked);
        }
        let record = candidates[0];
        let receipt = record
            .progress
            .shared_receipt
            .as_ref()
            .ok_or(FsError::CheckpointBlocked)?;
        if record.binding != fence.binding
            || receipt.submitted_revision != working.head
            || receipt.replica != self.config.replica
            || receipt.branch != incoming.branch
            || record.progress.state != SubmissionState::Shared
        {
            return Err(FsError::CheckpointBlocked);
        }
        let submitted = self.revision(&working.head)?;
        let remote = self.revision(&incoming.view.revision)?;
        let own = receipt.head == incoming.view.head && remote.tree == submitted.tree;
        let tree = if own {
            working.tree.clone()
        } else {
            let proof = proof.ok_or(FsError::CheckpointBlocked)?;
            if proof.format != CONTINUATION_PROOF_FORMAT
                || !proof.complete_projection
                || proof.namespace != incoming.id
                || proof.request.receipt != *receipt
                || proof.principal != *actor.principal()
                || proof.view != incoming.view
                || proof.descriptor_digest != incoming.view.revision
            {
                return Err(FsError::InvalidDescriptor);
            }
            // The trusted discovery owner validates the service's full published/current
            // ancestry assertion; projected descriptor identifiers are deliberately distinct.
            self.disjoint_tree(
                &submitted.tree,
                &working.tree,
                &remote.tree,
                capabilities,
                actor,
            )?
        };
        let mut next = working.clone();
        next.tree = tree;
        next.base = incoming.view.revision.clone();
        next.head = incoming.view.revision.clone();
        next.remote_source = Some(incoming.source.clone());
        next.generation = working
            .generation
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        next.applied = false;
        Ok((next, !own))
    }
}
impl Replica {
    pub fn prepare_continuation(
        &self,
        binding: &SyncBinding,
        proof: Option<&ContinuationProofV1>,
        fence: &ContinuationFence,
        capabilities: &CapabilitySnapshot,
        actor: Actor,
    ) -> Result<PreparedContinuation, FsError> {
        let core = lock(&self.core)?;
        core.continuation_fence(binding, fence, capabilities)?;
        perm::authority(&core.config, &actor)?;
        let (next, foreign, blocked) =
            match core.prepare_own(binding, fence, capabilities, &actor, proof) {
                Ok((next, foreign)) => (next, foreign, None),
                Err(
                    error @ (FsError::CheckpointBlocked
                    | FsError::MappingBlocked
                    | FsError::PermissionDenied),
                ) => (core.working()?.clone(), false, Some(error.code().into())),
                Err(error) => return Err(error),
            };
        Ok(PreparedContinuation {
            binding: binding.clone(),
            fence: fence.clone(),
            capabilities: capabilities.clone(),
            actor,
            proof: proof.cloned(),
            next,
            foreign,
            blocked,
        })
    }
    pub fn commit_continuation(
        &self,
        prepared: PreparedContinuation,
        fence: &ContinuationFence,
        capabilities: &CapabilitySnapshot,
    ) -> Result<ContinuationOutcome, FsError> {
        let mut core = lock(&self.core)?;
        if prepared.fence != *fence || prepared.capabilities != *capabilities {
            return Err(FsError::GenerationMismatch);
        }
        core.continuation_fence(&prepared.binding, fence, capabilities)?;
        if let Some(reason) = &prepared.blocked {
            if let Some(existing) = core.recoveries()?.into_iter().find(|r| {
                !r.selected_remote
                    && r.fence.as_ref() == Some(fence)
                    && r.binding == prepared.binding
                    && r.status.reason == *reason
            }) {
                return Ok(ContinuationOutcome::Blocked {
                    recovery: existing.status.operation,
                });
            }
            let operation = OperationId::random()?;
            let status = LocalWorkRecovery {
                operation: operation.clone(),
                reason: reason.clone(),
                entries: core
                    .working()?
                    .tree
                    .entries
                    .iter()
                    .map(|e| e.id.clone())
                    .collect(),
                actions: vec![
                    "inspect/export currently readable local work".into(),
                    "close blocking capabilities".into(),
                    "use current remote".into(),
                ],
            };
            let record = RecoveryRecord {
                status,
                working: core.working()?.clone(),
                fence: Some(fence.clone()),
                binding: prepared.binding,
                proof: prepared.proof,
                selected_remote: false,
            };
            core.journal.guard()?;
            crate::faults::hit("recovery-before-commit")?;
            core.journal.db.execute(
                "INSERT INTO local_work_recovery VALUES(?,?)",
                params![operation.as_str(), json(&record)?],
            )?;
            crate::faults::hit("recovery-after-commit")?;
            return Ok(ContinuationOutcome::Blocked {
                recovery: operation,
            });
        }
        let (next, foreign) = core.prepare_own(
            &prepared.binding,
            fence,
            capabilities,
            &prepared.actor,
            prepared.proof.as_ref(),
        )?;
        if foreign != prepared.foreign {
            return Err(FsError::GenerationMismatch);
        }
        if json(&next)? != json(&prepared.next)? {
            return Err(FsError::GenerationMismatch);
        }
        let operation = OperationId::random()?;
        let record = json(&(core.working()?, fence, &prepared.binding, &prepared.proof))?;
        let mut settled = core.recoveries()?;
        for recovery in &mut settled {
            if recovery.working.head == fence.head {
                recovery.selected_remote = true;
            }
        }
        let visibility = if foreign {
            let mut entries = core.working()?.tree.entries.clone();
            entries.extend(next.tree.entries.clone());
            entries.push(perm::root_entry(&next.tree));
            Some(VisibilitySnapshot {
                operation: operation.clone(),
                generation: next.generation,
                authority_generation: fence.authority_generation,
                capability_generation: capabilities.generation,
                tree: next.tree.clone(),
                entries,
            })
        } else {
            None
        };
        core.journal.guard()?;
        crate::faults::hit("continuation-before-commit")?;
        let tx = core
            .journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO continuation_records VALUES(?,?)",
            params![operation.as_str(), record],
        )?;
        for recovery in &settled {
            tx.execute(
                "UPDATE local_work_recovery SET record=? WHERE operation=?",
                params![json(recovery)?, recovery.status.operation.as_str()],
            )?;
        }
        tx.execute(
            "UPDATE sync_binding SET value=? WHERE singleton=1",
            [json(&prepared.binding)?],
        )?;
        tx.execute(
            "UPDATE working SET value=? WHERE singleton=1",
            [json(&next)?],
        )?;
        if let Some(visibility) = &visibility {
            tx.execute(
                "INSERT INTO dirty_visibility VALUES(1,?)",
                [json(visibility)?],
            )?;
        }
        tx.commit()?;
        core.working = Some(next);
        crate::faults::hit("continuation-after-commit")?;
        Ok(if foreign {
            ContinuationOutcome::DirtyReconciled {
                visibility: operation,
            }
        } else {
            ContinuationOutcome::OwnBaseAdvanced
        })
    }
}

impl Core {
    fn disjoint_tree(
        &self,
        base: &Tree,
        local: &Tree,
        remote: &Tree,
        capabilities: &CapabilitySnapshot,
        actor: &Actor,
    ) -> Result<Tree, FsError> {
        use std::collections::BTreeMap;
        if base.root != local.root || base.root != remote.root {
            return Err(FsError::CheckpointBlocked);
        }
        let index = |tree: &Tree| {
            tree.entries
                .iter()
                .map(|e| (e.id.clone(), e.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        let before = index(base);
        let after = index(local);
        let current = index(remote);
        let all: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
        let changed: BTreeSet<_> = all
            .into_iter()
            .filter(|id| before.get(id) != after.get(id))
            .collect();
        let foreign: BTreeSet<_> = before
            .keys()
            .chain(current.keys())
            .filter(|id| before.get(*id) != current.get(*id))
            .cloned()
            .collect();
        if !capabilities.complete
            || foreign
                .iter()
                .any(|id| capabilities.pinned.contains(id) || self.pinned_entry_ids().contains(id))
        {
            return Err(FsError::MappingBlocked);
        }
        for id in &foreign {
            if before
                .get(id)
                .into_iter()
                .chain(current.get(id))
                .any(|e| !matches!(e.content, EntryContent::File { .. }))
            {
                return Err(FsError::CheckpointBlocked);
            }
        }
        for id in &changed {
            let old = before.get(id);
            let new = after.get(id);
            if old != current.get(id) {
                return Err(FsError::CheckpointBlocked);
            }
            if old.is_none() && self.remote_entries.contains(id) {
                return Err(FsError::PermissionDenied);
            }
            if let (Some(old), Some(new)) = (old, new) {
                if old.owner != new.owner || old.group != new.group || old.mode != new.mode {
                    return Err(FsError::CheckpointBlocked);
                }
            }
            for entry in old.into_iter().chain(new) {
                if !matches!(entry.content, EntryContent::File { .. }) {
                    return Err(FsError::CheckpointBlocked);
                }
                let occupancy = |tree: &Tree| {
                    tree.entries
                        .iter()
                        .find(|e| e.parent == entry.parent && e.path == entry.path)
                        .map(|e| e.id.clone())
                };
                if occupancy(base) != occupancy(remote) {
                    return Err(FsError::CheckpointBlocked);
                }
                let mut parent = &entry.parent;
                let mut seen = BTreeSet::new();
                while parent != &base.root.id {
                    if !seen.insert(parent) {
                        return Err(FsError::InvalidTree);
                    }
                    let ancestor = before.get(parent).ok_or(FsError::CheckpointBlocked)?;
                    if after.get(parent) != Some(ancestor)
                        || current.get(parent) != Some(ancestor)
                        || ancestor.content != EntryContent::Directory
                    {
                        return Err(FsError::CheckpointBlocked);
                    }
                    parent = &ancestor.parent;
                }
            }
        }
        let mut result = remote.clone();
        result.entries.retain(|entry| !changed.contains(&entry.id));
        result
            .entries
            .extend(changed.iter().filter_map(|id| after.get(id).cloned()));
        result.entries.sort_by(|a, b| a.path.cmp(&b.path));
        validate_tree(&result)?;
        authorize_tree_transition(
            remote,
            &result,
            perm::authority(&self.config, actor)?,
            &self.config.authorities,
            &TransitionScope {
                read_prefixes: vec![String::new()],
                write_prefixes: vec![String::new()],
                read_only: false,
            },
        )?;
        Ok(result)
    }
}

impl Replica {
    pub fn pending_visibility(&self) -> Result<Option<VisibilitySnapshot>, FsError> {
        let core = lock(&self.core)?;
        core.current_visibility()
    }
    pub fn complete_visibility(
        &self,
        snapshot: &VisibilitySnapshot,
        capabilities: &CapabilitySnapshot,
    ) -> Result<(), FsError> {
        let core = lock(&self.core)?;
        let Some(current) = core.current_visibility()? else {
            return Err(FsError::GenerationMismatch);
        };
        if snapshot.operation != current.operation
            || snapshot.generation != current.generation
            || snapshot.authority_generation != current.authority_generation
            || snapshot.capability_generation != capabilities.generation
            || snapshot.tree != current.tree
            || snapshot.entries != current.entries
        {
            return Err(FsError::GenerationMismatch);
        }
        let authority: Option<String> = core
            .journal
            .db
            .query_row(
                "SELECT revision FROM live_authority WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if authority.is_none() {
            return Err(FsError::PermissionDenied);
        }
        core.journal.guard()?;
        crate::faults::hit("visibility-before-clear")?;
        core.journal
            .db
            .execute("DELETE FROM dirty_visibility WHERE singleton=1", [])?;
        Ok(())
    }
    pub fn local_work_recovery(&self) -> Result<Vec<LocalWorkRecovery>, FsError> {
        let core = lock(&self.core)?;
        core.recoveries()
            .map(|records| records.into_iter().map(|r| r.status).collect())
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct RecoveryRecord {
    status: LocalWorkRecovery,
    working: Working,
    fence: Option<ContinuationFence>,
    binding: SyncBinding,
    proof: Option<ContinuationProofV1>,
    selected_remote: bool,
}
impl Core {
    // Prepared before the caller's transaction so denial/progress and retention
    // become durable together. No synthetic credential or continuation authority.
    pub(crate) fn mounted_recovery_record(
        &self,
        reason: &str,
    ) -> Result<Option<(OperationId, Vec<u8>)>, FsError> {
        let enabled: bool = self.journal.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM mounted_collaboration)",
            [],
            |r| r.get(0),
        )?;
        if !enabled {
            return Ok(None);
        }
        let working = self.working()?;
        if self.recoveries()?.iter().any(|r| {
            !r.selected_remote
                && r.working.generation == working.generation
                && r.status.reason == reason
        }) {
            return Ok(None);
        }
        let binding: SyncBinding = from_json(&self.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        let operation = OperationId::random()?;
        let record = RecoveryRecord {
            status: LocalWorkRecovery {
                operation: operation.clone(),
                reason: reason.into(),
                entries: working.tree.entries.iter().map(|e| e.id.clone()).collect(),
                actions: vec![
                    "inspect/export currently readable local work".into(),
                    "resolve original publication before use current remote".into(),
                ],
            },
            working: working.clone(),
            fence: None,
            binding,
            proof: None,
            selected_remote: false,
        };
        Ok(Some((operation, json(&record)?)))
    }
    fn recoveries(&self) -> Result<Vec<RecoveryRecord>, FsError> {
        self.journal
            .db
            .prepare("SELECT record FROM local_work_recovery ORDER BY rowid")?
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .map(|r| from_json(&r?))
            .collect()
    }
    pub(crate) fn current_visibility(&self) -> Result<Option<VisibilitySnapshot>, FsError> {
        let bytes: Option<Vec<u8>> = self
            .journal
            .db
            .query_row(
                "SELECT record FROM dirty_visibility WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let mut snapshot: VisibilitySnapshot = from_json(&bytes)?;
        let working = self.working()?;
        snapshot.generation = working.generation;
        snapshot.authority_generation = self.journal.db.query_row(
            "SELECT COALESCE(max(generation),0) FROM live_authority_history",
            [],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )?;
        snapshot.tree = working.tree.clone();
        for entry in working
            .tree
            .entries
            .iter()
            .chain(std::iter::once(&perm::root_entry(&working.tree)))
        {
            if !snapshot.entries.contains(entry) {
                snapshot.entries.push(entry.clone());
            }
        }
        Ok(Some(snapshot))
    }
    pub(crate) fn continuation_roots(&self) -> Result<BTreeSet<ObjectId>, FsError> {
        let mut roots = BTreeSet::new();
        let add = |roots: &mut BTreeSet<ObjectId>, working: &Working| {
            roots.extend(crate::cache::object_set(&working.tree));
            for entry in &working.orphans {
                let mut objects = std::collections::BTreeMap::new();
                crate::cache::entry_objects(entry, &mut objects);
                roots.extend(objects.into_keys());
            }
        };
        for record in self.recoveries()? {
            add(&mut roots, &record.working);
        }
        for row in self
            .journal
            .db
            .prepare("SELECT record FROM continuation_records")?
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
        {
            let (working, _, _, _): (
                Working,
                ContinuationFence,
                SyncBinding,
                Option<ContinuationProofV1>,
            ) = from_json(&row?)?;
            add(&mut roots, &working);
        }
        if let Some(snapshot) = self.current_visibility()? {
            roots.extend(crate::cache::object_set(&snapshot.tree));
        }
        Ok(roots)
    }
}

impl Replica {
    pub fn use_current_remote(
        &self,
        operation: &OperationId,
        binding: &SyncBinding,
        fence: &ContinuationFence,
        actor: Actor,
    ) -> Result<Adoption, FsError> {
        let mut core = lock(&self.core)?;
        perm::authority(&core.config, &actor)?;
        core.continuation_fence(
            binding,
            fence,
            &CapabilitySnapshot {
                generation: fence.capability_generation,
                complete: false,
                pinned: BTreeSet::new(),
            },
        )?;
        let mut recovery = core
            .recoveries()?
            .into_iter()
            .find(|r| r.status.operation == *operation)
            .ok_or(FsError::NotFound)?;
        if recovery.selected_remote {
            return Err(FsError::OperationMismatch);
        }
        // Frozen candidates cannot be discarded or implicitly resolved by local selection.
        if core.sync_records()?.iter().any(|r| r.unresolved()) {
            return Err(FsError::CheckpointBlocked);
        }
        let old = core.working()?.clone();
        let remote = core.revision(&binding.view.revision)?;
        if remote.tree.root.id != old.tree.root.id {
            return Err(FsError::BaseMismatch);
        }
        authorize_tree_read(
            &remote.tree,
            &remote.tree.root.id,
            perm::authority(&core.config, &actor)?,
        )?;
        let mut next = old.clone();
        next.tree = remote.tree;
        next.base = binding.view.revision.clone();
        next.head = binding.view.revision.clone();
        next.remote_source = Some(binding.source.clone());
        next.epoch = next.epoch.checked_add(1).ok_or(FsError::LimitExceeded)?;
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        next.dirty = false;
        next.applied = false;
        next.orphans.clear();
        let mut entries = old.tree.entries.clone();
        entries.extend(next.tree.entries.clone());
        entries.push(perm::root_entry(&next.tree));
        recovery.selected_remote = true;
        let snapshot = json(&(&old, fence, binding, &recovery.proof))?;
        let snapshot_id = OperationId::random()?;
        core.journal.guard()?;
        crate::faults::hit("recovery-before-commit")?;
        let tx = core
            .journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO continuation_records VALUES(?,?)",
            params![snapshot_id.as_str(), snapshot],
        )?;
        tx.execute(
            "UPDATE local_work_recovery SET record=? WHERE operation=?",
            params![json(&recovery)?, operation.as_str()],
        )?;
        tx.execute(
            "UPDATE sync_binding SET value=? WHERE singleton=1",
            [json(binding)?],
        )?;
        tx.execute(
            "UPDATE working SET value=? WHERE singleton=1",
            [json(&next)?],
        )?;
        let visibility = VisibilitySnapshot {
            operation: snapshot_id,
            generation: next.generation,
            authority_generation: fence.authority_generation,
            capability_generation: fence.capability_generation,
            tree: next.tree.clone(),
            entries: entries.clone(),
        };
        tx.execute(
            "INSERT OR REPLACE INTO dirty_visibility VALUES(1,?)",
            [json(&visibility)?],
        )?;
        tx.commit()?;
        core.retain_epoch(old);
        let epoch = next.epoch;
        core.working = Some(next);
        crate::faults::hit("recovery-after-commit")?;
        Ok(Adoption {
            revision: binding.view.revision.clone(),
            epoch,
            entries,
        })
    }
    pub fn export_local_work(
        &self,
        operation: &OperationId,
        destination: &std::path::Path,
        actor: Actor,
    ) -> Result<(), FsError> {
        use std::{
            collections::BTreeMap,
            io::{Seek, SeekFrom, Write},
            os::fd::AsRawFd,
            time::{Duration, Instant},
        };
        let mut core = lock(&self.core)?;
        crate::capture::absolute_native(destination)?;
        core.journal.check_content_path(destination)?;
        let record = core
            .recoveries()?
            .into_iter()
            .find(|r| r.status.operation == *operation)
            .ok_or(FsError::NotFound)?;
        let authority = perm::authority(&core.config, &actor)?;
        let context = crate::metadata::MetadataContext::new(&core, authority, None)?;
        let mut entries = Vec::new();
        for entry in &record.working.tree.entries {
            // Only ordinary files and the directories needed to hold them are exported.
            if !matches!(
                entry.content,
                EntryContent::File { .. } | EntryContent::Directory
            ) {
                return Err(FsError::UnsupportedMode);
            }
            context.access(
                entry,
                if entry.content == EntryContent::Directory {
                    5
                } else {
                    4
                },
            )?;
            entries.push(entry.clone());
        }
        drop(context);
        let parent = crate::capture::directory(destination.parent().ok_or(FsError::InvalidPath)?)?;
        let leaf = crate::objects::name(destination.file_name().ok_or(FsError::InvalidPath)?)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let root = crate::objects::open_at(
            parent.as_raw_fd(),
            &leaf,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let mut directories = BTreeMap::new();
        directories.insert(String::new(), root);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let deadline = Instant::now() + Duration::from_millis(4500);
        for entry in entries {
            let parent_path = perm::parent(&entry.path);
            let directory = directories.get(parent_path).ok_or(FsError::InvalidTree)?;
            let name = crate::objects::name(
                std::path::Path::new(&entry.path)
                    .file_name()
                    .ok_or(FsError::InvalidPath)?,
            )?;
            match entry.content {
                EntryContent::Directory => {
                    if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    let child = crate::objects::open_at(
                        directory.as_raw_fd(),
                        &name,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                    )?;
                    directory.sync_all()?;
                    directories.insert(entry.path, child);
                }
                EntryContent::File { version } => {
                    let mut file = crate::objects::open_at(
                        directory.as_raw_fd(),
                        &name,
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    )?;
                    for extent in version.extents {
                        match extent {
                            Extent::Hole { length } => {
                                file.seek(SeekFrom::Current(
                                    i64::try_from(length).map_err(|_| FsError::LimitExceeded)?,
                                ))?;
                            }
                            Extent::Chunk {
                                object,
                                object_size,
                                offset,
                                length,
                            } => {
                                let bytes = core.fetch(&object, object_size, deadline)?;
                                let end = offset
                                    .checked_add(length)
                                    .ok_or(FsError::InvalidDescriptor)?;
                                let slice = bytes
                                    .get(offset as usize..end as usize)
                                    .ok_or(FsError::InvalidDescriptor)?;
                                file.write_all(slice)?;
                            }
                        }
                    }
                    file.set_len(version.size)?;
                    file.sync_all()?;
                    directory.sync_all()?;
                }
            }
        }
        directories[""].sync_all()?;
        parent.sync_all()?;
        Ok(())
    }
}
