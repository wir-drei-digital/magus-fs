//! Explicit acknowledgment of one exact, durably preserved displaced root.
//! This does not merge, publish, delete retained data, or establish writer closure.
use crate::{
    engine::{from_json, json, lock, Core},
    native_apply as na, native_recovery as recovery, native_root as nr, permissions as perm, *,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSettlementSelection {
    pub intent: OperationId,
    pub intent_generation: u64,
    pub retained_digest: ObjectId,
    pub working_generation: u64,
    /// Immutable source records link the owner-private copies, original base and provenance.
    pub recoveries: Vec<NativeRecoveryRecord>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSettlementReceipt {
    pub operation: OperationId,
    pub selection: NativeSettlementSelection,
}
fn owner(core: &Core, actor: &Actor) -> Result<(), FsError> {
    perm::authority(&core.config, actor)?;
    // Current authority, including revocation, remains a gate.
    na::authority_revision(core)?;
    let tree = na::current_authority_overlay(core, &core.working()?.tree)?;
    let a = perm::authority(&core.config, actor)?;
    perm::access(a, &perm::root_entry(&tree), 5)
}
fn selected(core: &Core, operation: &OperationId, actor: &Actor) -> Result<na::Intent, FsError> {
    let r = na::records(core)?
        .into_iter()
        .find(|r| &r.operation == operation)
        .ok_or(FsError::NotFound)?;
    if &r.actor != actor {
        return Err(FsError::PermissionDenied);
    }
    if r.released
        || !r.files.is_empty()
        || !matches!(r.status, NativeApplyStatus::Ready { .. })
        || !r
            .root
            .as_ref()
            .is_some_and(|root| root.phase == nr::RootPhase::Verified && root.ambiguous)
    {
        return Err(FsError::DirtyWorkingState);
    }
    Ok(r)
}
fn observe(core: &Core, r: &mut na::Intent) -> Result<NativeSettlementSelection, FsError> {
    let n = na::configuration(core)?;
    if !matches!(
        nr::rescan(core, &n.policy, r, true)?,
        nr::Rescan::Unchanged | nr::Rescan::Changed
    ) || !r.root.as_ref().unwrap().unsupported.is_empty()
    {
        return Err(FsError::DirtyWorkingState);
    }
    let mut recoveries = vec![];
    let root = r.root.as_ref().unwrap();
    // Every journaled copy must have its immutable source record and verified bytes, rather
    // than trusting a pathname or a caller-provided record as authority.
    for version in &root.versions {
        let bytes: Vec<u8> = core.journal.db.query_row(
            "SELECT record FROM native_recovery WHERE operation=? AND retained=?",
            params![
                r.operation.as_str(),
                version.version.to_str().ok_or(FsError::UnsafeStorage)?
            ],
            |row| row.get(0),
        )?;
        let record: NativeRecoveryRecord = from_json(&bytes)?;
        let (loaded, retained) = recovery::load(core, &record.id)?;
        if loaded != record
            || record.operation != r.operation
            || record.original_base != r.base
            || record.observed_generation != r.generation
            || record.source_path != version.path
            || record.observed_digest != ObjectId::parse(format!("sha256:{}", version.digest))?
            || record.causal_coverage != RecoveryCausality::Unknown
        {
            return Err(FsError::GenerationMismatch);
        }
        recovery::retained_bytes(&retained, &record.observed_digest)?;
        recoveries.push(record);
    }
    Ok(NativeSettlementSelection {
        intent: r.operation.clone(),
        intent_generation: r.generation,
        retained_digest: nr::retained_digest(r)?,
        working_generation: core.working()?.generation,
        recoveries,
    })
}
impl Replica {
    /// Fully observe one completed ambiguous structural intent. Quiesce/rebind affected
    /// writers before selecting/settling; arbitrary writer closure cannot be proven.
    pub fn inspect_native_settlement(
        &self,
        intent: OperationId,
        actor: Actor,
    ) -> Result<NativeSettlementSelection, FsError> {
        let core = lock(&self.core)?;
        owner(&core, &actor)?;
        let mut r = selected(&core, &intent, &actor)?;
        observe(&core, &mut r)
    }
    /// Acknowledge this exact preserved inventory. Original ambiguity/provenance and private
    /// copies remain retained. Replay returns the original receipt and cannot clear new work.
    pub fn settle_native_intent(
        &self,
        selection: NativeSettlementSelection,
        operation: OperationId,
        actor: Actor,
    ) -> Result<NativeSettlementReceipt, FsError> {
        let mut core = lock(&self.core)?;
        owner(&core, &actor)?;
        let mut r = selected(&core, &selection.intent, &actor)?;
        if let Some(bytes) = core
            .journal
            .db
            .query_row(
                "SELECT record FROM native_settlements WHERE operation=?",
                [operation.as_str()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let prior: NativeSettlementReceipt = from_json(&bytes)?;
            return if prior.selection == selection {
                Ok(prior)
            } else {
                Err(FsError::OperationMismatch)
            };
        }
        if r.settlement.is_some() {
            return Err(FsError::OperationMismatch);
        }
        let n = na::configuration(&core)?;
        let mut working = core.working()?.clone();
        if working.generation != selection.working_generation {
            return Err(FsError::GenerationMismatch);
        }
        if working.dirty || na::root_replaced(&core, &n)? {
            return Err(FsError::DirtyWorkingState);
        }
        let baseline = na::baseline(&core)?;
        if na::scan_tree(&core, &n, &working.tree)?.observations != baseline.observations {
            return Err(FsError::DirtyWorkingState);
        }
        let observed = observe(&core, &mut r)?;
        if observed != selection {
            return Err(FsError::GenerationMismatch);
        }
        crate::faults::capture_barrier("native-settlement-before-commit", 1)?;
        // Recheck after the fault boundary; a writer changing during validation is refused.
        if observe(&core, &mut r)? != selection
            || na::scan_tree(&core, &n, &working.tree)?.observations != baseline.observations
        {
            return Err(FsError::GenerationMismatch);
        }
        r.settlement = Some(selection.retained_digest.clone());
        let mut all = na::records(&core)?;
        let mut observations_clear = true;
        for other in all
            .iter_mut()
            .filter(|other| other.operation != r.operation && !other.released)
        {
            observations_clear &= na::verified_generations(other).is_ok();
            if other.root.as_ref().is_some_and(nr::RootIntent::exchanged) {
                observations_clear &= matches!(
                    nr::rescan(&core, &n.policy, other, true)?,
                    nr::Rescan::Unchanged
                );
            }
        }
        let current_completed = all.iter().any(|intent| {
            intent.revision == working.head
                && matches!(intent.status, NativeApplyStatus::Ready { .. })
        });
        let clear = current_completed
            && observations_clear
            && all
                .iter()
                .filter(|other| other.operation != r.operation)
                .all(|other| {
                    !other.ambiguous()
                        && (!other.mutating()
                            || matches!(other.status, NativeApplyStatus::Ready { .. }))
                });
        // This target already has a verified baseline; acknowledgment never installs a target.
        working.applied = clear;
        let receipt = NativeSettlementReceipt {
            operation: operation.clone(),
            selection,
        };
        core.journal.guard()?;
        let tx = core
            .journal
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO native_settlements VALUES(?,?)",
            params![operation.as_str(), json(&receipt)?],
        )?;
        tx.execute(
            "UPDATE native_apply SET record=? WHERE operation=?",
            params![json(&r)?, r.operation.as_str()],
        )?;
        tx.execute(
            "UPDATE working SET value=? WHERE singleton=1",
            [json(&working)?],
        )?;
        {
            // Preserve incoming revision and enumerate original retention; no queue/head change.
            let bytes: Vec<u8> = tx.query_row(
                "SELECT record FROM native_status WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let mut status: NativeStatus = from_json(&bytes)?;
            status.status = if clear {
                NativeApplyStatus::Ready {
                    revision: working.head.clone(),
                }
            } else if !current_completed {
                na::pending("unapplied_current_head")
            } else {
                na::pending("retained_candidate")
            };
            tx.execute(
                "UPDATE native_status SET record=? WHERE singleton=1",
                [json(&status)?],
            )?;
        }
        tx.commit()?;
        core.working = Some(working);
        crate::faults::capture_barrier("native-settlement-committed", 1)?;
        na::refresh_status(&core)?;
        Ok(receipt)
    }
}
