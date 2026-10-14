//! Volatile proof of completed clean mounted visibility. No durable authority.
use crate::{
    engine::{lock, Core},
    permissions as perm, *,
};
use rusqlite::OptionalExtension;
use std::sync::{Arc, Mutex, Weak};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationMode {
    Full,
    Affected,
}
/// Only successful fenced completion can construct a certificate.
pub struct CleanCertificate {
    target: Fence,
    tree: Tree,
    actor: Actor,
    config: ReplicaConfig,
    credential: ObjectId,
}
#[derive(Clone)]
struct Fence {
    head: RevisionId,
    generation: u64,
    epoch: u64,
    binding: SyncBinding,
    authority: u64,
}
/// Non-cloneable obligations owned by one Replica instance.
pub struct PreparedCleanVerification {
    owner: Weak<Mutex<Core>>,
    old: Fence,
    target: Fence,
    tree: Tree,
    actor: Actor,
    config: ReplicaConfig,
    credential: ObjectId,
    capabilities: CapabilitySnapshot,
    mode: VerificationMode,
    present: Vec<Entry>,
    absent: Vec<String>,
}
impl PreparedCleanVerification {
    pub fn mode(&self) -> VerificationMode {
        self.mode
    }
    pub fn present(&self) -> &[Entry] {
        &self.present
    }
    pub fn absent(&self) -> &[String] {
        &self.absent
    }
    pub fn revision(&self) -> &RevisionId {
        &self.target.head
    }
}
impl Core {
    fn clean_fence(&self) -> Result<Fence, FsError> {
        let w = self.working()?;
        let binding = crate::engine::from_json(&self.journal.db.query_row(
            "SELECT value FROM sync_binding WHERE singleton=1",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )?)?;
        let authority = self.journal.db.query_row(
            "SELECT COALESCE(max(generation),0) FROM live_authority_history",
            [],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )?;
        Ok(Fence {
            head: w.head.clone(),
            generation: w.generation,
            epoch: w.epoch,
            binding,
            authority,
        })
    }
    fn clean_authority(&self, target: &RevisionId) -> Result<(), FsError> {
        let authority = self
            .journal
            .db
            .query_row(
                "SELECT revision FROM live_authority WHERE singleton=1",
                [],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if authority.as_deref() != Some(target.as_str()) {
            return Err(FsError::PermissionDenied);
        }
        if self.current_visibility()?.is_some() {
            return Err(FsError::CheckpointWaiting);
        }
        Ok(())
    }
    fn check_clean_fence(&self, fence: &Fence, config: &ReplicaConfig) -> Result<(), FsError> {
        let now = self.clean_fence()?;
        if now.head != fence.head
            || now.generation != fence.generation
            || now.epoch != fence.epoch
            || now.binding != fence.binding
            || now.authority != fence.authority
            || self.config != *config
            || self.working()?.dirty
        {
            return Err(FsError::GenerationMismatch);
        }
        Ok(())
    }
}
impl Replica {
    pub fn invalidate_clean_verification(&self) -> Result<(), FsError> {
        lock(&self.core)?.clean_certificate = None;
        Ok(())
    }
    pub fn prepare_clean_verification(
        &self,
        binding: &SyncBinding,
        expected_generation: u64,
        actor: Actor,
        credential_stamp: &ObjectId,
        capabilities: &CapabilitySnapshot,
    ) -> Result<PreparedCleanVerification, FsError> {
        let mut core = lock(&self.core)?;
        let result = (|| {
            perm::authority(&core.config, &actor)?;
            let old = core.clean_fence()?;
            if old.generation != expected_generation || core.working()?.dirty {
                return Err(FsError::GenerationMismatch);
            }
            core.clean_authority(&binding.view.revision)?;
            // Fresh complete descriptor read/hash/equality remains mandatory on every call.
            let baseline = core.revision(&old.head)?;
            let remote = core.revision(&binding.view.revision)?;
            if baseline.tree != core.working()?.tree {
                return Err(FsError::InvalidTree);
            }
            let target = Fence {
                head: binding.view.revision.clone(),
                generation: old
                    .generation
                    .checked_add(1)
                    .ok_or(FsError::LimitExceeded)?,
                epoch: old.epoch.checked_add(1).ok_or(FsError::LimitExceeded)?,
                binding: binding.clone(),
                authority: old.authority,
            };
            let mut present = remote.tree.entries.clone();
            present.push(perm::root_entry(&remote.tree));
            let mut absent: Vec<String> = baseline
                .tree
                .entries
                .iter()
                .filter(|e| !remote.tree.entries.iter().any(|n| n.path == e.path))
                .map(|e| e.path.clone())
                .collect();
            let mut mode = VerificationMode::Full;
            if let Some(certificate) = &core.clean_certificate {
                let compatible = certificate.target.head == old.head
                    && certificate.target.generation == old.generation
                    && certificate.target.epoch == old.epoch
                    && certificate.target.binding == old.binding
                    && certificate.tree == baseline.tree
                    && core.working()?.applied
                    && certificate.actor == actor
                    && certificate.config == core.config
                    && certificate.credential == *credential_stamp
                    && old.authority == certificate.target.authority.saturating_add(1)
                    && same_context(&old.binding, binding)
                    && binding.publication == PublicationMode::SharedLive;
                if compatible {
                    if let Some((affected, missing)) = affected_obligations(
                        &baseline.tree,
                        &remote.tree,
                        capabilities,
                        &core.pinned_entry_ids(),
                    ) {
                        mode = VerificationMode::Affected;
                        present = affected;
                        absent = missing;
                    }
                }
            }
            Ok(PreparedCleanVerification {
                owner: Arc::downgrade(&self.core),
                old,
                target,
                tree: remote.tree,
                actor,
                config: core.config.clone(),
                credential: credential_stamp.clone(),
                capabilities: capabilities.clone(),
                mode,
                present,
                absent,
            })
        })();
        if result.is_err() {
            core.clean_certificate = None;
        }
        result
    }
    pub fn adopt_prepared_clean(
        &self,
        prepared: &PreparedCleanVerification,
    ) -> Result<Adoption, FsError> {
        let mut core = lock(&self.core)?;
        let result = (|| {
            if !Weak::ptr_eq(&prepared.owner, &Arc::downgrade(&self.core)) {
                return Err(FsError::ConfigMismatch);
            }
            core.check_clean_fence(&prepared.old, &prepared.config)?;
            core.clean_authority(&prepared.target.head)?;
            // A preparation is never itself a reusable certificate.
            core.clean_certificate = None;
            let adoption = core.adopt_clean(
                &prepared.target.head,
                prepared.old.generation,
                prepared.actor.clone(),
                Some(prepared.target.binding.clone()),
            )?;
            core.check_clean_fence(&prepared.target, &prepared.config)?;
            Ok(adoption)
        })();
        if result.is_err() {
            core.clean_certificate = None;
        }
        result
    }
    pub fn complete_clean_verification(
        &self,
        prepared: PreparedCleanVerification,
        credential_stamp: &ObjectId,
        capabilities: &CapabilitySnapshot,
    ) -> Result<(), FsError> {
        let mut core = lock(&self.core)?;
        let result = (|| {
            if !Weak::ptr_eq(&prepared.owner, &Arc::downgrade(&self.core)) {
                return Err(FsError::ConfigMismatch);
            }
            if prepared.credential != *credential_stamp || prepared.capabilities != *capabilities {
                return Err(FsError::GenerationMismatch);
            }
            core.check_clean_fence(&prepared.target, &prepared.config)?;
            core.clean_authority(&prepared.target.head)?;
            if core.revision(&prepared.target.head)?.tree != prepared.tree
                || core.working()?.tree != prepared.tree
            {
                return Err(FsError::InvalidTree);
            }
            core.acknowledge_clean(&prepared.target.head, prepared.target.epoch)?;
            core.clean_certificate = Some(CleanCertificate {
                target: prepared.target,
                tree: prepared.tree,
                actor: prepared.actor,
                config: prepared.config,
                credential: prepared.credential,
            });
            Ok(())
        })();
        if result.is_err() {
            core.clean_certificate = None;
        }
        result
    }
}

fn same_context(a: &SyncBinding, b: &SyncBinding) -> bool {
    a.id == b.id
        && a.branch == b.branch
        && a.publication == b.publication
        && a.transport_profile == b.transport_profile
        && a.transport_identity == b.transport_identity
}
fn same_permissions(a: &Entry, b: &Entry) -> bool {
    a.owner == b.owner && a.group == b.group && a.mode == b.mode
}
fn affected_obligations(
    old: &Tree,
    new: &Tree,
    capabilities: &CapabilitySnapshot,
    core_pins: &std::collections::BTreeSet<EntryId>,
) -> Option<(Vec<Entry>, Vec<String>)> {
    use std::collections::{BTreeMap, BTreeSet};
    if old.root != new.root || !capabilities.complete {
        return None;
    }
    let before: BTreeMap<_, _> = old.entries.iter().map(|e| (&e.id, e)).collect();
    let after: BTreeMap<_, _> = new.entries.iter().map(|e| (&e.id, e)).collect();
    let old_slots: BTreeMap<_, _> = old.entries.iter().map(|e| (&e.path, e)).collect();
    let new_slots: BTreeMap<_, _> = new.entries.iter().map(|e| (&e.path, e)).collect();
    let ids: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let mut paths = BTreeSet::new();
    for id in ids {
        let a = before.get(id).copied();
        let b = after.get(id).copied();
        if a == b {
            continue;
        }
        if capabilities.pinned.contains(id) || core_pins.contains(id) {
            return None;
        }
        if a.into_iter()
            .chain(b)
            .any(|e| e.content == EntryContent::Directory)
        {
            return None;
        }
        match (a, b) {
            (Some(a), Some(b)) => {
                if !same_permissions(a, b) {
                    return None;
                }
                changed.push(b);
            }
            (Some(a), None) => removed.push(a),
            (None, Some(b)) => added.push(b),
            _ => unreachable!(),
        }
        for e in a.into_iter().chain(b) {
            paths.insert(e.path.clone());
        }
    }
    // Initial envelope: one content edit/rename, or one atomic identity replacement.
    // A standalone addition or removal cannot establish unchanged projected scope.
    if changed.len() > 1
        || removed.len() > 1
        || added.len() > 1
        || (!added.is_empty() && (!changed.is_empty() || removed.len() != 1))
    {
        return None;
    }
    for e in &removed {
        let occupant = new_slots.get(&e.path)?;
        if !same_permissions(e, occupant) {
            return None;
        }
    }
    for e in &added {
        let previous = old_slots.get(&e.path)?;
        if !same_permissions(previous, e) {
            return None;
        }
    }
    let mut present = BTreeMap::new();
    let mut absent = Vec::new();
    present.insert(String::new(), perm::root_entry(new));
    for path in paths {
        if let Some(e) = new_slots.get(&path) {
            present.insert(path.clone(), (*e).clone());
        } else {
            absent.push(path.clone());
        }
        let mut ancestor = path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            let e = new_slots.get(&parent.to_owned())?;
            if e.content != EntryContent::Directory {
                return None;
            }
            present.insert(parent.to_owned(), (*e).clone());
            ancestor = parent;
        }
    }
    Some((present.into_values().collect(), absent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;
    use std::{
        io::Write,
        path::Path,
        time::{Duration, Instant},
    };
    fn import(rep: &Replica, r: &Revision) -> RevisionId {
        rep.import_revision(
            ImportDescriptor {
                expected: revision_id(r).unwrap(),
                bytes: encode_revision(r).unwrap(),
            },
            ChunkSource::Unavailable,
        )
        .unwrap()
    }
    fn rotate(rep: &Replica, b: &mut SyncBinding, r: &Revision) {
        b.source = RemoteSourceId::random().unwrap();
        b.view.view = ViewId::random().unwrap();
        b.view.head = HeadToken::random().unwrap();
        b.view.revision = import(rep, r);
        rep.observe_remote_authority(
            Some(&b.view.revision),
            rep.live_status().unwrap().authority_generation,
        )
        .unwrap();
    }
    fn snapshot() -> CapabilitySnapshot {
        CapabilitySnapshot {
            generation: 0,
            complete: true,
            pinned: Default::default(),
        }
    }
    fn stamp() -> ObjectId {
        ObjectId::for_bytes(b"offline-credential-stamp").unwrap()
    }
    fn prepare(rep: &Replica, b: &SyncBinding, actor: &Actor) -> PreparedCleanVerification {
        rep.prepare_clean_verification(
            b,
            rep.scheduling_snapshot().unwrap().generation,
            actor.clone(),
            &stamp(),
            &snapshot(),
        )
        .unwrap()
    }
    // Simulates the Core side of fresh pathname LOOKUP, not kernel scheduling/cache behavior.
    fn ordinary(w: &Workspace, p: &PreparedCleanVerification, deadline: Instant) -> usize {
        let mut calls = 0;
        for e in p.present() {
            assert!(Instant::now() < deadline, "offline total deadline");
            let parent = if e.path.is_empty() { &e.id } else { &e.parent };
            w.lookup_identity(parent).unwrap();
            let actual = w.lookup(&e.path).unwrap();
            assert_eq!(actual, *e);
            assert_eq!(w.native_attributes(&actual).unwrap(), *e);
            calls += 3;
        }
        for path in p.absent() {
            assert!(matches!(w.lookup(path), Err(FsError::NotFound)));
            calls += 1;
        }
        calls
    }
    fn published(rep: &Replica, b: &SyncBinding, id: &RevisionId) {
        let operation = rep.revision(id).unwrap().operation;
        let replica = rep.configuration().unwrap().replica;
        rep.enqueue_submission(PendingSubmission {
            operation: operation.clone(),
            local_revision: id.clone(),
            original_view: b.view.view.clone(),
            original_head: b.view.head.clone(),
            expected_local_generation: rep.scheduling_snapshot().unwrap().generation,
        })
        .unwrap();
        let mut progress = rep
            .sync_status()
            .unwrap()
            .submissions
            .into_iter()
            .find(|p| p.operation == operation)
            .unwrap();
        let private = PrivateReceipt {
            receipt: ReceiptId::random().unwrap(),
            operation: operation.clone(),
            replica: replica.clone(),
            submitted_revision: id.clone(),
            original_view: b.view.view.clone(),
            original_head: b.view.head.clone(),
        };
        let integration = IntegrationRequest {
            operation: OperationId::random().unwrap(),
            replica: replica.clone(),
            candidate_receipt: private.receipt.clone(),
            expected_head: b.view.head.clone(),
            branch: b.branch.clone(),
        };
        let shared = SharedReceipt {
            receipt: ReceiptId::random().unwrap(),
            operation: integration.operation.clone(),
            replica: replica.clone(),
            submitted_revision: id.clone(),
            branch: b.branch.clone(),
            head: HeadToken::random().unwrap(),
        };
        let request = CandidateRequest {
            operation: operation.clone(),
            replica,
            original_view: b.view.view.clone(),
            original_head: b.view.head.clone(),
            revision: id.clone(),
            upload: UploadId::random().unwrap(),
        };
        progress.request_digest = Some(
            RevisionId::parse(
                ObjectId::for_bytes(&serde_json::to_vec(&request).unwrap())
                    .unwrap()
                    .as_str(),
            )
            .unwrap(),
        );
        progress.request = Some(request);
        progress.private_receipt = Some(private);
        progress.integration = Some(integration);
        progress.shared_receipt = Some(shared);
        progress.state = SubmissionState::Shared;
        rep.record_sync_progress(&operation, SubmissionState::Queued, progress)
            .unwrap();
    }
    fn offline_attribution() -> Attribution {
        Attribution {
            captured_at_ns: 0,
            coverage: vec![String::new()],
            provenance: "engine_observed".into(),
        }
    }
    #[test]
    fn offline_checkpoint_provenance_is_supported() {
        let principal = PrincipalId::parse("principal:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let a = offline_attribution();
        let r = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            principal: principal.clone(),
            captured_at_ns: a.captured_at_ns,
            coverage: a.coverage,
            provenance: a.provenance,
            restoration: None,
            tree: Tree {
                root: Root {
                    id: EntryId::random().unwrap(),
                    owner: principal,
                    group: GroupId::parse("group:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
                    mode: 0o755,
                },
                entries: vec![],
            },
        };
        assert!(
            encode_revision(&r).is_ok(),
            "offline checkpoint attribution must satisfy the real descriptor codec"
        );
    }
    fn setup(
        path: &Path,
        baseline: &Revision,
        sender: bool,
    ) -> (Replica, Workspace, SyncBinding, Actor) {
        let actor = Actor::new(baseline.principal.clone());
        let group = baseline.tree.root.group.clone();
        let config = ReplicaConfig {
            replica: baseline.replica.clone(),
            authorities: vec![Authority {
                principal: baseline.principal.clone(),
                uid: 1001,
                primary_group: group.clone(),
                gid: 1001,
                groups: vec![group],
                dac_override: false,
                ownership_transfer: true,
            }],
            content_roots: vec![],
            cache_bytes: 1024 * 1024,
            history_administrators: vec![],
            retained_history_grants: vec![],
        };
        let rep = Replica::open(path, config).unwrap();
        let id = import(&rep, baseline);
        let w = rep.begin_live(&id, actor.clone(), false).unwrap();
        let mut b = SyncBinding {
            id: NamespaceId::random().unwrap(),
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::SharedLive,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision: id,
            },
            transport_profile: "/private/tmp/offline-synthetic-service.json".into(),
            transport_identity: TransportIdentity::for_bytes(b"approved-service-contract").unwrap(),
        };
        rep.configure_sync(b.clone()).unwrap();
        rep.observe_remote_authority(Some(&b.view.revision), 0)
            .unwrap();
        let mut seed = baseline.clone();
        seed.operation = OperationId::random().unwrap();
        rotate(&rep, &mut b, &seed);
        let p = prepare(&rep, &b, &actor);
        assert_eq!(p.mode(), VerificationMode::Full);
        rep.adopt_prepared_clean(&p).unwrap();
        ordinary(&w, &p, Instant::now() + Duration::from_secs(120));
        rep.complete_clean_verification(p, &stamp(), &snapshot())
            .unwrap();
        if sender {
            // Real local generation invalidation, with final bytes/permissions restored.
            // This omits body-write costs and thus is a favorable sender lower-work proxy.
            let e = &baseline.tree.entries[0];
            w.chmod(&e.path, e.mode ^ 0o100).unwrap();
            w.chmod(&e.path, e.mode).unwrap();
            let id = w
                .checkpoint(
                    &OperationId::random().unwrap(),
                    w.generation().unwrap(),
                    offline_attribution(),
                )
                .unwrap();
            published(&rep, &b, &id);
        }
        rep.set_metadata_profile_enabled(true).unwrap();
        (rep, w, b, actor)
    }
    fn emit(file: &mut std::fs::File, value: serde_json::Value) {
        serde_json::to_writer(&mut *file, &value).unwrap();
        writeln!(file).unwrap();
        file.flush().unwrap();
    }
    #[test]
    #[ignore = "one explicitly supervised three-delta offline decision"]
    fn offline_comparison() {
        use sha2::{Digest, Sha256};
        let input = std::fs::read(std::env::var("MAGUS_AFFECTED_INPUT").unwrap()).unwrap();
        let baseline = decode_revision(&input).unwrap();
        assert_eq!(
            revision_id(&baseline).unwrap().as_str(),
            "sha256:c40d27e10a9bb39f7ce5efb438f2fa40f92f9a648f6d9fa35e5ac877c684843e"
        );
        assert_eq!(baseline.tree.entries.len(), 502);
        let output = std::path::PathBuf::from(std::env::var("MAGUS_AFFECTED_OUTPUT").unwrap());
        let canonical = encode_revision(&baseline).unwrap();
        std::fs::write(output.with_extension("canonical.json"), &canonical).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)
            .unwrap();
        emit(
            &mut file,
            serde_json::json!({"kind":"setup","canonical_sha256":crate::model::hex(&Sha256::digest(&canonical)),"input_sha256":crate::model::hex(&Sha256::digest(&input)),"representation":"generated canonical bytes, not original SQLite encoding"}),
        );
        let mut fixtures = Vec::new();
        for delta in 0..3 {
            for sender in [false, true] {
                let path = output
                    .parent()
                    .unwrap()
                    .join(format!("state-{delta}-{sender}"));
                fixtures.push((delta, sender, setup(&path, &baseline, sender)));
            }
        }
        let start = Instant::now();
        let deadline = start + Duration::from_secs(120);
        emit(
            &mut file,
            serde_json::json!({"kind":"start","budget_seconds":120,"deltas":["same-id-content","atomic-replacement","standalone-creation"],"endpoints":["clean-receiver","mutation-invalidated-sender"],"kernel":"unmeasured","sender":"real chmod/revert/checkpoint plus synthetic admitted Shared receipt; body costs omitted","ordinary":"Core calls for parent lookup, path lookup, native attributes; no VFS"}),
        );
        for (delta, sender, (rep, w, mut binding, actor)) in fixtures {
            assert!(Instant::now() < deadline, "offline total deadline");
            let mut target = baseline.clone();
            target.operation = OperationId::random().unwrap();
            // Fixed deltas: same-size content descriptor, same-slot identity replacement, creation.
            let file_index = target
                .tree
                .entries
                .iter()
                .position(|e| matches!(e.content, EntryContent::File { .. }))
                .unwrap();
            match delta {
                0 => {
                    if let EntryContent::File { version } =
                        &mut target.tree.entries[file_index].content
                    {
                        for extent in &mut version.extents {
                            if let Extent::Chunk { object, .. } = extent {
                                *object =
                                    ObjectId::for_bytes(b"deterministic-offline-content-delta")
                                        .unwrap();
                            }
                        }
                    }
                }
                1 => {
                    target.tree.entries[file_index].id =
                        EntryId::parse("entry:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap()
                }
                _ => {
                    let mut entry = target.tree.entries[file_index].clone();
                    entry.path = "zz-offline-created".into();
                    entry.id = EntryId::parse("entry:dddddddddddddddddddddddddddddddd").unwrap();
                    target.tree.entries.push(entry);
                }
            }
            rotate(&rep, &mut binding, &target);
            let profile = rep.begin_metadata_profile(&binding.view.revision).unwrap();
            let cpu = metadata_thread_cpu_ns();
            let wall = Instant::now();
            let prep_start = Instant::now();
            let p = prepare(&rep, &binding, &actor);
            let prepare_ns = prep_start.elapsed().as_nanos();
            assert_eq!(
                p.mode(),
                if sender || delta == 2 {
                    VerificationMode::Full
                } else {
                    VerificationMode::Affected
                }
            );
            let mode = format!("{:?}", p.mode());
            let present = p.present.len();
            let absent = p.absent.len();
            let ancestor_count = p
                .present
                .iter()
                .filter(|e| e.content == EntryContent::Directory)
                .count();
            let adopt_start = Instant::now();
            let adoption = rep.adopt_prepared_clean(&p).unwrap();
            let adoption_ns = adopt_start.elapsed().as_nanos();
            let notifier_start = Instant::now();
            let remembered: Vec<_> = std::iter::once(&baseline.tree.root.id)
                .chain(baseline.tree.entries.iter().map(|e| &e.id))
                .collect();
            let mut notifications = remembered.len();
            for e in &adoption.entries {
                if !e.path.is_empty() {
                    for id in &remembered {
                        if **id == e.parent {
                            notifications += 1;
                            std::hint::black_box((&e.parent, &e.path));
                        }
                    }
                }
            }
            let notifier_estimate_ns = notifier_start.elapsed().as_nanos();
            let ordinary_start = Instant::now();
            let ordinary_calls = ordinary(&w, &p, deadline);
            let ordinary_ns = ordinary_start.elapsed().as_nanos();
            let completion_start = Instant::now();
            rep.complete_clean_verification(p, &stamp(), &snapshot())
                .unwrap();
            let completion_ns = completion_start.elapsed().as_nanos();
            let wall_ns = wall.elapsed().as_nanos();
            let cpu_ns = cpu
                .zip(metadata_thread_cpu_ns())
                .map(|(a, b)| b.saturating_sub(a));
            let retained_tree_bytes = serde_json::to_vec(
                &lock(&rep.core)
                    .unwrap()
                    .clean_certificate
                    .as_ref()
                    .unwrap()
                    .tree,
            )
            .unwrap()
            .len();
            emit(
                &mut file,
                serde_json::json!({"kind":"cell","delta":delta,"sender":sender,"mode":mode,"reason":if sender{"local mutation invalidated generation"}else if delta==2{"standalone creation outside envelope"}else{"compatible full-seeded clean chain"},"present":present,"absent":absent,"ancestors":ancestor_count,"ordinary_calls":ordinary_calls,"notifications":notifications,"notifier_estimate_ns":notifier_estimate_ns,"prepare_ns":prepare_ns,"adoption_ns":adoption_ns,"ordinary_ns":ordinary_ns,"completion_ns":completion_ns,"wall_ns":wall_ns,"cpu_ns":cpu_ns,"certificate_serialized_tree_bytes":retained_tree_bytes,"certificate_size_note":"serialized retained tree size, excludes Rust allocation overhead; one tree only","profile":profile.finish(),"applied":rep.live_status().unwrap().applied}),
            );
        }
        emit(
            &mut file,
            serde_json::json!({"kind":"end","elapsed_ns":start.elapsed().as_nanos(),"cleanup":"six owned offline replica directories retained under output; no external services/processes/mounts created"}),
        );
    }
}
