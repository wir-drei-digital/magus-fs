use super::*;
fn fixture() -> (tempfile::TempDir, Replica, RevisionId) {
    let dir = tempfile::Builder::new()
        .prefix("metadata-reuse-")
        .tempdir_in(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .unwrap();
    let principal = PrincipalId::parse(format!("principal:{:032x}", 1)).unwrap();
    let group = GroupId::parse(format!("group:{:032x}", 1)).unwrap();
    let config = ReplicaConfig {
        replica: ReplicaId::random().unwrap(),
        authorities: vec![Authority {
            principal: principal.clone(),
            uid: 1001,
            primary_group: group.clone(),
            gid: 1001,
            groups: vec![group.clone()],
            dac_override: false,
            ownership_transfer: true,
        }],
        history_administrators: vec![],
        retained_history_grants: vec![],
        content_roots: vec![],
        cache_bytes: 1024 * 1024,
    };
    let r = Revision {
        format: FORMAT.into(),
        hash: HASH.into(),
        layout: LAYOUT.into(),
        parents: vec![],
        operation: OperationId::random().unwrap(),
        replica: config.replica.clone(),
        principal: principal.clone(),
        captured_at_ns: 0,
        coverage: vec![String::new()],
        provenance: "explicit".into(),
        restoration: None,
        tree: Tree {
            root: Root {
                id: EntryId::random().unwrap(),
                owner: principal,
                group,
                mode: 0o755,
            },
            entries: vec![],
        },
    };
    let rep = Replica::open(dir.path().join("state"), config).unwrap();
    let id = rep
        .import_revision(
            ImportDescriptor {
                expected: revision_id(&r).unwrap(),
                bytes: encode_revision(&r).unwrap(),
            },
            ChunkSource::Unavailable,
        )
        .unwrap();
    (dir, rep, id)
}
fn replace(core: &Core, id: &RevisionId, bytes: &[u8]) {
    core.journal
        .db
        .execute(
            "UPDATE revisions SET descriptor=? WHERE id=?",
            rusqlite::params![bytes, id.as_str()],
        )
        .unwrap();
}
#[test]
fn fresh_select_and_hash_precede_every_hit() {
    let (_dir, rep, id) = fixture();
    rep.set_metadata_profile_enabled(true).unwrap();
    let window = rep.begin_metadata_profile(&id).unwrap();
    {
        let core = crate::engine::lock(&rep.core).unwrap();
        let _callback = crate::metadata_profile::Callback::for_core(&core);
        let first = load(&core, &id).unwrap();
        let second = load(&core, &id).unwrap();
        assert_eq!(first, second);
        assert!(
            Arc::ptr_eq(&first, &second),
            "verified immutable descriptor should be reused"
        );
    }
    let profile = window.finish();
    assert_eq!(profile.revision_load_count, 2);
    assert_eq!(profile.descriptor_hits, 1);
    assert_eq!(profile.descriptor_misses, 1);
    assert_eq!(profile.raw_bytes, 2 * profile.decoded_bytes);
}
#[test]
fn same_length_corruption_and_sql_errors_never_fallback() {
    let (_dir, rep, id) = fixture();
    let core = crate::engine::lock(&rep.core).unwrap();
    let r = load(&core, &id).unwrap();
    let original = encode_revision(&r).unwrap();
    let mut wrong = (*r).clone();
    wrong.tree.root.mode = 0o700;
    let wrong = encode_revision(&wrong).unwrap();
    assert_eq!(wrong.len(), original.len());
    let mut invalid = (*r).clone();
    invalid.tree.root.mode = 0xffff;
    for bytes in [
        wrong,
        b"{".to_vec(),
        vec![b' '; MAX_DESCRIPTOR + 1],
        serde_json::to_vec(&invalid).unwrap(),
    ] {
        replace(&core, &id, &bytes);
        assert_eq!(
            load(&core, &id).unwrap_err().code(),
            core.revision(&id).unwrap_err().code()
        );
        replace(&core, &id, &original);
        load(&core, &id).unwrap();
    }
    core.journal
        .db
        .execute("DELETE FROM revisions WHERE id=?", [id.as_str()])
        .unwrap();
    assert_eq!(load(&core, &id).unwrap_err().code(), "not_found");
    core.journal
        .db
        .execute("ALTER TABLE revisions RENAME TO missing_revisions", [])
        .unwrap();
    assert_eq!(load(&core, &id).unwrap_err().code(), "database_error");
}
#[test]
fn noncanonical_and_restore_keep_acceptance() {
    let (_dir, rep, id) = fixture();
    let core = crate::engine::lock(&rep.core).unwrap();
    let first = load(&core, &id).unwrap();
    replace(&core, &id, &serde_json::to_vec_pretty(&*first).unwrap());
    let second = load(&core, &id).unwrap();
    assert_eq!(first, second);
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&second, &load(&core, &id).unwrap()));
    let mut restored = (*first).clone();
    restored.format = RESTORE_FORMAT.into();
    restored.parents.push(id.clone());
    restored.restoration = Some(RestoreProvenance {
        source_revision: id,
        restore_metadata: false,
        recreated: Default::default(),
    });
    let rid = revision_id(&restored).unwrap();
    core.journal
        .db
        .execute(
            "INSERT INTO revisions(id,descriptor) VALUES(?,?)",
            rusqlite::params![rid.as_str(), encode_revision(&restored).unwrap()],
        )
        .unwrap();
    let a = load(&core, &rid).unwrap();
    let b = load(&core, &rid).unwrap();
    assert_eq!(a, b);
    assert!(!Arc::ptr_eq(&a, &b));
}
#[test]
fn two_slots_account_capacity_and_evict_lru() {
    let (_dir, rep, id) = fixture();
    let core = crate::engine::lock(&rep.core).unwrap();
    let first = load(&core, &id).unwrap();
    let mut r = (*first).clone();
    let mut ids = vec![id.clone()];
    for n in 1..3 {
        r.captured_at_ns = n;
        let key = revision_id(&r).unwrap();
        core.journal
            .db
            .execute(
                "INSERT INTO revisions(id,descriptor) VALUES(?,?)",
                rusqlite::params![key.as_str(), encode_revision(&r).unwrap()],
            )
            .unwrap();
        ids.push(key);
    }
    let second = load(&core, &ids[1]).unwrap();
    assert!(Arc::ptr_eq(&first, &load(&core, &id).unwrap()));
    load(&core, &ids[2]).unwrap();
    assert!(Arc::ptr_eq(&first, &load(&core, &id).unwrap()));
    assert!(!Arc::ptr_eq(&second, &load(&core, &ids[1]).unwrap()));
    let cache = core.metadata_descriptors.borrow();
    assert_eq!(cache.slots.iter().flatten().count(), 2);
    assert!(cache.retained() <= BUDGET);
    drop(cache);
    let mut raw = encode_revision(&r).unwrap();
    let initial = retained_bytes(&id, &raw, &r).unwrap();
    let old = raw.capacity();
    raw.reserve_exact(2048);
    assert_eq!(
        retained_bytes(&id, &raw, &r).unwrap() - initial,
        raw.capacity() - old
    );
    let initial = retained_bytes(&id, &raw, &r).unwrap();
    let old = r.provenance.capacity();
    r.provenance.reserve_exact(2048);
    assert_eq!(
        retained_bytes(&id, &raw, &r).unwrap() - initial,
        r.provenance.capacity() - old
    );
    assert_eq!(allocation::<Entry>(usize::MAX), None);
    // A valid decoded value with spare allocations can exceed the retained budget.
    let mut cache = DescriptorCache::new();
    let r = Arc::new(r);
    let overhead = retained_bytes(&id, &Vec::new(), &r).unwrap() + size_of::<DescriptorCache>();
    let raw = Vec::with_capacity(BUDGET - overhead);
    cache.insert(id.clone(), [0; 32], raw, Arc::clone(&r));
    assert_eq!(cache.retained(), BUDGET);
    let mut cache = DescriptorCache::new();
    cache.insert(id, [0; 32], Vec::with_capacity(BUDGET - overhead + 1), r);
    assert_eq!(cache.slots.iter().flatten().count(), 0);
}
#[test]
fn separate_roots_reopen_and_immutable_values() {
    let (dir, rep, id) = fixture();
    let config = crate::engine::lock(&rep.core).unwrap().config.clone();
    {
        let core = crate::engine::lock(&rep.core).unwrap();
        let original = load(&core, &id).unwrap();
        let mut returned = (*original).clone();
        returned.tree.root.mode = 0;
        assert_eq!(load(&core, &id).unwrap().tree.root.mode, 0o755);
        let (_other_dir, other, _other_id) = fixture();
        let other = crate::engine::lock(&other.core).unwrap();
        assert_eq!(load(&other, &id).unwrap_err().code(), "not_found");
        assert!(other
            .metadata_descriptors
            .borrow()
            .slots
            .iter()
            .all(Option::is_none));
    }
    drop(rep);
    let rep = Replica::open(dir.path().join("state"), config).unwrap();
    let core = crate::engine::lock(&rep.core).unwrap();
    assert!(core
        .metadata_descriptors
        .borrow()
        .slots
        .iter()
        .all(Option::is_none));
    load(&core, &id).unwrap();
}
#[test]
fn broken_journal_guard_never_uses_cache() {
    let (dir, rep, id) = fixture();
    let core = crate::engine::lock(&rep.core).unwrap();
    load(&core, &id).unwrap();
    std::fs::rename(
        dir.path().join("state/journal.sqlite"),
        dir.path().join("state/displaced.sqlite"),
    )
    .unwrap();
    assert_eq!(
        load(&core, &id).unwrap_err().code(),
        core.journal.guard().unwrap_err().code()
    );
    assert!(core
        .metadata_descriptors
        .borrow()
        .slots
        .iter()
        .all(Option::is_none));
}

#[test]
fn valid_descriptor_over_retained_budget_is_uncached() {
    let (_dir, rep, id) = fixture();
    let core = crate::engine::lock(&rep.core).unwrap();
    let r = load(&core, &id).unwrap();
    let mut raw = encode_revision(&r).unwrap();
    raw.resize(MAX_DESCRIPTOR, b' ');
    replace(&core, &id, &raw);
    let a = load(&core, &id).unwrap();
    let b = load(&core, &id).unwrap();
    assert_eq!(a, b);
    assert!(!Arc::ptr_eq(&a, &b));
    assert!(core
        .metadata_descriptors
        .borrow()
        .slots
        .iter()
        .all(Option::is_none));
}

#[test]
#[ignore = "one explicitly supervised fixed-budget release comparison"]
fn comparison() {
    use std::{
        io::Write,
        time::{Duration, Instant},
    };
    let input = std::path::PathBuf::from(std::env::var("MAGUS_METADATA_BENCH_INPUT").unwrap());
    let expected =
        RevisionId::parse(std::env::var("MAGUS_METADATA_BENCH_REVISION").unwrap()).unwrap();
    let output = std::path::PathBuf::from(std::env::var("MAGUS_METADATA_BENCH_OUTPUT").unwrap());
    let bytes = std::fs::read(&input).unwrap();
    let descriptor = decode_revision(&bytes).unwrap();
    assert_eq!(revision_id(&descriptor).unwrap(), expected);
    assert_eq!(descriptor.tree.entries.len(), 502);
    let canonical = encode_revision(&descriptor).unwrap();
    std::fs::write(output.with_extension("canonical.json"), &canonical).unwrap();
    let (_dir, rep, _unused) = fixture();
    {
        let core = crate::engine::lock(&rep.core).unwrap();
        core.journal
            .db
            .execute(
                "INSERT INTO revisions(id,descriptor) VALUES(?,?)",
                rusqlite::params![expected.as_str(), &canonical],
            )
            .unwrap();
    }
    rep.set_metadata_profile_enabled(true).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output)
        .unwrap();
    fn emit(file: &mut std::fs::File, value: serde_json::Value) {
        serde_json::to_writer(&mut *file, &value).unwrap();
        writeln!(file).unwrap();
        file.flush().unwrap();
    }
    let campaign = Instant::now();
    let deadline = campaign + Duration::from_secs(120);
    emit(
        &mut file,
        serde_json::json!({"kind":"start","schema":"magus-fs/metadata-comparison/v1","input_sha256":crate::model::hex(&Sha256::digest(&bytes)),"canonical_sha256":crate::model::hex(&Sha256::digest(&canonical)),"revision":expected.as_str(),"canonical_bytes":canonical.len(),"representation":"generated canonical reconstruction, not original SQLite bytes","warmups":100,"requests_per_block":1000,"orders":["ABC","BCA","CAB","ABC","BCA"],"budget_seconds":120,"cpu_clock":"CLOCK_THREAD_CPUTIME_ID","profile":"release; opt-in aggregate diagnostics enabled for all mechanisms","timing":"wall and actual thread CPU separate; stage maps exclusive, inclusive spans not summed"}),
    );
    fn batch(
        rep: &Replica,
        id: &RevisionId,
        mechanism: char,
        requests: usize,
        deadline: Instant,
    ) -> serde_json::Value {
        let window = rep.begin_metadata_profile(id).unwrap();
        let cpu = metadata_thread_cpu_ns();
        let wall = Instant::now();
        let mut completed = 0;
        {
            let core = crate::engine::lock(&rep.core).unwrap();
            for _ in 0..requests {
                if Instant::now() >= deadline {
                    break;
                }
                let _callback = crate::metadata_profile::Callback::for_core(&core);
                for _ in 0..if matches!(mechanism, 'B' | 'D') { 1 } else { 3 } {
                    if matches!(mechanism, 'C' | 'D') {
                        std::hint::black_box(load(&core, id).unwrap());
                    } else {
                        core.journal.guard().unwrap();
                        std::hint::black_box(core.revision(id).unwrap());
                    }
                }
                completed += 1;
            }
        }
        let cpu = cpu.zip(metadata_thread_cpu_ns()).map(|(a, b)| b - a);
        let wall = wall.elapsed().as_nanos() as u64;
        let profile = window.finish();
        let retained = crate::engine::lock(&rep.core)
            .unwrap()
            .metadata_descriptors
            .borrow()
            .retained();
        serde_json::json!({"mechanism":mechanism.to_string(),"requests":completed,"cpu_ns":cpu,"wall_ns":wall,"profile":profile,"retained_bytes":retained,"timed_out":completed!=requests})
    }
    let mut cold = batch(&rep, &expected, 'D', 1, deadline);
    cold["kind"] = "cold".into();
    cold["note"] = "one fresh SELECT/decode/canonical verification and cache fill".into();
    emit(&mut file, cold);
    for mechanism in ['A', 'B', 'C'] {
        let mut row = batch(&rep, &expected, mechanism, 100, deadline);
        let timeout = row["timed_out"] == true;
        row["kind"] = "warmup".into();
        emit(&mut file, row);
        if timeout {
            emit(
                &mut file,
                serde_json::json!({"kind":"finish","complete":false,"reason":"120s campaign cap during warmup"}),
            );
            return;
        }
    }
    for (block, order) in ["ABC", "BCA", "CAB", "ABC", "BCA"].iter().enumerate() {
        for mechanism in order.chars() {
            let mut row = batch(&rep, &expected, mechanism, 1000, deadline);
            let timeout = row["timed_out"] == true;
            row["kind"] = "block".into();
            row["block"] = block.into();
            emit(&mut file, row);
            if timeout {
                emit(
                    &mut file,
                    serde_json::json!({"kind":"finish","complete":false,"reason":"120s campaign cap"}),
                );
                return;
            }
        }
    }
    emit(
        &mut file,
        serde_json::json!({"kind":"finish","complete":true,"elapsed_ns":campaign.elapsed().as_nanos() as u64}),
    );
}
