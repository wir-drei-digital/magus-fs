#![allow(dead_code)]
use magus_fs_core::*;
use std::path::{Path, PathBuf};
pub fn principal(n: u32) -> PrincipalId {
    PrincipalId::parse(format!("principal:{n:032x}")).unwrap()
}
pub fn group(n: u32) -> GroupId {
    GroupId::parse(format!("group:{n:032x}")).unwrap()
}
pub fn actor() -> Actor {
    Actor::new(principal(1))
}
pub fn config() -> ReplicaConfig {
    ReplicaConfig {
        replica: ReplicaId::parse(format!("replica:{:032x}", 1)).unwrap(),
        authorities: vec![
            Authority {
                principal: principal(1),
                uid: 1001,
                primary_group: group(1),
                gid: 1001,
                groups: vec![group(1)],
                dac_override: false,
                ownership_transfer: true,
            },
            Authority {
                principal: principal(2),
                uid: 1002,
                primary_group: group(1),
                gid: 1001,
                groups: vec![group(1)],
                dac_override: false,
                ownership_transfer: false,
            },
            Authority {
                principal: principal(3),
                uid: 1003,
                primary_group: group(3),
                gid: 1003,
                groups: vec![group(3)],
                dac_override: false,
                ownership_transfer: false,
            },
            Authority {
                principal: principal(4),
                uid: 0,
                primary_group: group(1),
                gid: 1001,
                groups: vec![group(1)],
                dac_override: true,
                ownership_transfer: true,
            },
        ],
        history_administrators: vec![],
        retained_history_grants: vec![],
        content_roots: vec![],
        cache_bytes: 32 * 1024 * 1024,
    }
}
pub fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("fs1-task3-")
        .tempdir_in(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .unwrap()
}
pub fn revision() -> Revision {
    Revision {
        format: FORMAT.into(),
        hash: HASH.into(),
        layout: LAYOUT.into(),
        parents: vec![],
        operation: OperationId::random().unwrap(),
        replica: config().replica,
        principal: principal(1),
        captured_at_ns: 0,
        coverage: vec!["".into()],
        provenance: "explicit".into(),
        restoration: None,
        tree: Tree {
            root: Root {
                id: EntryId::random().unwrap(),
                owner: principal(1),
                group: group(1),
                mode: 0o755,
            },
            entries: vec![],
        },
    }
}
pub fn add_file(r: &mut Revision, path: &str, bytes: &[u8]) {
    r.tree.entries.push(Entry {
        path: path.into(),
        id: EntryId::random().unwrap(),
        parent: r.tree.root.id.clone(),
        owner: principal(1),
        group: group(1),
        mode: 0o640,
        content: EntryContent::File {
            version: FileVersion {
                size: bytes.len() as u64,
                extents: if bytes.is_empty() {
                    vec![]
                } else {
                    vec![Extent::Chunk {
                        object: ObjectId::for_bytes(bytes).unwrap(),
                        object_size: bytes.len() as u64,
                        offset: 0,
                        length: bytes.len() as u64,
                    }]
                },
            },
        },
    });
}
pub fn import(rep: &Replica, r: &Revision, source: ChunkSource) -> RevisionId {
    rep.import_revision(
        ImportDescriptor {
            expected: revision_id(r).unwrap(),
            bytes: encode_revision(r).unwrap(),
        },
        source,
    )
    .unwrap()
}
pub fn setup() -> (tempfile::TempDir, Replica, Workspace, RevisionId) {
    let d = scratch();
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let r = revision();
    let base = import(&rep, &r, ChunkSource::Unavailable);
    let w = rep.begin(&base, actor(), false).unwrap();
    (d, rep, w, base)
}
pub fn attr() -> Attribution {
    Attribution {
        captured_at_ns: 42,
        coverage: vec!["".into()],
        provenance: "engine_observed".into(),
    }
}
pub fn local(d: &Path, bytes: &[u8]) -> ChunkSource {
    let path = d.join("source");
    let store = ObjectStore::open(&path, ObjectLimits::default()).unwrap();
    store.install(bytes).unwrap();
    ChunkSource::Local { path }
}
pub fn err<T>(result: Result<T, FsError>, code: &str) {
    match result {
        Ok(_) => panic!("expected {code}"),
        Err(e) => assert_eq!(e.code(), code, "{e:?}"),
    }
}
pub fn database(d: &Path) -> PathBuf {
    d.join("state/journal.sqlite")
}
