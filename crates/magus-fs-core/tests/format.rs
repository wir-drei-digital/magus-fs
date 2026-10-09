use magus_fs_core::*;
use std::collections::HashMap;

fn revision() -> Revision {
    Revision {
        format: FORMAT.into(),
        hash: HASH.into(),
        layout: LAYOUT.into(),
        parents: vec![],
        operation: OperationId::parse("operation:00000000000000000000000000000001").unwrap(),
        replica: ReplicaId::parse("replica:00000000000000000000000000000002").unwrap(),
        principal: PrincipalId::parse("principal:00000000000000000000000000000003").unwrap(),
        captured_at_ns: 0,
        coverage: vec!["".into()],
        provenance: "explicit".into(),
        restoration: None,
        tree: Tree {
            root: Root {
                id: EntryId::parse("entry:00000000000000000000000000000004").unwrap(),
                owner: PrincipalId::parse("principal:00000000000000000000000000000003").unwrap(),
                group: GroupId::parse("group:00000000000000000000000000000005").unwrap(),
                mode: 493,
            },
            entries: vec![],
        },
    }
}
fn entry(r: &Revision, path: &str, n: u32) -> Entry {
    Entry {
        path: path.into(),
        id: EntryId::parse(format!("entry:{n:032x}")).unwrap(),
        parent: r.tree.root.id.clone(),
        owner: r.tree.root.owner.clone(),
        group: r.tree.root.group.clone(),
        mode: 420,
        content: EntryContent::File {
            version: FileVersion {
                size: 0,
                extents: vec![],
            },
        },
    }
}
const CANONICAL: &str = r#"{"format":"magus-fs/v1","hash":"sha256","layout":"fixed262144","parents":[],"operation":"operation:00000000000000000000000000000001","replica":"replica:00000000000000000000000000000002","principal":"principal:00000000000000000000000000000003","captured_at_ns":0,"coverage":[""],"provenance":"explicit","tree":{"root":{"id":"entry:00000000000000000000000000000004","owner":"principal:00000000000000000000000000000003","group":"group:00000000000000000000000000000005","mode":493},"entries":[]}}"#;

#[test]
fn literal_encoding_and_independent_hash() {
    let r = revision();
    assert_eq!(encode_revision(&r).unwrap(), CANONICAL.as_bytes());
    assert_eq!(decode_revision(CANONICAL.as_bytes()).unwrap(), r);
    assert_eq!(
        revision_id(&r).unwrap().as_str(),
        "sha256:7b1e3c8da76467f53da36b5642e06f2993b832ca873555b7df7d8fb64314c27b"
    );
}
#[test]
fn independent_input_maps_and_metadata_are_revision_bound() {
    let mut r = revision();
    let a = entry(&r, "a", 10);
    let b = entry(&r, "b", 11);
    let mut first = HashMap::new();
    first.insert("b", b.clone());
    first.insert("a", a.clone());
    let mut second = HashMap::new();
    second.insert("a", a);
    second.insert("b", b);
    r.tree.entries = first.into_values().collect();
    let mut other = r.clone();
    other.tree.entries = second.into_values().collect();
    // Force opposite orders so omitting canonical sorting fails on every run.
    r.tree.entries.sort_by(|a, b| a.path.cmp(&b.path));
    other.tree.entries.sort_by(|a, b| b.path.cmp(&a.path));
    assert_ne!(r.tree.entries, other.tree.entries);
    assert_eq!(
        encode_revision(&r).unwrap(),
        encode_revision(&other).unwrap()
    );
    let id = revision_id(&r).unwrap();
    other.tree.root.mode = 448;
    assert_ne!(revision_id(&other).unwrap(), id);
    other = r.clone();
    other.tree.entries[0].mode = 384;
    assert_ne!(revision_id(&other).unwrap(), id);
    other = r.clone();
    other.tree.entries[0].owner = PrincipalId::random().unwrap();
    assert_ne!(revision_id(&other).unwrap(), id);
    other = r.clone();
    other.operation = OperationId::random().unwrap();
    assert_ne!(revision_id(&other).unwrap(), id);
    other = r.clone();
    other.coverage = vec!["a".into()];
    assert_ne!(revision_id(&other).unwrap(), id);
}
#[test]
fn identity_validation_and_random_generation() {
    for bad in [
        "",
        "entry:abc",
        "replica:00000000000000000000000000000001",
        "entry:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "entry:0000000000000000000000000000000g",
    ] {
        assert!(EntryId::parse(bad).is_err());
    }
    assert_ne!(EntryId::random().unwrap(), EntryId::random().unwrap());
    assert!(ObjectId::parse(format!("sha256:{}", "g".repeat(64))).is_err());
    assert_eq!(
        ObjectId::for_bytes(b"abc").unwrap().as_str(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
#[test]
fn unsupported_and_malformed_descriptors_are_rejected() {
    for (from, to) in [
        ("magus-fs/v1", "magus-fs/v0"),
        ("sha256", "md5"),
        ("fixed262144", "fastcdc"),
    ] {
        assert!(matches!(
            decode_revision(CANONICAL.replace(from, to).as_bytes()),
            Err(FsError::UnsupportedFormat)
        ));
    }
    assert!(matches!(
        decode_revision(br#"{"version":1,"files":[]}"#),
        Err(FsError::UnsupportedFormat)
    ));
    for bytes in [
        CANONICAL.replace("493", "493.0"),
        CANONICAL.replace("\"mode\":493", "\"mode\":493,\"extra\":0"),
        CANONICAL.replace("\"mode\":493", "\"mode\":493,\"mode\":493"),
        CANONICAL.replace("entry:0000", "entry:ZZZZ"),
    ] {
        assert!(decode_revision(bytes.as_bytes()).is_err());
    }
    assert!(matches!(
        decode_revision(&vec![b' '; MAX_DESCRIPTOR + 1]),
        Err(FsError::LimitExceeded)
    ));
    assert!(
        decode_revision(format!("{}{}", "[".repeat(1000), "]".repeat(1000)).as_bytes()).is_err()
    );
}
#[test]
fn path_portability_duplicates_cycles_and_file_parents() {
    for bad in [
        "/abs",
        "../escape",
        "a/../b",
        "a//b",
        "a/./b",
        "a/",
        "C:drive",
        "a\\b",
        "bad\0x",
        "e\u{301}",
        ".",
        "",
    ] {
        let mut r = revision();
        r.tree.entries = vec![entry(&r, bad, 10)];
        assert!(validate_tree(&r.tree).is_err(), "{bad:?}");
    }
    for (a, b) in [
        ("a", "a"),
        ("A", "a"),
        ("Straße", "STRASSE"),
        ("Σ", "ς"),
        ("É", "é"),
    ] {
        let mut r = revision();
        r.tree.entries = vec![entry(&r, a, 10), entry(&r, b, 11)];
        assert!(validate_tree(&r.tree).is_err(), "{a} {b}");
    }
    let mut r = revision();
    let a = entry(&r, "a", 10);
    let mut b = entry(&r, "a/b", 11);
    b.parent = a.id.clone();
    r.tree.entries = vec![a, b];
    assert!(validate_tree(&r.tree).is_err());
    r.tree.entries[0].content = EntryContent::Directory;
    assert!(validate_tree(&r.tree).is_ok());
    r.tree.entries[0].parent = r.tree.entries[1].id.clone();
    assert!(validate_tree(&r.tree).is_err());
    r.tree.entries[0].parent = r.tree.root.id.clone();
    r.tree.entries[1].id = r.tree.entries[0].id.clone();
    assert!(validate_tree(&r.tree).is_err());
}
#[test]
fn extent_bounds_sparse_and_empty_files() {
    let mut r = revision();
    r.tree.entries = vec![entry(&r, "f", 10)];
    let object = ObjectId::for_bytes(b"abc").unwrap();
    let good = Extent::Chunk {
        object: object.clone(),
        object_size: 3,
        offset: 1,
        length: 2,
    };
    r.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 7,
            extents: vec![good.clone(), Extent::Hole { length: 5 }],
        },
    };
    assert!(validate_tree(&r.tree).is_ok());
    for (size, extents) in [
        (0, vec![Extent::Hole { length: 0 }]),
        (1, vec![]),
        (1, vec![good.clone()]),
        (
            MAX_FILE + 1,
            vec![Extent::Hole {
                length: MAX_FILE + 1,
            }],
        ),
        (
            1,
            vec![Extent::Chunk {
                object: object.clone(),
                object_size: MAX_CHUNK + 1,
                offset: 0,
                length: 1,
            }],
        ),
        (
            2,
            vec![Extent::Chunk {
                object: object.clone(),
                object_size: 3,
                offset: 2,
                length: 2,
            }],
        ),
        (
            1,
            vec![Extent::Chunk {
                object,
                object_size: 3,
                offset: u64::MAX,
                length: 2,
            }],
        ),
        (
            1,
            vec![
                Extent::Hole { length: u64::MAX },
                Extent::Hole { length: 2 },
            ],
        ),
        (100001, vec![Extent::Hole { length: 1 }; 100001]),
    ] {
        r.tree.entries[0].content = EntryContent::File {
            version: FileVersion { size, extents },
        };
        assert!(validate_tree(&r.tree).is_err());
    }
}

#[test]
fn post_unicode9_case_collision_is_rejected() {
    let mut r = revision();
    r.tree.entries = vec![entry(&r, "Ა", 10), entry(&r, "ა", 11)];
    assert!(validate_tree(&r.tree).is_err());
}
#[test]
fn errors_have_stable_machine_codes() {
    assert_eq!(FsError::UnsupportedFormat.to_string(), "unsupported_format");
}

#[test]
fn all_attribution_root_and_namespace_fields_affect_identity() {
    let r = revision();
    let original = revision_id(&r).unwrap();
    let mut changes = vec![];
    let mut v = r.clone();
    v.tree.root.owner = PrincipalId::random().unwrap();
    changes.push(v);
    let mut v = r.clone();
    v.tree.root.group = GroupId::random().unwrap();
    changes.push(v);
    let mut v = r.clone();
    v.tree.root.id = EntryId::random().unwrap();
    changes.push(v);
    let mut v = r.clone();
    v.replica = ReplicaId::random().unwrap();
    changes.push(v);
    let mut v = r.clone();
    v.principal = PrincipalId::random().unwrap();
    changes.push(v);
    let mut v = r.clone();
    v.captured_at_ns = 1;
    changes.push(v);
    let mut v = r.clone();
    v.parents = vec![original.clone()];
    changes.push(v);
    let mut v = r.clone();
    v.provenance = "native_scan_delete_create".into();
    changes.push(v);
    for v in changes {
        assert_ne!(revision_id(&v).unwrap(), original);
    }
    let mut v = r.clone();
    v.tree.entries = vec![entry(&v, "original", 10)];
    let original = revision_id(&v).unwrap();
    v.tree.entries[0].path = "renamed".into();
    assert_ne!(revision_id(&v).unwrap(), original);
}
#[test]
fn descriptor_and_collection_limits_are_enforced() {
    let mut r = revision();
    r.tree.entries = vec![entry(&r, "f", 10); MAX_ENTRIES + 1];
    assert!(matches!(
        validate_tree(&r.tree),
        Err(FsError::LimitExceeded)
    ));
    let mut r = revision();
    r.tree.entries = (0..40000)
        .map(|i| entry(&r, &format!("{i:05}{}", "x".repeat(240)), i + 10))
        .collect();
    assert!(matches!(encode_revision(&r), Err(FsError::LimitExceeded)));
    let mut r = revision();
    r.tree.entries = vec![entry(&r, "f", 10)];
    r.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: MAX_FILE,
            extents: vec![Extent::Hole { length: MAX_FILE }],
        },
    };
    let encoded = encode_revision(&r).unwrap();
    assert_eq!(decode_revision(&encoded).unwrap(), r);
    let oversized = String::from_utf8(encoded).unwrap().replace(
        &format!("{{\"kind\":\"hole\",\"length\":{MAX_FILE}}}"),
        &std::iter::repeat_n("{\"kind\":\"hole\",\"length\":1}", MAX_EXTENTS + 1)
            .collect::<Vec<_>>()
            .join(","),
    );
    assert!(oversized.len() < MAX_DESCRIPTOR);
    assert!(decode_revision(oversized.as_bytes()).is_err());
}
#[test]
fn nested_unknown_fields_bad_permissions_and_object_sizes_are_rejected() {
    let mut r = revision();
    r.tree.entries = vec![entry(&r, "f", 10)];
    let encoded = String::from_utf8(encode_revision(&r).unwrap()).unwrap();
    for changed in [
        encoded.replace("\"size\":0", "\"size\":0,\"unexpected\":0"),
        encoded.replace("\"kind\":\"file\"", "\"kind\":\"symlink\""),
        encoded.replace("\"mode\":420", "\"mode\":4095"),
    ] {
        assert!(decode_revision(changed.as_bytes()).is_err());
    }
    r.tree.root.mode = 0o1000;
    assert!(validate_tree(&r.tree).is_err());
    r.tree.root.mode = 0o755;
    r.tree.entries[0].content = EntryContent::File {
        version: FileVersion {
            size: 2,
            extents: vec![
                Extent::Chunk {
                    object: ObjectId::for_bytes(b"abc").unwrap(),
                    object_size: 3,
                    offset: 0,
                    length: 1,
                },
                Extent::Chunk {
                    object: ObjectId::for_bytes(b"abc").unwrap(),
                    object_size: 2,
                    offset: 0,
                    length: 1,
                },
            ],
        },
    };
    assert!(validate_tree(&r.tree).is_err());
    r.tree.entries[0].content = EntryContent::Directory;
    r.tree.entries[0].parent = EntryId::random().unwrap();
    assert!(validate_tree(&r.tree).is_err());
}

#[test]
fn directory_content_rejects_a_file_version_even_when_null() {
    let mut r = revision();
    r.tree.entries = vec![entry(&r, "d", 10)];
    r.tree.entries[0].content = EntryContent::Directory;
    let encoded = String::from_utf8(encode_revision(&r).unwrap()).unwrap();
    let changed = encoded.replace(
        "\"kind\":\"directory\"",
        "\"kind\":\"directory\",\"version\":null",
    );
    assert!(decode_revision(changed.as_bytes()).is_err());
}

const CANONICAL_V2: &str = r#"{"format":"magus-fs/v2","hash":"sha256","layout":"fixed262144","parents":["sha256:7b1e3c8da76467f53da36b5642e06f2993b832ca873555b7df7d8fb64314c27b"],"operation":"operation:00000000000000000000000000000001","replica":"replica:00000000000000000000000000000002","principal":"principal:00000000000000000000000000000003","captured_at_ns":0,"coverage":[""],"provenance":"explicit","restoration":{"source_revision":"sha256:7b1e3c8da76467f53da36b5642e06f2993b832ca873555b7df7d8fb64314c27b","restore_metadata":false,"recreated":{}},"tree":{"root":{"id":"entry:00000000000000000000000000000004","owner":"principal:00000000000000000000000000000003","group":"group:00000000000000000000000000000005","mode":493},"entries":[]}}"#;
#[test]
fn v2_restoration_literal_and_independent_hash_preserve_v1() {
    let revision = decode_revision(CANONICAL_V2.as_bytes()).unwrap();
    assert_eq!(encode_revision(&revision).unwrap(), CANONICAL_V2.as_bytes());
    assert_eq!(
        revision_id(&revision).unwrap().as_str(),
        "sha256:f1b96309415b5606f32a9d3a1c7daf71eacfc6530a502d47d9310ddf25492291"
    );
    assert_eq!(
        encode_revision(&decode_revision(CANONICAL.as_bytes()).unwrap()).unwrap(),
        CANONICAL.as_bytes()
    );
    assert!(matches!(
        decode_revision(
            CANONICAL_V2
                .replace("magus-fs/v2", "magus-fs/v3")
                .as_bytes()
        ),
        Err(FsError::UnsupportedFormat)
    ));
    assert!(decode_revision(
        CANONICAL_V2
            .replace("magus-fs/v2", "magus-fs/v1")
            .as_bytes()
    )
    .is_err());
    assert!(decode_revision(
        CANONICAL
            .replace("\"tree\":", "\"restoration\":null,\"tree\":")
            .as_bytes()
    )
    .is_err());
    assert!(decode_revision(CANONICAL_V2.replace("\"parents\":[\"sha256:7b1e3c8da76467f53da36b5642e06f2993b832ca873555b7df7d8fb64314c27b\"]","\"parents\":[]").as_bytes()).is_err());
}
