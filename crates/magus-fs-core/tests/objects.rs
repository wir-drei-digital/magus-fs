use magus_fs_core::*;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    sync::Arc,
};
fn area() -> (tempfile::TempDir, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().canonicalize().unwrap().join("store");
    (t, p)
}
#[test]
fn durable_reopen_and_private_modes() {
    let (_t, p) = area();
    let store = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    let id = store.install(b"abc").unwrap();
    drop(store);
    let store = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    assert_eq!(store.read_verified(&id).unwrap(), b"abc");
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(p.join(id.as_str()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(store.install(b"abc").unwrap(), id);
    assert!(store
        .read_verified(&ObjectId::for_bytes(b"missing").unwrap())
        .is_err());
    assert!(store.install(&vec![0; MAX_CHUNK as usize + 1]).is_err());
}
#[test]
fn corruption_is_detected_and_never_overwritten() {
    let (_t, p) = area();
    let store = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    let id = store.install(b"abc").unwrap();
    fs::write(p.join(id.as_str()), b"xyz").unwrap();
    assert!(matches!(
        store.read_verified(&id),
        Err(FsError::CorruptObject)
    ));
    assert!(matches!(store.install(b"abc"), Err(FsError::CorruptObject)));
    assert_eq!(fs::read(p.join(id.as_str())).unwrap(), b"xyz");
    fs::write(p.join(id.as_str()), vec![0; MAX_CHUNK as usize + 1]).unwrap();
    assert!(store.read_verified(&id).is_err());
}
#[test]
fn interrupted_stage_is_not_content_and_identical_install_is_concurrent() {
    let (_t, p) = area();
    let store = Arc::new(ObjectStore::open(&p, ObjectLimits::default()).unwrap());
    fs::write(p.join(".stage-interrupted"), b"partial").unwrap();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let s = store.clone();
            std::thread::spawn(move || s.install(b"same"))
        })
        .collect();
    let ids: Vec<_> = threads
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert!(ids.iter().all(|id| id == &ids[0]));
    assert_eq!(store.read_verified(&ids[0]).unwrap(), b"same");
    assert_eq!(fs::read(p.join(".stage-interrupted")).unwrap(), b"partial");
    assert_eq!(fs::read_dir(&p).unwrap().count(), 2);
}
#[test]
fn storage_symlinks_and_content_overlap_are_refused() {
    let (t, p) = area();
    let root = t.path().canonicalize().unwrap();
    fs::create_dir(root.join("outside")).unwrap();
    symlink(root.join("outside"), &p).unwrap();
    assert!(ObjectStore::open(&p, ObjectLimits::default()).is_err());
    fs::remove_file(&p).unwrap();
    let store = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    let id = ObjectId::for_bytes(b"abc").unwrap();
    let outside = root.join("victim");
    fs::write(&outside, b"abc").unwrap();
    symlink(&outside, p.join(id.as_str())).unwrap();
    assert!(store.read_verified(&id).is_err());
    assert!(store.install(b"abc").is_err());
    assert_eq!(fs::read(outside).unwrap(), b"abc");
    for content in [root.clone(), p.clone(), p.join("content")] {
        assert!(matches!(
            ObjectStore::open(
                &p,
                ObjectLimits {
                    content_roots: vec![content],
                    ..ObjectLimits::default()
                }
            ),
            Err(FsError::StorageOverlap)
        ));
    }
}

#[test]
fn storage_ancestor_aliases_special_files_and_unsafe_modes_are_refused() {
    let (t, p) = area();
    let root = t.path().canonicalize().unwrap();
    symlink(&root, root.join("alias")).unwrap();
    assert!(ObjectStore::open(root.join("alias/store"), ObjectLimits::default()).is_err());
    assert!(!p.exists());
    assert!(ObjectStore::open(
        &p,
        ObjectLimits {
            content_roots: vec![root.join("alias/content")],
            ..ObjectLimits::default()
        }
    )
    .is_err());
    assert!(ObjectStore::open(root.join("../escape"), ObjectLimits::default()).is_err());
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ObjectStore::open(&p, ObjectLimits::default()),
        Err(FsError::UnsafeStorage)
    ));
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    let store = ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    let id = store.install(b"abc").unwrap();
    fs::set_permissions(p.join(id.as_str()), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        store.read_verified(&id),
        Err(FsError::UnsafeStorage)
    ));
    fs::remove_file(p.join(id.as_str())).unwrap();
    let fifo = std::ffi::CString::new(p.join(id.as_str()).as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid owned test pathname; mkfifo creates only this fixture.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        store.read_verified(&id),
        Err(FsError::UnsafeStorage)
    ));
}
#[test]
fn lowered_limits_and_open_directory_anchor_are_enforced() {
    let (t, p) = area();
    let root = t.path().canonicalize().unwrap();
    assert!(ObjectStore::open(
        &p,
        ObjectLimits {
            max_chunk_size: MAX_CHUNK + 1,
            ..ObjectLimits::default()
        }
    )
    .is_err());
    let store = ObjectStore::open(
        &p,
        ObjectLimits {
            max_chunk_size: 3,
            ..ObjectLimits::default()
        },
    )
    .unwrap();
    assert!(store.install(b"abcd").is_err());
    let id = store.install(b"abc").unwrap();
    fs::rename(&p, root.join("original")).unwrap();
    fs::create_dir(root.join("replacement")).unwrap();
    symlink(root.join("replacement"), &p).unwrap();
    assert_eq!(store.read_verified(&id).unwrap(), b"abc");
    let other = store.install(b"xyz").unwrap();
    assert_eq!(
        fs::read(root.join("original").join(other.as_str())).unwrap(),
        b"xyz"
    );
    assert_eq!(fs::read_dir(root.join("replacement")).unwrap().count(), 0);
}

fn native_identity(path: &std::path::Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).unwrap();
    (m.dev(), m.ino())
}
fn overlap(store: &std::path::Path, content: std::path::PathBuf) -> Result<ObjectStore, FsError> {
    ObjectStore::open(
        store,
        ObjectLimits {
            content_roots: vec![content],
            ..ObjectLimits::default()
        },
    )
}
// Probe the owned fixture volume rather than assume its equivalence rules from the OS name.
fn native_alias_fixture(
    original: &str,
    alias: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    bool,
) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    let p = root.join(original);
    let q = root.join(alias);
    ObjectStore::open(&p, ObjectLimits::default()).unwrap();
    let aliases = q.exists() && native_identity(&p) == native_identity(&q);
    println!("native alias {original:?}/{alias:?} = {aliases}");
    (t, p, q, aliases)
}
#[test]
fn native_alias_equality_is_refused_without_conflating_distinct_directories() {
    for (original, alias) in [("store", "STORE"), ("café", "cafe\u{301}")] {
        let (_t, p, q, aliases) = native_alias_fixture(original, alias);
        if aliases {
            assert!(matches!(overlap(&p, q), Err(FsError::StorageOverlap)));
        } else {
            ObjectStore::open(&q, ObjectLimits::default()).unwrap();
            assert_ne!(native_identity(&p), native_identity(&q));
            let store = overlap(&p, q.clone()).unwrap();
            let id = store.install(b"private").unwrap();
            assert!(!q.join(id.as_str()).exists());
        }
    }
}
#[test]
fn native_alias_existing_containment_in_both_directions_is_refused() {
    for (original, alias) in [("store", "STORE"), ("café", "cafe\u{301}")] {
        let (_t, p, q, aliases) = native_alias_fixture(original, alias);
        ObjectStore::open(p.join("nested"), ObjectLimits::default()).unwrap();
        if aliases {
            assert!(matches!(
                overlap(&p.join("nested"), q.clone()),
                Err(FsError::StorageOverlap)
            ));
            assert!(matches!(
                overlap(&p, q.join("nested")),
                Err(FsError::StorageOverlap)
            ));
        } else {
            ObjectStore::open(&q, ObjectLimits::default()).unwrap();
            ObjectStore::open(q.join("nested"), ObjectLimits::default()).unwrap();
            assert!(overlap(&p.join("nested"), q.clone()).is_ok());
            assert!(overlap(&p, q.join("nested")).is_ok());
        }
    }
}
#[test]
fn native_alias_missing_content_descendants_are_refused() {
    for (original, alias) in [("store", "STORE"), ("café", "cafe\u{301}")] {
        let (_t, p, q, aliases) = native_alias_fixture(original, alias);
        let result = overlap(&p, q.join("not-created/deeper"));
        if aliases {
            assert!(matches!(result, Err(FsError::StorageOverlap)));
        } else {
            assert!(result.is_ok());
        }
        assert!(!q.join("not-created").exists());
    }
}
#[test]
fn native_alias_new_store_paths_are_refused_and_owned_empty_directory_is_removed() {
    for (original, alias) in [("store", "STORE"), ("café", "cafe\u{301}")] {
        let (t, p, q, aliases) = native_alias_fixture(original, alias);
        fs::remove_dir(&p).unwrap();
        for suffix in [None, Some("not-created/deeper")] {
            let content = match suffix {
                Some(s) => q.join(s),
                None => q.clone(),
            };
            let result = overlap(&p, content);
            if aliases {
                assert!(matches!(result, Err(FsError::StorageOverlap)));
                assert!(
                    !p.exists(),
                    "remove only the just-created empty store on refusal"
                );
            } else {
                assert!(result.is_ok());
                fs::remove_dir(&p).unwrap();
            }
        }
        let root = t.path().canonicalize().unwrap();
        ObjectStore::open(&p, ObjectLimits::default()).unwrap();
        let result = overlap(&p.join("new-store"), q.clone());
        if aliases {
            assert!(matches!(result, Err(FsError::StorageOverlap)));
            assert!(!p.join("new-store").exists());
        } else {
            assert!(result.is_ok());
        }
        assert!(root.is_dir());
    }
}
