use magus_fs_core::protocol::{BranchName, NamespaceId};
use magus_fs_service::config::read_private;
#[test]
fn remote_identity_and_branch_reject_ambiguous_wire_values() {
    assert!(NamespaceId::parse("a".repeat(32)).is_ok());
    for bad in ["A".repeat(32), "a".repeat(31), "../namespace".into()] {
        assert!(NamespaceId::parse(bad).is_err());
    }
    assert!(BranchName::parse("main_1".into()).is_ok());
    for bad in ["", "Main", "-main", "a/b"] {
        assert!(BranchName::parse(bad.into()).is_err());
    }
}
#[test]
fn control_files_reject_public_permissions_and_symlinks() {
    assert!(read_private(std::path::Path::new("/")).is_err());
    use std::os::unix::fs::{symlink, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let private = tmp.path().canonicalize().unwrap();
    let path = private.join("secret");
    std::fs::write(&path, b"private").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_private(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_private(&path).unwrap(), b"private");
    let link = private.join("link");
    symlink(&path, &link).unwrap();
    assert!(read_private(&link).is_err());
}
