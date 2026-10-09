#![cfg(target_os = "linux")]
use magus_fs_probe::{
    adapters::linux::FuseAdapter,
    source::{Fixture, Server},
};
#[test]
fn readonly_capability_dominates_root_and_private_obeys_modes() {
    let root = std::env::temp_dir().join(format!("fs0-linux-policy-{}", std::process::id()));
    let server = Server::spawn(
        Fixture::create(&root, 262144, Some(0o640)).unwrap(),
        "127.0.0.1:0",
    )
    .unwrap();
    let ro = FuseAdapter::connect(&server.url(), false, None).unwrap();
    assert_eq!(ro.write_as(2, 0, 0, 0, b"bad"), Err(libc::EROFS));
    assert_eq!(ro.read_as(2, 1001, 1001, 0, 1), Err(libc::EACCES));
    assert_eq!(ro.read_as(2, 1001, 0, 0, 1).unwrap(), b"#");
    let rw = FuseAdapter::connect(&server.url(), true, None).unwrap();
    assert_eq!(rw.write_as(2, 1001, 0, 0, b"bad"), Err(libc::EACCES));
    assert_eq!(rw.write_as(2, 0, 0, 0, b"private").unwrap(), 7);
    assert_eq!(rw.read_as(2, 0, 0, 0, 7).unwrap(), b"private");
    assert_eq!(ro.read_as(2, 0, 0, 0, 7).unwrap(), b"# Synth");
    assert!(FuseAdapter::connect(&server.url(), false, Some(&"0".repeat(64))).is_err());
    drop(server);
    std::fs::remove_dir_all(root).unwrap();
}
