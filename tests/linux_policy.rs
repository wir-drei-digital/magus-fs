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

struct OwnedFixture {
    root: std::path::PathBuf,
    server: Option<Server>,
}
impl OwnedFixture {
    fn new(label: &str, mode: Option<u32>) -> Self {
        let root =
            std::env::temp_dir().join(format!("fs0-linux-review-{}-{label}", std::process::id()));
        let server =
            Server::spawn(Fixture::create(&root, 262144, mode).unwrap(), "127.0.0.1:0").unwrap();
        Self {
            root,
            server: Some(server),
        }
    }
    fn url(&self) -> String {
        self.server.as_ref().unwrap().url()
    }
}
impl Drop for OwnedFixture {
    fn drop(&mut self) {
        drop(self.server.take());
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn authorized_private_root_writes_bypass_mode_but_ro_and_nonroot_do_not() {
    for mode in [0o444, 0] {
        let fixture = OwnedFixture::new(&format!("root-{mode:o}"), Some(mode));
        let ro = FuseAdapter::connect(&fixture.url(), false, None).unwrap();
        let rw = FuseAdapter::connect(&fixture.url(), true, None).unwrap();
        assert_eq!(ro.write_as(2, 0, 0, 0, b"bad"), Err(libc::EROFS));
        assert_eq!(rw.write_as(2, 1001, 1001, 0, b"bad"), Err(libc::EACCES));
        assert_eq!(
            rw.write_as(2, 0, 0, 0, b"private"),
            Ok(7),
            "authorized root mode{mode:o}"
        );
        assert_eq!(rw.read_as(2, 0, 0, 0, 7).unwrap(), b"private");
        assert_eq!(ro.read_as(2, 0, 0, 0, 7).unwrap(), b"# Synth");
        let mut standalone = magus_fs_probe::Probe::connect(&fixture.url(), true).unwrap();
        assert!(
            standalone.write("instructions.md", 0, b"bad").is_err(),
            "standalone Probe has no caller authorization"
        );
    }
}

struct MetadataSource {
    child: std::process::Child,
    url: String,
}
impl MetadataSource {
    fn directory(url: &str, mode: u32) -> Self {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let mut child = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fs0/permission_source.py"
            ))
            .args(["--source", url, "--directory-mode", &format!("{mode:o}")])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut url = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut url)
            .unwrap();
        assert!(
            url.starts_with("http://127.0.0.1:"),
            "metadata fixture did not become ready"
        );
        Self {
            child,
            url: url.trim().into(),
        }
    }
}
impl Drop for MetadataSource {
    fn drop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
#[test]
fn directory_read_and_search_rights_are_independent_and_parents_still_apply() {
    let fixture = OwnedFixture::new("directory", None);
    for mode in [0o400, 0o100] {
        let source = MetadataSource::directory(&fixture.url(), mode);
        let adapter = FuseAdapter::connect(&source.url, false, None).unwrap();
        if mode == 0o400 {
            assert!(
                adapter.directory_as(7, 1001, 1001).is_ok(),
                "read-only directory must allow enumeration"
            );
            assert_eq!(
                adapter.read_as(3, 1001, 1001, 0, 100),
                Err(libc::EACCES),
                "child requires parent search"
            );
        } else {
            assert!(
                matches!(adapter.directory_as(7, 1001, 1001), Err(libc::EACCES)),
                "search-only directory cannot enumerate"
            );
            assert_eq!(
                adapter.read_as(3, 1001, 1001, 0, 100).unwrap(),
                b"id,value\n1,synthetic\n"
            );
        }
        assert!(
            matches!(adapter.directory_as(7, 1002, 1002), Err(libc::EACCES)),
            "nonowner modes intact"
        );
        assert_eq!(
            adapter.read_as(3, 1002, 1002, 0, 100),
            Err(libc::EACCES),
            "nonowner parent search intact"
        );
    }
}
