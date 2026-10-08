use magus_fs_probe::{
    source::{Fixture, Server},
    Probe,
};
#[test]
fn verified_ranges_and_private_writes() {
    for chunk in [65536, 262144, 1048576] {
        let root = std::env::temp_dir().join(format!("fs0-{}-{chunk}", std::process::id()));
        let fixture = Fixture::create(&root, chunk, None).unwrap();
        let server = Server::spawn(fixture, "127.0.0.1:0").unwrap();
        let mut p = Probe::connect(&server.url(), false).unwrap();
        for (off, len) in [
            (0, 12),
            (67108859, 20),
            (chunk as u64 - 4, 12),
            (0, 0),
            (67108864, 10),
        ] {
            let got = p.read("data.bin", off, len).unwrap();
            let end = (off + len as u64).min(67108864);
            let expected: Vec<u8> = (off..end)
                .map(|i| ((i * 31 + i / 4096) % 251) as u8)
                .collect();
            assert_eq!(got, expected);
        }
        let before = p.fetched_bytes();
        p.read("data.bin", 0, 12).unwrap();
        assert_eq!(before, p.fetched_bytes());
        assert!(p.read("data.bin", u64::MAX, 2).is_err());
        assert!(p.write("data.bin", 0, b"x").is_err());
        let mut writable = Probe::connect(&server.url(), true).unwrap();
        let original = writable.read("instructions.md", 0, 200).unwrap();
        writable.write("instructions.md", 2, b"XYZ").unwrap();
        let mut expected = original;
        expected[2..5].copy_from_slice(b"XYZ");
        assert_eq!(writable.read("instructions.md", 0, 200).unwrap(), expected);
        assert!(writable.flush().is_err());
        server.corrupt(true);
        let mut fresh = Probe::connect(&server.url(), false).unwrap();
        assert!(fresh.read("data.bin", 0, 1).is_err());
        assert_eq!(fresh.cached_chunks(), 0);
        server.corrupt(false);
        assert!(fresh.read("data.bin", 0, 1).is_ok());
        let stats: serde_json::Value = serde_json::from_reader(
            ureq::get(&format!("{}/stats", server.url()))
                .call()
                .unwrap()
                .into_reader(),
        )
        .unwrap();
        assert!(stats["unique_chunks"].as_u64().unwrap() > 0);
        assert!(stats["metadata_bytes"].as_u64().unwrap() > 0);
        assert!(stats["retry_requests"].as_u64().unwrap() > 0);
        assert!(stats["content_body_bytes"].as_u64().unwrap() > 0);
        drop(server);
        assert!(Probe::connect("http://127.0.0.1:1", false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
