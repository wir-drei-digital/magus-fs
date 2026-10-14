mod support;
use support::*;
#[test]
fn profile_counts_genuine_metadata_from_another_thread() {
    let (_d, rep, w, base) = setup();
    rep.observe_remote_authority(Some(&base), rep.live_status().unwrap().authority_generation)
        .unwrap();
    rep.set_metadata_profile_enabled(true).unwrap();
    let profile = rep.begin_metadata_profile(&base).unwrap();
    std::thread::spawn(move || w.lookup("").unwrap())
        .join()
        .unwrap();
    let profile = profile.finish();
    assert_eq!(profile.callback_count, 1);
    assert_eq!(profile.load_count, 1);
    assert!(profile.decoded_bytes > 0);
    assert_eq!(profile.copy_count, 1);
    assert!(profile.cpu_inclusive_ns.contains_key("decode"));
}
