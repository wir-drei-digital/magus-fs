mod support;
use magus_fs_core::*;
use support::*;
#[test]
fn ordinary_reopen_integrity_and_replay() {
    let (d, rep, w, base) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"safe").unwrap();
    let op = OperationId::random().unwrap();
    let generation = w.generation().unwrap();
    let id = w.checkpoint(&op, generation, attr()).unwrap();
    drop(h);
    drop(w);
    drop(rep);
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let w = rep.begin(&base, actor(), false).unwrap();
    assert_eq!(w.checkpoint(&op, generation, attr()).unwrap(), id);
    assert_eq!(rep.integrity_check().unwrap(), "ok");
}

#[cfg(feature = "test-faults")]
#[test]
fn fault_worker() {
    let Some(path) = std::env::var_os("MAGUS_WORKER_STATE") else {
        return;
    };
    let rep = Replica::open(path, config()).unwrap();
    let s = rep.status().unwrap();
    let w = rep
        .begin(&s.selected_base.unwrap(), actor(), false)
        .unwrap();
    let op = OperationId::parse(std::env::var("MAGUS_WORKER_OPERATION").unwrap()).unwrap();
    let result = w.checkpoint(&op, s.generation, attr());
    if std::env::var("MAGUS_TEST_FAULT_ACTION").unwrap() != "pause" {
        let e = result.unwrap_err();
        assert_eq!(e.code(), "io_error");
        let FsError::Io(e) = e else { panic!() };
        assert_eq!(
            e.raw_os_error(),
            Some(
                if std::env::var("MAGUS_TEST_FAULT_ACTION").unwrap() == "EIO" {
                    libc::EIO
                } else {
                    libc::ENOSPC
                }
            )
        );
    }
}
#[cfg(feature = "test-faults")]
fn fault_case(point: &str, action: &str, clean: bool) {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (d, rep, w, base) = setup();
    let h = w.create("a", 0o600).unwrap();
    w.write(&h, 0, b"acknowledged working bytes").unwrap();
    if clean {
        let mut r = revision();
        add_file(&mut r, "a", b"acknowledged working bytes");
        import(&rep, &r, local(d.path(), b"acknowledged working bytes"));
        w.checkpoint(
            &OperationId::random().unwrap(),
            w.generation().unwrap(),
            attr(),
        )
        .unwrap();
    }
    let prior = rep.status().unwrap();
    let generation = w.generation().unwrap();
    drop(h);
    drop(w);
    drop(rep);
    let operation = OperationId::random().unwrap();
    let marker = d.path().join("ready");
    let output = std::fs::File::create(d.path().join("worker.log")).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fault_worker", "--nocapture"])
        .env("MAGUS_WORKER_STATE", d.path().join("state"))
        .env("MAGUS_WORKER_OPERATION", operation.as_str())
        .env("MAGUS_TEST_FAULT_POINT", point)
        .env("MAGUS_TEST_FAULT_ACTION", action)
        .env("MAGUS_TEST_FAULT_MARKER", &marker)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output))
        .spawn()
        .unwrap();
    let pid = child.id();
    if action == "pause" {
        let start = Instant::now();
        loop {
            if marker.exists() {
                break;
            }
            if let Some(exit) = child.try_wait().unwrap() {
                panic!("worker {pid} exited before point {point}: {exit}")
            }
            if start.elapsed() > Duration::from_secs(15) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("worker deadline")
            };
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    } else {
        assert!(child.wait().unwrap().success());
    }
    let rep = Replica::open(d.path().join("state"), config()).unwrap();
    let s = rep.status().unwrap();
    let committed = point == "after-commit";
    let operation_status = s
        .operations
        .iter()
        .find(|s| s.operation == operation)
        .unwrap();
    assert_eq!(
        operation_status.state,
        if committed {
            "committed"
        } else if action == "pause" {
            "pending"
        } else {
            "failed"
        }
    );
    if !committed {
        assert_eq!(s.head, prior.head);
        assert_eq!(s.dirty, prior.dirty);
        assert!(rep.prune(true).unwrap().evictable.is_empty())
    } else {
        assert_ne!(s.head, Some(base.clone()));
        assert!(!s.dirty)
    }
    let w = rep.begin(&base, actor(), false).unwrap();
    let h = w.open("a", OpenMode::Read).unwrap();
    assert_eq!(w.read(&h, 0, 100).unwrap(), b"acknowledged working bytes");
    let retried = w.checkpoint(&operation, generation, attr()).unwrap();
    if committed {
        assert_eq!(s.head, Some(retried.clone()));
    }
    assert_eq!(rep.status().unwrap().head, Some(retried));
    assert_eq!(rep.integrity_check().unwrap(), "ok");
    println!("fault point={point} action={action} owned_pid={pid} reaped=true prior_or_committed=true bytes_retained=true replay=true integrity=ok");
}
#[cfg(feature = "test-faults")]
#[test]
fn kill_owned_workers_at_three_commit_boundaries_and_replay() {
    for point in ["before-transaction", "during-transaction", "after-commit"] {
        fault_case(point, "pause", false)
    }
}
#[cfg(feature = "test-faults")]
#[test]
fn enospc_eio_at_object_sync_and_db_commit_keep_head_and_retryable_bytes() {
    for point in ["object-sync", "db-commit"] {
        for action in ["ENOSPC", "EIO"] {
            fault_case(point, action, false)
        }
    }
}

#[cfg(feature = "test-faults")]
#[test]
fn pending_clean_checkpoint_protects_refetchable_objects_from_prune() {
    fault_case("before-transaction", "pause", true)
}
