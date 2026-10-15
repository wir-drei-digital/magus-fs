use super::*;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Reply {
    status: u16,
    body: Vec<u8>,
    before_response: Option<Box<dyn FnOnce() + Send>>,
    response_body: Option<Box<dyn FnOnce() -> Vec<u8> + Send>>,
}
impl Reply {
    fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body: body.to_vec(),
            before_response: None,
            response_body: None,
        }
    }
}

pub(in crate::sync) struct Fixture {
    _network: std::sync::MutexGuard<'static, ()>,
    dir: PathBuf,
    pub(in crate::sync) transport: Transport,
    config: ReplicaConfig,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
    port: u16,
}
impl Fixture {
    pub(in crate::sync) fn response(&self, status: u16, body: &[u8]) {
        self.replies
            .lock()
            .unwrap()
            .push_back(Reply::new(status, body));
    }

    pub(in crate::sync) fn new() -> Self {
        let network = NETWORK_TEST.lock().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_slice_iter(include_bytes!(
                    "../../tests/fixtures/pool/cert.pem"
                ))
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap(),
                PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/fixtures/pool/key.pem"))
                    .unwrap(),
            )
            .unwrap();
        let tls = Arc::new(tls);
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::<Reply>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, seen, stopping, body_seen) = (
            accepted.clone(),
            requests.clone(),
            stop.clone(),
            bodies.clone(),
        );
        let scripted = replies.clone();
        let server = std::thread::spawn(move || {
            for socket in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let socket = socket.unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let (tls, seen, body_seen, scripted) = (
                    tls.clone(),
                    seen.clone(),
                    body_seen.clone(),
                    scripted.clone(),
                );
                std::thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(tls).unwrap();
                    let stream = rustls::StreamOwned::new(conn, socket);
                    let mut reader = BufReader::new(stream);
                    loop {
                        let mut request = String::new();
                        loop {
                            let mut line = String::new();
                            match reader.read_line(&mut line) {
                                Ok(0) | Err(_) => return,
                                _ => {}
                            }
                            if line == "\r\n" {
                                break;
                            }
                            request.push_str(&line);
                        }
                        let length = request
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        let mut body = vec![0; length];
                        if reader.read_exact(&mut body).is_err() {
                            return;
                        }
                        body_seen.lock().unwrap().push(body);
                        seen.lock().unwrap().push(request.clone());
                        if request.contains("/disconnect ") {
                            return;
                        }
                        if request.contains("/stall ") {
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        let mut reply = scripted
                            .lock()
                            .unwrap()
                            .pop_front()
                            .unwrap_or_else(|| Reply::new(200, b"ok"));
                        if let Some(action) = reply.before_response {
                            action();
                        }
                        if let Some(body) = reply.response_body {
                            reply.body = body();
                        }
                        let header = format!(
                            "HTTP/1.1 {} fixture\r\nContent-Length: {}\r\n\r\n",
                            reply.status,
                            reply.body.len()
                        );
                        if reader.get_mut().write_all(header.as_bytes()).is_err()
                            || reader.get_mut().write_all(&reply.body).is_err()
                        {
                            return;
                        }
                        if reader.get_mut().flush().is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let dir = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "fs2-pool-{}",
            RemoteSourceId::random().unwrap().as_str()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        };
        let config = ReplicaConfig {
            replica: ReplicaId::random().unwrap(),
            authorities: vec![],
            content_roots: vec![],
            cache_bytes: 0,
            history_administrators: vec![],
            retained_history_grants: vec![],
        };
        let profile = Profile {
            endpoint: format!("https://localhost:{port}"),
            namespace: NamespaceId::random().unwrap(),
            replica: config.replica.clone(),
            ca_file: private("ca", include_bytes!("../../tests/fixtures/pool/cert.pem")),
            token_file: private("token", "a".repeat(64).as_bytes()),
            publication_principal: None,
        };
        let path = private("profile", &serde_json::to_vec(&profile).unwrap());
        let (_, id, _, _) = load(&path, &[]).unwrap();
        let binding = SyncBinding {
            id: profile.namespace,
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::Isolated,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision: RevisionId::parse(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            transport_profile: path,
            transport_identity: id,
        };
        Self {
            _network: network,
            dir,
            transport: Transport::new(binding, &config).unwrap(),
            config,
            accepted,
            requests,
            replies,
            bodies,
            stop,
            server: Some(server),
            port,
        }
    }
    fn call(t: &Transport, path: &str, milliseconds: u64) -> Result<Vec<u8>> {
        t.bytes(
            "GET",
            path,
            vec![],
            64,
            Instant::now() + Duration::from_millis(milliseconds),
            false,
        )
    }
    fn wait_requests(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.requests.lock().unwrap().len() < count {
            assert!(Instant::now() < deadline, "fixture requests stalled");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
        self.server.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn fetch_fixture(f: &Fixture, deadline: Instant) -> std::result::Result<Vec<u8>, FsError> {
    f.transport.fetch(
        &f.transport.binding.source,
        &ObjectId::for_bytes(b"ok").unwrap(),
        2,
        deadline,
    )
}

#[test]
fn immutable_get_retries_only_service_admission_and_reuses_connection() {
    let f = Fixture::new();
    f.replies.lock().unwrap().extend([
        Reply::new(503, br#"{"code":"backpressure"}"#),
        Reply::new(200, b"ok"),
    ]);
    assert_eq!(
        fetch_fixture(&f, Instant::now() + Duration::from_secs(1)).unwrap(),
        b"ok"
    );
    let requests = f.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert!(requests.iter().all(|r| r.starts_with("GET ")));
    assert_eq!(f.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(f.transport.counters.lock().unwrap().retries, 1);
}

#[test]
fn immutable_get_persistent_admission_keeps_original_absolute_deadline() {
    let f = Fixture::new();
    f.replies
        .lock()
        .unwrap()
        .extend((0..300).map(|_| Reply::new(503, br#"{"code":"backpressure"}"#)));
    let start = Instant::now();
    let error = fetch_fixture(&f, start + Duration::from_millis(120)).unwrap_err();
    assert!(
        matches!(error,FsError::BaseUnavailable{cause:SourceFailure::Transport{ref kind},..} if kind=="deadline")
    );
    assert!(start.elapsed() < Duration::from_millis(300));
    assert!(f.requests.lock().unwrap().len() > 1);
    let start = Instant::now();
    let error = fetch_fixture(&f, start + Duration::from_secs(6)).unwrap_err();
    assert!(
        matches!(error,FsError::BaseUnavailable{cause:SourceFailure::Transport{ref kind},..} if kind=="deadline")
    );
    assert!(
        start.elapsed() >= Duration::from_millis(4400)
            && start.elapsed() < Duration::from_millis(4800)
    );
}

#[test]
fn immutable_get_revalidates_rotated_and_revoked_credentials_after_admission() {
    let f = Fixture::new();
    let token = f.dir.join("token");
    let mut first = Reply::new(503, br#"{"code":"backpressure"}"#);
    first.before_response = Some(Box::new(move || {
        std::fs::write(token, "b".repeat(64)).unwrap()
    }));
    f.replies
        .lock()
        .unwrap()
        .extend([first, Reply::new(200, b"ok")]);
    assert_eq!(
        fetch_fixture(&f, Instant::now() + Duration::from_secs(1)).unwrap(),
        b"ok"
    );
    let requests = f.requests.lock().unwrap();
    assert!(requests[0].contains(&format!("Bearer {}", "a".repeat(64))));
    assert!(requests[1].contains(&format!("Bearer {}", "b".repeat(64))));
    drop(requests);
    let token = f.dir.join("token");
    let mut denial = Reply::new(503, br#"{"code":"backpressure"}"#);
    denial.before_response = Some(Box::new(move || {
        std::fs::set_permissions(token, std::fs::Permissions::from_mode(0o644)).unwrap()
    }));
    f.replies.lock().unwrap().push_back(denial);
    let error = fetch_fixture(&f, Instant::now() + Duration::from_secs(1)).unwrap_err();
    assert!(
        matches!(error,FsError::BaseUnavailable{cause:SourceFailure::Transport{ref kind},..} if kind=="unsafe_storage")
    );
    assert_eq!(f.requests.lock().unwrap().len(), 3);
}

#[test]
fn immutable_get_hard_failures_and_post_are_never_retried() {
    let f = Fixture::new();
    for (status, body) in [
        (401, br#"{"code":"invalid_credential"}"#.as_slice()),
        (404, br#"{"code":"denied"}"#.as_slice()),
        (503, br#"{"code":"backend_unavailable"}"#.as_slice()),
        (404, br#"{"code":"backpressure"}"#.as_slice()),
        (200, b"no".as_slice()),
    ] {
        let count = f.requests.lock().unwrap().len();
        f.replies
            .lock()
            .unwrap()
            .push_back(Reply::new(status, body));
        assert!(fetch_fixture(&f, Instant::now() + Duration::from_secs(1)).is_err());
        assert_eq!(f.requests.lock().unwrap().len(), count + 1);
    }
    f.replies
        .lock()
        .unwrap()
        .push_back(Reply::new(503, br#"{"code":"backpressure"}"#));
    assert_eq!(
        f.transport
            .bytes(
                "POST",
                "/candidates",
                b"{}".to_vec(),
                64,
                Instant::now() + Duration::from_secs(1),
                false
            )
            .unwrap_err()
            .code,
        "backpressure"
    );
    assert_eq!(f.requests.lock().unwrap().len(), 6);
    assert_eq!(f.transport.counters.lock().unwrap().retries, 0);
}

#[test]
fn immutable_get_service_revocation_and_changed_trust_fail_after_admission() {
    let f = Fixture::new();
    f.replies.lock().unwrap().extend([
        Reply::new(503, br#"{"code":"backpressure"}"#),
        Reply::new(401, br#"{"code":"invalid_credential"}"#),
    ]);
    let error = fetch_fixture(&f, Instant::now() + Duration::from_secs(1)).unwrap_err();
    assert!(
        matches!(error,FsError::BaseUnavailable{cause:SourceFailure::Transport{ref kind},..} if kind=="invalid_credential")
    );
    assert_eq!(f.requests.lock().unwrap().len(), 2);
    let ca = f.dir.join("ca");
    let mut first = Reply::new(503, br#"{"code":"backpressure"}"#);
    first.before_response = Some(Box::new(move || {
        let mut bytes = std::fs::read(&ca).unwrap();
        bytes.push(b'\n');
        std::fs::write(ca, bytes).unwrap();
    }));
    f.replies.lock().unwrap().push_back(first);
    let error = fetch_fixture(&f, Instant::now() + Duration::from_secs(1)).unwrap_err();
    assert!(
        matches!(error,FsError::BaseUnavailable{cause:SourceFailure::Transport{ref kind},..} if kind=="config_mismatch")
    );
    assert_eq!(f.requests.lock().unwrap().len(), 3);
    assert_eq!(f.transport.counters.lock().unwrap().retries, 1);
    assert!(matches!(
        f.transport.fetch(
            &RemoteSourceId::random().unwrap(),
            &ObjectId::for_bytes(b"ok").unwrap(),
            2,
            Instant::now() + Duration::from_secs(1)
        ),
        Err(FsError::InvalidSource)
    ));
    assert_eq!(f.requests.lock().unwrap().len(), 3);
}

#[test]
fn immutable_get_local_dns_admission_is_not_retried() {
    fn stalled(_: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        std::thread::sleep(Duration::from_secs(1));
        Ok(vec![])
    }
    fn resolved(addr: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        let port = addr.rsplit(':').next().unwrap().parse::<u16>().unwrap();
        Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
    }
    let mut f = Fixture::new();
    f.transport.dns_lookup = stalled;
    for _ in 0..4 {
        assert_eq!(
            Fixture::call(&f.transport, "/ok", 40).unwrap_err().code,
            "deadline"
        );
    }
    f.transport.dns_lookup = resolved;
    let result = fetch_fixture(&f, Instant::now() + Duration::from_millis(200));
    // Wait for actual lookup work to release permits even when an assertion fails.
    std::thread::sleep(Duration::from_millis(1100));
    assert!(
        matches!(result,Err(FsError::BaseUnavailable{cause:SourceFailure::Transport{ref kind},..}) if kind=="backpressure")
    );
    assert_eq!(f.transport.counters.lock().unwrap().retries, 0);
    assert!(f.requests.lock().unwrap().is_empty());
}

#[test]
fn compatible_requests_and_reconstructed_transports_reuse_tls_connection() {
    let f = Fixture::new();
    assert_eq!(Fixture::call(&f.transport, "/ok", 1000).unwrap(), b"ok");
    let t = Transport::new(f.transport.binding.clone(), &f.config).unwrap();
    assert_eq!(Fixture::call(&t, "/ok", 1000).unwrap(), b"ok");
    assert_eq!(
        f.accepted.load(Ordering::SeqCst),
        1,
        "compatible client should reuse TLS connection"
    );
}
#[test]
fn canonical_revision_body_above_control_limit_transfers_exactly_then_reuses_connection() {
    let f = Fixture::new();
    let body: Vec<_> = (0..300_000).map(|n| (n % 251) as u8).collect();
    assert_eq!(
        f.transport
            .bytes(
                "PUT",
                "/uploads/fixture/revisions/fixture",
                body.clone(),
                64,
                Instant::now() + Duration::from_secs(2),
                false
            )
            .unwrap(),
        b"ok"
    );
    assert_eq!(f.bodies.lock().unwrap()[0], body);
    assert_eq!(Fixture::call(&f.transport, "/ok", 1000).unwrap(), b"ok");
    assert_eq!(f.accepted.load(Ordering::SeqCst), 1);
}
#[test]
fn retained_body_budget_returns_backpressure_and_releases_on_completion() {
    let f = Fixture::new();
    std::thread::scope(|scope| {
        let active: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    f.transport.bytes(
                        "PUT",
                        "/stall",
                        vec![7; 8 * 1024 * 1024],
                        64,
                        Instant::now() + Duration::from_secs(5),
                        false,
                    )
                })
            })
            .collect();
        f.wait_requests(4);
        assert_eq!(
            f.transport
                .bytes(
                    "PUT",
                    "/ok",
                    vec![8; 1024],
                    64,
                    Instant::now() + Duration::from_secs(1),
                    false
                )
                .unwrap_err()
                .code,
            "backpressure"
        );
        for job in active {
            job.join().unwrap().unwrap();
        }
    });
    assert_eq!(Fixture::call(&f.transport, "/ok", 1000).unwrap(), b"ok");
}
#[test]
fn expired_queued_body_releases_admission_before_workers_become_available() {
    let f = Fixture::new();
    std::thread::scope(|scope| {
        let active: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| Fixture::call(&f.transport, "/stall", 2000)))
            .collect();
        f.wait_requests(4);
        let expired: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    f.transport.bytes(
                        "PUT",
                        "/ok",
                        vec![7; 16 * 1024 * 1024],
                        64,
                        Instant::now() + Duration::from_millis(40),
                        false,
                    )
                })
            })
            .collect();
        for job in expired {
            assert_eq!(job.join().unwrap().unwrap_err().code, "deadline");
        }
        assert_eq!(
            f.transport
                .bytes(
                    "PUT",
                    "/ok",
                    vec![7; 1024],
                    64,
                    Instant::now() + Duration::from_millis(40),
                    false
                )
                .unwrap_err()
                .code,
            "deadline",
            "expired queued bodies must not retain quota"
        );
        for job in active {
            job.join().unwrap().unwrap();
        }
    });
    assert_eq!(
        f.requests.lock().unwrap().len(),
        4,
        "expired queued body must never dispatch"
    );
}
#[test]
fn token_rotation_uses_fresh_authorization_and_ca_replacement_fails_closed() {
    let f = Fixture::new();
    Fixture::call(&f.transport, "/ok", 1000).unwrap();
    std::fs::write(f.dir.join("token"), "b".repeat(64)).unwrap();
    Fixture::call(&f.transport, "/ok", 1000).unwrap();
    assert!(f.requests.lock().unwrap()[1].contains(&format!("Bearer {}", "b".repeat(64))));
    let mut ca = std::fs::read(f.dir.join("ca")).unwrap();
    ca.push(b'\n');
    std::fs::write(f.dir.join("ca"), ca).unwrap();
    assert_eq!(
        Fixture::call(&f.transport, "/ok", 1000).unwrap_err().code,
        "config_mismatch"
    );
    let mut binding = f.transport.binding.clone();
    binding.transport_identity = load(&binding.transport_profile, &[]).unwrap().1;
    let t = Transport::new(binding, &f.config).unwrap();
    Fixture::call(&t, "/ok", 1000).unwrap();
    assert_eq!(f.accepted.load(Ordering::SeqCst), 3);
}
#[test]
fn first_short_deadline_does_not_become_client_wide_timeout_and_body_is_bounded() {
    let f = Fixture::new();
    Fixture::call(&f.transport, "/ok", 100).unwrap();
    assert_eq!(Fixture::call(&f.transport, "/stall", 1000).unwrap(), b"ok");
    let start = Instant::now();
    assert_eq!(
        Fixture::call(&f.transport, "/stall", 40).unwrap_err().code,
        "deadline"
    );
    assert!(start.elapsed() < Duration::from_millis(250));
}
#[test]
fn post_disconnect_is_never_retried() {
    let f = Fixture::new();
    assert!(f
        .transport
        .bytes(
            "POST",
            "/disconnect",
            vec![],
            64,
            Instant::now() + Duration::from_secs(1),
            false
        )
        .is_err());
    assert_eq!(f.requests.lock().unwrap().len(), 1);
    assert_eq!(f.transport.counters.lock().unwrap().retries, 0);
}
#[test]
fn saturated_executor_returns_backpressure_and_queued_deadline_expires_before_dispatch() {
    let f = Fixture::new();
    std::thread::scope(|scope| {
        let active: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| Fixture::call(&f.transport, "/stall", 2000)))
            .collect();
        f.wait_requests(4);
        let start = Instant::now();
        assert_eq!(
            Fixture::call(&f.transport, "/ok", 40).unwrap_err().code,
            "deadline"
        );
        assert!(start.elapsed() < Duration::from_millis(250));
        let barrier = Arc::new(std::sync::Barrier::new(38));
        let queued: Vec<_> = (0..37)
            .map(|_| {
                let barrier = barrier.clone();
                let t = &f.transport;
                scope.spawn(move || {
                    barrier.wait();
                    t.fetch(
                        &t.binding.source,
                        &ObjectId::for_bytes(b"ok").unwrap(),
                        2,
                        Instant::now() + Duration::from_millis(2000),
                    )
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = queued.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            outcomes
                .iter()
                .any(|r| matches!(r,Err(FsError::BaseUnavailable{cause:SourceFailure::Transport{kind},..}) if kind=="backpressure")),
            "bounded queue must reject pressure"
        );
        for h in active {
            h.join().unwrap().unwrap();
        }
    });
    assert_eq!(f.transport.counters.lock().unwrap().retries, 0);
}
#[test]
fn queued_request_revalidates_private_credentials_at_dispatch() {
    let f = Fixture::new();
    std::thread::scope(|scope| {
        let active: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| Fixture::call(&f.transport, "/stall", 2000)))
            .collect();
        f.wait_requests(4);
        let pending = scope.spawn(|| Fixture::call(&f.transport, "/ok", 2000));
        std::thread::sleep(Duration::from_millis(40));
        std::fs::set_permissions(f.dir.join("token"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(pending.join().unwrap().unwrap_err().code, "unsafe_storage");
        for h in active {
            h.join().unwrap().unwrap();
        }
        assert_eq!(f.requests.lock().unwrap().len(), 4);
    });
}

#[test]
fn mounted_same_view_recovery_clears_resolved_discovery_error() {
    let fixture = Fixture::new();
    let principal = PrincipalId::random().unwrap();
    let group = GroupId::random().unwrap();
    let actor = Actor::new(principal.clone());
    let mut config = fixture.config.clone();
    config.cache_bytes = 32 * 1024 * 1024;
    config.authorities.push(Authority {
        principal: principal.clone(),
        uid: unsafe { libc::geteuid() },
        gid: 1001,
        primary_group: group.clone(),
        groups: vec![group.clone()],
        dac_override: false,
        ownership_transfer: false,
    });
    let rep = Replica::open(fixture.dir.join("state"), config.clone()).unwrap();
    let revision = Revision {
        format: FORMAT.into(),
        hash: HASH.into(),
        layout: LAYOUT.into(),
        parents: vec![],
        operation: OperationId::random().unwrap(),
        replica: config.replica,
        principal: principal.clone(),
        captured_at_ns: 0,
        coverage: vec!["".into()],
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
    let bytes = encode_revision(&revision).unwrap();
    let id = revision_id(&revision).unwrap();
    rep.import_revision(
        ImportDescriptor {
            expected: id.clone(),
            bytes: bytes.clone(),
        },
        ChunkSource::Unavailable,
    )
    .unwrap();
    let owner = rep.begin_live(&id, actor.clone(), false).unwrap();
    let mut binding = fixture.transport.binding.clone();
    binding.publication = PublicationMode::SharedLive;
    binding.view.revision = id;
    rep.configure_sync(binding.clone()).unwrap();
    rep.enable_mounted_collaboration(&owner, &binding, actor.clone())
        .unwrap();
    drop(owner.create("local-draft", 0o600).unwrap());
    let mut incoming = crate::sync::Incoming::new(&rep).unwrap();
    fixture.response(404, br#"{"code":"denied"}"#);
    assert!(incoming
        .poll_mounted(|_| panic!("denied discovery must not apply"))
        .is_err());
    assert!(rep.incoming_recovery().unwrap().discovery_error.is_some());
    let retained = rep.local_work_recovery().unwrap().remove(0).operation;
    fixture.response(200, &serde_json::to_vec(&binding.view).unwrap());
    fixture.response(200, &bytes);
    let denied_generation = rep.live_status().unwrap().authority_generation;
    let result = incoming
        .select_current_remote(|mut prepared| {
            assert_eq!(
                rep.live_status()?.authority_generation,
                denied_generation,
                "fresh authority must wait for the serialized apply owner"
            );
            assert!(prepared.observe_authority(&rep)?);
            let state = rep.scheduling_snapshot()?;
            let fence = ContinuationFence {
                generation: state.generation,
                head: state.head.unwrap(),
                binding: binding.clone(),
                authority_generation: prepared.authority_generation,
                credential_stamp: prepared.credential_stamp,
                capability_generation: 0,
            };
            rep.use_current_remote(&retained, &prepared.binding, &fence, actor.clone())
                .map(crate::sync::MountedIncoming::Clean)
        })
        .unwrap();
    assert!(
        result.is_some(),
        "explicit selection must reach Core for the same authenticated view"
    );
    assert!(rep.incoming_recovery().unwrap().discovery_error.is_none());
    assert!(rep.pending_visibility().unwrap().is_some());
    // Same-bound authenticated no-op still refreshes under the apply owner.
    fixture.response(200, &serde_json::to_vec(&binding.view).unwrap());
    fixture.response(200, &bytes);
    assert!(matches!(
        incoming
            .poll_mounted(|mut prepared| {
                assert!(!prepared.observe_authority(&rep)?);
                Ok(crate::sync::MountedIncoming::Unchanged)
            })
            .unwrap(),
        Some(crate::sync::MountedIncoming::Unchanged)
    ));

    // The actual private socket route performs HTTP before acquiring callback ownership.
    drop(owner.create("second-draft", 0o600).unwrap());
    rep.observe_remote_authority(None, rep.live_status().unwrap().authority_generation)
        .unwrap();
    let recovery = rep
        .local_work_recovery()
        .unwrap()
        .into_iter()
        .find(|r| r.operation != retained)
        .unwrap();
    let denied_generation = rep.live_status().unwrap().authority_generation;
    let options = std::collections::BTreeMap::from([
        ("operation-id".into(), recovery.operation.as_str().into()),
        (
            "expected-generation".into(),
            owner.generation().unwrap().to_string(),
        ),
    ]);
    let epoch = Arc::new(Mutex::new(rep.live_status().unwrap().epoch));
    let selected = Arc::new(AtomicUsize::new(0));
    let (callback_epoch, count, expected_actor) = (epoch.clone(), selected.clone(), actor.clone());
    let hook: crate::adapters::control::LocalWorkSelection =
        Arc::new(move |rep, actor, options| {
            assert_eq!(actor.principal(), expected_actor.principal());
            count.fetch_add(1, Ordering::SeqCst);
            crate::cli::local_work_selection(rep, actor, options, |apply| {
                let mut owned_epoch = callback_epoch.lock().unwrap();
                let adoption = apply()?;
                *owned_epoch = adoption.epoch;
                Ok(adoption)
            })
        });
    let path = fixture.dir.join("state");
    let server = crate::adapters::control::Server::start_with_local_work_owner(
        rep.clone(),
        &path,
        false,
        hook.clone(),
    )
    .unwrap();
    fixture.response(200, &serde_json::to_vec(&binding.view).unwrap());
    fixture.response(200, &bytes);
    let held = epoch.lock().unwrap();
    let requests = fixture.requests.lock().unwrap().len();
    std::thread::scope(|scope| {
        let request = scope.spawn(|| {
            crate::adapters::control::request(&path, "sync-local-work-use-remote", &options)
                .unwrap()
                .unwrap()
        });
        fixture.wait_requests(requests + 2);
        assert_eq!(
            rep.live_status().unwrap().authority_generation,
            denied_generation
        );
        drop(held);
        let response = request.join().unwrap();
        assert_eq!(response.exit, 0, "{}", response.value);
        assert_eq!(*epoch.lock().unwrap(), rep.live_status().unwrap().epoch);
        assert_eq!(
            response.value["adoption"]["epoch"].as_u64().unwrap(),
            *epoch.lock().unwrap()
        );
    });
    assert_eq!(selected.load(Ordering::SeqCst), 1);
    drop(server);
    let readonly = crate::adapters::control::Server::start_with_local_work_owner(
        rep.clone(),
        &path,
        true,
        hook,
    )
    .unwrap();
    let response = crate::adapters::control::request(&path, "sync-local-work-use-remote", &options)
        .unwrap()
        .unwrap();
    assert_eq!(response.value["error"], "read_only");
    assert_eq!(
        selected.load(Ordering::SeqCst),
        1,
        "readonly must not enter the owner callback"
    );
    drop(readonly);
}

#[test]
fn controller_stale_retry_preserves_exact_attempt_history() {
    let fixture = Fixture::new();
    let principal = PrincipalId::random().unwrap();
    let group = GroupId::random().unwrap();
    let actor = Actor::new(principal.clone());
    let mut config = fixture.config.clone();
    config.cache_bytes = 32 * 1024 * 1024;
    config.authorities.push(Authority {
        principal: principal.clone(),
        uid: unsafe { libc::geteuid() },
        gid: 1001,
        primary_group: group.clone(),
        groups: vec![group.clone()],
        dac_override: false,
        ownership_transfer: false,
    });
    let rep = Replica::open(fixture.dir.join("state"), config.clone()).unwrap();
    let revision = Revision {
        format: FORMAT.into(),
        hash: HASH.into(),
        layout: LAYOUT.into(),
        parents: vec![],
        operation: OperationId::random().unwrap(),
        replica: config.replica,
        principal: principal.clone(),
        captured_at_ns: 0,
        coverage: vec!["".into()],
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
    let bytes = encode_revision(&revision).unwrap();
    let id = revision_id(&revision).unwrap();
    rep.import_revision(
        ImportDescriptor {
            expected: id.clone(),
            bytes: bytes.clone(),
        },
        ChunkSource::Unavailable,
    )
    .unwrap();
    let owner = rep.begin_live(&id, actor.clone(), false).unwrap();
    let mut binding = fixture.transport.binding.clone();
    binding.publication = PublicationMode::SharedLive;
    binding.view.revision = id;
    rep.configure_sync(binding.clone()).unwrap();
    rep.enable_mounted_collaboration(&owner, &binding, actor.clone())
        .unwrap();

    drop(owner.create("first-save", 0o600).unwrap());
    let op = OperationId::random().unwrap();
    let revision = owner
        .checkpoint(
            &op,
            owner.generation().unwrap(),
            Attribution {
                coverage: vec!["".into()],
                captured_at_ns: 0,
                provenance: "explicit".into(),
            },
        )
        .unwrap();
    rep.enqueue_submission(PendingSubmission {
        operation: op.clone(),
        local_revision: revision.clone(),
        original_view: binding.view.view.clone(),
        original_head: binding.view.head.clone(),
        expected_local_generation: owner.generation().unwrap(),
    })
    .unwrap();
    let mut p = rep.sync_status().unwrap().submissions.remove(0);
    p.private_receipt = Some(protocol::PrivateReceipt {
        receipt: protocol::ReceiptId::random().unwrap(),
        operation: op.clone(),
        replica: rep.configuration().unwrap().replica,
        submitted_revision: revision.clone(),
        original_view: binding.view.view.clone(),
        original_head: binding.view.head.clone(),
    });
    p.state = SubmissionState::PrivateRemote;
    rep.record_sync_progress(&op, SubmissionState::Queued, p.clone())
        .unwrap();
    fixture.response(409, br#"{"code":"stale_head"}"#);
    let fresh = protocol::ViewBinding {
        head: protocol::HeadToken::random().unwrap(),
        ..binding.view.clone()
    };
    fixture.response(200, &serde_json::to_vec(&fresh).unwrap());
    let replica = rep.clone();
    let shared_head = protocol::HeadToken::random().unwrap();
    fixture.replies.lock().unwrap().push_back(Reply {
        status: 200,
        body: vec![],
        before_response: None,
        response_body: Some(Box::new(move || {
            let current = replica.sync_status().unwrap().submissions.remove(0);
            serde_json::to_vec(&protocol::SharedReceipt {
                receipt: protocol::ReceiptId::random().unwrap(),
                operation: current.integration.unwrap().operation,
                replica: replica.configuration().unwrap().replica,
                submitted_revision: current.local_revision,
                branch: binding.branch,
                head: shared_head,
            })
            .unwrap()
        })),
    });
    let result = crate::sync::controller::SyncController::new(&rep)
        .unwrap()
        .drain(
            &revision,
            DurabilityLevel::Shared,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(result.state, SubmissionState::Shared);
    assert_eq!(result.superseded.len(), 1);
    assert_eq!(
        result.superseded[0].expected_head,
        p.private_receipt.as_ref().unwrap().original_head
    );
    assert_eq!(
        result.integration.as_ref().unwrap().expected_head,
        fresh.head
    );
    assert_ne!(
        result.integration.as_ref().unwrap().operation,
        result.superseded[0].operation
    );
    assert_eq!(result.private_receipt, p.private_receipt);
    assert!(rep.local_work_recovery().unwrap().is_empty());
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("/integrations "));
    assert!(requests[1].contains("/views "));
    assert!(requests[2].contains("/integrations "));
}
