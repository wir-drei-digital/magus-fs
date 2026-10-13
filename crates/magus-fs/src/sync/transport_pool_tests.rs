use super::*;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) struct Fixture {
    _network: std::sync::MutexGuard<'static, ()>,
    dir: PathBuf,
    pub(super) transport: Transport,
    config: ReplicaConfig,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
    port: u16,
}
impl Fixture {
    pub(super) fn new() -> Self {
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
        let stop = Arc::new(AtomicBool::new(false));
        let (count, seen, stopping, body_seen) = (
            accepted.clone(),
            requests.clone(),
            stop.clone(),
            bodies.clone(),
        );
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
                let (tls, seen, body_seen) = (tls.clone(), seen.clone(), body_seen.clone());
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
                        if reader
                            .get_mut()
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .is_err()
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
                    Fixture::call(t, "/ok", 2000)
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = queued.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            outcomes
                .iter()
                .any(|r| r.as_ref().is_err_and(|e| e.code == "backpressure")),
            "bounded queue must reject pressure"
        );
        for h in active {
            h.join().unwrap().unwrap();
        }
    });
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
