#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_rejects_plaintext_userinfo_redirect_targets_and_content_paths() {
        for endpoint in [
            "http://localhost:1234",
            "https://user@localhost:1234",
            "https://localhost:1234/path",
            "https://localhost:1234/?q=x",
        ] {
            assert!(validate_endpoint(endpoint).is_err());
        }
        assert!(validate_endpoint("https://localhost:1234").is_ok());
    }
}
use magus_fs_core::{protocol::*, *};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub endpoint: String,
    pub namespace: NamespaceId,
    pub replica: ReplicaId,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_principal: Option<PrincipalId>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Counters {
    pub requests: u64,
    pub downloaded_body_bytes: u64,
    pub uploaded_body_bytes: u64,
    pub retries: u64,
    pub logical_unique_upload_bytes: u64,
}
#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub retryable: bool,
}
impl From<FsError> for Failure {
    fn from(e: FsError) -> Self {
        Self {
            code: e.code(),
            retryable: false,
        }
    }
}
pub type Result<T> = std::result::Result<T, Failure>;
pub fn validate_endpoint(s: &str) -> std::result::Result<reqwest::Url, FsError> {
    let url = reqwest::Url::parse(s).map_err(|_| FsError::InvalidSource)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(FsError::InvalidSource);
    }
    Ok(url)
}
/// Descriptor-relative open prevents symlink traversal and checks both private directory and file.
pub fn read_private(path: &Path, roots: &[PathBuf]) -> std::result::Result<Vec<u8>, FsError> {
    if !path.is_absolute()
        || roots
            .iter()
            .any(|root| path.starts_with(root) || root.starts_with(path))
    {
        return Err(FsError::StorageOverlap);
    }
    let parts: Vec<_> = path.components().collect();
    if parts.len() < 2 {
        return Err(FsError::UnsafeStorage);
    }
    let mut dir = File::open("/")?;
    for part in &parts[1..parts.len() - 1] {
        let Component::Normal(s) = part else {
            return Err(FsError::UnsafeStorage);
        };
        let name = std::ffi::CString::new(s.as_bytes()).map_err(|_| FsError::UnsafeStorage)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(FsError::UnsafeStorage);
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    let m = dir.metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
        return Err(FsError::UnsafeStorage);
    }
    let Component::Normal(leaf) = parts.last().ok_or(FsError::UnsafeStorage)? else {
        return Err(FsError::UnsafeStorage);
    };
    let name = std::ffi::CString::new(leaf.as_bytes()).map_err(|_| FsError::UnsafeStorage)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(FsError::UnsafeStorage);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > MAX_CONTROL as u64
    {
        return Err(FsError::UnsafeStorage);
    }
    let mut bytes = vec![];
    file.take(MAX_CONTROL as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONTROL {
        return Err(FsError::LimitExceeded);
    }
    Ok(bytes)
}
pub fn load(
    path: &Path,
    roots: &[PathBuf],
) -> std::result::Result<(Profile, TransportIdentity, Vec<u8>, String), FsError> {
    let mut p: Profile = serde_json::from_slice(&read_private(path, roots)?)
        .map_err(|_| FsError::InvalidDescriptor)?;
    p.endpoint = validate_endpoint(&p.endpoint)?
        .as_str()
        .trim_end_matches('/')
        .to_owned();
    let ca = read_private(&p.ca_file, roots)?;
    let token = String::from_utf8(read_private(&p.token_file, roots)?)
        .map_err(|_| FsError::InvalidDescriptor)?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FsError::InvalidDescriptor);
    }
    let bytes = serde_json::to_vec(&(&p, ObjectId::for_bytes(&ca)?))
        .map_err(|_| FsError::InvalidDescriptor)?;
    Ok((p, TransportIdentity::for_bytes(&bytes)?, ca, token))
}
type DnsLookup = fn(&str) -> std::io::Result<Vec<std::net::SocketAddr>>;
static DNS_OUTSTANDING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct DnsPermit;
impl Drop for DnsPermit {
    fn drop(&mut self) {
        DNS_OUTSTANDING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
fn system_lookup(host: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    (host, 0).to_socket_addrs().map(Iterator::collect)
}
struct BoundedResolver {
    lookup: DnsLookup,
    exhausted: Arc<std::sync::atomic::AtomicBool>,
}
impl reqwest::dns::Resolve for BoundedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        use std::sync::atomic::Ordering;
        if DNS_OUTSTANDING
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < 4).then_some(n + 1)
            })
            .is_err()
        {
            self.exhausted.store(true, Ordering::SeqCst);
            return Box::pin(async {
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "DNS admission exhausted",
                ))
                    as Box<dyn std::error::Error + Send + Sync>)
            });
        }
        let permit = DnsPermit;
        let host = name.as_str().to_owned();
        let lookup = self.lookup;
        Box::pin(async move {
            // The permit moves into actual blocking work, not the cancellable waiter.
            let addresses = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                lookup(&host)
            })
            .await??;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
#[derive(Clone)]
pub struct Transport {
    pub binding: SyncBinding,
    roots: Vec<PathBuf>,
    principals: Vec<PrincipalId>,
    replica: ReplicaId,
    dns_lookup: DnsLookup,
    pub counters: Arc<Mutex<Counters>>,
}
pub const MAX_UPLOAD_LIST_RESPONSE: usize = 512 * 1024;
impl Transport {
    pub fn new(binding: SyncBinding, config: &ReplicaConfig) -> std::result::Result<Self, FsError> {
        let t = Self {
            binding,
            roots: config.content_roots.clone(),
            principals: config
                .authorities
                .iter()
                .map(|a| a.principal.clone())
                .collect(),
            replica: config.replica.clone(),
            dns_lookup: system_lookup,
            counters: Arc::new(Mutex::new(Counters::default())),
        };
        t.credentials()?;
        Ok(t)
    }
    fn credentials(&self) -> std::result::Result<(Profile, Vec<u8>, String), FsError> {
        let (p, id, ca, token) = load(&self.binding.transport_profile, &self.roots)?;
        if id != self.binding.transport_identity
            || p.namespace != self.binding.id
            || p.replica != self.replica
        {
            return Err(FsError::ConfigMismatch);
        }
        if p.publication_principal
            .as_ref()
            .is_some_and(|p| !self.principals.contains(p))
        {
            return Err(FsError::UnknownPrincipal);
        }
        Ok((p, ca, token))
    }
    pub(super) fn credential_stamp(&self) -> std::result::Result<ObjectId, FsError> {
        ObjectId::for_bytes(self.credentials()?.2.as_bytes())
    }
    pub(super) fn publication_actor(&self, fallback: Actor) -> std::result::Result<Actor, FsError> {
        Ok(self
            .credentials()?
            .0
            .publication_principal
            .map(Actor::new)
            .unwrap_or(fallback))
    }
    pub fn bytes(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        limit: usize,
        deadline: Instant,
        object_body: bool,
    ) -> Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(Failure {
                code: "deadline",
                retryable: true,
            });
        }
        let (profile, ca, token) = self.credentials()?;
        // Own the async runtime on an ordinary thread, including when called from a
        // native adapter's Tokio runtime. Bounded shutdown never joins stalled DNS.
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .max_blocking_threads(4)
                        .build()
                        .map_err(|_| Failure {
                            code: "transport",
                            retryable: true,
                        })?;
                    let result = runtime.block_on(async {
                        match tokio::time::timeout_at(
                            tokio::time::Instant::from_std(deadline),
                            async {
                                let remaining = deadline.saturating_duration_since(Instant::now());
                                if remaining.is_zero() {
                                    return Err(Failure {
                                        code: "deadline",
                                        retryable: true,
                                    });
                                }
                                let cert =
                                    reqwest::Certificate::from_pem(&ca).map_err(|_| Failure {
                                        code: "invalid_source",
                                        retryable: false,
                                    })?;
                                let exhausted = Arc::new(std::sync::atomic::AtomicBool::new(false));
                                let network_error = |error: reqwest::Error| Failure {
                                    code: if exhausted.load(std::sync::atomic::Ordering::SeqCst) {
                                        "backpressure"
                                    } else if error.is_timeout() {
                                        "deadline"
                                    } else {
                                        "transport"
                                    },
                                    retryable: true,
                                };
                                let client = reqwest::Client::builder()
                                    .dns_resolver(Arc::new(BoundedResolver {
                                        lookup: self.dns_lookup,
                                        exhausted: exhausted.clone(),
                                    }))
                                    .no_proxy()
                                    .retry(reqwest::retry::never())
                                    .redirect(reqwest::redirect::Policy::none())
                                    .tls_certs_only([cert])
                                    .connect_timeout(Duration::from_secs(2).min(remaining))
                                    .timeout(remaining)
                                    .build()
                                    .map_err(network_error)?;
                                let url = format!(
                                    "{}/v1/n/{}{}",
                                    profile.endpoint,
                                    profile.namespace.as_str(),
                                    path
                                );
                                let method = reqwest::Method::from_bytes(method.as_bytes())
                                    .map_err(|_| Failure {
                                        code: "invalid_descriptor",
                                        retryable: false,
                                    })?;
                                {
                                    let mut c = self.counters.lock().unwrap();
                                    c.requests += 1;
                                    if object_body && method == reqwest::Method::PUT {
                                        c.uploaded_body_bytes += body.len() as u64;
                                    }
                                }
                                let download = object_body && method == reqwest::Method::GET;
                                let mut response = client
                                    .request(method, url)
                                    .bearer_auth(token)
                                    .header("content-type", "application/json")
                                    .body(body)
                                    .send()
                                    .await
                                    .map_err(network_error)?;
                                let status = response.status();
                                let max = if status.is_success() {
                                    limit
                                } else {
                                    MAX_CONTROL
                                };
                                if response.content_length().is_some_and(|n| n > max as u64) {
                                    return Err(Failure {
                                        code: "limit_exceeded",
                                        retryable: false,
                                    });
                                }
                                let mut bytes = vec![];
                                while let Some(chunk) =
                                    response.chunk().await.map_err(network_error)?
                                {
                                    if download {
                                        self.counters.lock().unwrap().downloaded_body_bytes +=
                                            chunk.len() as u64;
                                    }
                                    if bytes.len().saturating_add(chunk.len()) > max {
                                        return Err(Failure {
                                            code: "limit_exceeded",
                                            retryable: false,
                                        });
                                    }
                                    bytes.extend_from_slice(&chunk);
                                }
                                if !status.is_success() {
                                    let value: serde_json::Value =
                                        serde_json::from_slice(&bytes).unwrap_or_default();
                                    let code = match value["code"].as_str() {
                                        Some("stale_head") => "stale_head",
                                        Some("invalid_credential") => "invalid_credential",
                                        Some("backpressure") => "backpressure",
                                        Some("unsupported_operation") => "unsupported_operation",
                                        Some("expired_upload") => "expired_upload",
                                        // Collaboration-v1 definitive outcomes (FS2-B Task 2).
                                        Some("conflicted") => "conflicted",
                                        Some("already_resolved") => "already_resolved",
                                        Some("incomplete_resolution") => "incomplete_resolution",
                                        Some("invalid_resolution") => "invalid_resolution",
                                        Some("absent_alternative") => "absent_alternative",
                                        Some("invalid_cursor") => "invalid_cursor",
                                        Some("cursor_expired") => "cursor_expired",
                                        Some("base_unavailable") => "base_unavailable",
                                        _ => match status.as_u16() {
                                            401 => "invalid_credential",
                                            404 => "denied",
                                            409 => "conflict",
                                            413 => "limit_exceeded",
                                            503 => "backend_unavailable",
                                            _ => "invalid_response",
                                        },
                                    };
                                    return Err(Failure {
                                        code,
                                        retryable: status.as_u16() == 503,
                                    });
                                }
                                Ok(bytes)
                            },
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(Failure {
                                code: "deadline",
                                retryable: true,
                            }),
                        }
                    });
                    runtime.shutdown_timeout(deadline.saturating_duration_since(Instant::now()));
                    result
                })
                .join()
                .map_err(|_| Failure {
                    code: "transport",
                    retryable: true,
                })?
        })
    }
    /// Only the owned completed-object listing has this larger control response bound.
    pub fn upload_listing<T: serde::de::DeserializeOwned>(
        &self,
        upload: &UploadId,
        deadline: Instant,
    ) -> Result<T> {
        let bytes = self.bytes(
            "GET",
            &format!("/uploads/{}", upload.as_str()),
            vec![],
            MAX_UPLOAD_LIST_RESPONSE,
            deadline,
            false,
        )?;
        serde_json::from_slice(&bytes).map_err(|_| Failure {
            code: "invalid_response",
            retryable: false,
        })
    }
    pub fn json<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: impl Serialize,
        deadline: Instant,
    ) -> Result<T> {
        let body = if method == "GET" {
            vec![]
        } else {
            serde_json::to_vec(&body).map_err(|_| Failure {
                code: "invalid_descriptor",
                retryable: false,
            })?
        };
        if body.len() > MAX_CONTROL {
            return Err(Failure {
                code: "limit_exceeded",
                retryable: false,
            });
        }
        serde_json::from_slice(&self.bytes(method, path, body, MAX_CONTROL, deadline, false)?)
            .map_err(|_| Failure {
                code: "invalid_response",
                retryable: false,
            })
    }
}
impl RemoteFetcher for Transport {
    fn fetch(
        &self,
        source: &RemoteSourceId,
        id: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> std::result::Result<Vec<u8>, FsError> {
        if *source != self.binding.source || size > MAX_CHUNK {
            return Err(FsError::InvalidSource);
        }
        let result = self.bytes(
            "GET",
            &format!(
                "/views/{}/objects/{}",
                self.binding.view.view.as_str(),
                id.as_str()
            ),
            vec![],
            size as usize,
            deadline.min(Instant::now() + Duration::from_millis(4500)),
            true,
        );
        let bytes = result.map_err(|e| FsError::BaseUnavailable {
            object: id.clone(),
            cause: SourceFailure::Transport {
                kind: e.code.into(),
            },
        })?;
        if bytes.len() as u64 != size || ObjectId::for_bytes(&bytes)? != *id {
            return Err(FsError::CorruptObject);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn slow(_: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        std::thread::sleep(Duration::from_secs(1));
        Ok(vec!["127.0.0.1:9".parse().unwrap()])
    }
    fn ready(_: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(vec!["127.0.0.1:9".parse().unwrap()])
    }
    #[test]
    fn dns_deadline_and_admission_survive_timed_out_resolver_work() {
        let dir = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "fs2-dns-{}",
            RemoteSourceId::random().unwrap().as_str()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = |name: &str, bytes: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let p = Profile {
            publication_principal: None,
            endpoint: "https://slow-dns.invalid:9".into(),
            namespace: NamespaceId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            ca_file: private("ca", include_bytes!("../../tests/fixtures/client-ca.pem")),
            token_file: private("token", "a".repeat(64).as_bytes()),
        };
        let path = private("profile", &serde_json::to_vec(&p).unwrap());
        let (_, fingerprint, _, _) = load(&path, &[]).unwrap();
        let binding = SyncBinding {
            id: p.namespace,
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::Isolated,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision: RevisionId::parse(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            transport_profile: path,
            transport_identity: fingerprint,
        };
        let config = ReplicaConfig {
            replica: p.replica,
            authorities: vec![],
            content_roots: vec![],
            cache_bytes: 0,
            history_administrators: vec![],
            retained_history_grants: vec![],
        };
        let result = std::panic::catch_unwind(|| {
            for _ in 0..4 {
                let mut t = Transport::new(binding.clone(), &config).unwrap();
                t.dns_lookup = slow;
                let start = Instant::now();
                let e = t
                    .bytes(
                        "GET",
                        "/views",
                        vec![],
                        64,
                        start + Duration::from_millis(40),
                        false,
                    )
                    .unwrap_err();
                assert!(
                    start.elapsed() < Duration::from_millis(400),
                    "resolver drop exceeded deadline: {:?}",
                    start.elapsed()
                );
                assert_eq!(e.code, "deadline");
            }
            // A different Transport instance shares the cap while the timed-out work is still alive.
            let mut t = Transport::new(binding, &config).unwrap();
            t.dns_lookup = ready;
            let e = t
                .bytes(
                    "GET",
                    "/views",
                    vec![],
                    64,
                    Instant::now() + Duration::from_millis(100),
                    false,
                )
                .unwrap_err();
            assert_eq!(e.code, "backpressure");
            assert!(e.retryable);
            std::thread::sleep(Duration::from_millis(1100));
            let e = t
                .bytes(
                    "GET",
                    "/views",
                    vec![],
                    64,
                    Instant::now() + Duration::from_millis(100),
                    false,
                )
                .unwrap_err();
            assert_eq!(e.code, "transport");
        });
        std::fs::remove_dir_all(dir).unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}

impl Transport {
    /// One bounded authenticated WSS connection. Hints carry no content authority.
    /// It owns no SyncExecution/Core lock and shares HTTP's outstanding DNS budget.
    pub(super) fn hints(
        &self,
        stop: &std::sync::atomic::AtomicBool,
    ) -> std::result::Result<(), FsError> {
        use futures_util::StreamExt;
        use reqwest::dns::Resolve;
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        use std::sync::atomic::Ordering;
        use tokio_tungstenite::{
            tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig},
            Connector,
        };
        let (profile, ca, token) = self.credentials()?;
        let endpoint = validate_endpoint(&profile.endpoint)?;
        let host = endpoint
            .host_str()
            .ok_or(FsError::InvalidSource)?
            .to_owned();
        let port = endpoint
            .port_or_known_default()
            .ok_or(FsError::InvalidSource)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&ca) {
            roots
                .add(cert.map_err(|_| FsError::InvalidSource)?)
                .map_err(|_| FsError::InvalidSource)?;
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let url = format!(
            "{}/v1/n/{}/notifications?branch={}&after=0&limit=128",
            profile.endpoint.replacen("https:", "wss:", 1),
            profile.namespace.as_str(),
            self.binding.branch.as_str()
        );
        let mut request = url
            .into_client_request()
            .map_err(|_| FsError::InvalidSource)?;
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {token}")
                .parse()
                .map_err(|_| FsError::InvalidSource)?,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(4)
            .build()?;
        let result = runtime.block_on(async {
            let connect = async {
                let resolver = BoundedResolver {
                    lookup: self.dns_lookup,
                    exhausted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                };
                let mut addresses = resolver
                    .resolve(host.parse().map_err(|_| FsError::InvalidSource)?)
                    .await
                    .map_err(|_| FsError::InvalidSource)?;
                let mut address = addresses.next().ok_or(FsError::InvalidSource)?;
                address.set_port(port);
                let socket = tokio::net::TcpStream::connect(address).await?;
                let config = WebSocketConfig::default()
                    .max_message_size(Some(1024))
                    .max_frame_size(Some(1024));
                tokio_tungstenite::client_async_tls_with_config(
                    request,
                    socket,
                    Some(config),
                    Some(Connector::Rustls(Arc::new(tls))),
                )
                .await
                .map_err(|_| FsError::InvalidSource)
            };
            let (mut ws, _) = tokio::time::timeout(Duration::from_secs(2), connect)
                .await
                .map_err(|_| FsError::InvalidSource)??;
            let start = Instant::now();
            while !stop.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(30) {
                match tokio::time::timeout(Duration::from_millis(200), ws.next()).await {
                    Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                        #[derive(Deserialize)]
                        #[serde(deny_unknown_fields)]
                        struct Hint {
                            cursor: i64,
                        }
                        let hint: Hint =
                            serde_json::from_str(&text).map_err(|_| FsError::InvalidDescriptor)?;
                        if hint.cursor < 0 {
                            return Err(FsError::InvalidDescriptor);
                        }
                        #[cfg(feature = "test-faults")]
                        if std::env::var_os("MAGUS_TEST_DROP_WSS_HINTS").is_some() {
                            eprintln!("test_drop_wss_hint cursor={}", hint.cursor);
                            continue;
                        }
                        eprintln!("live_hint cursor={}", hint.cursor);
                    }
                    Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))))
                    | Ok(None)
                    | Ok(Some(Err(_))) => break,
                    _ => {}
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(200), ws.close(None)).await;
            Ok(())
        });
        runtime.shutdown_timeout(Duration::ZERO);
        result
    }
}

#[cfg(test)]
mod publication_actor_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn private_publication_actor_is_validated_and_bound_to_transport_identity() {
        let root = PathBuf::from(if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        })
        .join(format!(
            "fs2-publication-{}",
            RemoteSourceId::random().unwrap().as_str()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = |name: &str, bytes: &[u8]| {
            let p = root.join(name);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let principal = PrincipalId::parse(format!("principal:{}", "a".repeat(32))).unwrap();
        let group = GroupId::parse(format!("group:{}", "a".repeat(32))).unwrap();
        let replica = ReplicaId::random().unwrap();
        let namespace = NamespaceId::random().unwrap();
        let mut profile = serde_json::json!({"endpoint":"https://localhost:9","namespace":namespace,"replica":replica,"ca_file":private("ca",include_bytes!("../../tests/fixtures/client-ca.pem")),"token_file":private("token","a".repeat(64).as_bytes()),"publication_principal":principal});
        let path = private("profile", &serde_json::to_vec(&profile).unwrap());
        let (_, identity, _, _) = load(&path, &[]).unwrap();
        let binding = SyncBinding {
            id: namespace,
            branch: BranchName::parse("main".into()).unwrap(),
            publication: PublicationMode::Isolated,
            source: RemoteSourceId::random().unwrap(),
            view: ViewBinding {
                view: ViewId::random().unwrap(),
                head: HeadToken::random().unwrap(),
                revision: RevisionId::parse(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            transport_profile: path.clone(),
            transport_identity: identity,
        };
        let mut config = ReplicaConfig {
            replica,
            authorities: vec![Authority {
                principal: principal.clone(),
                uid: 1001,
                primary_group: group.clone(),
                gid: 1001,
                groups: vec![group],
                dac_override: false,
                ownership_transfer: false,
            }],
            content_roots: vec![],
            cache_bytes: 1,
            history_administrators: vec![],
            retained_history_grants: vec![],
        };
        assert!(Transport::new(binding.clone(), &config).is_ok());
        config.authorities.clear();
        assert_eq!(
            Transport::new(binding.clone(), &config)
                .err()
                .unwrap()
                .code(),
            "unknown_principal"
        );
        profile["publication_principal"] =
            serde_json::json!("principal:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        private("profile", &serde_json::to_vec(&profile).unwrap());
        assert_eq!(
            Transport::new(binding, &config).err().unwrap().code(),
            "config_mismatch"
        );
        profile["publication_principal"] = serde_json::json!("invalid");
        private("profile", &serde_json::to_vec(&profile).unwrap());
        assert!(load(&path, &[]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
