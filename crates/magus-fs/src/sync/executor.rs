//! Bounded HTTP ownership, independent of Replica/Core/adapter locks.
use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{mpsc, OnceLock, Weak};
use tokio::sync::{mpsc as async_mpsc, watch};

const MAX_EXECUTORS: usize = 16;
const QUEUE: usize = 32;
const ACTIVE: usize = 4;
const CLIENTS: usize = 8;
const BODY_BYTES: usize = 32 * 1024 * 1024;
static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static REGISTRY: OnceLock<Mutex<BTreeMap<String, Weak<Executor>>>> = OnceLock::new();

fn failure(code: &'static str) -> Failure {
    Failure {
        code,
        retryable: true,
    }
}
pub(super) struct Job {
    pub authorization: Authorization,
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub limit: usize,
    pub deadline: Instant,
    pub object_body: bool,
    pub dns_lookup: DnsLookup,
    pub counters: Arc<Mutex<Counters>>,
}
struct OwnedJob {
    job: Job,
    _body: BodyPermit,
}
struct Pending {
    job: Arc<Mutex<Option<OwnedJob>>>,
    reply: mpsc::Sender<Result<Vec<u8>>>,
}
pub(super) struct Executor {
    sender: async_mpsc::Sender<Pending>,
    body_bytes: Arc<std::sync::atomic::AtomicUsize>,
    stop: watch::Sender<bool>,
    completed: Mutex<mpsc::Receiver<()>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}
struct BodyPermit {
    used: Arc<std::sync::atomic::AtomicUsize>,
    bytes: usize,
}
impl Drop for BodyPermit {
    fn drop(&mut self) {
        self.used
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
    }
}
struct LivePermit;
impl Drop for LivePermit {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Executor {
    pub fn for_replica(replica: &ReplicaId) -> std::result::Result<Arc<Self>, FsError> {
        use std::sync::atomic::Ordering;
        let mut registry = REGISTRY.get_or_init(Default::default).lock().unwrap();
        registry.retain(|_, entry| entry.strong_count() > 0);
        if let Some(executor) = registry.get(replica.as_str()).and_then(Weak::upgrade) {
            return Ok(executor);
        }
        LIVE.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < MAX_EXECUTORS).then_some(n + 1)
        })
        .map_err(|_| FsError::Backpressure)?;
        let permit = LivePermit;
        let (sender, mut receiver) = async_mpsc::channel::<Pending>(QUEUE);
        let (stop, mut stopping) = watch::channel(false);
        let (complete, completed) = mpsc::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(4)
            .build()?;
        let worker = std::thread::Builder::new()
            .name("magus-http".into())
            .spawn(move || {
                let _permit = permit;
                runtime.block_on(async move {
                    let pool = Arc::new(Mutex::new(Pool::default()));
                    let mut active = tokio::task::JoinSet::new();
                    loop {
                        use std::{
                            future::{poll_fn, Future},
                            task::Poll,
                        };
                        enum Event {
                            Stop,
                            Completed,
                            Next(Option<Pending>),
                        }
                        let event = {
                            let changed = stopping.changed();
                            let mut changed = std::pin::pin!(changed);
                            poll_fn(|cx| {
                                if changed.as_mut().poll(cx).is_ready() {
                                    return Poll::Ready(Event::Stop);
                                }
                                if !active.is_empty() && active.poll_join_next(cx).is_ready() {
                                    return Poll::Ready(Event::Completed);
                                }
                                if active.len() < ACTIVE {
                                    if let Poll::Ready(next) = receiver.poll_recv(cx) {
                                        return Poll::Ready(Event::Next(next));
                                    }
                                }
                                Poll::Pending
                            })
                            .await
                        };
                        match event {
                            Event::Stop | Event::Next(None) => break,
                            Event::Completed => {}
                            Event::Next(Some(pending)) => {
                                let Some(owned) = pending.job.lock().unwrap().take() else {
                                    let _ = pending.reply.send(Err(failure("deadline")));
                                    continue;
                                };
                                let pool = pool.clone();
                                active.spawn(async move {
                                    // Explicit capture keeps admission for the whole response,
                                    // including timeout/cancellation, rather than dropping an unused field.
                                    let OwnedJob { job, _body } = owned;
                                    let deadline = job.deadline;
                                    let result = match tokio::time::timeout_at(
                                        tokio::time::Instant::from_std(deadline),
                                        run(job, pool),
                                    )
                                    .await
                                    {
                                        Ok(result) => result,
                                        Err(_) => Err(failure("deadline")),
                                    };
                                    let _ = pending.reply.send(result);
                                });
                            }
                        }
                    }
                    receiver.close();
                    while let Ok(pending) = receiver.try_recv() {
                        pending.job.lock().unwrap().take();
                        let _ = pending.reply.send(Err(failure("transport")));
                    }
                    active.abort_all();
                    while active.join_next().await.is_some() {}
                });
                // Actual blocking DNS keeps its global permit until lookup returns.
                runtime.shutdown_timeout(Duration::ZERO);
                let _ = complete.send(());
            })?;
        let executor = Arc::new(Self {
            sender,
            body_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            stop,
            completed: Mutex::new(completed),
            worker: Mutex::new(Some(worker)),
        });
        registry.insert(replica.as_str().to_owned(), Arc::downgrade(&executor));
        Ok(executor)
    }
    pub fn submit(&self, job: Job) -> Result<Vec<u8>> {
        let deadline = job.deadline;
        if Instant::now() >= deadline {
            return Err(failure("deadline"));
        }
        let bytes = job.body.len();
        self.body_bytes
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |used| used.checked_add(bytes).filter(|next| *next <= BODY_BYTES),
            )
            .map_err(|_| failure("backpressure"))?;
        let body = BodyPermit {
            used: self.body_bytes.clone(),
            bytes,
        };
        let job = Arc::new(Mutex::new(Some(OwnedJob { job, _body: body })));
        let (reply, receive) = mpsc::channel();
        self.sender
            .try_send(Pending {
                job: job.clone(),
                reply,
            })
            .map_err(|e| match e {
                async_mpsc::error::TrySendError::Full(_) => failure("backpressure"),
                async_mpsc::error::TrySendError::Closed(_) => failure("transport"),
            })?;
        receive
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| {
                // Cancel an expired job while still queued, releasing its body immediately.
                // An active request already owns it and the absolute timeout releases it.
                job.lock().unwrap().take();
                match e {
                    mpsc::RecvTimeoutError::Timeout => failure("deadline"),
                    mpsc::RecvTimeoutError::Disconnected => failure("transport"),
                }
            })?
    }
}
impl Drop for Executor {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        let finished = self
            .completed
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_millis(100))
            .is_ok();
        if let Some(worker) = self.worker.lock().unwrap().take() {
            // Worker holds no Executor Arc; only external owners can reach this drop.
            if finished {
                let _ = worker.join();
            }
        }
    }
}

#[derive(Default)]
struct Pool(VecDeque<(PathBuf, TransportIdentity, ObjectId, usize, reqwest::Client)>);
impl Pool {
    fn client(&mut self, job: &Job, ca: &[u8], token: &str) -> Result<reqwest::Client> {
        let path = &job.authorization.binding.transport_profile;
        let identity = &job.authorization.binding.transport_identity;
        let stamp = ObjectId::for_bytes(token.as_bytes())?;
        let dns = job.dns_lookup as usize;
        // Changing trust/profile/token discards old compatible state, including idle sockets.
        self.0.retain(|(p, id, s, lookup, _)| {
            p != path || (id == identity && *s == stamp && *lookup == dns)
        });
        if let Some(index) = self.0.iter().position(|(p, id, s, lookup, _)| {
            p == path && id == identity && *s == stamp && *lookup == dns
        }) {
            let entry = self.0.remove(index).unwrap();
            let client = entry.4.clone();
            self.0.push_back(entry);
            return Ok(client);
        }
        let cert = reqwest::Certificate::from_pem(ca).map_err(|_| Failure {
            code: "invalid_source",
            retryable: false,
        })?;
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(BoundedResolver {
                lookup: job.dns_lookup,
            }))
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .tls_certs_only([cert])
            .connect_timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .map_err(network_error)?;
        job.counters.lock().unwrap().client_setups += 1;
        if self.0.len() == CLIENTS {
            self.0.pop_front();
        }
        self.0
            .push_back((path.clone(), identity.clone(), stamp, dns, client.clone()));
        Ok(client)
    }
}
fn network_error(error: reqwest::Error) -> Failure {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(current) = cause {
        if current.is::<DnsAdmission>() {
            return failure("backpressure");
        }
        cause = current.source();
    }
    failure(if error.is_timeout() {
        "deadline"
    } else {
        "transport"
    })
}
async fn run(job: Job, pool: Arc<Mutex<Pool>>) -> Result<Vec<u8>> {
    if Instant::now() >= job.deadline {
        return Err(failure("deadline"));
    }
    let credentials = job.authorization.credentials();
    let (profile, ca, token) = match credentials {
        Ok(credentials) => credentials,
        Err(error) => {
            pool.lock()
                .unwrap()
                .0
                .retain(|(path, _, _, _, _)| *path != job.authorization.binding.transport_profile);
            return Err(error.into());
        }
    };
    let client = pool.lock().unwrap().client(&job, &ca, &token)?;
    let method = reqwest::Method::from_bytes(job.method.as_bytes()).map_err(|_| Failure {
        code: "invalid_descriptor",
        retryable: false,
    })?;
    // Private-file validation and client construction are synchronous. The outer
    // Tokio timeout polls this future first, so recheck before any late dispatch.
    if Instant::now() >= job.deadline {
        return Err(failure("deadline"));
    }
    {
        let mut counters = job.counters.lock().unwrap();
        counters.requests += 1;
        if job.object_body && method == reqwest::Method::PUT {
            counters.uploaded_body_bytes += job.body.len() as u64;
        }
    }
    let download = job.object_body && method == reqwest::Method::GET;
    let url = format!(
        "{}/v1/n/{}{}",
        profile.endpoint,
        profile.namespace.as_str(),
        job.path
    );
    let mut response = client
        .request(method, url)
        .bearer_auth(token)
        .header("content-type", "application/json")
        .timeout(job.deadline.saturating_duration_since(Instant::now()))
        .body(job.body)
        .send()
        .await
        .map_err(network_error)?;
    let status = response.status();
    let max = if status.is_success() {
        job.limit
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
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if download {
            job.counters.lock().unwrap().downloaded_body_bytes += chunk.len() as u64;
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
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let code = match value["code"].as_str() {
            Some("stale_head") => "stale_head",
            Some("dependency_changed") => "dependency_changed",
            Some("recompute_required") => "recompute_required",
            Some("invalid_credential") => "invalid_credential",
            Some("backpressure") => "backpressure",
            Some("unsupported_operation") => "unsupported_operation",
            Some("expired_upload") => "expired_upload",
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
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[test]
    fn idle_executor_stop_wakes_worker_and_releases_live_admission() {
        let executor = Executor::for_replica(&ReplicaId::random().unwrap()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        executor.stop.send(true).unwrap();
        executor
            .completed
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_millis(250))
            .unwrap();
        assert!(start.elapsed() < Duration::from_millis(250));
    }
    #[test]
    fn live_executor_limit_returns_backpressure_without_evicting_owner() {
        if std::env::var_os("MAGUS_TEST_EXECUTOR_LIMIT_CHILD").is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","sync::transport::executor::lifecycle_tests::live_executor_limit_returns_backpressure_without_evicting_owner"])
                .env("MAGUS_TEST_EXECUTOR_LIMIT_CHILD","1").output().unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let id = ReplicaId::random().unwrap();
        let owner = Executor::for_replica(&id).unwrap();
        let mut owners = vec![];
        loop {
            match Executor::for_replica(&ReplicaId::random().unwrap()) {
                Ok(executor) => {
                    owners.push(executor);
                    assert!(owners.len() < 17);
                }
                Err(error) => {
                    assert_eq!(error.code(), "backpressure");
                    break;
                }
            }
        }
        assert!(Arc::ptr_eq(&owner, &Executor::for_replica(&id).unwrap()));
    }
    #[test]
    fn last_owner_shutdown_cancels_active_and_queued_jobs_without_arc_cycle() {
        let fixture = super::super::pool_tests::Fixture::new();
        let transport = &fixture.transport;
        let executor = Executor::for_replica(&ReplicaId::random().unwrap()).unwrap();
        let weak = Arc::downgrade(&executor);
        let mut replies = Vec::new();
        for _ in 0..8 {
            let job = Job {
                authorization: Authorization {
                    binding: transport.binding.clone(),
                    roots: transport.roots.clone(),
                    principals: transport.principals.clone(),
                    replica: transport.replica.clone(),
                },
                method: "GET".into(),
                path: "/stall".into(),
                body: vec![],
                limit: 64,
                deadline: Instant::now() + Duration::from_secs(3),
                object_body: false,
                dns_lookup: transport.dns_lookup,
                counters: transport.counters.clone(),
            };
            let (reply, receive) = mpsc::channel();
            assert!(executor
                .sender
                .try_send(Pending {
                    job: Arc::new(Mutex::new(Some(OwnedJob {
                        job,
                        _body: BodyPermit {
                            used: executor.body_bytes.clone(),
                            bytes: 0
                        }
                    }))),
                    reply
                })
                .is_ok());
            replies.push(receive);
        }
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        drop(executor);
        assert!(start.elapsed() < Duration::from_millis(250));
        assert!(
            weak.upgrade().is_none(),
            "worker/job must not retain executor ownership"
        );
        for receive in replies {
            assert!(
                matches!(
                    receive.recv_timeout(Duration::from_millis(250)),
                    Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected)
                ),
                "shutdown must return bounded failure"
            );
        }
    }
}
