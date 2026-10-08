use crate::{Entry, Manifest, Result};
use axum::{
    extract::{Path as HttpPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    collections::{HashMap, HashSet},
    net::TcpListener,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub struct Fixture {
    pub(crate) manifest: Manifest,
    pub(crate) chunks: HashMap<String, Vec<u8>>,
}
impl Fixture {
    pub fn create(root: &Path, chunk_size: usize, mode: Option<u32>) -> Result<Self> {
        if ![65536, 262144, 1048576].contains(&chunk_size) {
            return Err("unsupported chunk size".into());
        }
        std::fs::create_dir(root)?;
        let result = (|| -> Result<Self> {
            std::fs::create_dir(root.join("nested"))?;
            let files = [
                (
                    "instructions.md",
                    b"# Synthetic workspace\nUse relative paths.\n".to_vec(),
                    0o644,
                ),
                (
                    "nested/table.csv",
                    b"id,value\n1,synthetic\n".to_vec(),
                    0o644,
                ),
                (
                    "run.sh",
                    b"#!/bin/sh\nprintf 'synthetic\\n'\n".to_vec(),
                    0o755,
                ),
                ("empty", vec![], 0o644),
                (
                    "data.bin",
                    (0..67108864u64)
                        .map(|i| ((i * 31 + i / 4096) % 251) as u8)
                        .collect(),
                    0o644,
                ),
            ];
            let mut entries = Vec::new();
            let mut chunks = HashMap::new();
            for (path, bytes, default_mode) in files {
                let p = root.join(path);
                std::fs::write(&p, &bytes)?;
                std::fs::set_permissions(
                    &p,
                    std::fs::Permissions::from_mode(mode.unwrap_or(default_mode)),
                )?;
                let m = p.metadata()?;
                let hashes = bytes
                    .chunks(chunk_size)
                    .map(|b| {
                        let h = hash(b);
                        chunks.entry(h.clone()).or_insert_with(|| b.to_vec());
                        h
                    })
                    .collect();
                entries.push(Entry {
                    path: path.into(),
                    size: m.len(),
                    mode: m.mode() & 0o7777,
                    uid: m.uid(),
                    gid: m.gid(),
                    directory: false,
                    chunks: hashes,
                });
            }
            let m = root.join("nested").metadata()?;
            entries.push(Entry {
                path: "nested".into(),
                size: 0,
                mode: m.mode() & 0o7777,
                uid: m.uid(),
                gid: m.gid(),
                directory: true,
                chunks: vec![],
            });
            Ok(Self {
                manifest: Manifest {
                    chunk_size,
                    entries,
                },
                chunks,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(root);
        }
        result
    }
}
#[derive(Default, serde::Serialize)]
struct Stats {
    metadata_bytes: u64,
    content_body_bytes: u64,
    unique_chunks: usize,
    #[serde(skip)]
    seen: HashSet<String>,
    retry_requests: u64,
}
struct HttpState {
    fixture: Fixture,
    stats: Mutex<Stats>,
    corruption: Arc<AtomicBool>,
}
async fn manifest(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    let body = serde_json::to_vec(&state.fixture.manifest).expect("serializable manifest");
    state.stats.lock().unwrap().metadata_bytes += body.len() as u64;
    body
}
async fn stats(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    serde_json::to_vec(&*state.stats.lock().unwrap()).expect("serializable stats")
}
async fn chunk(
    State(state): State<Arc<HttpState>>,
    HttpPath(id): HttpPath<String>,
) -> impl IntoResponse {
    let Some(body) = state.fixture.chunks.get(&id) else {
        return (StatusCode::NOT_FOUND, vec![]);
    };
    let mut body = body.clone();
    if state.corruption.load(Ordering::SeqCst) && !body.is_empty() {
        body[0] ^= 1
    }
    let mut stats = state.stats.lock().unwrap();
    if stats.seen.insert(id) {
        stats.unique_chunks += 1
    } else {
        stats.retry_requests += 1
    }
    stats.content_body_bytes += body.len() as u64;
    (StatusCode::OK, body)
}
pub struct Server {
    address: String,
    corruption: Arc<AtomicBool>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub fn spawn(fixture: Fixture, listen: &str) -> Result<Self> {
        let listener = TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?.to_string();
        let corruption = Arc::new(AtomicBool::new(false));
        let state = Arc::new(HttpState {
            fixture,
            stats: Mutex::new(Stats::default()),
            corruption: corruption.clone(),
        });
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (stop, done) = tokio::sync::oneshot::channel();
        let worker = thread::spawn(move || {
            runtime.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(listener).expect("validated listener");
                let app = Router::new()
                    .route("/manifest", get(manifest))
                    .route("/stats", get(stats))
                    .route("/chunks/{id}", get(chunk))
                    .with_state(state);
                let serving = axum::serve(listener, app).with_graceful_shutdown(async {
                    let _ = done.await;
                });
                if let Err(e) = serving.await {
                    eprintln!("fixture HTTP server failed: {e}")
                }
            })
        });
        Ok(Self {
            address,
            corruption,
            stop: Some(stop),
            worker: Some(worker),
        })
    }
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }
    pub fn corrupt(&self, enabled: bool) {
        self.corruption.store(enabled, Ordering::SeqCst)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
