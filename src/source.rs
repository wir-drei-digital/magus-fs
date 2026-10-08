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
            let mut data: Vec<u8> = (0..67108864u64)
                .map(|i| ((i * 31 + i / 4096) % 251) as u8)
                .collect();
            // Every supported chunk begins with a distinct little-endian block
            // number. This also preserves uniqueness independent of chunk size.
            for (index, block) in data.chunks_mut(65536).enumerate() {
                block[..8].copy_from_slice(&(index as u64).to_le_bytes());
            }
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
                ("data.bin", data, 0o644),
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
            let mut manifest = Manifest {
                digest: String::new(),
                chunk_size,
                entries,
            };
            manifest.digest = manifest.canonical_digest();
            Ok(Self { manifest, chunks })
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

#[cfg(test)]
mod manifest_tests {
    use super::*;
    #[test]
    fn connection_rejects_metadata_and_descriptor_tampering() {
        let root = std::env::temp_dir().join(format!("fs0-digest-{}", std::process::id()));
        let fixture = Fixture::create(&root, 262144, None).unwrap();
        let original = fixture.manifest.clone();
        for mutation in 0..11 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.entries[0].mode ^= 0o100,
                1 => changed.entries[0].uid = changed.entries[0].uid.wrapping_add(1),
                2 => changed.entries[0].gid = changed.entries[0].gid.wrapping_add(1),
                3 => changed.entries[0].path = "renamed.md".into(),
                4 => changed.entries[0].size -= 1,
                5 => changed.entries.swap(0, 1),
                6 => changed.entries[0].chunks[0] = "0".repeat(64),
                7 => changed.digest = "0".repeat(64),
                8 => changed.chunk_size = 65536,
                9 => changed.entries[4].chunks.swap(0, 1),
                _ => changed.entries[0].directory = true,
            }
            let server = Server::spawn(
                Fixture {
                    manifest: changed,
                    chunks: HashMap::new(),
                },
                "127.0.0.1:0",
            )
            .unwrap();
            let rejection = crate::Probe::connect(&server.url(), false)
                .err()
                .map(|error| error.to_string());
            let rejected = rejection.as_deref() == Some("manifest digest mismatch");
            drop(server);
            if !rejected {
                std::fs::remove_dir_all(&root).unwrap();
                panic!("mutation {mutation} accepted")
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
