use crate::{source::hash, Manifest, Result};
use std::{collections::HashMap, io::Read, time::Duration};
pub struct Probe {
    manifest: Manifest,
    url: String,
    agent: ureq::Agent,
    cache: HashMap<String, Vec<u8>>,
    overlay: HashMap<String, Vec<u8>>,
    writable: bool,
    fetched: u64,
}
fn fetch(agent: &ureq::Agent, url: &str, limit: usize) -> Result<Vec<u8>> {
    let response = agent.get(url).call()?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("response exceeds bound".into());
    }
    Ok(bytes)
}
impl Probe {
    pub fn connect(url: &str, writable: bool) -> Result<Self> {
        if !url.starts_with("http://") {
            return Err("fixture requires HTTP".into());
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .timeout_connect(Duration::from_secs(2))
            .timeout_read(Duration::from_secs(2))
            .timeout_write(Duration::from_secs(2))
            .redirects(0)
            .build();
        let bytes = fetch(&agent, &format!("{url}/manifest"), 1048576)?;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        if ![65536, 262144, 1048576].contains(&manifest.chunk_size) {
            return Err("invalid chunk size".into());
        }
        let mut paths = std::collections::HashSet::new();
        for e in &manifest.entries {
            if e.size > 67108864 || !paths.insert(e.path.clone()) {
                return Err("invalid manifest bounds or duplicate paths".into());
            }
            if e.path.starts_with('/')
                || e.path.split('/').any(|p| p == ".." || p.is_empty())
                || e.chunks.len() as u64
                    != if e.directory {
                        0
                    } else {
                        e.size.div_ceil(manifest.chunk_size as u64)
                    }
                || e.chunks
                    .iter()
                    .any(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err("invalid manifest".into());
            }
        }
        Ok(Self {
            manifest,
            url: url.into(),
            agent,
            cache: HashMap::new(),
            overlay: HashMap::new(),
            writable,
            fetched: 0,
        })
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn read(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let end = offset.checked_add(len as u64).ok_or("range overflow")?;
        let e = self
            .manifest
            .entries
            .iter()
            .find(|e| e.path == path)
            .ok_or("not found")?
            .clone();
        if e.directory {
            return Err("is directory".into());
        }
        if let Some(b) = self.overlay.get(path) {
            let start = offset.min(b.len() as u64) as usize;
            return Ok(b[start..end.min(b.len() as u64) as usize].to_vec());
        }
        let end = end.min(e.size);
        if offset >= end {
            return Ok(vec![]);
        }
        let chunk = self.manifest.chunk_size;
        let mut result = Vec::new();
        for i in offset / chunk as u64..=(end - 1) / chunk as u64 {
            let id = &e.chunks[i as usize];
            if !self.cache.contains_key(id) {
                let b = fetch(&self.agent, &format!("{}/chunks/{id}", self.url), chunk)?;
                self.fetched += b.len() as u64;
                let expected = (e.size - i * chunk as u64).min(chunk as u64) as usize;
                if b.len() != expected || hash(&b) != *id {
                    return Err("chunk integrity failure".into());
                }
                self.cache.insert(id.clone(), b);
            }
            let b = &self.cache[id];
            let start = offset.saturating_sub(i * chunk as u64) as usize;
            let stop = (end - i * chunk as u64).min(b.len() as u64) as usize;
            result.extend_from_slice(&b[start..stop]);
        }
        Ok(result)
    }
    pub fn write(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err("read-only view".into());
        }
        let e = self
            .manifest
            .entries
            .iter()
            .find(|e| e.path == path)
            .ok_or("not found")?;
        if e.mode & 0o222 == 0 {
            return Err("permission denied".into());
        }
        let size = e.size;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or("range overflow")?;
        if end > 67108864 {
            return Err("ephemeral overlay bound exceeded".into());
        }
        if !self.overlay.contains_key(path) {
            let b = self.read(path, 0, size as usize)?;
            self.overlay.insert(path.into(), b);
        }
        let b = self.overlay.get_mut(path).unwrap();
        b.resize(b.len().max(end as usize), 0);
        b[offset as usize..end as usize].copy_from_slice(bytes);
        Ok(bytes.len())
    }
    pub fn flush(&self) -> Result<()> {
        Err("unsupported durability: ephemeral FS0 overlay".into())
    }
    pub fn fetched_bytes(&self) -> u64 {
        self.fetched
    }
    pub fn cached_chunks(&self) -> usize {
        self.cache.len()
    }
}
