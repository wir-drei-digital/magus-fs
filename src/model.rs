use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub directory: bool,
    pub chunks: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub digest: String,
    pub chunk_size: usize,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// SHA-256 over compact JSON [domain, chunk_size, entries]. Entry field and
    /// descriptor ordering are fixed by this struct; digest itself is excluded.
    pub fn canonical_digest(&self) -> String {
        crate::source::hash(
            &serde_json::to_vec(&("magus-fs-manifest-v1", self.chunk_size, &self.entries))
                .expect("manifest fields are serializable"),
        )
    }
}
