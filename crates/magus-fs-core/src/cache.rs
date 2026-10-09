use crate::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkSource {
    Unavailable,
    Local { path: PathBuf },
    Http { base_url: String },
}
#[derive(Clone, Debug)]
pub struct PruneReport {
    pub evictable: Vec<ObjectId>,
    pub reclaimable_bytes: u64,
}
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::Instant,
};
pub(crate) fn unavailable(object: &ObjectId, cause: SourceFailure) -> FsError {
    FsError::BaseUnavailable {
        object: object.clone(),
        cause,
    }
}
impl ChunkSource {
    pub(crate) fn validate(&self) -> Result<(), FsError> {
        if let Self::Http { base_url } = self {
            let authority = base_url
                .strip_prefix("http://")
                .ok_or(FsError::InvalidSource)?
                .split('/')
                .next()
                .ok_or(FsError::InvalidSource)?;
            if base_url.contains(['?', '#', '@'])
                || authority.parse::<std::net::SocketAddr>().is_err()
            {
                return Err(FsError::InvalidSource);
            }
        }
        Ok(())
    }

    pub(crate) fn fetch(
        &self,
        id: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError> {
        self.validate()?;
        if size > MAX_CHUNK {
            return Err(FsError::LimitExceeded);
        }
        let bytes = match self {
            Self::Unavailable => return Err(unavailable(id, SourceFailure::Missing)),
            Self::Local { path } => {
                let store = ObjectStore::open_existing(path, ObjectLimits::default()).map_err(
                    |e| match e {
                        FsError::Io(e) => unavailable(id, SourceFailure::Io(e)),
                        other => other,
                    },
                )?;
                store.read_verified(id).map_err(|e| match e {
                    FsError::Io(e) => unavailable(id, SourceFailure::Io(e)),
                    other => other,
                })?
            }
            Self::Http { base_url } => {
                if !base_url.starts_with("http://") || base_url.contains(['?', '#', '@']) {
                    return Err(FsError::InvalidSource);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(unavailable(id, SourceFailure::Deadline));
                }
                let agent = ureq::AgentBuilder::new()
                    .resolver(|addr: &str| {
                        addr.parse::<std::net::SocketAddr>()
                            .map(|address| vec![address])
                            .map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "numeric source address required",
                                )
                            })
                    })
                    .redirects(0)
                    .timeout(remaining)
                    .build();
                let response = agent
                    .get(&format!(
                        "{}/{}",
                        base_url.trim_end_matches('/'),
                        id.as_str()
                    ))
                    .call()
                    .map_err(|e| match e {
                        ureq::Error::Status(status, _) => {
                            unavailable(id, SourceFailure::Http(status))
                        }
                        ureq::Error::Transport(e) => unavailable(
                            id,
                            SourceFailure::Transport {
                                kind: format!("{:?}", e.kind()),
                            },
                        ),
                    })?;
                let mut bytes = Vec::new();
                response
                    .into_reader()
                    .take(size + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| unavailable(id, SourceFailure::Io(e)))?;
                if Instant::now() >= deadline {
                    return Err(unavailable(id, SourceFailure::Deadline));
                }
                bytes
            }
        };
        if bytes.len() as u64 != size || ObjectId::for_bytes(&bytes)? != *id {
            return Err(FsError::CorruptObject);
        }
        Ok(bytes)
    }
    pub(crate) fn refetchable(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}
pub(crate) fn closure(tree: &Tree) -> BTreeMap<ObjectId, u64> {
    let mut objects = BTreeMap::new();
    for e in &tree.entries {
        entry_objects(e, &mut objects)
    }
    objects
}
pub(crate) fn entry_objects(entry: &Entry, objects: &mut BTreeMap<ObjectId, u64>) {
    if let EntryContent::File { version } = &entry.content {
        for ex in &version.extents {
            if let Extent::Chunk {
                object,
                object_size,
                ..
            } = ex
            {
                objects.insert(object.clone(), *object_size);
            }
        }
    }
}
pub(crate) fn object_set(tree: &Tree) -> BTreeSet<ObjectId> {
    closure(tree).into_keys().collect()
}
