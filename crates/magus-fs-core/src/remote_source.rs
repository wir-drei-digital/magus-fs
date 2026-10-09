//! Trusted callback boundary. Implementations must not re-enter a Replica.
use crate::{protocol::RemoteSourceId, *};
use std::{cell::Cell, sync::Arc, time::Instant};
thread_local! { static FETCHING: Cell<bool> = const { Cell::new(false) }; }
pub(crate) fn fetching() -> bool {
    FETCHING.with(Cell::get)
}
pub trait RemoteFetcher: Send + Sync {
    /// Deadline covers all transport work. Credentials and endpoints are outside content.
    fn fetch(
        &self,
        source: &RemoteSourceId,
        object: &ObjectId,
        size: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, FsError>;
}
pub(crate) fn fetch(
    fetcher: &dyn RemoteFetcher,
    source: &RemoteSourceId,
    object: &ObjectId,
    size: u64,
    deadline: Instant,
) -> Result<Vec<u8>, FsError> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FETCHING.with(|f| f.set(false));
        }
    }
    if FETCHING.with(|f| f.replace(true)) {
        return Err(FsError::ReplicaBusy);
    }
    let _reset = Reset;
    let bytes = fetcher.fetch(source, object, size, deadline)?;
    if Instant::now() >= deadline {
        return Err(crate::cache::unavailable(object, SourceFailure::Deadline));
    }
    if bytes.len() as u64 != size || ObjectId::for_bytes(&bytes)? != *object {
        return Err(FsError::CorruptObject);
    }
    Ok(bytes)
}
impl Replica {
    pub fn set_remote_fetcher(&self, fetcher: Arc<dyn RemoteFetcher>) -> Result<(), FsError> {
        crate::engine::lock(&self.core)?.remote_fetcher = Some(fetcher);
        Ok(())
    }
}
