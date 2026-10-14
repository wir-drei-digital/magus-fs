//! FUSE RELEASE, unlike FLUSH/close, ends the open file description and mmap lifetime.
use magus_fs_core::{CapabilitySnapshot, EntryId, FsError};
use std::collections::BTreeMap;
pub(crate) struct CapabilityTracker {
    generation: u64,
    complete: bool,
    handles: BTreeMap<u64, EntryId>,
}
impl CapabilityTracker {
    pub(crate) fn new(complete: bool) -> Self {
        Self {
            generation: 0,
            complete,
            handles: BTreeMap::new(),
        }
    }
    pub(crate) fn pin(&mut self, handle: u64, entry: EntryId) -> Result<(), FsError> {
        if self.handles.contains_key(&handle) {
            return Err(FsError::OperationMismatch);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        self.handles.insert(handle, entry);
        Ok(())
    }
    pub(crate) fn release(&mut self, handle: u64) -> Result<(), FsError> {
        if !self.handles.contains_key(&handle) {
            return Err(FsError::StaleHandle);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(FsError::LimitExceeded)?;
        self.handles.remove(&handle);
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> CapabilitySnapshot {
        CapabilitySnapshot {
            generation: self.generation,
            complete: self.complete,
            pinned: self.handles.values().cloned().collect(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mmap_close_and_cached_lookup_capabilities() {
        let mut tracker = CapabilityTracker::new(false);
        let cached_lookup = EntryId::random().unwrap();
        assert!(!tracker.snapshot().pinned.contains(&cached_lookup));
        assert!(!tracker.snapshot().complete);
        tracker.pin(1, cached_lookup.clone()).unwrap();
        let pinned = tracker.snapshot();
        // FLUSH/descriptor close does not invoke release: the kernel retains the file
        // description for mappings. Actual FD-close/mmap semantics require the live gate.
        assert!(tracker.snapshot().pinned.contains(&cached_lookup));
        tracker.release(1).unwrap();
        assert!(tracker.snapshot().pinned.is_empty());
        assert!(tracker.snapshot().generation > pinned.generation);
    }
}
