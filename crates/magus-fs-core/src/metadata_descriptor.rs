//! Reuse deterministic decoding only after a fresh, complete journal read.
use crate::{engine::Core, metadata_profile as profile, *};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use std::{mem::size_of, sync::Arc};
const BUDGET: usize = 16 * 1024 * 1024;
struct CachedDescriptor {
    expected: RevisionId,
    digest: [u8; 32],
    raw: Vec<u8>,
    revision: Arc<Revision>,
    charged: usize,
}
pub(crate) struct DescriptorCache {
    slots: [Option<CachedDescriptor>; 2],
    mru: usize,
}
impl DescriptorCache {
    pub(crate) fn new() -> Self {
        Self {
            slots: [None, None],
            mru: 0,
        }
    }
    fn remove(&mut self, expected: &RevisionId) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|s| &s.expected == expected) {
                *slot = None;
            }
        }
    }
    fn retained(&self) -> usize {
        size_of::<Self>()
            + self
                .slots
                .iter()
                .flatten()
                .map(|s| s.charged)
                .sum::<usize>()
    }
    fn insert(
        &mut self,
        expected: RevisionId,
        digest: [u8; 32],
        raw: Vec<u8>,
        revision: Arc<Revision>,
    ) {
        let Some(charged) = retained_bytes(&expected, &raw, &revision) else {
            return;
        };
        if size_of::<Self>()
            .checked_add(charged)
            .is_none_or(|n| n > BUDGET)
        {
            return;
        }
        while self
            .retained()
            .checked_add(charged)
            .is_none_or(|n| n > BUDGET)
            || self.slots.iter().all(Option::is_some)
        {
            let lru = if self.slots[1 - self.mru].is_some() {
                1 - self.mru
            } else {
                self.mru
            };
            self.slots[lru] = None;
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .expect("bounded eviction leaves room");
        self.slots[index] = Some(CachedDescriptor {
            expected,
            digest,
            raw,
            revision,
            charged,
        });
        self.mru = index;
    }
}
fn allocation<T>(capacity: usize) -> Option<usize> {
    capacity.checked_mul(size_of::<T>())
}
// Fixed slot records are included once in size_of::<DescriptorCache>().
fn retained_bytes(expected: &RevisionId, raw: &Vec<u8>, r: &Revision) -> Option<usize> {
    if r.restoration.is_some() {
        return None;
    }
    let mut total = size_of::<Revision>().checked_add(2 * size_of::<usize>())?;
    macro_rules! add {
        ($value:expr) => {
            total = total.checked_add($value)?
        };
    }
    add!(expected.heap_capacity());
    add!(raw.capacity());
    for value in [&r.format, &r.hash, &r.layout, &r.provenance] {
        add!(value.capacity());
    }
    add!(allocation::<RevisionId>(r.parents.capacity())?);
    for id in &r.parents {
        add!(id.heap_capacity());
    }
    add!(r.operation.heap_capacity());
    add!(r.replica.heap_capacity());
    add!(r.principal.heap_capacity());
    add!(allocation::<String>(r.coverage.capacity())?);
    for path in &r.coverage {
        add!(path.capacity());
    }
    add!(r.tree.root.id.heap_capacity());
    add!(r.tree.root.owner.heap_capacity());
    add!(r.tree.root.group.heap_capacity());
    add!(allocation::<Entry>(r.tree.entries.capacity())?);
    for e in &r.tree.entries {
        add!(e.path.capacity());
        add!(e.id.heap_capacity());
        add!(e.parent.heap_capacity());
        add!(e.owner.heap_capacity());
        add!(e.group.heap_capacity());
        if let EntryContent::File { version } = &e.content {
            add!(allocation::<Extent>(version.extents.capacity())?);
            for extent in &version.extents {
                if let Extent::Chunk { object, .. } = extent {
                    add!(object.heap_capacity());
                }
            }
        }
    }
    Some(total)
}
pub(crate) fn load(core: &Core, expected: &RevisionId) -> Result<Arc<Revision>, FsError> {
    let result = load_verified(core, expected);
    if result.is_err() {
        core.metadata_descriptors.borrow_mut().remove(expected);
    }
    result
}
fn load_verified(core: &Core, expected: &RevisionId) -> Result<Arc<Revision>, FsError> {
    let _span = profile::Span::begin("revision_load");
    core.journal.guard()?;
    profile::count("revision_load", 1);
    let raw = {
        let _span = profile::Span::begin("descriptor_select");
        core.journal
            .db
            .query_row(
                "SELECT descriptor FROM revisions WHERE id=?",
                [expected.as_str()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(FsError::NotFound)?
    };
    if raw.len() > MAX_DESCRIPTOR {
        return Err(FsError::LimitExceeded);
    }
    profile::count("raw_bytes", raw.len() as u64);
    let digest: [u8; 32] = {
        let _span = profile::Span::begin("raw_sha");
        Sha256::digest(&raw).into()
    };
    {
        let _span = profile::Span::begin("byte_compare");
        let mut cache = core.metadata_descriptors.borrow_mut();
        for index in 0..2 {
            if let Some(s) = &cache.slots[index] {
                if &s.expected == expected
                    && s.digest == digest
                    && s.raw.len() == raw.len()
                    && s.raw == raw
                {
                    let revision = Arc::clone(&s.revision);
                    cache.mru = index;
                    profile::count("descriptor_hit", 1);
                    return Ok(revision);
                }
            }
        }
        cache.remove(expected);
    }
    profile::count("descriptor_miss", 1);
    let revision = decode_revision(&raw)?;
    if revision_id(&revision)? != *expected {
        return Err(FsError::CorruptObject);
    }
    let revision = Arc::new(revision);
    core.metadata_descriptors.borrow_mut().insert(
        expected.clone(),
        digest,
        raw,
        Arc::clone(&revision),
    );
    Ok(revision)
}
#[cfg(test)]
#[path = "metadata_descriptor_tests.rs"]
mod tests;
