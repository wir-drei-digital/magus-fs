//! Metadata authority lives for one continuously locked public operation only.
use crate::{engine::Core, permissions as perm, *};
use rusqlite::OptionalExtension;
use std::{borrow::Cow, cell::OnceCell, sync::Arc};
pub(crate) struct MetadataContext<'a> {
    core: &'a Core,
    actor: &'a Authority,
    view: Option<&'a Revision>,
    pub(crate) tree: &'a Tree,
    authority: Option<Arc<Revision>>,
    authority_revision: Option<RevisionId>,
    base: OnceCell<Arc<Revision>>,
    // The Core borrow keeps this observed generation and descriptor indivisible.
    _authority_generation: u64,
}
fn identity<'a>(tree: &'a Tree, id: &EntryId) -> Option<Cow<'a, Entry>> {
    if *id == tree.root.id {
        Some(Cow::Owned(perm::root_entry(tree)))
    } else {
        tree.entries.iter().find(|e| e.id == *id).map(Cow::Borrowed)
    }
}
impl<'a> MetadataContext<'a> {
    pub(crate) fn new(
        core: &'a Core,
        actor: &'a Authority,
        view: Option<&'a Revision>,
    ) -> Result<Self, FsError> {
        let _span = crate::metadata_profile::Span::begin("metadata_context");
        let current = if view.is_none() {
            let remote = core
                .journal
                .db
                .query_row(
                    "SELECT revision FROM live_authority WHERE singleton=1",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?;
            if remote == Some(None) {
                return Err(FsError::PermissionDenied);
            }
            remote
                .flatten()
                .map(|id| {
                    crate::metadata_profile::count("authority_load", 1);
                    let id = RevisionId::parse(id)?;
                    let revision = crate::metadata_descriptor::load(core, &id)?;
                    Ok::<_, FsError>((id, revision))
                })
                .transpose()?
        } else {
            None
        };
        let (authority_revision, authority) = match current {
            Some((id, revision)) => (Some(id), Some(revision)),
            None => (None, None),
        };
        let generation = core.journal.db.query_row(
            "SELECT COALESCE(max(generation),0) FROM live_authority_history",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64;
        let tree = match view {
            Some(r) => &r.tree,
            None => &core.working()?.tree,
        };
        Ok(Self {
            core,
            actor,
            view,
            tree,
            authority,
            authority_revision,
            base: OnceCell::new(),
            _authority_generation: generation,
        })
    }
    fn base(&self) -> Result<&Revision, FsError> {
        if self.authority_revision.as_ref() == Some(&self.core.working()?.base) {
            return Ok(self
                .authority
                .as_ref()
                .expect("verified authority revision is present"));
        }
        if self.base.get().is_none() {
            let r = crate::metadata_descriptor::load(self.core, &self.core.working()?.base)?;
            let _ = self.base.set(r);
        }
        Ok(self
            .base
            .get()
            .expect("base initialized while Core remains locked"))
    }
    pub(crate) fn access(&self, entry: &Entry, bits: u16) -> Result<(), FsError> {
        if let Some(authority) = &self.authority {
            if let Some(current) = identity(&authority.tree, &entry.id) {
                perm::traversal(&authority.tree, &current.path, self.actor)?;
                perm::access(self.actor, &current, bits)?;
            } else {
                if self.core.remote_entries.contains(&entry.id)
                    || self.base()?.tree.entries.iter().any(|e| e.id == entry.id)
                {
                    #[cfg(feature = "test-faults")]
                    if std::env::var_os("MAGUS_TEST_AUTHORITY_BARRIER").is_some() {
                        let working = self.core.working()?;
                        eprintln!("test_authority_absent entry={} authority={:?} authority_generation={} working_head={} working_generation={} working_epoch={} bits={}", entry.id.as_str(), self.authority_revision, self._authority_generation, working.head.as_str(), working.generation, working.epoch, bits);
                    }
                    return Err(FsError::PermissionDenied);
                }
                // Every local ancestor still reaches the nearest freshly verified remote parent.
                let parent = identity(&self.core.working()?.tree, &entry.parent)
                    .ok_or(FsError::PermissionDenied)?;
                self.access(&parent, 1)?;
            }
        }
        if self.view.is_some() {
            if let Some(working) = &self.core.working {
                let current =
                    identity(&working.tree, &entry.id).ok_or(FsError::PermissionDenied)?;
                perm::traversal(&working.tree, &current.path, self.actor)?;
                return perm::access(self.actor, &current, bits);
            }
        }
        perm::access(self.actor, entry, bits)
    }
    pub(crate) fn resolve(&self, path: &str) -> Result<Entry, FsError> {
        if !path.is_empty() {
            crate::paths::validate_path(path)?;
        }
        if self.view.is_none() || self.core.working.is_none() {
            perm::traversal(self.tree, path, self.actor)?;
        }
        let entry = perm::entry(self.tree, path)?;
        self.access(&entry, 0)?;
        Ok(entry)
    }
    pub(crate) fn attributes(&self, entry: &Entry) -> Result<Entry, FsError> {
        let mut projected = entry.clone();
        if self.view.is_none() {
            self.access(entry, 0)?;
            let tree = self
                .authority
                .as_ref()
                .map(|r| &r.tree)
                .unwrap_or(&self.core.working()?.tree);
            if let Some(current) = identity(tree, &entry.id) {
                projected.owner = current.owner.clone();
                projected.group = current.group.clone();
                projected.mode = current.mode;
            }
        }
        if let (Some(view), Some(working)) = (self.view, &self.core.working) {
            let historical = perm::entry(&view.tree, &entry.path)?;
            if historical.id != entry.id {
                return Err(FsError::StaleHandle);
            }
            self.access(&historical, 0)?;
            let current = identity(&working.tree, &entry.id).ok_or(FsError::PermissionDenied)?;
            projected = historical;
            projected.owner = current.owner.clone();
            projected.group = current.group.clone();
            projected.mode = current.mode;
        }
        Ok(projected)
    }
}
