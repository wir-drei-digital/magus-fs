//! Pure identity-based three-way tree reconciliation (FS2-B Task 2).
//!
//! Entries are matched by stable `EntryId`, never by path. Locations are compared as
//! (parent identity, leaf name), so an ancestor rename on one side composes with an edit or
//! rename of a descendant on the other side. A known common base is mandatory: callers with
//! unknown causal origin must not invent one (that is reported by the service, not here).
//! Text merging is opt-in per branch policy, bounded, and never turns marker text into
//! canonical content. A clean outcome means mechanically merged, not semantically correct.
use crate::*;
use caseless::Caseless;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

/// Per-version input bound for eligible text (each of base/left/right).
pub const MAX_TEXT_INPUT: u64 = 256 * 1024;
pub const MAX_TEXT_LINES: usize = 4096;
pub const MAX_TEXT_OUTPUT: usize = 1024 * 1024;
/// Per-candidate text merge budget: count and summed base+left+right input bytes.
pub const MAX_TEXT_MERGES: usize = 16;
pub const MAX_TEXT_TOTAL: u64 = 8 * 1024 * 1024;
pub const MAX_POLICY_EXTENSIONS: usize = 32;
/// CSV and office/binary document formats stay opaque: line compatibility does not prove
/// row/formula correctness. A future typed validator may opt CSV into a declared policy.
const ALWAYS_OPAQUE: &[&str] = &[
    "csv", "tsv", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "odt", "ods", "odp", "pdf",
    "rtf", "zip",
];

/// Branch merge policy. The default is fully opaque; an explicit normalized extension
/// allowlist enables UTF-8 text merging only for those files.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergePolicy {
    pub text_extensions: Vec<String>,
}
impl MergePolicy {
    pub fn opaque() -> Self {
        Self::default()
    }
    /// Normalizes (lowercase, sorted, unique) and validates an allowlist.
    pub fn text<I, S>(extensions: I) -> Result<Self, FsError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = BTreeSet::new();
        for extension in extensions {
            let extension: String = extension.into();
            let normalized = extension.trim_start_matches('.').to_ascii_lowercase();
            if normalized.is_empty()
                || normalized.len() > 16
                || !normalized.bytes().all(|b| b.is_ascii_alphanumeric())
                || ALWAYS_OPAQUE.contains(&normalized.as_str())
            {
                return Err(FsError::UnsupportedMode);
            }
            set.insert(normalized);
        }
        if set.len() > MAX_POLICY_EXTENSIONS {
            return Err(FsError::LimitExceeded);
        }
        Ok(Self {
            text_extensions: set.into_iter().collect(),
        })
    }
    /// A stored policy must already be in normalized form.
    pub fn validate(&self) -> Result<(), FsError> {
        if Self::text(self.text_extensions.clone())? != *self {
            return Err(FsError::InvalidDescriptor);
        }
        Ok(())
    }
    pub fn mode(&self, path: &str) -> MergeMode {
        let leaf = path.rsplit('/').next().unwrap_or(path);
        match leaf.rsplit_once('.') {
            Some((stem, extension))
                if !stem.is_empty()
                    && self
                        .text_extensions
                        .iter()
                        .any(|e| e.as_str() == extension.to_ascii_lowercase()) =>
            {
                MergeMode::Text
            }
            _ => MergeMode::Opaque,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeMode {
    Opaque,
    Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    /// Both sides changed opaque/binary/malformed content differently.
    Content,
    /// Eligible text with overlapping edits; marker output is discarded.
    TextOverlap,
    /// Text bounds, per-candidate budget or the worker deadline were exceeded.
    MergeBudget,
    EditDelete,
    /// Distinct new identities claim the same (case-folded) parent/name.
    AddAdd,
    /// An existing identity collides with another at a parent/name, or a parent stopped
    /// being a directory.
    PathCollision,
    /// Both sides moved/renamed the same identity differently, or moves form a cycle.
    CompetingRename,
    /// A directory was removed on one side while the other side placed entries in it.
    DirectoryDelete,
    /// Incompatible owner/group/mode changes. Never resolved by broadening access.
    Metadata,
    /// Candidate ancestry carries unknown native causality; never merged automatically.
    UnknownCausality,
    /// No retained common base is available; no ancestor is chosen silently.
    MissingBase,
}
impl ConflictReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::TextOverlap => "text_overlap",
            Self::MergeBudget => "merge_budget",
            Self::EditDelete => "edit_delete",
            Self::AddAdd => "add_add",
            Self::PathCollision => "path_collision",
            Self::CompetingRename => "competing_rename",
            Self::DirectoryDelete => "directory_delete",
            Self::Metadata => "metadata",
            Self::UnknownCausality => "unknown_causality",
            Self::MissingBase => "missing_base",
        }
    }
    pub fn parse(code: &str) -> Result<Self, FsError> {
        [
            Self::Content,
            Self::TextOverlap,
            Self::MergeBudget,
            Self::EditDelete,
            Self::AddAdd,
            Self::PathCollision,
            Self::CompetingRename,
            Self::DirectoryDelete,
            Self::Metadata,
            Self::UnknownCausality,
            Self::MissingBase,
        ]
        .into_iter()
        .find(|r| r.code() == code)
        .ok_or(FsError::InvalidDescriptor)
    }
}

/// Immutable alternatives for one identity. Never contains marker or generated content.
/// A root metadata conflict uses the root id with no entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryConflict {
    pub id: EntryId,
    pub base: Option<Entry>,
    pub left: Option<Entry>,
    pub right: Option<Entry>,
    pub reason: ConflictReason,
    pub policy: MergeMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    Clean {
        tree: Tree,
        mechanically_merged: Vec<EntryId>,
    },
    Conflicted {
        alternatives: Vec<EntryConflict>,
    },
}

/// Which input an explicit resolution prefers (base, left = current, right = candidate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Base,
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextMerge {
    Merged(Vec<u8>),
    Overlap,
    Unsupported,
    Budget,
}

/// Content access for reconciliation. `read` returns verified, bounded bytes of a version;
/// `generated` returns the canonical chunked version of merged text. Installation of the
/// generated objects belongs to the caller (the service), never to reconciliation.
pub trait MergeContent {
    fn read(&self, version: &FileVersion) -> Result<Vec<u8>, FsError>;
    fn generated(&self, text: &[u8]) -> Result<FileVersion, FsError>;
    /// Default in-process merge; the service substitutes results from a killable worker.
    fn merge_text(
        &self,
        base: &FileVersion,
        left: &FileVersion,
        right: &FileVersion,
    ) -> Result<TextMerge, FsError> {
        Ok(merge_text(
            &self.read(base)?,
            &self.read(left)?,
            &self.read(right)?,
        ))
    }
}

/// Bounded UTF-8 three-way text merge. `Err` marker text from diffy is discarded.
pub fn merge_text(base: &[u8], left: &[u8], right: &[u8]) -> TextMerge {
    let mut texts = vec![];
    for bytes in [base, left, right] {
        if bytes.len() as u64 > MAX_TEXT_INPUT {
            return TextMerge::Budget;
        }
        if bytes.contains(&0) {
            return TextMerge::Unsupported;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return TextMerge::Unsupported;
        };
        if text.lines().count() > MAX_TEXT_LINES {
            return TextMerge::Budget;
        }
        texts.push(text);
    }
    match diffy::merge(texts[0], texts[1], texts[2]) {
        Ok(merged) if merged.len() > MAX_TEXT_OUTPUT => TextMerge::Budget,
        Ok(merged) => TextMerge::Merged(merged.into_bytes()),
        Err(_markers) => TextMerge::Overlap,
    }
}

/// Chunk bodies of a generated version, keyed by object identity, for installation.
pub type GeneratedChunks = Vec<(ObjectId, Vec<u8>)>;
/// Canonical fixed262144 chunking of generated bytes, with the chunk bodies to install.
pub fn chunked_version(bytes: &[u8]) -> Result<(FileVersion, GeneratedChunks), FsError> {
    let mut extents = vec![];
    let mut chunks = vec![];
    for chunk in bytes.chunks(262144) {
        let object = ObjectId::for_bytes(chunk)?;
        extents.push(Extent::Chunk {
            object: object.clone(),
            object_size: chunk.len() as u64,
            offset: 0,
            length: chunk.len() as u64,
        });
        chunks.push((object, chunk.to_vec()));
    }
    Ok((
        FileVersion {
            size: bytes.len() as u64,
            extents,
        },
        chunks,
    ))
}

/// One budget-admitted text merge, in deterministic identity order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextInput {
    pub id: EntryId,
    pub base: FileVersion,
    pub left: FileVersion,
    pub right: FileVersion,
}

/// Exactly the text merges `reconcile_trees` will request, so a caller can prefetch and
/// verify their inputs (and run them in a bounded worker) before reconciliation.
pub fn text_merge_plan(
    base: &Tree,
    left: &Tree,
    right: &Tree,
    policy: &MergePolicy,
) -> Vec<TextInput> {
    plan(base, left, right, policy)
        .into_iter()
        .filter_map(|(id, admitted)| admitted.map(|input| (id, input)))
        .map(|(_, input)| input)
        .collect()
}

pub fn reconcile_trees(
    base: &Tree,
    left: &Tree,
    right: &Tree,
    policy: &MergePolicy,
    objects: &dyn MergeContent,
) -> Result<MergeOutcome, FsError> {
    let merged = Reconciler::new(base, left, right, policy, objects, None)?.run()?;
    Ok(if merged.conflicts.is_empty() {
        MergeOutcome::Clean {
            tree: merged.tree,
            mechanically_merged: merged.mechanically_merged,
        }
    } else {
        MergeOutcome::Conflicted {
            alternatives: merged.conflicts.into_values().collect(),
        }
    })
}

/// Explicit resolution: every conflict takes the preferred input's state. Structural
/// fallout (a missing parent, a cycle, a collision) is repaired toward the preferred side;
/// anything still invalid fails rather than guessing.
pub fn resolve_trees(
    base: &Tree,
    left: &Tree,
    right: &Tree,
    policy: &MergePolicy,
    objects: &dyn MergeContent,
    prefer: Side,
) -> Result<Tree, FsError> {
    let merged = Reconciler::new(base, left, right, policy, objects, Some(prefer))?.run()?;
    if !merged.conflicts.is_empty() {
        return Err(FsError::TargetCollision);
    }
    Ok(merged.tree)
}

/// Explicit resolution with per-identity choices; identities without a choice (and
/// structural repairs) take `default`.
pub fn resolve_trees_with(
    base: &Tree,
    left: &Tree,
    right: &Tree,
    policy: &MergePolicy,
    objects: &dyn MergeContent,
    default: Side,
    choices: &BTreeMap<EntryId, Side>,
) -> Result<Tree, FsError> {
    let merged = Reconciler::new(base, left, right, policy, objects, Some(default))?
        .with_choices(choices.clone())
        .run()?;
    if !merged.conflicts.is_empty() {
        return Err(FsError::TargetCollision);
    }
    Ok(merged.tree)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Loc {
    parent: EntryId,
    name: String,
}
fn loc(e: &Entry) -> Loc {
    Loc {
        parent: e.parent.clone(),
        name: e.path.rsplit('/').next().unwrap_or(&e.path).to_owned(),
    }
}
/// Equal except for a path change caused only by an ancestor move.
fn same(a: &Entry, b: &Entry) -> bool {
    loc(a) == loc(b)
        && a.owner == b.owner
        && a.group == b.group
        && a.mode == b.mode
        && a.content == b.content
}
fn merge3<T: PartialEq + Clone>(b: &T, l: &T, r: &T) -> Option<T> {
    if l == b {
        Some(r.clone())
    } else if r == b || l == r {
        Some(l.clone())
    } else {
        None
    }
}
fn pick<T: Clone>(prefer: Side, b: &T, l: &T, r: &T) -> T {
    match prefer {
        Side::Base => b.clone(),
        Side::Left => l.clone(),
        Side::Right => r.clone(),
    }
}
fn fold(name: &str) -> String {
    name.nfd().default_case_fold().nfc().collect()
}
fn index(tree: &Tree) -> BTreeMap<&EntryId, &Entry> {
    tree.entries.iter().map(|e| (&e.id, e)).collect()
}
fn file(e: &Entry) -> Option<&FileVersion> {
    match &e.content {
        EntryContent::File { version } => Some(version),
        EntryContent::Directory => None,
    }
}

/// Deterministic text budget over identities whose content diverged on both sides.
fn plan(
    base: &Tree,
    left: &Tree,
    right: &Tree,
    policy: &MergePolicy,
) -> BTreeMap<EntryId, Option<TextInput>> {
    let (bi, li, ri) = (index(base), index(left), index(right));
    let mut out = BTreeMap::new();
    let (mut count, mut total) = (0usize, 0u64);
    for (id, b) in &bi {
        let (Some(l), Some(r)) = (li.get(id), ri.get(id)) else {
            continue;
        };
        let (Some(bv), Some(lv), Some(rv)) = (file(b), file(l), file(r)) else {
            continue;
        };
        if lv == bv || rv == bv || lv == rv {
            continue;
        }
        if [&b.path, &l.path, &r.path]
            .iter()
            .any(|p| policy.mode(p) != MergeMode::Text)
        {
            continue;
        }
        let size = bv.size.saturating_add(lv.size).saturating_add(rv.size);
        let admitted = [bv, lv, rv].iter().all(|v| v.size <= MAX_TEXT_INPUT)
            && count < MAX_TEXT_MERGES
            && total.saturating_add(size) <= MAX_TEXT_TOTAL;
        if admitted {
            count += 1;
            total += size;
        }
        out.insert(
            (*id).clone(),
            admitted.then(|| TextInput {
                id: (*id).clone(),
                base: bv.clone(),
                left: lv.clone(),
                right: rv.clone(),
            }),
        );
    }
    out
}

struct Merged {
    tree: Tree,
    mechanically_merged: Vec<EntryId>,
    conflicts: BTreeMap<EntryId, EntryConflict>,
}
struct Reconciler<'a> {
    base: &'a Tree,
    left: &'a Tree,
    right: &'a Tree,
    // Identity indexes: alternatives and repairs never rescan whole trees.
    indexes: [BTreeMap<&'a EntryId, &'a Entry>; 3],
    policy: &'a MergePolicy,
    objects: &'a dyn MergeContent,
    prefer: Option<Side>,
    choices: BTreeMap<EntryId, Side>,
    conflicts: BTreeMap<EntryId, EntryConflict>,
}
impl<'a> Reconciler<'a> {
    fn new(
        base: &'a Tree,
        left: &'a Tree,
        right: &'a Tree,
        policy: &'a MergePolicy,
        objects: &'a dyn MergeContent,
        prefer: Option<Side>,
    ) -> Result<Self, FsError> {
        // A known common base of the same root identity is required.
        if left.root.id != base.root.id || right.root.id != base.root.id {
            return Err(FsError::InvalidTree);
        }
        for tree in [base, left, right] {
            validate_tree(tree)?;
        }
        policy.validate()?;
        Ok(Self {
            base,
            left,
            right,
            indexes: [index(base), index(left), index(right)],
            policy,
            objects,
            prefer,
            choices: BTreeMap::new(),
            conflicts: BTreeMap::new(),
        })
    }
    fn with_choices(mut self, choices: BTreeMap<EntryId, Side>) -> Self {
        self.choices = choices;
        self
    }
    /// The explicit side for an identity under resolution; `None` while reconciling.
    fn choose(&self, id: &EntryId) -> Option<Side> {
        self.prefer
            .map(|default| self.choices.get(id).copied().unwrap_or(default))
    }
    fn alternatives(&self, id: &EntryId) -> (Option<Entry>, Option<Entry>, Option<Entry>) {
        (
            self.side(Side::Base, id),
            self.side(Side::Left, id),
            self.side(Side::Right, id),
        )
    }
    fn conflict(&mut self, id: &EntryId, reason: ConflictReason) {
        if self.conflicts.contains_key(id) {
            return;
        }
        let (base, left, right) = self.alternatives(id);
        let path = [&base, &left, &right]
            .into_iter()
            .flatten()
            .map(|e| e.path.clone())
            .next();
        let policy = match reason {
            ConflictReason::TextOverlap | ConflictReason::MergeBudget => MergeMode::Text,
            _ => path
                .map(|p| self.policy.mode(&p))
                .unwrap_or(MergeMode::Opaque),
        };
        self.conflicts.insert(
            id.clone(),
            EntryConflict {
                id: id.clone(),
                base,
                left,
                right,
                reason,
                policy,
            },
        );
    }
    fn side(&self, side: Side, id: &EntryId) -> Option<Entry> {
        let index = match side {
            Side::Base => &self.indexes[0],
            Side::Left => &self.indexes[1],
            Side::Right => &self.indexes[2],
        };
        index.get(id).map(|e| (*e).clone())
    }
    fn run(mut self) -> Result<Merged, FsError> {
        let root = self.root();
        let plan = plan(self.base, self.left, self.right, self.policy);
        let [bi, li, ri] = self.indexes.clone();
        let ids: BTreeSet<EntryId> = bi
            .keys()
            .chain(li.keys())
            .chain(ri.keys())
            .map(|id| (*id).clone())
            .collect();
        let mut entries: BTreeMap<EntryId, Entry> = BTreeMap::new();
        let mut mechanically_merged = vec![];
        for id in &ids {
            let (b, l, r) = (
                bi.get(id).copied(),
                li.get(id).copied(),
                ri.get(id).copied(),
            );
            let chosen = match (b, l, r) {
                (None, None, None) => None,
                (None, Some(x), None) | (None, None, Some(x)) => Some(x.clone()),
                (None, Some(l), Some(r)) => {
                    if same(l, r) {
                        Some(l.clone())
                    } else if let Some(p) = self.choose(id) {
                        match p {
                            Side::Base => None,
                            Side::Left => Some(l.clone()),
                            Side::Right => Some(r.clone()),
                        }
                    } else {
                        self.conflict(id, ConflictReason::AddAdd);
                        None
                    }
                }
                (Some(_), None, None) => None,
                (Some(b), None, Some(x)) | (Some(b), Some(x), None) => {
                    if same(b, x) {
                        None
                    } else if let Some(p) = self.choose(id) {
                        let deleted_left = l.is_none();
                        match (p, deleted_left) {
                            (Side::Base, _) => Some(b.clone()),
                            (Side::Left, true) | (Side::Right, false) => None,
                            _ => Some(x.clone()),
                        }
                    } else {
                        self.conflict(id, ConflictReason::EditDelete);
                        None
                    }
                }
                (Some(b), Some(l), Some(r)) => {
                    let merged = self.entry(b, l, r, plan.get(id))?;
                    if let Some((entry, text)) = merged {
                        if text {
                            mechanically_merged.push(id.clone());
                        }
                        Some(entry)
                    } else {
                        None
                    }
                }
            };
            if let Some(entry) = chosen {
                entries.insert(id.clone(), entry);
            }
        }
        let tree = self.structure(root, entries)?;
        Ok(Merged {
            tree,
            mechanically_merged,
            conflicts: self.conflicts,
        })
    }
    fn root(&mut self) -> Root {
        let (b, l, r) = (&self.base.root, &self.left.root, &self.right.root);
        let tuple = |x: &Root| (x.owner.clone(), x.group.clone(), x.mode);
        // Owner, group and mode are one permission unit: never composed across sides.
        if merge3(&tuple(b), &tuple(l), &tuple(r)).is_some() {
            return if tuple(l) == tuple(b) {
                r.clone()
            } else {
                l.clone()
            };
        }
        match self.choose(&b.id) {
            Some(p) => pick(p, b, l, r),
            None => {
                self.conflicts.insert(
                    b.id.clone(),
                    EntryConflict {
                        id: b.id.clone(),
                        base: None,
                        left: None,
                        right: None,
                        reason: ConflictReason::Metadata,
                        policy: MergeMode::Opaque,
                    },
                );
                b.clone()
            }
        }
    }
    /// Field-wise merge of an identity present on all three sides.
    fn entry(
        &mut self,
        b: &Entry,
        l: &Entry,
        r: &Entry,
        plan: Option<&Option<TextInput>>,
    ) -> Result<Option<(Entry, bool)>, FsError> {
        let mut reasons = vec![];
        let mut out = b.clone();
        let choice = self.choose(&b.id);
        let location = merge3(&loc(b), &loc(l), &loc(r)).unwrap_or_else(|| {
            reasons.push(ConflictReason::CompetingRename);
            pick(choice.unwrap_or(Side::Base), &loc(b), &loc(l), &loc(r))
        });
        out.parent = location.parent;
        out.path = location.name;
        // Owner, group and mode are one permission unit: different changes on the two sides
        // are a metadata conflict, never a composition neither side authored.
        let tuple = |x: &Entry| (x.owner.clone(), x.group.clone(), x.mode);
        (out.owner, out.group, out.mode) =
            merge3(&tuple(b), &tuple(l), &tuple(r)).unwrap_or_else(|| {
                reasons.push(ConflictReason::Metadata);
                pick(
                    choice.unwrap_or(Side::Base),
                    &tuple(b),
                    &tuple(l),
                    &tuple(r),
                )
            });
        let mut text = false;
        out.content = match merge3(&b.content, &l.content, &r.content) {
            Some(content) => content,
            None => {
                let reason = match plan {
                    // Not text-eligible (opaque/binary/directory kind change).
                    None => Some(ConflictReason::Content),
                    Some(None) => Some(ConflictReason::MergeBudget),
                    Some(Some(input)) => {
                        match self
                            .objects
                            .merge_text(&input.base, &input.left, &input.right)?
                        {
                            TextMerge::Merged(bytes) if bytes.len() <= MAX_TEXT_OUTPUT => {
                                if choice.is_none() {
                                    text = true;
                                    out.content = EntryContent::File {
                                        version: self.objects.generated(&bytes)?,
                                    };
                                    None
                                } else {
                                    // An explicit resolution never introduces generated text.
                                    Some(ConflictReason::TextOverlap)
                                }
                            }
                            TextMerge::Merged(_) | TextMerge::Budget => {
                                Some(ConflictReason::MergeBudget)
                            }
                            TextMerge::Overlap => Some(ConflictReason::TextOverlap),
                            TextMerge::Unsupported => Some(ConflictReason::Content),
                        }
                    }
                };
                match reason {
                    None => out.content.clone(),
                    Some(reason) => {
                        reasons.push(reason);
                        pick(
                            choice.unwrap_or(Side::Base),
                            &b.content,
                            &l.content,
                            &r.content,
                        )
                    }
                }
            }
        };
        if choice.is_none() {
            if let Some(reason) = reasons.into_iter().min_by_key(|r| match r {
                ConflictReason::CompetingRename => 0,
                ConflictReason::Content
                | ConflictReason::TextOverlap
                | ConflictReason::MergeBudget => 1,
                _ => 2,
            }) {
                self.conflict(&b.id, reason);
                return Ok(None);
            }
        }
        Ok(Some((out, text)))
    }
    /// Entries hold (parent, leaf name) in `path`; recompute and verify the structure.
    fn structure(
        &mut self,
        root: Root,
        mut entries: BTreeMap<EntryId, Entry>,
    ) -> Result<Tree, FsError> {
        // Every merged entry carries a leaf name; normalize unchanged entries too.
        for e in entries.values_mut() {
            e.path = loc(e).name;
        }
        let order = [Side::Left, Side::Right, Side::Base];
        for _ in 0..=entries.len() {
            let mut changed = false;
            // 1. Missing or non-directory parents.
            let ids: Vec<EntryId> = entries.keys().cloned().collect();
            for id in ids {
                let Some(parent) = entries.get(&id).map(|e| e.parent.clone()) else {
                    continue;
                };
                if parent == root.id {
                    continue;
                }
                match entries.get(&parent) {
                    Some(p) if p.content == EntryContent::Directory => {}
                    Some(_) => match self.choose(&id) {
                        None => {
                            self.conflict(&id, ConflictReason::PathCollision);
                            self.conflict(&parent, ConflictReason::PathCollision);
                            entries.remove(&id);
                        }
                        Some(_) => return Err(FsError::TargetCollision),
                    },
                    None => match self.choose(&parent).or(self.choose(&id)) {
                        None => {
                            self.conflict(&id, ConflictReason::DirectoryDelete);
                            self.conflict(&parent, ConflictReason::DirectoryDelete);
                            entries.remove(&id);
                        }
                        Some(p) => {
                            let restored = std::iter::once(p)
                                .chain(order)
                                .find_map(|s| self.side(s, &parent))
                                .filter(|e| e.content == EntryContent::Directory)
                                .ok_or(FsError::TargetCollision)?;
                            let mut restored = restored;
                            restored.path = loc(&restored).name;
                            entries.insert(parent.clone(), restored);
                            changed = true;
                        }
                    },
                }
            }
            // 2. Cycles created by independent directory moves.
            let mut cyclic = BTreeSet::new();
            for id in entries.keys() {
                let mut walk: Vec<EntryId> = vec![];
                let mut cursor = id.clone();
                while cursor != root.id {
                    if let Some(start) = walk.iter().position(|seen| *seen == cursor) {
                        // Only the identities on the cycle itself, not the path into it.
                        cyclic.extend(walk.drain(start..));
                        break;
                    }
                    walk.push(cursor.clone());
                    match entries.get(&cursor) {
                        Some(e) => cursor = e.parent.clone(),
                        None => break,
                    }
                }
            }
            let mut repaired = false;
            for id in &cyclic {
                match self.choose(id) {
                    None => {
                        self.conflict(id, ConflictReason::CompetingRename);
                        entries.remove(id);
                    }
                    Some(p) => {
                        let fixed = self.side(p, id).ok_or(FsError::TargetCollision)?;
                        let e = entries.get_mut(id).ok_or(FsError::TargetCollision)?;
                        let target = loc(&fixed);
                        if e.parent != target.parent || e.path != target.name {
                            e.parent = target.parent;
                            e.path = target.name;
                            repaired = true;
                        }
                    }
                }
            }
            if self.prefer.is_some() && !cyclic.is_empty() {
                if !repaired {
                    return Err(FsError::TargetCollision);
                }
                changed = true;
            }
            if !changed {
                break;
            }
        }
        // 3. Case-folded (parent, name) collisions between distinct identities.
        let mut slots: BTreeMap<(EntryId, String), Vec<EntryId>> = BTreeMap::new();
        for e in entries.values() {
            slots
                .entry((e.parent.clone(), fold(&e.path)))
                .or_default()
                .push(e.id.clone());
        }
        for ids in slots.into_values().filter(|ids| ids.len() > 1) {
            match self.prefer {
                None => {
                    let fresh = ids.iter().all(|id| !self.indexes[0].contains_key(id));
                    for id in &ids {
                        self.conflict(
                            id,
                            if fresh {
                                ConflictReason::AddAdd
                            } else {
                                ConflictReason::PathCollision
                            },
                        );
                        entries.remove(id);
                    }
                }
                Some(p) => {
                    // Keep the identity whose location is the preferred input's own.
                    let keep = ids
                        .iter()
                        .find(|id| {
                            self.side(p, id).is_some_and(|s| {
                                entries.get(*id).is_some_and(|e| loc(&s).parent == e.parent)
                            })
                        })
                        .cloned()
                        .ok_or(FsError::TargetCollision)?;
                    for id in ids.into_iter().filter(|id| *id != keep) {
                        remove_subtree(&mut entries, &id);
                    }
                }
            }
        }
        if !self.conflicts.is_empty() {
            return Ok(Tree {
                root,
                entries: vec![],
            });
        }
        // 4. Full paths from the merged identity structure.
        let mut paths: BTreeMap<EntryId, String> = BTreeMap::new();
        let ids: Vec<EntryId> = entries.keys().cloned().collect();
        for id in &ids {
            let mut chain = vec![];
            let mut cursor = id.clone();
            while cursor != root.id {
                if let Some(p) = paths.get(&cursor) {
                    chain.push(p.clone());
                    break;
                }
                let e = entries.get(&cursor).ok_or(FsError::InvalidTree)?;
                chain.push(e.path.clone());
                cursor = e.parent.clone();
                if chain.len() > MAX_ENTRIES {
                    return Err(FsError::InvalidTree);
                }
            }
            chain.reverse();
            paths.insert(id.clone(), chain.join("/"));
        }
        let mut out: Vec<Entry> = entries
            .into_values()
            .map(|mut e| {
                e.path = paths[&e.id].clone();
                e
            })
            .collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        let tree = Tree { root, entries: out };
        validate_tree(&tree)?;
        Ok(tree)
    }
}
fn remove_subtree(entries: &mut BTreeMap<EntryId, Entry>, id: &EntryId) {
    let mut doomed = BTreeSet::from([id.clone()]);
    loop {
        let more: Vec<EntryId> = entries
            .values()
            .filter(|e| doomed.contains(&e.parent) && !doomed.contains(&e.id))
            .map(|e| e.id.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        doomed.extend(more);
    }
    entries.retain(|id, _| !doomed.contains(id));
}
