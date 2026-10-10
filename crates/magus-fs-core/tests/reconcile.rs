//! FS2-B Task 2: identity-based three-way reconciliation table.
mod support;
use magus_fs_core::*;
use std::{cell::RefCell, collections::BTreeMap};
use support::{group, principal};

/// Verified in-memory content: chunk bodies by object id plus recorded generated text.
#[derive(Default)]
struct Store {
    objects: RefCell<BTreeMap<ObjectId, Vec<u8>>>,
    generated: RefCell<Vec<Vec<u8>>>,
    reads: RefCell<usize>,
}
impl Store {
    fn version(&self, bytes: &[u8]) -> FileVersion {
        let (version, chunks) = chunked_version(bytes).unwrap();
        for (id, body) in chunks {
            self.objects.borrow_mut().insert(id, body);
        }
        version
    }
    fn bytes(&self, version: &FileVersion) -> Vec<u8> {
        self.read(version).unwrap()
    }
}
impl MergeContent for Store {
    fn read(&self, version: &FileVersion) -> Result<Vec<u8>, FsError> {
        *self.reads.borrow_mut() += 1;
        let mut out = vec![];
        for extent in &version.extents {
            match extent {
                Extent::Chunk {
                    object,
                    offset,
                    length,
                    ..
                } => {
                    let body = self
                        .objects
                        .borrow()
                        .get(object)
                        .cloned()
                        .ok_or(FsError::NotFound)?;
                    out.extend_from_slice(&body[*offset as usize..(*offset + *length) as usize]);
                }
                Extent::Hole { length } => out.resize(out.len() + *length as usize, 0),
            }
        }
        Ok(out)
    }
    fn generated(&self, text: &[u8]) -> Result<FileVersion, FsError> {
        self.generated.borrow_mut().push(text.to_vec());
        Ok(self.version(text))
    }
}

struct Fixture {
    store: Store,
    root: Root,
    ids: RefCell<BTreeMap<String, EntryId>>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            store: Store::default(),
            root: Root {
                id: EntryId::random().unwrap(),
                owner: principal(1),
                group: group(1),
                mode: 0o755,
            },
            ids: RefCell::new(BTreeMap::new()),
        }
    }
    fn id(&self, name: &str) -> EntryId {
        self.ids
            .borrow_mut()
            .entry(name.to_owned())
            .or_insert_with(|| EntryId::random().unwrap())
            .clone()
    }
    fn parent_of(&self, path: &str) -> EntryId {
        match path.rsplit_once('/') {
            None => self.root.id.clone(),
            Some((parent, _)) => self.id(parent),
        }
    }
    fn dir(&self, path: &str) -> Entry {
        Entry {
            path: path.into(),
            id: self.id(path),
            parent: self.parent_of(path),
            owner: principal(1),
            group: group(1),
            mode: 0o755,
            content: EntryContent::Directory,
        }
    }
    /// A file identified by `name`, placed at `path` (identity survives renames).
    fn file_as(&self, name: &str, path: &str, bytes: &[u8]) -> Entry {
        Entry {
            path: path.into(),
            id: self.id(name),
            parent: self.parent_of(path),
            owner: principal(1),
            group: group(1),
            mode: 0o644,
            content: EntryContent::File {
                version: self.store.version(bytes),
            },
        }
    }
    fn file(&self, path: &str, bytes: &[u8]) -> Entry {
        self.file_as(path, path, bytes)
    }
    fn tree(&self, mut entries: Vec<Entry>) -> Tree {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let tree = Tree {
            root: self.root.clone(),
            entries,
        };
        validate_tree(&tree).unwrap();
        tree
    }
    fn merge(&self, b: &Tree, l: &Tree, r: &Tree, policy: &MergePolicy) -> MergeOutcome {
        reconcile_trees(b, l, r, policy, &self.store).unwrap()
    }
}
fn clean(outcome: MergeOutcome) -> (Tree, Vec<EntryId>) {
    match outcome {
        MergeOutcome::Clean {
            tree,
            mechanically_merged,
        } => (tree, mechanically_merged),
        MergeOutcome::Conflicted { alternatives } => panic!("unexpected conflict {alternatives:?}"),
    }
}
fn conflicts(outcome: MergeOutcome) -> Vec<(EntryId, ConflictReason)> {
    match outcome {
        MergeOutcome::Conflicted { alternatives } => {
            for a in &alternatives {
                // Alternatives are immutable inputs; nothing generated or marker-filled.
                for e in [&a.base, &a.left, &a.right].into_iter().flatten() {
                    assert!(e.path.split('/').all(|c| !c.is_empty()));
                }
            }
            alternatives.into_iter().map(|a| (a.id, a.reason)).collect()
        }
        MergeOutcome::Clean { tree, .. } => panic!("unexpected clean merge {tree:?}"),
    }
}
fn at<'a>(tree: &'a Tree, path: &str) -> &'a Entry {
    tree.entries
        .iter()
        .find(|e| e.path == path)
        .unwrap_or_else(|| panic!("missing {path}"))
}
fn opaque() -> MergePolicy {
    MergePolicy::opaque()
}

#[test]
fn disjoint_changes_merge_and_identical_outcomes_coalesce() {
    let f = Fixture::new();
    let d = f.dir("docs");
    let base = f.tree(vec![
        d.clone(),
        f.file("docs/a", b"a0"),
        f.file("docs/b", b"b0"),
    ]);
    let left = f.tree(vec![
        d.clone(),
        f.file("docs/a", b"a1"),
        f.file("docs/b", b"b0"),
        f.file("docs/l", b"new-left"),
    ]);
    let right = f.tree(vec![
        d.clone(),
        f.file("docs/a", b"a0"),
        f.file("docs/b", b"b1"),
        f.file("docs/r", b"new-right"),
    ]);
    let (tree, merged) = clean(f.merge(&base, &left, &right, &opaque()));
    assert!(merged.is_empty());
    let store = &f.store;
    let read = |p: &str| {
        store.bytes(match &at(&tree, p).content {
            EntryContent::File { version } => version,
            _ => panic!(),
        })
    };
    assert_eq!(read("docs/a"), b"a1");
    assert_eq!(read("docs/b"), b"b1");
    assert_eq!(read("docs/l"), b"new-left");
    assert_eq!(read("docs/r"), b"new-right");
    // Both sides making the same change (content and a new identical deletion) coalesce.
    let same = f.tree(vec![
        d.clone(),
        f.file("docs/a", b"same"),
        f.file("docs/b", b"b0"),
    ]);
    let (tree, _) = clean(f.merge(&base, &same, &same.clone(), &opaque()));
    assert_eq!(tree, same);
    let deleted = f.tree(vec![d, f.file("docs/a", b"a0")]);
    let (tree, _) = clean(f.merge(&base, &deleted, &deleted.clone(), &opaque()));
    assert_eq!(tree, deleted);
}

#[test]
fn known_identity_rename_composes_with_edit_and_ancestor_move() {
    let f = Fixture::new();
    let base = f.tree(vec![f.dir("d"), f.file_as("f", "d/f", b"original")]);
    // Left renames the directory and the file; right edits the same file identity.
    let mut moved = f.dir("d");
    moved.path = "e".into();
    let mut g = f.file_as("f", "e/g", b"original");
    g.parent = f.id("d");
    let left = f.tree(vec![moved, g]);
    let right = f.tree(vec![f.dir("d"), f.file_as("f", "d/f", b"edited")]);
    let (tree, _) = clean(f.merge(&base, &left, &right, &opaque()));
    let g = at(&tree, "e/g");
    assert_eq!(g.id, f.id("f"));
    assert_eq!(g.content, right.entries[1].content);
    // Ancestor-only path changes are not edits: the other side's delete wins cleanly.
    let mut moved = f.dir("d");
    moved.path = "e".into();
    let mut kept = f.file_as("f", "e/f", b"original");
    kept.parent = f.id("d");
    let left = f.tree(vec![moved, kept]);
    let right = f.tree(vec![f.dir("d")]);
    let (tree, _) = clean(f.merge(&base, &left, &right, &opaque()));
    assert_eq!(tree.entries.len(), 1);
    assert_eq!(tree.entries[0].path, "e");
}

#[test]
fn competing_renames_and_move_cycles_retain_alternatives() {
    let f = Fixture::new();
    let base = f.tree(vec![f.file_as("f", "f", b"x")]);
    let left = f.tree(vec![f.file_as("f", "g", b"x")]);
    let right = f.tree(vec![f.file_as("f", "h", b"x")]);
    assert_eq!(
        conflicts(f.merge(&base, &left, &right, &opaque())),
        vec![(f.id("f"), ConflictReason::CompetingRename)]
    );
    // Left moves a into b, right moves b into a: each move is clean alone, together a cycle.
    let base = f.tree(vec![f.dir("a"), f.dir("b")]);
    let mut a_in_b = f.dir("a");
    a_in_b.path = "b/a".into();
    a_in_b.parent = f.id("b");
    let left = f.tree(vec![f.dir("b"), a_in_b]);
    let mut b_in_a = f.dir("b");
    b_in_a.path = "a/b".into();
    b_in_a.parent = f.id("a");
    let right = f.tree(vec![f.dir("a"), b_in_a]);
    let found = conflicts(f.merge(&base, &left, &right, &opaque()));
    assert!(
        found
            .iter()
            .all(|(_, r)| *r == ConflictReason::CompetingRename),
        "{found:?}"
    );
    assert_eq!(found.len(), 2);
}

#[test]
fn add_add_and_parent_name_collisions_are_conflicts_never_last_writer() {
    let f = Fixture::new();
    let base = f.tree(vec![f.dir("d")]);
    let left = f.tree(vec![f.dir("d"), f.file_as("left-new", "d/x", b"left")]);
    let right = f.tree(vec![f.dir("d"), f.file_as("right-new", "d/x", b"right")]);
    let mut found = conflicts(f.merge(&base, &left, &right, &opaque()));
    found.sort();
    let mut want = vec![
        (f.id("left-new"), ConflictReason::AddAdd),
        (f.id("right-new"), ConflictReason::AddAdd),
    ];
    want.sort();
    assert_eq!(found, want);
    // Case-folded names collide too.
    let right = f.tree(vec![f.dir("d"), f.file_as("right-new", "d/X", b"right")]);
    assert_eq!(conflicts(f.merge(&base, &left, &right, &opaque())).len(), 2);
    // An existing identity moved onto a name newly created by the other side.
    let base = f.tree(vec![f.dir("d"), f.file_as("a", "a", b"a")]);
    let left = f.tree(vec![f.dir("d"), {
        let mut a = f.file_as("a", "d/a", b"a");
        a.parent = f.id("d");
        a
    }]);
    let right = f.tree(vec![
        f.dir("d"),
        f.file_as("a", "a", b"a"),
        f.file_as("other", "d/a", b"other"),
    ]);
    let found = conflicts(f.merge(&base, &left, &right, &opaque()));
    assert!(
        found.contains(&(f.id("a"), ConflictReason::PathCollision)),
        "{found:?}"
    );
    assert!(
        found.contains(&(f.id("other"), ConflictReason::PathCollision)),
        "{found:?}"
    );
}

#[test]
fn edit_delete_and_directory_descendant_edits_conflict() {
    let f = Fixture::new();
    let base = f.tree(vec![f.dir("d"), f.file("d/f", b"v0"), f.file("g", b"g0")]);
    let left = f.tree(vec![f.dir("d"), f.file("d/f", b"v1"), f.file("g", b"g0")]);
    let right = f.tree(vec![f.dir("d"), f.file("g", b"g0")]);
    assert_eq!(
        conflicts(f.merge(&base, &left, &right, &opaque())),
        vec![(f.id("d/f"), ConflictReason::EditDelete)]
    );
    // Right removes the whole directory while left edits a descendant and adds a child.
    let right = f.tree(vec![f.file("g", b"g0")]);
    let left = f.tree(vec![
        f.dir("d"),
        f.file("d/f", b"v1"),
        f.file("d/new", b"n"),
        f.file("g", b"g0"),
    ]);
    let found = conflicts(f.merge(&base, &left, &right, &opaque()));
    assert!(
        found.contains(&(f.id("d/f"), ConflictReason::EditDelete)),
        "{found:?}"
    );
    assert!(
        found.contains(&(f.id("d/new"), ConflictReason::DirectoryDelete)),
        "{found:?}"
    );
    assert!(
        found.contains(&(f.id("d"), ConflictReason::DirectoryDelete)),
        "{found:?}"
    );
    // An unchanged descendant deleted together with its directory is clean.
    let left = base.clone();
    let (tree, _) = clean(f.merge(&base, &left, &right, &opaque()));
    assert_eq!(tree, right);
}

#[test]
fn modes_owners_groups_merge_fieldwise_and_incompatible_metadata_conflicts() {
    let f = Fixture::new();
    let base = f.tree(vec![f.file("f", b"v0")]);
    let mut chmod = f.file("f", b"v0");
    chmod.mode = 0o600;
    let edit = f.file("f", b"v1");
    let (tree, _) = clean(f.merge(
        &base,
        &f.tree(vec![chmod.clone()]),
        &f.tree(vec![edit.clone()]),
        &opaque(),
    ));
    assert_eq!(tree.entries[0].mode, 0o600);
    assert_eq!(tree.entries[0].content, edit.content);
    let mut other = f.file("f", b"v0");
    other.mode = 0o640;
    assert_eq!(
        conflicts(f.merge(
            &base,
            &f.tree(vec![chmod.clone()]),
            &f.tree(vec![other]),
            &opaque()
        )),
        vec![(f.id("f"), ConflictReason::Metadata)]
    );
    let mut owner = f.file("f", b"v0");
    owner.owner = principal(2);
    let mut owner2 = f.file("f", b"v0");
    owner2.owner = principal(3);
    assert_eq!(
        conflicts(f.merge(
            &base,
            &f.tree(vec![owner]),
            &f.tree(vec![owner2]),
            &opaque()
        )),
        vec![(f.id("f"), ConflictReason::Metadata)]
    );
    let mut grouped = f.file("f", b"v0");
    grouped.group = group(2);
    let mut grouped2 = f.file("f", b"v0");
    grouped2.group = group(3);
    assert_eq!(
        conflicts(f.merge(
            &base,
            &f.tree(vec![grouped]),
            &f.tree(vec![grouped2]),
            &opaque()
        )),
        vec![(f.id("f"), ConflictReason::Metadata)]
    );
    // Root metadata is merged the same way.
    let mut l = base.clone();
    l.root.mode = 0o700;
    let mut r = base.clone();
    r.root.mode = 0o750;
    assert_eq!(
        conflicts(f.merge(&base, &l, &r, &opaque())),
        vec![(f.root.id.clone(), ConflictReason::Metadata)]
    );
}

#[test]
fn permission_change_racing_content_edit_is_structurally_clean_and_left_to_authorization() {
    // Reconciliation makes no authorization decisions: a directory narrowed on one side and a
    // file added beneath it on the other merge structurally; the service re-authorizes the
    // complete resulting delta under current rights before any commit.
    let f = Fixture::new();
    let base = f.tree(vec![f.dir("d"), f.file("d/f", b"v0")]);
    let mut narrowed = f.dir("d");
    narrowed.mode = 0o500;
    let left = f.tree(vec![narrowed.clone(), f.file("d/f", b"v0")]);
    let right = f.tree(vec![
        f.dir("d"),
        f.file("d/f", b"v1"),
        f.file("d/added", b"a"),
    ]);
    let (tree, _) = clean(f.merge(&base, &left, &right, &opaque()));
    assert_eq!(at(&tree, "d").mode, 0o500);
    assert_eq!(at(&tree, "d/added").id, f.id("d/added"));
}

#[test]
fn unknown_identity_replacement_is_not_matched_by_path() {
    // Left saved by delete+create (new identity at the same path); right edited the original
    // identity. Paths never establish identity, so the original is an edit/delete conflict.
    let f = Fixture::new();
    let base = f.tree(vec![f.file_as("old", "f", b"v0")]);
    let left = f.tree(vec![f.file_as("new", "f", b"v1")]);
    let right = f.tree(vec![f.file_as("old", "f", b"v2")]);
    let found = conflicts(f.merge(&base, &left, &right, &opaque()));
    assert!(
        found.contains(&(f.id("old"), ConflictReason::EditDelete)),
        "{found:?}"
    );
    // A mismatched root identity means there is no known common base.
    let mut foreign = left.clone();
    foreign.root.id = EntryId::random().unwrap();
    assert!(matches!(
        reconcile_trees(&base, &foreign, &right, &opaque(), &f.store),
        Err(FsError::InvalidTree)
    ));
}

#[test]
fn opt_in_text_merges_non_overlapping_edits_and_never_emits_markers() {
    let f = Fixture::new();
    let text = MergePolicy::text(["TXT", ".md"]).unwrap();
    assert_eq!(
        text.text_extensions,
        vec!["md".to_string(), "txt".to_string()]
    );
    let base = f.tree(vec![f.file("notes.txt", b"one\ntwo\nthree\n")]);
    let left = f.tree(vec![f.file("notes.txt", b"ONE\ntwo\nthree\n")]);
    let right = f.tree(vec![f.file("notes.txt", b"one\ntwo\nTHREE\n")]);
    // Default policy is opaque.
    assert_eq!(
        conflicts(f.merge(&base, &left, &right, &opaque())),
        vec![(f.id("notes.txt"), ConflictReason::Content)]
    );
    let (tree, merged) = clean(f.merge(&base, &left, &right, &text));
    assert_eq!(merged, vec![f.id("notes.txt")]);
    let EntryContent::File { version } = &tree.entries[0].content else {
        panic!()
    };
    assert_eq!(f.store.bytes(version), b"ONE\ntwo\nTHREE\n");
    // Overlapping edits keep alternatives; marker text never becomes generated content.
    let before = f.store.generated.borrow().len();
    let right = f.tree(vec![f.file("notes.txt", b"uno\ntwo\nthree\n")]);
    let found = match f.merge(&base, &left, &right, &text) {
        MergeOutcome::Conflicted { alternatives } => alternatives,
        other => panic!("{other:?}"),
    };
    assert_eq!(found[0].reason, ConflictReason::TextOverlap);
    assert_eq!(found[0].policy, MergeMode::Text);
    assert_eq!(
        found[0].right.as_ref().unwrap().content,
        right.entries[0].content
    );
    assert_eq!(f.store.generated.borrow().len(), before);
}

#[test]
fn csv_office_binary_and_malformed_text_stay_opaque() {
    for blocked in ["csv", "xlsx", "docx", "pdf"] {
        assert!(MergePolicy::text([blocked]).is_err(), "{blocked}");
    }
    assert!(MergePolicy::text(["../x"]).is_err());
    assert!(MergePolicy {
        text_extensions: vec!["TXT".into()]
    }
    .validate()
    .is_err());
    let f = Fixture::new();
    let text = MergePolicy::text(["txt"]).unwrap();
    let base = f.tree(vec![
        f.file("table.csv", b"a,b\n1,2\n"),
        f.file("blob.txt", b"x\ny\n"),
    ]);
    let left = f.tree(vec![
        f.file("table.csv", b"A,b\n1,2\n"),
        f.file("blob.txt", b"x\0\ny\n"),
    ]);
    let right = f.tree(vec![
        f.file("table.csv", b"a,b\n1,3\n"),
        f.file("blob.txt", b"x\ny\0\n"),
    ]);
    let mut found = conflicts(f.merge(&base, &left, &right, &text));
    found.sort();
    let mut want = vec![
        (f.id("table.csv"), ConflictReason::Content),
        (f.id("blob.txt"), ConflictReason::Content),
    ];
    want.sort();
    assert_eq!(found, want);
    assert_eq!(
        merge_text(b"a", &[0xff, 0xfe], b"b"),
        TextMerge::Unsupported
    );
}

#[test]
fn text_bounds_and_per_candidate_budget_produce_budget_conflicts() {
    let f = Fixture::new();
    let text = MergePolicy::text(["txt"]).unwrap();
    let big = vec![b'a'; (MAX_TEXT_INPUT + 1) as usize];
    let base = f.tree(vec![f.file("big.txt", &big)]);
    let left = f.tree(vec![f.file("big.txt", b"left")]);
    let right = f.tree(vec![f.file("big.txt", b"right")]);
    let reads = *f.store.reads.borrow();
    assert_eq!(
        conflicts(f.merge(&base, &left, &right, &text)),
        vec![(f.id("big.txt"), ConflictReason::MergeBudget)]
    );
    assert_eq!(
        *f.store.reads.borrow(),
        reads,
        "over-bound inputs are never read"
    );
    let lines = "x\n".repeat(MAX_TEXT_LINES + 1);
    assert_eq!(
        merge_text(lines.as_bytes(), b"a\n", b"b\n"),
        TextMerge::Budget
    );
    // Seventeen eligible merges: the first sixteen (identity order) merge, the rest is budget.
    let names: Vec<String> = (0..17).map(|i| format!("t{i:02}.txt")).collect();
    let mk = |f: &Fixture, v: &[u8; 3]| -> Tree {
        let entries = names
            .iter()
            .map(|n| {
                let body = [b"a\nb\nc\n".to_vec(), vec![]].concat();
                let mut lines: Vec<Vec<u8>> =
                    body.split(|b| *b == b'\n').map(|l| l.to_vec()).collect();
                for (i, x) in v.iter().enumerate() {
                    if *x != 0 {
                        lines[i] = vec![*x];
                    }
                }
                f.file(n, &lines.join(&b'\n'))
            })
            .collect();
        f.tree(entries)
    };
    let base = mk(&f, &[0, 0, 0]);
    let left = mk(&f, &[b'L', 0, 0]);
    let right = mk(&f, &[0, 0, b'R']);
    let plan = text_merge_plan(&base, &left, &right, &text);
    assert_eq!(plan.len(), MAX_TEXT_MERGES);
    let found = conflicts(f.merge(&base, &left, &right, &text));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, ConflictReason::MergeBudget);
    let mut sorted: Vec<EntryId> = names.iter().map(|n| f.id(n)).collect();
    sorted.sort();
    assert_eq!(found[0].0, sorted[16]);
}

#[test]
fn explicit_resolution_prefers_one_side_and_repairs_structure() {
    let f = Fixture::new();
    let base = f.tree(vec![f.dir("d"), f.file("d/f", b"v0"), f.file("g", b"g0")]);
    let left = f.tree(vec![
        f.dir("d"),
        f.file("d/f", b"left"),
        f.file("g", b"g-left"),
    ]);
    let right = f.tree(vec![
        f.dir("d"),
        f.file("d/f", b"right"),
        f.file("h", b"h-right"),
        f.file("g", b"g0"),
    ]);
    let current = resolve_trees(&base, &left, &right, &opaque(), &f.store, Side::Left).unwrap();
    let candidate = resolve_trees(&base, &left, &right, &opaque(), &f.store, Side::Right).unwrap();
    assert_eq!(at(&current, "d/f").content, left.entries[1].content);
    assert_eq!(at(&candidate, "d/f").content, right.entries[1].content);
    // Non-conflicting changes from both sides survive either selection.
    for tree in [&current, &candidate] {
        assert_eq!(at(tree, "g").content, at(&left, "g").content);
        assert!(tree.entries.iter().any(|e| e.path == "h"));
    }
    // Candidate added beneath a directory current deleted: the directory is restored.
    let left = f.tree(vec![f.file("g", b"g0")]);
    let right = f.tree(vec![
        f.dir("d"),
        f.file("d/f", b"v0"),
        f.file("d/new", b"n"),
        f.file("g", b"g0"),
    ]);
    let tree = resolve_trees(&base, &left, &right, &opaque(), &f.store, Side::Right).unwrap();
    assert!(tree.entries.iter().any(|e| e.path == "d/new"));
}

#[test]
fn collaboration_dtos_are_closed_bounded_and_snake_case() {
    use magus_fs_core::protocol::*;
    let request = ResolutionRequest {
        operation: OperationId::random().unwrap(),
        replica: ReplicaId::random().unwrap(),
        conflicts: vec![ConflictId::random().unwrap()],
        expected_head: HeadToken::random().unwrap(),
        replacement: ReceiptId::random().unwrap(),
    };
    request.validate().unwrap();
    let mut duplicate = request.clone();
    duplicate.conflicts.push(duplicate.conflicts[0].clone());
    assert!(duplicate.validate().is_err());
    let mut many = request.clone();
    many.conflicts = (0..=MAX_RESOLUTION_CONFLICTS)
        .map(|_| ConflictId::random().unwrap())
        .collect();
    assert!(many.validate().is_err());
    let mut wire = serde_json::to_value(&request).unwrap();
    // Struct-order compact JSON is the digest input; unknown fields are rejected.
    assert_eq!(
        serde_json::to_string(&request)
            .unwrap()
            .split(':')
            .next()
            .unwrap(),
        "{\"operation\""
    );
    wire["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResolutionRequest>(wire).is_err());
    let summary = ConflictSummary {
        id: ConflictId::random().unwrap(),
        receipt: ReceiptId::random().unwrap(),
        reason: ConflictReason::UnknownCausality,
        state: ConflictState::Open,
    };
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(value["reason"], "unknown_causality");
    assert_eq!(value["state"], "open");
    assert_eq!(
        ConflictReason::parse("text_overlap").unwrap(),
        ConflictReason::TextOverlap
    );
    assert!(ConflictReason::parse("lww").is_err());
    assert!(ConflictId::parse("0".repeat(31)).is_err());
}

#[test]
fn permission_tuple_changes_on_different_sides_conflict_instead_of_composing() {
    // Left changes the group, right the mode: composing would grant the new group a mode
    // neither side authored. (owner, group, mode) is one unit.
    let f = Fixture::new();
    let mut base_file = f.file("f", b"v0");
    base_file.mode = 0o640;
    let base = f.tree(vec![base_file.clone()]);
    let mut grouped = base_file.clone();
    grouped.group = group(2);
    let mut widened = base_file.clone();
    widened.mode = 0o660;
    assert_eq!(
        conflicts(f.merge(
            &base,
            &f.tree(vec![grouped.clone()]),
            &f.tree(vec![widened.clone()]),
            &opaque()
        )),
        vec![(f.id("f"), ConflictReason::Metadata)]
    );
    let mut owned = base_file.clone();
    owned.owner = principal(2);
    assert_eq!(
        conflicts(f.merge(
            &base,
            &f.tree(vec![owned]),
            &f.tree(vec![widened.clone()]),
            &opaque()
        )),
        vec![(f.id("f"), ConflictReason::Metadata)]
    );
    // The same tuple from both sides, or a tuple change against a content edit, is clean.
    let (tree, _) = clean(f.merge(
        &base,
        &f.tree(vec![grouped.clone()]),
        &f.tree(vec![grouped.clone()]),
        &opaque(),
    ));
    assert_eq!(tree.entries[0].group, group(2));
    let mut edited = base_file.clone();
    edited.content = f.file("f", b"v1").content;
    let (tree, _) = clean(f.merge(
        &base,
        &f.tree(vec![grouped]),
        &f.tree(vec![edited.clone()]),
        &opaque(),
    ));
    assert_eq!(
        (tree.entries[0].group.clone(), tree.entries[0].mode),
        (group(2), 0o640)
    );
    assert_eq!(tree.entries[0].content, edited.content);
    // Root: group on one side, mode on the other.
    let mut l = base.clone();
    l.root.group = group(2);
    let mut r = base.clone();
    r.root.mode = 0o775;
    assert_eq!(
        conflicts(f.merge(&base, &l, &r, &opaque())),
        vec![(f.root.id.clone(), ConflictReason::Metadata)]
    );
}

#[test]
fn explicit_resolution_applies_per_conflict_choices_and_base_selection() {
    let f = Fixture::new();
    let base = f.tree(vec![
        f.file("a", b"a0"),
        f.file("b", b"b0"),
        f.file("c", b"c0"),
    ]);
    let left = f.tree(vec![
        f.file("a", b"a-left"),
        f.file("b", b"b-left"),
        f.file("c", b"c0"),
    ]);
    let right = f.tree(vec![
        f.file("a", b"a-right"),
        f.file("b", b"b-right"),
        f.file("c", b"c-right"),
    ]);
    let choices =
        std::collections::BTreeMap::from([(f.id("a"), Side::Left), (f.id("b"), Side::Base)]);
    let tree = resolve_trees_with(
        &base,
        &left,
        &right,
        &opaque(),
        &f.store,
        Side::Right,
        &choices,
    )
    .unwrap();
    assert_eq!(at(&tree, "a").content, at(&left, "a").content);
    assert_eq!(at(&tree, "b").content, at(&base, "b").content);
    // Non-conflicting change from the candidate survives.
    assert_eq!(at(&tree, "c").content, at(&right, "c").content);
    let all_base = resolve_trees(&base, &left, &right, &opaque(), &f.store, Side::Base).unwrap();
    assert_eq!(at(&all_base, "a").content, at(&base, "a").content);
    assert_eq!(at(&all_base, "c").content, at(&right, "c").content);
}
