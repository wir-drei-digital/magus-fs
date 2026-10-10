//! Service reconciliation of an original private candidate against the current destination.
//! Text inputs are read from verified storage and merged by a separate killable worker
//! process under one 5s deadline; no database lock is held meanwhile. Generated objects are
//! installed and verified by the caller before its single atomic metadata commit.
use crate::{auth, revisions as r, views::core_error, Error, Result, ServiceState};
use magus_fs_core::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    sync::Mutex,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const WORKER_ARG: &str = "merge-worker";
const WORKER_DEADLINE: Duration = Duration::from_secs(5);
/// Hex-encoded admitted inputs (at most `MAX_TEXT_TOTAL`) plus framing.
const WORKER_INPUT_LIMIT: usize = 2 * MAX_TEXT_TOTAL as usize + 65_536;
const WORKER_OUTPUT_LIMIT: usize = 2 * MAX_TEXT_MERGES * MAX_TEXT_OUTPUT + 65_536;

pub(crate) enum Planned {
    Clean {
        tree: Tree,
        generated: Vec<(ObjectId, Vec<u8>)>,
        mechanically_merged: Vec<EntryId>,
    },
    Conflicted(Vec<EntryConflict>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerItem {
    base: String,
    left: String,
    right: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    outcome: String,
    merged: Option<String>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The isolated worker's whole job: bounded framed input to bounded framed output.
pub fn worker_transform(input: &[u8]) -> Option<Vec<u8>> {
    let items: Vec<WorkerItem> = serde_json::from_slice(input).ok()?;
    if items.len() > MAX_TEXT_MERGES {
        return None;
    }
    let mut results = vec![];
    for item in items {
        let merged = merge_text(
            &unhex(&item.base)?,
            &unhex(&item.left)?,
            &unhex(&item.right)?,
        );
        results.push(match merged {
            TextMerge::Merged(bytes) => WorkerResult {
                outcome: "merged".into(),
                merged: Some(hex(&bytes)),
            },
            TextMerge::Overlap => WorkerResult {
                outcome: "overlap".into(),
                merged: None,
            },
            TextMerge::Unsupported => WorkerResult {
                outcome: "unsupported".into(),
                merged: None,
            },
            TextMerge::Budget => WorkerResult {
                outcome: "budget".into(),
                merged: None,
            },
        });
    }
    serde_json::to_vec(&results).ok()
}
/// Entry point of `magus-fs-service merge-worker` (stdin -> stdout, no configuration).
pub fn worker_main() -> i32 {
    #[cfg(feature = "test-faults")]
    if std::path::Path::new("/control/slow-merge-worker").is_file() {
        std::thread::sleep(Duration::from_secs(30));
    }
    let mut input = vec![];
    if std::io::stdin()
        .take(WORKER_INPUT_LIMIT as u64 + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > WORKER_INPUT_LIMIT
    {
        return 1;
    }
    match worker_transform(&input) {
        Some(output) if std::io::stdout().write_all(&output).is_ok() => 0,
        _ => 1,
    }
}
fn decode_results(output: &[u8], expected: usize) -> Option<Vec<TextMerge>> {
    let results: Vec<WorkerResult> = serde_json::from_slice(output).ok()?;
    if results.len() != expected {
        return None;
    }
    results
        .into_iter()
        .map(|r| match (r.outcome.as_str(), r.merged) {
            ("merged", Some(text)) => {
                let bytes = unhex(&text)?;
                (bytes.len() <= MAX_TEXT_OUTPUT).then_some(TextMerge::Merged(bytes))
            }
            ("overlap", None) => Some(TextMerge::Overlap),
            ("unsupported", None) => Some(TextMerge::Unsupported),
            ("budget", None) => Some(TextMerge::Budget),
            _ => None,
        })
        .collect()
}
/// Deadline, crash or malformed output all become retained budget conflicts.
async fn run_worker(items: Vec<WorkerItem>) -> Vec<TextMerge> {
    let expected = items.len();
    let budget = vec![TextMerge::Budget; expected];
    if expected == 0 {
        return vec![];
    }
    let Ok(input) = serde_json::to_vec(&items) else {
        return budget;
    };
    let Ok(exe) = std::env::current_exe() else {
        return budget;
    };
    let Ok(mut child) = tokio::process::Command::new(exe)
        .arg(WORKER_ARG)
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return budget;
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return budget;
    };
    let run = async {
        let writer = async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await
        };
        let mut output = vec![];
        let mut limited = stdout.take(WORKER_OUTPUT_LIMIT as u64 + 1);
        let reader = limited.read_to_end(&mut output);
        let (written, read) = tokio::join!(writer, reader);
        written?;
        read?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, output))
    };
    match tokio::time::timeout(WORKER_DEADLINE, run).await {
        Ok(Ok((status, output))) if status.success() && output.len() <= WORKER_OUTPUT_LIMIT => {
            decode_results(&output, expected).unwrap_or(budget)
        }
        _ => {
            // The future (and its child handle) is dropped: kill_on_drop reaps the worker.
            budget
        }
    }
}

/// Prefetched verified inputs and worker results; records generated chunks.
struct Content {
    chunks: BTreeMap<ObjectId, Vec<u8>>,
    results: Vec<(TextInput, TextMerge)>,
    generated: Mutex<Vec<(ObjectId, Vec<u8>)>>,
}
impl MergeContent for Content {
    fn read(&self, version: &FileVersion) -> std::result::Result<Vec<u8>, FsError> {
        assemble(&self.chunks, version)
    }
    fn generated(&self, text: &[u8]) -> std::result::Result<FileVersion, FsError> {
        let (version, chunks) = chunked_version(text)?;
        self.generated
            .lock()
            .map_err(|_| FsError::ReplicaBusy)?
            .extend(chunks);
        Ok(version)
    }
    fn merge_text(
        &self,
        base: &FileVersion,
        left: &FileVersion,
        right: &FileVersion,
    ) -> std::result::Result<TextMerge, FsError> {
        Ok(self
            .results
            .iter()
            .find(|(i, _)| &i.base == base && &i.left == left && &i.right == right)
            .map(|(_, m)| m.clone())
            .unwrap_or(TextMerge::Budget))
    }
}
fn assemble(
    chunks: &BTreeMap<ObjectId, Vec<u8>>,
    version: &FileVersion,
) -> std::result::Result<Vec<u8>, FsError> {
    if version.size > MAX_TEXT_INPUT {
        return Err(FsError::LimitExceeded);
    }
    let mut out = Vec::with_capacity(version.size as usize);
    for extent in &version.extents {
        match extent {
            Extent::Chunk {
                object,
                offset,
                length,
                ..
            } => {
                let body = chunks.get(object).ok_or(FsError::NotFound)?;
                let end = offset.checked_add(*length).ok_or(FsError::InvalidTree)?;
                out.extend_from_slice(
                    body.get(*offset as usize..end as usize)
                        .ok_or(FsError::CorruptObject)?,
                );
            }
            Extent::Hole { length } => out.resize(out.len() + *length as usize, 0),
        }
    }
    Ok(out)
}

/// Three-way reconciliation of full trees: base = the candidate's recorded full base,
/// left = the current destination, right = the original candidate (lifted, full).
pub(crate) async fn reconcile(
    state: &ServiceState,
    namespace: &str,
    base: &Tree,
    current: &Tree,
    candidate: &Tree,
    policy: &MergePolicy,
) -> Result<Planned> {
    let plan = text_merge_plan(base, current, candidate, policy);
    let mut chunks = BTreeMap::new();
    for input in &plan {
        for version in [&input.base, &input.left, &input.right] {
            for extent in &version.extents {
                if let Extent::Chunk {
                    object,
                    object_size,
                    ..
                } = extent
                {
                    if !chunks.contains_key(object) {
                        let bytes = state
                            .objects
                            .read_ready(namespace, object, *object_size)
                            .await?;
                        chunks.insert(object.clone(), bytes.to_vec());
                    }
                }
            }
        }
    }
    let mut items = vec![];
    for input in &plan {
        items.push(WorkerItem {
            base: hex(&assemble(&chunks, &input.base).map_err(core_error)?),
            left: hex(&assemble(&chunks, &input.left).map_err(core_error)?),
            right: hex(&assemble(&chunks, &input.right).map_err(core_error)?),
        });
    }
    let merged = run_worker(items).await;
    let content = Content {
        chunks,
        results: plan.into_iter().zip(merged).collect(),
        generated: Mutex::new(vec![]),
    };
    match reconcile_trees(base, current, candidate, policy, &content).map_err(core_error)? {
        MergeOutcome::Clean {
            tree,
            mechanically_merged,
        } => {
            let used = r::objects_of_tree(&tree);
            let mut generated = content
                .generated
                .into_inner()
                .map_err(|_| Error::backend())?;
            generated.retain(|(id, _)| used.contains_key(id.as_str()));
            generated.sort();
            generated.dedup();
            Ok(Planned::Clean {
                tree,
                generated,
                mechanically_merged,
            })
        }
        MergeOutcome::Conflicted { alternatives } => Ok(Planned::Conflicted(alternatives)),
    }
}

/// Conflicts are only disclosed when every identity they name was visible to the caller:
/// in the current authorized projection, in its original projected view, or newly created
/// by its own candidate. Anything else is denied without revealing hidden siblings.
pub(crate) fn conflicts_visible(
    s: &r::Snapshot,
    view: &r::BoundView,
    current: &Revision,
    conflicts: &[EntryConflict],
) -> Result<()> {
    let a = s.authority()?;
    let now = crate::views::project(current, &current.tree, a, &s.context.prefixes)?;
    let base: BTreeSet<&EntryId> = view.full.tree.entries.iter().map(|e| &e.id).collect();
    let mut allowed: BTreeSet<&EntryId> = now.tree.entries.iter().map(|e| &e.id).collect();
    allowed.extend(view.projected.tree.entries.iter().map(|e| &e.id));
    allowed.insert(&current.tree.root.id);
    for c in conflicts {
        if let Some(right) = &c.right {
            if !base.contains(&right.id) {
                allowed.insert(&right.id);
            }
        }
    }
    for c in conflicts {
        let entries = [&c.base, &c.left, &c.right];
        if !allowed.contains(&c.id)
            || entries.into_iter().flatten().any(|e| {
                !allowed.contains(&e.id)
                    || !s.context.prefixes.iter().any(|p| {
                        auth::within(&e.path, p)
                            || (e.content == EntryContent::Directory && auth::within(p, &e.path))
                    })
            })
        {
            return Err(Error::not_found());
        }
    }
    Ok(())
}

/// Paths whose identity, location, metadata or content differ; empty string for the root.
pub(crate) fn changed_paths(old: &Tree, new: &Tree) -> Vec<String> {
    let mut paths = vec![];
    for e in &new.entries {
        if old.entries.iter().find(|o| o.id == e.id) != Some(e) {
            paths.push(e.path.clone());
        }
    }
    for o in &old.entries {
        if new.entries.iter().find(|e| e.id == o.id) != Some(o) {
            paths.push(o.path.clone());
        }
    }
    if old.root != new.root {
        paths.push(String::new());
    }
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_framing_is_bounded_and_never_returns_marker_text() {
        let items = vec![
            WorkerItem {
                base: hex(b"a\nb\nc\n"),
                left: hex(b"A\nb\nc\n"),
                right: hex(b"a\nb\nC\n"),
            },
            WorkerItem {
                base: hex(b"a\n"),
                left: hex(b"x\n"),
                right: hex(b"y\n"),
            },
            WorkerItem {
                base: hex(b"a"),
                left: hex(&[0xff]),
                right: hex(b"b"),
            },
        ];
        let output = worker_transform(&serde_json::to_vec(&items).unwrap()).unwrap();
        let results = decode_results(&output, 3).unwrap();
        assert_eq!(results[0], TextMerge::Merged(b"A\nb\nC\n".to_vec()));
        assert_eq!(results[1], TextMerge::Overlap);
        assert_eq!(results[2], TextMerge::Unsupported);
        assert!(!String::from_utf8_lossy(&output).contains("<<<<<<<"));
        // Malformed, oversized or mismatched framing is never trusted.
        assert!(worker_transform(b"{}").is_none());
        assert!(decode_results(&output, 2).is_none());
        assert!(decode_results(br#"[{"outcome":"merged","merged":null}]"#, 1).is_none());
        assert!(unhex("abc").is_none());
        let too_many: Vec<_> = (0..=MAX_TEXT_MERGES)
            .map(|_| WorkerItem {
                base: String::new(),
                left: String::new(),
                right: String::new(),
            })
            .collect();
        assert!(worker_transform(&serde_json::to_vec(&too_many).unwrap()).is_none());
    }
    #[test]
    fn changed_paths_cover_moves_metadata_and_removals() {
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: PrincipalId::random().unwrap(),
            group: GroupId::random().unwrap(),
            mode: 0o755,
        };
        let entry = Entry {
            path: "a".into(),
            id: EntryId::random().unwrap(),
            parent: root.id.clone(),
            owner: root.owner.clone(),
            group: root.group.clone(),
            mode: 0o644,
            content: EntryContent::Directory,
        };
        let old = Tree {
            root: root.clone(),
            entries: vec![entry.clone()],
        };
        let mut moved = entry.clone();
        moved.path = "b".into();
        let new = Tree {
            root,
            entries: vec![moved],
        };
        assert_eq!(
            changed_paths(&old, &new),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
