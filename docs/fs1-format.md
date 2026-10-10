# FS1 canonical revisions and immutable chunks

`magus-fs-core` is the v1 local model and chunk store for macOS and Linux. The [local engine](fs1-durability.md) adds a journal and permission evaluation; capture, mounts and shared services remain separate tasks. The existing FS0 probe remains a separate package and its manifests are rejected with `unsupported_format`; there is no implicit migration. Task1 selected initial native capture layout `fixed262144` (262144 bytes), with SHA-256. Future extent edits may retain slices of existing chunks up to 1048576 bytes.

## Public interfaces

All fallible operations return typed errors, including decoding and validation:

```rust
ObjectStore::open(path: impl AsRef<Path>, limits: ObjectLimits) -> Result<ObjectStore, FsError>
ObjectStore::open_existing(path: impl AsRef<Path>, limits: ObjectLimits) -> Result<ObjectStore, FsError>
ObjectStore::inventory(&self) -> Result<Vec<(ObjectId, u64)>, FsError>
ObjectStore::install(&self, bytes: &[u8]) -> Result<ObjectId, FsError>
ObjectStore::read_verified(&self, id: &ObjectId) -> Result<Vec<u8>, FsError>
encode_revision(revision: &Revision) -> Result<Vec<u8>, FsError>
decode_revision(bytes: &[u8]) -> Result<Revision, FsError>
revision_id(revision: &Revision) -> Result<RevisionId, FsError>
validate_tree(tree: &Tree) -> Result<(), FsError>
```

`open_existing` refuses a missing source and never creates it. `inventory` enumerates published IDs/sizes through the open directory with private-file checks; it does not itself hash every body. The engine verifies that inventory before reporting resident bytes. Owned staging files are omitted from published inventory and counted separately for engine quota enforcement.

`ObjectLimits { max_chunk_size: u64, content_roots: Vec<PathBuf> }` defaults to 1048576 and an empty list. Callers opening a store for selected workspaces must supply **all selected content roots**, including intended destinations that do not exist yet. Equal roots or containment in either direction fail with `storage_overlap`. This uses native device/inode identity and directory ancestry from no-follow traversal, rather than path spelling or a Unicode lowercase approximation. A missing destination is checked through its nearest existing ancestor. The check runs before creation and again against the actual opened store after creation, so newly resolvable case/normalization aliases cannot bypass it. On refusal, a newly created empty store is removed only after its native identity is rechecked, and the parent is synced; cleanup errors are reported. Existing directories are never removed by this check. Truly distinct directories on case-sensitive filesystems remain valid. An empty list means the caller has no selected content roots; this API cannot discover unrelated workspaces. The future configuration layer owns that inventory.

IDs are distinct Rust newtypes with private payloads. `parse(impl Into<String>) -> Result<Self, FsError>` and serde validate the entire string; `as_str()` exposes its canonical representation. `ObjectId` and `RevisionId` use `sha256:` followed by exactly 64 lowercase ASCII hex digits. Object IDs hash all raw chunk bytes; revision IDs hash the canonical descriptor bytes. They remain distinct types despite identical textual syntax. `ObjectId::for_bytes(&[u8])` is fallible and enforces the chunk maximum.

`EntryId`, `ReplicaId`, `OperationId`, `PrincipalId`, and `GroupId` respectively use `entry:`, `replica:`, `operation:`, `principal:`, and `group:`, each followed by exactly 32 lowercase hex digits. Their `random() -> Result<Self, FsError>` constructors obtain 128 bits directly from OS randomness through pinned getrandom. Stable identity is never inferred from a path, content, or timestamp. Hash-derived object/revision identity is intentionally separate from these logical identities. Knowing an ID grants no access.

`FsError::code()` and Display expose `invalid_id`, `unsupported_format`, `invalid_descriptor`, `invalid_tree`, `invalid_path`, `limit_exceeded`, `corrupt_object`, `unsafe_storage`, `storage_overlap`, or `io_error`. `Io` retains the underlying `std::io::Error` and exposes it as its source. Malformed serde input, including an overlong nested array, reports `invalid_descriptor`; byte/depth and explicit model/store limits report `limit_exceeded`. Callers must not infer a hole from any error or missing object.

## Canonical byte encoding

The descriptor is compact UTF-8 JSON, with no BOM, whitespace, or trailing newline. Serialization uses pinned serde_json 1.0.151: UTF-8 characters remain UTF-8, JSON syntax/control characters use JSON escapes, and all numeric fields are base-10 unsigned integers. Floats and unknown fields are rejected. No arbitrary metadata maps enter the wire format.

Struct fields occur in exactly this order:

| Struct | Fields in order |
|---|---|
| Revision | `format`, `hash`, `layout`, `parents`, `operation`, `replica`, `principal`, `captured_at_ns`, `coverage`, `provenance`, `tree` |
| Tree | `root`, `entries` |
| Root | `id`, `owner`, `group`, `mode` |
| Entry | `path`, `id`, `parent`, `owner`, `group`, `mode`, `content` |
| Directory content | `kind` (`directory`) |
| File content | `kind` (`file`), `version` |
| FileVersion | `size`, `extents` |
| Chunk extent | `kind` (`chunk`), `object`, `object_size`, `offset`, `length` |
| Hole extent | `kind` (`hole`), `length` |

`format`, `hash`, and `layout` must be exactly `magus-fs/v1`, `sha256`, and `fixed262144`. Unsupported/missing identifiers fail explicitly. `parents` is an ordered list with no duplicate revision IDs; order is meaningful and remains hash-bound. It may be empty. The operation, replica and acting principal are required. `captured_at_ns` is unsigned Unix epoch nanoseconds for display, never conflict ordering; zero is valid.

`coverage` is a nonempty set of selected relative subtree paths, sorted in canonical encoding; the empty string denotes the namespace root. Coverage records which selected subtrees the operation observed, including a subtree absent after deletion. It does not assert cache residency, offline completeness, or service publication. Duplicate paths are invalid. `provenance` must be `explicit`, `native_scan_delete_create`, `engine_observed`, or (FS2-B, additive) `native_unknown_causality`, which marks native content whose causal base is unknown (see [fs2-full.md](fs2-full.md)). The native scan fallback records uncertain rename identity as delete/create. The later capture implementation owns choosing these values and enforcing its include/exclude policy.

Tree entries are sorted by their exact NFC path (UTF-8 lexicographic order). Input vectors may arrive in arbitrary order, including values collected from independently ordered maps. Decoding also sorts entries and coverage, so re-encoding gives the same bytes. Root metadata is a separate required directory record. Entry IDs are unique including the root; each explicit parent ID must identify the directory at the exact path prefix. This simultaneously rejects missing parents, file-as-parent, identity duplicates and cycles. All owner/group/mode and namespace changes affect revision identity. Modes are ordinary rwx bits only, integers 0 through 511; exported metadata does not control internal store permissions.

A literal empty-tree fixture is pinned in `crates/magus-fs-core/tests/format.rs`. Its 492 UTF-8 bytes independently hash in Rust and Python to:

```text
sha256:7b1e3c8da76467f53da36b5642e06f2993b832ca873555b7df7d8fb64314c27b
```

The retained exact bytes and Python verification are in `.superpowers/sdd/fs1-plan/task-2/canonical.json` and `python-hash.log`. This is a v1 format compatibility vector, not an FS0 manifest.

## Paths, Unicode, and structural limits

Paths are relative UTF-8 NFC names separated by `/`. Non-NFC input is rejected without rewriting. Empty entry paths, absolute paths, empty components, `.`/`..`, backslash, colon and control characters are invalid. Individual components are at most 255 UTF-8 bytes and complete paths at most 4096. The empty path is reserved for root coverage; root itself is stored separately.

NFC validation uses **unicode-normalization 0.1.25 / Unicode 17.0.0**. Collision keys use NFD, **caseless 0.2.2 / Unicode 16.0.0 default full case folding**, then NFC. Normalization and folding deliberately have different pinned table versions. Tests cover German sharp-s expansion, Greek sigma/final sigma, accented Latin case and Georgian Mtavruli introduced after Unicode 9. These are actual non-ASCII checks on both target platforms. This policy does not claim every future Unicode case pair or every OS-specific filename equivalence; in particular folds newly added after Unicode 16 are not guaranteed. A materializer must still refuse target-specific collisions and unsupported names instead of overwriting them. Updating either table requires explicit v1 compatibility review; do not silently upgrade dependencies.

Hard maximums are chunk 1048576 bytes, descriptor 16777216 bytes, 100000 tree entries, 100000 extents per file, and logical file size 1099511627776 bytes (1 TiB). Parents/coverage arrays also cap at 100000 items. JSON nesting caps at 16 before any deserialization; input byte size is checked first. Bounded sequence visitors stop before deserializing an excess element; the entry-content decoder avoids buffering an entire unbounded extent array in serde's tagged-enum machinery. Canonical encoding uses a bounded output writer, sorted borrowed entry references, and checked sizes rather than cloning the content model.

Extents concatenate in array order; their implicit logical offsets start at zero. Every length is positive and checked addition must equal the declared logical file size exactly. `offset` is the source chunk offset; checked `offset + length <= object_size <= 1048576` is required. Repeated references to one object ID must agree on its object size throughout the tree. Empty files have zero extents. A hole contributes only logical length. The independent caps can reject a large dense file even below 1 TiB; the upper bound is not a promise that every dense layout fits 100000 descriptors.

## Store layout and durability boundary

The store path is the object directory itself. Each published filename is the complete canonical object ID. Owned staging names start with `.stage-operation:` and have fresh random suffixes. There is no mutable manifest in this directory. Reads expose the entire bounded chunk only after SHA-256 validation; callers may take ranges afterward. There is no unchecked range API.

Store parents must already exist. Traversal opens every path component using directory descriptors with `O_NOFOLLOW`; root and object symlinks, symlink ancestors, special files and unsafe existing permissions are refused. Relative paths resolve against the process working directory; parent traversal is refused. On macOS, use explicit `/private/tmp/...` or another symlink-free spelling, rather than `/tmp/...`. After open, operations remain anchored to the opened directory even if its pathname is replaced. The root must belong to the effective UID with mode0700, and object files must be ordinary files belonging to that UID with mode0600. New files/directories are set to those internal modes independently of the revision's owner/group/mode. This protects against other unprivileged users, not a hostile process with the same storage UID or a host administrator.

Installation ordering:

1. Enforce the chunk bound and hash the requested bytes. Create a fresh owned stage with `O_CREAT|O_EXCL|O_NOFOLLOW`, and mode0600.
2. Write all bytes, synchronize the stage file, reread the same open file, and verify its hash.
3. Publish with `linkat` in the same directory. This is atomic and never replaces an existing destination. If the destination exists, reopen without symlink following, verify its entire bounded contents and private metadata, and synchronize that same verified file. Corrupt existing content returns an error and remains untouched.
4. Synchronize the object directory, unlink only the owned stage, and synchronize the directory again before returning success. Initial directory creation also synchronizes both the new directory and its parent before open succeeds.

Errors leave prior objects unchanged. A process failure may leave an unreferenced staging file or a fully installed unreferenced object; reopening never interprets staging files as content or deletes another operation's stage. Later explicit GC/recovery owns orphan inventory. In particular, a failure after publication but before a sync may leave a visible object without having acknowledged durable installation. Journal callers must only commit references after successful installation, as required by FS1's crash order.

Tests exercise ordinary local filesystem operations, reopen, concurrent identical installs, interrupted-stage residue, corruption, excessive sizes, FIFO/symlink refusal, fd anchoring, modes and overlap. They do not simulate a hardware power failure or claim mounted FS1 acceptance. The fsync barriers rely on the local filesystem/OS durability contract; failures propagate. No native mount benchmarks or FS0 matrix need to be rerun for this isolated core addition.

## Explicit v2 restoration descriptors

Task7 adds `magus-fs/v2` for revisions produced by live historical restoration. V1 remains closed and byte-identical: it rejects any `restoration` field, including null. V2 requires the typed `restoration` field between `provenance` and `tree`. It has exactly `source_revision`, `restore_metadata`, and `recreated`, in that order. `recreated` is a bounded map from validated source EntryId to fresh destination EntryId, encoded in ascending source-ID order; duplicate source keys, duplicate destination IDs, identity reuse and more than 100000 mappings fail. This is a typed identity mapping, not an arbitrary metadata bag. No timestamps or host security metadata are added.

The standalone decoder checks version, shape, bounds, declared source-parent membership and destination identity membership. Creation/import and archive closure additionally require actual source and replaced-head descriptors. They check the selected source ID, first parent as replaced head, common root identity, the exact set of source identities absent from that head, fresh output identities absent from both parent trees, mapped parents, paths, kinds and content. Missing parent descriptors fail explicitly. Ordinary capture/checkpoint continue emitting v1; mixed v1/v2 ancestry is supported. Older v1-only readers explicitly reject v2 with `unsupported_format`; they must never strip restoration provenance.

The independent v2 empty-tree restoration vector in `tests/format.rs` declares the unchanged v1 fixture as its parent/source and has an empty recreated map. Its 713 canonical bytes hash independently in Python to `sha256:f1b96309415b5606f32a9d3a1c7daf71eacfc6530a502d47d9310ddf25492291`; exact bytes and the Python result are retained in Task7 evidence. A modified provenance field changes revision identity. Archives retain the canonical v2 descriptor itself, so deleted-entry recovery lineage survives without the original journal.
