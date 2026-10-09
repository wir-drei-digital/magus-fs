# FS1 ordinary folders and standalone CLI

Build with Rust 1.92.0: `cargo build --locked -p magus-fs`. The binary is `target/debug/magus-fs`. This is the standalone owner of the same local engine used by later mount adapters. Every invocation emits one JSON object on stdout and diagnostics on stderr: exit 0 success, 1 typed operation failure, 2 invalid arguments or unavailable prerequisites. There is no mount command or default-build fault endpoint in this task. A mounted engine will own its journal; Task5 must route controls through its private channel rather than opening competing owners.

Use a new absolute control directory outside the selected content and every intended destination. Paths are traversed with no-follow directory descriptors; symlink ancestors, including macOS `/tmp`, are refused. Canonical `/private/tmp` is suitable for isolated Mac examples. All configured content roots and each dynamic capture root, intended destination and staging root are checked against the entire control directory using native device/inode ancestry. Checks repeat before publication; case/normalization aliases cannot bypass overlap checks. Existing destinations, including empty directories, are refused. Sibling staging must also stay outside every configured selected/intended content root: a destination nested inside already selected content is refused with `storage_overlap` before creating its wrapper. FS1 does not choose an alternate staging location.

The initialization file is a strict JSON wrapper:

```json
{
  "replica": {
    "replica": "replica:11111111111111111111111111111111",
    "authorities": [{
      "principal": "principal:11111111111111111111111111111111",
      "uid": 501,
      "primary_group": "group:11111111111111111111111111111111",
      "gid": 0,
      "groups": ["group:11111111111111111111111111111111"],
      "dac_override": false,
      "ownership_transfer": true
    }],
    "content_roots": ["/private/tmp/fs1-example/tree"],
    "cache_bytes": 33554432
  },
  "root": "/private/tmp/fs1-example/tree",
  "policy": {"included_roots": ["."], "excluded_prefixes": ["omit"]},
  "creation_umask": 18
}
```

The selected `root` must appear in `replica.content_roots` with exactly the same absolute path spelling. Init rejects a missing member with exit2 `config_mismatch` before creating control storage; native identity/alias overlap checks still apply.

Supply actual trusted host mappings: the example UID/GID describes the qualified Mac scratch fixture, not every machine. macOS created files here inherit directory GID 0 although the process primary group is 20. Observe actual `stat` ownership and configure it explicitly; unmapped ownership fails `mapping_blocked`. No command asks for privileges to restore ownership. The actor is selected from the effective process UID; adapters must bind trusted actors, never arbitrary wire principal IDs. `creation_umask` is decimal 18 (`0022`), the engine's fixed creation policy.

```sh
magus-fs init --state /private/tmp/fs1-example/state --config /private/tmp/fs1-example/config.json
magus-fs capture --state /private/tmp/fs1-example/state --root /private/tmp/fs1-example/tree --operation-id operation:00000000000000000000000000000001
magus-fs history --state /private/tmp/fs1-example/state
magus-fs materialize --state /private/tmp/fs1-example/state --revision sha256:REVISION_HEX --destination /private/tmp/fs1-example/full
magus-fs checkpoint --state /private/tmp/fs1-example/state --operation-id operation:00000000000000000000000000000002
magus-fs status --state /private/tmp/fs1-example/state
```

`REVISION_HEX` is the 64-digit ID returned by capture. History includes each validated descriptor and its exact canonical JSON as `canonical_descriptor`; save that string without an extra newline for an import. `checkpoint` versions the engine's working branch and does not scan ordinary files. Supply `--expected-generation N` from status for a durable same-operation retry; omitting it uses the currently observed generation. Native application fsync concerns host bytes; an explicit capture is the local revision boundary. A dirty engine branch blocks capture instead of discarding it.

A fresh lazy replica needs a canonical descriptor and a source, with no native capture:

```sh
magus-fs init --state /private/tmp/fs1-example/lazy --config /private/tmp/fs1-example/config.json --revision-manifest /private/tmp/fs1-example/revision.json --source http://127.0.0.1:8765/objects
```

HTTP accepts numeric IPv4/IPv6 addresses with an explicit port only. Hostnames, HTTPS, redirects, credentials, queries and fragments fail the synthetic FS1 boundary. `file:///ABSOLUTE_OBJECT_STORE` selects an existing local immutable store. Descriptor import fetches zero bodies and records missing closure sizes. This proves usable lazy metadata/source configuration, not source availability, authenticated shared acceptance or offline readiness. The latest explicit Local/Http source updates shared-object registrations after transactional size checks; an Unavailable import never downgrades an existing endpoint.

Status exposes `captured_revision`, `working_generation`, `uncaptured`, `base_revision`, `resident_verified_bytes`, `missing_bytes`, `pinned_recovery_points`, and `ready_mode`. Uncaptured is `true` for dirty engine work, otherwise `"unknown"`: a previous capture cannot prove the current native folder is still clean. Full means the selected engine closure is verified resident; on-demand means usable selected metadata and recorded source configuration without complete residency. Missing bytes count unique complete objects, so repeated chunks do not double-count. No shared/remote success is implied.

## Selection, native identity and bounded generations

`CapturePolicy { included_roots, excluded_prefixes }` uses relative canonical paths with whole-directory-segment matching. `.` selects the root. Globs, `..`, absolute components, non-NFC and nonportable paths are refused. Structural ancestor directories are included. A missing included root fails; excluded roots remain outside the selected view. Selection is persisted in the owning SQLite journal and must match across invocations.

The scanner records device, inode, kind, size, nanosecond modification/change times, ownership, mode, link count and complete observed directory names before hashing. It retains no-follow descriptors through the attempt, installs fixed262144/SHA-256 chunks, and rescans the complete observed selection before committing. File, rename or directory changes retry, with at most three attempts in one 30-second budget, then `unstable_capture` and no head advancement. A stable unsupported generation instead returns its inventory. Blocking native filesystem I/O retains OS semantics; checks occur between native calls. This validates observed generations, not a semantic transaction across independent programs or an adversary who invisibly restores every observed value.

Entry identity is preserved only when the prior successful scan in this same replica matches the same path's device/inode/kind and the working tree still contains that recorded identity there. Changed identity or kind creates a new EntryId. Unobserved renames are delete/create; equal bytes, path and timestamps alone never infer continuity. Across scans/restarts, native inode reuse can be indistinguishable without a stronger host identity facility. The implementation documents that limit and fails conservatively on observed conflicts. Failed candidate identity evidence is retained transactionally with its operation so an unchanged retry can complete; changed observations/payload reject `operation_mismatch`.

V1 provenance is the reviewed `native_scan_delete_create`. Coverage contains canonical effective selected-frontier paths; exclusions expand a root into disjoint selected subtrees. Empty coverage selection records root metadata using `""`. Coverage describes the captured selected view, not proof of complete host-root coverage or authorization to delete excluded/missing paths. Exact include/exclude configuration stays in the local native record. FS2 publication must combine scoped changes safely and never infer deletion outside the captured scope.

## Metadata and staging contract

Regular files/directories, empty directories, binary bytes, logical owner/group and rwx including executable bits are supported. Symlinks, hardlinks (`nlink > 1`), non-UTF8/non-NFC/nonportable names, portable Unicode case-fold collisions, special files, extended ACLs, special mode bits and unsupported xattrs are inventoried and refused. Inventory traverses even unsupported directory names; it does not silently skip their children. Portability uses the reviewed normalization17/folding16 policy. Materialization additionally creates the complete target namespace with exclusive fd-relative operations before writing bytes, detecting actual target filesystem aliases without overwrite.

**macOS `com.apple.provenance` has one explicit host-local disposition.** Capture/materialization observe and report the exact name, value length and `host_local_nonportable_observed_only` disposition. They leave the source/OS-created destination attribute untouched; they never delete, synthesize or replay it. Its opaque value is not logged or bound into portable v1 metadata, and it is neither authentication nor a fidelity/security claim. The qualified ordinary round trip observes 11-byte values. Only this exact attribute on macOS has this exception; quarantine, resource forks, FinderInfo, arbitrary xattrs and ACLs remain refused. Linux has no such exception.

Materialization authorizes historical entry identities against current live metadata and ancestry, stages verified full bytes, reads the actual staged extents back, applies and rechecks exact mapped UID/GID/mode, synchronizes, and publishes with no-replace native rename. Current revocation/identity absence denies restoration. Supported metadata failure or missing/corrupt bodies never produces an announced ready destination. Newly created stage wrappers are private and kept outside content, with an atomically replaced `ownership.json` plus the engine's recovery row. The row records owned native identity before the first manifest write. Inherited unsupported ACL/xattrs on the stage control directory block before any lazy body hydration; if manifest writing fails, the journal retains the failed stage ownership proof. They record staging device/inode, intended destination and (once prepared) content device/inode. Status is `staging`, `prepared`, `failed` or `ready`; errors are typed. A crash can leave prepared output published but unacknowledged: validate recorded native ownership and closure before recovery, never infer readiness merely from a pathname. Task4 exposes recovery evidence and intentionally performs no automatic cleanup or resume. Successful wrappers also remain as owned provenance records. Only explicitly test-owned paths are removed by the harness.

## Exact new core APIs

```rust
Replica::reopen(state: impl AsRef<Path>) -> Result<Replica, FsError>
Replica::configure_native(config: NativeConfig) -> Result<(), FsError>
Replica::native_config() -> Result<Option<NativeConfig>, FsError>
Replica::native_metadata_diagnostics() -> Result<Vec<NativeMetadataDisposition>, FsError>
Replica::capture(root: impl AsRef<Path>, policy: CapturePolicy,
                 operation: OperationId, actor: Actor) -> Result<RevisionId, FsError>
Replica::materialize(revision: &RevisionId, destination: impl AsRef<Path>,
                     mapping: MaterializationMapping) -> Result<MaterializationResult, FsError>
Replica::materialization_recovery() -> Result<Vec<MaterializationRecovery>, FsError>
CapturePolicy::validate() -> Result<(), FsError>
ChunkSource::validate() -> Result<(), FsError>
```

`NativeConfig { root, policy, creation_umask }`; `MaterializationMapping { actor }` selects trusted local authorization while persisted `ReplicaConfig.authorities` supplies logical→host UID/GID. `MaterializationResult { revision, destination, verified_bytes }` reports logical bytes including verified explicit holes. `UnsupportedEntry { path, reason }` is exposed through `FsError::UnsupportedEntries(Vec<UnsupportedEntry>)`. Added body-free codes are `unstable_capture`, `unsupported_entries`, `mapping_blocked`, `dirty_working_state`, `target_collision`. Existing engine/model/source/GC policy remains binding. Reopen loads persisted config after obtaining the same guarded private control-root and single-owner lock; no sidecar parser or second authority exists.

## Reproduce native qualification

```sh
cargo test --locked -p magus-fs-core --test capture --test materialize
cargo build --locked -p magus-fs
python3 -m unittest discover -s tests/fs1 -p test_cli.py
cargo build --locked -p magus-fs --features test-faults
MAGUS_TEST_FEATURES=test-faults python3 -m unittest discover -s tests/fs1 -p test_cli.py
docker build --pull=false --progress=plain -f tests/fs1/Dockerfile.local -t fs1-task4-local .
```

The Dockerfile copies the new CLI crate with the workspace and executes actual Linux Rust/core and nonroot ordinary-file CLI tests; it installs no host driver, changes no host security setting, and creates no mount. Fault controls exist only in nondefault `test-faults`; normal CLI arguments expose none. Tests exercise owned subprocess barriers at both observation and hashing boundaries, failed commit replay, manifest replacement, metadata inventory, ownership refusal and native aliases. Native mount and final V1–V12 acceptance remain later tasks.
