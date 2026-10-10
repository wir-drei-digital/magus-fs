# FS2-A full native folders

A configured native folder runs background capture, publication and incoming regular-file application through `magus-fs sync run --state STATE --serve true`. Use `magus-fs sync status --state STATE` for separate local/private/shared progress, current live state and `native` readiness/displacements. The same private owner control channel serves these commands while the daemon runs.

Start with ordinary files whose bytes and mapped metadata match the attached view; Core verifies that inventory before watching. Mismatched initial files fail closed. Initial directory materialization is a separate operation, and this application path does not force a remote tree over an arbitrary existing directory.

Native `notify = 8.2.0` events schedule scans after100ms; a scan runs every2s and immediately at startup or after overflow. Events never suppress capture by pathname or elapsed time. Incoming authenticated metadata/log polling runs every1s even without WSS hints. Capture/admission, publication and incoming advancement share `SyncExecution`; Core's mutex is not held across remote fetches. A capture interrupted before queue admission is re-enqueued with its original operation and attached base before capturing a later generation. Existing pending descriptors are never rebased.

Core remains the only journal, capture, permission and native-application owner. Files are ordinary filesystem files and remain usable after the owner process exits. A full folder cannot revoke access to plaintext already available through the host filesystem; remote authority checks protect Core and service operations, not offline direct OS reads.

## Application contract

`Replica::apply_native_revision(&RevisionId, u64, OperationId, Actor)` and `apply_native_view(SyncBinding, u64, OperationId, Actor)` return `Result<NativeApplyStatus, FsError>`. Status is `Ready { revision }`, `Pending { reason }`, `Unstable { reason }`, or `ApplyBlocked { reason }`. Current native state and retained displacement paths are available through `native_status()` and the active verification operation `scan_native_status()`.

Only regular-file creation and exchange beneath existing directories are implemented. Deletion, directory creation/movement, changed logical identities at existing paths, ownership/mode changes and unsupported native metadata are retained as blocked work. A missing expected file is not deletion authorization. Root and directory identity checks use no-follow directory descriptors. Staging is in the replica's private control directory, outside content, and must be on the same device. Unsupported exchange/no-replace primitives fail without overwrite fallback.

The intent and original generation precede the filesystem mutation. macOS uses `renameatx_np` with `RENAME_SWAP`/`RENAME_EXCL`; Linux uses `renameat2` with `RENAME_EXCHANGE`/`RENAME_NOREPLACE`. The displaced native generation stays in private staging. Its baseline observation and digest come from the same read that verified the old canonical bytes; later observations cannot silently replace that verified baseline. Its identity, metadata and bytes, the installed target, and the final folder inventory are checked before committing the native baseline, working revision, binding and any matching applied receipt in one SQLite transaction. No hard links join writable generations. A racing unexpected displacement is retained and cannot become Ready. Recovery uses the original operation/generation and never unlinks a replacement it cannot identify as its own.

Application of multiple files is sequential. Ordinary programs may observe a mixture during application; this is not an atomic directory snapshot. Readiness verifies the current pathname generation at the observation boundary. It does not promise that another process lacks a stale file descriptor or cached RAM buffer, or that a subsequent write cannot occur.

## Capture and retained writes

`capture_native_changes(OperationId, Actor)` rescans without relying on event delivery. It skips a new checkpoint only when native identity/metadata and verified bytes match the baseline. An in-place save retains its canonical EntryId; an unknown atomic-save replacement keeps FS1 delete/create semantics. A verified application commits new native identities against the accepted canonical IDs, avoiding an echo checkpoint.

`scan_native_status()` scans retained displaced inodes as well as current content. A late old-FD write clears applied readiness, marks unknown causality and copies an observed version into a separate retained file. An unresolved retained write blocks a later application from making a new Ready claim. These separately addressable pending alternatives retain their original application operation, path and version paths across owner restart. Every persisted native status rebuilds this enumeration from durable intents, including when a later application is rejected. That operation links to the durable original base, native generation and canonical EntryId in the owner intent. They are not canonical captured revisions or private-remote receipts. Explicit promotion/reconciliation and richer conflict inspection belong to FS2-B; the engine never invents base-aware causality for an old descriptor write.

Admission stops at 512 MiB or 128 retained/staged generations instead of deleting evidence. External writers can grow an inode through an already-open FD; the next scan reports backpressure and preserves it. This is an admission/retention policy, not an OS quota on other processes. Metadata-only observation is insufficient: the Linux gate reproduced same-size writes with indistinguishable timestamps, so bytes are checked too.

`recover_native_application(Actor)` retries exact retained application intents. `verify_native_baseline(Actor)` can establish the initial observed inventory only from matching bytes and mapped metadata. Both operate through Core's existing owner. Remote fetch callbacks for application run outside its mutex, and fetched bytes are verified before cache installation and native mutation. Incoming revisions and original bases are GC roots. Existing queue records and immutable source identities are preserved.

## Reproduce the native gates

From this checkout, with the existing Rust 1.92.0 toolchain:

```sh
RUSTUP_TOOLCHAIN=stable cargo test --locked -p magus-fs-core --test native_apply --features test-faults
python3 tests/fs2/full_native.py --output /private/tmp/NEW_FULL_OUTPUT
python3 tests/fs2/full_native.py --case supplement --output /private/tmp/NEW_RESTART_OUTPUT
python3 tests/fs2/full_native.py --case retention --output /private/tmp/NEW_RETENTION_OUTPUT
```

The full harness uses macOS ordinary files and a separate unprivileged Linux client container against the actual authenticated HTTPS service, PostgreSQL and S3 fixture. It verifies dropped native hints/rescans, in-place and atomic saves, no echo or needless own-acceptance rewrite, atomic exchange/no-replace, retained late descriptor writes, owner-process crash recovery, editor/parent/symlink races, frozen dirty candidates, readonly parents and blocked directory creation. The supplemental gate verifies unchanged-endpoint transport recovery and exact retained alternatives after owner restart. The retention gate writes through a held FD at the displaced-verification/baseline barrier and checks alternative bytes, rejected-apply enumeration and owner restart on both platforms. `--platform macos|linux` selects one platform; `--case permissions` probes only readonly/structural application. Outputs must be new absolute paths. The default complete journey has a600s bound plus bounded setup/cleanup; missing prerequisites return2, failed assertions1, and success0.

All source/dependency/image/binary hashes, actual byte/status evidence, failed results and exact owned cleanup are retained by the harness. Fault instrumentation is compiled only with `test-faults`; the default binary cannot enable the omitted-event or crash barriers. `tests/fs2/native_core.py` remains an independent Core-only gate and does not substitute for the service journey.

The native status distinguishes Pending, Unstable and ApplyBlocked using safe error codes. A transient discovery failure clears native readiness and forces re-verification when the service recovers, including when the remote head is unchanged. This is not a claim that disconnected capture/publication or arbitrary editor recovery has been fully qualified. General namespace/metadata application, broader editor/stale-RAM compatibility and disconnected reconciliation remain FS2-B gates.
