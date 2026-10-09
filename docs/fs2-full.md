# FS2 full native folders — partial Core checkpoint

Task 5 is incomplete. This checkpoint adds the native Core APIs and their ordinary-file tests on macOS and Linux. It does not add a watcher, automatic publication, the full-folder service journey, or new CLI commands. `notify = 8.2.0` remains the approved dependency for the pending watcher work; it has not been installed here.

Core remains the only journal, capture, permission and native-application owner. Files are ordinary filesystem files and remain usable after the owner process exits. A full folder cannot revoke access to plaintext already available through the host filesystem; remote authority checks protect Core and service operations, not offline direct OS reads.

## Application contract

`Replica::apply_native_revision(&RevisionId, u64, OperationId, Actor)` and `apply_native_view(SyncBinding, u64, OperationId, Actor)` return `Result<NativeApplyStatus, FsError>`. Status is `Ready { revision }`, `Pending { reason }`, `Unstable { reason }`, or `ApplyBlocked { reason }`. Current native state and retained displacement paths are available through `native_status()` and the active verification operation `scan_native_status()`.

Only regular-file creation and exchange beneath existing directories are implemented. Deletion, directory creation/movement, changed logical identities at existing paths, ownership/mode changes and unsupported native metadata are retained as blocked work. A missing expected file is not deletion authorization. Root and directory identity checks use no-follow directory descriptors. Staging is in the replica's private control directory, outside content, and must be on the same device. Unsupported exchange/no-replace primitives fail without overwrite fallback.

The intent and original generation precede the filesystem mutation. macOS uses `renameatx_np` with `RENAME_SWAP`/`RENAME_EXCL`; Linux uses `renameat2` with `RENAME_EXCHANGE`/`RENAME_NOREPLACE`. The displaced native generation stays in private staging. Its identity, metadata and bytes, the installed target, and the final folder inventory are checked before committing the native baseline, working revision, binding and any matching applied receipt in one SQLite transaction. No hard links join writable generations. A racing unexpected displacement is retained and cannot become Ready. Recovery uses the original operation/generation and never unlinks a replacement it cannot identify as its own.

Application of multiple files is sequential. Ordinary programs may observe a mixture during application; this is not an atomic directory snapshot. Readiness verifies the current pathname generation at the observation boundary. It does not promise that another process lacks a stale file descriptor or cached RAM buffer, or that a subsequent write cannot occur.

## Capture and retained writes

`capture_native_changes(OperationId, Actor)` rescans without relying on event delivery. It skips a new checkpoint only when native identity/metadata and verified bytes match the baseline. An in-place save retains its canonical EntryId; an unknown atomic-save replacement keeps FS1 delete/create semantics. A verified application commits new native identities against the accepted canonical IDs, avoiding an echo checkpoint.

`scan_native_status()` scans retained displaced inodes as well as current content. A late old-FD write clears applied readiness, marks unknown causality and copies an observed version into a separate retained file. An unresolved retained write blocks a later application from making a new Ready claim. These retained versions are recovery evidence; their reconciliation/publication is not implemented by this checkpoint.

Admission stops at 512 MiB or 128 retained/staged generations instead of deleting evidence. External writers can grow an inode through an already-open FD; the next scan reports backpressure and preserves it. This is an admission/retention policy, not an OS quota on other processes. Metadata-only observation is insufficient: the Linux gate reproduced same-size writes with indistinguishable timestamps, so bytes are checked too.

`recover_native_application(Actor)` retries exact retained application intents. `verify_native_baseline(Actor)` can establish the initial observed inventory only from matching bytes and mapped metadata. Both operate through Core's existing owner. Remote fetch callbacks for application run outside its mutex, and fetched bytes are verified before cache installation and native mutation. Incoming revisions and original bases are GC roots. Existing queue records and immutable source identities are preserved.

## Reproduce this partial gate

From this checkout, with the existing Rust 1.92.0 toolchain:

```sh
RUSTUP_TOOLCHAIN=stable cargo test --locked -p magus-fs-core --test native_apply --features test-faults
python3 tests/fs2/native_core.py --output /private/tmp/NEW_ABSOLUTE_OUTPUT
```

The second command builds the pinned Rust Linux test image, runs ordinary native files in one owned container with networking disabled, records source/image/binary hashes, and cleans up that exact container. It is explicitly a Core API gate. It cannot substitute for the still-required `tests/fs2/full_native.py` real watcher/service journey on both systems.

Remaining Task 5 work includes notification/rescan scheduling, automatic capture and publication under `SyncExecution`, native status in private control/CLI, frozen restart handling, service-connected native proof, and full review. General namespace/metadata application, broader editor/stale-RAM compatibility and disconnected reconciliation remain early FS2-B work.
