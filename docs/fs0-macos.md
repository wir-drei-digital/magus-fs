# FS0 macOS NFS candidate — incomplete qualification

This is an isolated synthetic feasibility probe. It is not a filesystem product release, production writable on-demand client, multi-user authentication service, or qualified live FS2 adapter. The manifest is verified and pinned when connecting. An optional `--expect-digest SHA256` additionally pins an externally expected identity; hashing alone does not authenticate an untrusted HTTP service.

## Reproduce

Rust is pinned to 1.92.0 in rust-toolchain.toml. On the qualification host the installed `stable` alias is exactly that compiler; check `RUSTUP_TOOLCHAIN=stable rustc --version --verbose` before using the override. Do not change the global toolchain. Cargo.lock pins the dependency graph.

```sh
RUSTUP_TOOLCHAIN=stable cargo build --locked
RUSTUP_TOOLCHAIN=stable cargo test --locked
python3 -m unittest discover -s tests/fs0 -p 'test_*.py'
python3 tests/fs0/macos_run.py --output /private/tmp/REPLACE-WITH-UNIQUE-FS0-PATH
```

The output path must be new and absolute. The runner owns a synthetic source, dedicated loopback NFS endpoints and new mount directories, captures commands/outcomes, runs ordinary Python syscalls with time bounds, and retains reports. `--prepare-only` prints the exact mount command and waits for a human to mount it. A failed unmount retains the server and prints only the exact owned cleanup path. Never delete an output directory while it contains a mount. The runner always returns incomplete qualification (exit 2) until the separate generation/handle/failure gates are integrated; a registered mount is never an overall pass.

Manual CLI interfaces:

```sh
# ROOT and MOUNTPOINT must be new; SOURCE is the URL printed by source.
target/debug/magus-fs-probe source --root ROOT
target/debug/magus-fs-probe mount --backend nfs --source SOURCE --mountpoint MOUNTPOINT --mode ro --prepare-only
target/debug/magus-fs-probe mount --backend nfs --source SOURCE --mountpoint MOUNTPOINT --mode private --backing NEW-ABSOLUTE-BACKING --prepare-only
```

Without `--prepare-only`, the CLI starts the endpoint and attempts the printed mount command, leaving the endpoint available after a mount error. Readiness JSON includes PID, loopback port, fixed UID/GID, source digest, hydration bytes, exact mount argv and path. There is no privileged driver installation, sudoers change, portmapper registration or public listener. macOS provides `/sbin/mount_nfs`. `RUST_LOG=nfsserve=debug` enables opt-in protocol diagnostics; use synthetic data only because upstream debug tracing can include request bytes.

Private mode requires a new owned mode0700 backing directory. Explicit `--resume-backing` reuses a directory whose manifest marker matches the source digest; it never silently reinitializes an existing directory. Keep its `tree/` and `manifest.json` together. Restart still needs the manifest source; disconnected startup is not implemented. Host contents are trusted, invocation-owned test resources, not a hostile local-user boundary.

## Inspected nfsserve 0.11.0 contract

| Surface | Finding and candidate decision |
|---|---|
| Request identity | `rpcwire.rs` parses AUTH_UNIX into private RPCContext; NFSFileSystem receives no request actor. Adapter uses process effective UID/primary GID for every request; forged UID0 does not override the fixed actor. Loopback is not local multi-user authentication. Supplementary group policy and general multi-user permissions are unqualified. |
| Readonly | `ReadOnly` capability rejects mutation RPCs; every adapter mutation callback also rejects readonly mode. Raw WRITE, SETATTR size/mode, REMOVE and RENAME are tested directly with several forged credentials, independently of kernel readonly flags. |
| ACCESS | Upstream returns requested access bits, masking readonly to READ/LOOKUP, without full mode checks; it is not an authorization oracle. Adapter enforces reads, traversal and private writes itself. Execute/access presentation needs native qualification. |
| Stability | `nfs_handlers.rs` always returns FILE_SYNC after successful `vfs.write`, ignoring requested stability. Connecting the ephemeral Probe write overlay would be false durability and is rejected. |
| COMMIT | Procedure21 returns RPC PROC_UNAVAIL; wire test confirms it. Whether macOS avoids it after FILE_SYNC is still unrun. |
| Private backing | Fully hydrate the bounded fixture through verified Probe reads. Existing-file writes and supported setattr operations call fsync plus macOS F_FULLFSYNC before success. Initial files, marker and directories are synchronized. SIGKILL/resume proves process-crash persistence, not a power-cut test or storage-hardware guarantee. |
| Namespace | Private create/unlink/rename/mkdir/symlink are deliberately unsupported in this bounded candidate. It cannot pass editor replacement-save semantics yet. No SQLite, history, revision journal or sync protocol is introduced. |
| Handles | Pinned readonly handles bind the manifest prefix and stable fixture ID. No OPEN/CLOSE callbacks exist, so no per-open generation guarantee is claimed. Private fixed namespace reuses IDs only for the same pinned fixture; no replacement/unlink lifecycle is implemented. |
| Cache/live changes | NFSv3 has no callback invalidation here. Mount requests actimeo0; kernel effective flags must be captured. Raw generation-switch test proves an existing endpoint stays pinned while a new endpoint sees new permissions. It does not prove live native cache convergence or FS2 suitability. |
| Locks | Candidate requests nolocks. Any observed same-host advisory behavior is separate from distributed lock guarantees; no server lock manager is implemented. |
| Bounds/concurrency | Probe HTTP is synchronous and bounded; its Axum server owns a separate runtime. NFS uses four worker threads, with synchronous reads serialized by the Probe mutex. This is bounded synthetic instrumentation, not a throughput or adversarial RPC hardening claim. |

Readonly range mode stays on demand. Private mode eagerly downloads the entire synthetic tree (about64MiB); readiness reports actual fetched bytes. This is a compatibility/durability experiment, not proof of writable lazy hydration. FS1 must combine lazy reads and durable private changes.

## Observed macOS result, 2026-10-09

Host: Darwin arm64, macOS26.5.2; rustc1.92.0; Python3.14.7. Real mount_nfs returned0 without sudo for two uniquely owned readonly mounts. Root and file stat returned source UID501/GID20/mode0644 (root0755). However Python open/listdir and independent `/bin/cat` and `/bin/ls` timed out. The protocol trace shows successful LOOKUP and GETATTR, then no READ/READDIR request. Identical timestamp-zero metadata is returned, not a changing timestamp. Raw RPC reads continue to pass. Root cause remains unresolved; no native read/write/readonly/permission gate passes from these facts.

An attempted generic mount update returned0 but did not change effective actimeo; it briefly cleared the client readonly flag and the flag was immediately restored. Server readonly enforcement remained active throughout. This was not a successful cache-option experiment. Original effective options include rdirplus already, so no unsupported-READDIR explanation is established.

Ordinary unmount timed out after5seconds; force unmount returned EPERM. Exact owned resources and subsequent cleanup outcomes are recorded in the task report. Native mmap/locks/old handles, incoming-generation/cache visibility, private write/fsync and failure/recovery scenarios are not-run because ordinary access stalls. `ordinary_io.py` includes those runnable basic scenarios and records errno/outcomes; unsupported private rename/create remains an explicit failure, never skipped as pass.

## Bounded next decision

First resolve or isolate the native open/readdir stall with protocol/syscall evidence, keeping existing resources bounded. If this NFS candidate remains incompatible, reject it and qualify a macOS FUSE adapter against the same Probe. Any driver installation requires a separate explicit user action. If private NFS works, extend only the minimum native-backed create/rename/unlink lifecycle needed for ordinary replacement-save, retaining old host file descriptors for old handles and synchronizing namespace directories. Do not replace FS1 with an ad hoc persistence engine. Live FS2 suitability requires a separate invalidation/handle design; pinned mount success would not prove it.

## Dependency/distribution facts

nfsserve0.11.0 declares BSD-3-Clause and no MSRV. Direct async-trait0.1.89 declares MIT/Apache-2.0; tracing-subscriber0.3.23 declares MIT. Tokio/serde/ureq and their locked dependencies remain from the fixture probe; libc is explicit for effective actor identity and macOS full sync. Exact transitive versions/checksums are in Cargo.lock. This inspection is not a legal review. The repository has not selected its own redistribution license and grants no runtime release license here. There is no package/install claim.
