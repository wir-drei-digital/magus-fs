# FS0 macOS NFS candidate — controlled native qualification

This is an isolated synthetic feasibility probe. It is not a filesystem product release, production writable on-demand client, multi-user authentication service, or qualified live FS2 adapter. The manifest is verified and pinned when connecting. An optional `--expect-digest SHA256` additionally pins an externally expected identity; hashing alone does not authenticate an untrusted HTTP service.

## Reproduce

Rust is pinned to 1.92.0 in rust-toolchain.toml. On the qualification host the installed `stable` alias is exactly that compiler; check `RUSTUP_TOOLCHAIN=stable rustc --version --verbose` before using the override. Do not change the global toolchain. Cargo.lock pins the dependency graph.

```sh
RUSTUP_TOOLCHAIN=stable cargo build --locked
RUSTUP_TOOLCHAIN=stable cargo test --locked
python3 -m unittest discover -s tests/fs0 -p 'test_*.py'
python3 tests/fs0/macos_run.py --output /private/tmp/REPLACE-WITH-UNIQUE-FS0-PATH --chunk-size 262144 --uid 501 --gid 20
```

The output path must be new and absolute. The runner owns a synthetic source, dedicated loopback NFS endpoints and new mount directories, captures commands/outcomes, runs ordinary Python syscalls with time bounds, and retains reports. Candidate paths are registered before command launch; command children are owned and stopped/reaped on interruption. A pending child, active mount or unknown mount-table status retains the servers. Cleanup consults the mount table with a bounded command instead of stat into a stalled mount. `--prepare-only` prints the exact mount command and waits for a human to mount it. A failed unmount retains the server and prints only the exact owned cleanup path. Never delete an output directory while it contains a mount. The runner returns0 only after all controlled native stages and owned cleanup pass; observed failures return1. It records `result.json`. This single-profile result does not complete the combined FS0 matrix or qualify live FS2 behavior. The ordinary stages use a fresh `actimeo=1,locallocks` mount and verify current effective options; raw CLI readiness retains its original conservative mount argv, and both prepared/actual argv are recorded.

Manual CLI interfaces:

```sh
# ROOT and MOUNTPOINT must be new; SOURCE is the URL printed by source.
target/debug/magus-fs-probe source --root ROOT
target/debug/magus-fs-probe mount --backend nfs --source SOURCE --mountpoint MOUNTPOINT --mode ro --prepare-only
target/debug/magus-fs-probe mount --backend nfs --source SOURCE --mountpoint MOUNTPOINT --mode private --backing NEW-ABSOLUTE-BACKING --prepare-only
```

Without `--prepare-only`, the CLI starts the endpoint and attempts the printed mount command, leaving the endpoint available after a mount error. Readiness JSON includes PID, loopback port, fixed UID/GID, source digest, hydration bytes, exact mount argv and path. There is no privileged driver installation, sudoers change, portmapper registration or public listener. macOS provides `/sbin/mount_nfs`. `RUST_LOG=nfsserve=debug` enables opt-in protocol diagnostics; use synthetic data only because upstream debug tracing can include request bytes.

Private mode requires a new owned mode0700 backing directory. Explicit `--resume-backing` reuses a directory whose manifest marker matches the source digest; it never silently reinitializes an existing directory. Keep its `tree/`, `manifest.json` and `permissions.json` together. The host tree is internal storage (directories0700/files0600), not an exported permission-faithful native tree. Digest-bound exported modes are initialized from the manifest and stored in the permissions snapshot; both attributes and authorization use those modes, independent of umask. An acknowledged chmod0444/0200/0000 therefore does not remove the daemon’s internal access on restart. Pre-fix disposable FS0 backing without permissions.json is rejected explicitly; no migration or FS1 format is implied. Restart still needs the manifest source; disconnected startup is not implemented. Host contents are trusted, invocation-owned test resources, not a hostile local-user boundary.

## Inspected nfsserve 0.11.0 contract

| Surface | Finding and candidate decision |
|---|---|
| Request identity | `rpcwire.rs` parses AUTH_UNIX into private RPCContext; NFSFileSystem receives no request actor. Adapter uses process effective UID/primary GID for every request; forged UID0 does not override the fixed actor. Loopback is not local multi-user authentication. Supplementary group policy and general multi-user permissions are unqualified. |
| Readonly | `ReadOnly` capability rejects mutation RPCs; every adapter mutation callback also rejects readonly mode. Raw WRITE, SETATTR size/mode, REMOVE and RENAME are tested directly with several forged credentials, independently of kernel readonly flags. |
| ACCESS | A pinned local patch delegates to a default-denying policy hook. The adapter evaluates current durable modes and ancestor traversal for the fixed actor. Readonly protocol masking removes mutation bits while retaining authorized EXECUTE. GETATTR checks ancestor search; READDIRPLUS omits child attributes/handles when that check fails. Direct0755 execution and0644 denial,0400 directory names-only and0100 search-only all have native proof. See [vendor provenance and small patch](../vendor/README.md). |
| Stability | `nfs_handlers.rs` always returns FILE_SYNC after successful `vfs.write`, ignoring requested stability. Connecting the ephemeral Probe write overlay would be false durability and is rejected. |
| COMMIT | Procedure21 returns RPC PROC_UNAVAIL; wire test confirms it. Native write/fsync/readback and remount persistence passed with FILE_SYNC backing; the observed private trace contains no unimplemented COMMIT request. No general COMMIT support is claimed. |
| Private backing | Fully hydrate the bounded fixture through verified Probe reads. Existing-file writes call fsync plus macOS F_FULLFSYNC before success. Mode changes write and fully synchronize a staging permissions snapshot, atomically rename it, synchronize the containing directory and full-sync again before in-memory publication or a success reply. Pre-rename failures preserve the prior snapshot and mode; a storage failure after rename has an uncertain old-or-new complete snapshot outcome and returns an error, not a rollback or success promise. Initial files, marker and directories are synchronized. SIGKILL/resume proves process-crash persistence, not a power-cut test or storage-hardware guarantee. |
| Namespace | Private create/unlink/rename/mkdir/symlink are deliberately unsupported in this bounded candidate. It cannot pass editor replacement-save semantics yet. No SQLite, history, revision journal or sync protocol is introduced. |
| Handles | Pinned readonly handles bind the manifest prefix and stable fixture ID. No OPEN/CLOSE callbacks exist, so no per-open generation guarantee is claimed. Private fixed namespace reuses IDs only for the same pinned fixture; no replacement/unlink lifecycle is implemented. |
| Cache/live changes | NFSv3 has no callback invalidation here. The controlled runner requests and verifies actimeo1. Native old descriptors/mmap/mount stay pinned after a gateway publishes a changed manifest; a fresh mount sees the new mode, while the old mount still presents its old mode beyond TTL. This is explicit lack of in-place generation adoption, not live convergence or FS2 suitability. |
| Locks | Raw CLI argv requests nolocks (observed errno45). The controlled runner uses documented locallocks and verifies strict child contention (exit75, EAGAIN/EWOULDBLOCK) on readonly/private mounts. This is same-client advisory locking only; no server lock manager or distributed lock guarantee. |
| Bounds/concurrency | Probe HTTP is synchronous and bounded; its Axum server owns a separate runtime. NFS uses four worker threads, with synchronous reads serialized by the Probe mutex. This is bounded synthetic instrumentation, not a throughput or adversarial RPC hardening claim. |

Readonly range mode stays on demand. Private mode eagerly downloads the entire synthetic tree (about64MiB); readiness reports actual fetched bytes. This is a compatibility/durability experiment, not proof of writable lazy hydration. FS1 must combine lazy reads and durable private changes.

## Observed macOS result, 2026-10-09

Host: macOS26.5.2 arm64, rustc1.92.0, Python3.14.7. Controlled native profile with256KiB source chunks passed21 stages. Enumeration fetched0 content bytes; cold4KiB head/tail requests fetched1,310,720bytes due to native read-ahead; warm repeat added0. A full64MiB scan matched an independently computed SHA-256. Private eager hydration was67,108,958bytes and is reported separately.

Actual syscalls prove metadata/ownership/modes, exact reads/EOF, readonly mutation denials, native0755 execution/0644 denial, group/other access, mode000 denial, independent directory read/search rights, mmap/old-descriptor private visibility, local locks, byte writes with fsync, truncate and chmod444 persistence through daemon stop/remount. Raw RPC tests additionally cover forged credentials/handles and readonly bypass. Private CREATE/rename replacement remain unsupported (EROFS); the harness reports successful **classification**, never successful replacement support. Old handles survive the failed replacement attempt because no replacement occurred.

A changed source manifest remains invisible to the pinned old mount/descriptors/mmap; a newly connected mount sees it. An injected owned source503 causes uncached native reads to fail EIO while the warmed tiny file remains readable; restoring the source permits exact reads again. This is a bounded failure observation, not disconnected-write or live-sync support. All13 mounts normally unmounted,15 owned serving/helper processes reaped, and independent mount-table/process inspection found none remaining.

Earlier stalled native reads were associated with a pending macOS Network Volumes TCC prompt for the responsible Codex/ChatGPT application. After the user granted that specific permission, the same snapshot binary/digest and TTL1 options passed ordinary read/list/unmount. No Full Disk Access, TCC database modification, privileged driver, sudoers change or password handling was used. Earlier timeout/failed-cleanup evidence remains in the task report; old resources were independently verified absent before new mounts.

Native permission tests subsequently exposed upstream ACCESS overgrant/undergrant and READDIRPLUS metadata leakage. The small pinned dependency patch closes those observed failures. Its maintenance cost is explicit: rebase/audit on dependency upgrades and rerun real native permission plus Linux build/tests. A general actor/authentication framework was not added.

## Runner integration contract

`run(output, prepare_only=False, chunk_size=262144, uid=501, gid=20)` and the matching CLI accept65536/262144/1048576 chunk sizes. The output must be fresh. Numeric fixture identity is a test-only canonical manifest projection through the existing shared helper; real Rust chunk bodies remain unchanged. Original/projected digests are recorded. Source counters count original Rust response payloads and exclude projection/control/network framing bytes.

`result.json` includes `state`, `passed`, `cases`, `commands`, `mounts`, `transfer`, `manifest_digest`, `fixture_identity`, `fixture_uid_gid`, `chunk_size`, `owned_token`, `owned_pids`, `revision`, `binary_sha256`, `environment`, `private_hydrated_bytes`, `generation_digests`, `cleanup`, `reaped`, `cleanup_errors`, `remaining_owned_resources`, and an `error` on failure. Cases carry `state`, `observed` or error/errno, and exact `command`; the readonly/private observations retain shared ordinary-case evidence. Commands retain name/argv/PID/return code or timeout and log paths. Mount records retain source manifest, prepared/actual argv, actual mount-table entry and current NFS options. Cleanup records must show every owned path absent and every recorded process reaped.

Transfer snapshots are `before`, `enumeration`, `cold`, `warm`, `full`, each with source byte/chunk/retry counters; `full_scan` contains actual bytes/hash and independent expected hash. No aggregate pass should be inferred from the runner exit alone. Task4 supervises each native profile in a separate session with a600-second deadline plus5-second reporting grace. Cleanup-pending returns aggregate failure while retaining the native runner/gateway; parent interruption requests guarded cleanup without terminating serving children. Exact ownership, logs and recovery instructions remain in sibling supervision evidence; see the combined runbook. Task4 now runs six fresh native Mac profiles and six Linux profiles, normalizes all required observations, and verifies exact cross-platform manifest identity. The final combined matrix passed; see [combined qualification](fs0-qualification.md). Readonly/private observations also record actual root UID/GID/mode separately: the daemon-mapped root501:20/mode0755 is outside the manifest digest. Do not rewrite old evidence to a later source revision.

## Dependency/distribution facts

nfsserve0.11.0 declares BSD-3-Clause and no MSRV. The local path patch preserves its license and records the exact published archive/source checksums; Linux Docker builds copy the vendor directory. Direct async-trait0.1.89 declares MIT/Apache-2.0; tracing-subscriber0.3.23 declares MIT. Tokio/serde/ureq and their locked dependencies remain from the fixture probe; libc is explicit for effective actor identity and macOS full sync. Exact transitive versions/checksums are in Cargo.lock. This inspection is not a legal review. The repository has not selected its own redistribution license and grants no runtime release license here. There is no package/install claim.
