# FS1 macOS durable on-demand NFS

The macOS `magus-fs mount` transport uses the same Replica/Workspace engine, verified chunk store and FULL SQLite working transactions as Linux. There is no eager private host-tree backing. Descriptor import, directory enumeration and handle issuance fetch no content bodies. Partial writes preserve uncached base extents; unavailable slices fail rather than becoming holes. NFS WRITE success is issued only after the engine's durable working commit, matching the dependency's FILE_SYNC response. Native buffered writes still require successful fsync for an application durability boundary. A checkpoint is a separate local revision operation, never shared publication.

## Build and qualify

The pinned toolchain is Rust1.92.0. On this host `stable` is that exact version; verify before using the override. The acceptance fault binary is separate from the default binary; fault instrumentation is not enabled in the normal mount.

```sh
RUSTUP_TOOLCHAIN=stable rustc --version --verbose
RUSTUP_TOOLCHAIN=stable cargo build --locked -p magus-fs --features test-faults
cp target/debug/magus-fs target/debug/magus-fs-faults
RUSTUP_TOOLCHAIN=stable cargo build --locked -p magus-fs
python3 -m unittest discover -s tests/fs1 -p test_macos_wire.py
python3 tests/fs1/macos_run.py --output /private/tmp/REPLACE-WITH-NEW-FS1-PATH
```

Use a new absolute output path with an existing parent. Keep it short enough for macOS Unix-domain socket paths. `MAGUS_FS_BIN` and `MAGUS_FS_FAULT_BIN` may select explicit binaries. Outputs retain source hashes and compiler/fixture inputs, the actual binaries and hashes, descriptors, synthetic object source/state, commands, native errno/byte/hash observations, OS/NFS options and cleanup evidence. Exit0 requires the implemented native assertions and confirmed cleanup, exit1 records observed failure, exit2 means missing prerequisites. A real foreign-kernel-UID control probe is separately blocked on this host by existing noninteractive sudo policy; it is not represented as a passed native assertion.

The wrapper reuses the qualified FS0 supervisor: a600-second deadline and5-second reporting grace. It signals the native runner alone, never its serving process group. Failed normal unmount leaves the runner, source and endpoints alive with exact owned recovery instructions. No force-unmount, deletion through a live mount, privileged driver or host security change is part of the workflow.

## Mount and owner controls

Initialize/capture or import a revision with the existing [local CLI](fs1-local.md). Configuration must explicitly include the intended mountpoint among `content_roots`; private state must remain outside every content root. The mountpoint must be new. The process UID must map to a configured logical actor.

```sh
target/debug/magus-fs mount --state /private/tmp/example-state \
  --revision sha256:REPLACE_WITH_REVISION --mountpoint /private/tmp/example-view \
  --mode private
```

The foreground command starts a loopback NFS endpoint and invokes mount_nfs with `nosuid,nodev,locallocks,vers=3,tcp,rsize=65536,wsize=65536,actimeo=1,soft,timeo=10,retrans=2` plus exact endpoint ports and rw/ro. `--mode read-only` makes all content, namespace and metadata mutations fail, including server-time requests. Local advisory locks are client-local; no distributed lock service is provided.

On macOS, `--prepare-only true` **starts and keeps the real NFS server and private control channel running**, creates the empty mountpoint and prints JSON containing `mount_command`; it does not invoke mount_nfs. This is for an external owner/supervisor that registers the mount before starting it. It is not a validation-only command. Optional `--nfs-port PORT` is accepted only with preparation and binds the numeric loopback port; the default is a fresh OS-assigned port. Default and prepared servers remain foreground until their owner terminates them after confirmed unmount. Empty mountpoint removal is the owner's responsibility.

Mounted `status`, `history`, and `checkpoint` use the existing CLI command syntax and the same owning Replica through state/control.sock. The channel checks actual macOS `getpeereid` credentials on both ends, requires the effective owner UID, rejects extra request fields, and uses a0700 state directory and0600 owned socket. A regular file, unsafe socket or live existing endpoint is not removed. A stale owned socket is reclaimed only while holding the engine ownership lock. A readonly mount also denies checkpoint through this private channel. The NFS actor and control peer have distinct jobs: NFS is one trusted configured workspace actor; AUTH_UNIX wire UIDs never select a stronger actor. Loopback is not multi-user authentication.

## Identity, permissions and retention

Opaque handles combine a random daemon-session nonce with a monotonically assigned entry ID. Wrong nonce/unknown IDs fail. Authorized file handles retain an engine Handle, binding exact EntryId, Workspace and opening generation, for the entire daemon lifetime. Mutable handles follow edits to that identity, not a reused pathname. Unlink/replacement leaves the old issued identity available and does not resurrect its path. Historical workspaces bind their immutable revision but continue to use current identity/path authority. No OPEN/CLOSE callback is invented.

Current shared permission checks apply to ACCESS, lookup, read/write and metadata mutation. Directory names can be enumerated without search, but child GETATTR/READDIRPLUS optional attributes/handles and FSINFO attributes remain absent when traversal is denied. DELETE uses writable/searchable parent authority rather than target write mode. REMOVE(directory) and RMDIR(file) fail without namespace effects. Creation applies the persisted umask; uid/gid attributes must agree with the fixed configured creation identity. Unsupported attrs are rejected before creation.

Retention is conservative: one capability per authorized issued file, plus its opening generation and current open-unlinked version, stays live until server exit. These remain core prune roots, so closed native descriptors cannot release cache roots during that mount. Namespace identity and timestamp maps also last for the session. The cost grows with all identities issued during a mount, including deleted/replaced entries; cache pressure may return ENOSPC/backpressure. This is a bounded qualification mount policy, not a scalable garbage-collection or per-open lifecycle claim.

NFSv3 EXCLUSIVE-create verifier semantics are not implemented and return NOTSUPP. Qualified Darwin falls back to GUARDED CREATE. The engine atomically creates only absent names; native O_EXCL duplicate and simultaneous guarded requests preserve the existing identity/bytes. The vendor patch only adds defaulted mkdir-attrs and typed directory-removal hooks to the existing audited permission delta; [provenance](../vendor/README.md) remains reconstructible against unchanged upstream checksums/license.

## Session timestamps and host metadata

Darwin sends SET_TO_SERVER_TIME in both its exclusive-create follow-up and guarded CREATE. The qualified adapter projects real server-wall-clock atime/mtime/ctime for this daemon session. Unchanged entries stay stable; successful supported mutations update relevant projected times, DONT_CHANGE preserves values, and client-chosen times fail before any mutation. Standalone server-time updates require current write authority or logical ownership; retaining an identity with bits0 grants neither. Readonly denial is absolute.

These are NFS session observations/cache metadata. They reset after daemon restart and are **not original timestamps, durable revision fields, archive timestamp fidelity or restored historical times**. Canonical v1 descriptors and revision IDs are unchanged by this compatibility projection. Mode/owner/data/namespace durability remains in the shared engine. General combined setattr, client timestamps, hardlinks, symlinks, arbitrary xattrs/ACLs and multi-host locks are outside this qualification; rejected operations are not claimed as supported.

macOS may create ordinary `._` AppleDouble files to store its com.apple.provenance metadata on NFS. The adapter preserves these actual writes and includes them in working revisions. The harness records their names, exact byte hashes and modes before crash and verifies them after restart; it does not strip sidecars or hide closure differences. The host's original com.apple.provenance attribute remains observation-only for native capture, as documented in fs1-local.md. Other unsupported native xattrs/ACLs retain capture-failure semantics.

## Crash recovery qualification

Before killing a mounted endpoint, all workload children exit after acknowledged operations and the native runner starts and records an owned recovery watcher. The watcher starts a **separate cleanup-only Replica** on the exact old loopback port after the old process exits. Its preinitialized configuration references only local fixture storage and never-mounted recovery roots; its empty readonly tree has mode0000 and grants no useful content access. It does not read or reopen the crashed state. The adapter's fresh session nonce makes old handles return STALE70 rather than aliasing lost capabilities. The cleanup endpoint continues serving until normal unmount of the old kernel view succeeds, then terminates. Only then does a fresh actual-state mount verify acknowledged bytes, modes, namespace absence, generation/head and checkpoint retry.

This ordering is necessary: reopening the actual Replica while its dead served root remains mounted can time out in the shared native content/control separation checks (observed macOS errno60). Earlier cached successes are not a reliable restart mechanism. No root check is skipped and no timeout is treated as safe. Operational restart requires supervised cleanup/unmount first; seamless process/descriptor continuation and future live handoff remain outside this qualification.

The real adapter's exact-port/stale behavior is first qualified against an unmounted RPC endpoint; the empty cleanup-only fixture is also checked before native interruption. Native tests then kill mounted daemons after fsync/before checkpoint and after checkpoint acknowledgment. This is process-loss evidence, not a physical power-cut guarantee. On unresolved unmount the cleanup endpoint and source stay alive, and the supervisor returns failure with exact recovery evidence. No new workload or native mount may consume the cleanup namespace.
