# FS1 durable Linux mount

Build with the pinned Rust1.92.0 toolchain (`cargo build --locked -p magus-fs`). Linux uses fuser0.18.0 with the shared FS1 engine. The FS0 probe remains a separate ephemeral experiment. No host driver installation or security configuration is performed by these commands.

Initialize/import or capture a replica as described in [fs1-local.md](fs1-local.md). The state directory must be private, owned by the daemon's UID and outside all content. Include the intended absolute mountpoint in `ReplicaConfig.content_roots` before initialization. Its parent must exist, and the mountpoint itself must be new. The adapter validates the shared native-identity boundary before and after creating that directory. It never implicitly scans or captures native content.

```sh
magus-fs mount --state /absolute/state --revision sha256:REVISION_HEX --mountpoint /absolute/view --mode private
magus-fs mount --state /absolute/state --revision sha256:REVISION_HEX --mountpoint /absolute/view --mode read-only --source http://127.0.0.1:8765
```

`--source` updates the selected revision's registered immutable source through the existing validated import API. Omit it for complete local content or an already registered source. Synthetic HTTP retains the numeric-address/explicit-port boundary; there is no DNS, HTTPS, redirect, grant or shared publication service in FS1. Missing bodies never become holes. Metadata operations do not fetch bodies. Direct I/O avoids stale content pages and speculative hydration; mmap is not qualified by this task.

The command owns the foreground daemon lifetime. Successful native writes and namespace/metadata mutations use the engine's durable transaction before acknowledgement. `fsync`/`fdatasync` synchronize local working state; they do not create a revision. A private mount resumes its dirty branch. Read-only mounts retain the requested revision's content and recheck current live authority. They deny namespace, content and metadata mutation even for configured root.

Native kernel request UIDs resolve only through persisted `Authority` mappings. No UID automatically gains engine privileges: configured `dac_override` and `ownership_transfer` remain authoritative. The kernel additionally enforces `default_permissions`; configured logical groups are a fixed allow-list, and kernel supplementary group permission must also permit access. Every presented UID/GID comes from the configured logical mapping, including the revision-bound root. Unknown mappings fail. An open handle is bound to the opening UID/workspace and EntryId; historical handles retain their selected content, mutable handles follow edits to their identity, and unlink/replacement does not redirect a handle to a reused pathname. Handles expire on daemon loss. Passing a handle between different UIDs is not supported.

Directory reading and search are independent. Readdir exposes names, identities and types, never child attributes; lookup/getattr still require current path traversal. Creation uses the shared fixed umask0022. Implemented native operations include lookup, listing, getattr, read/write/append, create, mkdir/rmdir, truncate with explicit sparse holes, rename/replacement, unlink, chmod/chown, open/release and fsync. Ordinary `flock` is local to the Linux kernel mount and is tested for conflict and release. Cross-host locks are not claimed.

Unsupported links, xattrs, special nodes, timestamp updates, combined setattr classes, special mode bits, rename flags and POSIX byte-range locks return `EOPNOTSUPP` (95); the read-only mutation boundary returns `EROFS` (30). Ordinary permission denial is `EACCES` (13), absent entries `ENOENT` (2), and unavailable/corrupt content `EIO` (5). Engine I/O preserves native errno, including injected `ENOSPC` (28). Existing typed namespace errors map to the corresponding native errno. Combined setattr classes are refused before any change rather than committing a partial multi-class operation. Timestamps remain epoch in the V1 model.

## Mounted control owner

`checkpoint`, `status` and `history` automatically use `STATE/control.sock` while the mount owns the journal. They execute the same CLI command implementation against the same serialized `Replica`; a competing journal is not opened. CLI JSON/error/exit conventions are retained. The endpoint is outside content, socket mode0600 inside state0700, with no-symlink ancestry/type/owner validation and Linux `SO_PEERCRED` verification in both directions. Only the storage UID can use it; a wire principal is not an authentication mechanism and is rejected. Read-only mount controls also deny checkpoint.

The private protocol is one JSON request (`command`, `options`) followed by a write-side shutdown, and one JSON response (`exit`, `value`). Requests are limited to64KiB, client responses to64MiB, stream I/O timeouts to5seconds. Only checkpoint/status/history commands are accepted. Successful unmount joins the control worker and removes only its recorded socket inode. A new daemon can reclaim a correctly owned stale socket only after acquiring the exclusive replica lock and verifying connection refusal. A regular file, symlink, unsafe mode/owner or live endpoint is never removed. Other standalone commands remain unavailable while that replica is owned.

## Owned native qualification

```sh
docker build --pull=false --progress=plain --build-arg VERIFY=1 -f tests/fs1/Dockerfile.linux -t magus-fs1-runtime .
python3 tests/fs1/linux_run.py --image magus-fs1-runtime --output /absolute/new-evidence-directory
```

The recipe pins the Rust1.92.0 builder and Debian runtime by digest. `VERIFY=1` runs Linux Rust tests, fmt and Clippy; normal iteration builds do not repeat those gates. It produces a default binary and a distinct nondefault `test-faults` acceptance binary. The latter injects engine `object-sync` ENOSPC only in the selected owned mount. Never deploy that binary.

The Rancher harness records source hashes/dirty state, image ID, exact commands/exits, native errno, source body counters, independent64MiB SHA, process IDs, fault boundaries and cleanup. It compares mounted and fully materialized bytes/mapping, proves cold4KiB header/tail hydration <=2MiB, warm0 and metadata0, exercises permissions/read-only confinement, physically shuts down the source listener, and tests dirty fsync plus checkpoint recovery across owned SIGKILL/restart. The original revision remains readable after offline full replacement. Private controls are exercised while mounted, including foreign-UID denial, wire-principal rejection and stale-file preservation.

Only the fixture/daemon helper receives SYS_ADMIN for FUSE, CHOWN/FOWNER for synthetic native mapping, and DAC_OVERRIDE for setup. Workload containers have separate PID/network namespaces, a read-only root, no-new-privileges, no storage/control/source/device mounts and all capabilities dropped. The confined root workload receives only DAC_OVERRIDE (effective and bounding masks2); it cannot reach daemon PIDs, the source, `/dev/fuse`, Docker, state/cache, or control sockets and cannot remount, unmount or create a mount namespace.

Normal cleanup first removes any owned workload containers, then unmounts each registered mount with a5second bound, waits for its daemon, joins source/control threads, and verifies no mounts remain. Only then does it remove owned helpers and marker-verified synthetic directories. The daemon-loss cases kill only the recorded daemon PID, unmount the disconnected FUSE view, and restart from the same state. Failed unmount retains the serving helper/state and reports failure; never delete a live mount. Missing Docker/image/device prerequisites return exit2 (blocked), failed assertions return1, and only complete native success with verified cleanup returns0. This Linux task does not replace the later combined V1–V12/platform acceptance gate.
