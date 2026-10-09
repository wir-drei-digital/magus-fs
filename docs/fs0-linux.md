# Linux FS0 qualification

The Linux `fuser` candidate is qualified for an immutable, pinned synthetic FS0 namespace with verified range reads, read-only views and explicitly ephemeral private bytes. This is not a versioned filesystem release. macOS remains a separate unresolved gate; FS0 is incomplete across platforms.

From this checkout, build and run the owned Docker qualification:

```sh
docker build -f tests/fs0/Dockerfile.linux -t fs0-task3-runtime-final .
python3 tests/fs0/linux_run.py --output /tmp/fs0-linux-NEW-UNIQUE-NAME
```

The output directory must be new. The runner writes `result.json` and full command/stdout/stderr evidence. It returns 0 only after its required scenarios and cleanup pass, or 2 on a blocked/failed qualification. This task-specific runner does not replace Task 4's cross-platform aggregate predicate.

The builder pins Rust 1.92.0 by image digest, adds rustfmt/clippy only inside the disposable build stage, and runs fmt, clippy and the full Rust suite. The runtime pins Debian bookworm-slim by digest and contains the binary, FUSE tooling, Python and standard mount/unmount utilities; no compiler is copied. Cargo.lock pins `fuser` 0.18.0 with default features disabled, using its direct kernel FUSE backend rather than linking libfuse.

The Rancher Linux daemon container gets `/dev/fuse` and only `SYS_ADMIN`; it has a read-only image, bounded tmpfs for three synthetic 64 MiB fixtures, and no Docker socket. A uniquely named VM `/tmp` bind uses existing shared propagation. The runner does not change Rancher or host propagation/security configuration. Actual workload containers receive only an exact FUSE view, a separate PID/network namespace, `--network none`, a read-only image, `no-new-privileges` and all capabilities dropped. Root cases retain only `DAC_OVERRIDE` to exercise mode bypass. The source/daemon/controller trees and `/dev/fuse` are absent from those workloads. A cleanup helper gets the VM `/tmp` parent only after unmount, verifies there are no owned submounts, and removes only the recorded empty directory with `rmdir`.

The adapter CLI accepts an existing source:

```sh
magus-fs-probe mount --backend fuse --source http://ADDRESS:PORT \
  --mountpoint /ABSOLUTE/NEW/PATH --mode ro --expect-digest SHA256
```

`--mode private` enables the same Probe's in-memory byte overlay. `--prepare-only` validates the manifest/options/path and exits without mounting. `--backing` and `--resume-backing` are rejected for FUSE. Mount options always include `default_permissions,nosuid,nodev,allow_other` and `ro` or `rw`. Kernel permission checks are supplemented by daemon caller/parent checks. The tested mapped source principal is UID/GID 0:0; nonowner and primary-group identities are tested only inside disposable containers. Supplemental-group authorization is conservatively unsupported in daemon checks and needs FS1 treatment.

Ordinary mounted tests cover exact ranges/EOF, metadata and traversal, root mode000 bypass with all read-only mutations denied, private write/readback, sparse extension/reopen, read mmap and visibility of private writes in an existing mmap, local lock contention and pinned manifests/open descriptors. Enumeration fetched zero content bodies; two 4 KiB head/tail reads fetched 524,288 bytes with the 256 KiB chunk size, and a warm repeat fetched zero additional bytes.

`fsync` and `fdatasync` return `EOPNOTSUPP`, including after private writes. FUSE's close `flush` succeeds because it is a close/error notification, not a persistence guarantee. Private create, rename, truncate, chmod and other namespace/metadata mutations return `EOPNOTSUPP`; read-only mutations return `EROFS` or normal permission errors. Classified unsupported operations are not reported as implemented support. The source serves an immutable snapshot; editing its input files is not generation publication. Different manifests require fresh mounts. Existing handles/mounts remain pinned; no live invalidation or distributed locking claim is made. FS1/FS2 must implement and qualify those contracts.

Cross-platform identity must use one source manifest. Separate default fixtures differ in native UID/GID (this Linux run 0:0 versus Mac 501:20). A bounded follow-up can run a dedicated source container as numeric UID/GID 501:20 with an owned writable tmpfs, publish its HTTP port only to host loopback, and let both adapters consume that single source URL/manifest with `--expect-digest`. That route still requires native proof in Task 4; no host account changes or permission bypass are implied.
