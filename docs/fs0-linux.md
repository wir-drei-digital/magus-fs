# Linux FS0 qualification

The Linux `fuser` candidate is qualified for an immutable, pinned synthetic FS0 namespace with verified range reads, read-only views and explicitly ephemeral private bytes. This is not a versioned filesystem release. Both Linux and macOS now have measured native FS0 proof in the twelve-profile matrix. Whole-branch FS0 completion awaits scoped re-review of the final corrections. The Task3 measurements below remain historical evidence of that qualification.

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

For the focused permission regressions added after review, run:

```sh
python3 tests/fs0/linux_run.py --focused-permissions --output /tmp/fs0-linux-permissions-NEW-UNIQUE-NAME
```

These fixtures vary only manifest metadata and continue forwarding all content chunks to the real Rust source. They qualify mode0400 directory name enumeration without child search, mode0100 search without enumeration, and root private write/readback on mode0444/mode000 with nonroot and read-only denial contrasts.

`--mode private` enables the same Probe's in-memory byte overlay. `--prepare-only` validates the manifest/options/path and exits without mounting. `--backing` and `--resume-backing` are rejected for FUSE. Mount options always include `default_permissions,nosuid,nodev,allow_other` and `ro` or `rw`. Kernel permission checks are supplemented by daemon caller/parent checks. Directory enumeration requires directory read permission; child lookup/read still requires ancestor search permission. Private byte writes pass through a crate-private byte-store method only after the adapter authorizes the actual caller, so authorized root DAC override is honored while the independent read-only guard remains absolute. Standalone Probe writes retain their existing mode restriction. The tested mapped source principal is UID/GID 0:0; nonowner and primary-group identities are tested only inside disposable containers. Supplemental-group authorization is conservatively unsupported in daemon checks and needs FS1 treatment.

Ordinary mounted tests cover exact ranges/EOF, metadata and traversal, root mode000 bypass with all read-only mutations denied, private write/readback, sparse extension/reopen, read mmap and visibility of private writes in an existing mmap, local lock contention and pinned manifests/open descriptors. Enumeration fetched zero content bodies; two 4 KiB head/tail reads fetched 524,288 bytes with the 256 KiB chunk size, and a warm repeat fetched zero additional bytes.

`fsync` and `fdatasync` return `EOPNOTSUPP`, including after private writes. FUSE's close `flush` succeeds because it is a close/error notification, not a persistence guarantee. Private create, rename, truncate, chmod and other namespace/metadata mutations return `EOPNOTSUPP`; read-only mutations return `EROFS` or normal permission errors. Classified unsupported operations are not reported as implemented support. The source serves an immutable snapshot; editing its input files is not generation publication. Different manifests require fresh mounts. Existing handles/mounts remain pinned; no live invalidation or distributed locking claim is made. FS1/FS2 must implement and qualify those contracts.

Task4 adds `python3 tests/fs0/run.py --platform all --image fs0-task2-access-runtime --output ABSOLUTE_NEW_PATH` for three chunk sizes and two fresh journeys per platform, including streamed full scans and strict lock-child observations. The final twelve-profile Linux/macOS matrix passed. Normal manifest entries are explicitly projected to501:20; internal Rust fixture files and the daemon-mapped virtual root remain0:0 on Linux. Original/projected identities, root metadata, construction actor and measurement scope are recorded separately. Independently constructed platform endpoints are compared only after exact immutable digest equality is verified. See [combined qualification](fs0-qualification.md) for schema, measurements, cleanup, installed editor/harness inventory and authentication/live-update limitations. All four task reviews passed; whole-branch completion awaits scoped re-review of the final corrections.
