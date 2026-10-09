# FS0 qualification runner

The final combined native matrix passed all twelve profiles: two fresh journeys at65536/262144/1048576-byte chunks on Linux FUSE and macOS NFS. Each profile passed all11 normalized required cases and cleanup. Task and whole-branch review corrections are complete at code `c55167f`; this is a bounded synthetic adapter qualification, not a filesystem release or integrated PoC.

The measured invocation was:

```sh
python3 tests/fs0/run.py --platform all --image fs0-task2-access-runtime \
  --output /private/tmp/fs0-task4-cross-platform-final
```

The approved local image was `sha256:19fae6e75834c1685021016c6d0f75d562c845b113e83eca1e5701539bbfada4`. Output must be an absolute, new path with an existing parent. The runner creates `result.json` and six native profile directories per selected platform, retaining actual commands/stdout/stderr, manifests, measurements, environment and cleanup evidence. `--platform linux` or `--platform macos` scopes qualification. Exit0 means every selected gate passed; exit1 means observed I/O, identity, measurement or cleanup failure; exit2 means missing prerequisite/proof. An escaping runner exception preserves any existing native report and known owned resources; cleanup errors cannot hide observed failures. Native Mac execution now runs in a separate session behind a supervised reporting boundary: each profile has a600-second deadline, a5-second report grace and0.1-second polling. An explicit cleanup-pending report returns failure immediately. Deadline or parent SIGINT/SIGTERM requests guarded cleanup via SIGINT to the runner PID alone; it never kills serving children or their process group. The aggregate returns failed/exit1 while an unresolved native runner and its in-process projection gateway remain alive. Scalar-only parent signal handling stays active through aggregate publication.

The schema is `magus-fs-fs0-result-v1`. Required profiles are journeys1/2 × three chunk sizes per platform. Cases include state, expected, observed and actual command lists, including every contributor to composite cases. The Mac normalizer checks all20 contributing scenarios, exact successful command records, actual13 registered mounts/options, canonical manifests, source measurements and15 reaped serving/helper PIDs. Required stage modes are independently fixed: normal-private/resumed-private must be private/rw, every other named view ro. Actual mount argv, daemon requested mode and table flags must agree with that requirement. Both readonly/private lock details require contended/flock/Darwin errno35/exit75. Final cleanup_errors and remaining_owned_resources must be explicit empty lists. Missing/false observations, unconfirmed cleanup, unknown resources or wrong native pass flags cannot qualify. Aggregation rejects missing profiles/cases/commands, differing same-size manifest identities, reused tokens and stale counters. Child exit0 alone is insufficient.

Each profile starts fresh sources, caches, private state and mounts. Enumeration fetched0 content bodies and warm range repeats added0. Exact4KiB head/tail reads of64MiB fetched the following original source payload bytes; both journeys agreed:

| Chunk bytes | Linux cold bytes | Mac cold bytes |
| ---: | ---: | ---: |
|65536|131072|1114112|
|262144|524288|1310720|
|1048576|2097152|2097152|

Each streamed full scan read67108864 bytes and matched independent SHA-256 `1977adb6a954de29fb854e5ea942b2ba29bc8c7846e83440d94e37ab61858369`. Full source content payload totaled67108864 bytes after the scan. Native readahead is included in cold transfer; chunk size remains an experiment, not a production layout decision. Private Mac eager hydration67108958 bytes is separate from these readonly measurements.

Normal entries use explicit test-only UID/GID501:20 projection over real Rust source chunks. The proxy verifies the original canonical digest, preserves all other fields/descriptors, recomputes the projected digest and records original/projected identities plus construction actor. Actual projected digests matched across both platforms and both journeys:

| Chunk bytes | Verified manifest SHA-256 |
| ---: | --- |
|65536|`b232d894e2ed751f4d01b2c78b2868dc1e5120d2e786b399cc0bfdd3c0bb185f`|
|262144|`7da2a6998bc659f298580023bec0aec6655fe2273606dd3995b2d59fcdf319c6`|
|1048576|`32b6efdc9e3556ece92295f9248b7d9c32e33d66df42395a4e968dac82e7e592`|

Permission variants remain separate identities. Source files may inherit a parent's group; process getgid does not establish fixture identity. The observed daemon-mapped root is Linux0:0 and Mac501:20, both mode0755, outside the FS0 manifest digest. Matching digests do not imply matching root ownership. FS1 must bind root metadata in its durable format.

Counters measure original Rust source response payloads. `content_body_bytes` includes repeated chunk requests. `retry_requests` counts repeated hash requests, not inferred retry intent. `metadata_bytes` excludes projected proxy responses, stats/control traffic and network framing; projected response lengths are separately recorded. These are not measurements of every network leg.

Linux readonly root workloads retain only DAC_OVERRIDE; existing-byte private workloads use owner501:20 with all capabilities dropped. Permission negatives use isolated numeric principals and separate manifest variants. Strict flock children qualify only structured EAGAIN/EWOULDBLOCK from flock with exit75 and no stderr. Mac fixed-principal native permissions include group/other, mode000, independent directory read/search, readonly mutation denial and0755 execution/0644 denial. Both adapters prove actual subprocess reads, mmap, local lock contention and old/new generation mount pinning.

Linux private bytes remain on-demand and ephemeral: fsync/fdatasync and private namespace/metadata mutations are explicitly unsupported. Mac private backing is eagerly hydrated; existing-file writes/fsync, truncate and chmod survive daemon stop/remount, without a power-cut or writable lazy-replica claim. Mac CREATE/rename replacement remains unsupported. Old descriptors survive the failed replacement attempt because replacement did not occur. Mac source-failure proof covers warmed-file reads, uncached EIO and recovery. Neither adapter provides live invalidation or distributed locking.

Native cleanup unmounts owned views before reaping servers and retains failed-run evidence. Each supervised profile also writes sibling `.supervision.json`, `.runner.stdout` and `.runner.stderr` files containing exact argv, runner PID/liveness, deadlines, last complete native snapshot, known owned paths/PIDs and recovery action. For pending cleanup, inspect `/sbin/mount -t nfs` and the native report; retain the serving runner. Separately authorized unmount of an exact confirmed owned path lets its native guard resume cleanup automatically. Never delete a mounted path or terminate its projection/NFS servers. Supervision failure stops further Mac profiles; missing prerequisites remain blocked. The final matrix cleaned24 Linux mounts/48 serving PIDs and78 Mac mounts/90 serving/helper PIDs. Independent controller read-only checks found no NFS mounts, no recorded Mac PIDs and none of the102 recorded Linux containers remaining. No deletion through mounted paths, host security change, public push or deployment occurred. Evidence/output and the approved local image remain for review.

Read-only inventory selected Visual Studio Code1.135.0 and codex-cli0.158.0-alpha.13 for later real compatibility journeys; Claude Code2.1.295 is also installed. Installed versions are not compatibility proof. No editor session, paid model call, personal configuration edit or install occurred. Real editor and external-harness journeys remain an integrated PoC gate.

The pinned Linux `fuser`0.18.0 and patched macOS `nfsserve`0.11.0 qualify only for this FS0 scope; see [Linux](fs0-linux.md) and [Mac](fs0-macos.md). Synthetic HTTP has no authentication/TLS; digest pinning provides identity/integrity, not principal authentication. Durable replicas/history, authenticated update authority, general multiuser/supplemental-group policy, generation publication/invalidation and complete namespace operations remain future implementation gates. FS1 planning follows this qualified checkpoint; the shared ICM tracks current execution.

## Reviewed correction checkpoint

Code `c55167f` closes the final FSINFO ancestor-metadata bypass: denied optional attributes are omitted through authorized getattr, while the successful filesystem-info encoding remains intact. Nine real NFS wire tests pass, including denied and authorized handles. Late finite SIGINT/SIGTERM during final cleanup/serialization now yields a failed report and exit1, tested on Python3.9.6 and3.14.7. Host Rust4 and Linux Rust7 plus fmt/clippy/build pass. The original twelve-profile matrix and later supervised Mac profile retain their original binaries and provenance; they were not relabeled or repeated for this narrow correction.

For a fresh run of the corrected build, explicitly select `--image fs0-final-runtime`. Its image ID is `sha256:474b2bcb09d7ad22e9a73b1588bfdec0e21719e2bc30445277101bf771e96ac0`; host binary SHA256 is `66a1d977d980e6726afa52dbf9e424ee8a0a8077e9966d5d1be200e7e6679507`, Linux binary is `ae30dd8e34d49480dacbaba5613f56acf67ea5e9082804d71a7ba89eaa2e8de8`. Earlier image references above describe the measured matrix. The runner default remains that historical image, so use the explicit flag.

One reviewed Minor remains: a continuous SIGINT/SIGTERM stream during every final report write can prevent the publication retry loop from returning until signals stop. This occurs after owned cleanup, preserves failed status for observed interruption and does not invalidate native results. FS1's first harness task must replace it with bounded publication and a sticky failed result. No production cancellation-liveness guarantee is claimed from this checkpoint.
