# FS1 combined qualification

Run from the repository on the qualified macOS host with Rancher Desktop available:

```sh
python3 tests/fs1/run.py --platform all --output /private/tmp/FS1_NEW_SHORT_NAME
```

The absolute output path must be new, with an existing parent. Keep it short because the macOS control socket has a native path-length limit. `--image magus-fs1-runtime` is optional; the selected tag is rebuilt from the current sources. No driver installation, password prompt, host permission change, push or deployment is performed. Missing mandatory prerequisites return 2, observed failures return 1, and only both fresh journeys on both operating systems can return 0. A single-platform selection records incomplete qualification.

The command verifies Rust 1.92.0, runs workspace fmt/clippy/tests, builds independent default and `test-faults` binaries, builds the Linux image with the same gates, and compares every contributing source file inside the image with the host. `source.json`, `commands.json`, platform profiles and `result.json` preserve the actual Git revision/dirty status, source SHA-256s, image ID, binary hashes, command logs and native evidence. A dirty build remains labeled dirty after a subsequent commit; retained logs are never rewritten as evidence for a different revision.

Each journey uses fresh synthetic state and owned mounts. Its corpus includes instructions, CSV, binary bytes, an executable report script, empty directories, permission fixtures and a deterministic 64 MiB file. Native fixtures deliberately use different authority layouts: Linux tests separate numeric users including confined root; macOS uses a fixed mapped principal on loopback NFS. An additional independent archive worker has no access to the original journal/cache and has networking denied (Seatbelt on macOS; a separate UID1001, network-none, read-only-root Linux container).

| Case | Direct evidence |
|---|---|
| V1 | Full and mounted closure: names, SHA-256s, modes, mapped UID/GID; executable full files after serving daemon exit |
| V2 | Zero content bodies for enumeration; cold head/tail transfer ≤2 MiB; zero warm delta; complete 64 MiB SHA-256 |
| V3 | Native append/truncate/sparse/open-unlinked/replacement, metadata/namespace changes and old revision bytes |
| V4 | Native fsync ACK before checkpoint and checkpoint ACK before owned daemon loss; exact recovered bytes, modes, absent names and captured head |
| V5 | Native source file/rename/directory/symlink races at capture barriers; old head survives rejection |
| V6 | Native cached reads, bounded uncached error and durable offline replacement/new bytes; full native edits/capture/materialize |
| V7 | Native readonly mutation denial, mode/umask, parent permissions and explicit identity mapping |
| V8 | Native ENOSPC and restart; disk-backed quota, corruption, active-handle/pin protection, explicit dry-run/apply prune, last-copy rejection |
| V9 | Independent mixed-v1/v2 archive verification/restoration with original state unavailable and network denied; malformed closure rejected |
| V10 | Current-policy historical content and metadata; explicit restored head, retained-history authority and separate source/derived output revisions |
| V11 | Native unsupported entries, xattrs/ACL inventory, capture races, guarded materialization ownership and parent/symlink races |
| V12 | Exact checkpoint replay, changed capture payload rejection, unchanged head on failed capture, mounted standalone owner commands denied busy |

The gate retains the CLI tests' actual asserted values and command results, alongside named test outcomes; a subprocess exit alone cannot satisfy a case. Missing/skipped case evidence, an unverified closure, any warm transfer, a stale recovered checkpoint or incomplete resource evidence fails normalization. Native ENOSPC, unavailable-source errors and rejected unsupported operations are expected observations within an otherwise successful case.

## Native operation support and limits

| Operation | Linux FUSE | macOS loopback NFS |
|---|---|---|
| Read/list/range/full | Lazy verified shared-engine reads | Lazy verified shared-engine reads |
| Create/write/append/truncate/sparse | Durable private working state | Durable private working state; server writes report FILE_SYNC |
| Rename/replace/unlink/open identity | Retained handles preserve the original entry | Session handles preserve identity; old process handles become STALE after loss |
| Mode/owner/group | Explicit mapping/current authority | Fixed-principal mapping/current authority |
| Readonly | Engine and adapter denial, including confined root | Adapter and engine deny mutations |
| fsync/checkpoint | fsync is local durability; explicit checkpoint creates a private revision | Same boundary; checkpoint is available through private owner control |
| Session timestamps | Explicit updates unsupported | Authorized server-now projection; no durable generation/dirty change |
| mmap | Not qualified for FS1 | Not qualified for FS1 |
| Locks | Qualified flock in one kernel; advanced locking rejected | Qualified flock in one kernel; no distributed lock claim |
| Links, arbitrary xattrs/ACLs, client timestamps | Unsupported interfaces reject operations | Explicit native EIO/EPROCUNAVAIL where the OS maps NFS errors; client timestamps unsupported |
| Crash restart | Owned SIGKILL, bounded ordinary unmount, actual-state restart | Supervised cleanup-only endpoint, normal unmount, then actual-state restart |

The macOS cleanup-only endpoint is an empty mode000 read-only state. It exists solely to permit normal unmount after daemon loss and never serves recovered workload content. This is not seamless open-FD recovery. Serving helpers outlive reporting when cleanup is unresolved; the coordinator returns bounded failure with retained ownership and recovery instructions. Final publication reuses Task1's two-write sticky-interruption helper and cannot be delayed indefinitely by a signal stream.

The actual foreign-kernel-UID macOS control probe remains unqualified under the existing noninteractive sudo policy. Forged RPC credentials, fixed-principal mapping, owner-only socket mode and private-control validation do not stand in for that probe. No second-user NFS authentication claim is made. Host administrators remain outside confined workload boundaries.

## Format, durability and dependencies

The reviewed format contract is [fs1-format.md](fs1-format.md). SHA-256 objects use fixed 262144-byte chunks. The Task1 fixed/FastCDC measurements selected fixed chunks after FastCDC failed the recorded threshold; see [fs1-chunk-layout.md](fs1-chunk-layout.md). The pinned comparison dependency is FastCDC 5.0.0, v2020 normalization1. Rust is 1.92.0; rusqlite 0.40.2 uses bundled SQLite with default features disabled; Linux fuser is 0.18.0; NFS uses the audited nfsserve 0.11.0 patch. Exact compiler and dependency builds are retained by each gate.

SQLite uses WAL, FULL synchronous and foreign keys, with macOS fullfsync. Immutable verified chunks are installed and synchronized before references; local head and operation result advance in one transaction. Process-kill evidence is not power-loss certification. Capture/checkpoint normally emits the frozen `magus-fs/v1` descriptor; restoration emits the explicit `magus-fs/v2` provenance descriptor, with source revision, metadata intent and old-to-fresh entry mapping. Mixed ancestry is verified independently. Durable timestamps and arbitrary metadata maps are outside FS1.

`com.apple.provenance` remains untouched and explicitly nonportable on macOS. Other unsupported metadata causes an inventory error. Historical full output applies current metadata and reports both source history and the derived current-policy revision; it must not claim historical metadata equality when policy changed. See [fs1-recovery.md](fs1-recovery.md), [fs1-durability.md](fs1-durability.md), [fs1-linux.md](fs1-linux.md) and [fs1-macos.md](fs1-macos.md).

Durable local working bytes, a private captured revision and future shared publication are separate states. FS1 implements the first two. No watcher synchronization, remote publication, multi-host lock or FS2 integration is implied. FS1 qualification additionally requires task review and the final whole-range review; the runnable gate alone does not close those reviews.

## Task8 measured checkpoint

The retained combined run at `/private/tmp/fs1-combined-2/result.json` passed48 V-case results across two fresh journeys per OS. It records the actual dirty source snapshot based on `efe631a`,129 contributing source hashes, and image `sha256:29a1304ef9d737aa422623f4658877c69b22f7a43d4365e9938bb37eab05a40c`. A separate final audit confirmed those sources and absence of every recorded owned host PID, native mountpoint, container and Linux VM path. Task and whole-FS1 reviews remain separate prerequisites for milestone qualification.

Both journeys measured metadata0 bytes, macOS cold1,310,720 bytes and Linux cold524,288 bytes, with warm0 additional bytes. Every64MiB scan matched SHA256 `0d9f8390657caaf114fa00a6a191f1559b488bb89f7c61b9e8d95b392330c3e4`. Offline missing-base EIO returned within0.057s on macOS and0.004s on Linux. Mac full-scan cumulative source count was67,723,304 bytes including earlier binary/partial-write checks; Linux's full-scan count was67,108,864 bytes. All observed native errors, acknowledged/recovered heads and exact command logs remain in the report. The earlier `/private/tmp/fs1-combined-1` failure is retained separately: its newly added full-closure scan had legitimately warmed the later offline-negative file, fixed by isolating the parity replica.

## Qualified local FS1 milestone

FS1 is qualified at code `b9e3fe197adf09c60014774cf6ddc7f721edb036`, following all eight task reviews, the whole-FS1 review and one scoped correction review. This is an unmerged development checkpoint, not a runtime release or FS2 synchronization claim.

The whole review corrected three supported interactions: native capture beneath a searchable non-writable parent, current permission presentation on historical mounts, and recovery pins whose selected ancestry contains never-fetched chunks. The corrected code passed host111/Linux114 primary Rust tests plus one nested worker each, fmt/clippy, host/Linux CLI18 each, Mac wire8, and focused native history15 Linux/7 Mac cases. Normal unmount and exact owned-resource cleanup were verified. The independent review found all four findings (including prune documentation) addressed and no new Critical/Important breakage.

Correction evidence is `/private/tmp/fs1-final-fix`, with130 contributing source hashes and final image `sha256:1deff50cf288c3a6abd4945248c984c950dcd06f1686408902a0b4303167e0c4`. Host binary hash is `fe3a5c11d036c86d357ff6c176a9bc1ecafcb8259d68f8a98758b71da67dc7c1`; Linux is `8b2faff726b21717ff80b2bc4b196dc7982bc284ce465221aa765e497155b699`. The original48-case combined run and later validator-only normalization retain their original source/image identities; they were not rerun or relabeled for these corrections.

The additional historical-permission runner uses real native mounts:

```sh
python3 tests/fs1/history_permissions.py --binary ABSOLUTE_MAGUS_FS_BINARY --output ABSOLUTE_NEW_SHORT_PATH
```

On Linux, run it inside the existing owned FUSE qualification container setup, not an unrestricted host or arbitrary root shell. Exact container argv is retained in `linux-native-history-final.command.json` under the correction evidence. macOS uses the existing fixed-actor loopback profile. The runner does not replace the full combined gate.

Historical native traversal still requires current rights on each traversed historical directory identity. Moving a readable file elsewhere does not grant search through a former directory whose current mode denies search or whose identity was deleted. Explicit export/restore retains its separate, current retained-history grant policy. This preserves the declared authority boundary; no broader moved-path native guarantee is claimed.
