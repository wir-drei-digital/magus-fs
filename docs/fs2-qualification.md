# FS2-A connected qualification

This gate qualifies the connected A slice. It does not complete FS2, S1–S15, the integrated PoC, release packaging, or external harness qualification. FS2-B owns the remaining reconciliation, structural native application, robustness and recovery work.

Run on the qualified macOS host with Rancher Desktop available and Rust 1.92.0 selected by the `stable` alias:

```sh
python3 tests/fs2/run.py --slice connected --platform all --output /private/tmp/FS2A_NEW_SHORT_PATH
```

The absolute output path must be new and have an existing parent. The command builds separate default/fault host binaries in the release profile, runs host/Python/style checks, builds a fresh source-matched release Linux image with debug Linux checks, and performs two journeys with separate synthetic credentials, PostgreSQL/S3 volumes, service processes, native owners and FUSE mounts. Exit 0 requires both journeys, nested native assertions, exact receipt/base bindings, 20 serialized target-save measurements per journey, provenance and independently inspected cleanup. Exit 1 is an observed failure; exit 2 is a prerequisite or deliberately incomplete probe. A focused development probe is `python3 tests/fs2/run.py --probe --output /private/tmp/FS2A_NEW_PROBE_PATH`; it cannot qualify success.

The ordinary fixture includes instructions, a procedure, integer CSV, a Python report script, a precreated reports directory, empty file/directory, executable, opaque bytes and deterministic 64 MiB content. Independent expected file hashes and report math remain in each journey's `expected.json`, outside client trees. Initial full native hydration has a 60s aggregate budget; incoming hydration keeps 30s and each remote object fetch 4.5s. The Mac full folder remains readable after its owner stops. Linux opens the same authorized view lazily, then receives procedure edits on its existing mount through durable polling. Twenty small saves are serialized by precise revision drains; capture/private/shared/visible times are observed upper bounds, with environment-specific p50/p95 and no universal SLA.

The worker uses a separate replica and reports-only grant, with isolated publication and an independently retained private candidate lineage anchored to its authorized main view. It is not a named shared-service worker branch. Its ordinary Python report is Alice-owned and retains worker replica/grant attribution. A private receipt leaves shared content unchanged; explicit authorized integration against the original main head exposes the expected report automatically to Mac and Linux.

Fault builds discard actual native callbacks and authenticated WSS text-frame hints while scans/polling recover. Real service/client process restarts and discarded committed HTTPS responses retain exact operation/base/receipt identities. Default binaries are inspected for absence of instrumentation. Transfer records count admitted client object bodies including repeated requests, backend verification response chunks and successful backend PUT bodies separately; logical unique uploads are recorded independently. Counts concern application content bodies, not HTTP headers/TLS overhead. Bootstrap full hydration is separate from Linux metadata-zero/cold-bounded/warm-zero reads and changed-content upload limits.

Each output preserves commands, dependency versions/licenses, compiler/image/binary/source hashes, profiles with secrets in private control files, ordinary native operations, receipt/ready timelines, transfer logs, failures and ownership manifests. Cleanup discovers exact mounts from the kernel mount table, including revoked mounts whose stat is denied, and normally unmounts/reaps exact owned mounts before deleting exact labelled Docker resources; a failed unmount preserves serving helpers. Host synthetic trees and evidence remain available for inspection.

Existing limitations include sequential multi-file native visibility, regular-file exchange/create under existing directories, retained `ApplyBlocked` for unsupported structural work, no remote revocation of offline full-folder plaintext, no general many-principal host mapping, and no old credential-bound source rebinding guarantee. Durable current authority still governs attached mounts. Private candidate fast-forward integration is the A boundary; automatic compatible/text reconciliation belongs to B.

Linux file inode epochs remain capabilities for their original bytes. If ordinary pathname LOOKUP and OPEN straddle incoming epoch adoption, the adapter returns ESTALE so Linux VFS revalidates the pathname. A new open obtains the new epoch; a held descriptor retains its original read/fstat bytes and rejects writes with ESTALE. The deterministic native regression pauses the actual FUSE lookup reply across adoption, tests both held and no-held cases, and uses one application open with no retry:

```sh
python3 tests/fs2/lookup_epoch.py --output /private/tmp/FS2A_NEW_EPOCH_PATH
```

Final development qualification may reuse recorded unchanged checks through a retained, hashed driver. This is distinct from the fresh default command above: the driver must prove the current source inventory, immutable image and all host binaries match, name each reused check and amended boundary, and preserve failed runs. Runtime changes require checks at the affected boundary; native/client changes require fresh native journeys. A service-only correction can retain unchanged native evidence with an explicit source bridge and real service regression. Control/descriptor request bodies and total HTTP/TLS traffic are not measured by the content counters.

The connected development qualification passed at `/private/tmp/fs2a-c6-f5/result.json` using the retained checked-evidence driver, current187-input source inventory (raw source.json SHA256 `6f99fe7ebee4af06cad1dd348cb0180fb5b06d878b508dfc9627440dab462b2b`) and release image `sha256:fffea90005f5d9b27f94d3921914c402dc8960a346f62c5913ac7eff42e2fcf5`. Both fresh journeys completed20 saves and all required assertions; independently audited cleanup removed16 exact Docker resources and all6 Mac owner launches after6 normal unmounts. Visible p95 was 10.892s/10.282s. The retained evidence/reuse map preserves the earlier runtime and infrastructure failures. Independent review is recorded separately; this passing slice does not complete FS2-B or full FS2.

The connected gate enforces one 15-second budget from the original save start through Linux content visibility and Mac Ready. Capture and both visibility observations share that deadline; a slow predicate completing after it fails. Exact revision drains retain their separate 60-second contract and cannot make an over-budget save qualify. Normalization also rejects visible times above 15 seconds. Procedure integration records must match raw requests, the independently captured original main head, the private candidate receipt, and the shared operation/replica/branch; candidate and integration operations retain separate identities.

Review hardening was verified with 44 Python tests and a new normalization of the immutable original evidence at `/private/tmp/fs2a-c6-fix1/result.json`. Its `source-bridge.json` names the four changed harness files and hashes the new normalizer/observer, while preserving the original runtime commit,187-input source inventory,image and raw results. All40 recorded save stages and42 receipts pass the current collector checks. This is a hardened evaluation of retained runtime evidence, not a newly executed current-harness20×2 journey.

## Qualified checkpoint and next work

FS2-A runtime `e03ddad` has completed all six task reviews, whole-A review and one scoped final correction review. Two fresh connected journeys at `d13374e` passed all40 saves and42 procedure receipt bindings; observed visible p95 was10.892s/10.282s (maximum11.817s/10.785s). Linux metadata content was0bytes, cold reads524288bytes and warm repetition0; each20-save batch uploaded480content bytes. These are observed bounds, not a millisecond or total-wire SLA.

Task6 harness hardening at `fef3eab` passed44 Python checks and revalidated original evidence with stronger total15s/receipt-binding assertions. Final service correction `e03ddad` adds migration003 and reuses only identical currently authorized views under the namespace lock. Legacy IDs remain valid, NULL authority snapshots are excluded from reuse, and edited history is not deleted. Its separate real HTTPS/PG/S3 regression passed224 stable requests, credential/generation/grant/head/projection separation, original/legacy replay and credential/parent revocation; host/Linux service tests13/13 and the existing focused68-observation service contract passed. The source bridge records189 inputs; unchanged native observations remain attributed to their original binaries, not the final service image.

```sh
python3 tests/fs2/view_reuse.py --output /private/tmp/FS2A_NEW_VIEW_PATH
```

Revision admission is2 concurrent requests; larger test bursts may correctly return503. Repeat startup exercises additive migration compatibility. Do not delete old view IDs or rewrite queued original bases to reduce row counts. Genuine history retention belongs to FS2-B, whose migrations start at004.

Safe redacted discovery/acknowledgement diagnostics remain a nonblocking FS2-B Task3 item. Existing pending/retry/authorization behavior is preserved. Full structural native application and Mac NFS live epochs, conflict reconciliation, disconnected recovery, dependencies, CRDT comparison and actual editor/external-harness gates remain B work. Start B on a new isolated branch. No product migration or deployment is implied by local qualification.
