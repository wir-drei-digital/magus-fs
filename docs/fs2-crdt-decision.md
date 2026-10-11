# Bounded ordinary-file CRDT experiment (FS2-B Task 5)

## Protocol declared before implementation

The experiment alone depends on exact Automerge 0.12.0 and the existing public
`magus_fs_core::merge_text`. Its own workspace/lockfile excludes it from the
shipping workspace. No production adoption or helper-limit change is authorized.

Synthetic UTF-8 files are materialized using ordinary reads and whole-file writes.
The seed document has actor `00`; edits use distinct deterministic actors `01`,
`02`, `03`. Each editor save declares an independently recorded frontier: the
seed, a named earlier save, unknown, or deliberately unavailable heads. Known
saves fork at those exact heads, apply `update_text`, and save/reload. Unknown
and unavailable saves retain their bytes and return explicit held outcomes;
no latest-head fallback is permitted. Merge forks in forward/reverse order and,
for three saves, all six exchange orders. Reload final serialized state in a
separate process. Mechanical text/hashes/frontiers are separate from independent
semantic expectations; convergence alone is insufficient.

Fixtures: distinct-line insertion/deletion, overlapping replacement, delayed
whole-file save after a newer known save, unknown editor origin, unavailable
frontier, multibyte accented/emoji text, repeated lines, empty document concurrent
insertions, dependent save followed by concurrent edit, and restart. Exact intent
is asserted for unambiguous distinct edits; ambiguous same-position insertion or
replacement requires preservation of alternatives and is scored against an
independently declared set/required fragments rather than whichever output occurs.
All original input files remain in retained evidence. Three-way overlap discards
marker output and preserves originals; unsupported/budget outcomes remain visible.

Benchmarks: exact 16,384-byte and 262,144-byte ASCII fixtures with 64-byte lines;
100 sequential edits replace a fixed-width decimal marker in alternating lines
and alternate two distinct actors. Each CRDT save is based on recorded current
heads; helper receives the same base/current-save/unchanged other input. Measure
initialization, per-change update+commit, merge/exchange, serialization and helper
latency separately; report median and nearest-rank p95, complete serialized state
bytes and encoded change bytes (not transport framing). Initial fixture encoding
and history growth are included. Use an optimized explicit measurement profile.
The unmodified helper's 256KiB/4096-line limits apply: over-limit inputs return
Budget rather than being clipped. Each benchmark process has a 30-second wall
limit including initialization; the full experiment phase has a 300-second wall
limit. Preserve streamed partial metrics and mark timeouts/unfinished changes.
Build time is reported separately and excluded from these experiment bounds.

This is one local machine, synthetic files, retained complete CRDT history and
whole-file diffing. It does not qualify network transport, history GC, production
editor provenance, filesystem integration, or organizational scale. Decision will
be filled from raw observations: adopt, limit, or reject with causal, preservation,
storage, throughput and integration costs explicitly weighed.

## Recorded protocol correction from first run

The initially asserted helper result for the dependent-save fixture was Merged.
The real helper returned Overlap when combining adjacent B/C line changes; raw
`/private/tmp/fs2b-t5-green1/dependent-save.jsonl` retains that failure. The
mechanical assertion now reflects that conservative behavior. The independently
declared semantic expectation remains `A\nB\nC\n`; no intent expectation was
changed to match a CRDT output. This is an observed comparison finding.

## Decision: reject automatic ordinary-file adoption

Keep production three-way merging and retained conflict alternatives intact.
Automerge is confined to this development experiment. A later instrumented-editor
CRDT proposal would require its own bounded implementation and review.

Causal correctness holds when the experiment supplies actual read frontiers:
known prior heads are forked exactly; unknown origin is held; a real failed
`fork_at` remains base_unavailable. An ordinary whole-file save does not itself
supply that read frontier. Using latest heads would manufacture causality.

All nine CRDT scenarios converge over every tested exchange order and survive
save/load plus a separate-process reload. Five independently specified exact
intent results match: distinct insertion/deletion, delayed save, Unicode,
repeated lines, and dependent save. Empty-document concurrent insertions retain
both declared fragments (`β\nα\n`) but do not establish an intended order.
However, concurrent `old\n` → `alice\n` and `old\n` → `bob\n` mechanically
converge to `babice\n`, preserving neither complete alternative. The existing
helper returns Overlap and retains the two original files. This known-frontier
counterexample is sufficient to reject automatic adoption; convergence does not
prove intent preservation. The helper also conservatively overlaps adjacent
changes in the dependent-save fixture where Automerge yields `A\nB\nC\n`.

## Measured performance and storage

Two settled runs on Apple M4 Pro, 12 CPUs, 48GiB, macOS26.5.2, Rust1.92.0.
Both use opt-level3 `measurement` (release inheritance, no LTO,16 codegen units),
exact Automerge0.12.0 from crates.io (MIT), and the actual pinned diffy0.5.2
shipping helper. Build duration is retained separately. No shipping dependency
or limit changed. All100 changes completed for both sizes in both runs; per-case
30s and experiment300s bounds held. Complete experiment phases took27.71/27.96s.

First settled run; latency values are median / nearest-rank p95 milliseconds:

| Fixture | 16KiB | 256KiB |
|---|---:|---:|
| 100-change wall time | 1.364s | 25.689s |
| Completed changes / wall second | 73.31 | 3.89 |
| CRDT fork + update + commit | 10.351 / 11.066 | 215.622 / 234.302 |
| CRDT merge | 2.094 / 2.189 | 32.141 / 34.449 |
| CRDT serialization | 0.068 / 0.103 | 0.288 / 0.328 |
| Three-way helper call | 0.040 / 0.046 | 0.535 / 0.612 |
| Complete iteration including file I/O/checks | 13.015 / 13.716 | 251.733 / 275.990 |
| Initial → final compressed CRDT state bytes | 316 → 2449 | 1983 → 4153 |
| Initial raw encoded change bytes | 16484 | 262244 |
| Raw encoded changes including initial state,100 edits | 31333 | 277093 |

Second run:1.507/25.786s (66.34/3.88 changes/s); CRDT update median/p95
11.557/12.368 and215.916/243.078ms; helper0.043/0.048 and0.535/0.593ms.
Full phase metrics and100 raw samples per size/run are retained. Bytes, hashes,
frontiers and final serialized states repeat exactly; timings vary.

The very repetitive ASCII fixtures compress strongly. State sizes are complete
compressed `save()` bytes, not memory usage; wire sizes sum actual raw encoded
changes including the initial change, not a network protocol or transport
framing. The helper has no CRDT history/wire state: its measured inputs/output
are ordinary fixed-size file bytes, and no service/CAS storage measurement is
claimed. Benchmark inputs change one numeric marker; the other helper side is
unchanged. This measures a sequential editor save path, not difficult concurrent
merges or adversarial diff performance. The256KiB dataset has exactly4096lines;
separate above-byte/above-line fixtures prove Budget without clipping. A NUL
fixture proves Unsupported. These are helper-only boundary checks; oversized
CRDT throughput is not claimed.

## Integration cost and limits

A production CRDT path would need reliable read-to-save frontier attribution,
durable actor/operation identity and history retention, bounded state/GC/replay,
authorization-aware replication, and explicit mapping to the existing immutable
ordinary-file hashes/descriptors. It must preserve complete conflicting editor
alternatives even when character operations converge. This experiment supplies
frontiers synthetically; it does not solve editor causality, real history expiry,
network exchange, filesystem watchers, grants, or distributed crash recovery.
Separate-process reload proves persisted text/heads, not an entire daemon's
transaction protocol. The costs and the demonstrated intent failure outweigh
the useful conservative-overlap avoidance for the scoped ordinary-file path.

## Reproduce and inspect

```sh
python3 tests/fs2/crdt_comparison.py --output /private/tmp/CRDT_NEW_ABSOLUTE_PATH
python3 tests/fs2/crdt_comparison.py --validate /private/tmp/CRDT_NEW_ABSOLUTE_PATH
python3 -m unittest discover -s tests/fs2 -p test_crdt_comparison.py
cargo +stable fmt --manifest-path tools/crdt-experiment/Cargo.toml --all --check
cargo +stable clippy --locked --manifest-path tools/crdt-experiment/Cargo.toml --all-targets --all-features -- -D warnings
```

Rust stable must identify exactly1.92.0. The runner is qualified on this macOS
host and records its environment; it is not a cross-platform deployment gate.
Output must be new. A timed-out benchmark retains partial streamed metrics and
explicit timeout/completed-change counts; it is a measured outcome, not a hidden
retry. A non-timeout error fails the gate. Intent mismatches remain separately
reported findings even when the causal/mechanical gate passes.

Retained settled evidence: `/private/tmp/fs2b-t5-final2` and
`/private/tmp/fs2b-t5-final3`; independent repeat comparison:
`/private/tmp/fs2b-t5-repeatability.json`. Each contains original fixture inputs,
raw operation/frontier/exchange/restart results, ordinary files, serialized
states, optimized binary+digest, all33 source snapshots/digests (including the
experiment's own manifest/lock and full helper crate source),108-package
metadata/license/source manifest,106 registry package manifest copies and any available license files,
compiler/environment, build status and raw benchmark samples/summaries.
Automerge declares MIT in its retained Cargo.toml; the resolved archive contains
no license file (its recorded license_files is empty). The exact registry archive
is separately retained at `/private/tmp/fs2b-t5-automerge-0.12.0.crate`, SHA256
`2fb849130973a7808a167887f56b1e8bdc36b9b541542602dcb337f34aecf47b`, matching
the experiment lock checksum. Shipping provenance intentionally excludes `tools`; these independent manifests
are the authoritative experiment evidence.
