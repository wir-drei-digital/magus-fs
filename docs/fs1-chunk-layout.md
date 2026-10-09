# FS1 initial capture layout

Task2 must implement **fixed262144-byte chunks with SHA-256 identity** for initial capture. This choice does not freeze durable serialization: Task2 must identify the format and capture layout explicitly. Extent writes can retain slices independently of the initial capture chunker.

Both Rust1.92.0 platforms pass independently reconstructed whole-file and individual chunk hashes for every corpus/variant/layout run. CDC uses pinned `fastcdc = "=5.0.0"`, v2020, min65536/avg262144/max1048576, normalization1, seed0. The [library source](https://docs.rs/crate/fastcdc/5.0.0/source/src/v2020/mod.rs) defines the streaming implementation.

| Platform | Corpus | Fixed insertion new bytes | CDC insertion new bytes | CDC savings | CDC/fixed CPU |
|---|---|---:|---:|---:|---:|
| host | fs0-64mib | 67,112,960 | 67,112,960 | 0.00% | 1.050 |
| host | text-csv-8mib | 2,625,536 | 5,246,976 | -99.84% | 1.038 |
| linux | fs0-64mib | 67,112,960 | 67,112,960 | 0.00% | 1.235 |
| linux | text-csv-8mib | 2,625,536 | 5,246,976 | -99.84% | 1.117 |

CDC fails the required50% insertion savings on both large corpora on both platforms. All other observed limits pass (CPU<=3x, peakRSS<128MiB, cold two-range hydration<=2MiB), but every rule is required. Fixed's maximum cold two-range hydration is524288 bytes; CDC's is2097152 bytes. Worst observed full-process RSS is21962752 bytes. Initial capture scans/rechunks the whole file. Fixed insertion may transfer nearly all bytes; these synthetic corpora do not justify choosing CDC for this PoC. This is a bounded selection rule, not a product performance promise or a claim about other datasets.

Run `RUSTUP_TOOLCHAIN=stable python3 tests/fs1/chunk_benchmark.py --output ABSOLUTE_NEW_PATH` on this host after verifying the stable alias is exactly1.92.0. Linux uses the pinned Rust1.92.0 image recorded in the task report. Each nonempty corpus/layout/variant gets one unmeasured warmup and three independently verified timed runs. Empty files and their variants get one correctness run. CPU ratios compare medians of each complete five-variant suite. CPU/RSS cover the complete child lifetime via `wait4`; elapsed includes launch and diagnostic JSON, and independent verification is excluded. Capture-only timings remain separately available. The page cache is warm; cold amplification models an empty verified chunk cache using actual selected descriptors and deduplicates identical hydrated bodies.

The FS0 corpus is exactly64MiB: byte(i)=(i*31+floor(i/4096)) mod251, with each64KiB block's first8 bytes replaced by its little-endian block number. Its independent SHA-256 is1977adb6a954de29fb854e5ea942b2ba29bc8c7846e83440d94e37ab61858369. The8MiB repetitive corpus repeats the exact notes/CSV row specified in `write_corpora`; small files contain4095 deterministic bytes and0 bytes. Variants insert4096 bytes at65537, overwrite4096 at1048579, append65536, and truncate to half. For small inputs insertion splices at EOF; overwrite explicitly zero-extends the gap. Header/tail requests are4096 bytes each, shortened at EOF; amplification divides by unique requested bytes when the ranges overlap.

Content buffers are bounded to the chunk size (CDC<=1MiB). Descriptor/hash-index metadata scales with the number of chunks and is included in RSS; no whole-corpus byte vector is retained. The candidate representation is an actually encoded48-byte descriptor (LE u64 offset + LE u64 length +32 raw hash bytes). Reported descriptor bytes exclude future durable envelopes, indexes, journals and object storage overhead. Equal hashes deduplicate content transfer, while ordered descriptors retain repeated occurrences; changed content is independently checked against the descriptor hash.

Retained evidence: `.superpowers/sdd/fs1-plan/task-1/host/result.json`, `linux/result.json`, all raw per-run JSON/command/stdout/stderr artifacts, `selection.json` and `self-review.log`. Each report retains source/compiler/library/binary fingerprints, inputs/outputs, raw samples, medians, byte counters and cleanup. Superseded3.2.1 and partial-RSS measurements remain clearly named and do not drive selection.

Final result publication is shared through `tests/support/publication.py`. After owned cleanup, it samples scalar interruption state before encoding, publishes once, and reconciles at most once more if interrupted during the first publication. Interrupted results stay failed/exit1. Its last pre-encoding sample defines `parent_interrupts`: later signals can update the scalar handler but cannot force more writes or mutate the saved result. Retained resources remain the coordinator's responsibility and are preserved in the report.
