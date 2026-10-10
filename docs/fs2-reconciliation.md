# Reconciliation and immutable conflicts (FS2-B Task 2)

This extends the [service revision authority](fs2-protocol.md) and the
[native client](fs2-full.md). Canonical `magus-fs/v1`/`v2` bytes, the closed
service-v1 DTOs and their request digests are unchanged. New behaviour is advertised
by the unauthenticated `GET /capabilities` →
`{"protocol":"magus-fs/service-v1","capabilities":["collaboration-v1"]}`; `/health`
bytes are unchanged. New DTOs live in core `collaboration_protocol.rs`; new requests use
the existing digest rule (SHA-256 of the compact struct-order JSON).

## Pure reconciliation (core `reconcile.rs`)

`reconcile_trees(base, left, right, policy, objects) -> MergeOutcome` matches entries by
stable `EntryId`, never by path. Location is `(parent identity, leaf name)`, so an
ancestor rename composes with an edit or rename of a descendant; location, content and
the permission tuple (owner, group, mode) merge independently. The tuple is one unit:
different tuple changes on the two sides (even group on one side and mode on the other)
are a `metadata` conflict, never a composition neither side authored. Identical changes
coalesce. A known base of
the same root identity is required. Outcomes:

- `Clean { tree, mechanically_merged }`: `mechanically_merged` lists identities whose
  text was merged; it means *mechanically* merged, never semantically correct.
- `Conflicted { alternatives }`: immutable `EntryConflict { id, base, left, right,
  reason, policy }` records. They contain only input entries, never marker or generated
  content. Reasons: `content`, `text_overlap`, `merge_budget`, `edit_delete`, `add_add`
  (new identities on one case-folded parent/name), `path_collision`, `competing_rename`
  (including move cycles), `directory_delete`, `metadata`, plus the service-only
  `unknown_causality` and `missing_base` (no ancestor is ever chosen silently).

Text merge is opt-in per branch: `MergePolicy { text_extensions }` is a normalized
(lowercase, sorted, unique, ≤32) allowlist; the default is fully opaque. CSV/TSV and
office/PDF/archive formats cannot be allowlisted. Each base/left/right must be
≤256 KiB, ≤4096 lines, valid UTF-8 without NUL, and output ≤1 MiB. A candidate gets at
most 16 text merges and 8 MiB summed input, admitted in identity order; anything else
is a retained `merge_budget` conflict. diffy `=0.5.2` (no default features) performs
the merge; its `Err` marker text is discarded. `resolve_trees_with(..., default, choices)` applies an
explicit base/current/candidate selection per identity (with a default), repairing
missing parents, move cycles and collisions toward the chosen side, and fails instead of
guessing.

## Service integration

`POST /integrations` keeps expected-head CAS. If `expected_head` is not the current
head the result is the retained `409 stale_head`, as before. Before any retained outcome
(stale or unknown causality) is recorded, the candidate is re-authorized under current
rights — credential, grant, current metadata and scope of its delta — without requiring
unrelated path stability (ruling R12); a revoked or narrowed submitter is denied and no
409 result or conflict row is written. Otherwise:

1. A candidate whose revision or unpublished ancestry carried
   `native_unknown_causality` (recorded at candidate time in `candidate_causality`;
   older candidates fall back to their own provenance) is never fast-forwarded, rebased
   or merged: one whole-candidate `unknown_causality` conflict is retained with
   base/current/candidate alternatives (rulings R1/R6/R10).
2. A candidate based on the current head fast-forwards exactly as in A.
3. Otherwise the original private candidate (lifted to the full tree) is merged with
   its recorded full base and the current full destination. Ruling R11: using the
   caller's own issued view as a write base (candidate submission, integration, merge,
   receipt replay) does not need `history`; reading an old view's descriptor or objects
   still does. Text inputs are read from verified storage
   and merged by a separate `magus-fs-service merge-worker` process (empty environment,
   bounded framed stdin/stdout) under one 5 s deadline outside every database lock; the
   deadline, a crash or malformed output become retained `merge_budget` conflicts. A
   clean merge produces a revision whose parents are `[current full, candidate full]`,
   attributed to the integration operation; the complete resulting delta
   (current → merged) is re-authorized under current rights and scope, so a permission
   narrowed or an identity moved out of scope since the base denies publication
   (`404`) and the private receipt stays retained. Unchanged hidden siblings take the
   current state. Generated chunks are installed under a fresh generation and verified
   by readback before the single atomic metadata/head/event/operation commit; a commit
   that dies leaves at most unreferenced ready objects for later GC.
4. Conflicts are only disclosed when every identity they name was visible to the caller
   (current projection, original view or its own new entry); otherwise the result is a
   plain `404`. A conflicted integration records the operation (`409`,
   `{"code":"conflicted","conflicts":[ConflictId…]}`, replayed exactly) and at most 128
   immutable conflict records; more becomes one whole-candidate `merge_budget` record.
   The branch, events and every other change of that candidate stay unpublished.

A commit that finds the head moved retries the whole decision (≤3 attempts, 100/300 ms);
because of CAS that yields `stale_head`. Merge and resolution provenance (submitted,
projected base, full base, candidate, current, mechanically merged identities) is a
service-only sidecar (`revision_provenance`); projected views keep empty parents and do
not enumerate server-side lineage.

## Conflict records, alternatives and resolution

Migration `004_collaboration.sql` adds `branch_merge_policy`, `candidate_causality`,
`conflicts` (immutable payload + digest, bound to the original candidate receipt, full
base, candidate and current revisions, original and current heads and the integrating
operation; unique per integration and entry), `conflict_alternatives`,
`conflict_resolutions` (separate link rows) and `revision_provenance`, plus
`views.alternative/alternative_entry`. Nothing is backfilled.

| Route | Request / response |
|---|---|
| `GET /capabilities` | unauthenticated `Capabilities` |
| `GET /conflicts?cursor=` | `read`; conflicts of candidates submitted by the caller's replica (the holder of the original private receipt) on granted branches, omitting entry conflicts whose identity is authorized on no side under the current grant/scope/metadata; `ConflictPage {items: ConflictSummary{id,receipt,reason,state}[≤32], next}`; the cursor is namespace/principal/query-bound |
| `GET /conflicts/{id}` | `ConflictDetail {summary, alternatives: AlternativeRef{id,side,entry,path}[≤3], expected_head}`; hidden (`404`) under the same rule; `path` only when the identity is present on that side and currently authorized, `path: null` means absent *or* unauthorized |
| `GET /conflicts/{id}/alternatives/{alt}` | an authorized pinned `ViewBinding` for the ordinary descriptor/object routes; authorization runs first, so an absent identity and an unauthorized one are the same `404 not_found` |
| `POST /resolutions` | `ResolutionRequest {operation, replica, conflicts[1..128], expected_head, replacement}` → `SharedReceipt` |

Alternative views project the side's immutable tree under *current* metadata for
identities that still exist (a historic mode never reopens access); identities absent
from the current head need `history`. They are re-authorized on every descriptor/object
read and can never be a candidate base.

A resolution names every conflict retained by the integration(s) it resolves
(`400 incomplete_resolution` otherwise) and a complete private replacement candidate
based on `expected_head`, submitted by the same replica that holds the conflicted
candidates' original private receipts (others get `404`; ruling R12). The service rejects a changed head (`409 stale_head`,
recorded), an already resolved conflict (`409 already_resolved`), an
unknown-causality replacement (`400 invalid_resolution`) and anything the current
rights do not allow (`404`): resolution never broadens access or grants metadata
privileges. The published revision is the lifted replacement with the conflicting
candidates added as parents; links are recorded per conflict, and the original
alternatives stay addressable and exportable.

## Client

Journal schema 4 (in-place from 1–3; newer schemas fail closed) lets sync records
carry `superseded` stale integration attempts, an immutable `resolves` target, the
`resolution` request and a `resolved_by` link. A shared-live owner that receives a
definitive `stale_head` keeps that attempt on record and retries against the current
head (fetched through `POST /views`), so compatible offline work merges after
reconnect; `conflicted` is a definitive retained outcome and keeps incoming application
blocked. Unknown-causality candidates stay held (Task 1); `sync integrate` turns them
into an `unknown_causality` conflict.

```sh
magus-fs sync conflicts list   --state S [--cursor TOKEN]
magus-fs sync conflicts show   --state S --conflict ID
magus-fs sync conflicts export --state S --conflict ID --alternative ALT --destination NEW_DIR
magus-fs sync resolve --state S --conflicts ID[,ID…] --expected-head HEAD \
    [--select base|current|candidate] [--choices ID:SIDE[,ID:SIDE…]] \
    [--replacement LOCAL_REVISION] [--operation-id OP]
```

Export writes the authorized projection into a fresh `0700` directory (files `0600`,
create-new, verified chunks, ≤512 MiB). `sync resolve` checks every conflict is open and
that `HEAD` is the current head (`stale_head` otherwise: revalidate, never replay),
fetches and imports that view, and composes the replacement with `resolve_trees_with`
(opaque policy) from the candidates' base, the current view and the candidate side. Every
conflict needs a side: `--choices` per conflict, `--select` for the rest (a
whole-candidate conflict's side applies to every entry). The candidate side is the
newest of the named candidates (all on one unpublished local chain with one original
base), or `--replacement`, a later local revision descending from it: edit, rename or
chmod files in the native folder (they stay held — incoming application cannot overwrite
them while the conflict is unresolved), let them be captured, and pass that revision to
replace content, paths and metadata. The replacement is stored as an attributed
`explicit` revision parented on the current view, uploaded as a private candidate and
posted. Once shared, the resolved candidates, their unpublished ancestors and the
replacement source chain get `resolved_by`, which ends the hold: incoming application
resumes. `--operation-id` resumes an interrupted resolution with its frozen request.

Limitations: local composition is opaque, so an entry the service could have text-merged
takes its chosen side when the same candidate also has real conflicts (choose or replace
it explicitly). Stale candidates whose required ancestors were moved or deleted by others
are denied at private submission by the A path-stability rule rather than reaching the
merge.

## Gate

```sh
python3 tests/fs2/reconciliation.py --output /private/tmp/NEW_SHORT_PATH
```

It builds source-matched host and Linux binaries, starts owned PG/S3/HTTPS fixtures and
native ordinary-folder owners on macOS and Linux, and exercises disconnected compatible
and text merges, text/binary/namespace conflicts with atomic non-publication, alternative
export and explicit absence, delayed and commit-raced resolution, the unknown-causality
hold → conflict → resolution → resumed application path on both OSes, scoped
hidden-sibling/move/collision/revocation negatives, the killable worker deadline and a
service killed between generated-object installation and commit. Exit 0/1/2 =
passed/failed/missing prerequisite.
