# FS2-B recovery

One replica owner journals local capture, original publication requests, incoming cursor and
safe discovery/acknowledgement codes. Restart never substitutes a new base or operation for
an uncertain request. Current authentication runs before lookup/upload; operation lookup
recovers an immutable result and does not itself publish. `cursor_expired` triggers a current
authorized snapshot; pending local candidates remain retained. `base_unavailable` remains an
explicit recovery outcome, never invented ancestry. Transport failures stay retryable;
revoked/narrowed authority denies remote effects without erasing already cached local bytes.

`sync status` includes `status.incoming` with the durable cursor, snapshot requirement and
redacted discovery/acknowledgement codes. It contains no raw URL, transport body or credential.
Native startup resolves unchanged missing chunks through their verified per-object source
bindings under the current transport credential, including after a local checkpoint.

`sync recovery list|capture|export|release` retains the Task 1 opaque selectors. Additionally:

```
magus-fs sync recovery compare --state STATE --archive ABSOLUTE_ARCHIVE
magus-fs sync recovery import --state STATE --archive ABSOLUTE_ARCHIVE --operation-id OPERATION
```

The live owner verifies every archive member, compares content paths, and imports a new
attributed local revision against the actual current base, with an immutable source link in
its journal. Current metadata wins for present paths; absent entries receive fresh identities
and safe local metadata. It neither advances the working head nor queues/integrates the new
revision. Source descriptors stay intact. Explicit later selection/publication is a separate
operation. Recovery imports are bounded to128 and retained as local GC roots.

Authenticated history uses `GET /history?view=VIEW&cursor=TOKEN` and
`POST /history/HISTORY/view {}`. Pages are at most32 summaries/64KiB with query/principal-bound
opaque continuation. Only entries of actually published shared revisions appear; a private
merge parent is never a history grant. Every list/pin/content read checks current read/history,
current ancestor permissions and historical/current path scope. Deleted or moved-out entries
require all of `history`, `admin`, `retained_history` and a currently readable scoped parent.
A former reader cannot use an old history selector to reopen deleted content. Exact-file
grants retain only required directory scaffolding, with current ancestor permissions.

`POST /restores` accepts `operation`, `replica`, `history`, `expected_head` and
`restore_metadata`. It creates a new shared revision. Default false keeps current owner,
group and mode. A deleted entry receives a fresh EntryId with current actor/group and0644,
subject to current destination parent policy. Metadata restoration is an explicit admin
request and must pass normal metadata/ownership checks. The expected head and current grant
are rechecked at commit. The immutable restoration sidecar records the full historical source;
ordinary current projections retain canonical standalone `parents: []` and omit historical
lineage. Reading restored current content does not require history permission. Exact committed
restore replay/lookup recovers the immutable receipt after current authorization checks,
including parent write policy for a deleted destination; a fresh occupant at the same name
does not readmit the old effect. New restore operations still reject name/identity collisions.

Trusted local storage collection is configuration-bound, never a client endpoint:

```
magus-fs-service gc PRIVATE_CONFIG --namespace NAMESPACE --dry-run
magus-fs-service gc PRIVATE_CONFIG --namespace NAMESPACE --plan OPAQUE_TOKEN
```

Dry-run records exact immutable generations. Execution locks namespace then object generations,
rechecks active leases and all retained revision references, marks deleting before backend I/O,
and deletes only that exact generation. A killed collector resumes the same plan. Referencing a
marked generation is refused. Every committed revision closure remains a root in this PoC:
private/shared receipts, operations/bases, conflicts/resolutions and issued history/view pins.
Thus committed history retention is unbounded; collection reclaims only expired partial uploads
and never-referenced generated objects. This deliberately preserves acknowledged recovery.
Synthetic test expiry values do not alter production retention defaults.

PostgreSQL fixtures use fsync/full_page_writes/synchronous_commit on persistent owned volumes;
S3 fixtures retain their owned volume and verified immutable generations. Restart evidence is
specific to those declared settings. Missing/corrupt bytes never count as ready; corruption
quarantines the witness. Qualification does not imply a remote-provider durability guarantee.

Run fresh owned fixtures with:

```
python3 tests/fs2/recovery.py --platform all --output ABSOLUTE_NEW_PATH
python3 tests/fs2/service_faults.py --output ABSOLUTE_NEW_PATH
python3 tests/fs2/client_protocol.py --output ABSOLUTE_NEW_PATH
```

Focused `--case` and immutable `--reuse-image` recovery runs are development evidence and are
marked incomplete. Images must match the complete captured source manifest. Exit0 means the
selected cases and owned cleanup passed, exit1 an observed failure, exit2 missing prerequisites.
Full FS2/PoC qualification belongs to Task 6 and retains fresh state twice.

Trusted corruption repair accepts verified replacement bytes in a private source file:

```
magus-fs-service repair PRIVATE_CONFIG --namespace NAMESPACE --object OBJECT --source PRIVATE_BYTES
```

Repair keeps the corrupt immutable generation as quarantine evidence, verifies a fresh
conditional-create generation by hash and size, then atomically rebinds retained references.
Canonical descriptors and recorded receipts remain intact. An interrupted attempt never
exposes unverified bytes; its proposed generation remains durably owned for resume.
Quarantine/unfinished repair storage is retained without pruning in this PoC.
