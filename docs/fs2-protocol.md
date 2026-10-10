# Service revision authority (FS2-A Task 2)

The wire protocol is `magus-fs/service-v1`, served over authenticated HTTPS and
WSS. It consumes the [authenticated storage boundary](fs2-service.md). Canonical
`magus-fs/v1` and `magus-fs/v2` bytes and hashes remain unchanged. This service
boundary does not implement a native sync controller or claim replica readiness.

A trusted local provision file may now include `authority` and `root_policy`.
Both are closed DTOs. Authority fields are `principal`, `uid`, `primary_group`,
`gid`, `groups`, `dac_override`, and `ownership_transfer`; root policy fields are
`id`, `owner`, `group`, and `mode`. The principal must match the provision record,
the primary group must be in its unique bounded group list, and root owner/group
and mode must be valid. Policies insert immutably under the namespace lock;
conflicting bootstrap overwrites return `policy_conflict`. UID/GID are inert
mapping data and never authenticate HTTP. Delegated workers use their parent's
logical principal and their own credential/replica, with narrower grants.
Legacy upload-only provisioning remains valid; revision routes fail closed until
policy exists. Delegation supports eight ancestors; attempting to create a ninth
returns `400 delegation_depth` before token insertion.

All routes below use `/v1/n/{namespace}`. JSON requests reject unknown fields.
IDs and branch names use the validated core protocol types. No endpoint accepts
an arbitrary actor, raw full-revision read, or hash-existence query.

| Route | Request / response |
|---|---|
| `PUT /uploads/{upload}/revisions/{revision}` | Exact canonical bytes; validates hash and credential attribution; `{revision,staged:true}` |
| `POST /seed` | `{branch,revision,upload}`; configured root policy, root-scoped admin, empty branch and verified closure required; shared receipt |
| `POST /views` | `{branch}`; `{view,head,revision}` |
| `GET /views/{view}/descriptor` | Exact projected canonical descriptor, no file bodies |
| `GET /views/{view}/objects/{object}` | Verified bytes only when reachable through the caller's currently authorized view |
| `POST /candidates` | `{operation,replica,original_view,original_head,revision,upload}`; private receipt |
| `POST /integrations` | `{operation,replica,candidate_receipt,expected_head,branch}`; shared receipt, retained `409 stale_head`, or (collaboration-v1) retained `409 {code:"conflicted",conflicts}`; see [fs2-reconciliation.md](fs2-reconciliation.md) |
| `GET /operations/{replica}/{operation}` | Original result/status after current authorization |
| `GET /changes?branch=main&after=0&limit=128` | `{events:[{sequence,head}],cursor}`; ordered durable paging |
| `GET /notifications?branch=main` | Authenticated WSS, messages `{cursor}` only; hints are disposable |

A private receipt contains `receipt`, `operation`, `replica`,
`submitted_revision`, `original_view`, and `original_head`. A shared receipt
contains `receipt`, `operation`, `replica`, `submitted_revision`, `branch`, and
`head`. Both preserve submitted revision identity. The head is an opaque token;
fetch a new authorized view to obtain the projected accepted snapshot. It is not
a full revision hash. Upload/staging acknowledgement is not a private receipt.

Each view is immutable, bound to its issuing credential, principal, replica,
branch, full server base, exact projected descriptor, and visible identities.
Its canonical snapshot has empty parents and its own hash. Coverage is root
relative. Full ancestry stays server-side. Old view access requires current
history/read scope and current identity/ancestor permissions; absent identity
recovery is explicitly outside A. Current permission checks are conservative:
if any formerly visible identity is no longer authorized, the old descriptor is
denied. A fresh view can expose the remaining authorized subset. Projection retains an
entry only when its entire authorized ancestor chain is retained; denied
directory metadata is never added merely to repair structural closure.

A submitted candidate parents the projected base, directly or through a bounded
single-parent chain staged in its owned upload. Every intermediate descriptor
is checked; up to 128 staged revisions and 64 MiB total descriptor bytes are
accepted. v2 decoding remains supported for staging, but scoped restore/lift
returns `unsupported_operation`; A does not strip restoration provenance.
Only operations derived from visible identities are overlaid on the full base.
Unseen siblings remain intact. Removing or moving a directory with unseen
descendants fails closed. Core authorization independently checks grants,
readonly, current rwx, owner/group transfer rules, and both move paths. Existing
metadata cannot be changed in the same candidate to manufacture write access.

Submitted bytes remain staged, and immutable operation records retain their
request, source view, submitted revision, derived full revision, actor and
replica. Derived candidates parent the original full base. Private candidates
do not update the shared branch. Integration requires the expected head to be
the current head (else a retained `stale_head`). In A it was fast-forward only;
FS2-B Task 2 merges a candidate with an older base three-way against its recorded
full base, or retains immutable conflicts, without rebasing or replacing either
candidate ([fs2-reconciliation.md](fs2-reconciliation.md)).

Operations are keyed by namespace, replica and operation ID, with credential,
principal, kind and canonical request digest binding. Exact replays return the
original receipt/status; changed requests return conflict. Replays reauthorize
current credentials, scope and tree permissions. Current path stability is
checked for the actual authorized delta and its required ancestor identities;
an unrelated unchanged hidden sibling move does not invalidate a private receipt
or prevent a durable stale-head result. Receipt possession alone grants
no access. Candidate and integration IDs must be distinct operations.

Descriptor decoding/projection/authorization happens between short database
phases. Each DB phase retains the reviewed 2-second client deadline and connection
invalidation rules. Final transactions lock the namespace before ordered object
rows, recheck current credentials/grant generation and head, verify object
readiness, then commit references, receipt, branch and event together. Immutable
S3 installation precedes these references; PostgreSQL does not make S3 I/O atomic.
Concurrent integration retries a changed preparation at most three times with
100/300 ms backoff. Seed/candidate/integration requests have a 60-second outer
budget; ordinary requests retain 10 seconds. There are no implicit HTTP retries.

The existing global admission cap remains 32 requests. Descriptor staging, view
projection/object reachability, candidate/seed/integration and operation lookup
share a two-request revision-work cap, acquired before large body allocation.
Durable change paging and each WSS polling tick acquire that cap for the bounded
work only; an idle WSS connection holds no revision permit. Pressure returns
retryable `503 backpressure`. No CPU or storage work is spawned past cancellation.
This is a bounded PoC throughput policy, not a worst-case 512 MiB memory proof.

Durable events return only cursor and opaque head, filtered by current scope and
permissions. Their internal affected paths never appear in responses. Pages scan
at most 128 rows; an empty filtered page may advance the cursor. Poll until caught
up even with WSS connected. The current implementation retains the log; a
negative cursor returns `expired_cursor`, a cursor beyond the branch log returns
`invalid_cursor`. WSS rechecks authorization every polling tick and closes on
revocation. Messages/frames are bounded to 1024 bytes. Notification delivery does
not establish application readiness or replace `/changes` backfill.

Run the real boundary gate with a fresh absolute output directory:

```sh
python3 tests/fs2/service_protocol.py --output /private/tmp/FS2_PROTOCOL_NEW
```

It records compiler/dependency/source/image provenance, direct HTTP observations,
private control files, database invariants, restart evidence and exact owned
cleanup. Exit 0 means the implemented service boundary passed, 1 means observed
failure, and 2 means a missing prerequisite. Later FS2 tasks own local durable
queues, native application, connected mounts and broader reconciliation.
