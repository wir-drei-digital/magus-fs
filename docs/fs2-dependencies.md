# Declared dependencies and restricted CSV validation

FS2-B adds `POST /v1/n/{namespace}/declarations`, `/validations`, and
`/validated-integrations` to collaboration-v1. Existing closed service-v1 candidate and
integration request digests remain unchanged. No declaration means unknown coverage.
Explicit coverage is `complete_declared`, `partial`, or `unknown`; complete means only the
explicitly declared set, never a claim that arbitrary code's undeclared reads were observed.

A declaration is a separate immutable operation, with at most one declaration per private
candidate receipt. Reads identify an owner-issued published view, projected revision and
visible entry. Missing-path assertions identify a normalized path and its observed view.
The service resolves those to authorized immutable full revisions privately. Requests carry
at most128 combined observations and64KiB JSON. Source revisions and candidate output retain
existing committed revision/object roots through migration006 foreign keys. No old immutable
revision bytes, request digests or parent lists are rewritten.

Current authority is checked on declaration, result recording, result replay and publication.
Ordinary historical input reads need their normal current history/read authority; declaration
replay recovers an already-recorded result under current receipt/read/scope guards without
new input-equality or expected-head admission. Unsupported private/conflict/history-export
views are not validator inputs; the configured CSV task reads ordinary published snapshots.

Trusted provisioning may supply `validator_policy` with branch, validator id, version,
executable hash, image digest, worker principal/replica and exact normalized `output_paths`.
The fixture selects `integer-csv` and `report.txt`. A new effect that changes any protected
path/value, including movement/deletion through ancestor changes, needs complete declaration
and a current configured pass. A CSV-only update stays ordinary. Every attached declaration
is enforced even if the report's path or bytes did not change. Optional explicitly selected
validators also require an eligible pass. Fresh history restore changing a protected output
returns `recompute_required`; unrelated restores and admin-only initial seed keep their
existing rules. Exact committed restore/publication results retain their replay semantics.

The central check runs under the existing namespace transaction lock for ordinary integration,
validated integration and replacement conflict resolution. It verifies current authorization,
policy, head, every declared input identity/value and every asserted absence against the
current shared tree and the proposed final state. Thus changing one's own declared input
alongside its derived output cannot pass. Changed observations return `dependency_changed`;
missing or ineligible policy proof returns `recompute_required`. The complete private receipt
remains recoverable. These admission errors do not claim shared acceptance.

`ValidationRecord` binds declaration, expected head, validator/version/executable hash,
pinned input binding, exact output candidate receipt and pass/fail/timeout. A separate
validate-only credential is bound by trusted configuration; ordinary writers cannot submit
passing records. Worker grants cannot include other actions. Raw authorized stale outcomes
are recorded independently of permission to publish. Replay retains current qualifying
identity/action/scope/read guards while recovering an old immutable result after later
head/input/policy-version changes. New publication requires the current policy and current
worker grant, so an old passing result has no authority of its own.

The PoC trusted Linux launcher is `tests/fs2/validation_worker.py`, using the existing owned
fixture infrastructure. It verifies the authorized pinned input descriptor/chunks and exact
private output descriptor/bytes, whose hash must match the candidate receipt. It builds the
fixed integer CSV executable from `tests/fs2/validator/`, pins the built image digest, and
checks the actual image executable hash before launch. Content scripts remain data. The
launcher holds HTTP credentials outside the workload; it submits results using the separate
worker credential. This qualifies the configured local worker, not an external provider.

The exact workload recipe is `--network none --read-only --cap-drop ALL --security-opt
no-new-privileges --pids-limit64 --memory256m --cpus1 --user1001:1001`, with read-only exact
snapshot at `/input`, fresh owned `/output`,16MiB tmpfs `/tmp`, fixed argv/environment,
30s wall deadline and1MiB combined stdout/stderr. No service/backend credential, daemon
control socket, Docker socket, host home, device or arbitrary content executable is mounted.
Only exact owned container/client processes are killed and reaped on timeout/output overflow.
Negative probes use separately recorded test executables/images under the same launch recipe.

The live owner accepts `sync declare --state STATE --request JSON` and existing
`sync integrate --state STATE --revision REVISION --expected-head HEAD`. Automatic mounted
publication may first reach a policy hold. Declaration/validation attachment preserves the
original private receipt; explicit integration creates a fresh attempt for definitive policy
holds while retaining all prior attempts. A recomputed descendant's verified shared receipt
atomically links only definitive dependency-held ancestors in the same bound owner/namespace/
branch, unblocking local applied readiness. Original private receipts/errors stay unchanged.
Siblings, unpublished/foreign candidates, conflicts and unknown causality do not qualify.
SQLite schema7 adds this optional journal link; schemas1–6 upgrade additively, future schemas
fail closed, and older schema6 binaries refuse7. There is no pruning or fabricated backfill.

Run the real combined gate on the qualified macOS/Rancher host:

```sh
python3 tests/fs2/dependencies.py --output /private/tmp/NEW_ABSOLUTE_DIRECTORY
```

The directory must not exist. Exit0 requires mandatory scenarios and normal owned cleanup;
exit1 is failure and exit2 a missing prerequisite. The gate captures exact source/image/binary
hashes, raw requests/receipts, restricted launches, ordinary paused mounted Python input races,
automatic Mac visibility and cleanup. `--phase` or a compatible `--reuse-image` narrows the
evidence and is labeled accordingly; missing cases never count as full qualification.
