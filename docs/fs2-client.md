# FS2-A durable client and authenticated source

The client uses the replica's existing exclusive SQLite journal for its binding, submission queue, original requests and revision-scoped receipts. The CLI owns HTTPS credentials. Core has no new network dependency. This checkpoint implements publication and lazy object reads; it never claims native application or replica Applied readiness.

## Trusted profile and attachment

Create a private directory mode 0700 outside all configured content roots. Its profile, CA and token files must be regular single-link files owned by the effective user, mode 0600, with no symlink components. All paths are absolute. The bearer file contains exactly 64 hexadecimal characters, without a newline.

```json
{"endpoint":"https://host.example:8443","namespace":"0123456789abcdef0123456789abcdef","replica":"replica:0123456789abcdef0123456789abcdef","ca_file":"/private/client/ca.pem","token_file":"/private/client/token"}
```

Use the existing `magus-fs init --state STATE --config CONFIG` to create an empty local replica, then:

```sh
magus-fs sync attach --state STATE --profile PROFILE --branch main
```

Attachment fetches a standalone authorized projected descriptor and zero file bodies. The default publication mode is `isolated`; only explicit `--publication shared-live` enables automatic integration. The opaque RemoteSourceId maps to one exact namespace/view/profile identity. A distinct TransportIdentity hashes the normalized endpoint, namespace, replica, CA bytes and credential-file path; token contents are excluded to allow rotation. Each request checks current files and this fingerprint. An existing binding cannot be retargeted in this task; safe view advancement belongs to later application work.

TLS validates the explicit CA and hostname. HTTP, URL userinfo/query/path, redirects and ambient proxies are refused. Async HTTP runs on a dedicated ordinary-thread runtime even when a native adapter calls the synchronous callback from Tokio. Runtime shutdown is bounded. A process-wide admission limit permits at most four blocking DNS resolutions across all transports, including requests whose deadlines have expired; each permit remains held until the underlying resolution actually finishes. Exhaustion returns retryable backpressure. Callbacks cannot re-enter Core. Missing native object reads share the original 4.5-second deadline; complete bytes must match both expected size and SHA256 before cache installation.

## Publication and revision-scoped status

After a local checkpoint, enqueue its revision with that checkpoint descriptor's original OperationId:

```sh
magus-fs sync run --state STATE --revision REVISION --operation-id OPERATION --enqueue-only true
magus-fs sync run --state STATE
magus-fs sync status --state STATE --revision REVISION
magus-fs sync drain --state STATE --revision REVISION --level private-remote --deadline-ms 60000
magus-fs sync integrate --state STATE --revision REVISION --expected-head HEAD_TOKEN
```

`sync status` without a revision lists retained records. Durability levels are `local`, `private-remote`, `shared` and `applied`; Applied explicitly returns unsupported in Task3. Unknown revisions and unknown levels fail. A private receipt and a shared receipt refer to their submitted revision, so later dirty work cannot change an earlier revision's receipt. Integration persists a different OperationId and explicit expected head before sending; it never rewrites the candidate's original view/head/request.

`sync run --state STATE --serve true` owns the journal and private control socket in the foreground. Concurrent sync/checkpoint/history/status commands use the authenticated owner channel. No CLI command opens a competing writer. Mount owners expose the same channel; read-only owners reject mutation/sync requests.

The queue retains original candidate/base object closures through pruning and restart. Enqueue checks generation and rejects changes under an existing operation ID. At most 128 unresolved submissions are admitted; pressure retains existing work. Upload closure is bounded to 4096 objects / 512 MiB; staged ancestry to 128 revisions / 64 MiB descriptor bytes. Each whole chunk is at most 1 MiB. Ordinary control requests, responses and errors remain bounded to 64 KiB. Only `GET /uploads/{id}` permits a 512 KiB response so a completed list of up to 4096 objects fits; its closed DTO validates unique IDs, each size, total size and upload identity. Only required objects absent from the authorized base and completed owned upload session are uploaded.

Counters distinguish requests, retries, received object-body bytes (including partial or invalid replies), attempted upload-body bytes offered to HTTP, and successfully acknowledged logical unique upload bytes. Upload counters do not claim socket-level transmitted bytes; interrupted attempts may be counted again. Counters are per controller/command, not durable accounting.

A tick makes at most 3 attempts, with 100/300 ms backoff and no implicit HTTP retries. Ordinary requests use 2-second connect / 10-second total bounds; publication and target drain have at most 60 seconds total. An incomplete drain exits nonzero with `ok:false`, a typed reason (`deadline`, `integration_required`, or the retained failure), and the full revision-specific progress. The same result passes through the private owner channel. Successful drain returns only when its requested receipt is present (or Local is requested).

Before candidate/integration POST, the exact request is journaled and its remote outcome marked unknown. Restart queries the authorized operation result first. An ambiguous 404 permits only bounded exact replay of that persisted request, which the service reauthorizes. A matching result resolves uncertainty. Current denial retains the original bytes/request and possible prior-commit flag. Expired upload sessions do not silently generate a new upload/digest; explicit recovery is future work.

## Reproduction

```sh
python3 tests/fs2/client_protocol.py --output /private/tmp/FS2_CLIENT_NEW_PATH
```

The gate uses synthetic owned PostgreSQL 18, SeaweedFS, explicit fixture TLS and the actual CLI/core/transport. A separate example probe invokes ordinary public Replica APIs with the production transport for range/full reads and local edits. It does not bypass authentication, hashing or queue state. The gate records compiler/dependency/source/image inputs, transfer counters, exact receipts, process kills and cleanup. Exit 0 means the implemented boundary passed, exit 1 is a failure, exit 2 a missing prerequisite. Native mount live adoption/application is a later gate.

The upload-list resume amendment also has a narrow source-matched gate: `python3 tests/fs2/client_upload_listing.py --output /private/tmp/FS2_LISTING_NEW_PATH`. It proves reuse after an owned upload session has a completed listing larger than 64 KiB, without changing the persisted request or base.
