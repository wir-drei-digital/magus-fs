# FS2-A standalone service boundary

Task 1 adds `magus-fs-service`, PostgreSQL authority and verified S3 chunk uploads. Upload completion is neither a private revision receipt nor shared publication. Views, descriptors, candidates, branches, sync clients and authorized content reads belong to subsequent tasks; there is deliberately no raw hash-read route.

Run the real isolated gate from this checkout:

```sh
python3 tests/fs2/service_storage.py --output /private/tmp/FS2_NEW_PATH
```

Use a new absolute output directory. Docker, OpenSSL and Rust 1.92.0 are required. The runner builds the pinned Linux image with workspace fmt/clippy/tests, starts owned PostgreSQL and SeaweedFS containers, generates private synthetic credentials/CA, exercises HTTPS and inspects actual backing bytes/state. It retains command, source, backend, response and cleanup evidence. Exit 0 means the Task 1 local gate passed; 1 means observed failure and 2 means infrastructure unavailable. This does not qualify Infomaniak or close FS2.

The PostgreSQL and S3 image indexes, selected platform images, flags, mounts and resource limits are retained in the output. PostgreSQL uses `/var/lib/postgresql` with PGDATA `/var/lib/postgresql/18/docker`, fsync/full_page_writes/synchronous_commit enabled. SeaweedFS has one 1GiB volume and persistent filer metadata. PG is limited to 512MiB/2 CPUs, S3 to 1GiB/2 CPUs and the service to 512MiB/2 CPUs; each has pids256. Only the service port is published, on random host loopback through a separate owned ingress bridge. PostgreSQL and S3 attach only to the internal backend network; the service attaches to both. Backend credentials and all state live outside content. Explicit backend credentials travel over the private owned Docker network; this local trust boundary is not a production backend-transport qualification.

## Service and administration

```sh
magus-fs-service provision /ABS/PRIVATE/service.json /ABS/PRIVATE/bootstrap.json
magus-fs-service serve /ABS/PRIVATE/service.json
```

Configuration and provisioning inputs must be ordinary owned mode0600 files within mode0700 private directories. Every path component is opened without following symlinks; use canonical absolute paths. Provisioning is trusted local administration using the database credential. Errors and Debug values redact credentials and backend details. Bearer tokens are 256 random bits, lowercase hex on the wire; only SHA256 digests enter the database. Provisioning accepts a bounded array of namespace/principal/replica/token/expiry/action/branch/prefix records. Administrative HTTPS delegation creates a fresh token returned once; grant revocation increments generation and invalidates descendants.

Configuration fields: `listen`, `database`, `s3_endpoint`, `s3_bucket`, `s3_access_key`, `s3_secret_key`, `private_backend_http`, `tls_cert`, `tls_key`. The last two identify private PEM files. Backend HTTP requires the explicit fixture switch. S3 transport uses explicit credentials, path style, no environment discovery, no proxy inheritance, no redirects and no automatic retries. The exposed service supports TLS only and never redirects HTTP to HTTPS. Fixture clients trust only the generated CA, including strict CA key-usage validation; wrong roots, wrong hostnames and expired certificates fail. The gate injects unusable ambient proxy settings and exercises a real307 backend redirect, requiring exactly one request and no redirected request. Do not put profile/configuration files in mounted content.

## Public interfaces

Core `protocol` exports distinct validated random128-bit lowercase-hex `NamespaceId`, `UploadId`, `ViewId`, `ReceiptId`, `HeadToken` and `RemoteSourceId`, plus validated `BranchName` and upload/control bounds. Existing canonical IDs and revision bytes remain unchanged.

The service exports `ServiceState::open(Config) -> async Result<ServiceState>`, `serve(ServiceState, std::net::TcpListener, RustlsConfig, shutdown_future) -> async io::Result<()>`, and `AuthContext` with read-only identity getters and scoped `permits`. Context fields are private to the service crate and originate only in credential validation. `VerifiedObjects::install(&AuthContext, &UploadId, &ObjectId, Bytes) -> async Result<()>` owns reservation, backend installation and readiness. Task 2 supplies a view-authorized read boundary rather than exposing raw object lookup now.

| Route | Result |
|---|---|
| GET `/health` | Protocol and liveness only; not backend readiness |
| POST `/v1/n/{namespace}/uploads` with `{}` | Owned 15-minute leased upload ID, capped at credential expiry |
| GET `/v1/n/{namespace}/uploads/{upload}` | Only completed objects of the caller's current credential/session |
| PUT `/v1/n/{namespace}/uploads/{upload}/objects/{sha256:id}` | Exact whole-object body, digest, size and verified readiness |
| POST `/v1/n/{namespace}/grants` with `revoke` or `delegate` | Current admin scope required; delegation narrows scope and expiry |

All JSON inputs are closed. Staging requires `write`; it grants no read/publication authority. Invalid/expired/revoked credentials return401, cross-scope resources404, malformed/hash mismatches400, bounds413, conflicts409, backend uncertainty503. Session reuse rechecks credential generation, ownership, parent authority and lease. Object bodies are at most1MiB; control JSON64KiB; each session4096 objects/512MiB. Bodies have a3second read deadline, requests10seconds, database acquisition/connect2seconds and queries2seconds. At most32 requests enter handlers concurrently. Clients own their bounded retry policy.

## Durability and crash behavior

Every mutation locks the namespace row before object rows. A bounded serialized PostgreSQL connection guards transactions; S3 I/O runs outside a transaction. Closed connections reconnect after backend restart. A reservation commits its namespace-scoped object generation, storage key and durable lease before storage I/O. Keys include namespace, digest and random generation. Conditional S3 creation prevents overwriting a generation; identical uncertain retries use verified readback. Only after bounded full readback matches digest and size does another transaction recheck current authentication/session and mark the generation and session object ready.

A crash after S3 install but before readiness leaves `uploading`, no completed session listing and no revision receipt. Retry resolves the same immutable generation and then commits readiness. PostgreSQL does not make S3 I/O atomic. The gate separately kills that boundary and restarts service, PG and S3 with retained volumes, then independently hashes stored bytes. Restart readiness records the bucket response and registration of the exact previously present volume IDs; a bucket HEAD alone can succeed before SeaweedFS can read its content. No acknowledged object is reuploaded to make a restart test pass. Detected corrupt stored bytes transactionally make that exact generation unusable and remove it from completed listings. Process-restart evidence is not power-loss certification. GC and concurrent corruption/deletion hardening are later milestones; no collector currently removes leased generations.

The `test-faults` binary alone recognizes the fixture's private `/control/pause-install` barrier, after S3 readback and before readiness. Default builds do not contain that behavior. Tests preserve ownership intent before creating resources and remove only exact label/ID-matching resources. Cleanup failure retains explicit evidence and fails the gate.
