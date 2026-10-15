# FS3 Daytona qualification

Task4 is partial and blocked. On 2026-10-15 an actual `daytona-medium`
container (snapshot image `daytonaio/sandbox:0.9.0`) ran Debian13/AMD64,
glibc2.41, FUSE and ordinary synthetic write/fsync/read through Debian
bindfs1.14.7. Normal unmount failed with ENOENT. The packaged magus-fs client
has **not** run on Daytona, and hosted FS3 is not qualified.

## Read-only preflight

```sh
python3 tests/fs3/daytona.py \
  --package-manifest /absolute/package/manifest.json \
  --provider-config /absolute/private/provider.json \
  --output /absolute/new-preflight --preflight
```

The provider JSON must be mode0600. It may contain `daytona_env_file`,
`service_url` (HTTPS), `service_ca_file`, `client_config_file`, and a redacted
`capability_evidence` object. The environment reader selects only
`DAYTONA_API_KEY`; it never executes shell environment files, logs the value,
or puts credentials in argv. Preflight uses only the official GET
`/api-keys/current`, checks lifecycle permission names and package archive
hashes, and reports exact missing prerequisites. It never creates sandboxes,
ports, snapshots, services or other resources. Exit2 is blocked; exit1 includes
an observed failure or unresolved owned cleanup. Preflight cannot exit0.

Without `--preflight`, this partial driver still emits an explicit incomplete
result. There is no implemented live magus-fs journey to invoke yet. Do not
replace that gate with the bindfs capability probe, local Docker proof, or
unit-test fixture output.

## Verified obstacle and preserved evidence

The first empty capability-only worker mounted an uninitialized FUSE device
and could not normally unmount it. F6 explicitly permitted deleting that exact
empty worker after preserving diagnostics: no magus-fs installation, build,
save, publication, or unique user bytes existed. Provider GET404 and failed SSH
confirmed removal. This exception did not qualify normal teardown or waive
receipt/recovery requirements for actual work.

One replacement worker used a real bindfs daemon. Ordinary UID1002 wrote,
fsynced and read exact synthetic bytes; it could not sudo. Default `daytona`
UID1001 has passwordless sudo and is consequently a control identity, not a
qualified unprivileged workload. Root owns the daemon. Normal fusermount3 and
direct `umount2(path,0)` both returned ENOENT while the live mount remained.
Control and daemon shared the same mount namespace/root; direct and
`/proc/<daemon>/root` path identities matched. A syscall trace and sysboxfs
fingerprints were retained. No force/lazy unmount or host configuration change
was attempted. The owned replacement and helper are preserved pending an
explicit lifecycle decision; auto-stop30minutes and no auto-delete remain.

The observed failure matches the open upstream
[Daytona issue5167](https://github.com/daytonaio/daytona/issues/5167).
[sysbox-fs fix103](https://github.com/nestybox/sysbox-fs/pull/103) explains a
similar FUSE path-access failure. This is supporting diagnostic context, not
proof of the actual Daytona host component version or root cause.

No magus-fs endpoint existed or was exposed. The prepared route was an owned
local default ARM64 service with synthetic private PostgreSQL/S3 and
end-to-end TLS into sandbox loopback. Daytona's documented SSH access works,
but native reverse forwarding was rejected. A minimal byte-blind SSH-stdio
relay was considered; it was neither implemented nor started because FUSE
teardown failed first. No AMD64 cross-build, new package, public ingress,
provider purchase, production deployment or provider contact occurred.

Primary interfaces inspected: [FUSE](https://www.daytona.io/docs/en/mount-external-storage/),
[SSH](https://www.daytona.io/docs/en/ssh-access/),
[sandboxes](https://www.daytona.io/docs/en/sandboxes/),
[REST API](https://www.daytona.io/docs/tools/api/). No SDK dependency was added.

## Resumption gates

1. Resolve the provider lifecycle decision. Preserve the failed probe and
   exact resource ownership. Do not silently waive normal unmount or replace
   it with sandbox deletion.
2. Prove the selected private transport with bounded concurrent binary streams,
   close/disconnect/capacity tests and an actual TLS probe. Keep service and
   control credentials outside the non-sudo workload identity.
3. Build the exact observed architecture only after those prerequisites pass.
   The accepted packages currently contain ARM64 only. The proposed separate
   local cross-build uses Rust1.92.0, release/default client, four jobs,
   12GiB cap, 1800-second ceiling and isolated caches; it has not run. Preserve
   source/build/binary/license hashes and qualify its actual packaged mount.
4. Run the hosted scope/readonly/private-history/API-bypass/revoked-reconnect
   assertions and cold/warm/range measurements with actual ordinary I/O.
5. Bind the save's operation, revision, certain remote receipt and exact bytes.
   Recover independently before teardown. Normally unmount and stop owned
   helpers, delete only the owned sandbox, confirm absence, and independently
   recover the same bytes afterward. An uncertain ACK or failed independent
   pre-deletion recovery must prevent deletion. No unit fake qualifies these.

`validate_provider()` checks required evidence fields and ordering;
`deletion_permitted()` is the fail-closed receipt/recovery/normal-teardown guard.
They are shape/consistency validators, not a claim that supplied JSON proves
execution. The future live driver must bind raw remote commands, hashes,
receipts and independent recovery to those fields.

## Reuse accepted evidence without repeating matrices

```sh
python3 tests/fs3/run.py --phase all \
  --evidence-manifest /absolute/private/evidence-index.json \
  --output /absolute/new-aggregate
```

The index records `current_source` (the exact package-source manifest) and a
`phases` map. Each executed entry has `result`, its `sha256`, the original
`source` manifest, an exact `differences` map with `earlier`/`current` hashes,
and the review reference. Every retained result is hashed and normalized;
no subprocess or native phase is launched. Missing provider proof remains
blocked and unresolved provider cleanup fails the aggregate.

Runtime changes are rejected except the exact reviewed Task2 attach-error
classification hashes and exact MIT metadata additions. The earlier inventory
omitted `.dockerignore`; its one explicit extension uses the byte-identical
accepted Task3 hash. Every harness/documentation addition or modification is
still enumerated with exact hashes. This is a source-attributed composition,
not a claim that old tests ran again on current code. Original failed runs and
their source identities remain unchanged.
