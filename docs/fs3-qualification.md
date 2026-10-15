# FS3 local technical qualification

FS3 is not yet qualified. Local unsigned archives cover only macOS ARM64 and Linux ARM64. No hosted provider, x86_64, notarization, public release or updater is implied. Retained isolation and scale runs have their own immutable source/binary identities; current scripts do not claim they were rerun.

## Build and package

Use Rust 1.92.0 (verify `rustc +stable --version`). With the reviewed sources and existing Linux release image available:

```sh
python3 scripts/package.py --prepare-host --host-build-proof /private/tmp/NEW_HOST_BUILD.json
python3 scripts/package.py --output /private/tmp/NEW_PACKAGES --image sha256:IMMUTABLE_RELEASE_IMAGE --host-build-proof /private/tmp/NEW_HOST_BUILD.json
python3 tests/fs3/packaging.py --package-manifest /private/tmp/NEW_PACKAGES/manifest.json --output /private/tmp/NEW_PACKAGE_CHECK
```

The host build is a single cached default-feature release build. Packaging requires its exact unchanged runtime-source and binary record. The currently accepted Linux freeze is `sha256:875888cb5586f46489613188c8b227227348d6fcb056ec0b675e2571c8335f32`; another image requires an explicit reviewed build record update. Linux default binaries are read from the immutable release image and retain the original image/source identity. Only exact MIT Cargo metadata additions and recorded FS3 harness/documentation differences bridge the frozen build. No new build or historical execution is inferred. The manifest records source commit, dirty status, source and diff hashes, compiler/profile, each platform, archive/member checksums and license hashes. Its version/source identity is the package identity; there is no new runtime version protocol.

Archives contain one named binary, MIT, complete third-party notices and this runbook. Sorted members and zero timestamps/owner metadata make repeated archives byte-identical for identical inputs. `SHA256SUMS` also covers the manifest; verify it against your trusted local output. These local artifacts are unsigned; checksums do not authenticate a downloaded publisher.

Use `scripts/package.py`'s `install(manifest, platform, role, new_absolute_prefix)` verifier, as exercised by the packaging phase, rather than extracting an untrusted archive. It verifies all enumerated regular files, rejects links/traversal/absolute/extra/duplicate entries and independently hashes the extracted binary. Existing and interrupted prefixes are never overwritten. Retry into a different new owned prefix. Keep state/config/content outside installation prefixes. Remove only your recorded install prefix; removing a binary does not uninstall or delete state/history.

## Runtime prerequisites and explicit configuration

Linux archives are AArch64 ELF binaries. Inspection of both frozen defaults finds DT_NEEDED `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, loader `/lib/ld-linux-aarch64.so.1`, maximum referenced GLIBC symbol version 2.34. They were exercised on Debian bookworm (glibc 2.36); the symbol requirement alone does not qualify another distribution. Client mounts require kernel FUSE, accessible `/dev/fuse`, compatible `fusermount3`, and the required mount permissions/capabilities. No driver or privileged helper is installed by packaging. Python and Docker belong to the qualification harness, not binary runtime dependencies.

macOS uses the existing system loopback NFS adapter and `/sbin/mount_nfs`, with the host's existing Network Volumes permission. System CoreFoundation/CoreServices/Security, libiconv and libSystem are dynamically linked. This is fixed-actor trusted-client NFS, not authenticated multi-user NFS; use separate trusted client identities. Foreign kernel UID authentication and retained-handle/cache revocation limitations remain.

Client commands require explicit private config/state (`init --state ... --config ...`, `capture`, `mount --state ... --revision ... --mountpoint ... --mode private`). See `docs/fs1-local.md`, `docs/fs1-macos.md`, `docs/fs1-linux.md` in the source checkout for the full config contract. A remote profile uses `sync attach --state ... --profile ... --branch main --publication shared-live` with explicit endpoint, namespace, replica, CA and token-file paths. Keep private config mode0600 and control/state directories mode0700, separate from workload mounts. Do not run a second journal writer while a live owner holds the state; use the live control/status interface.

The service archive is only `magus-fs-service`, not PostgreSQL/S3 or fixture tools. Start with `magus-fs-service serve /absolute/private/service.json`; provision through the existing explicit administrative command. Configuration supplies listen address, database, S3 endpoint/bucket/credentials and TLS certificate/key paths. PostgreSQL and S3 must already be reachable and privately administered. The qualification fixture creates isolated synthetic backends and certificates; it is not a production configuration template.

Normal shutdown first unmounts each client, verifies kernel mount absence, then stops/reaps its owner and service. If normal unmount fails, preserve state and helpers for recovery; never delete a mounted directory. Package checks retain raw commands, failed attempts and owned cleanup.

## Durability and phase runner

Local durable writes, PrivateRemote receipt, Shared publication and peer Applied/fresh-byte equality are distinct milestones. A local fsync does not establish remote deletion safety. Explicit dry-run/token-checked pruning preserves protected closures; cache_bytes bounds admitted content, not total disk. SQLite metadata/history and conservative NFS session roots can grow; there is no automatic eviction or history deletion guarantee. Copied plaintext cannot be remotely erased. Performance samples are descriptive, not an SLO.

```sh
python3 tests/fs3/run.py --phase packaging --package-manifest /private/tmp/PACKAGES/manifest.json --output /private/tmp/NEW_RUN
python3 tests/fs3/run.py --phase scale --image sha256:IMMUTABLE_IMAGE --output /private/tmp/NEW_SCALE
python3 tests/fs3/run.py --phase isolation --image sha256:IMMUTABLE_IMAGE --output /private/tmp/NEW_ISOLATION
python3 tests/fs3/run.py --phase all --image sha256:IMMUTABLE_IMAGE --package-manifest /private/tmp/PACKAGES/manifest.json --provider-config /absolute/private/provider.json --output /private/tmp/NEW_ALL
```

Exit0 means the selected phase passed, exit1 failed, exit2 blocked. Only relevant inputs are required. `all` executes the phases; it does not import earlier results. Missing or blocked actual provider evidence can never pass `all`. Provider execution is a later task; no credentials are read by local packaging. Daytona's documented local snapshot import requires AMD64; these ARM64 archives cannot qualify that route. Confirm actual target architecture and endpoint/trust/FUSE/lifecycle prerequisites before a separate AMD64 build or provider run. Keep provider inputs private and workload/control credentials separate. A fake provider can only test failure handling.
