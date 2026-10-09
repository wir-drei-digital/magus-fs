# Linux live views and open epochs

An attached `shared-live` Linux mount polls the authenticated durable change log and current authorized view. A separate explicitly trusted WSS connection receives cursor hints; hints are not content authority and do not hold the publication execution gate. Discovery and publication share the bounded `SyncExecution` gate, without holding Core's mutex across discovery requests. The Core journal owns incoming authority, working state, immutable sources and receipts.

```sh
magus-fs sync attach --state STATE --profile PROFILE --branch main --publication shared-live
magus-fs mount --state STATE --revision ATTACHED_PROJECTED_REVISION --mountpoint MOUNT --mode private
magus-fs sync status --state STATE
```

Use `--mode read-only` for an absolute readonly live mount. The default isolated publication mode preserves private work and does not adopt shared updates automatically. Existing unbound FS1 snapshot mounts keep their historical behavior.

## Descriptor semantics

Each accepted remote adoption advances a persistent epoch independently of the ordinary local mutation generation. Files receive distinct native inodes per epoch; directory identities remain stable to avoid invalidating a path walk halfway through a directory lookup. Existing descriptors read the preceding epoch's bytes and size. Current identity, ancestry and permission checks still apply. A remote rename retaining the identity permits old reads under current ancestry. A remote replacement or unlink removing that identity denies old-epoch reads conservatively. Same-epoch open-unlinked, append and fsync semantics are unchanged.

Writes, truncates and handle metadata mutations from an old epoch return `ESTALE` before mutation. Readonly denial remains absolute. No implicit private branch or rebase is created. Epoch trees and their object roots remain protected while descriptors retain them. Native fsync is local durability and does not imply upload or shared acceptance.

Core adopts only clean, generation-matching state. Unresolved submissions and unsubmitted local checkpoints block replacement. A newer authority projection can revoke access while incoming content remains pending; dirty bytes and queued original bases are retained. Legitimate local creates retain their own identity and permissions, subject to the current remote parent authority. The independently journaled authority generation rejects stale observations; its immutable history records authenticated descriptor identities or definitive denial. Authentication denial closes this replica’s mounted remote access; a transient transport outage retains last-known authority. It does not disable unrelated replicas or delete retained bytes. Explicit owner-controlled local recovery/archive APIs retain their existing scope; they must remain outside the workload boundary. These controls cannot erase previously downloaded files or copies and do not replace the existing explicit local recovery/archive rules.

Every incoming source is an immutable opaque identity outside canonical content. The trusted resolver retains its original namespace, projected view and profile binding. A queued publication continues using its original binding and request digest after another view becomes active. Projected snapshots have their own canonical hashes and no parents; they are not the server's full revision DAG.

Refreshing the token file within the same immutable profile requests a fresh credential-bound view/source. A clean mount may adopt it even when the content hash is unchanged. Cached old-epoch reads still require current authority. Uncached reads through an older credential-bound source may fail conservatively after token replacement; A does not promise historical credential rebinding. Dirty content remains retained: `live.pending_revision` and `live.pending_source` distinguish pending content/source adoption from the active epoch, including same-content reauthorization. The older source is never retargeted. Broader offline/archive reauthorization and rehydration remain a B recovery consideration.

## Trusted publication identity

A privately provisioned transport profile may include `"publication_principal": "<configured principal ID>"`. It chooses the attached checkpoint/publication actor; the principal must exist in the local replica's configured authorities and the authenticated service credential must independently authorize the resulting descriptor. This field participates in the immutable transport identity, so changing it after attachment requires a new attachment. Omitting it preserves daemon-owner behavior and existing profile fingerprints.

This is an administrative provisioning choice, not a workload or wire-supplied impersonation parameter. Private-control peer authorization, per-request native UID/GID authorization, current logical rights, readonly denial and service grant enforcement remain separate. The synthetic gate provisions Alice explicitly, then runs the Python workload as uid1001 and checks its Alice-attributed checkpoint/private receipt without remapping Alice to root.

## Native readiness

Descriptor import and working-tree adoption do not assert Applied. The adapter invalidates existing inode data/attributes, old and new names, and affected directory entries through the actual FUSE notifier. It then performs ordinary kernel metadata lookups, checking current names, types and sizes and absence of removed names. Only that acknowledgement marks the adopted projected revision ready. A matching shared receipt can then expose `applied_revision`; the submitted, private, shared and projected identities stay distinct. Failed invalidation or inconsistent lookup keeps acknowledgement pending.

DefaultPermissions, direct I/O, native ownership mapping and current metadata projection remain enabled. The daemon, local control socket and transport credentials must stay outside the workload's mount/security boundary.

## Qualification

```sh
python3 tests/fs2/linux_live.py --output ABSOLUTE_NEW_PATH
```

This uses the existing owned Rancher HTTPS/PostgreSQL/S3 fixture and a fresh source-matched Linux image. Output includes source/compiler/dependency/image/binary identities, native observations and exact owned cleanup. Exit 0 means the implemented gate passed, 1 an observed failure, and 2 a missing prerequisite. Cleanup normally unmounts before reaping/removing serving resources; failures retain the helpers.

This boundary does not implement macOS NFS live adoption, native full-directory watchers/apply, reconciliation, or general native directory application. Those remain later work; this gate is not full FS2/PoC qualification.
