# Independent local recovery

Task7 archives are plaintext, self-contained recovery directories. `archive.json` is canonical JSON with a selected revision and a sorted path/length/SHA-256 inventory. `revisions/<sha256>` contains unchanged canonical descriptors for the selected revision and all ancestors; `objects/<sha256>` contains their exact combined object closure. SHA-256 verifies integrity, not the publisher's identity. The verifier needs neither a replica journal nor a configured source endpoint. Ordinary visible `._` files are included as content when selected. Exact native `com.apple.provenance` remains observed-only, untouched and never replayed; extended ACLs, arbitrary xattrs and timestamp fidelity are not promised.

```sh
magus-fs export --state /absolute/state --revision sha256:REVISION --destination /absolute/new-archive
magus-fs verify --archive /absolute/new-archive
magus-fs restore --archive /absolute/new-archive --destination /absolute/new-content --config /absolute/current-policy.json
```

Every entry in every exported ancestor must be readable under current authority. Current identities use their current path, traversal and access metadata; old modes never grant export access. Missing identities require the explicit retained-history grant below. An incomplete export has no valid closure and must never be treated as a backup. Export hydrates and verifies required objects before acknowledging success; hydration can fail with `base_unavailable` or quota backpressure.

Verification bounds the manifest and each descriptor to 16 MiB, combined descriptors to 64 MiB, members to 100,000 and each object to 1 MiB. It rejects noncanonical descriptors, unknown/extra/missing members, duplicate or colliding names, wrong sizes/digests, paths outside the two fixed member namespaces, symlinks, hardlinks and special files. Member names are exact lowercase digests. No archive control file is copied into the emitted user tree.

## Current offline destination policy

The caller already possesses archive plaintext. The archive supplies no current authority; a separate policy supplies the selected actor, native mappings, default owner/group/modes and optional per-path overrides. The host still enforces real destination creation and ownership operations. Example (replace IDs and numeric UID/GID with the intended current mapping):

```json
{
  "authorities": [{
    "principal": "principal:11111111111111111111111111111111",
    "uid": 1001,
    "primary_group": "group:11111111111111111111111111111111",
    "gid": 1001,
    "groups": ["group:11111111111111111111111111111111"],
    "dac_override": false,
    "ownership_transfer": false
  }],
  "actor": {"principal": "principal:11111111111111111111111111111111"},
  "owner": "principal:11111111111111111111111111111111",
  "group": "group:11111111111111111111111111111111",
  "file_mode": 384,
  "directory_mode": 448,
  "entries": [{
    "path": "report.sh",
    "owner": "principal:11111111111111111111111111111111",
    "group": "group:11111111111111111111111111111111",
    "mode": 448
  }]
}
```

These decimal modes are 0600 and 0700. Overrides must name a unique existing source path (empty string selects the root), reference current mapped owners/groups and use supported ordinary mode bits. File and directory kinds come from the validated source tree. Unsupported ownership changes or unavailable native ownership mappings fail. This initial offline policy requires the selected actor to have read/write permission on resulting files and read/write/search on resulting directories; policies that remove that access are refused before publication. This policy deliberately makes the script executable while keeping data files nonexecutable; it does not claim historical mode fidelity.

Offline restore creates a fresh, owned `.magus-archive-recovery-*` replica outside both the archive and destination, imports only independently verified archive bytes, derives a descriptor with the explicit current policy, and uses the shared descriptor-relative materializer. `source_revision` identifies the unchanged archived descriptor; `derived_revision` identifies the actual emitted metadata tree. `head_changed:false` means no original replica head was advanced. Existing destinations and symlink ancestors are rejected. The archive, recovery controls and user content stay disjoint through native ancestry checks.

## Deleted-entry authority and live-head restoration

Trusted initialization may configure `history_administrators` as logical principal IDs. It defaults to empty and does not derive from DAC override, ownership-transfer authority or archived metadata. `retained_history_grants` also defaults to empty. Existing stored configurations without these fields reopen unchanged.

A currently configured administrator may atomically replace the grant set through `Replica::set_retained_history_grants` or the standalone CLI:

```sh
magus-fs history-grants --state /absolute/state --config /absolute/grants.json
```

The CLI derives its actor from the current kernel UID and persisted mapping. Its input is an array of `{ "principal": "principal:…", "revision": "sha256:…", "entries": ["entry:…"] }`. Each revision and entry must already be retained; duplicate, empty, unknown or out-of-scope grants fail. An empty array revokes all grants. Reopen uses the durable updated configuration. An explicit stale configuration supplied to `Replica::open` is still a configuration mismatch. These are local trusted-administration APIs, not remote authentication or a shared-service grant system. Actor selection alone is not authentication.

A grant applies only to that absent identity in that exact revision for export/restore. It cannot disclose siblings, bypass a currently present identity's mode000/owner change or replace destination create/write rights. Ordinary historical reads and `materialize` continue to deny absent identities. Standalone admin/export/restore/prune commands require the replica owner lock and return `replica_busy` while a mount owns state; they do not open a second journal or widen the mounted control protocol.

```sh
magus-fs restore --state /absolute/state --revision sha256:SOURCE --operation-id operation:ID
magus-fs restore --state /absolute/state --revision sha256:SOURCE --operation-id operation:ID --restore-metadata true
```

Live restore requires a clean current working state. It overlays source entries, retains unrelated/current entries absent from the source, and creates an attributed v2 revision whose parents preserve the replaced head and selected source. Typed, revision-bound restoration provenance records the source revision, explicit metadata intent and old-to-fresh identity mapping. V1 descriptor bytes/hashes remain unchanged; see [the format contract](fs1-format.md). It is not an exact namespace rollback: selected capture coverage does not authorize deleting newer or out-of-coverage content. Namespace moves check current source and destination parents. Cross-kind, nonempty directory and source-identity path-cycle collisions fail safely. Displaced entries remain accessible to their existing handles. Deleted/recreated entries receive fresh identities with current actor/group/umask creation policy; they never resurrect old capabilities.

Default restore keeps current access metadata. `--restore-metadata true` deliberately requests historical values, but every changed mode or owner/group must pass today's chmod/chown-equivalent authority. Current source read and destination write requirements still apply. The CLI reports `head_changed:true, materialized:false`; this commits engine history and working state and does not rewrite the native source folder. Materialize the returned revision separately when native output is desired. A failed materialization never proves a head change, and a successful head restore never proves native publication.

## Retention and recovery observations

```sh
magus-fs prune --state /absolute/state --dry-run
magus-fs prune --state /absolute/state --token sha256:DRY_RUN_TOKEN
```

The typed report returns resident reachable, candidate, pinned and protected bytes plus candidate IDs, a revalidated token and applied reclaimed IDs/bytes. Reachable and pinned/protected counts overlap; they are not disjoint totals. All committed descriptors remain retained. Pins protect complete ancestry closure; dirty working entries, live handles/orphans and pending/failed candidates remain roots. The token covers generation, inventory, retained revisions, pins, sources and temporary roots. New roots invalidate stale candidate sets. Applying `Replica::prune(false)` without a token is rejected; use `apply_prune`.

Unreferenced published objects can be reclaimed. Referenced objects are eligible only when clean and refetchable; application verifies all referenced candidates against their currently registered sources before removing any candidate. An expired source returns `base_unavailable` and retains candidate bytes. A source pointing back to the same native cache directory is not an independent copy. Local-only retained history is never deleted. There is no history-pruning command. A refetch probe establishes availability during the operation, not a future server retention promise; pin recovery points when independent local availability is required. Quota exhaustion returns backpressure; it does not silently drop protected bytes. Interrupted object staging consumes quota.

Materialization records retain staging and prepared-content device/inode identities. Recovery observation checks the current destination identity and exact content closure without deleting anything. A rename followed by directory-sync failure leaves `unacknowledged`, possibly present output; failure never means absence. `destination_identity_verified` and `content_verified` are fresh read-only observations, not cleanup authorization or power-loss durability guarantees. A replacement at the saved path is left untouched. Failed stages/recovery replicas are retained for diagnosis; inspect their owned identity before any manual cleanup.

## Qualification

```sh
docker build -f tests/fs1/Dockerfile.recovery -t magus-fs1-task7-recovery .
python3 tests/fs1/recovery_io.py --output /absolute/new-evidence-directory
```

The macOS worker runs under `sandbox-exec`: original native tree/database/cache reads are denied and TCP to a proven-live listener plus UDP are denied with native errors. The Linux worker runs as UID1001 in a separate read-only container with `--network none`, no capabilities and no original-state mount; original paths are inaccessible and actual external socket operations fail. Each worker exports mixed v1/v2 ancestry including a granted deleted entry with a fresh identity, then invokes fresh verifier/restore subprocesses using only the binary, archive and explicit current policy, checks every file independently, executes the restored script and rejects missing/corrupt/extra/malicious-reference and tampered-provenance archives without creating a destination. Source/binary/image hashes, commands, exits, native errors and scoped container cleanup are retained. Failure is exit1; missing prerequisites are exit2, never a pass. `--platform macos` and `--platform linux` select a focused gate.

These tests qualify process isolation and acknowledged local operation behavior on the tested filesystems. They do not simulate power loss, a compromised host administrator, arbitrary storage hardware, immutable remote-retention contracts or a released multi-user service.
