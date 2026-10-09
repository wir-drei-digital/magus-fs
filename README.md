# magus-fs

A planned open-source, self-hostable versioned filesystem for human and agent workspaces.

The project targets macOS and Linux first. Its core scope includes full local replicas, on-demand mounts, file history and restore, automatic synchronization, disconnected file work, conflict reconciliation, Unix-like ownership/permissions and read-only sandbox views. Magus will integrate the filesystem through an adapter; the filesystem must also work without Magus.

## Current state

The unmerged `codex/fs-poc` branch contains the qualified FS0 mount checkpoint and FS1's durable local engine, lazy Linux FUSE/macOS NFS adapters, private revisions and independent recovery archives. The [FS1 combined qualification runbook](docs/fs1-qualification.md) defines two fresh V1–V12 journeys per OS, source/binary/image provenance and fail-closed cleanup. FS1 task, whole-range and scoped correction reviews are complete at code `b9e3fe1`; see the runbook for the distinct original-matrix and correction evidence. No filesystem release, shared synchronization or integrated PoC is claimed.

Run the complete FS1 gate on the qualified macOS host with Rancher Desktop running:

```sh
python3 tests/fs1/run.py --platform all --output /private/tmp/FS1_NEW_SHORT_NAME
```

The output path must be new. The command builds separate default/fault binaries and a fresh Linux image; it uses only synthetic owned resources. Exit0 requires every mandatory case on both platforms, exit1 means failure and exit2 means a missing prerequisite. See the [local CLI](docs/fs1-local.md), [durability](docs/fs1-durability.md), [format](docs/fs1-format.md) and [recovery](docs/fs1-recovery.md) contracts.

## Shared specifications and progress

Maintainers with the shared Magus ICM checkout should read its `DELIVERY.md` (normally `../magus-icm/DELIVERY.md`). It locates the active ICM checkout/worktree; that local planning workspace is not part of this public repository. The standalone project record within that checkout is `work/2026-10-09-magus-fs/CONTEXT.md`; it links the specification, delivery sequence and handoff. The project card is `projects/magus-fs.md`.

Set `MAGUS_ICM_ROOT` to the active ICM checkout when using a nonstandard layout. Keep shared requirements and coordination there, and keep implemented interfaces, contributor instructions and executable tests here. Do not duplicate the authoritative project spec into a second drifting copy.

## Development and distribution

Repository: [wir-drei-digital/magus-fs](https://github.com/wir-drei-digital/magus-fs). Initial documentation is published on `main`; FS1 development continues locally on `codex/fs-poc`. No runtime release exists. License and redistributable dependencies will be selected before external distribution; no license is granted by this planning README. Build/test commands are documented in the qualification runbook; no packaged installation exists.
