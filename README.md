# magus-fs

A planned open-source, self-hostable versioned filesystem for human and agent workspaces.

The project targets macOS and Linux first. Its core scope includes full local replicas, on-demand mounts, file history and restore, automatic synchronization, disconnected file work, conflict reconciliation, Unix-like ownership/permissions and read-only sandbox views. Magus will integrate the filesystem through an adapter; the filesystem must also work without Magus.

## Current state

FS0 mounts, FS1 durable replicas and FS2-A connected synchronization are qualified locally on macOS/Linux. FS2-A runtime `e03ddad` closes all six task reviews, whole-slice review and its correction review. The [FS2-A runbook](docs/fs2-qualification.md) distinguishes the two real connected journeys from subsequent harness/service corrections. FS2-B reconciliation/recovery is planned but unimplemented; full FS2, the integrated PoC and a filesystem release remain outstanding.

Run the complete FS1 gate on the qualified macOS host with Rancher Desktop running:

```sh
python3 tests/fs1/run.py --platform all --output /private/tmp/FS1_NEW_SHORT_NAME
```

The output path must be new. The command builds separate default/fault binaries and a fresh Linux image; it uses only synthetic owned resources. Exit0 requires every mandatory case on both platforms, exit1 means failure and exit2 means a missing prerequisite. See the [local CLI](docs/fs1-local.md), [durability](docs/fs1-durability.md), [format](docs/fs1-format.md) and [recovery](docs/fs1-recovery.md) contracts.

## Shared specifications and progress

Maintainers with the shared Magus ICM checkout should read its `DELIVERY.md` (normally `../magus-icm/DELIVERY.md`). It locates the active ICM checkout/worktree; that local planning workspace is not part of this public repository. The standalone project record within that checkout is `work/2026-10-09-magus-fs/CONTEXT.md`; it links the specification, delivery sequence and handoff. The project card is `projects/magus-fs.md`.

Set `MAGUS_ICM_ROOT` to the active ICM checkout when using a nonstandard layout. Keep shared requirements and coordination there, and keep implemented interfaces, contributor instructions and executable tests here. Do not duplicate the authoritative project spec into a second drifting copy.

## Development and distribution

Repository: [wir-drei-digital/magus-fs](https://github.com/wir-drei-digital/magus-fs). Remote `main` contains the initial documentation; completed development is merged into local `main` only. No runtime release exists. License and redistributable dependencies will be selected before external distribution; no license is granted by this planning README. Build/test commands are documented in the qualification runbook; no packaged installation exists.

The FS2-A connected gate is documented in [FS2-A qualification](docs/fs2-qualification.md). It exercises a full native Mac folder, lazy Linux mount, isolated Python worker, explicit integration, real restart/hint/response-loss recovery and twenty serialized saves in each of two fresh journeys. The source, receipt, content-transfer and normal-unmount evidence qualifies this slice only; FS2-B implementation and full FS2/PoC qualification remain outstanding.

```sh
python3 tests/fs2/run.py --slice connected --platform all --output /private/tmp/FS2A_NEW_SHORT_PATH
```
