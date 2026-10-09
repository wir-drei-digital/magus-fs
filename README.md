# magus-fs

A planned open-source, self-hostable versioned filesystem for human and agent workspaces.

The project targets macOS and Linux first. Its core scope includes full local replicas, on-demand mounts, file history and restore, automatic synchronization, disconnected file work, conflict reconciliation, Unix-like ownership/permissions and read-only sandbox views. Magus will integrate the filesystem through an adapter; the filesystem must also work without Magus.

## Current state

The local FS0 branch contains the synthetic fixture/range source and experimentally qualified Linux FUSE adapter for pinned read-only and ephemeral private-byte views. Native macOS NFS now passes the controlled fixed-principal qualification after Network Volumes permission and a narrow dependency permission fix. The combined twelve-profile native matrix passes; task reviews and whole-branch review corrections are complete. FS0 is qualified as an unmerged experimental checkpoint, with the final signal-stream reporting limitation recorded in the runbook. The [combined qualification runbook](docs/fs0-qualification.md) describes six fresh profiles per platform, strict reports and exact limits; platform details are in the [Linux](docs/fs0-linux.md) and [macOS](docs/fs0-macos.md) runbooks. No filesystem release or integrated PoC is claimed.

## Shared specifications and progress

Maintainers with the shared Magus ICM checkout should read its `DELIVERY.md` (normally `../magus-icm/DELIVERY.md`). It locates the active ICM checkout/worktree; that local planning workspace is not part of this public repository. The standalone project record within that checkout is `work/2026-10-09-magus-fs/CONTEXT.md`; it links the specification, delivery sequence and handoff. The project card is `projects/magus-fs.md`.

Set `MAGUS_ICM_ROOT` to the active ICM checkout when using a nonstandard layout. Keep shared requirements and coordination there, and keep implemented interfaces, contributor instructions and executable tests here. Do not duplicate the authoritative project spec into a second drifting copy.

## Development and distribution

Repository: [wir-drei-digital/magus-fs](https://github.com/wir-drei-digital/magus-fs). Initial documentation is published on `main`; FS0 development continues locally on `codex/fs-poc`. No runtime release exists. License and redistributable dependencies will be selected before external distribution; no license is granted by this planning README. Build/test commands are documented in the qualification runbook; no packaged installation exists.
