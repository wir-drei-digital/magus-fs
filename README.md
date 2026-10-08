# magus-fs

A planned open-source, self-hostable versioned filesystem for human and agent workspaces.

The project targets macOS and Linux first. Its core scope includes full local replicas, on-demand mounts, file history and restore, automatic synchronization, disconnected file work, conflict reconciliation, Unix-like ownership/permissions and read-only sandbox views. Magus will integrate the filesystem through an adapter; the filesystem must also work without Magus.

## Current state

The local FS0 development branch contains a verified synthetic fixture/range source, probe CLI, owned test harness and experimental macOS NFS adapter. Raw protocol tests pass, but native macOS ordinary I/O currently stalls and Linux qualification is pending. No filesystem release or complete FS0 gate is claimed. See the [macOS qualification runbook](docs/fs0-macos.md) for actual behavior, limits and build/test commands.

## Shared specifications and progress

Maintainers with the shared Magus ICM checkout should read its `DELIVERY.md` (normally `../magus-icm/DELIVERY.md`). It locates the active ICM checkout/worktree; that local planning workspace is not part of this public repository. The standalone project record within that checkout is `work/2026-10-09-magus-fs/CONTEXT.md`; it links the specification, delivery sequence and handoff. The project card is `projects/magus-fs.md`.

Set `MAGUS_ICM_ROOT` to the active ICM checkout when using a nonstandard layout. Keep shared requirements and coordination there, and keep implemented interfaces, contributor instructions and executable tests here. Do not duplicate the authoritative project spec into a second drifting copy.

## Development and distribution

Repository: [wir-drei-digital/magus-fs](https://github.com/wir-drei-digital/magus-fs). Initial documentation is published on `main`; FS0 development continues locally on `codex/fs-poc`. No runtime release exists. License and redistributable dependencies will be selected before external distribution; no license is granted by this planning README. Build/test commands are documented in the qualification runbook; no packaged installation exists.
