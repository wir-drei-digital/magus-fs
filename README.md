# magus-fs

A planned open-source, self-hostable versioned filesystem for human and agent workspaces.

The project targets macOS and Linux first. Its core scope includes full local replicas, on-demand mounts, file history and restore, automatic synchronization, disconnected file work, conflict reconciliation, Unix-like ownership/permissions and read-only sandbox views. Magus will integrate the filesystem through an adapter; the filesystem must also work without Magus.

## Current state

This repository currently contains project-entry documentation only. No filesystem, daemon, mount, CLI, tests or package is implemented. The next milestone is a real macOS/Linux mount feasibility proof, including reads/writes, byte accounting and read-only permission checks. A service range API alone cannot satisfy that gate.

## Shared specifications and progress

Maintainers with the shared Magus ICM checkout should read its `DELIVERY.md` (normally `../magus-icm/DELIVERY.md`). It locates the active ICM checkout/worktree; that local planning workspace is not part of this public repository. The standalone project record within that checkout is `work/2026-10-09-magus-fs/CONTEXT.md`; it links the specification, delivery sequence and handoff. The project card is `projects/magus-fs.md`.

Set `MAGUS_ICM_ROOT` to the active ICM checkout when using a nonstandard layout. Keep shared requirements and coordination there, and keep implemented interfaces, contributor instructions and executable tests here. Do not duplicate the authoritative project spec into a second drifting copy.

## Development and distribution

Repository: [wir-drei-digital/magus-fs](https://github.com/wir-drei-digital/magus-fs). Initial documentation is published on `main`; development continues on `codex/fs-foundation`. No runtime release exists. License and redistributable dependencies will be selected before external distribution; no license is granted by this planning README. No installation/build/test command is advertised until it actually exists.
