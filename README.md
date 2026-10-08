# magus-fs

A planned open-source, self-hostable versioned filesystem for human and agent workspaces.

The project targets macOS and Linux first. Its core scope includes full local replicas, on-demand mounts, file history and restore, automatic synchronization, disconnected file work, conflict reconciliation, Unix-like ownership/permissions and read-only sandbox views. Magus will integrate the filesystem through an adapter; the filesystem must also work without Magus.

## Current state

This repository currently contains project-entry documentation only. No filesystem, daemon, mount, CLI, tests or package is implemented. The next milestone is a real macOS/Linux mount feasibility proof, including reads/writes, byte accounting and read-only permission checks. A service range API alone cannot satisfy that gate.

## Shared specifications and progress

Read the [Magus ICM delivery record](../magus-icm/DELIVERY.md). It locates the active ICM checkout/worktree. The standalone project record within that checkout is `work/2026-10-09-magus-fs/CONTEXT.md`; it links the specification, delivery sequence and handoff. The project card is `projects/magus-fs.md`.

Set `MAGUS_ICM_ROOT` to the active ICM checkout when using a nonstandard layout. Keep shared requirements and coordination there, and keep implemented interfaces, contributor instructions and executable tests here. Do not duplicate the authoritative project spec into a second drifting copy.

## Development and distribution

Initial branch: `codex/fs-foundation`. No public remote or release has been created. License and redistributable dependencies will be selected before external distribution; no license is granted by this planning README. No installation/build/test command is advertised until it actually exists.
