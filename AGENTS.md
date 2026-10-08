# magus-fs agent entrypoint

1. Read README.md. Resolve the shared ICM through `MAGUS_ICM_ROOT` or the sibling `magus-icm/DELIVERY.md` locator; follow its active-worktree pointer.
2. Read the active ICM's `AGENTS.md`, `_shared/quality.md`, `_shared/architecture.md`, `projects/magus-fs.md` and `work/2026-10-09-magus-fs/CONTEXT.md`.
3. Keep implementation and runnable tests here; shared product specifications and coordination belong in the ICM. Do not implement the superseded Magus-internal slice-2 store in parallel.
4. Follow the reviewed per-milestone spec/plan and the already selected Superpowers SDD workflow. This documentation-only initialization is not implementation approval for an unwritten plan.
5. Real mounts, permission enforcement, disconnected work and conflict preservation are required filesystem behavior. SDK or mock checks cannot replace their end-to-end gates.
6. Test only isolated synthetic trees/users/mounts. Preserve user files and unrelated processes; clean up only resources recorded as owned by the current test. Keep credentials out of traces and fixtures.
7. Retain actual commands, versions, hashes, transfer measurements, failure outcomes and cleanup evidence. Never infer a runtime guarantee from documentation or report a skipped gate as passed.
8. Use feature branches and signed-off commits. Do not publish a remote, install privileged drivers or deploy services implicitly as part of editing documentation.
