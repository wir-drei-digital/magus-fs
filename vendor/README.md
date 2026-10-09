# Local nfsserve 0.11.0 permission patch

`nfsserve-0.11.0/` is the exact published crate with only the changes in `nfsserve-access.patch`. The upstream BSD-3-Clause LICENSE is unchanged. `nfsserve-0.11.0-baseline.json` records every original file SHA-256, upstream VCS metadata, and the original crates.io archive SHA-256:

`ef1424b6d88c60a091931392970999ea3ceab132d968e6a5545c770fad5b97d7`

The archive checksum was verified against both the cached published archive and the original root Cargo.lock before adding the local path patch. No Cargo registry source/cache was modified. Root Cargo.lock now resolves the local path; the Linux Docker build explicitly copies vendor/.

The small patch adds a fail-closed `NFSFileSystem::access` policy hook, delegates ACCESS to it, retains the readonly mutation mask while permitting authorized EXECUTE, and omits READDIRPLUS child attributes/handles when authorized GETATTR fails. This avoids bypassing missing directory search permissions through prefetched metadata. RFC1813 permits the optional attributes/handle to be absent. The Magus FS0 adapter supplies the fixed-principal policy and checks GETATTR ancestors; the hook does not introduce request identity, authentication or a multi-user model.

Upstream readonly ACCESS previously returned READ|LOOKUP for every object, rejecting legitimate executable files and advertising search on unsearchable directories. Writable ACCESS echoed all request bits, including executable permission on mode0644. Merely changing the capability flag was therefore unsafe. Native and raw RPC regression evidence is retained in the Task2 report; tests/fs0/test_nfs.py covers masks, mode changes, forged credentials/handles, metadata omission and readonly mutation denial.

Maintenance cost: updates require rebasing this small patch, re-verifying the archive and file baselines, and rerunning both native permission/cleanup checks and Linux build/tests. The dependency is not a public fork or general NFS security qualification. No additional protocol/namespace/history engine is included. Inspect the patch rather than treating the entire vendored crate as newly authored code.

To audit, reverse-apply the patch to a temporary copy of the vendored directory and compare every file against the baseline checksums. The focused vendor regression performs this operation without touching the Cargo registry or working copy.
