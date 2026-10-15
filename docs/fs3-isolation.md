# Scoped multi-user isolation phase

Run from the checkout with the tested Docker/FUSE environment available:

```sh
python3 tests/fs3/isolation.py --image sha256:IMMUTABLE_IMAGE_ID --output /private/tmp/FS3_NEW_PATH
```

The output must be a new absolute path. Exit 0 qualifies only the isolation phase
(F3-1/F3-2); exit 1 records failure and exit 2 records unavailable prerequisites.
This command does not build Rust or qualify FS3 packaging, caching, fanout or a
hosted provider. Its source bridge compares actual image inputs and all five
binary hashes. Runtime differences reject reuse. The existing FS2 final-run
source rules remain unchanged. The sole allowed existing fixture difference is
the exact optional logical-principal/group/metadata mapping extension to Lazy.
New FS3 harness files are recorded separately, with their actual hashes.

Five independent Linux containers each expose a real FUSE mount. A1 and A2 use
one logical principal with separate replica credentials; B and the unaffected
peer have different logical principals. The readonly worker has only read
permission under `reports`. Every ordinary workload runs as UID/GID 1001:1001.
That UID names the acting principal in its own trusted client configuration;
other logical owners have distinct UID mappings for metadata. Identical numeric
UIDs across containers do not imply shared logical authority. Control processes
run separately as root; tokens, service configuration and state are inaccessible
to workload UID 1001. Only synthetic manifest-owned resources are used.

The phase records private candidate receipts, explicit integration and exact
shared head plus independent fresh bytes. Direct HTTPS checks cover foreign and
guessed views, objects, private operations/receipts/replay, closed revision
selectors, private history, branch scope and readonly uploads. Private results
are absent from peer mounts until integration. Ordinary readonly mutation and
known Unix-mode write restrictions fail immediately. Private siblings are absent
from authorized projections.

Prefix grants govern remote publication. A never-observed new local identity
may be written durably under a currently writable parent, even at the name of a
hidden sibling. This does not disclose or change the hidden remote identity.
The terminal scope checks separately stage a genuinely absent out-of-prefix
candidate and capture a mounted hidden-name collision. Both must fail candidate
submission with 404, without a private receipt, successful operation or shared
head effect. The owner's original hidden bytes stay unchanged and the denied
local bytes remain retained. Upload/staging acknowledgement is not a private
receipt. This is the established FS2 private-local versus remote authority
boundary, not an assertion that every out-of-prefix local create returns errno.

The isolated replica is disconnected, revoked, normally unmounted and restarted
with the same state before reconnecting. Current authority must then deny fresh
mounted access and old-view/operation/publication/replay API attempts, while an
authorized peer continues to publish and other peers read the exact bytes.
Previously copied plaintext cannot be remotely erased. Owner-controlled recovery
and archive APIs belong outside the workload trust boundary.

`result.json` uses schema 1 with phase, status, source, binaries, assertions,
measurements, cleanup, failures and blocked reasons. Assertions bind acceptance
IDs to expected/observed outcomes and raw evidence pointers. The normalizer
rejects missing required assertions, missing ordinary mount evidence, conflicting
outcomes, missing source/binary binding and unresolved cleanup. A blocked
prerequisite is never a runtime pass. Failed runs stay failed; successful later
runs do not overwrite them. Cleanup normally unmounts each recorded actual
kernel mount before stopping helpers and removes only ownership-verified
resources. Cleanup failure preserves helpers and fails the phase.

This Linux matrix does not claim authenticated multi-user macOS NFS. The macOS
adapter uses its documented fixed-actor loopback model and requires separate
trusted mount/client identities. Retained-handle and client-cache limits remain.
The functional baseline's historical failed recovery rows still require explicit
owner recovery; this phase neither rewrites those rows nor replays the complete
historical PoC. No performance target, total-disk quota, package installation or
external provider support follows from an isolation pass.
