# Development builds and focused FS2 runs

Keep Rancher Desktop running and use only fresh, short, absolute output paths with existing parents. Reuse is for development fix rounds; task closeout still requires affected regressions and fresh complete native gates.

Build one debug runtime image from the exact working source, then record its immutable ID:

```sh
docker build -f tests/fs2/Dockerfile.linux --build-arg VERIFY=0 --build-arg BUILD_PROFILE=dev --build-arg BIN_DIR=debug -t magus-fs2-dev .
FS2_DEV_IMAGE=$(docker image inspect --format '{{.Id}}' magus-fs2-dev)
```

The image must have `magus.fs2.build-profile=dev`. Every captured source input must match its `/src` copy, including harness tests; rebuild after changing any captured input. Tags are mutable, so pass the recorded ID between runs. Reconciliation and native completion also resolve any supplied tag to an immutable ID before setup and refuse missing or wrong-profile images. Source verification runs before the service journey. A borrowed image is retained without claiming ownership for that run; each run still owns and cleans its fresh fixtures.

The new runners rebuild host binaries incrementally on every invocation. Only the service/runtime Docker build is skipped; native completion's separate core matrix keeps its own build and image:

```sh
python3 tests/fs2/reconciliation.py --reuse-image "$FS2_DEV_IMAGE" --phase merge --output /private/tmp/FS2B_NEW_MERGE
python3 tests/fs2/native_complete.py --reuse-image "$FS2_DEV_IMAGE" --case structural --output /private/tmp/FS2B_NEW_STRUCTURAL
```

Their `result.json` records `build_reuse` (requested reference, immutable ID and profile) and always sets `complete_gate` to false when reuse is requested, even if all phases/cases ran successfully.

Existing service runners accept the same debug image through `--skip-build --image`. For example, prepare the matching host service first when skipping their host checks, then run a focused protocol check:

```sh
cargo +stable build --locked -p magus-fs-service
python3 tests/fs2/service_protocol.py --skip-build --skip-checks --image "$FS2_DEV_IMAGE" --review-edge-only --output /private/tmp/FS2_NEW_PROTOCOL
```

Those existing runners retain their own check/qualification semantics. The connected runner (`tests/fs2/run.py --probe --reuse-image`) requires a separate **release** image; do not pass the debug image to it. Retained focused evidence does not replace fresh final gates.

At task closeout omit reuse and focused selectors for the full native runs, and run the affected complete regression suites:

```sh
python3 tests/fs2/reconciliation.py --output /private/tmp/FS2B_NEW_FINAL_RECONCILIATION
python3 tests/fs2/native_complete.py --platform all --output /private/tmp/FS2B_NEW_FINAL_NATIVE
```

No flag preserves fresh runtime image builds. Keep failures, source/binary hashes and cleanup evidence alongside the successful runs; never relabel a development result as a complete gate.
