# Debian package validation — 2026-09-14



These are local evaluation results, not release authorization or CI evidence.
The native ARM64 target ran Ubuntu 24.04 and systemd 255.4-1ubuntu8.17;
Docker 29.1.3 and Compose 2.40.3 were used for container tests.
The source baseline was `9760102`, with the Compose simplification and later
Debian configuration-example fix included as working-tree changes. The local
`.2` candidate changed the Debian version, not the runtime source; the branch
retains `.1` in `debian/changelog`.

## Artifact identities

| Architecture | Package version | SHA-256 |
| --- | --- | --- |
| amd64 | `0.1.0-1~ubuntu24.04.1` | `a5347b4aca71d684eabc437733f674274af47092945749ee10a96ba147959fd8` |
| arm64 | `0.1.0-1~ubuntu24.04.1` | `bfd5ec034dd6705d0133b40875f8b83ad87c8b83ccce5f1b60c328d248fc63df` |
| arm64 | `0.1.0-1~ubuntu24.04.2` | `c0e75ec777ff8e275fe7dd2f7fab42ac8f4c36c8fb9145c553187fa8ce6a797e` |

The amd64 package predates the merge of `main`; its smoke result does not claim
a rebuild of the final branch. ARM64 packages were built natively from the merged
runtime source. Builds produced external per-binary SBOMs, build metadata and
checksums. Payload, architecture and metadata checks passed.

## Passed checks

- Full local `mise run check` on the merged checkout, including the previously
  failing live mutable State/Record convergence test. The later configuration
  example correction was exercised by the protected service harness.
- amd64 `.1` and native ARM64 `.1`/`.2` two-node Compose: install, direct Event
  delivery, offline sender restart, backlog delivery, and receiver recreation
  without peers. These use reference provisioning, not systemd credentials.
- Native ARM64 fresh install: expected rejection without provisioning, protected
  service startup, local Event publish/delivery/ack, restart and package removal.
- Purge preserved configuration/provisioning and the service account. The
  original deployment was restored after testing with separate state directories.
- ARM64 `.2` -> `.1` -> `.2` transitions with both enabled and disabled boot
  settings: service stops during replacement, boot setting and configuration/
  provisioning are preserved, and the pre-transition Event remains deliverable.
- Final `.2` process runs as `aster`, with `NoNewPrivs=1` and no effective
  capabilities; shared libraries resolve, installed package files pass dpkg
  verification, readiness returns 200, and the API rejects anonymous access
  with 401. The original disabled boot setting was restored.

## Failures retained and limits

The initial protected service harness exposed a missing `storage.operations`
object in the Debian example after merging `main`. The example was corrected;
the continued harness and subsequent clean installation passed.

The first lifecycle helper exited after the successful install/purge checks
because `reset-failed` rejected an unloaded unit during restoration. A dense
sequence of later restarts hit the unit's configured start-rate limit. The
helper was corrected to tolerate an unloaded unit during housekeeping and clear
the rate counter between independent cases. Start, readiness and Event checks
remained mandatory. The installed unit and its rate limits were not relaxed.
The final transition run passed; earlier failures were retained, not relabeled
as successful full runs.

GitHub Actions execution is pending. These checks do not qualify machine reboot,
schema-changing upgrade/rollback, reproducible output, complete dependency
license admission, release signing, or final deployment/security approval.
No atomic requirement evidence status is changed by this record.

## Retained evidence

The task workspace retains logs and receipts under these output collections:

- `deb-compose-2026-09-14`: full local check log and amd64 Compose receipt.
- `arm64-native-2026-09-14/results`: native build, package metadata, Compose,
  initial systemd failure and successful continued systemd test.
- `arm64-upgrade-2026-09-14`: first successful package upgrade receipt.
- `arm64-lifecycle-2026-09-14`: fresh install/purge log, failed helper attempts,
  successful transition receipt, `.2` Compose receipt and final process probes.

Raw logs, binaries, test state and credentials are not committed to this repository.
