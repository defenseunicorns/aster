#

# Latest-main package and finite-TTL device validation — 2026-09-17

## Outcome

Status: **latest-main package passed direct runtime and finite-TTL checks on
both provisioned CM4 participants; the third CM4 passed install integrity only**.

The existing ARM64 package workflow was manually dispatched on the exact
latest `main` commit. It completed its native Ubuntu 24.04 build, package
payload/SBOM verification, protected-service install exercise, and artifact
retention without a source or CI change. The resulting package was installed
on all three test CM4 devices, and every installed binary matched across the
three devices.

The two provisioned, frozen participants then passed fresh-state direct API
checks for local Event behavior, restart, bidirectional peer convergence, and
the additive finite Linux Event TTL behavior merged after the v0.1 profile was
frozen. Expiry removed one logical item and 10,669 logical payload bytes on
each node, and a fresh operation was accepted afterward. The expired operation
key remained permanently retired and returned `NotFound`; this is
content-capacity reuse, not operation-key reuse.

The third test device had no pre-existing configuration, mission reference, or
client token. It therefore passed package installation, integrity, common
binary identity, and command-startup smoke checks only. A proposed transfer of
the repository's non-production provisioning bundle was not authorized for
that device during this run, so no protected runtime result is claimed for it.
This does not expand the frozen two-node annex or turn the declared spare into
a third qualification participant.

This is bounded engineering evidence. It does not complete v0.1 release
qualification, change requirement status, or authorize production use.

## Artifact binding

| Field | Value |
| --- | --- |
| Build workflow | `Build: .deb arm64`, manual `workflow_dispatch` |
| Build run | [`35210078468`](https://github.com/edgesoftops/astertech/actions/runs/35210078468) |
| Build job | `105165249194` |
| Source commit | `71669176bef2d96a6aa34abaae004ad40142b135` |
| Package | `aster` |
| Version | `0.1.0~alpha.1-1` |
| Architecture | `arm64` |
| Package bytes | 10,961,422 |
| Package SHA-256 | `5739c2b4debfd7d6d91d466706239410520e7bf68d0701ae9132f4761aa56905` |
| Package artifact ID | `10492125757` |
| Build-record artifact ID | `10491777098` |
| Installed `/usr/bin/aster` SHA-256, all nodes | `bd147483dde5c9bd6b4517c30a6ae8aa65baadfb80f13abca28cc1a4ef7fef95` |
| Installed `/usr/bin/aster-agent` SHA-256, all nodes | `9280bb4f87cb9b0dca401f0fa344ee5ac1b1a1083d4cfabd7de45e10b030b6da` |
| Installed `/usr/sbin/aster-credential-admin` SHA-256, all nodes | `ffc43dfc86aa29f856f89602811242ba873801a93972b4914919095e36eadc2e` |

The retained build metadata binds Rust 1.97.1, Cargo 1.97.1,
`cargo-cyclonedx` 0.5.9, `cyclonedx-editor-validator` 0.34.0, the locked
`Cargo.lock` digest, binary checksums, SBOMs, build information, and package
changes. A focused local invocation of `tools/test_deb_package.py` also accepted
the downloaded package's metadata, ARM64 ELF payload, external SBOMs, and
checksums. No local full test suite was run; the workflow and source CI remain
authoritative as requested.

## Installation observations

All three devices reported `aster 0.1.0~alpha.1-1 arm64` with installed status,
clean `dpkg --verify aster`, clean `dpkg --audit`, and successful `aster
--help` and `aster-agent --help` execution.

The previously installed version was `0.1.0-1~ubuntu24.04.1`. Debian version
ordering treats `0.1.0~alpha.1-1` as older, so installation required an
explicit package downgrade. The package correctly stopped the active service
on the two provisioned nodes and did not restart it during installation. This
version-ordering observation is not represented as a normal unattended upgrade
path.

The target devices are ARM64 Debian 13 CM4 systems. The package itself was
built and exercised by the workflow on its declared native Ubuntu 24.04 ARM64
builder. This record does not broaden the supported distribution claim.

## Direct finite-TTL and API observations

Both provisioned nodes used separate fresh state directories containing only
their existing carrier identity before first startup. Their original
configurations and protected provider state were retained. The selector was
derived locally from already-authorized retained Event metadata and kept
root-only; topic and scope values were not copied into this record.

The direct public API checks passed identically on both nodes:

- `/livez` and `/readyz` returned HTTP 200;
- zero TTL and a finite tombstone returned `InvalidArgument`;
- `u64::MAX` TTL was accepted and returned exactly;
- a 2,000-ms Event was visible through query and poll before expiry;
- its exact operation retry preserved the Event identity and decoded as
  `inserted=false`;
- changing TTL under the same operation key returned `Aborted`;
- after tracked expiry, query and poll withheld the Event;
- retrying the expired operation returned `NotFound`;
- local maintenance reclaimed one logical item and 10,669 logical payload
  bytes;
- a new operation key was accepted after that reclamation;
- an Event with absent TTL remained visible through a real package-service
  restart;
- delivery acknowledgement and exact reacknowledgement passed; and
- subscription deletion and repeated deletion passed.

| Measurement | `cm4-a` | `cm4-b` |
| --- | ---: | ---: |
| Baseline items / payload bytes | 0 / 0 | 0 / 0 |
| Before expiry items / payload bytes | 2 / 21,255 | 2 / 21,255 |
| After expiry items / payload bytes | 1 / 10,586 | 1 / 10,586 |
| Reclaimed items / payload bytes | 1 / 10,669 | 1 / 10,669 |
| Active / retired / reverse operation rows after expiry | 1 / 1 / 1 | 1 / 1 / 1 |
| Final active / retired / reverse operation rows | 3 / 1 / 3 | 3 / 1 / 3 |
| Operation audit | complete | complete |
| Sanitized receipt SHA-256 | `f4e37e718c05f65eae4842744718e0077dd455ecd51e5b8d9864c9880a0a0884` | `7b5ec8e9f460c5f6f749cbc250329cee61dcd657a278777125c1b2e2ce9dc7d3` |

The direct TTL probe was a temporary controller-created public-API client, not
a package member, product harness, or CI change. Its SHA-256 was
`943e78d9e140978b479055af3c9f347bac7986f515bb5c0902794e0adb89c32e`.
The sanitized receipts remain protected on their source devices.

## Direct two-node observations

A second fresh state on each provisioned participant preserved its carrier
identity and original one-peer configuration. Both directions passed:

| Direction | Publisher result | Receiver result |
| --- | --- | --- |
| `cm4-a` to `cm4-b` | local publish, exact retry, and query passed; receipt SHA-256 `5a317a35b9d04973ef0c56ef07f4e3e6fe3297c30cf4f74c902810111bace6bf` | matching Event hash at attempt 1 in 140 ms; query and ack/reack passed; receipt SHA-256 `5c7b6cb2fd17f0fb3e8463accac955a42a3c1e813bea6731eb638402bbdb7b08` |
| `cm4-b` to `cm4-a` | local publish, exact retry, and query passed; receipt SHA-256 `9763d6859d6fbd9312460221823e8e8de6a91f80b90a7ef26fb1fc23dc735f62` | matching Event hash at attempt 1 in 157 ms; query and ack/reack passed; receipt SHA-256 `3298e09b8d57873a3ff61575f22361aea93b98bc7bc615e0114ae340fb76a7d7` |

The receivers reported 21 and 26 cumulative authenticated contacts,
respectively. The temporary direct mesh client SHA-256 was
`907671f2af932ab61ee3f9eca1b86d3e4a00f3f832414fb1fcf4963d16a00fab`.
Network addresses, carrier and mission identities, selectors, operation keys,
subscription IDs, and raw credentials are excluded.

## Superseded validation diagnostics

Three procedure issues were resolved before the clean retained run:

1. The first fresh-state parent was `root:root 0700`, which prevented the
   service account from traversing to state. Matching the earlier working
   `root:aster 0750` parent resolved startup without a product change.
2. The public documentation's example selector was outside these devices'
   provisioned authorization. Selecting an already-authorized value locally
   resolved `PermissionDenied`; no authorization was widened.
3. Protobuf JSON omitted the default `inserted=false` field on an exact retry.
   A diagnostic confirmed identical Event identity with the field absent. The
   clean probe decoded absence as the Protobuf default.

The clean `ttl-rerun2` receipts above are authoritative. Earlier partial state
was not used to satisfy any retained check.

## Final device state and claim boundary

At handoff:

- `cm4-a` and `cm4-b` had their byte-exact original configurations restored,
  were active in Normal mode, and returned HTTP 200 from both health paths;
- their restored configuration SHA-256 values remained
  `752ff4f2647869eb0fea2706dca11a58698d9cc0bb7715c11e7011e561b761c8`
  and
  `4a91d4863e8bc1b31290308d26451dd871f2c898359e1f7523d0770fd21884ab`;
- the third CM4 retained the exact package but remained disabled, inactive,
  and unconfigured; and
- protected run state and receipts remained on the two source devices for
  review.

This supplemental run does not repeat or supersede the earlier ReceiveOnly,
1,024-operation capacity, provider backup/recovery, token reload, or strict
idle observations. Those remain bound to the earlier package record. It also
does not run the deferred 24-hour soak, a true network partition,
rotation/revoke/rekey/destruction, signing or reproducibility replay,
independent implementation, external review, FIPS, or production
authorization.

Finite TTL remains an additive implementation extension beyond the frozen
Linux Event MVP v0.1 profile. This record supplies the previously missing
test-device observation for expiry withholding, local cleanup, restart,
permanent retry fencing, and logical content-capacity reuse without changing
the approved annex, requirement credit, or release posture.
