#

# CM4 CI-package MVP validation — 2026-09-15 through 2026-09-16

## Outcome

Status: **direct two-device MVP functionality passed; full-profile provider
lifecycle remains externally blocked**.

The actual CI-generated `arm64` package was installed on both frozen CM4
participants and exercised through its package service and public API, without
the removed device harness and without a CI or package-content change. Package
installation and integrity, protected startup, local and two-node Event
behavior, Rust and generated-Go restart recovery, both ReceiveOnly identity
orderings, clean operation-capacity behavior, offline ledger audit, bearer
reload, packaged-provider backup/recovery, and strict idle resource checks
passed the direct observations below.

This record is sufficient to state that the selected bounded MVP functionality
works on the two accepted devices. It is not a complete v0.1 release
qualification or production authorization. Mission/provider rotation,
revocation, rekey, Previous-generation destruction, and Active-reference
destruction were not run because the repository does not issue the required
authorized replacement mission bundles, roster, signed registry, or stopped
authority state. Inventing those inputs or destroying the only live generation
would not be valid evidence. The 24-hour soak and true network partition remain
explicitly deferred by Decision 0043.

Decision 0043's internal approvals, frozen inventory, accepted package name,
and post-MVP deferrals remain valid. No additional approval is required for
this bounded engineering result.

## Artifact binding

| Field | Value |
| --- | --- |
| Package | `aster` |
| Version | `0.1.0-1~ubuntu24.04.1` |
| Architecture | `arm64` |
| Package bytes | 10,958,256 |
| Package SHA-256 | `d934eee9e1a32fa41f2a1b5890df8d7e02d4cbee13c5a57ca75da5ddfc753156` |
| CI run | [`35064358840`](https://github.com/edgesoftops/astertech/actions/runs/35064358840) |
| Source commit | `78855860fc5c59404f77c60324240d7b60a5564c` |
| Installed `/usr/bin/aster-agent` SHA-256, both nodes | `35c53f34e19474c2b9e8c476c2aa97d33ba12668cf8df27256ef5606fed72304` |
| Installed `/usr/sbin/aster-credential-admin` SHA-256, both nodes | `5976ba0afbe05e6064b5ec00414d027f488260995aae51a91d2c43bf9a506abe` |

The repository's focused Debian-package check accepted package metadata, ARM64
payload, ELF architecture, external SBOMs, and checksums. Both devices reported
the exact package version and architecture; `dpkg --verify aster` and
`dpkg --audit` were clean. No local full test suite was run; the source
revision's CI result remained authoritative as requested.

The package upgrade stopped the manually started, disabled service and did not
restart it. The service was started explicitly for validation. This is a
package-lifecycle observation, not a data-plane failure.

## Frozen devices and configuration

Both mandatory participants matched the accepted inventory: physical Raspberry
Pi Compute Module 4 Rev 1.1, `aarch64`, Debian 13, systemd 257, local
`ext4`, four online CPUs, and 949,702,656 bytes of RAM. Network addresses,
credentials, host keys, device identifiers, peer coordinates, operation IDs,
and authorized topic/scope values are intentionally excluded. The declared
spare did not participate.

Both original configurations passed `aster-agent --check-config
/etc/aster/agent.json` as the final service user. Each uses Normal mode, one
manual peer, no relay, the accepted 10,000-item/64-MiB store limits, and the
accepted operation-ledger limits of 1,000,000 rows, 201,326,592 logical bytes,
and a 10,000-row emergency reserve.

| Participant | Restored configuration SHA-256 |
| --- | --- |
| `cm4-a` | `752ff4f2647869eb0fea2706dca11a58698d9cc0bb7715c11e7011e561b761c8` |
| `cm4-b` | `4a91d4863e8bc1b31290308d26451dd871f2c898359e1f7523d0770fd21884ab` |

Fresh scenario state directories copied only the node's existing identity key
before first startup. This preserved both frozen carrier-identity orderings
while preventing earlier retained Events or operation rows from satisfying a
new check.

## Direct Event/API observations

The installed package passed these checks on both nodes:

- `/livez` and `/readyz` returned HTTP 200;
- authenticated status returned the strict schema, configured/effective mode,
  store and delivery bounds, operation headroom, warning state, and audit
  coherence;
- Rust publication returned `inserted=true`; an exact operation retry
  returned the same identity, counters, sequence and marker with
  `inserted=false`;
- Rust query returned exactly one Event with every expected field and payload;
- Rust polling returned attempt 1, a real package-service restart preserved the
  unacknowledged delivery, and a fresh client process received the same exact
  Event at attempt 2;
- first Rust acknowledgement returned
  `already_acknowledged=false`, and its exact retry returned `true`;
- the strict generated-Go recovery example ran on fresh identity-preserving
  state: begin returned attempt 1, its exact publication retry preserved the
  effect, and a separate post-restart process returned exact attempt 2,
  acknowledged it, observed ten quiet 500-ms polls, and queried the retained
  Event exactly; and
- prior direct Normal-mode observations retained exact peer Event exchange,
  atomic bearer-token replacement plus `SIGHUP`, new-token acceptance,
  old-token rejection, original-token restoration, and readiness.

The exact-source validation clients were local validation artifacts, not
package contents and not CI changes:

| Client | SHA-256 |
| --- | --- |
| Rust `aster-agent-acceptance-fixture` | `616e9a9a23db823d38d0daffb71ff50141ea40ce9921ee040191b15212e6643a` |
| generated-Go `agent-smoke` | `f708bb6c547699f672b146a7a04478263c64e21867fc40796f6a57802a368bac` |
| generated-Go `agent-load` | `ebc1ecafccf460749cf0ff3fbf2321c02184115042a26fdb26665ca709e29214` |

The Rust client was cross-compiled from the package source commit as a static
AArch64 executable. It resolved only the earlier validation-client
availability blocker; it did not modify the server package or CI.

## ReceiveOnly observations

ReceiveOnly passed both frozen carrier-identity orderings without regenerating
or selecting identities:

1. The prospective Normal peer's package service was stopped, and a UDP
   counter exclusively bound its configured peer endpoint.
2. The other node started from fresh identity-preserving state, and
   authenticated status reported configured and effective `receive_only`.
3. During 120 seconds, the stopped peer endpoint observed zero datagrams, zero
   bytes, and zero sources.
4. The ReceiveOnly node retained one locally published Event.
5. The Normal peer then started and initiated authenticated contact. The
   ReceiveOnly node accepted the exact Normal-origin Event through its durable
   subscription.
6. The Normal peer's exact query still returned a single Event: its own. It did
   not receive the ReceiveOnly node's local Event.

The reverse ordering produced the same zero-contact and disclosure result.
Mandatory response traffic after a Normal peer initiates remains expected and
is not a radio-silence claim.

## Operation-capacity observations

Each node used a separate fresh ReceiveOnly state while the peer was unable to
initiate. The generated public client offered exactly 1,024 unique
publications at 2/s, with four workers, a 4,096-byte payload, 30-second request
timeout, and a deterministic replay/conflict checkpoint every 50 planned
slots.

| Observation | `cm4-a` | `cm4-b` |
| --- | ---: | ---: |
| Scheduled / attempted / completed | 1,024 / 1,024 / 1,024 | 1,024 / 1,024 / 1,024 |
| Accepted / inserted | 1,024 / 1,024 | 1,024 / 1,024 |
| Skipped / rejected / protocol-invalid / transport-indeterminate | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Exact-replay probes | 35/35 matched | 35/35 matched |
| Changed-intent conflict probes | 35/35 matched | 35/35 matched |
| Peak in flight | 2 | 3 |
| Latency p50 / p95 / p99 | 170 / 341 / 508 ms | 165 / 324 / 426 ms |
| Receipt SHA-256 | `7e5ba37f5f705e131da62c70528baa0eb6634e351687ede9a82a8274feaf18cd` | `3f792eb74dd9a2c3a51deef4aae268b643ae86ffe9ab0e7ff2e31c29fd686a67` |

Authenticated final status on each node reported 1,024 active and reverse
rows, zero retired rows, zero profile remaining, warning active, exhaustion
active, and 1,024 stored Events. With the service stopped, the packaged
inspection command then reported on both:

```text
EVENT_OPERATION_AUDIT status=pass state=complete scanned=2048 total=2048 units=ledger-and-reverse-rows
```

This clean isolated rerun supersedes the earlier failed overload attempt as the
candidate capacity observation. That historical attempt remains a valid
non-qualifying observation; it is not represented as part of either clean
receipt, and this result does not qualify an offered rate.

## Provider observations and remaining lifecycle prerequisite

The provider administration executable is present at the package's actual
`/usr/sbin/aster-credential-admin` path. The earlier lookup under
`/usr/bin` was a validation error, not a package omission.

On both nodes, with the package service stopped:

- two invocations of the same backup operation returned
  `BACKUP disposition=available generation=1`;
- each node's two 8,254-byte owner-only backup outputs were byte-identical;
- backup ciphertext differed between hosts, as expected for same-host recovery;
- same-host recovery returned
  `RECOVER disposition=existing generation=1`; and
- the exact original configuration and Ready state were restored.

Rotation, revoke/rekey, destruction of Previous, and destructive Active
reference testing remain unexecuted. The documented procedure requires
pre-existing authorized replacement bundles, a replacement roster and signed
registry, and stopped-authority state. The repository explicitly does not
issue or recover those production authority inputs. Destroying the only live
reference without them would make the devices unrecoverable and would not
validate the intended lifecycle. This is an external technical prerequisite,
not an approval gap or package-binary absence.

## Strict idle resource observations

Each node used a fresh empty ReceiveOnly state with the peer unable to initiate.
After 60 seconds of stabilization, one unchanged package process was sampled
from `/proc` for 120 seconds with no API request or workload during the
window.

| Measurement | `cm4-a` | `cm4-b` | Profile disposition |
| --- | ---: | ---: | --- |
| CPU, percent of one core | 3.69% | 3.61% | pass, at most 5% |
| RSS bytes | 15,859,712 | 15,761,408 | pass, at most 64 MiB |
| Peak RSS bytes | 15,859,712 | 15,761,408 | pass, at most 128 MiB |
| Executable bytes | 14,383,376 | 14,383,376 | pass, at most 16 MiB |
| Empty state bytes | 1,056,800 | 1,056,800 | observed |
| Free state bytes | 10,446,368,768 | 10,373,447,680 | observed |

This controlled rerun resolves the earlier near-89% post-workload observation:
that sample did not establish the profile's idle preconditions and is not an
idle-threshold result.

## Explicit post-MVP exclusions

Per Decision 0043, this increment does not run or claim:

- a 24-hour soak or true network partition;
- package/archive signing or independent reproducibility replay;
- package renaming;
- independent implementation, external review, FIPS, or production
  authorization; or
- additional qualification automation.

## Access path, retained evidence, and final device state

The controller's ZeroTier path required a 1,000-byte TCP MSS for reliable bulk
or long-lived SSH traffic. One transient node-A route loss occurred after its
capacity client had exited successfully; connectivity returned without device
or package mutation, and its receipt, status, audit, idle sample, and final
restoration were subsequently captured. This describes the controller access
path, not an Aster carrier qualification.

Run-specific state directories, capacity receipts, and provider backup
artifacts remain protected on their source devices for evidence review. They
are not package inputs and do not replace the original state.

At handoff, both nodes had their byte-exact original configuration restored,
were active in Normal mode, and returned HTTP 200 from both `/livez` and
`/readyz`. No credential, token, reference, host key, peer coordinate,
authorized topic/scope, or raw provider artifact is retained in this record.

## Disposition

The selected CI package passes the directly exercisable bounded Linux Event
MVP functionality on both frozen CM4 devices. The earlier Rust-client,
generated-Go recovery, ReceiveOnly instrumentation, clean capacity, packaged
provider path, and idle-resource blockers are resolved by the observations
above.

Do not reinterpret this as complete v0.1 release qualification. The protected
mission rotation/revoke/rekey/destruction chain still requires externally
issued authorized replacement material, and Decision 0043 explicitly defers
the soak, true-partition, signing/reproduction, independent-review, and
production-authorization work.
