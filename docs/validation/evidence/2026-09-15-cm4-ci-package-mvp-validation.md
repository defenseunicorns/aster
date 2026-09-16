#

# CM4 CI-package MVP validation — 2026-09-15 through 2026-09-16

## Outcome

Status: **direct two-device run completed with blockers and incomplete checks**.

The actual CI-generated `arm64` package was installed on both frozen CM4
participants and exercised through its package service and public API, without
the removed device harness. Package installation, protected startup, local
Event behavior, restart recovery, Normal-mode peer exchange, inbound transfer
in both ReceiveOnly orderings, bearer-token reload, the 1,024-operation profile
stop, and offline operation-ledger audits passed the direct checks described
below.

This artifact is not an MVP candidate pass. The package omits the provider
administration executable required for the protected-provider lifecycle, the
current Rust reference client was unavailable for device execution, and the
resource samples showed sustained CPU near 89% of one core without proving the
profile's strict idle preconditions. One deliberately over-offered capacity
attempt on `cm4-a` also produced transport-indeterminate results before the
workload was completed conservatively. ReceiveOnly non-initiation and local
inventory non-disclosure were not instrumented. These observations keep E04,
E05, E07, E09, E10, and E11 from passing.

Decision 0043's internal approvals, frozen inventory, and post-MVP deferrals
remain valid. This record does not claim production authorization, full G4/G6,
a 24-hour soak, or a true network partition.

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

The repository's focused Debian-package check accepted the package metadata,
ARM64 payload, ELF architecture, external SBOMs, and checksums. Both devices
reported the exact package version and architecture; `dpkg --verify aster` and
`dpkg --audit` were clean. Signing and independent reproduction remain
post-MVP under Decision 0043.

The package upgrade stopped the manually started, disabled service and did not
restart it. The service was started explicitly for validation. This is a
package-lifecycle observation, not a data-plane failure.

## Frozen devices and configuration

Both mandatory participants matched the accepted inventory: physical
Raspberry Pi Compute Module 4 Rev 1.1, `aarch64`, Debian 13, systemd 257, local
`ext4`, four online CPUs, and 949,702,656 bytes of RAM. Network addresses,
credentials, host keys, device identifiers, peer coordinates, and authorized
topic/scope values are intentionally excluded. The declared spare did not
participate.

Both configurations passed `aster-agent --check-config` as the final service
user. Each used Normal mode, one manual peer, no relay, the accepted
10,000-item/64-MiB store limits, and the accepted operation-ledger limits of
1,000,000 rows, 201,326,592 logical bytes, and a 10,000-row emergency reserve.
Original configuration digests were restored after ReceiveOnly testing:

| Participant | Configuration SHA-256 |
| --- | --- |
| `cm4-a` | `752ff4f2647869eb0fea2706dca11a58698d9cc0bb7715c11e7011e561b761c8` |
| `cm4-b` | `4a91d4863e8bc1b31290308d26451dd871f2c898359e1f7523d0770fd21884ab` |

## Direct functional observations

The following completed against the installed package on both nodes:

- `/livez` and `/readyz` returned HTTP 200;
- the generated-Go status client authenticated and validated configured and
  effective mode, store and delivery bounds, operation accounting, warning
  state, and audit coherence;
- a fresh Event publication returned `inserted=true`; an identical retry
  returned the same durable effect with `inserted=false`;
- a unique logical-key query returned the exact retained Event and payload
  after nine bounded scan pages;
- a durable subscription returned an attempt-1 delivery; after a package
  service restart, the same Event returned at attempt 2; first acknowledgement
  was fresh and the repeated acknowledgement was idempotent;
- restart-to-ready measured 5,695 ms on `cm4-a` and 5,756 ms on `cm4-b`;
- in Normal mode, each node queried the other node's uniquely keyed Event with
  an exact payload match and no convergence wait;
- ReceiveOnly configuration and inbound transfer passed in both orderings: the
  ReceiveOnly node was started while the Normal peer was stopped, authenticated
  status reported configured and effective `receive_only`, and the exact newly
  published Event arrived after the Normal peer started. The checks did not
  directly measure outbound-contact non-initiation or local inventory
  non-disclosure, so E04 remains partial; and
- atomic bearer-token replacement plus `SIGHUP` accepted the new token,
  rejected the old token as unauthenticated, and accepted the restored original
  token without losing readiness.

The current generated-Go clients were built from the artifact source commit as
static ARM64 executables. Their device hashes were:

| Client | SHA-256 |
| --- | --- |
| `agent-smoke` | `f708bb6c547699f672b146a7a04478263c64e21867fc40796f6a57802a368bac` |
| `agent-load` | `ebc1ecafccf460749cf0ff3fbf2321c02184115042a26fdb26665ca709e29214` |

## Operation-capacity observations

Both nodes finished at exactly 1,024 active operation rows with 1,024 reverse
rows, zero retired rows, zero profile remaining, and both profile warning and
profile exhaustion active. The package's offline inspection command then
reported on each node:

```text
EVENT_OPERATION_AUDIT status=pass state=complete scanned=2048 total=2048 units=ledger-and-reverse-rows
```

`cm4-b` supplied the clean workload receipt: starting from 5 rows, all 1,019
planned publications were accepted and inserted with no skips, rejections,
protocol errors, or transport-indeterminate outcomes. Twenty-one exact-replay
and twenty-one changed-intent conflict probes matched. Latency was 669 ms p50,
1,078 ms p95, and 1,214 ms p99.

`cm4-a` reached the same audited boundary, but its workload history includes a
failed overload attempt and must not be represented as a clean qualification
receipt:

1. Four workers offered 100/s: 42 inserted and 462 late slots were skipped;
   one exact-replay and one conflict probe matched.
2. Thirty-two workers offered 20/s: 224 results were accepted, 30 were
   transport-indeterminate, and the probe stopped the run. Authenticated
   capacity advanced by all 254 attempts, demonstrating that the 30 uncertain
   calls committed; they were not retried with new keys.
3. The remaining 208 rows ran at 2/s with four workers: all 208 were accepted
   and inserted with zero skips or uncertain results; eleven exact-replay and
   eleven conflict probes matched.

This establishes the stored profile boundary and healthy offline audit on
both devices. It does not erase the failed overload receipt or qualify a rate.

## Resource observations

| Measurement | `cm4-a` | `cm4-b` | Profile disposition |
| --- | ---: | ---: | --- |
| Executable bytes | 14,383,376 | 14,383,376 | pass, at most 16 MiB |
| RSS bytes (`VmRSS`) | 63,905,792 | 65,003,520 | pass, at most 64 MiB |
| Peak RSS bytes (`VmHWM`) | 63,905,792 | 65,003,520 | pass, at most 128 MiB |
| State bytes | 50,532,384 | 67,375,136 | observed |
| Free state bytes | 10,466,168,832 | 10,392,854,528 | observed |
| Post-workload CPU, percent of one core | 88.7% and 89.4% confirmation | 89.8% | **not accepted**; idle preconditions not established |

RSS and peak RSS are `/proc/<pid>/status` `VmRSS` and `VmHWM` readings captured
after the final restart. The CPU samples were separate 20-second `/proc`
observations after workloads, offline audits, service restarts, and observed
convergence had completed. No controller request or workload was launched
during those samples, but active peer contact was not instrumented or excluded.
The similar result on both devices and the `cm4-a` confirmation sample retain a
resource concern, but the samples do not establish the profile-defined idle
condition and therefore cannot be called a conclusive 5% idle-threshold
failure. E11 remains not passed pending an explicitly instrumented idle rerun.

## Blocking gaps and failed checks

- **Rust client unavailable:** an exact-source ARM64 Rust client could not be
  built because the controller lacks an ARM C compiler required by `ring`, and
  the retained older Rust fixture rejected the current response schema with
  `internal`.
  The current Rust client check therefore remained incomplete on both devices;
  this is not attributed to an installed-package defect.
- **Packaged provider administration:** protected provider loading and service
  readiness passed, and bearer-token reload passed, but the CI package does not
  install `/usr/bin/aster-credential-admin`. Backup/recovery stopped at command
  lookup before provider mutation; rotation, destructive recovery, revoke,
  rekey, and destroy were not run. Zero-byte invalid backup stdout files were
  removed and both services were returned to Ready.
- **Idle CPU:** both devices showed sustained post-workload CPU near 89% of one
  core, but the strict idle preconditions were not established. The 5% target
  cannot be accepted or conclusively rejected from this sample and requires a
  rerun with active peer contact explicitly excluded or measured.
- **Go recovery example:** the exact generated-Go status and load clients ran,
  while restart recovery was exercised directly through the public package
  API. The strict fresh-selector `recovery-begin`/`recovery-resume` example was
  not completed against the pre-populated mission state.

These are candidate blockers, not post-MVP deferrals and not passes.

## Explicit post-MVP exclusions

Per Decision 0043, this increment does not run or claim:

- a 24-hour soak or true network partition;
- package/archive signing or independent reproducibility replay;
- package renaming;
- independent implementation, external review, FIPS, or production
  authorization; or
- additional qualification automation.

## Access path and final device state

The controller's ZeroTier path required a 1,000-byte TCP MSS for reliable bulk
SSH transfer; ordinary short SSH control traffic and direct CM4-to-CM4 Aster
traffic worked. This describes the controller access path, not an Aster carrier
qualification.

At the end of validation, both nodes had their original configuration and
bearer token restored, were in Normal mode, and returned HTTP 200 from
`/readyz`. Temporary invalid provider outputs and temporary restart receipts
were removed. The synthetic Event and operation rows are intentionally retained
as the durable state supporting the capacity and restart observations.

## Disposition

The selected CI package demonstrates a substantial working Linux Event slice
on both frozen CM4 devices, including direct package install/start, local and
peer Event behavior, restart recovery, ReceiveOnly, token reload, and the
audited 1,024-operation boundary. It must not advance as a passing MVP
candidate until at least the incomplete ReceiveOnly non-initiation/disclosure
checks, failed overload receipt, missing packaged provider administration path,
unavailable current Rust-client device execution, incomplete strict Go recovery
example, and unresolved CPU concern are dispositioned and the affected checks
are rerun.
