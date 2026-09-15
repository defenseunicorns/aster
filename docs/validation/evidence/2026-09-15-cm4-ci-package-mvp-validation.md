#

# CM4 CI-package MVP validation — 2026-09-15

## Outcome

Status: **partial direct validation; stopped for OS-engineer handoff**.

The exact CI-generated `arm64` package was installed on the two frozen CM4
participants and exercised directly, without the experimental device harness.
The completed observations below passed. Remaining checks are explicitly
unrun; this record does not claim full G4, G6, production qualification, or a
24-hour soak.

Device access stopped when the OS engineer began testing. No observations made
by that engineer are incorporated here.

## Artifact binding

| Field | Value |
| --- | --- |
| Package | `aster` |
| Version | `0.1.0-1~ubuntu24.04.1` |
| Architecture | `arm64` |
| Package SHA-256 | `d4a245499590862f83739d93d0d441529d9e2e9b7c1fec80329d09b3d6d71b1e` |
| CI run | [`34857228552`](https://github.com/edgesoftops/astertech/actions/runs/34857228552) |
| Source commit | `96700b53732848327edfe7294396f47221348580` |
| Installed `/usr/bin/aster-agent` SHA-256, both nodes | `011a38cebf4b3166dacd398b7edcf67c93ea350509cb5dddffc253b5a5922e21` |

The package identity matched the CI checksum metadata. The repository's
focused Debian-package check accepted the payload, ARM64 ELF architecture,
external SBOMs, and checksums. Signing and an independent reproduction replay
are post-MVP under Decision 0043.

## Frozen devices

Both mandatory participants matched the accepted inventory: physical
Raspberry Pi Compute Module 4 Rev 1.1, `aarch64`, Debian 13, systemd 257, local
`ext4`, four online CPUs, and 949,702,656 bytes of RAM. Network addresses,
credentials, host keys, and device identifiers are intentionally excluded.

The declared spare did not participate.

## Completed direct observations

The following checks completed against the installed CI package on both
mandatory nodes unless a node is named explicitly:

- protected provisioning and service readiness;
- local API status, subscription, publish, poll, acknowledgement, and query;
- service restart followed by readiness;
- direct peer configuration and mutual authenticated contact;
- a fresh 4,096-byte Event exchange, delivered on the first poll, acknowledged,
  acknowledged idempotently a second time, and returned exactly by query;
- ReceiveOnly in both node orderings: a ReceiveOnly node started alone without
  an authenticated contact or failed contact attempt, then accepted inbound
  delivery and acknowledgement after its Normal peer started; and
- on `cm4-a`, 512 distinct operations were accepted, an identical retry added
  no operation-ledger row, the capacity audit completed, and the configured
  profile warning was active.

The peer setup initially used the mission authority where the peer node
identity was required. Correcting that configuration produced mutual
authenticated contact; this was a test-configuration error, not an artifact
change.

## Resource observations

| Measurement | `cm4-a` | `cm4-b` |
| --- | ---: | ---: |
| Executable bytes | 14,383,376 | 14,383,376 |
| RSS / peak RSS bytes | 28,753,920 | 28,499,968 |
| Start-to-ready milliseconds | 5,396 | 5,346 |
| Stop milliseconds | 214 | 315 |
| Initial state bytes | 1,056,800 | 16,846,880 |
| Final state bytes | 16,846,880 | 16,846,880 |
| State growth bytes | 15,790,080 | 0 |
| Final free state bytes | 10,494,054,400 | 10,420,854,784 |
| Operation rows | 517 | 2 |
| Audit complete | yes | yes |

Short CPU samples taken immediately after the workload were 67% on `cm4-a`
and 64% on `cm4-b`. They are not steady-idle measurements and therefore do not
establish the profile idle-CPU threshold. Replication activity may have still
been in progress on `cm4-b`.

## Not run in this session

The following items did not complete before the device handoff and are not
passes:

- generated Rust and Go client binaries on the devices;
- the complete protected-provider rotation, backup, recovery, revoke, rekey,
  and destroy sequence;
- bounded service-isolation and recovery;
- the full operation-capacity boundary and steady-idle CPU measurement; and
- any 24-hour soak or true network partition.

## Access-path observation

The controller's ZeroTier access path exhibited a path-MTU mismatch: the
interface advertised 2,800 bytes while stable ICMP payload was observed only
through 1,280 bytes. A 1,000-byte TCP MSS was used for controller SSH access.
Direct CM4-to-CM4 UDP probing, Aster mutual authenticated contact, and the fresh
Event exchange succeeded. This describes the test access path and is not an
Aster failure or a broader carrier qualification.

## Disposition

The actual CI package is the sole artifact represented by this record. Its
completed direct checks demonstrate working install, provisioning, lifecycle,
local Event behavior, direct peer exchange, ReceiveOnly behavior, and the
observed 512-operation warning boundary on the two frozen devices.

Because the listed scenarios remain unrun, this is partial MVP engineering
evidence rather than a complete profile qualification or release decision.
