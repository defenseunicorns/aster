#

# Event operation-ledger CM4 inventory amendment — 2026-09-11

Status: **bounded engineering-observation inventory amendment; qualification=false**.

This amendment changes only the third node's declared participation for the
enumerated Task 9 local scenarios below. The [2026-09-10 inventory](2026-09-10-cm4-candidate-inventory.md)
is preserved as historical evidence. Its observed hardware/image/OS facts are
not refreshed or requalified by this role declaration; a new read-only preflight
must verify each participant before later artifact execution or Event traffic.

The mandatory pair remains `cm4-a` (`rpi4-1`) and `cm4-b` (`rpi4-2`). They alone
participate in the connected and disconnected/reconnect A/B scenarios. This
amendment does not satisfy E02, G3, G4, G5, a signed candidate annex, or release
authorization.

## Exact support role and scenario binding

The device previously labeled `cm4-spare` is labeled `cm4-support` for this
amendment, with unchanged operator label `rpi4-3`.

Declared role: `standalone local-rate observation support participant`.

Its only permitted scenario IDs are:

| Offered Events/s | 256-byte payload | 4,096-byte payload | 65,536-byte payload |
| ---: | --- | --- | --- |
| 0.2 | `T9-LOCAL-S-R0p2-P256` | `T9-LOCAL-S-R0p2-P4096` | `T9-LOCAL-S-R0p2-P65536` |
| 1 | `T9-LOCAL-S-R1-P256` | `T9-LOCAL-S-R1-P4096` | `T9-LOCAL-S-R1-P65536` |
| 5 | `T9-LOCAL-S-R5-P256` | `T9-LOCAL-S-R5-P4096` | `T9-LOCAL-S-R5-P65536` |
| 10 | `T9-LOCAL-S-R10-P256` | `T9-LOCAL-S-R10-P4096` | `T9-LOCAL-S-R10-P65536` |
| 50 | `T9-LOCAL-S-R50-P256` | `T9-LOCAL-S-R50-P4096` | `T9-LOCAL-S-R50-P65536` |

Each point uses 100 new unique-Event publications, no configured peers, and
fresh scenario state. Public exact/conflict probes are separate observations,
not additional accepted load. The ignored operator manifest binds the complete
matrix, supplied artifact/config hashes, timeout, sampling, and resource checks.

`cm4-support` is not a mandatory G4 peer. It must not join, receive, store,
forward, or relay any `T9-CONNECTED-AB-*` or `T9-DISCONNECTED-AB-*` scenario.
All other third-node scenarios remain outside this amendment.

## Evidence and operating boundaries

- Only scenarios run after this committed revision may use this support role.
- Measurements are not pooled across inventory revisions. Every later receipt
  must bind the exact inventory revision and artifact/config/scenario identity.
- The inspection-only overlay does not establish carrier or direct-path
  qualification; connected/disconnected observations require their own exact
  operator bindings outside this sanitized record.
- There is no million-operation, default-capacity, long-lifetime, candidate
  rate, profile promotion, physical-CM4 qualification, or role-approval claim.
  Both large tool modes remain hard-blocked by the unchanged custody ceiling.
- Host-access identities, addresses, usernames, credentials, host-key
  fingerprints, mission/carrier identities, raw operation keys, and raw command
  logs are excluded from this record.
- This B0 amendment alone does not authorize artifact execution or Event
  traffic; the controller must first review the complete B0 preflight.
