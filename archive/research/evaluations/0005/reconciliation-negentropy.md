# Negentropy reconciliation component curve

Status: **PARTIAL / local demo / buy as a narrow component**  
Authority: `data-mesh-requirements.md`, SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`  
Registered evidence: BVB-547, BVB-551, BVB-552, BVB-795, BVB-799

## Outcome first

Buy Negentropy's exact identifier-set reconciliation mechanism rather than
designing another range/fingerprint exchange. Do not mistake it for the replica
engine. It owns neither durable progress nor payload transfer, causality,
class semantics, tombstones, conflict handling, authorization, or security.

The component is highly effective when replicas are close and develops a clear
fallback knee when they are far apart. The composed protocol therefore needs a
bounded switch to a bulk identifier exchange or another admitted high-delta
mechanism; always using Negentropy is not the delete-first answer.

## Executed curve

Both sides held exactly `N` deterministic 32-byte identifiers. `Δ` is total
symmetric difference, split equally between the sides. Messages were capped at
4,096 bytes. Every run returned the exact expected `have` and `need` sets, and
five repetitions produced identical byte, frame, round-trip, and result counts.
Elapsed values below are medians and remain host-local observations.

### Hold Δ = 20 while increasing N

| N per side | Protocol bytes | Round trips | Median reconcile | Full-ID ratio |
|---:|---:|---:|---:|---:|
| 1,000 | 6,002 | 2 | 0.176 ms | 9.378% |
| 10,000 | 7,315 | 2 | 0.351 ms | 1.143% |
| 100,000 | 16,799 | 4 | 1.716 ms | 0.262% |
| 1,000,000 | 20,542 | 5 | 10.309 ms | 0.032% |

A thousandfold increase in total set size raised protocol bytes only 3.42× for
the same difference. Cost is therefore difference-sensitive, though not a
literal function of `Δ` alone.

### Hold N = 100,000 while increasing Δ

| Symmetric Δ | Protocol bytes | Round trips | Median reconcile | Full-ID ratio |
|---:|---:|---:|---:|---:|
| 2 | 1,733 | 2 | 0.470 ms | 0.027% |
| 20 | 16,799 | 4 | 1.716 ms | 0.262% |
| 200 | 148,977 | 26 | 13.553 ms | 2.328% |
| 2,000 | 1,451,473 | 249 | 119.750 ms | 22.679% |
| 20,000 | 8,697,120 | 1,506 | 647.852 ms | 135.893% |

At 20% total symmetric difference, this exact 4 KiB-framed exchange was larger
than sending both complete 32-byte identifier sets. That is useful decision
data, not a candidate failure: a bounded composition should choose the cheaper
mechanism before reaching that region.

## Requirements accounting

- DM-5.2-18 is **partial**: the FOSS component demonstrates a strong
  difference-sensitive identifier reconciliation primitive over independently
  varied `N` and `Δ`, but not complete synchronization cost including payloads,
  persistence, transport, or application effects.
- DM-5.2-01 through DM-5.2-04 remain unknown for this component because it does
  not apply replica changes or own retention.
- DM-5.2-09 through DM-5.2-14 remain unowned. Negentropy's timestamp field is a
  range-ordering input and must never be promoted into causal correctness or
  conflict arbitration.
- DM-5.2-19 through DM-5.2-22 remain unknown: the evaluated exchange keeps its
  progress in memory and provides no restart/any-peer persistence contract.

## Residual ownership

The replica layer must supply stable item identities, authenticated scope/topic
selection, durable reconciliation checkpoints, actual item fetch, idempotent
apply, class-specific causality/conflicts, tombstone policy, admission limits,
and a deterministic bulk fallback. Resource and peak-RSS evidence remains
unknown because the host denied the external peak-memory instrumentation; no
memory bound is inferred from elapsed time.
