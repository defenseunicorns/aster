# Bounded hierarchy scale diagnostic


This opt-in diagnostic grows the static Event hierarchy without growing one
flat multicast domain. It generates eight leaf scopes, two regional scopes, and
one root scope on 11 private Docker IP/mDNS segments. Ten static directed
authorizations join each leaf to its region and each region to the root. Events
therefore cross exactly two bridge hops; no process receives a configured peer
identity or peer address.

```text
leaves 0..3 --> region-a --\
                             root consumer
leaves 4..7 --> region-b --/
```

Each leaf has its own publisher cohort and one multi-homed leaf bridge. Four
leaf bridges meet one regional bridge on each regional segment. The two
regional bridges, root consumer, and one different-authority outsider share the
root segment. At the full tier, the largest local discovery domain has nine
members and the most exposed multi-homed bridge can see only 12 peers, even
though 75 authorized processes are live across the complete hierarchy.

## Prerequisites

- Native Linux with Docker Engine and the Compose plugin. Docker Desktop and
  other virtualized multicast paths are outside this diagnostic.
- Permission to use the Docker daemon and the repository toolchain installed
  with `mise install`.
- Enough host memory, CPU, and process capacity for the selected tier. The full
  tier runs 76 long-lived processes.

The runner creates only uniquely named, project-scoped Docker resources. It has
no keep mode and performs no broad Docker prune.

## Run one explicit tier

First validate the smallest generated model without starting its cohort:

```sh
mise run hierarchy-scale-compose -- --publishers-per-leaf 1 --config-only
```

Then run that functional canary:

```sh
mise run hierarchy-scale-compose -- --publishers-per-leaf 1
```

The only accepted publisher counts are fixed tiers:

| Publishers per leaf | Publishers | Authorized processes | Live processes including outsider |
|---:|---:|---:|---:|
| 1 | 8 | 19 | 20 |
| 4 | 32 | 43 | 44 |
| 8 | 64 | 75 | 76 |

Advance deliberately after inspecting the preceding result:

```sh
mise run hierarchy-scale-compose -- --publishers-per-leaf 4
mise run hierarchy-scale-compose -- --publishers-per-leaf 8
```

The runner never sweeps all tiers or retries a failed tier automatically. The
64-publisher run is deliberately explicit because it is a much heavier
same-host workload than the functional canary.

## What one run checks

1. Generate the complete topology with distinct process identities, stores,
   credentials, and local interface memberships. Static bridge authorization
   defines membership; mDNS supplies only adjacent carrier coordinates.
2. With discovery disabled, every source publishes its allowed and denied
   fixtures durably before any peer can be contacted.
3. Start the complete cohort and require mission-authenticated contact
   connectivity on every segment. The foreign-authority outsider must be
   rejected before inventory and must receive no route.
4. Require the root consumer to contain exactly one allowed route from every
   publisher and no denied route. At the full tier that is exactly 64 allowed
   routes. Plaintext fixture sentinels must not appear in route-only bridge
   logs.
5. At the regional layer, require progress beyond the first eight-route contact
   batch. This exercises bounded round-robin progress rather than accepting a
   root result containing only the first batch from each region.
6. Fail on reported discovery or authenticated-peer capacity drops, unexpected
   process exits, disconnected authorized segment graphs, inventory mismatch,
   or unauthorized delivery.
7. Report bounded timing, resource, contact, route-offer, and duplicate-offer
   diagnostics. These values characterize the run; they are not target-device
   thresholds.
8. Stop all peers, restart the root consumer alone with discovery disabled, and
   require the same exact durable allowed-route set with no denied route.
9. Remove and audit only the generated project resources, including its
   containers, segments, volumes, and uniquely named image.

Current acknowledged bridge routes can be offered again on later contacts.
Exact route identity makes the receiver result idempotent, and this diagnostic
reports duplicate offers so their cost is visible. It does not claim that the
current bridge lane reaches quiescent, difference-only anti-entropy.

## Reading the boundary

This topology demonstrates why hierarchy can keep local peer domains bounded:
the full run has 75 authorized processes globally, but no local discovery domain
has more than nine members and no multi-homed bridge sees more than 12 peers.
It is also deliberately positioned below current implementation cliffs:

- a process retains at most 32 visible discovered or authenticated peers;
- outbound and restart bridge selection has a 256-route window;
- contact reconciliation still performs total-inventory work rather than work
  proven proportional to the difference; and
- acknowledged routes may be reoffered, so duplicate-offer reporting is a
  measurement rather than a quiescence claim.

A pass is same-host, same-kernel, same-implementation Docker development
feedback. It is not retained evidence and moves no requirement status. It does
not establish supported dynamic join/leave, bandwidth or complete storage
quotas, dynamic routing or interest policy, revocation/rekey lifecycle,
cross-class custody, physical or hostile-network behavior, target-device
resource fitness, 100 members per scope, 1,000 nodes across bridges, complete
MVP credit, or release authorization.
