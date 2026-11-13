# Decision 0037: Measure the flat LAN ceiling before adding hierarchy


- Status: Accepted for exploratory development feedback
- Date: 2026-08-31
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0036](0036-mission-authenticated-lan-discovery-mvp.md)
  and roadmap action `P2-2`

## Context

The retained selected Event result with 32 identities used mostly serial
two-process contact cohorts. It did not place 32 independently persisted nodes
on one discovery domain at the same time or measure their aggregate resource
use. The automatic LAN runtime intentionally retains at most 32 locator
candidates and 32 authenticated mission identities per process.

The product scale target is not a thousand-node multicast domain. Topics,
scopes, relays, filtered bridges, and optional hierarchical scopes bound
propagation. Before implementing that hierarchy, however, the current flat-LAN
building block needs a short, repeatable concurrency baseline that can expose
candidate starvation, disconnected contact graphs, reconciliation failure, and
obviously unhealthy resource growth.

## Decision

1. Add an opt-in, generated Docker Compose diagnostic for exactly 8, 16, or 32
   authorized nodes on one private bridge. One separately provisioned outsider
   shares the carrier network but not the mission authority. No node receives a
   peer identity or address.
2. Give every process a distinct credential, carrier identity, store, client
   token, and named volume. Disable discovery while each authorized node creates
   a durable subscription and publishes one unique 1-KiB Event. Restart every
   process together with discovery enabled.
3. Require one concurrent query batch in which every authorized node returns the
   exact complete Event set with no extras. Treat a later successful partial
   response as a regression rather than a retryable condition. Require the
   time-unioned authenticated contact graph to be connected,
   require the outsider to complete no authenticated contact and query no Event,
   and reject candidate-limit or authenticated-member-capacity drops. At 32
   authorized nodes plus the outsider, each authorized node can observe exactly
   32 remote carrier candidates without raising the product limit.
4. After convergence, observe a bounded steady-state window, then stop all
   processes cleanly. Restart authorized nodes with discovery disabled and
   require the complete durable Event set again.
5. Use a declared 5-, 10-, or 20-second synchronization cadence for the 8-,
   16-, or 32-node tier respectively. A local diagnostic query that misses its
   three-second response window is retried only within the enclosing bounded
   exact-inventory deadline and is counted in the result as a warning. Report
   first-exact node observations separately from the final all-exact batch.
6. Sample controller timing, receipt counters, authenticated graph degree,
   Docker container-accounted memory, CPU, PIDs, network and block I/O, plus
   apparent state bytes. Require every sampled process to remain running and
   every stopped process to exit zero. Measurements are diagnostic. Proposed
   Tier-2 brackets and growth warnings are not silently converted into product
   acceptance thresholds.
7. Generate the Compose model in a private temporary directory and remove only
   the exact project-scoped containers, network, volumes, and uniquely named
   image. Do not expose a keep mode or invoke broad Docker pruning.

## Claim boundary

Adding or running this diagnostic moves no requirement status and creates no
retained evidence by itself. A passing run is same-host, same-kernel,
same-implementation Docker feedback. It does not prove 100 nodes per scope,
1,000 nodes across bridged scopes, scope hierarchy, bridge filtering, physical
switch multicast behavior, independent failure domains, hostile-LAN bounds,
NAT/WAN behavior, Tier-2 resource fitness, energy use, or release readiness.

Container memory and I/O counters are not physical-device measurements. Sampled
CPU is not cumulative energy. The outsider check repeats one authorization
negative case; it is not a hostile-peer campaign.

## Consequences

- Developers can advance explicitly from 8 to 16 to 32 concurrent nodes without
  hand-authoring Compose services or sharing credentials and volumes.
- Exact all-node convergence and the authenticated contact graph distinguish a
  working sparse mesh from a collection of healthy containers.
- The 32-node result identifies the flat discovery ceiling that the next
  multi-scope bridge increment must compose rather than enlarge indefinitely.
- Resource knees or contact storms found here should shape bounded neighbor
  rotation and hierarchy before any 100-node experiment.
