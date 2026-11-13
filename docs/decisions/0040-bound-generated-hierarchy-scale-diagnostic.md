# Decision 0040: Bound a generated hierarchy scale diagnostic

> ****

- Status: Accepted for a bounded development diagnostic
- Date: 2026-08-31
- Amended: 2026-09-01 — ordered the two bounded follow-on increments
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0037](0037-bound-concurrent-lan-scale-baseline.md),
  [Decision 0039](0039-compose-a-static-event-hierarchy-over-semantic-v6.md),
  and roadmap action `P2-2`

## Context

The flat-LAN diagnostic deliberately stops at 32 authorized nodes because each
process retains at most 32 visible discovered or authenticated peers. The
five-node hierarchy MVP demonstrates two payload-blind Event bridge hops, but
does not show whether the same static runtime makes progress when many sources
are distributed across small local discovery domains.

The current runtime also has implementation cliffs that a larger diagnostic
must expose rather than conceal: outbound and restart bridge selection has a
256-route window, contact reconciliation performs total-inventory work, and an
acknowledged bridge route may be offered again on a later contact. A broad
1,000-node experiment before measuring these boundaries would consume far more
host capacity without producing a sharper engineering signal.

## Decision

1. Add one opt-in generator with exactly eight leaf scopes feeding two regional
   scopes and one root scope. Eight leaf segments, two regional segments, and
   one root segment produce 11 separate IP/mDNS discovery domains. Ten static
   directed authorizations connect each leaf to its region and each region to
   the root, so every delivered Event crosses exactly two bridge hops.
2. Accept only `--publishers-per-leaf 1`, `4`, or `8`. The full tier contains
   64 publishers, eight leaf bridges, two regional bridges, one root consumer,
   and one foreign-authority outsider: 76 live processes, 75 authorized. The
   largest local discovery domain contains nine processes, and a multi-homed
   bridge can see at most 12 peers. No peer identity or peer address is
   configured.
3. Publish the allowed and denied fixtures durably at every source while
   discovery is disabled. After the cohort starts, require authenticated
   contact connectivity on every segment, outsider rejection before inventory,
   no plaintext sentinel in route-only bridge logs, no capacity/drop signal,
   and an exact durable root route set containing one allowed route per
   publisher and no denied route.
4. At the full tier, require all 64 allowed routes at the root and require both
   regional paths to make progress beyond the bridge lane's first
   eight-routes-per-contact batch. A partial first batch is a failure, not a
   smaller successful scale result.
5. Stop every peer, reopen the root consumer alone with discovery disabled, and
   require the same exact durable route set. Unexpected exits, graph gaps,
   inventory changes, unauthorized delivery, or failed cleanup fail the run.
6. Report bounded controller timing, process/container resources, contact and
   offer activity, and duplicate offers. Duplicate dispositions demonstrate
   idempotent handling and make current reoffer cost visible; they do not prove
   quiescent or difference-proportional anti-entropy.
7. Generate all Compose state in a private temporary directory and clean up
   only the exact project-scoped containers, networks, volumes, and uniquely
   named image. Do not add a keep mode or broad Docker pruning.
8. Require operators to select one tier explicitly. Provide a configuration
   canary, but do not automatically sweep tiers or retry a failed run.

## Requirement and evidence boundary

This is a `P2-2` measurement instrument for the existing static Event hierarchy.
Adding or running it moves no atomic requirement status, capability maturity,
or retained evidence credit. A result is same-host, same-kernel,
same-implementation Docker development feedback and is not retained
automatically.

The diagnostic does not resolve the 32-visible-peer limit, the 256-route
outbound/restart window, total-inventory contact work, or acknowledged-route
reoffers. It does not establish supported join/leave administration, bandwidth
or complete storage quotas, dynamic route/interest replacement,
revocation/rekey, cross-class custody, physical or hostile-network operation,
target-device resource fitness, long-offline or power-loss recovery, 100 nodes
per scope, 1,000 nodes across bridges, complete-MVP credit, or release
authorization.

## Consequences

- Hierarchical fan-out can be measured with 75 authorized live processes while
  every local discovery domain remains well below the flat peer cap.
- The exact durable root route set and regional progress expose starvation
  beyond the first contact batch without treating aggregate process count as
  proof of scale.
- Resource and duplicate-offer reports identify the next concrete bottleneck;
  they do not silently become product thresholds or maturity evidence.
- The [roadmap's active implementation lanes](../validation/capability-roadmap.md#active-post-hierarchy-implementation-lanes)
  first establishes a durable generation for bounded dynamic Event-bridge
  configuration, then binds peer-specific difference reconciliation to that
  generation. Increasing this fixed tree further comes after those increments.
