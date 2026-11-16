# Decision 0045: Remove the experimental libp2p test oracle

> Historical scope: the subsequent retirement of `aster-lab`, `aster-host`,
> and the native/Gate H controllers supersedes their retention and execution
> instructions below. Recorded results remain bound to their original revisions.

- Status: accepted — bounded test and dependency maintenance
- Date: 2026-10-14
- Supersedes: Decision 0029's retained-oracle boundary and Decision 0026's
  lock-only Hickory audit disposition
- Related: [Decision 0029](0029-close-proposal-0004-libp2p-pilot.md),
  [Decision 0026](0026-lock-only-hickory-advisories.md),
  [current CI policy](../validation/ci.md)

## Context

The closed Proposal 0004 provider remained an all-feature workspace test
consumer despite having no selected-runtime role. Its retention policy allowed
removal before 2026-11-23. Useful volume and reconnect scenarios should exercise
the selected production node and Iroh rather than maintain an experimental
provider. This is not a retrospective provider comparison or selection result.

## Decision

1. Remove `aster-libp2p-provider`, the `aster-lab/libp2p-candidate` integration,
   and their dependency edges. Keep the rest of `aster-lab`, including its
   provider-neutral ownership and resource tests.
2. Remove the retention gate and the obsolete Hickory 0.25.2 audit suppressions; retain
   unrelated advisory/license exceptions and the netlink patch.
3. Exercise two Events each direction using production `aster-node` contacts
   over persistent direct-loopback Iroh endpoints. A one-MiB plaintext Event
   cannot fit the existing one-MiB sealed-object bound. Use plaintext of
   `MAX_OBJECT_BYTES - 11 * 1024` bytes per Event, the smallest whole-KiB margin
   above this fixture's measured hybrid-envelope overhead. Assert the actual
   overhead and sealed bound before transfer, then verify exact sealed bytes
   and authenticated plaintext at each destination. Do not change production
   limits, envelope encoding, or protocol versions.
4. Exercise completed contact, disconnect, reconnect, fresh mission
   authentication, and exact 64-KiB delivery on unchanged endpoints. Reject a
   wrong expected mission identity before insertion. Do not overlap contacts
   or add a separate replay test.
5. Archive the manual runtime-volume diagnostic's eight files and workflow
   byte-for-byte under `archive/diagnostics/runtime-volume/`. Remove the active
   workflow and caller. Do not port its telemetry patch or add instrumentation.
6. Preserve historical decisions, proposals, receipts, and requirements
   baselines. The old diagnostic is historical source, not an active recipe.

## Consequences and verification boundary

The new regressions establish same-implementation loopback correctness, not
throughput, target-resource fitness, NAT behavior, independent interoperability,
or release acceptance. No atomic requirement status changes. Existing resource
coverage remains unchanged; exact two-one-MiB plaintext volume is explicitly
not claimed. Historical records remain available without claiming that their
removed provider or diagnostic can be run from the current workspace.

Run the focused selected-node tests, dependency-scope regressions,
requirements traceability, and the complete `mise run check` aggregate. Hosted
CI, fresh-advisory audits, and target-platform qualification remain distinct
from local verification.
