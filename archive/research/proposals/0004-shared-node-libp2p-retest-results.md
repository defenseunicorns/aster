# Proposal 0004 result: shared-node baseline retained; no provider selected


- Status: superseded — stopped before formal Phase 0; no arm selected
- Date: 2026-08-23
- Proposal: [Shared-node rust-libp2p retest](0004-shared-node-libp2p-retest.md)
- Disposition: [Decision 0029](../decisions/0029-close-proposal-0004-libp2p-pilot.md)
- Requirements baseline:
  [`data-mesh-requirements.md`](../../data-mesh-requirements.md), SHA-256
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`

## Result

Proposal 0004 is closed with **none selected**. The provider-free shared-node
architecture passed its Gate-H prerequisite, but neither the corrected-native
arm nor the rust-libp2p arm completed the proposal's formal comparison. The
rust-libp2p work therefore does not enter the selected-stack implementation,
default, deployment, release, or production lanes.

This is a portfolio and completion disposition. It is not a claim that
rust-libp2p failed gates that were never run. The publish-disabled provider and
its opt-in lab feature remain only as a bounded test oracle under
[Decision 0027](../decisions/0027-libp2p-pilot-dependency-policy.md). They grant
no requirement, conformance, compatibility, dependency-admission, capability,
or production credit and must be removed or explicitly reauthorized by that
decision's deadline.

## Evidence retained

### Provider-free Gate H

Gate H passed for the provider-free shared-node baseline, not for a libp2p
provider:

- signed commit
  `224fd940bc580a2f62dadbaa93a873b38935e10c` and tree
  `41607bab0383e59ce7a2a0a48a4ee8e399707491`;
- candidate binary SHA-256
  `2989cb11992f04a843bfd97004206097d9a7349ad73dc75e7d9525da187e59f5`;
- fault receipt: 25/25 cases, 40/40 commands, and 26/26 static checks, receipt
  SHA-256
  `2976f81bbff43dfec62ba6cb017aa3794038b6963eaa4c03e44efc9753139662`;
- live retry-08 cohort: 10/10 trials, summary SHA-256
  `20c4ccaf26385ac72a20f53349253c27887509e2a1a3ca140e7c9338e2ba9ad9`;
- evidence aggregate SHA-256
  `4cd435976e6544d20120e917da151be6a4f4177174d5265191cf3a1d546abe0b`;
  and
- evidence-index SHA-256
  `7ac26490c89c124681c98a0c226c4592c2e03dba525802f311618454b39afee9`.

The raw Gate-H evidence remains in the local evidence store and is
not committed in this public tree. A later post-hoc revalidation attempt was
stopped because local Git configuration no longer matched the frozen receipt.
The historical hashes and disposition are retained; this result does not call
that cohort freshly revalidated on 2026-08-23.

### Default-disabled rust-libp2p development checkpoint

The version-controlled closure tree preserves the final development checkpoint
before closure. Its exact source files are:

- `crates/aster-lab/src/mesh_experiment/libp2p_candidate.rs` — SHA-256
  `7b12a8f028593729a36a1bc524cff09939c803bc168b36959e6fb576d6dfa1fe`;
- `crates/aster-libp2p-provider/src/adapter.rs` — SHA-256
  `eb9ab9ef50cf248042872f993d114c37c0af4399792945426b9504061503ec22`.

The lab source hash includes a watchdog-only stabilization made after a slow
shared CI runner exhausted the original 120-second bound while continuing far
beyond the required frame count. The bound is now 300 seconds; the workload
and every delivery, durability, backpressure, stream, identity, and resource
assertion are unchanged. This is a deadlock bound, not throughput credit.

Its locked, offline, localhost-only validation passed:

- 20/20 `aster-libp2p-provider` tests, including Identify, controlled AutoNAT
  v1, controlled relay/DCUtR, bounded framing, connection attribution, and
  replacement lifecycle;
- 17/17 opt-in `aster-lab` tests, including a 10,000-frame bidirectional run,
  fresh Aster authentication on direct connection replacement, and the
  archived 64 KiB trial-14 payload size; and
- warning-denied Clippy for the provider and opt-in lab graph.

These are development tests, not the missing formal Phase-0 or Phase-1
receipts. The provider-only relay/DCUtR test and full-node direct-replacement
test are separate witnesses; no combined supervisor-bound relayed-to-direct
replacement was executed.

## Phase accounting

| Phase | Final disposition |
| --- | --- |
| Gate H | Passed for the provider-free shared-node prerequisite only. |
| Phase 0 | Not completed for either eligible arm: no exact comparative source, SBOM, advisory, feature-graph, or oracle freeze. |
| Phase 1 | Incomplete. The rust-libp2p checkpoint supplied development characterization; no formal corrected-native versus rust-libp2p result exists. |
| Phases 2–4 | Stopped before execution. No impairment, hostile-input, scale, resource, privacy, NAT/relay matrix, or physical-network selection credit. |
| Phase 5 | Not reached. No formal selection deletion patch or identical-partial-transfer rollback receipt was produced. |

No stopped phase is recorded as a zero-trial pass or as a candidate failure.

## Why the lane closes

Proposal 0005 introduced an independent requirements-first comparison.
Proposal 0006 then retained Iroh 1.0.3,
Negentropy 0.5.1, and redb 4.2.0 only as the bounded engineering baseline,
while keeping `production_selected=false`. Continuing Proposal 0004 would
reopen a narrower provider-first comparison after the program had selected a
different implementation direction and would preserve overlapping experimental
connectivity work without closing the larger semantic, security, Blob, policy,
physical, target, and release gates.

The useful Proposal 0004 outcome is the provider-neutral shared-node ownership
and admission architecture. The rust-libp2p wrapper remains a temporary test
oracle only; it is not a second selected carrier.

## Continuing obligations

- Decision 0027's dependency exception remains fail-closed and expires on
  2026-11-23, or before any default, release, deployment, or production use,
  whichever comes first.
- Any future rust-libp2p proposal must start from a new decision and formal
  freeze. It cannot inherit selection credit from this result.
- The selected-stack implementation proceeds through its independent profile,
  persistence, reconciliation, carrier, security, and release gates.
- Historical Proposal 0004 receipts and commits remain immutable; this result
  appends the disposition rather than rewriting the experiment.
