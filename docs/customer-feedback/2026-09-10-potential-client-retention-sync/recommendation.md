#

# Recommendation review: retention and synchronization feedback

- Feedback ID: `CF-2026-09-10-01`
- Feedback record: [Feedback](feedback.md)
- Review date: 2026-09-16
- Recommendation status: `Proposed`
- Review owner: Aster product and architecture reviewers
- Requirement and evidence effect: **None**

## Executive recommendation

The feedback reinforces Aster's current roadmap rather than requiring a product
pivot. Finite Event TTL is now a merged foundation. Capture its reported test-
device observation in a reviewable record, then use the capability in a narrow,
instrumented 24-hour Event workflow before extending into measured growth
behavior and policy-driven, higher-capacity custody.

Do not treat the feedback as a request to replace CRDTs, create a new server
architecture, commit to seven-day retention, or change the requirements'
provisional offline-tolerance value.

## Assessment

The feedback maps primarily to existing capability actions:

- **P0-1:** define the exact workload, platforms, retention policy, operating
  bounds, and acceptance claim;
- **P1-1:** close the applicable Event lifecycle and bounded-retention subset;
- **P2-2:** measure long-offline recovery, synchronization work, storage,
  bandwidth, memory, and target-resource behavior; and
- **P2-1:** introduce a supported custody or forwarding profile only after its
  lifecycle, policy, and administration dependencies are stable.

No new top-level capability action is needed. The first client-shaped profile
should remain single-scope and Event-only unless confirmed workloads require
another data class.

## Delivered foundation and evidence boundary

[PR #28, "Expose finite Event TTL over Connect"](https://github.com/edgesoftops/astertech/pull/28)
merged on 2026-09-16, and its required CI checks passed. Finite Linux Event TTL,
expiry withholding, local cleanup, reclaimed logical capacity, restart
behavior, and retry classification are therefore implemented mechanisms rather
than proposed feature work.

A parallel session reportedly exercised the TTL capability on test devices,
but no retained validation record is currently linked. Treat that result as an
unretained observation: it reduces uncertainty and makes evidence capture the
next action, but it does not by itself move requirement status, capability
maturity, or the 24-hour qualification boundary.

The retained record should bind the exact artifact or commit, device profile,
TTL cases, elapsed custody interval, expiry withholding, capacity reuse,
restart behavior, result, and explicit nonclaims. Until that record is reviewed,
do not describe the device result as retained qualification evidence.

## Scoring method

Scores are relative from 1 to 5:

- **Value** combines client relevance, roadmap leverage, and reduction of
  product or qualification risk.
- **Remaining effort** combines engineering, review, qualification, dependency,
  and operational complexity. It is not a calendar estimate.
- **Balance** is value divided by remaining effort. Dependencies and confidence
  break ties.

## Value/effort ranking

| Rank | Candidate action | Value | Remaining effort | Balance | Roadmap fit |
| ---: | --- | ---: | ---: | ---: | --- |
| **1** | **Instrumented 24-hour selected-Event retention and reconnect qualification** | 5 | 2 | **2.5** | P0-1, P2-2 |
| **2** | **Dataset-growth synchronization benchmark and Event-path remediation** | 5 | 3 | **1.7** | P2-2; `DM-5.2-18` |
| **3** | **Higher-capacity same-scope custody-node profile** | 4 | 3 | **1.3** | P2-1, P2-2 |
| **4** | **Few-kilobytes-per-second stress profile** | 2 | 2 | **1.0** | P1-4, P2-2 |
| **5** | **Cross-segment onward synchronization through the custody node** | 4 | 4 | **1.0** | P2-1, P1-3 |
| **6** | **Seven-day retention profile** | 3 | 5 | **0.6** | P1-1, P2-2 |

Finite Event TTL is excluded from this ranking because it is delivered
foundation rather than remaining feature scope. Capturing its device result is
evidence maintenance, not a competing customer feature.

## Recommended capability increments

### 1. Instrumented 24-hour Event qualification

The current Linux Event evaluation profile already defines a two-participant
offline soak using 4-KiB Events at 10 Events per hour per participant for 24
hours, followed by reconnection and convergence. The latest CM4 device record
states that this soak and a true network partition were not run.

The next retained scenario should measure local publication, restart
preservation, later delivery, gap reporting, acknowledgement, zero-difference
second-contact cost, retained bytes, database growth, remaining capacity,
convergence time, transmitted bytes, inventory work, peak RSS, and CPU.

The low-rate fixture is a bounded evaluation, not a representative telemetry,
sensor, or AI-detection claim.

References:

- `docs/validation/linux-event-mvp-evaluation-profile-v0.1.md`, "Capacity and
  workload matrix"
- `docs/validation/evidence/2026-09-15-cm4-ci-package-mvp-validation.md`, "Not
  run in this session"

### 2. Measure synchronization cost as retained data grows

For a fixed difference between two participants, vary retained dataset size and
record transmitted bytes and frames, inventory rows examined, convergence
duration, CPU, peak RSS, durable progress-state growth, and zero-difference
repeat-contact cost.

Start with the Event-only profile. The current roadmap already records that
difference-proportional local work is not demonstrated and that total-snapshot
inventory behavior can starve Blob carrier IDs at the 100,000-item ceiling.
Remediate measured Event-path bottlenecks before expanding this acceptance
matrix across all classes.

### 3. Define a higher-capacity same-scope custody profile

Configure an ordinary Aster participant with larger validated Event custody
quotas, selected topics and priorities, declared retention and pressure
behavior, payload-blind carrying where applicable, storage headroom status, and
later forwarding to an authenticated participant in the same scope.

Do not create a special server type until the configuration profile proves
insufficient. Complete storage accounting, supported administration, and
representative physical evidence remain open.

### 4. Retain the constrained link as a stress scenario

The feedback's few **kilobytes** per second is distinct from the requirements'
provisional low single-digit **kilobits** per second. Record exact units and
conditions. Do not make the new scenario a release gate until workload and
delivery objectives are known.

### 5. Add cross-segment forwarding later

Onward synchronization across another network adds bridge administration,
dynamic policy, revocation/rekey, quota, and topology dependencies. Prove
same-scope custody first, then create a separate multi-segment profile with
explicit authorization, filtering, and failure behavior.

### 6. Keep seven-day retention aspirational

At one Event per second, seven days produces 604,800 Events, far beyond the
current evaluation profile's 10,000-item aggregate configuration even though
the separate operation ledger has a larger allowance. A credible seven-day
profile requires confirmed rates, payloads, selection policy, storage sizing,
garbage collection, recovery evidence, and a delivery objective.

## Recommended roadmap sequencing

1. Capture and review a sanitized test-device record for the merged TTL
   capability without broadening its claim boundary.
2. Define a successor client-shaped evaluation profile under P0-1 that uses
   the merged TTL capability where applicable.
3. Run the instrumented 24-hour and fixed-difference growth scenarios under
   P2-2.
4. Add the same-scope custody profile under P2-1/P2-2.
5. Pull cross-segment, mixed-class, or seven-day work forward only when
   confirmed customer facts justify it.

This preserves the roadmap's single-scope, Event-only first-customer boundary.
It does not make the ordered bridge lane a global prerequisite for customer
readiness.

## Planning issue to resolve

The current evaluation documents are inconsistent about the 24-hour workload.
The decision register describes the provisional offline-tolerance workload as
excluded or deferred, while its qualification chain still defines the 24-hour
scenario as required G5 work. A successor profile or focused register
correction should make the intended claim boundary unambiguous before new
qualification claims are made.

## Recommendations not adopted

- Do not replace the synchronization model based on this feedback.
- Do not treat seven days as a first-release commitment.
- Do not create a distinct storage-server architecture before testing an Aster
  configuration profile.
- Do not equate kilobytes per second with kilobits per second.
- Do not broaden the first acceptance slice to State, Record, or Blob without
  confirmed workload data.
- Do not move requirement IDs or evidence status based on this review.

## Information needed

- Target operating systems, hardware tiers, and available storage.
- Event rates and payload-size distributions by workload.
- Whether AI detections include imagery or other Blob content.
- The policy used to identify mission-critical data.
- Maximum acceptable delivery time after reconnection.
- Typical and worst-case bandwidth, loss, latency, and contact duration.
- Whether the higher-capacity participant remains in one scope.
- Integration blockers, decision timing, and customer-assigned priorities.

## Disposition and authoritative follow-up

- Recommendation disposition: `Proposed`
- Decision date: Not decided.
- Authoritative follow-up artifacts: None.
- Delivered implementation: merged [PR #28](https://github.com/edgesoftops/astertech/pull/28)
- Device-validation observation: Reported from a parallel session; retained
  evidence record not yet linked.
- Requirement IDs changed by this review: None.
- Evidence status changed by this review: None.
