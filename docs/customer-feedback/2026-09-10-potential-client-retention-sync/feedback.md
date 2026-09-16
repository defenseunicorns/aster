#

# Potential-client feedback: retention and synchronization

- Feedback ID: `CF-2026-09-10-01`
- Feedback date: 2026-09-10
- Recorded date: 2026-09-16
- Customer label: Potential client
- Feedback state: `Reviewed`
- Source type: Call notes with follow-up clarification
- Source basis: Handwritten "Lessons" notes, user-provided call context, and
  subsequent clarification
- Source snapshot SHA-256:
  `18ba829c81fd77082847298cdb827292bdc005d19b10ae74d4d722e486ef6fbf`
- Recommendation review: [Recommendation](recommendation.md)
- Requirement authority: **None — advisory feedback only**

## Authority boundary

This document records confirmed feedback and its provenance boundary. It is not
a product requirement, roadmap commitment, acceptance criterion, implementation
instruction, evidence receipt, or release authorization. Aster-authored product
analysis is kept in the separate recommendation review.

## Overall takeaway

The potential client is interested in future integration. Their feedback
emphasizes practical synchronization as retained data accumulates, preservation
of selected mission-critical data during disconnection, and exploration of a
higher-capacity storage participant within a tactical network.

Integration blockers, target platforms, timing, and client-assigned priorities
remain unanswered.

## Confirmed feedback

| Topic | Confirmed feedback |
| --- | --- |
| Data workloads | Telemetry, sensor data, and AI detections are relevant workloads. |
| Growth and synchronization cost | As accumulated CRDT data grows, synchronization takes progressively longer. Memory consumption and network traffic also increase. The concern is operational cost; the client did not request rejection of CRDTs. |
| Near-term offline retention | A strong initial result would preserve 24 hours of selected mission-critical data on an offline node and make that content available for transmission when connectivity returns. |
| Longer-term aspiration | Seven days of mission-critical data retention on an offline node is an ideal future goal, not an immediate expectation. |
| Extremely constrained connectivity | Links offering only a few kilobytes per second are possible. This was raised as a radical edge case rather than the primary operating condition or an immediate release gate. |
| Higher-capacity storage participant | An early concept is to dedicate a participant within a tactical network to storing more useful information than resource-constrained participants such as drones can retain. A local PC or edge server could fill this role. |
| Later onward synchronization | When the tactical network segment reconnects to another network, the higher-capacity participant could synchronize collected information onward, for example to a base. |

## Context supplied with the feedback

- The intended benefit of the higher-capacity participant is to retain more
  useful information despite limits on individual participants.
- Retention during disconnection and delivery after reconnection are distinct
  outcomes.
- The feedback did not assign relative priority among the topics above.

## Not confirmed or still unanswered

- Integration blockers and required external systems.
- Target operating systems, device tiers, and available storage.
- Event rates, payload-size distributions, and data volumes by workload.
- How mission-critical data is selected.
- Maximum acceptable delivery time after reconnection.
- Typical and worst-case bandwidth, loss, latency, and contact duration.
- Whether AI detections include imagery or other large binary content.
- Whether the higher-capacity participant remains in one scope or crosses an
  administrative boundary.
- Decision timing and client-assigned priorities.

## Source boundaries and corrections

- Questions appearing above the source notes' "Lessons" section were discussion
  prompts, not confirmed feedback.
- Product implications and roadmap comparisons in the source summary were
  Aster-authored analysis. They are not repeated here as customer statements.
- No customer identity is recorded in this package.

## Related feedback

- None recorded.
