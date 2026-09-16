#

# Recommendation review: integration and delivery workflows

- Feedback ID: `CF-2026-09-16-01`
- Feedback record: [Feedback](feedback.md)
- Review date: 2026-09-16
- Recommendation status: `Proposed`
- Review owner: Aster product and architecture reviewers
- Requirement and evidence effect: **None**

## Executive recommendation

Treat this feedback as validation of existing Blob, store-and-forward, adopter-
surface, status, and protected-provisioning roadmap work rather than as a
commitment to customer-specific connectors.

First define a narrow Event-and-Blob integration profile and its transfer-state
semantics. Then qualify lossless artifact delivery with associated metadata and
publish a technology-neutral adapter example. Defer named middleware
connectors, downstream transformations, granular delivery semantics, and
bulk onboarding implementation until their ownership and policy boundaries are
confirmed.

## Assessment

The feedback maps primarily to existing capability actions:

- **P0-1:** define the adopter workflow, included data classes, target systems,
  delivery meanings, security boundary, and acceptance thresholds;
- **P1-1:** close applicable Blob retention, staging cleanup, expiry, pressure,
  and crash-recovery behavior;
- **P1-3:** preserve protected identity provisioning and administration rather
  than treating bulk addition as unauthenticated discovery;
- **P2-1:** use existing scoped, payload-blind store-and-forward behavior where
  indirect delivery is required;
- **P2-2:** qualify interruption, resume, resource use, and difference work for
  the selected artifact workflow; and
- **P2-3:** expose stable transfer and node status and provide a usable,
  technology-neutral adopter surface.

No new top-level capability action is warranted. The potentially new product
decisions are narrower: whether artifact groups need atomic readiness, whether
granular delivery control belongs in Aster's propagation model, and which
administrative operations are meant by bulk onboarding.

## Completeness and sanitization boundary

The confidential source was reviewed expectation by expectation. Every
product-relevant behavior is addressed across the five recommended increments:
protected artifact-and-metadata delivery, finer delivery policy, indirect
application ingress and egress, sustained authorized data and status access,
lifecycle observability, and protected multi-node onboarding.

Completeness here means preservation of product semantics, open questions, and
ownership boundaries—not verbatim traceability. The recommendation does not
retain the source's organization or system names, exact formats, workload
labels, examples, taxonomy, ordering, topic count, or distinctive external-
technology relationships.

## Scoring method

Scores are relative from 1 to 5:

- **Value** combines adopter relevance, roadmap leverage, and reduction of
  integration or qualification risk.
- **Remaining effort** combines engineering, review, qualification, security,
  dependency, and operational complexity. It is not a calendar estimate.
- **Balance** is value divided by remaining effort. Dependencies and confidence
  break ties.

## Value/effort ranking

| Rank | Candidate action | Value | Remaining effort | Balance | Roadmap fit |
| ---: | --- | ---: | ---: | ---: | --- |
| **1** | **Define and expose selected Event-and-Blob transfer status and lifecycle records** | 5 | 3 | **1.7** | P0-1, P2-3; P1-1/P2-2 dependencies |
| **2** | **Qualify lossless artifact delivery with associated metadata** | 5 | 3 | **1.7** | P1-1, P2-2, P2-3 |
| **3** | **Publish a technology-neutral local integration adapter pattern and sample** | 5 | 4 | **1.3** | P2-3 |
| **4** | **Decide protected granular-delivery semantics** | 4 | 4 | **1.0** | P0-1, P2-1; security-policy dependency |
| **5** | **Define and implement protected bulk onboarding** | 3 | 5 | **0.6** | P1-3; P2-1/P2-3 dependencies |

The first two actions have the same numeric balance. Status comes first because
it defines the observations needed to qualify the artifact workflow and gives
adapter authors stable meanings for progress and completion.

## Recommended capability increments

### 1. Define transfer and health status semantics

For one explicitly bounded Event-and-Blob evaluation profile, define states for
local durable publication, eligibility, pending contact, offered progress,
partial durable receipt, receiver completion, application delivery or
acknowledgement, expiry, eviction, policy withholding, retry, and terminal
failure. Define which states are local observations and which are authenticated
remote facts.

Lifecycle records should correlate ingestion or publication, transfer start,
receiver durability, application delivery or acknowledgement, and cleanup
across restart. Define retention, access control, overhead, and whether each
time value is local, authenticated remote metadata, or monotonic elapsed time;
wall-clock values remain advisory rather than correctness inputs.

For node health, distinguish local observations from authenticated remote
reports and define freshness, unavailable-node behavior, and whether visibility
is local, peer-scoped, or broader. No status surface should imply unauthorized
global membership visibility.

Expose only the subset supported by the selected runtime and API. Correlate
status with lifecycle records without exposing payloads, protected routing
metadata, or unauthorized node information. Do not label sender completion as
receiver or application completion.

This is a P2-3 adopter-surface increment with P1-1 lifecycle and P2-2 recovery
dependencies. It does not establish all-class status or production
observability.

### 2. Qualify an artifact-and-metadata workflow

Exercise an immutable Blob plus an authenticated metadata reference across
interrupted contacts, restart, resume from an eligible participant,
deduplication, exact reconstruction, application delivery, and cleanup. Measure
transferred bytes, durable progress, storage use, peak memory, and completion
state.

Start without promising atomic activation of a group of related artifacts. If
the adopter requires all-or-nothing readiness, define that separately as an
application-visible manifest and activation contract rather than inferring it
from successful movement of individual objects.

### 3. Publish a technology-neutral adapter pattern

Provide one neutral reference adapter or sample that maps a local message
source into Aster publication and maps an Aster subscription into a downstream
consumer or adapter-managed destination queue. Document long-lived connection
recovery, acknowledgement, reconnect, backpressure, ordering, deduplication,
expiry, authorization, and failure ownership.

Keep the adapter outside the mesh's correctness core and avoid freezing a
vendor-specific contract before target middleware semantics and maintenance
ownership are known. An example is not evidence that every external system is
supported.

### 4. Resolve granular-delivery semantics before implementation

Determine whether finer delivery control belongs in an application delivery
selector, a protected topic or scope policy, or a custody instruction. Any
design must preserve scope authorization, payload-blind forwarding, offline
delivery, deduplication, and non-disclosure of unauthorized membership.

Do not equate configured peer addresses with application-level recipients or
permit recipient targeting to bypass subscriptions and scopes.

### 5. Separate the bulk-onboarding operations

Define which operations are actually needed: identifier inventory, credential
provisioning, registration, peer admission, scope membership, policy
assignment, or configuration import. Build only the reviewed subset through a
protected administrative surface with bounded batches, per-node results,
idempotent retry, rollback behavior, and an audit record.

This work follows the selected provisioning backend and operator-lifecycle
decisions. Ease of use must not weaken identity or authorization controls.

## Recommended roadmap sequencing

1. Use P0-1 to select the initial Event-and-Blob workflow and define exact
   transfer, health, and completion meanings.
2. Add the selected status and lifecycle surface under P2-3 while closing its
   P1-1 and P2-2 dependencies.
3. Run the lossless artifact-and-metadata qualification scenario.
4. Publish the neutral adapter pattern against the stabilized surface.
5. Pull granular-delivery or bulk-onboarding implementation forward only after
   their policy and ownership questions are resolved.

This sequence reuses the current roadmap and avoids making customer-specific
integration work a prerequisite for unrelated capability progress.

## Recommendations not adopted

- Do not commit to a connector for any named external product based on this
  feedback alone.
- Do not place downstream transformation, visualization, or final-system
  delivery inside Aster without a separate product decision.
- Do not claim atomic deployment or activation of an artifact group from
  successful delivery of its individual objects.
- Do not interpret access to authorized data as unrestricted access to every
  document or status record.
- Do not bypass topic, scope, identity, or authorization policy to implement
  finer delivery controls.
- Do not automate bulk admission until provisioning, authorization, failure,
  and audit semantics are reviewed.
- Do not move requirement IDs or evidence status based on this feedback review.

## Information needed

- The first adopter workflow and its priority relative to the other requests.
- Target platforms, deployment topology, carriers, and security profile.
- Artifact sizes, composition, update frequency, readiness semantics, and
  acceptable delivery time.
- Local and downstream middleware delivery, ordering, replay, and
  acknowledgement contracts.
- Message schemas, rates, payload distributions, retention, and latency needs.
- Required transfer states, node-health signals, lifecycle retention, and
  operator audience.
- The exact meaning and authorization model for finer delivery control.
- The exact administrative operations included in bulk onboarding.
- Ownership and support expectations for adapters and downstream integrations.

## Privacy and claim boundary

This review intentionally uses capability categories rather than the names or
distinctive technology combination in the confidential source. It must not be
used to infer or reconstruct the customer's identity or deployment.

## Disposition and authoritative follow-up

- Recommendation disposition: `Proposed`
- Decision date: Not decided.
- Authoritative follow-up artifacts: None.
- Requirement IDs changed by this review: None.
- Evidence status changed by this review: None.
