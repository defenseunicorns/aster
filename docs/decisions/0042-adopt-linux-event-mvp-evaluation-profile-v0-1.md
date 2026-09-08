#

# Decision 0042: Adopt the Linux Event MVP Evaluation Profile v0.1

- Status: Proposed; ratification blocked by register row `P0-1-D15`
- Proposed: 2026-09-06
- Proposed authority: [Linux Event MVP Evaluation Profile v0.1](../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
- Register: [P0-1 decision and gate register](../implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)
- Roadmap action: `P0-1 — define the claim boundary`

## Context

The 348 atomic requirements preserve the hash-bound target and evidence trace,
but they are not a flat backlog, progress percentage, or sufficient definition
of a customer claim. A useful evaluation decision needs one coherent boundary
that states who may use it, what behavior and artifacts are included, where it
may run, how it is secured and operated, what must be measured, and what
remains unsupported.

The proposed profile therefore selects the narrowest reusable customer slice
that exercises Aster's current product direction without presenting
development mechanisms as a release. It is Event-only because Event has the
most complete live application and offline-first exchange path. It is Linux-
only so the operating system, service manager, filesystem, package form, and
resource measurements can be exact. It is explicitly non-production and
time-bounded because protected provisioning, supported artifacts, physical
target evidence, and release authorization remain open. Its 2-, 8-, and
20-node tiers include the largest bounded topology proposed for this
evaluation while requiring the exact physical/virtual composition and avoiding
a broader scale claim.

The profile also needs explicit constrained-operation and lifetime-capacity
boundaries. Restart-selected ReceiveOnly is included so inbound synchronization
can be evaluated without claiming physical radio silence or zero-byte
transmission. Publish-operation accounting, authenticated status, warning, and
terminal capacity-error behavior are included because safe idempotent retries
require durable operation keys that cannot be silently deleted or reused.

## Proposed decision

Adopt the proposed
[Linux Event MVP Evaluation Profile v0.1](../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
as the reusable P0-1 claim boundary only after the remaining ratification
blocker below is resolved. The package has four distinct roles:

1. The proposed profile defines the bounded application, platform, topology,
   security, workload, resource, lifecycle, artifact, and evidence contract.
2. The mutable
   [decision and gate register](../implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)
   records resolved boundary choices, open candidate gates, production
   deferrals, owners, targets, and exit artifacts. It does not replace the
   profile or atomic requirements trace.
3. The
   [DM-8-05 disposition](../implementation/dm-8-05-linux-event-v0.1-disposition.md)
   (`sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53`)
   is an unsigned evaluation-only proposal for two exact dependency tuples.
   Dependency, Legal, and Release decisions are each Pending. It grants no
   production or general-license authority.
4. The
   [candidate-annex schema](../implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md)
   is provisional and revisionable. It describes how a later exact candidate
   would bind artifacts, environments, results, receipts, and approvals; the
   schema is not qualification evidence by itself.

Implementation and retained-evidence gates do not by themselves block P0-1.
P0-1 defines what a candidate would have to satisfy; it does not assert that
the implementation, artifacts, devices, or receipts already satisfy it. The
approved design nevertheless makes exact dependency disposition part of the
claim boundary and therefore a prerequisite to ratification:

- `P0-1-D06` is resolved for the profile definition. Internal approval of the
  exact provider selection and bound digest was recorded on 2026-09-08 against
  the
  [approved initial systemd credential provider design](../superpowers/specs/2026-09-07-systemd-credential-provider-design.md).
  Security and deployment approvals remain mandatory candidate gate E01. If
  final review requires Debian or generic Debian-family support, D06 reopens
  and the provider must be redesigned and versioned before the affected
  profile or candidate proceeds.
- `P0-1-D15` remains Open until dependency, legal, and release owners each
  record approval of the exact evaluation-only DM-8-05 proposal digest and
  dependency coordinates. Existing lockfile, dependency-policy, and notice
  entries do not substitute for those approvals.

Until D15 closes through its reviewed exit records, this decision and the
profile remain Proposed and the
[approved design](../superpowers/specs/2026-09-06-linux-event-mvp-evaluation-profile-design.md)
remains authoritative.

## Candidate and production boundary

Ratifying P0-1 would define the reusable profile; it would not authorize an
evaluation candidate. G1 through G6 still require, in order, an accepted Event
baseline, a frozen source/API commit, reproducible signed artifacts, focused
target tests, workload qualification, and a signed issue/refuse/defer
disposition for the exact artifact set. Every applicable evaluation-blocking
register row and completed annex field must pass before issuance.

This proposal changes no atomic requirement status, mapping, retained receipt,
capability maturity, implementation claim, or production-readiness claim. A
production profile must supersede v0.1 through a separate reviewed decision and
must close every applicable production obligation rather than inheriting this
evaluation-only subset.

## Separate implementation boundary

No runtime or API work is authorized by this documentation decision. After the
candidate Event-service branch is integrated and reviewed, a separate plan may
implement restart-selected `mesh.emission_policy`, effective ReceiveOnly
status, authenticated operation-capacity/headroom status, the distinct
nonretryable operation-map exhaustion error, retry-documentation corrections,
and the Rust/Go qualification cases. Protected-provider composition,
reproducible packaging, physical-device qualification, and release disposition
remain owned by their separate workstreams and gates.

## Consequences

- Reviewers receive one bounded profile instead of inferring readiness from a
  count of requirements or mechanisms.
- D06 is resolved for profile definition while its security/deployment reviews
  remain visible candidate gate E01; D15 remains the profile-ratification
  blocker.
- G1-G6 and every other evaluation gate remain mandatory after P0-1 closes.
- State, Record, Blob, BTLE, dynamic routing, broader scale, production use,
  and all other profile exclusions remain unsupported by this proposal.
