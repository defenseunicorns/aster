#

# Decision 0042: Adopt the Linux Event MVP Evaluation Profile v0.1

- Status: Accepted
- Proposed: 2026-09-06
- Accepted: 2026-09-08
- Authority: [Linux Event MVP Evaluation Profile v0.1](../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
- Amendment status: incorporated into the current profile authority
- Register: [P0-1 decision and gate register](../implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)
- Roadmap action: `P0-1 — define the claim boundary`

## Context

The 348 atomic requirements preserve the hash-bound target and evidence trace,
but they are not a flat backlog, progress percentage, or sufficient definition
of a customer claim. A useful evaluation decision needs one coherent boundary
that states who may use it, what behavior and artifacts are included, where it
may run, how it is secured and operated, what must be measured, and what
remains unsupported.

The profile selects the narrowest reusable customer slice
that exercises Aster's current product direction without presenting
development mechanisms as a release. It is Event-only because Event has the
most complete live application and offline-first exchange path. It is Linux-
only so the operating system, service manager, filesystem, package form, and
resource measurements can be exact. It is explicitly non-production and
time-bounded because protected provisioning, supported artifacts, physical
target evidence, and release authorization remain open.

The accepted pre-merge profile now selects the exact Raspberry Pi reference
2026-06-18, Debian GNU/Linux 13 `trixie`, `6.18.39+rpt-rpi-v8`, systemd
`257.13-1~deb13u1`, local `ext4`, physical Raspberry Pi Compute Module 4 Rev
1.1, and `aarch64` boundary recorded by the 2026-09-08 amendment. The rationale
for that narrower fast path is:

- two physical `aarch64` CM4 nodes minimize time to physical qualification;
- the third device is support capacity, not evidence for a broader tier;
- one `arm64` artifact is required;
- `x86_64`, Ubuntu, VMs, and 8-/20-node scale are deferred without changing
  atomic requirement status;
- D06 is resolved for profile definition by the exact v2 design and digest;
  and
- E01, G1–G6, final candidate approvals, and production gates remain open.

The profile also needs explicit constrained-operation and lifetime-capacity
boundaries. Restart-selected ReceiveOnly is included so inbound synchronization
can be evaluated without claiming physical radio silence or zero-byte
transmission. Publish-operation accounting, authenticated status, warning, and
terminal capacity-error behavior are included because safe idempotent retries
require durable operation keys that cannot be silently deleted or reused.

## Decision

Adopt the
[Linux Event MVP Evaluation Profile v0.1](../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
as the reusable P0-1 claim boundary. The package has four distinct roles:

1. The profile defines the bounded application, platform, topology,
   security, workload, resource, lifecycle, artifact, and evidence contract.
2. The mutable
   [decision and gate register](../implementation/linux-event-mvp-evaluation-profile-v0.1-register.md)
   records resolved boundary choices, open candidate gates, production
   deferrals, owners, targets, and exit artifacts. It does not replace the
   profile or atomic requirements trace.
3. The
   [DM-8-05 disposition](../implementation/dm-8-05-linux-event-v0.1-disposition.md)
   (`sha256:a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53`)
   is the hash-bound evaluation-only proposal for two exact dependency tuples.
   Its separate
   [internal role-approval record](../implementation/dm-8-05-linux-event-v0.1-role-approvals.md)
   (`sha256:4edda9457c78d0c1d177590c1583691071e708ccbbace078cc15a82dd9bcac85`)
   records Dependency/license, Legal/compliance, and Release approval and
   resolves D15. Neither record grants candidate release, production, or
   general-license authority.
4. The
   [candidate-annex schema](../implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md)
   is provisional and revisionable. It describes how a later exact candidate
   would bind artifacts, environments, results, receipts, and approvals; the
   schema is not qualification evidence by itself.

Implementation and retained-evidence gates do not by themselves block P0-1.
P0-1 defines what a candidate would have to satisfy; it does not assert that
the implementation, artifacts, devices, or receipts already satisfy it. The
approved design nevertheless makes exact dependency disposition part of the
claim boundary:

- `P0-1-D06` is resolved for the profile definition. Internal approval of the
  exact provider selection and bound digest was recorded on 2026-09-08 against
  the
  [approved Raspberry Pi systemd credential provider v2 design](../superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md)
  at
  `sha256:30c5dfe71a203fcdd69dd330f9b5c68eeaee5032b624ee41912aa4723a9f853f`.
  Security and deployment approvals of that exact design and digest remain
  mandatory candidate gate E01.
- `P0-1-D15` is resolved. Dependency/license, Legal/compliance, and Release
  approval of the exact evaluation-only disposition and bound digest was
  recorded on 2026-09-08. The approval is limited to the exact dependency
  coordinates and this profile; it does not authorize a candidate or close
  production `DM-8-05`.

With D06 and D15 resolved for profile definition, this decision accepts the
profile as amended. The current profile incorporates the accepted 2026-09-08
platform, architecture, topology, artifact, D06, and acceptance selections;
historical design records do not override that profile authority.

## Candidate and production boundary

Accepting P0-1 defines the reusable profile; it does not authorize an
evaluation candidate. G1 through G6 still require, in order, an accepted Event
baseline, a frozen source/API commit, reproducible signed artifacts, focused
target tests, workload qualification, and a signed issue/refuse/defer
disposition for the exact artifact set. Every applicable evaluation-blocking
register row and completed annex field must pass before issuance.

This decision changes no atomic requirement status, mapping, retained receipt,
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
- D06 and D15 are resolved for profile definition. D06 security/deployment
  reviews of the exact v2 design and digest remain visible candidate gate E01;
  all other candidate gates and final approvals remain required.
- G1-G6 and every other evaluation gate remain mandatory after P0-1 closes.
- One reproducible `arm64` artifact and focused qualification on exactly two
  mandatory physical CM4 nodes replace the earlier dual-architecture and
  2/8/20-node selections for this pre-merge profile; the optional third CM4 is
  declared support capacity only.
- Ubuntu, `x86_64`, VMs, 8-/20-node scale, State, Record, Blob, BTLE, dynamic
  routing, production use, and all other profile exclusions remain unsupported
  by this decision.
