# Production implementation requirements status

- Status date: 2026-09-15
- Requirements authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Requirements SHA-256: `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Planning view: [`capability-roadmap.md`](capability-roadmap.md)
- Atomic requirements index: [`requirements-matrix.csv`](requirements-matrix.csv)
- Exhaustive cross-lane trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Matrix SHA-256: `57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2`
- Retained receipt baseline (parent PR-A/pre-subscription): signed commit `ee57c0f1a0ff67b9a301220b63bb009593ef626b`
- PR-B code baseline: signed commit `e5feff0b03bff70018825212cab905cebeefadcb`
- Current controlled Iroh relay source/test freeze: signed commit
  `b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`; exact source manifest and gates in
  [Current controlled Iroh relay automated evidence](#current-controlled-iroh-relay-automated-evidence)
- Selected Iroh namespace-NAT retained-receipt source freeze: signed commit
  `15f4e0b8e9f817508c14fcbb4b307d6949add557`; exact immutable source,
  sanitized receipt, replay boundary, and nonclaims in
  [Selected Iroh namespace-NAT retained receipt](#selected-iroh-nat-retained-receipt)
- Selected live Event retained-receipt source freeze: signed commit
  `c464129d58c250dea2ecbf5f51d7ece0e5aab6d0`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, forced-process replay
  boundary, and nonclaims in
  [Selected live Event retained receipt](#selected-live-event-retained-receipt)
- Selected live State/Record retained-receipt source freeze: signed commit
  `6cabb4cefaf6200c4642abddeb6f559dab043295`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, replay boundary, and
  nonclaims in [Selected live State and Record retained receipt](#selected-live-state-and-record-retained-receipt)
- Selected live State-subscription retained-receipt source freeze: signed commit
  `8912fc33571449d1beb4a4cb0f204b5dcd44e8c2`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, forced-process replay
  boundary, selector-separation boundary, and nonclaims in
  [Selected live State subscription retained receipt](#selected-live-state-subscription-retained-receipt)
- Selected live Record-subscription retained-receipt source freeze: signed commit
  `0c1134411953f4bb52133b50aff9989cd4ce3930`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, whole-conflict and
  forced-process replay boundaries, selector separation, and nonclaims in
  [Selected live Record subscription retained receipt](#selected-live-record-subscription-retained-receipt)
- Selected live Blob-subscription retained-receipt source freeze: signed commit
  `26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, exact-publication/shared-
  content and forced-process replay boundaries, and nonclaims in
  [Selected live Blob subscription retained receipt](#selected-live-blob-subscription-retained-receipt)
- Selected live Blob retained-receipt source freeze: signed commit
  `044d90ff07c8e754b3d490cb810d42de3c915e3d`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, replay boundary, and
  nonclaims in [Selected live Blob retained receipt](#selected-live-blob-retained-receipt)
- Selected Linux Event custody retained-receipt source freeze: signed commit
  `ade6ee1839997e14f479463d724e208a89ec8b89`; exact immutable source,
  owner-restricted raw custody, sanitized receipt, replay boundary, and
  nonclaims in
  [Selected Linux Event custody retained receipt](#selected-linux-event-custody-retained-receipt)
- Prior semantic-v4 State/Record source/test freeze: signed commit
  `a0813a2b30b26f69ea7653dd0d3e04eba454c1b3`; exact source manifest and gates in
  [Prior selected State and Record network automated evidence](#prior-selected-state-and-record-network-automated-evidence)
- Prior semantic-v5 direct Blob source/test freeze: exact source manifest and
  bounded gates in [Prior semantic-v5 direct Blob network automated evidence](#prior-semantic-v5-direct-blob-network-automated-evidence)
- Current live selected Blob mechanism and bounded retained observation: source,
  focused current-code boundary, and exact limitations in
  [Current live selected Blob mechanism](#current-live-selected-blob-mechanism)
- Prior PR-C source freeze: exact SHA-256 identities in
  [Prior PR-C automated evidence](#prior-pr-c-automated-evidence)
- Prior selected State stopped-slice source freeze: exact SHA-256 identities in
  [Prior selected State stopped-slice automated evidence](#prior-selected-state-stopped-slice-automated-evidence)
- Prior selected Record stopped-slice source freeze: exact SHA-256 identities in
  [Prior selected Record stopped-slice automated evidence](#prior-selected-record-stopped-slice-automated-evidence)
- Prior selected Blob source freeze: exact SHA-256 identities in
  [Prior selected Blob automated evidence](#prior-selected-blob-automated-evidence)
- Prior semantic-v3 selected Event custody source freeze: exact SHA-256 identities in
  [Prior semantic-v3 selected Event custody automated evidence](#prior-semantic-v3-selected-event-custody-automated-evidence)
- Current protected live startup/control source freeze: signed commit
  `164ccc1dbafd7fa954c06eb7cf555671ff597ba1`; exact SHA-256 identities and
  current-code gates in [Current protected live startup and control automated evidence](#current-protected-live-startup-and-control-automated-evidence)
- Selected N=32 retained-receipt source freeze: signed commit
  `6f280b680c0481faae5067e87cdc52d6597dc83c`; exact Cargo release-profile binary identity,
  validator boundary, and sanitized evidence in
  [Selected N=32 retained receipt](#selected-n32-retained-receipt)
- Prior protected stopped provisioning/control administration source freeze:
  exact SHA-256 identities and full automated matrices in
  [Prior protected provisioning and control administration automated evidence](#prior-protected-provisioning-and-control-administration-automated-evidence)
- Release status: **not production-authorized**

This is the tracked implementation ledger for the active production lane. It
does not create a proposal, choose a provider, or convert research evidence into
release evidence. Update it only when reviewed reproducible evidence changes
the status of a requirement. `implemented-uncredited` may be supported by reviewed
source plus repeatable automated tests; `observed-bounded` additionally requires
the stated retained execution receipt. Neither class implies release evidence.
Use the capability roadmap for planning and merge review. The rows below are an
exhaustive evidence trace, not a flat backlog, a completion denominator, or a
release score.

## Trace vocabulary

The `selected_status` column uses only `observed-bounded`,
`implemented-uncredited`, and `open`. The remaining values below describe
separate source, evidence, or gate dimensions.

| Trace value | Meaning |
|---|---|
| `observed-bounded` | Real production-lane code passed a stated, reproducible test, but only within the recorded environment and claim boundary |
| `implemented-uncredited` | A mechanism exists, but the complete requirement has not been demonstrated |
| `open` | The selected production composition does not yet implement the obligation |
| `semantic-source` | Proven current semantic code or tests remain an equivalence source until the selected composition passes the replacement tests |
| `research-only` | Evaluation informed implementation, but its result is not production acceptance |
| `external-gate` | Completion requires target hardware, independent authorship/review, an admitted cryptographic module, or stakeholder-set values |

## Adopted security-profile applicability

The hash-bound requirements baseline remains unchanged. On 2026-08-28,
[Decision 0033](../decisions/0033-policy-selected-security-profiles.md) and the
[security-profile requirements disposition](security-profile-requirements-disposition.md)
refined its universal metadata and post-quantum wording for current planning and
release review:

- source payload encryption/authentication, payload-blind forwarding, Aster
  mission authorization, plaintext minimization, algorithm agility, and
  downgrade resistance remain hard profile-invariant boundaries;
- metadata protection is best effort within a declared exposure budget, may use
  an admitted authenticated encrypted carrier for ephemeral contact metadata,
  and protects persistent forwarding metadata independently where practical;
- Aster must support complete classical and hybrid-PQ profiles, while mission
  policy decides which are permitted or required and a required hybrid profile
  fails closed before inventory; and
- packet-capture and validated-module gates apply to the exact profile and
  claims under review rather than assuming universal PQ and zero metadata on
  every carrier.

The generated trace records this disposition on `DM-6-01` through `DM-6-03`,
`DM-6-09`, `DM-6-11`, `DM-6-12`, `DM-6-25`, `DM-6-26`, `DM-6-29`,
`DM-6-30`, `DM-11-22`, `DM-12-10`, and `DM-14-23`. It does not move any
selected status, owner, evidence, receipt, or count. The atomic trace points to
the new profile document only as a non-credit relevant artifact and narrows
stale remaining-gap wording. The current selected implementation remains the
fixed hybrid-PQ path described below. An additive profile-`0x0002`
reference/two-node mission path now exists, but no stock runtime/CLI selector,
retained receipt, or general profile negotiation exists.

## Selected composition and authority boundaries

The production lane is Iroh-first. Carrier authentication is deliberately not
mission authentication, and neither is source or control authorization:

1. Iroh authenticates a carrier endpoint over direct IP or one explicitly
   configured HTTPS relay. Rostered routes name the exact expected carrier;
   default-off automatic LAN discovery instead treats each mDNS endpoint ID as
   an untrusted locator candidate and grants it no mission authority. The relay
   origin and trust mode remain bounded operator inputs, and path choice is
   never mission or data authorization.
2. The current `aster-core` four-flight hybrid-PQ mission session authenticates
   the independently provisioned mission `NodeId` before any inventory is
   loaded or disclosed. Rostered contacts additionally check the exact expected
   mission ID. Automatic LAN contacts admit the authority-authenticated mission
   identity only after current nonrevocation checks and retain no reusable
   carrier-to-mission trust binding. This is suite `0x0001` behavior, whose
   mission record is not bound to the Iroh TLS exporter, not a claim that every
   future policy-selected profile must use that handshake.
3. The unchanged `aster-core` control-envelope provider authenticates the stable
   mission authority, delegated signer, exact sequence/predecessor chain, and
   revocation or recipient-filtered scope-epoch effect. Flash controls reconcile
   and activate from a durable contiguous prefix before the Event lane opens.
4. The unchanged `aster-core` source-envelope provider authenticates each
   Event, State, Record, or Blob publisher and protected header. State and
   Record enter the semantic-v4/v5 class- and direction-separated mutable
   lanes. Blob enters only semantic v5: its authenticated source phase precedes
   direct carrier ranges, and v1-v4 emit zero Blob frames. Content authorization
   remains separate from route authorization.
5. Semantic v6 adds one selected Event bridge lane after control authorization.
   Both peers must enable it. Each offer is filtered against the authenticated
   peer's route-grant commitments, and the receiver freshly verifies the exact
   source, wrapper, complete authorization chain, and current static policy
   before durable acknowledgement. Route-only intermediates do not open
   payload plaintext; a separately content-authorized target may do so.

Outside that stock composition, the additive profile-`0x0002` path provisions
an exact singleton classical policy, separately encrypts/authenticates
semantic-v1 Events and controls, binds P-256 mission authorization to an exact
Iroh TLS exporter before inventory, and uses QUIC rather than `ASTRFR01` for
ordinary application frames. Its local redb profile/generation binding and
same-implementation tests are mechanisms only; the selected runtime and
evidence statuses below do not move.

| Component | Selected responsibility | Deliberately excluded |
|---|---|---|
| `aster-profile` | Requirements-owned complete reconciliation key and canonical inventory ordering | Semantic identity, source security, policy, or a competing product object model |
| `aster-redb-store` | One mission-bound transaction authority for ordered control/policy, content-verified Event/State/Record/Blob publication, the shared causal frontier, Event/State/Record delivery ledgers, the metadata-only exact-publication Blob delivery ledger, Event custody, class-specific operations/cursors, guarded Record resolution, route-only Event cache, Blob depot markers, and v5 exact pending Blob source plans plus peer-neutral carrier prefixes. An additive open path binds one exact mission/profile/generation and rejects mismatch, rollback, or implicit advance. It grants ordinary Blob visibility only after exact depot, fresh full-content, and fresh current-lineage completion agree atomically. | Authenticating the caller-supplied profile generation, snapshot/backup-resistant rollback, deriving identity from unverified bytes, route-only Blob relay/custody, executing application merge code, State/Record/Blob TTL or GC, complete physical allocation/sanitization, automatic revoke-plus-rekey, or a second authority |
| `aster-negentropy` | Sole bounded set-difference mechanism over class-specific exact Event, State, Record, and v5 Blob source transfer identities, with timestamp zero | Object transfer, Blob carrier-prefix ownership, semantic identity, policy, or durable contact progress |
| `aster-iroh` | Direct endpoint lifecycle, exact carrier authentication, rostered allowlist admission, unrostered carrier acceptance only into the higher-layer mission handshake, bounded exchange, opt-in exact carrier ALPN selection and TLS-exporter channel binding, an opt-in singleton controlled HTTPS relay with explicit WebPKI or replacement DER-root trust and observation-only path telemetry, and default-off short-lived nearby lookup or sanitized locator browsing on the default IPv4 multicast interface or an explicit sorted, deduplicated bounded interface set | Mission identity, item/source authorization, production/hosted discovery or public/default relay fallback, port mapping, hostile-bounded upstream discovery state, lifetime IP pinning, representative or physical NAT acceptance, or physical-path proof |
| `aster-node` | Sole stock composition root for mission-before-inventory/control-before-data; exact rostered carrier/mission checks or bounded authority-authenticated automatic LAN admission; exact control/Event/State/Record transfer; semantic-v3/v4/v5/v6 Event custody; semantic-v4/v5/v6 State/Record lanes; semantic-v5/v6 direct content-capable Blob source-before-carrier transfer; semantic-v6 static selected Event bridge negotiation, peer-route filtering, bounded rotation, durable receiver outcomes, and restart promotion; constrained emission with ReceiveOnly zero Blob; caller-provided protected live `NodeConfig`; actor-owned live Event/State/Record/Blob and privileged control handles; durable Event delivery, retained-bounded State positive-current-version, Record whole-key active-head, and metadata-only exact-publication Blob delivery; capacity-one joined Blob worker with bounded regular-file publication and zeroize-on-drop plaintext pages; exclusive stopped Event/State/Record/Blob/control facades; local zeroization; receipts and CLI. Its mission module additionally exposes an owned, cancellation-safe two-node profile-`0x0002` Iroh authorization/raw-exchange path. | Supported bridge administration or dynamic hierarchy lifecycle, stock runtime/CLI profile selection, production or hostile-LAN discovery qualification, production SecretStore or protected stock CLI/bindings, cross-process admin IPC, automatic revoke-plus-rekey, global convergence claims, State materialized-view or synthetic-withdrawal delivery, dynamic `NodeConfig` interest mutation through State/Record/Blob application subscriptions, Blob peer/convergence status, route-only Blob relay/custody, State/Record/Blob TTL/GC, broader State/Record partitions/relays, physical RF silence, automatic merge, generalized policy, coordinated provider destruction, platform-complete zeroization, or release authorization |
| `aster-core` | Profile-`0x0001` mission/control/source security and recipient-filtered rekey planning; additive profile-`0x0002` provisioned singleton policy, P-256 semantic-v1 Event/control forms, four-flight exporter-bound session, and exact-magic facade; provider-neutral bounded provisioning protection plus operation-bound opaque SecretStore install/load/destroy contracts | A production SecretStore/protection backend, stock runtime profile selection, profile-`0x0002` State/Record/Blob/batch/bridge/rekey, hardware/platform custody policy, operational recovery or physical-erasure assurance; the core remains authoritative migration source and is not deleted while replacements lack equivalent tests |

Each control transfer ID is the exact envelope digest authenticated against its
mission authority, delegated signer, chain sequence, predecessor, and effect.
Event, State, Record, and Blob transfer IDs are SHA-256 digests of exact randomized sealed
representations. Each is intentionally distinct from the semantic `ItemId`
derived by the source-envelope profile. Negentropy and Fetch/Offer use
class-specific exact Event, State, and Record transfer IDs and semantic-v5 Blob
source IDs; redb maintains disjoint semantic
indexes plus one authenticated publisher-dot and causal-frontier authority
across Event, State, Record, and Blob. Canonical strict kind-2 Blob carrier IDs
enter only the v5 carrier-range grammar.

The selected handshake default/highest semantic version is 6 with offer
`[6, 5, 4, 3, 2, 1]`. Event remains compatible across all six values;
State/Record mechanics run in v4-v6, and Blob mechanics run in v5/v6. The
static selected Event bridge lane is v6-only. V6 ordinary lane encodings are
byte-identical to v5, and a peer without v6 negotiates the prior behavior.
V1-v4 emit zero Blob frames. Stable
wire/profile, ABI, handshake framing, and source-object formats remain version
1. Current-code v4-v6 automation does not alter any retained v1-v3 receipt.

The selected node's normal dependency graph contains neither SQLite nor
`rusqlite`. The old caller-ID opaque `put` path remains isolated for compatibility
and is not reconciled by the selected Event protocol. No old semantic path has
been deleted.

## Production-lane requirements trace

The machine-readable trace contains exactly one row for every one of the 348
atomic matrix requirements. It keeps selected-production status independent
from proven migration sources, non-credit artifacts, research pointers,
disposition, and external-gate ownership. It also carries the matrix level,
phase, class, and final-stack flag. Atomization deliberately retains repeated
phase, acceptance, and deliverable statements, so row totals must not be used as
product progress percentages or as a count of independently ratified work
items.
`python3 tools/check-implementation-requirements.py` verifies complete ID parity,
unique rows, valid selected states, exact selected-status containment, and the
conservative generated claim boundary.

The current generated totals are 49 `implemented-uncredited`, 84
`observed-bounded`, and 215 `open` rows. The exact selected-mapping count is
137 and is validated from the generated trace. The earlier 2026-08-28 prose
value of 131 was corrected to 132 before this increment; the rosterless LAN
discovery mechanism adds one exact mapping and moves two existing open
requirements without adding retained-evidence credit.
The selected Event bridge work adds four exact mappings and moves exactly
`DM-5.5-09`, `DM-5.5-10`, `DM-5.5-11`, and `DM-6-08` from `open` to
`implemented-uncredited`. It adds no retained execution evidence or
`observed-bounded` movement. The mechanism is profile-`0x0001`, Event-only,
and route-only-provider capable. Its semantic-v6 selected runtime negotiates a
typed bounded lane, filters outbound target scopes by authenticated-peer route
grants, acknowledges only durable receiver outcomes, and rotates a bounded
eight-route contact batch across repeated contacts. Redb reopen yields
nonauthorizing candidates until provider verification and durable
authorization-high-water promotion. Current verification remains linear in the
complete supplied lifetime authorization chain, and a stale incomplete prefix
does not establish current mission policy. The opt-in five-process hierarchy
Compose scenario is same-host development evidence and moves no status.
Thirteen exact rows additionally carry the Decision 0033 policy disposition
without changing those totals or their selected evidence. The selected live
Event receipt moves exactly `DM-5.1-05` through `DM-5.1-07`, `DM-5.2-06`, `DM-5.2-07`,
and `DM-5.5-02` from `implemented-uncredited` to `observed-bounded`. It changes
no `open` row and strengthens, without another status movement, `DM-5.2-08`,
`DM-6-06`, `DM-7-16`, and `DM-7-17`. No broader `DM-7` or other class row
moves. The receipt retains four peerless Event publications, exact retry and
changed-intent rejection, priority-threshold transfer with one authenticated
gap, forced receiver-process termination after a flushed unacknowledged poll,
fresh-process attempt-two replay and acknowledgement, normal-policy gap
closure, one selector-policy change, and final peerless reopen. It does not
claim a positive failed-contact observation or post-policy beta delivery.

The current v2 selected live
State/Record receipt supersedes v1. Across those two versions, the receipt
family moves `DM-5.1-02`, `DM-5.1-09`, `DM-5.3-01`, `DM-5.3-02`, and
`DM-5.3-06` through `DM-5.3-10` from `implemented-uncredited` to
`observed-bounded`; moves `DM-5.2-15` and `DM-12-04` from `open` to
`observed-bounded`; and moves `DM-11-06` and `DM-11-07` from `open` to
`implemented-uncredited`. V2 newly supplies the movements for `DM-5.1-02`,
`DM-5.2-15`, and `DM-5.3-01`. It also broadens retained evidence without
status movement for `DM-1-05`, `DM-5.1-01`, `DM-5.1-08`, `DM-5.2-01`,
`DM-5.2-09`, `DM-7-11`, `DM-7-16`, `DM-7-17`, `DM-8-01`, and `DM-8-02`.

The receipt exercises actor-owned live State and Record publication/query on a
common bounded command lane, peerless publication, exact noninserting retry,
explicit receiver interests, mission-authenticated direct-Iroh reconciliation,
concurrent State tie-break, Record sibling annotation, no-discard ordinary
publish failure, exact-guard resolution, a causally later State successor, an
authenticated empty State tombstone propagated only after the successor was
observed, superseded history, graceful handle closure, and peerless restart
projection. The existing semantic-v4/v5 lanes
continue to acknowledge exact Apply/Fetch outcomes before the next attempt,
report exact Finish remainder, type capacity deferral, and fairly rotate durable
peer/class/local Offer/Fetch cursors within the 256-peer/1,024-row bound. Each
mutable object remains capped at 1 MiB and each class at 4,096 rows/16 MiB.
The v2 receipt proves, within its bounded producer-attested and checker-bound
sequence, two concurrent State maxima, deterministic ID tie-break, a successor
whose authenticated context observes both initial versions, and a later empty
tombstone whose context observes the successor. It does not establish
indefinite tombstone retention, compaction or garbage-collection behavior, or
a delete-wins rule. At that earlier receipt boundary, `DM-5.1-01` remained
`implemented-uncredited`, and `DM-5.2-16` and `DM-5.2-17` remain `open`.
Record had no durable application delivery subscription at that receipt
boundary. The later retained Record-subscription receipt below now bounds that
whole-key mechanism without changing the earlier receipt's claims. Longer
partitions, relay custody,
automatic registered-policy merge (`DM-5.3-05`), mixed implementations,
physical systems, scale, and release acceptance remain open.

The later selected live State-subscription receipt moves exactly `DM-5.1-01`
and `DM-5.2-02` from `implemented-uncredited` to `observed-bounded`. It adds
evidence without another status movement for `DM-5.2-06`, `DM-5.2-07`,
`DM-5.2-08`, `DM-5.2-15`, `DM-5.5-02`, `DM-6-06`, `DM-7-11`, `DM-7-14`,
`DM-7-15`, `DM-7-16`, `DM-7-17`, and `DM-7-18`. The earlier mutable receipt
remains the primary evidence for `DM-1-05`, `DM-5.1-02`, `DM-5.2-01`,
`DM-5.2-09`, `DM-5.3-01`, and `DM-5.3-02`; this later receipt does not move or
replace those rows. The observation is positive-current-version delivery only:
it is neither a materialized view nor a transition feed, emits no synthetic
withdrawal when a key has no Current version, and does not dynamically mutate
configured `NodeConfig` network interests.

The selected live Record-subscription receipt moves exactly `DM-5.1-08` from
`implemented-uncredited` to `observed-bounded`. It strengthens, without another
status movement, `DM-5.2-02`, `DM-5.2-06` through `DM-5.2-09`, `DM-5.2-15`,
`DM-5.3-06` through `DM-5.3-10`, `DM-5.5-02`, `DM-6-02`, `DM-6-06`,
`DM-7-11`, and `DM-7-14` through `DM-7-18`. `DM-7-11`, `DM-7-14`,
`DM-7-15`, and `DM-7-18` remain `implemented-uncredited`; `DM-7-20` is
unchanged. The receipt proves one retained whole-conflict projection across a
forced receiver SIGKILL and fresh-process attempt-two replay, exact token and
selector separation, fresh-query guarded resolution, a new successor
projection, query-only superseded history, and one final peerless reopen. It
does not credit `DM-5.3-05`, `DM-6-23`, `DM-12-04`, any `DM-8` row, finite
TTL/GC, physical or mixed operation, scale/resource brackets, or release gates.

The selected live Blob-subscription receipt moves exactly `DM-5.3-04` from
`implemented-uncredited` to `observed-bounded`. It strengthens, without another
status movement, `DM-5.1-10`, `DM-5.1-11`, `DM-5.1-22`, `DM-6-02`,
`DM-6-06`, `DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-16`, and `DM-7-18`.
The one-host peerless receipt retains two exact source publications sharing one
`BlobId`, finalized depot variant, and committed chunk; a flushed
unacknowledged attempt one survives receiver `SIGKILL`, rotates to attempt two,
accepts the restored earlier same-tenure token for exact acknowledgement and
reacknowledgement, and finishes with an empty local ledger after peerless
reopen. It adds no network, selector-withholding/network-interest-separation,
peer-status, TTL/GC, plaintext/read, physical/mixed, scale/resource, release,
or authorization credit.

Across the superseded v1 and current v2 live Blob receipts, `DM-5.1-10`
through `DM-5.1-13`, `DM-5.2-19` through `DM-5.2-22`, and `DM-7-16` are now
`observed-bounded`. The prior v1 receipt had already moved the first three
`DM-5.1` rows and `DM-7-16`; v2 newly moves exactly `DM-5.1-13` and the four
`DM-5.2` rows from `implemented-uncredited` to `observed-bounded`. It changes
no `open` row. The
receipt retains one 96-KiB two-chunk peerless publication, exact retry and
changed-source conflict preservation, direct-Iroh seeding, a 16-KiB non-public
partial retained exactly across graceful reopen, another 16-KiB continuation
from a different eligible peer without source refetch, the 65,870-byte finish,
exact 98,638-carrier-byte reconstruction, authenticated pages, 11 graceful
actor lifetimes, closed-handle behavior, and metadata-only encrypted-depot
custody.
It broadens evidence without status movement for `DM-1-03`, `DM-1-05`,
`DM-5.1-22`, `DM-5.2-01`, `DM-5.3-04`, `DM-5.6-01`,
`DM-6-01` through `DM-6-06`, `DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-17`,
`DM-7-18`, `DM-7-20`, `DM-8-01`, `DM-8-02`, `DM-9-13`, and `DM-9-14`.
The already-observed rows in that list do not move again.

The historical stopped/local selected Blob slice moved `DM-5.1-10`,
`DM-5.1-11`, `DM-5.3-04`, `DM-9-13`, and `DM-9-14` from `open` to
`implemented-uncredited` for fixed-profile authenticated manifest/chunking,
immutable publication, bounded encrypted depot resume, and bounded-memory
streaming. Semantic v5 subsequently added a direct,
content-capable-peer-only Blob source/carrier path with durable peer-neutral
range prefixes and completion-gated publication; `DM-5.1-12`, `DM-5.1-13`, and
`DM-5.2-19` through `DM-5.2-22` moved from `open` to
`implemented-uncredited`. Current code now also exposes a cloneable
`SelectedBlobHandle` from the running actor for bounded regular-file
publication and authenticated zeroize-on-drop plaintext pages. Focused
automation covers exact retry, queue/admission/cancellation bounds, rekey and
zeroization closure, peerless publication, later direct-Iroh transfer, receiver
read, and peerless restart read. Terminal/stale cleanup removes pending source,
carrier-prefix/network, and authenticated-cache visibility while deliberately
retaining bounded quota-charged depot expected or committed staging, backing
files/chunks where present, reserved-byte authority, and the unfinished
physical-lineage fence until a future explicit GC protocol. Durable source/cache
transitions remain lifecycle-serialized, and terminal multi-carrier scheduling
advances to the lexicographically greatest carrier ID. The retained v2 receipt
observes an interrupted partial transfer, exact progress across graceful
receiver reopen, and continuation from a different eligible peer; it does not
retain the separate cleanup/race cases.
Blob peer/convergence status, route-only relay/custody, TTL/GC,
metadata-independent pure-byte identity, hundreds-of-MiB/RSS or
physical/resource acceptance, mixed implementations, a release artifact, and
complete physical allocation accounting remain open.

The current rosterless LAN discovery mechanism moves exactly `DM-5.7-01` and
`DM-5.7-04` from `open` to `implemented-uncredited`. It changes no
`observed-bounded` row. A default-off `--discover-lan` mode takes no neighbor
identity or address, treats mDNS endpoint IDs only as untrusted locator
candidates, authenticates the carrier, completes the profile-`0x0001` mission
handshake, checks current nonrevocation and the 32-mission admission bound, and
only then constructs control inventory. It retains at most 32 outbound locator
candidates, uses the existing 16-inbound and 16-outbound contact caps, repeats
whole-second discovery windows of at most 30 seconds, and stops permanently
when Event emission policy leaves `Normal`. Exact rostered nearby and manual
routes remain separate modes. Multi-homed nodes may additionally select an
explicit sorted, deduplicated bounded list of local IPv4 multicast interfaces;
an empty list retains the prior default-interface behavior. This changes only
where locator advertisements are sent and browsed, not their trust or mission
authorization meaning.

Current source ordering and focused tests cover passive browser lifecycle,
unrostered carrier acceptance, same-authority mission success,
different-authority rejection, pre-inventory admission, bounds, CLI
exclusivity, and emission-policy shutdown. The shipped quickstart is a runnable
operator path, not a retained
receipt. No physical-host discovery, authenticated Event-delivery receipt,
hostile-cardinality or resource qualification, NAT/WAN rendezvous, BTLE,
mixed-implementation, supported-target, or production credit is created. The
upstream mDNS maps remain uncapped, and the stock mission record is not bound to
the Iroh TLS exporter; carrier and mission identities are therefore
same-contact observations rather than durable common-ownership proof.

The selected controlled-Iroh slice moves exactly `DM-5.8-06`, `DM-5.8-09`,
`DM-11-02`, and `DM-13-04` from `open` to `implemented-uncredited`. Direct IP is
composed into the selected Rust node and CLI. An additive opt-in accepts one
exact root-origin HTTPS relay, with either embedded WebPKI trust or bounded
explicit DER roots that replace WebPKI, while hosted discovery, public/default
relay fallback, and port mapping remain disabled. Current-code real processes
observe direct contacts while that relay is unavailable; a separate local
fixture gives the initiator an unusable initial direct candidate, disables IP at
the responder, observes Relay at both authenticated endpoints, synchronizes one
Event, and repeats as an exact no-op. A different focused runtime test rejects
the wrong expected mission before inventory construction. Initial direct
candidates may be probed in parallel with the relay,
and authenticated Iroh negotiation may learn later direct paths, so this is not
a direct-first chronology, lifetime address pin, or NAT result. The path witness
is bounded coalesced diagnostic state and never authorizes or proves delivery.
No retained receipt or `observed-bounded` credit is created by that controlled-
relay slice. Physical IP, representative NAT direct/fallback, BTLE, mixed
implementation, resource thresholds, State/Record/Blob-over-relay acceptance,
and every release gate remain open.

The separate selected Iroh namespace-NAT retained receipt moves exactly
`DM-5.8-07` from `open` to `observed-bounded`, `DM-5.8-09` from
`implemented-uncredited` to `observed-bounded`, and `DM-11-03` from `open` to
`implemented-uncredited`. On one Darwin arm64 host, the two cells ran four
fresh selected-Iroh endpoints total (two per cell) inside separate Docker Linux
LAN and NAT-router namespaces.
The cone cell disabled every relay and observed Direct at both endpoints, 978
cross-NAT UDP packet observations, one exact Event delivery and acknowledgement,
and an exact replay no-op. The restrictive cell admitted one exact controlled
HTTPS relay, recorded three direct-drop packets and no direct cross-NAT packet,
observed Relay at both endpoints, accepted two relay sessions with 2,052 HTTPS
packet observations, delivered and acknowledged one exact Event, and repeated
as an exact no-op. This is bounded software namespace-NAT evidence, not a
direct-first or timed fallback chronology, physical NAT hardware or path,
public Internet, hosted discovery, public/default relay, port-mapping,
independent-implementation, BTLE, resource-threshold, complete-MVP, or release
result. `DM-5.8-08` and `DM-12-09` therefore remain `open`.

The selected N=32 retained receipt moves exactly `DM-9-21A` from
`implemented-uncredited` to `observed-bounded`. One operator-attested Cargo
release-profile binary run for the signed current-tree source completed the
selected Event Ping/Pong line on one macOS arm64 host over direct loopback with
32 distinct mission identities and stores, 65 exact cohorts, 158 exact-named
executions with distinct READY PIDs, 30 payload-blind intermediates, and 32
distinct log-observed READY PIDs in the final zero-difference no-op. No overlap
timing or OS sampler proves simultaneity. This does not move the bracketed
`DM-9-21` target of at least 100 nodes or any physical, distributed, NAT,
controlled-relay, BTLE, cross-transport, independent-implementation, resource,
or release row.

The selected Event custody mechanism slice originally moved `DM-5.4-05`,
`DM-5.4-09`, `DM-5.4-10`, `DM-5.4-12` through `DM-5.4-19`, `DM-5.4-21`,
`DM-5.4-22`, `DM-5.7-03`, `DM-9-24`, `DM-9-25`, `DM-11-15`, and
`DM-11-17` from `open` to `implemented-uncredited`; it also strengthened
`DM-5.4-01` and `DM-5.5-07`. The retained Linux acceptance now upgrades
exactly `DM-5.4-05`, `DM-5.4-09`, `DM-5.4-12` through `DM-5.4-16`,
`DM-5.4-18`, `DM-5.4-22`, `DM-5.5-07`, `DM-9-24`, and `DM-9-25` from
`implemented-uncredited` to `observed-bounded`; moves `DM-12-06` and
`DM-12-07` from `open` to `observed-bounded`; and corrects the equivalent MVP
restatements `DM-11-13` and `DM-11-16` from `open` to
`implemented-uncredited`. The bounded receipt retains six authenticated Event
publications, a Priority floor, two ReceiveOnly responders, four route-only
acceptances, two distinct Linux-boottime expiries, one explicit stopped-store
priority retirement, a persisted quota reduction from four items to two, and
Flash-before-Immediate delivery after the origin runtime stopped. It records
zero legacy, State, Record, Blob, and control namespace content.

No credit moves for retry cadence (`DM-5.4-10`), generic global lowest-priority
eviction (`DM-5.4-11`), physical RF silence (`DM-5.4-17`), complete-MVP scope
(`DM-5.4-19`, `DM-11-15`, `DM-11-17`), qualitative simplicity
(`DM-5.4-21`), nonconnectivity during forwarding (`DM-12-05`), or selected
carrier composition (`DM-5.7-03`). The quota transition is explicit
stopped-store pressure followed by a persisted lower quota, not automatic
startup downsizing. The observation is one same-implementation Linux arm64
container on one kernel with direct loopback contacts; it is not physical,
impaired-link, long-duration, mixed-implementation, scale, or release evidence.

PR C previously moved `DM-7-11`, `DM-7-14`, `DM-7-15`, and `DM-7-18` to
`implemented-uncredited` for the live Event boundary. The preceding PR-B
movement was `DM-5.5-02`. The retained live Event receipt now upgrades that row
plus the other five exact Event rows named above to `observed-bounded`; it does
not move the broader PR-C `DM-7` rows. The earlier live Blob receipts retain
nine cumulative observed Blob rows across v1 and v2. The already-merged local ConnectRPC
agent moves `DM-7-09` and `DM-7-10` from `open` to
`implemented-uncredited` and extends the mapped evidence for the existing
Event application boundary. That agent remains an alpha same-host,
same-implementation surface; it adds no live State/Record/Blob or production
deployment claim.

The protected stopped provisioning/control-administration slice changes no
selected status. It strengthens existing evidence for `DM-2-14`, `DM-3-12`,
`DM-6-13`, `DM-6-14`, `DM-6-18` through `DM-6-23`, `DM-11-20`, and
`DM-12-08`, and adds explicit partial-evidence mappings while keeping
`DM-3-11`, `DM-11-18`, and `DM-11-19` `open`. The totals above therefore do
not move. The extra three mappings prevent useful stopped-Rust mechanisms from
being mistaken for completed operational provisioning or MVP credit. The later
protected live Rust startup mechanism likewise changes evidence wording only.

### Where the selected lane stands

This roll-up is calculated from all 348 rows in the generated trace. Counts are
not completion percentages: `implemented-uncredited` means a partial mechanism
exists, and `observed-bounded` means only the stated environment and claim
boundary passed.

All 57 rows with an external gate are included within the 219 `open` rows:
`gate_kind` is an independent ownership dimension, not a fourth selected status.
The generator validates the trace totals; this family roll-up is the human
summary of that same CSV.

| Requirement family | Implemented, not fully credited | Observed, bounded | Open | Total |
|---|---:|---:|---:|---:|
| DM-1 Project brief | 0 | 3 | 4 | 7 |
| DM-2 Scope | 1 | 0 | 13 | 14 |
| DM-3 Operating environment | 0 | 1 | 12 | 13 |
| DM-5 Functional requirements | 23 | 50 | 49 | 122 |
| DM-6 Security requirements | 3 | 18 | 15 | 36 |
| DM-7 Developer experience | 6 | 3 | 12 | 21 |
| DM-8 Implementation constraints | 0 | 2 | 17 | 19 |
| DM-9 Performance and scale | 2 | 3 | 27 | 32 |
| DM-10 Compatibility | 0 | 0 | 6 | 6 |
| DM-11 MVP scope | 9 | 0 | 24 | 33 |
| DM-12 Acceptance criteria | 0 | 4 | 7 | 11 |
| DM-13 Deliverables | 1 | 0 | 10 | 11 |
| DM-14 Open design items | 0 | 0 | 23 | 23 |
| **Total** | **45** | **84** | **219** | **348** |

The selected lane is strongest today in bounded Event synchronization and
security ordering: real-process direct contacts, a default-off bounded
rosterless-LAN discovery mechanism, one controlled connectivity-relay Event
path, retained one-host namespace-NAT direct and controlled-relay Event
observations, temporal payload-blind Event relay,
source authentication, mission-before-inventory, control-before-Event,
durable Consume/Carry receive intent, protected receiver-directed filtering,
live high-level Event operations and last-contact status, freshly verified gap
inspection, actor-owned live State publication/query and deterministic
concurrent projection followed by causal-successor and immediate tombstone
projection, retained-bounded durable positive-current-version State delivery
across one forced receiver-process restart with configured-interest separation,
actor-owned live Record publication/query, explicit
conflict annotation and exact-guard resolution, class-specific State/Record
reconciliation with a retained bounded direct-Iroh conflict observation,
actor-owned live Blob publication and authenticated zeroize-on-drop paged reads
over a bounded encrypted depot plus semantic-v5 direct source-before-carrier
transfer and peer-neutral resume, recipient-filtered rekey, captured-node exclusion, typed bounded live
and stopped control administration, caller-provided protected/opaque-reference
live `NodeConfig` plus stopped Event/admin opens, restart/no-op behavior, and
same-UID Unix terminal software zeroization. A separate retained Linux receipt
now bounds Event TTL expiry, route-only quota pressure, priority ordering, and
ReceiveOnly ingestion within one loopback container.
The largest remaining blocks are
broader networked and long-retention Blob-delivery acceptance, State
materialized-view or synthetic-withdrawal semantics if required, dynamic
network-interest administration, and
selected-node bindings,
broader State/Record partition/relay acceptance, automatic registered-policy
merge, Blob-specific sync/peer status, representative process/crash recovery
and longer-offline Blob evidence, representative live usability, route-only
Blob relay/custody, Blob TTL/GC and larger/RSS resource acceptance, broader
conflict workflows,
cross-class and non-Linux custody plus physical constrained-operation
acceptance,
physical and mixed-implementation carrier acceptance, dynamic bridge lifecycle
and bridged scale/resource evidence,
language bindings onto the selected node, a production provisioning/SecretStore
backend and protected stock CLI/bindings, automatic or atomic revocation-to-rekey
remediation, independent interoperability/review, and release/dependency
admission.

Against this six-item selected-lane evidence and gap inventory, which is not a
priority order:

1. **Selected Event live surface — implemented, not accepted complete.** PR C
   composes publish/query/subscribe/poll/ack, unsubscribe, authenticated gaps,
   and bounded peer/last-contact status with the running actor. A current-code
   real-process test publishes offline and delivers later. There is no retained
   PR-C acceptance artifact, and status/gap absence does not prove convergence
   or publisher completeness.
2. **State, Record, and Blob have retained live application-delivery
   observations; broader acceptance remains open.**
   Actor-owned `SelectedStateHandle` and `SelectedRecordHandle` share the
   running node's bounded application command lane, source-seal and durably
   publish while peerless, query freshly verified projections, and close with
   the actor. The Record handle preserves and annotates every causal head,
   rejects ordinary publish across an unresolved conflict, and commits only an
   exact-guard application-reviewed successor. The retained two-participant run
   proves concurrent State tie-break, a causally later successor that
   supersedes both initial versions, propagation of a later authenticated empty
   tombstone, two-head Record preservation, guarded resolution, superseded
   history, exact retry, direct synchronization, and immediate peerless restart
   projection. The causal observation/publication order is producer-attested
   and checker-bound; the receipt does not prove indefinite tombstone
   retention, garbage collection, delete-wins behavior, longer partitions,
   relays, physical or mixed implementations, scale, or release.
   Historical stopped `SelectedBlobNode` remains available. Current
   `RunningNode::selected_blobs()` returns a cloneable actor-owned handle that
   admits a nonempty regular file under the selected 64-MiB/1,024-chunk bound,
   publishes through a capacity-one joined worker, and returns freshly
   authenticated zeroize-on-drop plaintext pages of at most 64 KiB. Exact
   retry, cancellation/admission boundaries, policy/rekey races, shutdown and
   zeroization closure, direct-Iroh later synchronization, receiver read, and
   peerless restart read have focused automation. Separately, the
   runtime reconciles durable State/Record objects in semantic v4/v5 through
   protected class/direction exact-ID lanes under explicit interests. Exact
   result acknowledgement, exact Finish remainder, typed capacity deferral,
   per-object/per-class limits, and fair durable cursor rotation bound each
   contact. Semantic v5 additionally stages each exact Blob source before its
   carriers, persists peer-neutral 16-KiB prefixes, resumes the exact complement
   from another eligible content peer after receiver reopen, and withholds the
   publication until depot, full-content, and current-lineage proofs agree.
   The retained three-participant Blob receipt exercises the live boundary,
   direct seeding, a one-contact 16-KiB partial retained across graceful reopen,
   one-contact 16-KiB continuation from a different eligible peer without
   source refetch, the 65,870-byte finish, exact 98,638-carrier-byte
   reconstruction, and a final peerless reopen. A separate retained State
   subscription receipt now observes durable positive-current-version delivery,
   forced receiver-process termination and attempt-two redelivery, explicit
   current tombstone delivery, acknowledgement/reacknowledgement, and separation
   between static network interests and application subscriptions. A separate
   retained Record receipt now observes complete whole-key active-head delivery,
   forced-process attempt-two redelivery, guarded resolution, successor delivery,
   selector separation, and final peerless reopen. A separate retained Blob
   subscription receipt now observes two exact publications sharing one
   immutable `BlobId` and depot variant/chunk, forced receiver `SIGKILL`,
   attempt-two redelivery, earlier same-tenure token acknowledgement and
   reacknowledgement, and final empty local-ledger status on one peerless host.
   State
   materialized-view or synthetic-withdrawal semantics, dynamic `NodeConfig`
   interest mutation,
   broader disconnected/relay acceptance, automatic registered-policy Record
   merge, Blob-specific sync/peer status, route-only Blob relay/custody,
   metadata-independent byte identity, Blob TTL/GC, and large-Blob/RSS
   acceptance remain open.
   Their broader proven semantic implementation remains the migration source.
3. **Selected Event finite TTL, forwarding age, expiry, quotas, priority, and
   receive-only — implemented and boundedly observed; broader acceptance
   remains open.** Semantic-v3-format
   mechanics, inherited by semantic v4/v5, bind cumulative custody to the
   authenticated session and exact Event transfer;
   Linux supplies suspend-inclusive finite age; redb atomically owns quota,
   retirement, lease, retry, receipt, and replay-fence state; the node schedules
   priority work, exposes aggregate/scope configuration and live thresholds,
   and accepts bounded authenticated inbound Event work in ReceiveOnly. Normal
   and AtLeast still run v4 mutable reconciliation because the threshold is
   Event-only; ReceiveOnly initiates and discloses no mutable objects.
   The retained Linux receipt observes six authenticated publications, a
   Priority floor, two ReceiveOnly responders, four route-only acceptances, two
   distinct expiry points, one explicit stopped-store pressure retirement, a
   persisted four-to-two item quota replacement, and Flash-before-Immediate
   delivery in one same-implementation container. State/Record/Blob custody,
   cross-class lowest-priority eviction, non-Linux finite TTL, physical RF
   silence, older-version deterministic partials, constrained physical links,
   scale, mixed implementations, and release acceptance remain open.
4. **Protected operational provisioning and generalized control
   administration — bounded live/stopped Rust mechanisms implemented;
   operational composition open.** Caller-provided `NodeConfig` and stopped
   `SelectedEventNode`/`SelectedControlAdmin` accept a bounded authenticated
   protected artifact or exact operation-bound opaque SecretStore reference.
   The running actor's `SelectedControlHandle` and stopped admin publish bounded
   revocation/rekey controls with sanitized errors and exact retry. No production
   SecretStore/protection backend, protected stock CLI or binding,
   cross-process admin IPC, registry/credential issuance and recovery,
   automatic/atomic revoke-plus-rekey workflow, coordinated provider destroy,
   or physical-erasure assurance is delivered.
5. **Selected IP, namespace-NAT operation, and one controlled-relay mechanism —
   boundedly observed, not accepted complete; physical IP/relay deployment,
   representative NAT, BTLE, mixed implementation, at-least-100-node scale,
   and resources remain open.** The bounded carrier and selected CLI support
   direct IP plus exactly one opt-in relay with explicit TLS trust and no public
   fallback. The retained two-cell receipt observes selected Event operation
   through cone/direct and restrictive/controlled-relay Linux namespace NATs on
   one physical host. It is not physical or representative NAT acceptance and
   makes no direct-first chronology claim. The separate one-host direct-loopback
   N=32 Event receipt moves only `DM-9-21A`; it does not satisfy the
   at-least-100-node or resource brackets.
6. **Targets, licenses, cryptographic module, independent review, SBOM, and
   signed release — open external/release gates.** No production authorization
   follows from the implementation slices.

The dependency-aware implementation priorities and exit criteria are maintained
in the [capability roadmap](capability-roadmap.md). Before broader multi-hop,
long-retention, public-binding, or supported-profile claims, that roadmap now
gates the relevant work on causal/lifecycle design and runs executable
conformance, operational security, and physical carrier risk as parallel
foundational tracks. The inventory above remains the evidence authority for its
stated gaps; completing one code slice or crossing a planning gate does not
silently satisfy them.

### Current static selected Event hierarchy mechanism

Semantic v6 adds a typed selected Event bridge lane without changing the stable
replication wire or the ordinary v5 lane encodings. After mission and control
authorization, both peers declare whether the static bridge role is enabled.
The initiator sends then receives one bounded direction; the responder receives
then sends. Each direction offers at most eight exact wrapper/source pairs and
finishes with a bounded remaining count. Strict frame decoding caps one wrapper
at 524,322 bytes and one source envelope at 1 MiB. A process-local cursor rotates
later eligible routes for at most 256 authenticated peers; restart may repeat a
first batch, while exact durable identity keeps replay idempotent.

Outbound selection checks every target scope and epoch against the current
authenticated peer's mission route-grant commitments before materializing an
offer. The receiver freshly verifies the complete configured authorization
chain, exact source and wrapper, edge continuity, loop rules, source topic and
priority, current static policy, and target authority before commit. Duplicate,
promoted, stored-inactive, and not-selected are durable receiver-local outcomes;
authentication or policy failure remains fatal. Route-only bridge roles never
open payload plaintext. A separately content-authorized target may open the
source and returns only safe identity metadata, payload length, and payload
SHA-256. Reopen makes persisted routes live only after fresh provider
verification and authorization-high-water promotion.

The opt-in hierarchy controller composes five long-running processes across
three isolated Docker IP segments with no configured peer identities or
addresses. Two multi-homed route-only nodes bridge alpha to parent to bravo;
the other roles are a publisher, a content-authorized consumer, and one
foreign-authority outsider. The controller is bounded and always cleans up its
project resources. Its result is same-host current-tree development evidence,
not a retained execution root. Static unprotected-reference provisioning,
linear complete-chain verification, process-local cursor reset, dynamic
join/leave and policy lifecycle, quotas, physical operation, hostile discovery,
cross-class custody, and bridged-scale/resource acceptance remain open.

### Current live selected Blob mechanism

The current selected node exposes `RunningNode::selected_blobs()` as a cloneable
`SelectedBlobHandle` on the same bounded actor-owned application lane as Event,
State, and Record. It exposes publication, bounded page reads, and durable
metadata-only delivery for exact source-authenticated Blob publications. The
signed-source v2 retained receipt below observes one bounded interrupted/reopen/
different-peer resume use of publication and page reads and moves `DM-5.1-10`
through `DM-5.1-13`, `DM-5.2-19` through `DM-5.2-22`, and `DM-7-16`; it predates
the delivery queue. The separate signed-source Blob-subscription receipt below
now bounds peerless exact-publication delivery, forced receiver-process
replacement, same-tenure token rotation/acknowledgement, shared-content
publication separation, and final reopen. Neither receipt relabels the earlier
source freezes or the separate unretained cleanup/race automation.

The live publisher accepts an already-open regular file only at cursor zero,
and runs admitted file work on one joined capacity-one worker. Before
preparation or durable mutation, the worker rejects an empty, non-regular, or
over-64-MiB input. It rechecks metadata and length
across bounded preparation/encryption passes, enforces the selected 1,024-chunk
ceiling and depot quotas, source-seals only exact completed content, and commits
through the existing operation-key-idempotent store authority. Pre-enqueue
cancellation cannot publish; post-enqueue cancellation is explicitly
indeterminate and exact retry recovers the durable result. Failed or changed
sources may retain bounded quota-charged nonpublic staging; no staging GC is
claimed.

`read_page` exact-loads the current application projection, checks its
startup-authenticated route/content/depot capability, streams only the requested
authenticated range, and performs a final policy/lifecycle check before
disclosing a nonempty page of at most 64 KiB, spanning at most two canonical
chunks. Plaintext is
held in a zeroize-on-drop value; caller copies become caller custody. Rekey,
revocation, shutdown, and terminal zeroization close new disclosure, while
durable exact retry remains subject to current authorization. Coherence failures
that contradict authenticated cache/store/depot claims terminate the actor;
ordinary absence, capacity, and unsettled-policy outcomes stay sanitized.

The Blob delivery queue uses the exact source semantic publication identity,
not `BlobId`, because distinct publishers, counters, or priorities may sign
separate publications of the same immutable content identity. A durable local
selector covers one topic/scope and optional descendants but cannot add or
change configured semantic-v5 network interests or route/content authority.
Poll fails closed unless its bound covers the complete matching retained set,
then freshly verifies every exact source envelope, current policy, epoch,
revocation, route/content lineage, and completed depot before atomically
committing attempts. Delivery exposes authenticated identity metadata only;
plaintext remains on the existing read surface. Opaque tokens bind the
subscription incarnation, publication, tenure, and issued attempt. Exact
ack/re-ack is idempotent, and an earlier nonzero attempt at or below the durable
high-water remains valid while the same pending tenure is active. Wrong-tenure,
wrong-incarnation, malformed, future/unissued, removed/recreated, or
cross-bound tokens fail closed. `delivery_status` reports audited selector/pending/ack/cursor
counts only; it is not peer, contact, transfer-progress, sync, or convergence
status.

Focused current-code tests cover command queue and oversize admission, two-pass source
change, exact retry/conflict and shared-variant deduplication, page bounds and
cancellation, tamper/reopen, lineage replacement and epoch advance, rekey during
page disclosure, terminal closure, peerless live publication followed by
direct-Iroh transfer and receiver read, and peerless receiver restart read. The
delivery tests separately cover exact publication identity, shared-BlobId
publications, retry/token rotation, ack/re-ack, cross-binding rejection,
selector removal/recreation, predecessor migration, bounds, policy withholding,
and reopen. The semantic-v5 cleanup/race cases remain separate same-process automation. The
retained v2 receipt advances the nine IDs named above and broadens evidence
without status movement for `DM-5.3-04`, `DM-7-11`, `DM-7-14`, `DM-7-15`,
`DM-7-17`, `DM-7-18`, `DM-7-20`, `DM-9-13`, and `DM-9-14`.
The later Blob-subscription receipt moves exactly `DM-5.3-04` and strengthens
only the peerless exact-publication delivery boundary described in its retained
section; it makes no selector-withholding, network-interest-separation,
network, peer-status, plaintext/read, TTL/GC, resource, or release claim.

The shipped Blob quickstart contains publication/page-read and delivery guides;
the compiled
`live_blob_acceptance` and `live_blob_subscription_acceptance` producers are
retained acceptance harnesses, not minimal developer samples. Blob-specific
sync/peer status, selected-node language binding, and local-agent method remain
absent.
Route-only relay/custody, TTL/expiry/GC,
metadata-independent pure-byte identity,
100-plus-MiB and process-RSS evidence, complete physical allocation accounting,
physical systems/carriers, mixed implementations, long-duration/power-loss
acceptance, arbitrary-peer or route-only resume, long-offline recovery, and
release authorization remain open.

### First selected Event API stack

The historical Event API work was deliberately split so the selected store
keeps one authority and each claim can be tested independently:

1. **PR A — foundation:** `SelectedEventNode` publishes arbitrary
   policy-authorized Events idempotently and performs bounded acceptance-marker
   queries. The selected redb store maintains and audits the durable
   acceptance-marker inverse index used by those queries. The compiled
   [quickstart](../quickstart/selected-event-api.md) exercises the public
   application projection without exposing sealed bytes, keys, inventory, or
   carrier/reconciliation mechanics.
2. **PR B — durable delivery and receive intent:** idempotent
   durable Consume subscriptions drive stopped-state poll/ack; Carry selectors
   support receive/forward without local application delivery. Poll plans are
   bounded, source/content authorization is freshly re-verified, attempts are
   committed before return, semantic-ID acknowledgement is idempotent, and
   restart/conflict/gap/zero-match/inactive-pending/stale-plan tests preserve
   the cursor and pending-ledger invariants. The canonical union of active
   Consume and Carry selectors is exchanged inside the mission-protected
   session and intersects both directional inventory and Offer/Fetch with
   current route authority. Empty selectors mean receive-none. A negative
   runtime test transfers subscribed `beta`, withholds authorized but
   unsubscribed `alpha`, and transfers nothing to a receiver with no selectors.
3. **PR C — live application handle (current code):** the cloneable
   `SelectedEventHandle` sends bounded commands to the running actor's sole
   authority and exposes publish/query/subscribe/poll/ack, unsubscribe, gaps,
   and status. Selector insertion/removal serialize against contact policy;
   shutdown and zeroization close command admission. A focused process test
   publishes with no peer, restarts into later synchronization, polls and
   acknowledges at the receiver, and verifies the acknowledgement after
   receiver restart.

PR C completes this Event-only code surface, not the generalized multi-class
MVP. `LastContactComplete` is only the most recent bounded authenticated
negotiation with active configured peers. A gap-free page is anchored only by
freshly verified positions already observed by the local store. Subscription
replacement is unsubscribe followed by subscribe, not an atomic update.
At the PR-C boundary, finite TTL was still open; the later selected Event
custody slice now adds it on Linux together with semantic-v3-format age,
priority, quota, and constrained emission inherited by v4. State/Record/Blob
custody (distinct from v4 mutable reconciliation), selected-node
bindings/local-agent integration, operational/live provisioning and broader
control policy administration, physical and mixed-implementation acceptance,
N=32/resource brackets, and dependency/cryptographic/review/SBOM/signed-release
gates all remained open. The later local State, Record, and Blob slices change
only their explicitly mapped rows. Stakeholder-owned supported targets and
resource values remain
external decisions rather than values inferred by this implementation.

### First selected State API slice

The later State stack began without changing the Event wire:

1. **Typed source capabilities:** `aster-core::source_state` constrains the
   existing source-envelope provider to State and distinguishes route-verified
   metadata from content-verified semantic acceptance. Exact payload, class,
   publisher, topic, scope, priority, causal stamp, logical key, tombstone,
   content length, key epoch, and durable no-TTL decisions are verified.
2. **Bounded transactional projection:** `aster-redb-store` adds disjoint State
   semantic/exact/operation/projection tables while sharing the authenticated
   publisher-dot and causal-frontier authority with Event. It rejects
   cross-class namespace and dot reuse, retains bounded exact-key history,
   marks dominated versions `Superseded`, preserves all active causal maxima,
   and selects the greatest complete semantic ID as current. The dedicated
   operation ledger is capped at 4,096 rows and 512 KiB and participates in the
   aggregate store limits.
3. **Stopped high-level facade:** `SelectedStateNode` owns the exclusive stopped
   writer, publishes by durable application operation key, and queries one exact
   topic/scope/logical key. It freshly verifies every active and inactive plan
   candidate, independently recomputes the reducer, and race-rechecks the exact
   policy-bound plan. Only active versions are exposed; an authenticated current
   tombstone remains visible, and optional active concurrent/superseded versions
   remain recoverable.

This source/store/facade composition provided the first stopped-slice
current-code evidence, not a retained acceptance artifact. At that historical
slice State had no live handle, subscription, inventory, Fetch/Offer frame,
relay cache, or reconciliation identity. The later v4 runtime adds protected
reconciliation without relabelling this evidence. Old-epoch exact operation
replay still requires current authorization;
future-epoch State is rejected. No TTL, expiry, garbage collection, delete-wins,
State convergence across nodes, independent interoperability, or physical
acceptance was claimed by that slice. Live application State/Record operations
were open at that freeze; the later live mutable slice supersedes that current
absence without relabelling the historical evidence. The first Blob slice
described later was stopped/local, and subsequent semantic-v5 and current live
Blob sections separately record newer mechanisms.

### First selected Record API slice

The next local slice adds Record without changing the Event wire:

1. **Typed source capabilities:** `aster-core::source_record` constrains the
   existing source-envelope provider to Record and distinguishes route-verified
   metadata from content-verified semantic acceptance. Exact payload, class,
   publisher, topic, scope, priority, causal stamp, logical key, tombstone,
   content length, key epoch, and durable no-TTL decisions are verified.
2. **Bounded transactional conflict projection:** `aster-redb-store` adds
   disjoint Record semantic/exact/operation/projection tables while sharing the
   authenticated publisher-dot and causal-frontier authority with Event and
   State. It preserves every active causal maximum, marks one stable complete-
   semantic-ID head `Current`, annotates the others `Concurrent`, retains
   dominated versions as `Superseded`, and has no delete-wins rule. Ordinary
   operation-bound publication cannot collapse a context that observes multiple
   heads. Explicit resolution requires at least two exact guarded heads, binds
   that sorted set into the operation digest, requires a successor observing all
   of them, and rejects a stale plan without mutation.
3. **Stopped high-level facade:** `SelectedRecordNode` owns the exclusive
   stopped writer, publishes by durable application operation key, queries one
   exact topic/scope/logical key, and returns an opaque resolution guard with an
   explicit conflict. It freshly verifies every active and inactive candidate,
   independently recomputes all dispositions and the sorted head set, and race-
   rechecks the policy-bound plan. An application computes reviewed output in
   its own code and submits the exact guard through `resolve`; no application
   merge policy runs during ingest.

The durable operation and guard rules distinguish idempotent retry from silent
conflict loss. A changed payload or head set under the same operation key fails
closed. An exact successful resolution retry returns its original immutable
revision after restart and after an authorized rekey, while a new operation
cannot reuse an old-policy guard. A current tombstone remains visible; a
concurrent tombstone and edit retain both heads in either semantic-ID order.

This source/store/facade composition provided the first stopped-slice
current-code evidence, not a retained acceptance artifact. At that historical
slice Record had no live handle, subscription, inventory, Fetch/Offer frame,
relay cache, or reconciliation identity; publishers and N-way heads were
exercised only through privileged local ingestion. The later v4 runtime adds
protected reconciliation without relabelling this evidence. No automatic
registered-policy merge, finite TTL, expiry, explicit-policy garbage
collection, independent interoperability, physical acceptance, or release
credit is claimed. The first Blob slice described next was stopped/local; the
subsequent semantic-v5 and current live Blob sections separately record newer
mechanisms without relabelling this historical evidence.

### First selected Blob API slice

The final local data-class slice adds Blob without changing the Event wire:

1. **Typed source and manifest capabilities:** `aster-core::source_blob`
   constrains the existing source-envelope provider to a nonempty fixed-64-KiB
   Blob profile. The capability binds exact sealed bytes, canonical manifest,
   Blob ID, content group, epoch, route commitment, chunk records, media/schema
   identity metadata, and plaintext. A private keyless completion verifier
   requires every authenticated expected and committed store record plus the
   finalized manifest digest; raw mechanical store finalization is not
   publication authority.
2. **Bounded transactional publication and encrypted depot:**
   `aster-redb-store` adds disjoint Blob exact/semantic/publication/operation
   tables and structural read plans while sharing the authenticated publisher
   dot and causal frontier with Event, State, and Record. Ciphertext files live
   in a private sibling depot. File write/sync/rename/directory-sync precedes an
   exact redb marker; unmarked remnants may be reclaimed, while a marked
   missing or different file fails integrity. Dedicated byte/chunk-row/variant
   limits and operation limits participate in fail-closed reopen, collision,
   mission, quota, and terminal audits.
3. **Stopped streaming facade:** `SelectedBlobNode` owns the exclusive stopped
   writer, makes bounded preparation and encryption passes over a seekable
   source, commits one signed publication only after exact depot completion,
   and synchronously streams freshly verified chunks into caller-owned output.
   It verifies every retained active or inactive publication, independently
   selects the greatest active semantic publication ID, rechecks the exact
   store plan, and mints completion only for the winner.

`BlobId` commits exact plaintext bytes, the canonical chunk profile, and
media/schema identity metadata; it is not a separate metadata-independent
whole-byte content ID. Exact operation retry rehashes the source, passes current
authorization, and freshly verifies the original publication and historical
variant. A new operation may sign another publication over the same completed
variant; a rekey creates an epoch-specific encrypted variant.

The database is pinned to one fixed depot owner from its first successful Store
open, not treated as a relocatable backup. Redb persists a domain-separated
commitment over a random owner token, canonical store path, and, on Unix, the
exact device/inode; the sibling depot marker must carry the same binding before
any chunk/variant scan or reclaim. The first database to initialize a parent’s
depot wins, and another cannot adopt it. Moving/copying even an empty bound
database to another path fails on reopen. On Unix, a new inode also fails,
moving the depot with the database does not preserve the binding, and a
same-path replacement cannot adopt an existing depot. This slice provides no
supported rebind/restore migration. Non-Unix keeps token-plus-canonical-path
binding but cannot distinguish a copied database restored over that same path,
so equivalent inode/rollback resistance is not claimed.
Owner-token or owner-binding migration is all-or-none and admits missing fields
only for canonical empty Blob rows/counters with no fixed depot root; partial
fields, any logical Blob state, or any fixed depot root fail without repair.

At this historical stopped/local freeze, the source/store/facade composition
provided current-code automated evidence, not a retained acceptance artifact.
It had no Blob inventory, carrier object, remote chunk transfer, any-peer
resume, or network reconciliation; the later semantic-v5 slice below supersedes
those network absences, and the current live Blob section above supersedes the
historical absence of a live handle. The current live section above supersedes
the historical delivery-subscription absence; Blob peer/convergence status
remains absent.
Durable chunk rows/import variants, including retained unpublished staging,
continue to consume their admission caps pending explicit GC. The byte cap
reserves canonical ciphertext-file bytes for every durable expected chunk
record; it does not measure redb allocation, directory blocks, hostile unrelated
entries, snapshots, backups, swap, or complete physical usage. No pure-byte
dedup, maximum-size or hundreds-of-MiB acceptance, physical sanitization,
independent interoperability, or release credit is claimed.

### Semantic-v5 selected Blob network slice

The current selected offer is `[6, 5, 4, 3, 2, 1]`. The semantic-v5 slice
inherits Event v1-v4 and State/Record v4 behavior and adds Blob class `3`
source lanes plus one carrier range lane. Semantic v6 inherits those ordinary
lanes unchanged and adds only the opt-in Event-bridge mechanics lane. V1-v4
emit and accept zero Blob frames. Stable wire/ABI version 1, session framing,
`ASTRENV2`/`ASTRENV3`, manifests, `ASTRBT01`, typed ObjectIDs, and cryptographic
suite remain unchanged.

The v5 slice is direct between content-capable peers. Each exact
topic/scope/epoch interest carries an opaque 32-byte provider proof bound to
mission authority, authenticated claimant NodeID, and the current content
grant. Inventory, source, and every range send recheck that proof, current route
authority, durable nonrevocation, source route lineage, and physical content
lineage. Route-only authority is insufficient.

The fully authenticated source and exact manifest plan is staged atomically
before any carrier range. Redb stores one contiguous prefix under the exact
source transfer ID plus strict kind-2 carrier ID. A prefix extension is at most
16 KiB and is not owned by the peer or session, so another eligible content
peer can continue the exact complement after runtime/store/provider-cache
teardown and reopen. Peer cursor state affects bounded fair selection only. The
requester's Finish remaining count is echoed for sequencing; each exact
Result/Ack tuple binds accepted durable-prefix progress and is not an
independent responder attestation of requester disk truth.

Network admission is capped at 64 MiB plaintext and 1,024 64-KiB chunks. The
source envelope remains capped at 1 MiB, one carrier at 128 KiB, pending source/
manifest/prefix metadata at 10,000 rows, pending prefix bytes at 64 MiB, and
configured cursor peers at 256. Capacity deferral preserves accepted and
existing pending state. Conflicting prefixes, stale policy/lineage, wrong
identity or proof, and integrity failure do not become absence or success.

Pending state is absent from ordinary Blob publication inventory, query, read,
and service. Atomic promotion requires the exact pending plan, every verified
canonical carrier, matching `BlobDepotCompletion`, a freshly streamed
`VerifiedBlobContentCompletion`, and a fresh `CurrentBlobLineage`. The content
proof decrypts/authenticates every exact chunk, checks each plaintext digest,
and verifies the whole BlobID. A merely staged, partial, or carrier-complete
object remains nonpublic.

Same-epoch replacement invalidates peer proofs and current-lineage checks and
withholds old rows. Redb deliberately rejects another physical lineage for the
same `(BlobID, content group, numeric epoch)` with
`PhysicalLineageConflict`; republishing or resuming that Blob requires advancing
the numeric epoch. Normal and AtLeast run the v5 lane because AtLeast is
Event-only. ReceiveOnly advertises, requests, stages, promotes, and counts zero
Blob work.

The focused provider/frame/redb tests are current-code same-implementation
automation. The final runtime gate is one small bounded three-node direct-Iroh
case in which the first source leaves a durable prefix, all receiver runtime/
store/provider-cache ownership tears down, and a different completed eligible
content peer continues the exact complement after reopen to proof-gated
visibility. It creates no retained execution root and does not relabel any
historical Event/control receipt. At that network freeze, live Blob application
access and subscription were absent; the current live mechanism above
supersedes only the access absence. Blob subscription and class-specific status,
selected route-only Blob relay/custody, TTL/expiry/GC, pure whole-byte identity
or metadata-independent deduplication, 100+ MiB/RSS and resource acceptance,
physical carriers, mixed implementations, and release authorization remain
open.

### Protected provisioning and live or stopped control administration slice

This slice composes the existing protected-artifact boundary with selected
live/stopped Rust entry points and makes persistent custody a typed provider
seam:

1. **Provider-neutral secret custody contract:** `aster-core::provisioning`
   exposes a versioned, bounded, redacted `ProvisioningSecretRef`, separate
   caller-chosen install/load/destroy operation identities, sanitized failures,
   and checked install/load/destroy helpers. Plaintext construction rejects
   empty or oversized input, and checked install rejects a zeroized value
   before backend invocation. Install validates the exact operation; load and
   destroy validate the exact operation and caller-supplied opaque reference.
   Loaded plaintext
   remains an Aster-owned zeroizing in-process value. A destroy receipt records
   only the trusted backend's durable-tombstone assertion; `NotFound` is
   indeterminate, and neither result proves physical erasure.
2. **Protected live and stopped opens:** caller-provided `NodeConfig` plus
   stopped `SelectedEventNode` and `SelectedControlAdmin` can authenticate one
   bounded protected file or byte slice through a caller-owned
   `ProvisioningUnprotector`, or load one exact operation-bound opaque reference
   through a caller-owned `ProvisioningSecretLoader`. Live construction first
   validates the complete private `NodeConfigOptions` value and durable terminal
   state. Passing preflight invokes the provider/loader exactly once without
   creating state; failure never falls back to plaintext parsing. The stock CLI
   and bindings remain on explicitly named unprotected compatibility paths.
3. **Typed live and stopped administration:** stopped `SelectedControlAdmin`
   and the running actor's cloneable `SelectedControlHandle` publish a
   nonzero-generation `RevocationRequest` or `ScopeRekeyRequest`. Rekey input is
   rejected before provider/RNG/store work unless it carries a nonempty signed
   registry of at most 16 MiB, an independently retained nonzero registry
   generation floor, 1–128 unique recipients, and at most 256 aggregate topic
   grants. Registry credentials and canonical recipients authenticate before
   key generation. Publication either durably commits and activates the exact
   local control or returns an exact same-signer historical receipt; a remote or
   different signer cannot be relabeled as local recovery.
4. **Bounded live lifecycle:** the process-local control queue has capacity one,
   takes the actor's policy write lease, and yields after at most four commands.
   A successful publication refreshes live policy before response. An
   authenticated pending gap is deferred rather than actor-fatal: fresh work
   returns `PolicyUnsettled`, while exact historical retry remains recoverable.
   Cancellation after enqueue does not cancel actor-owned work and the command
   may still commit, so callers must retain and exactly retry requests. A lost
   self-revocation response is recovered through stopped admin after actor
   teardown; no cross-process live-admin IPC exists.
5. **Fail-closed post-revocation chain:** a fresh recipient-package rekey
   rejects a recipient already revoked when the request is evaluated. An exact
   same-signer historical duplicate can still recover its original durable
   receipt after a recipient is later revoked. A legacy recipient-less scope
   control may remain authenticated historical state if it predates revocation,
   but it is rejected after revocation. Authenticated predecessor/rollback poison
   purges its descendant suffix and leaves a durable rejected-sequence fence so
   replayed descendants cannot activate until a valid alternate fills the
   fenced sequence.

Relative state and file-artifact paths are resolved against one captured
absolute current directory before any caller provider/loader can change the
process current directory. Protected live config retains that exact absolute
lexical state pathname and rejects later public-field mutation before state
creation. It does not bind an inode, parent directory, symlink resolution,
rename history, database replacement, or rollback state. Protected file reads
have the documented no-follow Unix checks; equivalent non-Unix path-swap
assurance, parent-directory symlink or rename resistance across every boundary,
rollback-resistant persistent identity, and a supported restore/rebind
procedure remain open.

The slice remains Rust-only. The stock `aster node`, `control-revoke`, and
`control-rekey` paths still ingest an owner-only unprotected-reference bundle,
and C/Go/Python expose no selected protected path or live control handle. No
production SecretStore or protection backend is selected; the in-memory fixture
proves only the API model, not backend authentication, durability, hardware
custody, backup/recovery, or media sanitization. `READY` and `STOP` expose only
the non-identifying `provider-protected-artifact` or
`provider-secret-reference` origin. Both origins support graceful shutdown, but
live local zeroization cannot destroy provider custody. Revocation and rekey are
separate administrator transactions. There is no automatic affected-scope
discovery, durable rekey-required fence, atomic revoke-plus-rekey operation, or
coordination of live drain, store terminalization, and provider destroy.

No row below means that an entire source requirement passes. Credit is limited
to the production-lane mechanism and evidence boundary named in the final
column.

| Requirement | Current state | Production-lane implementation | Credit and remaining gap |
|---|---|---|---|
| `DM-1-03`, `DM-1-04`, `DM-1-05` peer flow, temporal relay, and resynchronization | `observed-bounded` | `aster-node` + typed Event/State/Record/Blob sources + redb + Negentropy + Iroh | Earlier retained Event flows committed Ping/Pong peerless and exact-forwarded through isolated edges. The live mutable v2 receipt separately published State and Record with zero peerless contacts, later reconciled seven exact mutable items, and reproduced the tombstone-current State plus resolved Record projections after peerless restart. The retained live Blob run separately published one two-chunk object peerless, retained interrupted progress across graceful receiver reopen, continued from a different eligible peer, and reproduced authenticated pages after final reopen. Physical systems, longer custody, process/crash recovery, arbitrary-peer or route-only Blob relay/resume, generalized policy, mixed implementations, and scale remain open. |
| `DM-2-14` adopting-program key policy | `implemented-uncredited` | Existing control formats plus typed bounded live `SelectedControlHandle` and stopped `SelectedControlAdmin`, exact recipient-filtered planning, and atomic redb publication intent | Rust callers can choose one revocation or one scope/epoch and exact recipient/topic policy through sanitized requests; live publication serializes under the actor policy-write authority and refreshes policy before response. This is not generalized policy governance: no production backend, protected stock CLI/bindings, cross-process admin IPC, registry issuance/recovery, automatic/atomic revoke-plus-rekey workflow, or additional key-management mechanism is shipped. |
| `DM-3-11`, `DM-11-18`, `DM-11-19` pre-mission provisioning/identity/keying | `open` | Protected-artifact and opaque-reference live `NodeConfig` plus stopped Rust opens and provider-neutral SecretStore contracts | Current Rust construction validates bounded options and terminal state before one provider/loader call or state creation and binds credentials to one absolute lexical state pathname. This mechanism is not the operational window or complete MVP: the stock CLI remains unprotected-reference, and identity/key issuance, production backend, recovery/backup/rollback policy, inode/symlink/rename/rollback binding, selected-node bindings, coordinated destruction, admitted-module/FIPS decision, and retained operational evidence remain absent. |
| `DM-5.1-01`, `DM-5.1-02` State class and convergence | `observed-bounded` | Typed source-authenticated State capabilities, bounded redb versions/operations, shared Event-State causal frontier, stopped `SelectedStateNode`, actor-owned `SelectedStateHandle`, a durable at-least-once positive-current-version queue, and semantic-v4/v5 class/direction runtime reconciliation | The retained mutable v2 run remains primary for peerless publication, exact retry, explicit-interest direct reconciliation, deterministic two-maximum projection, a causal successor, a later current tombstone, handle closure, and immediate peerless restart projection; it observes `DM-5.1-02`. The later State-subscription receipt moves `DM-5.1-01` by adding one retained durable application-delivery sequence across concurrency, successor supersession, forced receiver-process termination, redelivery, acknowledgement, explicit current tombstone, and reopen. This is positive-current-version delivery only: it is not a materialized projection or transition feed, emits no synthetic Current-to-None withdrawal, and does not dynamically mutate configured `NodeConfig` network interests. Longer partitions, relay custody, independent interoperability, scale, physical systems, and bindings remain open. |
| `DM-5.1-04` Event support | `observed-bounded` | Existing `aster-core` Event envelope ported through selected redb/runtime, with live and stopped high-level projections | The retained sample seals, persists, reconciles, verifies, and reacts to Event. Current-code live-handle tests publish, query, consume, and later synchronize arbitrary authorized Events, but they are not a retained PR-C acceptance receipt. Other data classes and independent wire interoperability remain open. |
| `DM-5.1-05` through `DM-5.1-07` Event immutability, order, and gaps | `observed-bounded` | Authenticated Event sequence/dot, semantic and exact-transfer indexes, publisher/topic/scope positions, durable live query, and a public bounded verified gap view | The retained live run committed four Events peerless, returned the original on exact retry, rejected changed-intent reuse without mutation, retained alpha publisher positions one through three across forced receiver-process restart, exposed the exact authenticated half-open gap `[2,3)` while routine sequence two was withheld, and closed through three after normal-policy transfer and final peerless reopen. Gap absence remains local verified-position evidence, not publisher completeness or global convergence. Independent interoperability, longer streams/partitions, physical systems, scale, and release acceptance remain open. |
| `DM-5.1-08`, `DM-5.1-09` Record class and disconnected concurrency mechanism | `observed-bounded` | Typed source-authenticated Record capabilities, bounded redb revisions/operations, shared causal frontier, stopped `SelectedRecordNode`, actor-owned `SelectedRecordHandle`, durable whole-key active-head subscribe/poll/acknowledge/unsubscribe, and semantic-v4/v5 class/direction runtime reconciliation | The earlier mutable run created revisions on peerless stores, reconciled both inventories, exposed the same annotated two-head conflict, guarded resolution, and reproduced history after restart. The later Record-subscription receipt moves only `DM-5.1-08`: it delivers a complete edit/tombstone conflict at limit one, preserves its projection across forced SIGKILL and fresh-process replay, requires a fresh exact guard for resolution, delivers the successor under a new projection, and retains query-only superseded history through final peerless reopen. Longer partitions, relays, mixed implementations, scale, bindings, physical systems, automatic merge, TTL/GC, and release acceptance remain open. |
| `DM-5.1-10`, `DM-5.1-11` Blob class, streaming, and immutability | `observed-bounded` | Typed source-authenticated Blob capabilities, canonical fixed-64-KiB manifest, bounded encrypted depot, immutable exact publication, stopped `SelectedBlobNode` streaming, cloneable actor-owned `SelectedBlobHandle` publication and zeroize-on-drop paged reads, durable metadata-only exact-publication delivery, and a semantic-v5 direct source-before-carrier network path | The retained transfer run published and read one 96-KiB two-chunk Blob, then seeded, resumed, and reopened it. The later peerless delivery receipt retains two exact publications sharing one immutable `BlobId`, finalized depot variant, and committed chunk while remaining independent delivery identities across forced receiver-process replacement and final reopen. Peer/convergence status, route-only custody, TTL/GC, pure-byte identity/dedup, physical/resource and large-Blob/RSS acceptance, mixed implementation, and release authorization remain open. |
| `DM-5.1-12`, `DM-5.1-13`, `DM-5.2-19` through `DM-5.2-22` Blob chunk transfer and peer-neutral resume | `observed-bounded` | Semantic-v5 exact source-before-carrier transfer among directly authenticated content-capable peers; peer-bound content proof on inventory and every range; peer-neutral durable 16-KiB prefixes; exact missing-complement scheduling; atomic completion-gated visibility; live bounded-page access after promotion | Across v1 and v2 all six rows in this group are `observed-bounded`; v1 had already moved `DM-5.1-12`, and v2 newly moves the other five. The v2 receiver retains a non-public 16,384-byte prefix across graceful reopen, continues by exactly 16,384 bytes from a different eligible peer without refetching the source, then receives 65,870 bytes to reconstruct exactly the seeded 98,638 carrier bytes before promotion. Each of the three participants retains exactly two committed ciphertext chunks. The later peerless delivery receipt does not broaden this network-transfer result. Cleanup and race cases remain current-code automation. Peer/convergence status, process-crash or power-loss and long-offline recovery, arbitrary-peer or route-only resume/custody, TTL/GC, 100+ MiB/RSS/physical/mixed acceptance, and release authorization remain open. |
| `DM-5.1-17` through `DM-5.1-22` common item fields | `implemented-uncredited` / `observed-bounded` | Event, State, Record, and Blob authenticate their applicable class, topic, scope, priority, publisher, causal stamp, logical key, tombstone, epoch, and content commitments; Event adds finite TTL and all four classes now have actor-owned live Rust handles | The exact row statuses remain field-specific. Semantic-v3/v4/v5 Event contacts use authenticated priority, source TTL, and cumulative age. Retained live mutable, transfer-Blob, and Blob-delivery receipts exercise authenticated publisher identity through actor-owned handles; the delivery receipt exposes freshly verified applicable identity metadata without plaintext. Blob peer/convergence status, State/Record/Blob finite TTL and custody, cross-class eviction, physical/mixed acceptance, and release remain open. |
| `DM-5.2-01` eventual convergence | `observed-bounded` | Class-specific Negentropy difference over exact Event transfer IDs in v1-v5, State/Record transfer IDs in v4/v5, and Blob source IDs in v5, plus mission-bound redb | Retained Event receipts cover temporal forwarding; the live mutable receipt covers bounded two-peer direct reconciliation, and the live Blob v2 receipt covers a bounded three-peer direct seed/interruption/reopen/different-peer continuation plus final peerless reopen. These are not all-reachable-node or long-partition results. Route-only Blob custody, arbitrary-peer resume, mixed implementations, physical links, requirement scale, and release acceptance remain open. |
| `DM-5.2-02` subscribed in-scope convergence | `observed-bounded` | Durable canonical Event Consume/Carry selectors; durable State positive-current-version, Record whole-key, and Blob exact-publication application selectors; v4/v5 class-separated configured State/Record network interests; and v5 exact Blob network selectors carrying a peer-bound current content proof, all intersected with current mission authority | Retained State and Record receipts keep application subscriptions durable across forced process replacement and final reopen while proving those selectors do not mutate configured `NodeConfig` network interests. The peerless Blob receipt retains its exact subscription and deliveries across process replacement, but does not observe selector withholding or network-interest separation; current-code tests preserve that separation and cannot expand route/content or network authority. A local application selector alone does not prove replication. The bounded observations are not all-reachable-node or global convergence; repeated multi-scope lifecycle, longer partitions, route-only Blob relay, physical peers, scale, mixed implementations, and a retained four-class networked receipt remain open. |
| `DM-5.2-06` through `DM-5.2-08` delivery, duplicate suppression, and idempotent outcome | `observed-bounded` | Exact transfer acceptance, durable operation-keyed publication, at-least-once Event/State/Record/Blob pending ledgers, freshly verified live poll, durable attempt numbers, projection/publication tenures, and idempotent acknowledgement/reacknowledgement | Retained Event and State runs cover forced-process replay and exact acknowledgement. The Record receipt adds one complete two-head projection across forced process replacement. The peerless Blob receipt independently keys two publications sharing one `BlobId`, retains one flushed unacknowledged attempt across forced process replacement, rotates the attempt token, and acknowledges/reacknowledges both publications; acknowledgement idempotence does not prove arbitrary application-side effects are transactional. These are controlled mechanisms and post-poll process boundaries, not every crash/power-loss point, cycle/broadcast evidence, bindings, independent interoperability, physical systems, scale, or release acceptance. |
| `DM-5.2-09`, `DM-5.2-10`, `DM-5.2-13`, `DM-5.2-14` causality and clock-independent correctness | `observed-bounded` / `implemented-uncredited` | Authenticated dots/context, atomic Event-State-Record-Blob causal frontier/high-water, Pong observation of Ping, causal projections and whole-head-set Record delivery identity, class-specific Negentropy timestamp zero, and monotonic semantic-v3-format Event custody age inherited by v4/v5 | Earlier retained evidence binds causal State/Record schedules. The Record-subscription receipt additionally preserves one complete sorted edit/tombstone active-head set and projection across attempts, then requires a fresh query guard and emits the causally observing successor under a new projection. Causal ordering is producer-attested and exact identities, counters, observed sets, projections, and dispositions are checker-bound; public receipt fields do not expose full causal vectors. Blob causal convergence, finite State/Record/Blob TTL, non-Linux Event TTL, long-running operation, and independent interoperability remain open. |
| `DM-5.2-15` deletion propagation as tombstones | `observed-bounded` | Authenticated State and Record tombstones use ordinary signed causal context, immutable transfer, retained reducer history, and semantic-v4/v5 direct reconciliation; State adds positive-current-version delivery and Record adds whole-key active-head delivery | State receipts remain primary for this row. The Record receipt adds bounded evidence that a peerless Current tombstone is delivered, later retained as one head in a complete edit/tombstone conflict, and remains query-only Superseded after explicit resolution and final reopen. It adds no status movement and does not establish delete-wins, indefinite retention, compaction, garbage collection, longer partitions, relay propagation, or independent interoperability. `DM-5.2-16` and `DM-5.2-17` remain open. |
| `DM-5.2-18` difference-proportional synchronization | `implemented-uncredited` | Bounded class-specific Negentropy exact-ID reconciliation for Event in v1-v5, State/Record in v4/v5, and Blob source plans in v5; Blob carrier work requests only the exact missing contiguous complement | Equal Event inventory transferred nothing; current-code mutable and Blob automation bounds each attempt and rotates durable cursors fairly. Total-size-versus-difference cost evidence across all four classes at requirement scale remains open. |
| `DM-5.3-01`, `DM-5.3-02` State causal resolution and concurrent tie-break | `observed-bounded` | Freshly verified exact-key causal maxima; authenticated context dominance; greatest complete semantic State ID current; retained `Concurrent`/`Superseded` history; immutable-fact v4/v5 ingest with current source lineage; actor-owned live query | The retained v2 run first converged two peerless concurrent State maxima on both actors with the greatest complete semantic ID Current and the other Concurrent. A later node-a successor carried the exact two initial heads and versions, became Current on both actors, and left both predecessors Superseded; the later tombstone then became Current with all three predecessors Superseded, including after immediate peerless restart. This moves causal resolution as well as the already-observed tie-break row. Mixed implementations, indefinite retention/GC, relays, physical systems, adversarial scale, and release acceptance remain open. |
| `DM-5.3-04` Blob preservation outside causal merge | `observed-bounded` | Immutable Blob bytes/identity metadata remain outside State/Record reducers; multiple stopped or live signed source publications may reference one exact completed depot variant and remain independent delivery identities; live reads select a freshly authenticated current publication; semantic-v5 staging stays outside ordinary publication indexes until exact completion | The retained peerless Blob-delivery run binds two exact publications with distinct source identities and counters to one immutable `BlobId`, one finalized depot variant, and one committed chunk, then delivers and acknowledges both independently across forced process replacement and final reopen. This moves only this row. Peer/convergence status, selector-withholding/network-interest separation, route-only custody, retention/GC policy, pure-byte identity, large/RSS/physical/resource scale, mixed implementations, and release authorization remain open. |
| `DM-5.3-06` through `DM-5.3-10` Record sibling preservation, annotation, API, no-discard, and recoverable history | `observed-bounded` | Freshly verified exact-key causal heads; actor-owned live `RecordConflict`; sorted sibling IDs and query-only opaque exact guard; atomically guarded successor; durable non-authorizing whole-head-set delivery; optional query-only superseded history; merge-free v4/v5 ingest | The retained Record-delivery run keeps all visible heads and complete sorted sibling IDs together at limit one, preserves one conflict projection across process replacement, excludes superseded plaintext and the resolution guard, requires a fresh exact query before resolution, emits the successor under a new projection, and reproduces both superseded originals only through explicit query after final reopen. Hidden sibling IDs do not disclose or authorize hidden lineage. This strengthens existing observed rows without another movement. Automatic registered-policy merge (`DM-5.3-05`), explicit-policy GC, bindings, longer partitions/relays, mixed implementations, scale, physical systems, and release acceptance remain open. |
| `DM-5.4-01`, `DM-5.4-05`, `DM-5.4-09`, `DM-5.4-10`, `DM-5.4-12` through `DM-5.4-19`, `DM-5.4-21`, `DM-5.4-22` selected priority, TTL, and constrained operation | `implemented-uncredited` / `observed-bounded` | Source-authenticated Event priority/TTL; semantic-v3-format cumulative custody inherited by v4/v5; Linux expiry; bounded scheduler/retry/retirement; Normal/AtLeast/ReceiveOnly startup and live policy; retained Linux custody acceptance | The retained run moves exactly `DM-5.4-05`, `DM-5.4-09`, `DM-5.4-12` through `DM-5.4-16`, `DM-5.4-18`, and `DM-5.4-22` to `observed-bounded`. It authenticates six priority/TTL combinations, withholds one already-expired Flash Event and one Routine Event below a Priority floor, accepts four route-only Events into a ReceiveOnly relay, expires one on Linux-boottime reopen, retires one Priority RouteEvent under explicit stopped pressure, then delivers Flash before Immediate into a ReceiveOnly receiver. `DM-5.4-10` retry cadence, `DM-5.4-11` generic global eviction, `DM-5.4-17` physical RF silence, `DM-5.4-19` complete-MVP scope, and `DM-5.4-21` qualitative simplicity gain no observed credit. Selected finite State/Record/Blob TTL, non-Linux Event TTL, physical/impaired links, scale, mixed implementations, and release authorization remain open. |
| `DM-5.5-01` through `DM-5.5-03`, `DM-5.5-05` through `DM-5.5-07` topic/scope and payload-blind relay boundary | `implemented-uncredited` / `observed-bounded` | Authenticated topic/scope; durable Event Consume/Carry, State positive-current-version, Record whole-key, and Blob exact-publication application selectors; protected receiver interest; current peer scope/epoch route commitments; bounded route-only cache; aggregate and exact-scope Event custody quotas | Retained State and Record receipts prove that network interest and application subscription are separate static surfaces. Current-code Blob delivery adds the same local selector separation but no retained beta/gamma observation yet. A local application selector does not itself prove replication. The Linux custody receipt remains primary for route-only expiry/pressure/quota behavior. Dynamic multi-scope lifecycle, bridges, other-class custody, physical/mixed implementations, scale, and release authorization remain open. |
| `DM-5.5-09` through `DM-5.5-11` selected Event bridge edge and filters | `implemented-uncredited` | Profile-`0x0001` provider-gated directed edge enrollment and authorization, active-generation checks, exact topic/priority intersection with local narrowing, first and nested Event wrappers, transactional redb authorization/source/wrapper/dependency persistence, and a semantic-v6 static selected runtime with authenticated-peer route filtering, bounded per-peer rotation, durable receiver outcomes, and fresh restart promotion | Focused tests cover two hops, wrong edge and target peer, loop, stale/disabled authority, denied topic/priority, more-than-eight-route progress, restart candidate re-verification, deterministic promotion, reserve-aware rollback, corruption, pagination, and canonical bridge frames. An opt-in five-process, three-segment Compose scenario exercises the intended static path but supplies no retained receipt. Supported administration, joined/left lifecycle, bandwidth and complete storage quotas, dynamic routing/interest policy and rekey lifecycle, cross-class bridge, physical/mixed operation, hostile-input and scale evidence, and release authorization remain open. |
| `DM-5.6-01` through `DM-5.6-03`, `DM-5.6-05` direct, infrastructure-free, intermediate, and duplicate-bounded transfer | `implemented-uncredited` / `observed-bounded` | Default direct Iroh line with hosted discovery, public/default relays, and port mapping disabled; additive controlled relay is explicit and singleton | Exact Events moved through payload-blind Aster intermediates and restart no-op; the retained live Blob receipt separately observes same-implementation direct seeding, interrupted progress, and different-peer continuation. `DM-5.6-01` still requires independent conformant-node evidence. The controlled connectivity relay and namespace-NAT receipt create no Blob custody claim. Physical transport, independent conformance, cycles/broadcast, representative NATs, alternate carriers, and generalized custody remain open. |
| `DM-5.7-01` through `DM-5.7-04` automatic discovery, manual peering, emission policy, and pre-exchange authentication | `implemented-uncredited` / `observed-bounded` | Manual routes and exact rostered nearby lookup remain available. Separate default-off `--discover-lan` accepts no neighbor coordinates, sanitizes mDNS observations to untrusted carrier IDs, and authorizes only the independently authority-authenticated, active mission identity before inventory. Repeated windows, explicit sorted/deduplicated bounded IPv4-interface selection for multi-homed nodes, and Aster-retained candidate/member sets are bounded. | Rostered manual contact has retained mission-authenticated evidence. The complete automatic discovery/authentication chain has current-code tests and runnable quickstarts/Compose evaluations, not a retained execution receipt. Upstream discovery state is not fully hostile-bounded; the stock mission record supplies no carrier-to-mission common-ownership proof. Two-physical-host Event delivery, packet/resource/hostile-input qualification, BTLE, mixed implementations, protected provisioning, supported packaging, and release authorization remain open. |
| `DM-5.8-06`, `DM-11-02`, `DM-13-04` selected IP transport, MVP inclusion, and adapter deliverable | `implemented-uncredited` | Bounded `aster-iroh` direct UDP/QUIC endpoints composed by `aster-node`, with exact rostered endpoint/mission bindings or feature-gated mDNS locator candidates followed by independent mission authorization, plus selected CLI configuration | Source and current same-implementation loopback automation prove the selected IP mechanism, including direct contact while a configured relay is unavailable. Rosterless LAN discovery has focused mechanism tests but no retained or physical-host receipt. The separate retained namespace-NAT receipt does not turn these product-scope rows into a supported or released adapter result. Physical/representative networks, target packaging/stability, bindings, mixed implementations, dependency/license/SBOM admission, complete-MVP acceptance, and release authorization remain open. |
| `DM-5.8-07` selected IP operation across NAT networks | `observed-bounded` | Selected Iroh endpoints behind two isolated Linux software-NAT namespaces with exact operator-known full-cone mappings and no relay, discovery, public/default relay, or port mapping | Both endpoints observed Direct; one exact Event was delivered and acknowledged, replay was an exact no-op, and 978 cross-NAT UDP observations agreed with complementary nft DNAT/SNAT and directional forwarding counters. This is one same-build, same-implementation, one-host namespace result, not discovery or punching, dynamic or representative NATs, physical hardware/path, public Internet, mixed implementations, resource evidence, or release authorization. |
| `DM-5.8-09` controlled relay-assisted connectivity | `observed-bounded` | One exact DER-pinned HTTPS relay under a restrictive software-NAT policy, with hosted discovery, public/default fallback, port mapping, and direct cross-NAT traffic absent | Both authenticated endpoints observed Relay; nft recorded three direct-drop packets, WAN capture recorded zero direct packets and 2,052 controlled-relay HTTPS packet observations, two exact allowlisted sessions were accepted, one Event was delivered and acknowledged, and replay was an exact no-op. This proves bounded relay-assisted connectivity, not a temporal direct-first sequence: Iroh may probe paths in parallel and later learn authenticated direct paths. Physical or independently operated relay service, public/default relay operation, mobility/outage recovery, State/Record/Blob-over-relay acceptance, mixed implementations, supported packaging, and release authorization remain open. |
| `DM-11-03` MVP NAT inclusion | `implemented-uncredited` | The selected composition now contains the retained cone/direct and restrictive/controlled-relay namespace-NAT mechanisms above | The NAT mechanism is implemented and has one retained one-host namespace observation, but the complete MVP is not shipped. Physical and representative NATs, discovery/punching, BTLE, supported-target packaging, bindings, protected operational provisioning, dependency/license admission, mixed implementations, resource evidence, and release authorization remain open. |
| `DM-11-06`, `DM-11-07` MVP conflict detection and annotation | `implemented-uncredited` | Actor-owned live `SelectedRecordHandle`, explicit sorted-sibling `RecordConflict`, opaque exact projection guard, no-discard ordinary publish failure, and guarded resolution | The mechanism exists and the retained two-participant run exercises it, but the complete MVP is not shipped. Blob's local metadata-delivery ledger is unrelated to Record conflict detection and is not Blob peer/convergence status. The agent and selected-node language bindings lack Record operations, automatic registered-policy merge is absent, and physical/mixed/release gates remain open. |
| `DM-12-04` disconnected Record edits acceptance | `observed-bounded` | Two peerless authenticated publishers, direct-Iroh reconciliation, two annotated siblings, no-discard ordinary publish failure, exact-guard resolution, and restart history | One same-implementation, one-host, two-participant, brief-partition scenario passed without silent loss and retained both superseded originals after restart. It is not physical, mixed-implementation, long-duration, relay/NAT/BTLE, adversarial-scale, product-release, or release-authorization evidence. |
| `DM-12-06`, `DM-12-07` constrained priority/expiry and emission-mode acceptance | `observed-bounded` | Retained Linux-boottime Event custody acceptance across an origin, route-only relay, and receiver using AtLeast, Normal, and ReceiveOnly | One equivalent same-implementation Linux-container loopback scenario never delivered either of two expired Flash Events, delivered the surviving Flash Event before the surviving Immediate Event, withheld one Routine Event below a Priority floor, and ingested eligible inbound synchronization at both ReceiveOnly actors while each, during ReceiveOnly operation, initiated zero contacts and disclosed zero local data/control objects. This is not a physical constrained link or RF-silence result; impairment/loss, long disconnection, suspend injection, mixed implementations, target hardware, other-class custody, scale, product release, and release authorization remain open. |
| `DM-6-01` through `DM-6-07`, `DM-6-09` through `DM-6-12` source/route protection | `observed-bounded` / `implemented-uncredited` | Profile `0x0001` retains exact source envelopes, typed Event/State/Record/Blob capabilities, and separate route/content authorization. Additive profile `0x0002` supplies separately encrypted/authenticated semantic-v1 Event route/content layers and an Iroh-protected ephemeral contact path with a declared exposure budget. | Retained Event and State receipts cover freshly verified profile-`0x0001` delivery. The Record and Blob receipts retain their prior exact boundaries. Profile `0x0002` has same-implementation source/route/content and real-Iroh tests but no retained capture or at-rest inspection evidence, so no status moves. Blob peer/convergence status, route-only Blob custody, complete networked class acceptance, key lifecycle completion, physical/mixed acceptance, profile-specific capture/resource evidence, and independent review remain open. |
| `DM-6-08` route-only Event bridge storage and transform | `implemented-uncredited` | The selected bridge retains the unchanged source-sealed Event under authenticated target-scope wrappers, persists opaque exact authorization/source/wrapper bytes plus bounded metadata, and carries them through a semantic-v6 runtime that never invokes payload opening at a route-only intermediate; only a separately content-authorized target may open and hash the payload | Focused tests exercise route-only opening failure, durable-before-result application, target delivery, restart recovery, peer-route filtering, and two nested hops. The adapter does not make a provider with content grants payload-blind. The Compose log/sentinel checks are same-host development evidence, not a retained capture or at-rest receipt. Other-class bridge custody, profile-`0x0002` bridge, physical/mixed operation, hostile-input or scale evidence, complete-MVP credit, and release authorization remain open. |
| `DM-6-13`, `DM-6-14`, `DM-6-18`, `DM-6-19`, `DM-6-25`, `DM-6-26` identity, authorization, and current hybrid mission/source mechanics | `observed-bounded` | Carrier identity and mission `NodeId` are independent; rostered contacts check the exact expected mission while automatic LAN contacts authorize the authority-authenticated active mission identity without retaining a carrier-to-mission binding; mission auth completes before inventory; dynamic topic-content and scope-route grants remain distinct; current live Rust config and stopped Event/admin opens accept protected artifacts or opaque secret references. Additive profile `0x0002` supplies P-256 credentials/source Events/controls and an exact Iroh-exporter-bound mission path without PQ operations or duplicate application records. | The retained runtime receipt still uses exact rostered peers, unprotected-reference provisioning, and profile `0x0001`; automatic LAN admission and profile `0x0002` have same-implementation mechanism tests only and add no observed credit. The stock profile-`0x0001` mission record is not exporter-bound. Stock runtime/CLI profile selection, a production backend, protected operational issuance/recovery, snapshot-resistant rollback, provider-aware destruction, non-Unix/physical zeroization, profile-`0x0002` State/Record/Blob/batch/bridge/rekey, target resource/capture evidence, profile-specific admitted-module/algorithm-policy gates, and independent review remain open. A fresh recipient-package rekey refuses an already-revoked recipient; exact historical retry remains recoverable. There is no automatic remediation workflow. |
| `DM-3-12`, `DM-6-20` captured-node exclusion and intermittent propagation | `observed-bounded` | Source-authenticated ordered Flash controls, payload-blind forwarding, durable revocation checks before Event, durable rejected-sequence fencing, and exact local historical retry | The retained authority-absent relay scenario denied two captured-node cohorts. Rejection-fence, same-signer historical retry, self-revocation receipt ordering, and cancelled-enqueued stopped recovery have focused current-code automation only. The live additions do not create new intermittent-propagation evidence. Revocation/rekey remain separate; longer impaired partitions, multiple relays/carriers, physical systems, broader topologies, process/power crash injection, and independent implementations remain open. |
| `DM-6-21`, `DM-12-08` recipient-filtered field rekey and integrated acceptance | `observed-bounded` | Recipient-filtered rekey through typed bounded live/stopped planning, source control, redb, and Iroh runtime; a fresh request fails closed for an already-revoked recipient, while exact same-signer historical receipt remains recoverable; post-revocation legacy recipient-less controls fail closed | The retained receipt advanced one scope once and excluded the captured node. Current-code live automation additionally refreshes epoch-two policy before Event publication and recovers the same receipt after canonical recipient reorder and a higher witness; it adds no observed credit. Both paths use separate revocation and rekey transactions, not automatic affected-scope discovery or atomic remediation. Repeated/multi-scope churn, production provisioning/custody, physical field evidence, independent implementations/review, and release acceptance remain open. |
| `DM-6-22` local zeroization | `observed-bounded` | Same-UID Unix `aster zeroize` plus a separate provider-neutral operation/reference-bound SecretStore destroy contract | The retained receipt covers drain and bounded software overwrite of the two unprotected-reference files only. Protected/secret-reference live nodes support graceful shutdown, but local zeroization has no provider destroyer and cannot destroy provider custody. No production SecretStore backend or coordinated drain-plus-provider-destroy workflow exists; a backend tombstone does not prove its own durability or physical erasure. Inode deletion, physical/copy-on-write/snapshot/swap/backup sanitization, redb rollback resistance, non-Unix behavior, remote triggering, and independent platform assurance remain open. |
| `DM-6-23` freshness and replay rejection | `observed-bounded` | Protected session replay checks, exact chained controls, rejected-sequence fencing, exact historical local receipts, policy-bound Event transactions, and durable/idempotent application/control operations | Current focused cells purge authenticated predecessor/rollback poison, fence replayed descendants, return nonfatal `PolicyUnsettled` for a pending gap while exact retry remains recoverable, and retain actor ownership after post-enqueue caller cancellation. The retained receipt predates these additions. This covers one caller-cancellation boundary, not process/power interruption; physical capture replay, every data class, other live command/contact boundaries, long retention/eviction, and independent implementations remain open. |
| `DM-11-20` MVP revocation | `implemented-uncredited` | Durable revocation plus typed bounded live `SelectedControlHandle`, stopped `SelectedControlAdmin`, and exact historical retry | Current live tests return self-revocation receipt before teardown and recover cancelled enqueued work through stopped exact retry. One older real-process captured-leaf scenario passed, but the complete MVP, production provisioning/custody, protected stock CLI/bindings, cross-process admin IPC, automatic/atomic revoke-plus-rekey remediation, platform-complete zeroization assurance, generalized policy management, and release gates remain incomplete. |
| `DM-7-09`, `DM-7-10` optional local agent and gRPC-like IPC | `implemented-uncredited` | `aster-agent`, strict v1 JSON/check mode, protected-loader runtime seam, repository-owned v1alpha1 Protobuf schema, pre-body-authenticated bounded loopback application listener, separate lifecycle-only health listener, token reload, bounded drain/recovery, sanitized public details, generated independent Go client, and process checker | One bounded same-host run emitted 14 passing receipts: three startup refusals without state/listener effects, five readiness transitions, exact all-field Event recovery after `SIGKILL`, higher-attempt redelivery, acknowledgement persistence, token reload, exact unary/stream drain outcomes, and combined canary absence. The separate generated Go client used Connect unary and server streaming, but no independent server implementation or separately qualified gRPC/gRPC-Web client run was exercised. The fixture's loader is unprotected and test-only. Protected provisioning, dedicated-namespace and service-manager acceptance, stronger OS identity, packaging, amd64/arm64 qualification, representative deployment, physical/mixed-network evidence, independent server interoperability, and release authorization remain open; both rows remain `implemented-uncredited`. |
| `DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-18` high-level documented boundary | `implemented-uncredited` | Typed live and stopped Event/State/Record/Blob operations; authenticated Event-only Connect/gRPC/gRPC-Web agent operations; strict configuration reference and operations quickstart; bounded sanitized errors; no transport/reconciliation/depot types in application handles; live State/Record/Blob guides; compiled stopped examples; retained State-subscription/Record-subscription/Blob producers; and a separately generated Go Event client used by black-box process acceptance | The process run used public status, publish, query, subscribe, poll, stream, and acknowledge operations from the generated Go client. It recovered one exact Event across restart by comparing all eleven exposed fields while emitting only equality/count/continuation evidence; it also observed operation-key conflict, durable higher-attempt redelivery, acknowledgement persistence, token reload, graceful drain, and canary-free process/client output. This strengthens only the bounded Event-agent and documentation evidence: the acceptance client is a harness, not an independent usability study or customer provider, and the service remains Event-only. State still has no contact status or materialized-view/withdrawal feed; Blob local ledger counts are not sync/peer status. Protected provisioning, selected-node bindings, namespace/service-manager integration, production packaging, automatic merge, independent server interoperability, physical/mixed-network and supported-target evidence, and release authorization remain open. These four rows remain `implemented-uncredited`. |
| `DM-7-16`, `DM-7-17`, `DM-7-20` offline publication/later sync/sample | `observed-bounded` | Built-in applications, compiled Event/custody/State/Record/stopped-Blob examples, actor-owned live Event/State/Record/Blob handles, retained live-Event/State-subscription/Record-subscription/live-Blob/live-Blob-subscription acceptance producers, live State/Record/Blob publication/read/delivery guide snippets, and the local-agent sample | The retained runs establish brief offline publication/later sync for their frozen boundaries; the peerless Blob-delivery receipt adds retained offline publication/delivery evidence without moving any row in this group. It makes no later-sync claim. These same-implementation one-host schedules are not stakeholder-set long-offline, power-loss, physical, independent-usability/interoperability, scale, or release results. The acceptance producers are not minimal adopter samples, so `DM-7-20` is unchanged. |
| `DM-8-01`, `DM-8-02` Rust implementation | `observed-bounded` | Rust 1.91 workspace, current selected-lane checks/tests, and retained Cargo release-profile Rust live-mutable and live-Blob executables | The retained live-Blob executable is 12,246,960 bytes with SHA-256 `e057c2046754de2fb0485b288b383031c49bbd05b96d34247bb72cefbdbcddb8`. Like the earlier live-mutable binary, its source-binary-execution link is operator-attested, not cryptographically proven or reproducible, and it is not a product release artifact. Supported-target acceptance, packaging, and release authorization remain open. |
| `DM-9-13`, `DM-9-14` Blob streamed reading and bounded working memory | `implemented-uncredited` | Stopped synchronous `read_into`, live authenticated zeroize-on-drop pages capped at 64 KiB and at most two canonical chunks, a joined capacity-one worker, canonical independently authenticated chunks, final whole-content verification, one manifest-bounded digest vector, independently chunk-bounded adapters, and semantic-v5 16-KiB ranges | The retained fixture returns eight exact pages across four reads but is only 96 KiB. The later Blob-delivery receipt is metadata-only and adds no plaintext-read or memory-use observation. Component bounds are not a whole-process peak-memory measurement and do not establish large-Blob storage streaming or supported-target RSS behavior. Blob peer/convergence status, alternate carriers, 100+ MiB brackets, complete physical accounting, mixed implementations, and retained resource evidence remain open. |
| `DM-9-24`, `DM-9-25` bounded/configurable local storage | `observed-bounded` | Validated accounted-namespace aggregate `StoreLimits`, exact-scope Event `CustodyQuota`, authority/tombstone partitions, 1-MiB mutable-object and 4,096-row/16-MiB per-class caps, 256-peer/1,024-row cursor caps, bounded retirement and one-snapshot scheduling | The retained Linux run observes one route-only scope within an explicit four-item/one-MiB quota, then an explicit stopped-store pressure retirement and persisted two-item replacement before reopen and forwarding. This is a bounded logical Event/RouteEvent observation, not complete local-storage or redb/filesystem allocation accounting. Accepted-dot, causal-frontier, Event-position/high-water, State/Record/Blob GC/custody, hostile entries, snapshots/backups/swap, live quota administration, sustained physical pressure, scale, mixed implementations, and release authorization remain open. |
| `DM-11-13`, `DM-11-15`, `DM-11-16`, `DM-11-17` MVP priority, TTL, and emission hooks | `implemented-uncredited` | Fixed four-level Event priority set; public finite Event publication; semantic-v3-format cumulative custody/expiry inherited by v4/v5; Normal/AtLeast/ReceiveOnly startup and live hooks with authenticated inbound Event ingestion | `DM-11-13` and `DM-11-16` now correctly reflect mechanisms already present and exercised by the bounded receipt; `DM-11-15` and `DM-11-17` were already implemented-uncredited. None moves to observed-bounded because each is a complete-MVP product-scope obligation and the complete MVP is not shipped. Priority count/names remain provisional; finite Event TTL is Linux-only; selected State/Record/Blob TTL is rejected/open; ReceiveOnly is not physical RF silence. Bindings, protected provisioning, supported packaging, physical/mixed acceptance, and release gates remain open. |
| `DM-9-21A` many-node operation | `observed-bounded` | Demo accepts `--nodes 2..=32`; its deterministic schedule is `2N+1` cohorts and `5N-2` children | One operator-attested Cargo release-profile binary run for the signed current-tree source passed an N=32 direct-loopback line on one macOS arm64 host: 32 distinct mission identities/stores, 65 exact cohorts, 158 exact-named executions with distinct READY PIDs, 30 payload-blind intermediates, and 32 distinct log-observed READY PIDs in the final zero-difference no-op. No overlap timing or OS sampler proves simultaneity, and the receipt does not cryptographically prove the source-to-binary-to-execution link. This does not prove the full 2–32 range, the separate bracketed target of at least 100 nodes, distributed/physical scale, NAT/relay/BTLE/cross-transport behavior, independent interoperability, resource thresholds, or release acceptance. |

Broader State/Record partition, relay, crash, and mixed-implementation behavior,
route-only Blob relay/custody, arbitrary-peer or process-crash Blob resume,
networked and long-retention Blob-delivery acceptance, Blob peer/convergence
status, TTL/GC,
pure-byte identity/dedup, and
large/RSS/physical/resource and mixed-implementation Blob behavior,
automatic registered-policy Record merge, and release acceptance remain open.
Selected-composition credit is limited to the exact stopped and actor-owned
application mechanisms, the retained bounded live-mutable,
State-subscription, and Record-subscription direct-Iroh receipts,
the retained bounded interrupted/reopened/different-peer live Blob receipt,
current-code semantic-v5 cleanup/race automation, and the exact controlled carrier
evidence named above. No retained State/Record claim extends beyond the
two-participant, one-host, direct-only boundary recorded below.

## Current controlled Iroh relay automated evidence

The current controlled-carrier code freeze is signed commit
`b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`. Its signature verifies as Good
against the repository signer. The exact ordered nine-file
`shasum -a 256` block is below; SHA-256 of the newline-terminated block itself is
`729917a6d596a38e3eda7d3da2cce76c0ba19e1a0f8fed3dc4912d96ef5e90b7`.

```text
55503cbd3747d96f282396a7e37cd3c05122a9fc76e44a41863346cd052dfe95  Cargo.toml
5b26134242180affeeaa555175e7400f682c47e14b2e7d2df2decfe14ee5f90c  Cargo.lock
633501b83d0efcacf7bb0f9c0f46bc5d16dcc20589f6a974b7df8a3add9f95c8  crates/aster-iroh/Cargo.toml
d773516cdff95878d50e6296be0363681ef583679ff4f93da82f76fb084aee4f  crates/aster-iroh/src/lib.rs
e5e5bc2c0cb96c8f93809256b2e32b95077f7246523d1c26b2d341b1e653c0d5  crates/aster-node/Cargo.toml
bcce6280c8ff61bebaa772510f62105ad71236afad0806732d1490132d721587  crates/aster-node/src/main.rs
f73349707d66fc864545297ed391ba091ee2774bed7dd552dd619c1fcad56bf0  crates/aster-node/src/runtime.rs
f81b8de1c89e50be866f259c98d6413b25dfff9f5b892686f0b440becb96c9c0  crates/aster-node/tests/mesh_cli.rs
511cd30571eacbe2314bdecdcb27b7f171622a40bca5a1a821265e6de7716fea  fuzz/Cargo.lock
```

`aster-iroh` admits one exact HTTPS relay origin alongside at most eight sorted
unique operator-supplied initial direct candidates. A relay URL is at most 2
KiB, the complete carrier route text is at most 3,072 bytes, and the URL must
name a root origin with a host and no user information, query, or fragment.
Trust is explicit: embedded WebPKI or one through eight valid DER CA roots, each
at most 64 KiB and together at most 256 KiB. Explicit roots replace WebPKI; no
insecure or unrelated-CA fallback exists. The selected node CLI currently
supplies one initial direct locator from each existing `--peer` value. Hosted
lookup, public/default relay substitution, and port mapping remain disabled.

Direct-plus-controlled-relay startup defers relay readiness, so an unavailable
relay does not block an exact direct contact. Relay-only startup requires the
configured relay to become ready and disables all IP transports. Iroh may probe
the supplied initial paths in parallel; this API promises no temporal
direct-first ordering. After exact endpoint authentication, Iroh may negotiate
additional direct paths, so initial locators are not a lifetime IP allowlist and
those route semantics and this source/test slice alone are not NAT acceptance
evidence. Endpoint identity and the sole configured relay origin remain exact.

Every connection retains a bounded diagnostic `Direct`, `Relay`, or `Unknown`
path witness. It subscribes before the initial snapshot, coalesces observed
path-kind transitions, preserves the last observed Direct/Relay value across an
ordinary path close, caps the count at 1,024, and marks saturation or lost
continuity. It is not an exact event ledger and never establishes identity,
membership, authorization, receipt validity, or synchronization success.

The carrier all-feature suite passed 13/13 in 9.28 seconds. It covers exact route
and trust bounds; relay-only exchange under explicit roots; rejection of a valid
but unrelated CA without fallback; usable direct selection; direct operation
after the configured relay is already unavailable; wrong endpoint/relay
substitution; and bounded failure after relay loss with no public substitute.
The fixture is a test-only local HTTPS relay. The normal selected-node graph
uses Iroh's client relay support but does not enable `iroh-relay/server` or
`test-utils`; the server/test graph is confined to the dev/all-feature fixture.

The `mesh_cli` suite passed 20/20 in 153.91 seconds within the full serialized
gate. Its controlled-relay real-process case gives the lower-carrier-ID
initiator one deliberately unusable initial direct locator while the responder
uses relay-only mode. Both endpoints report Relay for successful hybrid-mission-
authenticated contacts, one offline Event is delivered, and the repeat contact
is an exact no-op. The separate focused runtime test
`right_carrier_with_wrong_expected_mission_fails_before_inventory` proves that
the independently expected mission mismatch fails before inventory
construction; the carrier path observation is not that ordering proof. Another
real-process test observes only Direct while the exact configured relay is
unavailable. Partial configuration, malformed DER roots, and duplicate
token-bearing relay URLs fail before state or mission access, with values
redacted from parse errors. After the final harness correction, the focused
controlled-relay Event test passed 1/1 again in 204.69 seconds on the frozen
`mesh_cli.rs` bytes above.

The exact final serialized repository gate was:

```sh
env CARGO_TARGET_DIR=/private/tmp/aster-controlled-relay-full-check \
  CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 mise run check
```

It exited zero when run outside the sandbox for loopback tests. Visible
constituent results included `aster-node` library 170/170 in 157.48 seconds,
`aster-node` `mesh_cli` 20/20 in 153.91 seconds, `aster-iroh` 13/13 in 9.28
seconds, `aster-ip` 50/50 in 2.20 seconds, and `aster-lab` library 32/32 in
53.56 seconds. The complete command also passed the remaining workspace tests
and doctests plus language, conformance, license, dependency, formatting, and
strict lint gates. No trustworthy aggregate wall time was retained.

Fresh all-feature Rustdoc with warnings denied also exited zero in 57.67
seconds:

```sh
env RUSTDOCFLAGS=-Dwarnings \
  CARGO_TARGET_DIR=/private/tmp/aster-controlled-relay-rustdoc-final-20260825 \
  CARGO_BUILD_JOBS=2 \
  cargo doc --locked --workspace --all-features --no-deps
```

This source/test slice is current-code, same-implementation, one-host automated
evidence, not a retained execution root. It originally moved only `DM-5.8-06`,
`DM-5.8-09`, `DM-11-02`, and `DM-13-04` from `open` to
`implemented-uncredited`; by itself it creates no `observed-bounded` credit and
relabels no historical receipt. The later, separately frozen namespace-NAT
receipt below upgrades only the exact rows and claim boundaries stated there.
This source/test slice does not prove
a physical relay deployment, direct operation across NAT, direct-first
fallback, multi-host operation, BTLE, mixed implementations, N=32/resource
brackets, packet-capture confidentiality, State/Record/Blob-over-relay behavior,
route-only Blob custody, supported-target packaging, dependency/license/SBOM
admission, or release authorization. The connectivity relay is below the
peer-to-peer QUIC and mission/source protections; it is not the payload-blind
Aster Event node from retained temporal-relay receipts.

## Selected Iroh NAT retained receipt

On 2026-08-26, the exact selected composition at signed commit
`15f4e0b8e9f817508c14fcbb4b307d6949add557` and tree
`09d2f5bb037d694367e24ec50747aba8cac83b96` passed the two-cell
`aster-selected-iroh-nat-receipt/v1` suite. The commit signature verified as
Good for `code@jeffm.us` with ED25519 key
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The source-bound
`Cargo.lock` SHA-256 is
`61a774190d9cb3b54a7fca62353bd0241f62bf676d1bf956ac7f1fef0c6d5521`,
and the requirements SHA-256 remains
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

The checked-in canonical
[`aster-selected-iroh-nat-receipt/v1` receipt](evidence/selected-iroh-nat-15f4e0b.json)
is exactly 48,302 bytes with SHA-256
`55dc67ac606e92c44c2e36d959b23bc52880b483bdab21a7c2ec47487eee0393`.
It is the only raw-run file copied into source control. The complete raw root is
`/private/tmp/aster-selected-iroh-nat.zFpaqB/20260826T143559Z-selected-iroh-nat-50726015670670e9`
on the validating host. It retains encrypted state, mission bundles,
credentials, and packet captures under an external-restricted boundary and
must not be copied into documentation or treated as the public receipt.

The build used the exact selected-NAT Dockerfile SHA-256
`2b7ce7b548aaec3fb3a0b412bde3547753e4e7f45ddeb44d98bd7f5ed973e56c`
and build-input manifest SHA-256
`ce908e0c1b8ed743f3cdf03bd3525df72f9fc5a89d8e59ce7759211f833c3183`.
The local image/config ID was
`sha256:05d80d1ddf9624f70c7c4bcfcf9a78a02ce5d957967d6f5221c676a56f36740f`.
The three runtime artifacts were:

```text
1715eb1ee572d619abb8641482cb9b7418a82bb14ac2ab7c40a39238476f9da2  aster; 11,957,512 bytes
dc59753490170e6b018b3bdcf2da257c27f70747386d4f1053407adf5b7fe6ab  aster-selected-nat; 3,216,136 bytes
df7b8127881a82b0677083c17d4f6f85d187bfbb93a9d5d23abdcfbb624584ed  aster-selected-relay; 4,928,672 bytes
```

The run used one Darwin arm64 physical host, Docker 29.4.0, OrbStack 2.2.3,
and kernel `7.0.14-orbstack-00380-ga7e0a2dc9535` to host isolated Docker Linux
network namespaces. Across both cells, four selected endpoints (two per cell)
used fresh, disjoint carrier identities, mission identities, mission
authorities, subscriptions, state directories, and stores. Each cell published
one exact 32-byte source-authenticated Event, observed one destination delivery
on attempt one, acknowledged it, observed an empty
post-ack poll, and repeated both the acknowledgement and subscription contact
as exact no-ops. Each cell retained four successful contact receipts, with all
control, mutable, and Blob work zero.

| Cell | Exact retained observation |
|---|---|
| Cone/direct | Two selected endpoints were placed behind separate LAN and software-NAT-router namespaces with exact operator-known static full-cone mappings. Relay, hosted discovery, public/default relay, and port mapping were disabled. Both endpoints selected Direct with zero observed transitions. The two WAN captures retained 489 packets each with zero drops and 978 aggregate cross-NAT UDP/44000 observations; complementary nft DNAT/SNAT and directional forwarding counters agreed. |
| Restrictive/controlled relay | The restrictive nft policy recorded three direct-drop packets. The WAN captures retained 1,025 and 1,027 packets with zero drops, zero direct cross-NAT observations, and 2,052 controlled-relay HTTPS observations, with zero HTTP, hosted-discovery, or public-relay observations. Both endpoints selected Relay with zero observed transitions. The exact DER-pinned, two-identity-allowlisted relay accepted two sessions, rejected zero, and reached an active-session peak of two. |

The receipt's canonical raw manifest contains 99 records, 10,928 manifest
bytes, and 1,094,629 enumerated artifact bytes, with SHA-256
`6253de629d1ba2791bf86e4a72c316761a7f80b3420c0b03577dc1f5e026bbe4`.
The canary scan covered exactly 26 enumerated finalized targets: 11 in the
cone/direct cell and 15 in the restrictive/relay cell, including the named WAN
captures. It searched raw bytes, lowercase hexadecimal, and standard Base64,
found zero matches, and first proved all three encodings against one positive
control per cell. This is not an all-file, all-storage, or whole-host secret
scan. The external-restricted state and credential files were metadata-
inspected only.

Both standalone 32-byte canary control files were overwritten, synchronized,
unlinked, and absent after cleanup. The restrictive relay's temporary private-
key file received the same bounded-software treatment. Each cell ended with
zero runtime containers, networks, and namespaces. Those assertions do not
claim deletion of the selected local build image, physical erasure, global
host sanitization, or sanitization of retained encrypted state and credentials.
The image/config ID is a local identity only, not a registry image digest.

The canonical projection was reproduced byte-for-byte from the raw root at the
same 48,302-byte size and SHA-256. The current receipt checker has SHA-256
`357b2ac98300dfb88e8ce2dc97672f4c685d401de82c80756db51b0dacb73823`;
it passed against the immutable signed source, and its synthetic fail-closed
suite passed 38/38.
Review requires both the public receipt and access-controlled raw root; the
checked-in JSON alone cannot replay packet, nft, chronology, or raw-artifact
bindings. Validate the retained receipt with a source repository containing the
signed commit object and the reviewer's configured trusted signer:

```sh
python3 tools/check-selected-iroh-nat-receipt.py \
  --raw-root /private/tmp/aster-selected-iroh-nat.zFpaqB/20260826T143559Z-selected-iroh-nat-50726015670670e9 \
  --source . \
  docs/validation/evidence/selected-iroh-nat-15f4e0b.json
```

To independently reproject the sanitized JSON, choose a fresh nonexistent
owner-controlled output path; the projector refuses to overwrite an existing
path. The result must compare byte-for-byte with the checked-in receipt:

```sh
nat_review_dir="$(mktemp -d /private/tmp/aster-selected-nat-review.XXXXXX)"
chmod 700 "$nat_review_dir"
python3 lab/orchestrate.py selected-iroh-nat-project \
  --raw-root /private/tmp/aster-selected-iroh-nat.zFpaqB/20260826T143559Z-selected-iroh-nat-50726015670670e9 \
  --output "$nat_review_dir/selected-iroh-nat-receipt.json"
cmp "$nat_review_dir/selected-iroh-nat-receipt.json" \
  docs/validation/evidence/selected-iroh-nat-15f4e0b.json
shasum -a 256 "$nat_review_dir/selected-iroh-nat-receipt.json"
```

This receipt moves exactly `DM-5.8-07` from `open` to
`observed-bounded`, `DM-5.8-09` from `implemented-uncredited` to
`observed-bounded`, and `DM-11-03` from `open` to
`implemented-uncredited`. Relay-assisted connectivity was observed while the
restrictive policy blocked direct traffic; no temporal direct-first or fallback
sequence is claimed because Iroh may probe paths in parallel and learn later
authenticated direct paths. The receipt is one same-build,
same-implementation, one-host software-namespace result. It does not claim
dynamic endpoint discovery or hole punching, representative or physical NAT
hardware/path, public Internet, hosted discovery, public/default relay, port
mapping, an independently operated relay, lab-network exclusivity, a complete
listener-wide pre-authentication cap, independent implementation, BTLE,
State/Record/Blob-over-relay behavior, mobility/outage recovery, independent
clock assurance, resource thresholds, a hermetic build, complete MVP, product
release, or release authorization. `DM-5.8-08` and the physical release gate
`DM-12-09` remain `open`.

## Selected live Event retained receipt

On 2026-08-27, the selected live Event composition at signed source commit
`c464129d58c250dea2ecbf5f51d7ece0e5aab6d0` and tree
`5120f9a184bf1eee63ed0545c3d8673388762b7b` passed the
`aster-selected-live-event-receipt/v1` contract. The source signature verified
Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The checked-in canonical
[`aster-selected-live-event-receipt/v1` receipt](evidence/selected-live-event-c464129.json)
is exactly 9,573 bytes with SHA-256
`4d71d04e4ebcc9f63c0e84e7f11e83bf1f3d1ad2ca8608486cdcc875b6dfeef0`.

The runner required a clean signed `HEAD`, bound the exact commit, tree,
signature, admitted files, and tool hashes, and rechecked the source after both
build and execution. The exact Cargo build command was:

```text
cargo build --release --locked -p aster-node --example live_event_acceptance
```

The one copied Cargo release-profile executable is 12,298,240 bytes with
SHA-256
`8b39949cabc12604e49614f7172bce4031e6dac6d987bbe5678869b17d1d8115`.
The bounded 180-second run exited zero across three OS processes. Stderr is
exactly empty. Stdout is 41,381 bytes/99 lines with SHA-256
`bc5e01fe3038640629862ba8df44f69500bfafbe407cd43ba2f84de9201d9849`;
it contains exactly 7 `READY`, 4 `CONTACT`, 6 `STOP`, and 3 narrowly scoped
`LIVE_EVENT_CHILD` coordination records. The canonical transcript is
exactly 79 `LIVE_EVENT` records/21,111 bytes with SHA-256
`6becd5f2d4cb9447a6260064a1eef55b944e3a2f19071d399e43bc8a2c503158`.
The receipt excludes exact participant identifiers, paths, ports, PIDs, and
payload bytes; payloads appear only as SHA-256 commitments.

The retained acceptance facts are exact and bounded:

- Two participants used distinct carrier and mission identities under one
  common mission authority disjoint from all participant identities, exact
  reciprocal carrier/mission peer bindings, and at most two concurrent actors
  across seven actor lifetimes.
  Six lifetimes shut down gracefully, the one intentionally killed receiver
  process emitted no `STOP`, six retained handles closed with their actors, and
  both UDP binds were reacquired.
- The publisher committed four durable Events while peerless: three alpha
  publications at authenticated publisher sequences one through three and one
  authorized beta publication. All four were locally queryable with four
  acceptance markers. One exact publication retry inserted nothing; one
  changed-intent reuse was rejected and preserved the original publication.
- The receiver's durable alpha subscription selected exactly the three alpha
  Events. During the priority-threshold contact, exact Event-transfer
  accounting was three offered, three fetched, three inserted, and zero
  duplicates. Alpha sequences one (`priority`) and three (`flash`) were
  returned at delivery attempt one, while routine sequence two was withheld.
  The authorized but unsubscribed beta Event was also withheld. The freshly
  verified alpha gap was exactly `[2,3)`, and contact status was
  `last_contact_complete` for the negotiated priority policy rather than a
  claim that no locally stored work existed.
- After the attempt-one poll result was durably committed, returned, and
  flushed, the parent forcibly terminated the receiver OS process before any
  acknowledgement. This was not a graceful actor restart. A fresh receiver
  process replayed the durable alpha subscription and returned the same two
  Event identifiers at delivery attempt two. It acknowledged and exactly
  reacknowledged both, then returned an empty poll.
- A later normal-policy direct contact delivered routine alpha sequence two at
  attempt one. The receiver acknowledged and exactly reacknowledged it; the
  gap became closed-through-three and the fresh status was
  `last_contact_complete`. A beta selector was then inserted and removed with
  an exact already-absent retry. Status correctly became
  `policy_changed_since_contact`, but there was no fresh post-policy contact,
  beta delivery, or beta acknowledgement.
- The final peerless receiver reopen replayed the alpha subscription, queried
  exactly the three alpha Events in canonical publisher positions, retained a
  closed-through-three gap, reported offline, returned an empty poll, and
  closed the retained handle. Event control, mutable, and Blob activity stayed
  zero throughout this Event-only scenario.

The complete raw root remains outside source control in owner-restricted
custody on the validating host. Its seven directories, including the root, are
owner-only `0700`. Its exact inventory contains 11 regular one-link files with
no aliases: one copied executable, four public terminal/metadata artifacts,
and, for each participant, one mission bundle, one identity key, and one redb
store. The six participant artifacts are validated only by path, regular-file
type, owner, mode, link count, and byte-count metadata. The runner and checker
never open, read, or hash their contents. The raw root may contain credentials
or identity-bearing state and must not be copied into documentation, committed,
or treated as the public receipt.

The source-bound producer is 95,217 bytes with SHA-256
`0133440013ec0d08eace6f4abdd9336aab18c53569b372f6a59e0411e50af5e7`;
the runner is 34,757 bytes with SHA-256
`727ebd6353ceed3b5e88ce0726264fae60ba8aac022f5f8cb3fb1151a60bcff0`;
the checker is 122,872 bytes with SHA-256
`93f71fc1e21e31059b2d04bbcb1576ed56478c49b49488e64eaf46b6dd953243`;
and the independently admitted adversarial test source is 106,308 bytes with
SHA-256
`565778872277a315481f483c05a158bb034faa9be65dbec0ca598efa12f1c4f9`.
Its fail-closed suite passed all 51 adversarial tests.

The checker deterministically projects canonical JSON from the retained raw
root. Two projections must compare byte-for-byte and reproduce the checked-in
9,573-byte receipt and SHA-256. Because the evidence/documentation commit is a
descendant of the source freeze, projection and validation require a separate
clean checkout detached at the exact signed source commit:

```sh
projection_a="$(mktemp -d /private/tmp/aster-live-event-projection-a.XXXXXX)"
projection_b="$(mktemp -d /private/tmp/aster-live-event-projection-b.XXXXXX)"
chmod 700 "$projection_a" "$projection_b"

python3 tools/check-selected-live-event-receipt.py - \
  --raw-root /path/to/retained-owner-only-raw-root \
  --source /path/to/aster-source-worktree-detached-at-c464129d58c250dea2ecbf5f51d7ece0e5aab6d0 \
  --output "$projection_a/selected-live-event-receipt.json"

python3 tools/check-selected-live-event-receipt.py - \
  --raw-root /path/to/retained-owner-only-raw-root \
  --source /path/to/aster-source-worktree-detached-at-c464129d58c250dea2ecbf5f51d7ece0e5aab6d0 \
  --output "$projection_b/selected-live-event-receipt.json"

cmp "$projection_a/selected-live-event-receipt.json" \
  "$projection_b/selected-live-event-receipt.json"
cmp "$projection_a/selected-live-event-receipt.json" \
  docs/validation/evidence/selected-live-event-c464129.json
shasum -a 256 "$projection_a/selected-live-event-receipt.json"

python3 tools/check-selected-live-event-receipt.py \
  --raw-root /path/to/retained-owner-only-raw-root \
  --source /path/to/aster-source-worktree-detached-at-c464129d58c250dea2ecbf5f51d7ece0e5aab6d0 \
  docs/validation/evidence/selected-live-event-c464129.json
```

The source-to-binary-to-execution link is explicitly
`operator-attested-not-cryptographically-proven`, and the admitted source list
is not a complete reproducible build closure. The receipt observes no positive
failed-contact attempt: both `awaiting_authenticated_contact` observations have
zero failed attempts. It also has no fresh contact after the selector-policy
change and therefore no beta delivery or acknowledgement. Priority-withheld
data is outside the negotiated work and does not establish a `work_remained`
status. The final restart is one immediate peerless reopen, not indefinite
Event retention, compaction, or garbage-collection evidence.

This receipt claims only one-host loopback, same-implementation,
two-participant direct-Iroh live Event behavior. It does not claim distinct
physical hosts, physical IP or RF behavior, NAT or Internet traversal,
controlled or public relay use, BTLE, independent-implementation
interoperability, scale beyond two participants, resource thresholds or a
long-duration soak, State/Record/Blob live acceptance, a reproducible build, a
product release, or release authorization.

The receipt moves exactly `DM-5.1-05` through `DM-5.1-07`, `DM-5.2-06`,
`DM-5.2-07`, and `DM-5.5-02` from `implemented-uncredited` to
`observed-bounded`. It strengthens, without another status movement,
`DM-5.2-08`, `DM-6-06`, `DM-7-16`, and `DM-7-17`. It changes no `open` row,
no broader `DM-7` row, and no other class status.

## Selected live State and Record retained receipt

On 2026-08-27, the selected live State/Record composition at signed source
commit `6cabb4cefaf6200c4642abddeb6f559dab043295` and tree
`e6c8577f77035f6a0c0891a0beb084e52debe53e` passed the
`aster-selected-live-mutable-receipt/v2` contract. The source signature
verified Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`.
The checked-in canonical
[`aster-selected-live-mutable-receipt/v2` receipt](evidence/selected-live-mutable-6cabb4c.json)
is exactly 7,752 bytes with SHA-256
`054945ecf94e8bfba1b130f6a5f47e9b1e0e17ad69f3b1472085a1d10f05eeaa`.
It explicitly supersedes the v1 receipt at source
`2ccfba0d18bf8d8221ab11fb485b32fcf6270272`, whose canonical SHA-256 was
`299a3c3b8d1685deb5980ed091797f7d46119562b67c3d853b94d8552c83b67a`.
The source-bound checker is 108,731 bytes with SHA-256
`4281cc547f145e1b1423aa61a529cb5017762f1e5c2c0730454220607796bdf7`;
the independently admitted fail-closed test oracle is 85,670 bytes with
SHA-256
`42f6043a4cbe35a39404bf63ed3e2a153d86b2e14b70e00bb6fb65983894cc42`.

The runner verified the signed, clean source before build, after build, and
after execution. It invoked exactly:

```text
cargo build --release --locked -p aster-node --example live_mutable_acceptance
/private/tmp/aster-selected-live-mutable-6cabb4c-final/binary/aster-live-mutable-acceptance /private/tmp/aster-selected-live-mutable-6cabb4c-final
```

The copied Cargo release-profile executable is 12,280,032 bytes with SHA-256
`34e7a2a888737170486d44dc154dab08592c2cdbb9778b9c6df71b7c2f4e6c11`.
The exact run exited zero. Its stdout is 40,330 bytes/68 lines with SHA-256
`484434e27d86e441f7f516be3c604dc52fc9ebab5035f9ee0b0d0bffbe2778bc`;
stderr is exactly empty. The public 48-record transcript is 20,774 bytes with
SHA-256
`9171d6078d9a6692cba2598f1c3a2e7b2bb1c3b9bb3d35341a8cd3172ee5b805`.
The canonical receipt excludes exact participant identifiers, paths, ports,
PIDs, and payload bytes; payloads appear only as SHA-256 commitments.

The retained acceptance facts are exact and bounded:

- Two participants used two distinct carrier identities and two distinct
  mission identities under one common authority with disjoint mission identity
  bindings and exact reciprocal expected-peer bindings.
- Six actor lifetimes ran across three sequential phases, with at most two
  actors concurrently. All six shut down gracefully; four retained State/Record
  handle clones closed with the actor; and both UDP binds were reacquired after
  final shutdown.
- Both participants published one initial State value and one Record revision
  while peerless. Peerless and restart phases recorded zero contacts. Six exact
  publication retries and two exact Record-resolution retries inserted nothing.
- Each connected actor completed four contacts, producing eight paired
  positive, direct-only, error-free `CONTACT` lines. Selected mutable accounting
  aggregated exactly seven offered, seven fetched, and seven inserted items,
  zero duplicates, and zero deferred or remaining mutable/Event work. Event and
  control counters were zero. All Blob source, operation, acceptance, depot,
  range, cursor, staging, remaining, deferred, and lifecycle counters were also
  zero, including the newer Blob lifecycle fields on every `STOP` record.
- Both initial connected State projections selected the greatest complete
  authenticated semantic State ID as Current and retained the other concurrent
  maximum as Concurrent. Node-a then published its counter-4 non-tombstone
  successor with the exact two initial heads and versions in its observed sets;
  two connected projections made it Current and marked both initial versions
  Superseded.
- Only after node-b queried that successor did node-b publish its counter-3
  empty authenticated tombstone with the successor as its exact observed head
  and all three earlier versions in its observed-version set. Two connected
  projections and two immediate peerless restart projections made that
  tombstone Current and retained the successor plus both initial versions as
  exactly three Superseded predecessors.
  The empty payload commitment is
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Preserving the v1 Record behavior, both live projections exposed the same two
  sibling IDs and exact conflict guard. Ordinary publish returned Conflict
  without insertion or sibling change. The node-a counter-3 guarded resolution
  observed both siblings; exact resolution retry inserted nothing, both
  connected projections converged, and both peerless restart projections
  retained the successor plus both superseded originals.

The complete raw root remains outside source control at
`/private/tmp/aster-selected-live-mutable-6cabb4c-final` on the validating host. Its
seven directories, including the root, are owner-only `0700`. Its exact
inventory contains 11 regular files with one link each and no aliases: one
copied executable, four public terminal/metadata files, and, for each of two
participant directories, one mission bundle, one identity key, and one redb
store. The six participant secret artifacts are validated only by regular-file
identity, owner, mode, link, and path metadata. The checker never opens, reads,
or hashes their contents. The raw root may contain credentials or
identity-bearing data and
must not be copied into documentation, committed, or treated as the public
receipt.

The original retained run and the two independent canonical projections used
these exact commands while the source checkout was clean at the signed source
commit:

```sh
python3 tools/run-selected-live-mutable.py \
  --source /Users/megamind/code/aster \
  --raw-root /private/tmp/aster-selected-live-mutable-6cabb4c-final

python3 tools/check-selected-live-mutable-receipt.py - \
  --raw-root /private/tmp/aster-selected-live-mutable-6cabb4c-final \
  --source /Users/megamind/code/aster \
  --output /private/tmp/aster-live-mutable-projection-6cabb4c/selected-live-mutable-receipt.json

python3 tools/check-selected-live-mutable-receipt.py - \
  --raw-root /private/tmp/aster-selected-live-mutable-6cabb4c-final \
  --source /Users/megamind/code/aster \
  --output /private/tmp/aster-live-mutable-projection-6cabb4c-b/selected-live-mutable-receipt.json

cmp /private/tmp/aster-live-mutable-projection-6cabb4c/selected-live-mutable-receipt.json \
  /private/tmp/aster-live-mutable-projection-6cabb4c-b/selected-live-mutable-receipt.json
shasum -a 256 \
  /private/tmp/aster-live-mutable-projection-6cabb4c/selected-live-mutable-receipt.json
```

Future review must use a separate clean checkout detached at the exact signed
source commit because this evidence/documentation commit is a descendant. With
the retained raw root available, validate the checked-in receipt byte-for-byte
as follows:

```sh
python3 tools/check-selected-live-mutable-receipt.py \
  --raw-root /private/tmp/aster-selected-live-mutable-6cabb4c-final \
  --source /path/to/aster-source-worktree-detached-at-6cabb4c \
  docs/validation/evidence/selected-live-mutable-6cabb4c.json
```

The receipt's source-to-binary-to-execution link is explicitly
`operator-attested-not-cryptographically-proven`, and its admitted source list
is not a complete reproducible build closure. It claims only one-host loopback,
same-implementation, two-participant live State/Record behavior. It does not
claim distinct physical hosts, NAT or Internet traversal, a controlled or
public relay, BTLE, independent-implementation interoperability, scale beyond
two participants, resource thresholds or a long-duration soak, Event or Blob
live-application acceptance, a reproducible build, a product release, or
release authorization. The exact State causal observation and publication
order is producer-attested and checker-bound: the checker binds the transcript
shape, identities, publisher counters, payload commitments, observed
head/version sets, projections, and dispositions, but the retained result is
not an independent causality observer. The single immediate peerless reopen
does not claim indefinite tombstone retention, compaction or garbage
collection, or delete-wins semantics against an unobserved concurrent value.

The superseded v1 receipt moved exactly `DM-5.1-09`, `DM-5.3-02`, and
`DM-5.3-06` through `DM-5.3-10` from `implemented-uncredited` to
`observed-bounded`; moved `DM-11-06` and `DM-11-07` from `open` to
`implemented-uncredited`; and moved `DM-12-04` from `open` to
`observed-bounded`. It strengthened, without moving,
`DM-1-05`, `DM-5.1-01`, `DM-5.1-08`, `DM-5.2-01`, `DM-5.2-09`, `DM-7-11`,
`DM-7-16`, `DM-7-17`, `DM-8-01`, and `DM-8-02`. V2 preserves those movements
and strengthened mappings and newly moves `DM-5.1-02` and
`DM-5.3-01` from `implemented-uncredited` to `observed-bounded` and
`DM-5.2-15` from `open` to `observed-bounded`. At the mutable-v2 receipt
boundary it left `DM-5.1-01` `implemented-uncredited`; the later State
subscription receipt below moves that row. `DM-5.2-16` and `DM-5.2-17` remain
`open`.

## Selected live State subscription retained receipt

On 2026-08-27, the selected positive-current-version State delivery boundary
at signed source commit `8912fc33571449d1beb4a4cb0f204b5dcd44e8c2` and tree
`8de452c720e42e9f8e7596448ea60a2ed34bf707` passed the
`aster-selected-live-state-subscription-receipt/v1` contract. The source
signature verified Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The checked-in canonical
[`aster-selected-live-state-subscription-receipt/v1` receipt](evidence/selected-live-state-subscription-8912fc3.json)
is exactly 9,656 bytes with SHA-256
`7d0b568dd4d57c3f2967da55953896829261877513c59c51a0b274eeda69485f`.
The source-bound checker is 72,930 bytes with SHA-256
`620126d1606a0f72cc7fd88458753f2876c38447af9dcd91cb9efe5d3a221563`;
the independently admitted fail-closed oracle is 51,824 bytes with SHA-256
`16577951d5e49e48154991441c2fdd6b8410af4488dc5430db7721f5339a9669`.

The exact Cargo release build was:

```text
cargo build --release --locked -p aster-node --example live_state_subscription_acceptance
```

The copied executable is 12,520,016 bytes with SHA-256
`9cb8207893526f463c64ee72a464a027c392e718fe832907c4c2477758842705`.
Its exact run exited zero. Stdout is 56,744 bytes/101 lines with SHA-256
`27d747eb5639aa594be44998cf27e14b86e8a45ae3a5334abf8a49e1698b2929`
and contains ten READY, ten CONTACT, nine STOP, and two child-coordination
records; stderr is exactly empty. The private 70-record transcript is 25,820
bytes with SHA-256
`bef3e6eb153c16d4dcd9dd328c2fb89c24bd1028b96dfa51f839835b17abcc9f`.
The canonical receipt excludes participant, object, subscription, token, path,
socket, port, and PID values; payloads and delivery tokens appear only through
SHA-256 commitments.

The retained acceptance facts are exact and bounded:

- Two participants use distinct carrier and mission identities under one
  common authority with disjoint mission bindings and reciprocal expected-peer
  bindings. Ten actor lifetimes span seven phases with at most two concurrent:
  nine stop gracefully and the parent sends one receiver child `SIGKILL` after
  its durable attempt-one poll is flushed but before acknowledgement. The run
  uses three OS processes, closes nine retained handles, and reacquires both
  participant binds after final shutdown.
- Six durable State publications comprise two peerless concurrent origins, one
  causally dominant successor, a network-interested but application-unsubscribed
  value, an authorized but network-uninterested value, and one explicit empty
  tombstone. Ten positive direct-only CONTACT records aggregate exactly five
  State offers, fetches, and inserts with zero duplicates and zero Event,
  control, or Blob activity.
- One exact-key application subscription is inserted once and durably replayed
  seven times. Four positive-current-version deliveries cover the receiver's
  local origin, the successor at attempt one, the same successor at attempt two
  in a fresh process, and the explicit current tombstone. Superseding the local
  origin retires its pending delivery and prevents an acknowledged or
  superseded ancestor from reappearing. The fresh child acknowledges and
  idempotently reacknowledges the successor; the later actor does the same for
  the tombstone. Four empty polls and the final peerless reopen preserve the
  empty acknowledged-delivery set.
- Eight checker-bound token cases prove the attempt-one token remains valid
  after attempt-two rotation, attempt-two acknowledgement is idempotently
  replayable, and malformed, wrong-State, wrong-subscription, and retired-origin
  tokens fail closed. Exact token bytes never enter the public receipt.
- The configured network-interest surface and the application subscription are
  deliberately separate. The network-interested beta State reaches durable
  receiver storage without application delivery because it is unsubscribed;
  authorized gamma remains withheld because it is absent from static configured
  network interests. Creating or replaying the State application subscription
  does not mutate `NodeConfig` or change either outcome.
- The final State projection is the explicit current tombstone with the causal
  successor and both origins retained as exactly three Superseded ancestors.
  The final store statistics bind six retained State rows at the publisher and
  five at the receiver; contact accounting binds five aggregate network
  insertions. The final immediate peerless
  reopen replays the subscription, the empty acknowledged-delivery set, the
  tombstone projection, and both selector-separation outcomes.

The complete owner-restricted raw root remains outside source control at
`/private/tmp/aster-selected-live-state-subscription-8912fc3` on the validating
host. Its seven directories are owner-only `0700`; its exact inventory contains
11 one-link regular files with no aliases. The six participant mission bundles,
identity keys, and redb stores are checked only as file metadata. The checker
never opens, reads, or hashes their contents. This raw root may contain
credentials or identity-bearing data and must not be committed or treated as
the public receipt.

A new capture requires a fresh exclusive raw-root path, a clean checkout at a
good-signed source commit, and the repository-pinned Python 3.13.7 and Rust
1.97.1 runtimes already installed through `mise`. Select those runtimes from a
neutral directory, then execute the source-bound tools by absolute path; this
avoids trusting checkout configuration merely to run the verifier:

```sh
ASTER_SOURCE=/path/to/clean-good-signed-aster-source
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
mise exec python@3.13.7 rust@1.97.1 -- python3 "$ASTER_SOURCE/tools/run-selected-live-state-subscription.py" \
  --source "$ASTER_SOURCE" \
  --raw-root /private/tmp/aster-selected-live-state-subscription-new

install -d -m 700 /private/tmp/aster-live-state-subscription-projection
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-state-subscription-receipt.py" - \
  --raw-root /private/tmp/aster-selected-live-state-subscription-new \
  --source "$ASTER_SOURCE" \
  --output /private/tmp/aster-live-state-subscription-projection/selected-live-state-subscription-receipt.json
```

Replaying the checked-in projection requires the installed pinned Python
runtime, the externally retained raw root, and a separate clean checkout
detached at the exact signed source commit. Pass both the source-bound checker
and the checked-in receipt by absolute path because the receipt postdates the
signed source freeze:

```sh
ASTER_SOURCE=/path/to/aster-source-detached-at-8912fc33571449d1beb4a4cb0f204b5dcd44e8c2
ASTER_RECEIPT=/absolute/path/to/current-aster-checkout/docs/validation/evidence/selected-live-state-subscription-8912fc3.json
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-state-subscription-receipt.py" \
  --raw-root /path/to/retained/selected-live-state-subscription-raw-root \
  --source "$ASTER_SOURCE" \
  "$ASTER_RECEIPT"
cd "$ASTER_SOURCE"
"$ASTER_PYTHON" tools/test-selected-live-state-subscription-receipt.py
```

The source-to-binary-to-execution link is operator-attested, not cryptographic
or reproducible-build proof, and the admitted source list is not a complete
reproducible-build closure. State causal observation and publication order are
producer-attested and checker-bound rather than independently observed. This is
one-host, same-implementation, direct-loopback evidence with two participants;
participant secret artifacts are metadata-only evidence. It does not claim
distinct physical hosts, physical IP, NAT or Internet traversal, a controlled
or public relay, BTLE, mixed or independent implementations, scale beyond two,
resource thresholds, long-duration soak, Event/Record/Blob live-application
acceptance, indefinite tombstone retention, compaction, garbage collection, a
release artifact, or production authorization.

Most importantly, this contract delivers only freshly verified positive Current
State versions. An explicit current tombstone is a delivered State version; it
is not a synthetic withdrawal. The subscription is not a materialized view or
transition feed, emits no Current-to-None event when no Current version exists,
and does not dynamically mutate static `NodeConfig` network interests.

This receipt moves exactly `DM-5.1-01` and `DM-5.2-02` from
`implemented-uncredited` to `observed-bounded`. It strengthens, without another
status movement, `DM-5.2-06`, `DM-5.2-07`, `DM-5.2-08`, `DM-5.2-15`,
`DM-5.5-02`, `DM-6-06`, `DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-16`,
`DM-7-17`, and `DM-7-18`. The earlier mutable v2 receipt remains primary for
`DM-1-05`, `DM-5.1-02`, `DM-5.2-01`, `DM-5.2-09`, `DM-5.3-01`, and
`DM-5.3-02`. This receipt does not move or replace those rows and does not
credit `DM-7-20` or any `DM-8` row.

## Selected live Record subscription retained receipt

On 2026-08-27, the selected whole-key Record delivery boundary at signed source
commit `0c1134411953f4bb52133b50aff9989cd4ce3930` and tree
`f809e85bd7cfc69557821f080218274cb50d5ec2` passed the
`aster-selected-live-record-subscription-receipt/v1` contract. The source
signature verified Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The checked-in canonical
[`aster-selected-live-record-subscription-receipt/v1` receipt](evidence/selected-live-record-subscription-0c11344.json)
is exactly 10,357 bytes with SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`.
The source-bound checker is 88,222 bytes with SHA-256
`758998810af88b3a5a11d334ee9c3a51fa71f638625363f210b57642cb39bef5`;
the independent fail-closed oracle is 77,282 bytes with SHA-256
`fc57eaff5123e22c2d497630ca3edf6f2bcc7e7e772ce41862c8bc4f3cdac0e0`.

The exact Cargo release build was:

```text
cargo build --release --locked -p aster-node --example live_record_subscription_acceptance
```

The copied executable is 12,717,856 bytes with SHA-256
`6b60b118a2a6f64eec0c3b119e3fb8e69bee638453cacf5b94b95a38660b9fb3`.
Its exact run exited zero. Stdout is 44,278 bytes/76 lines with SHA-256
`756ccb39d19b75b50713bbc3fe1f67634dbd80ba3dd3416cd877642a6d30b588`
and contains seven READY, eight CONTACT, six STOP, and two child-coordination
records; stderr is exactly empty. The private 53-record transcript is 19,519
bytes with SHA-256
`c351ee63f4557326666e45371ef155a90fde3aa183fe3053f081a4811748ccc1`.
The canonical receipt excludes participant, object, subscription, path, port,
PID, and token values; payloads and tokens appear only through SHA-256
commitments.

The retained acceptance facts are exact and bounded:

- Two participants use distinct carrier and mission identities under one
  authority with disjoint mission bindings and reciprocal expected-peer
  bindings. Seven actor lifetimes span three OS processes with at most two
  actors/processes live: six stop gracefully, while the parent sends the first
  receiver child `SIGKILL` after its durable attempt-one conflict poll is
  flushed but before acknowledgement. The fresh attempt-two child is a distinct
  process, and both participant binds are reacquired after final shutdown.
- Five Record publications cover the peerless singleton, direct two-head
  conflict and selector controls, and explicit resolution successor. The one
  connected phase emits positive direct-only zero-error contacts and aggregates
  exactly three offers, fetches, and inserts with zero duplicates and zero
  Event, control, or Blob activity.
- One application subscription is inserted once and durably replayed five
  times. Seven polls produce four deliveries and three empty results. The first
  delivery is a peerless Current tombstone left unacknowledged. Later polls emit
  exactly one complete edit/tombstone conflict at `delivery_limit=1` and
  `scan_limit=16`; `has_more=false`, Superseded plaintext is absent, and no
  resolution guard is exposed. Attempt one is flushed before SIGKILL and a fresh
  process emits the same projection at attempt two.
- Record acknowledgement tokens are exactly 89 bytes but remain opaque and
  excluded. Attempt two rotates the token while durable storage restores the
  attempt-one token for acknowledgement. Exact acknowledgement and
  reacknowledgement are idempotent; malformed, wrong-subscription,
  wrong-projection, and retired-singleton tokens fail closed, while exact
  already-acknowledged conflict work remains idempotently reacknowledgeable.
- Delivery sibling IDs are complete and non-authorizing. They do not disclose
  or grant access to hidden policy lineage, and the delivery never carries a
  `RecordResolutionGuard`. A fresh exact query returns the two-head guard;
  explicit resolution inserts once, its exact retry is noninserting, and the
  successor is delivered at attempt one under a new projection. Both retired
  siblings remain recoverable only through an explicit include-superseded
  query.
- Network interest and application subscription are separate static surfaces.
  Network-interested application-unmatched beta reaches receiver storage but
  is not delivered; application-matched network-uninterested gamma remains
  withheld. Subscription insertion and replay do not mutate `NodeConfig`.
- The final immediate peerless reopen replays the subscription, resolves the
  successor as Current, returns both retired siblings only as Superseded query
  history, preserves beta/gamma separation, and yields an empty delivery poll.
  Final receiver subscription statistics are exactly one subscription, zero
  pending, one acknowledged row, one cursor, and generation one; the two
  distinct successful acknowledgement operations remain transcript-bound.

The owner-restricted raw root remains outside source control. Its seven
directories are mode `0700`; its exact inventory has 11 one-link regular files
with no aliases. The two mission bundles, two identity keys, and two redb stores
are checked only as metadata. The checker never opens, reads, or hashes their
contents. This retained root may contain credentials or identity-bearing data
and must not be committed or treated as the public receipt.

A new capture requires a fresh exclusive raw-root path, a clean checkout at a
good-signed source commit, and the repository-pinned Python 3.13.7 and Rust
1.97.1 runtimes. Select those runtimes from a neutral directory, then execute
the source-bound tools by absolute path:

```sh
ASTER_SOURCE=/path/to/clean-good-signed-aster-source
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
mise exec python@3.13.7 rust@1.97.1 -- python3 "$ASTER_SOURCE/tools/run-selected-live-record-subscription.py" \
  --source "$ASTER_SOURCE" \
  --raw-root /private/tmp/aster-selected-live-record-subscription-new

install -d -m 700 /private/tmp/aster-live-record-subscription-projection
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-record-subscription-receipt.py" - \
  --raw-root /private/tmp/aster-selected-live-record-subscription-new \
  --source "$ASTER_SOURCE" \
  --output /private/tmp/aster-live-record-subscription-projection/selected-live-record-subscription-receipt.json
```

Replaying the checked-in projection requires the externally retained raw root
and a separate clean checkout detached at the exact signed source commit. The
receipt postdates the signed source freeze, so pass both paths explicitly:

```sh
ASTER_SOURCE=/path/to/aster-source-detached-at-0c1134411953f4bb52133b50aff9989cd4ce3930
ASTER_RECEIPT=/absolute/path/to/current-aster-checkout/docs/validation/evidence/selected-live-record-subscription-0c11344.json
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-record-subscription-receipt.py" \
  --raw-root /path/to/retained/selected-live-record-subscription-raw-root \
  --source "$ASTER_SOURCE" \
  "$ASTER_RECEIPT"
cd "$ASTER_SOURCE"
"$ASTER_PYTHON" tools/test-selected-live-record-subscription-receipt.py
```

The source-to-binary-to-execution link is operator-attested, not cryptographic
or reproducible-build proof, and the selected admitted source list is not a
complete reproducible build closure. Record causal observation and publication
order are producer-attested and checker-bound rather than independently
observed. This is one-host, same-implementation, direct-loopback evidence with
two participants; participant secret artifacts are metadata-only evidence. The
forced SIGKILL is not power-loss or filesystem-crash recovery, and the final
reopen is one immediate observation rather than a long retention, compaction,
or garbage-collection interval.

This receipt does not claim hidden-lineage disclosure or authorization,
distinct physical hosts, physical IP, NAT or Internet traversal, a controlled
or public relay, BTLE, mixed implementations or carriers, scale beyond two,
resource thresholds, long-duration soak, Event/State/Blob application
acceptance, finite TTL/retention/expiry/compaction/GC, automatic registered
merge or resolution, a reproducible build, a release artifact, production
authorization, or operational readiness.

This receipt moves exactly `DM-5.1-08` from `implemented-uncredited` to
`observed-bounded`, producing totals of 44 `implemented-uncredited`, 83
`observed-bounded`, and 221 `open`. It strengthens, without another status
movement, `DM-5.2-02`, `DM-5.2-06` through `DM-5.2-09`, `DM-5.2-15`,
`DM-5.3-06` through `DM-5.3-10`, `DM-5.5-02`, `DM-6-02`, `DM-6-06`,
`DM-7-11`, and `DM-7-14` through `DM-7-18`. `DM-7-11`, `DM-7-14`,
`DM-7-15`, and `DM-7-18` remain `implemented-uncredited`; `DM-7-20` remains
unchanged. It adds no credit to automatic merge `DM-5.3-05`, replay/freshness
`DM-6-23`, disconnected-edit acceptance `DM-12-04`, any `DM-8` row, or any
TTL/GC, physical/mixed, scale/resource, product-release, or authorization gate.

## Selected live Blob subscription retained receipt

On 2026-08-27, the selected exact-publication Blob delivery boundary at signed
source commit `26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1` and tree
`1a788cd628422f141e54fc7c0583559ce70663ea` passed the
`aster-selected-live-blob-subscription-receipt/v1` contract. The source
signature verified Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The checked-in canonical
[`aster-selected-live-blob-subscription-receipt/v1` receipt](evidence/selected-live-blob-subscription-26e0a09.json)
is exactly 10,269 bytes with SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`.
The source-bound checker is 73,310 bytes with SHA-256
`2068c8ac41ccc0fadebfb41184872589bb70be199c77ea95de36c426c60ab269`;
the independent fail-closed oracle is 41,865 bytes with SHA-256
`e9121b10c38865caf8b8dadfcd899cd02c995f48f32c2320599e1e9e29ffda47`
and passes 13 tests covering 61 rejection mutations.

The exact Cargo release build was:

```text
cargo build --release --locked -p aster-node --example live_blob_subscription_acceptance
```

The copied executable is 12,812,960 bytes with SHA-256
`ef54a48dfdedf528faec6f7a9543cf73f8590a20b570effe8f6fc8d428bbc01f`.
Its exact run exited zero. Stdout is 23,086 bytes/44 lines with SHA-256
`53da1012615e008c69a6f5c15a15fa4fc43e567594cf14450b145b8799f33e1e`
and contains four READY, zero CONTACT, three STOP, and two child-coordination
records; stderr is exactly empty. The private 35-record transcript is 11,880
bytes with SHA-256
`4a72e57e137c02d5638660f0a13a6b86971ceef5c16fad91e378f13efc1e1fdd`.
The canonical receipt excludes participant, publication, Blob, subscription,
path, process, and token values; payloads and opaque tokens appear only through
SHA-256 commitments.

The retained acceptance facts are exact and bounded:

- One participant on one host uses one carrier identity, mission identity, and
  authority domain. Four actor lifetimes span three OS processes with at most
  two processes and one actor live concurrently. Three lifetimes stop
  gracefully; the parent sends the first receiver child `SIGKILL` after its
  durable attempt-one poll is flushed but before acknowledgement, and no STOP
  record is accepted for that child.
- Two distinct exact source publications have counters and acceptance markers
  one and two but share one immutable `BlobId`, one finalized capability-bound
  depot variant, and one committed ciphertext chunk of 207 bytes. Both remain
  independent delivery identities. Delivery is authenticated metadata only;
  the acceptance run neither delivers plaintext nor exercises the separate
  exact-publication read surface.
- One application subscription is inserted once and durably replayed four
  times. Five polls produce two unique deliveries, three delivery attempts,
  and two empty results at `delivery_limit=1` and `scan_limit=16`. The first
  publication is flushed unacknowledged at attempt one, redelivered by the
  fresh process at attempt two, and then acknowledged; the second publication
  is delivered and acknowledged once. Both exact acknowledgements are
  idempotently reacknowledged.
- Blob acknowledgement tokens are exactly 57 bytes but remain opaque and
  excluded. Attempt-two redelivery rotates the token. The owner-only handoff
  artifact restores the earlier attempt-one token after process replacement;
  that earlier token remains valid during the same pending tenure for exact
  acknowledgement and reacknowledgement. Malformed and wrong-publication
  tokens fail closed, and the handoff artifact is fsynced before termination
  and removed after use.
- Conflicting reuse of the durable subscription identity is rejected without
  selector change. This receipt does not include a withheld publication and
  does not claim selector-withholding or network-interest separation.
- The final immediate peerless reopen replays the subscription and yields an
  empty delivery poll. Final local ledger statistics are exactly one
  subscription, zero pending deliveries, two acknowledged deliveries, two
  cursors, and selector generation one. These are local ledger counts, not
  contact, transfer-progress, synchronization, convergence, or peer status.
- Every phase is peerless: contacts, contact errors, offers, fetches, inserts,
  Blob ranges/bytes fetched, network staging bytes, and Event/State/Record/
  control activity are all zero. Store inspection binds two Blob publications
  and operations, the one finalized variant/chunk, no pending Blob, and empty
  non-Blob namespaces.

The owner-restricted raw root remains outside source control. Its seven
directories are mode `0700`; its exact inventory has 10 one-link regular files
with no aliases. The mission bundle, identity key, redb store, depot owner
marker, finalized variant, and committed ciphertext chunk are checked only as
metadata. The checker never opens, reads, or hashes their secret or ciphertext
contents. This retained root may contain credentials or identity-bearing data
and must not be committed or treated as the public receipt.

A new capture requires a fresh exclusive raw-root path, a clean checkout at a
good-signed source commit, and the repository-pinned Python 3.13.7 and Rust
1.97.1 runtimes. Select those runtimes from a neutral directory, then execute
the source-bound tools by absolute path:

```sh
ASTER_SOURCE=/path/to/clean-good-signed-aster-source
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
mise exec python@3.13.7 rust@1.97.1 -- python3 "$ASTER_SOURCE/tools/run-selected-live-blob-subscription.py" \
  --source "$ASTER_SOURCE" \
  --raw-root /private/tmp/aster-selected-live-blob-subscription-new

install -d -m 700 /private/tmp/aster-live-blob-subscription-projection
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-blob-subscription-receipt.py" - \
  --raw-root /private/tmp/aster-selected-live-blob-subscription-new \
  --source "$ASTER_SOURCE" \
  --output /private/tmp/aster-live-blob-subscription-projection/selected-live-blob-subscription-receipt.json
```

Replaying the checked-in projection requires the externally retained raw root
and a separate clean checkout detached at the exact signed source commit. The
receipt postdates the signed source freeze, so pass both paths explicitly:

```sh
ASTER_SOURCE=/path/to/aster-source-detached-at-26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1
ASTER_RECEIPT=/absolute/path/to/current-aster-checkout/docs/validation/evidence/selected-live-blob-subscription-26e0a09.json
cd /private/tmp
ASTER_PYTHON="$(mise where python@3.13.7)/bin/python3"
"$ASTER_PYTHON" "$ASTER_SOURCE/tools/check-selected-live-blob-subscription-receipt.py" \
  --raw-root /path/to/retained/selected-live-blob-subscription-raw-root \
  --source "$ASTER_SOURCE" \
  "$ASTER_RECEIPT"
cd "$ASTER_SOURCE"
"$ASTER_PYTHON" tools/test-selected-live-blob-subscription-receipt.py
```

The source-to-binary-to-execution link is operator-attested, not cryptographic
or reproducible-build proof, and the selected admitted source list is not a
complete reproducible build closure. Blob publication order, store inspection,
and fsync timing are producer-attested and checker-bound rather than
independently observed. This is one-host, peerless, same-implementation evidence
with one participant; secret and ciphertext artifacts are metadata-only
evidence. The forced `SIGKILL` is not power-loss or filesystem-crash recovery,
and the final reopen is one immediate observation rather than a long retention,
compaction, or garbage-collection interval.

This receipt does not claim network contact, transfer, synchronization,
convergence, or peer status; distinct physical hosts; physical IP, NAT or
Internet traversal; a controlled or public relay; BTLE; selector withholding
or network-interest separation; policy, rekey, revocation, or route-interest
mutation; mixed implementations or carriers; scale beyond one participant;
resource thresholds or long-duration soak; Event/State/Record live-application
acceptance; Blob plaintext delivery or exact-publication read; finite TTL,
retention, expiry, compaction, or garbage collection; a reproducible build; a
release artifact; production authorization; or operational readiness.

This receipt moves exactly `DM-5.3-04` from `implemented-uncredited` to
`observed-bounded`, producing totals of 43 `implemented-uncredited`, 84
`observed-bounded`, and 221 `open`. It strengthens, without another status
movement, `DM-5.1-10`, `DM-5.1-11`, `DM-5.1-22`, `DM-6-02`, `DM-6-06`,
`DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-16`, and `DM-7-18`. It changes no
`open` row and adds no credit to network or selector separation, peer status,
TTL/GC, plaintext/read or resource behavior, physical/mixed operation, scale,
release acceptance, or authorization gates.

## Selected live Blob retained receipt

On 2026-08-27, the selected live Blob composition at signed source commit
`044d90ff07c8e754b3d490cb810d42de3c915e3d` and tree
`8a2d0ebc38c9786660de0909b9df3d5defea1c08` passed the
`aster-selected-live-blob-receipt/v2` contract. The source signature verified
Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The checked-in canonical
[`aster-selected-live-blob-receipt/v2` receipt](evidence/selected-live-blob-044d90f.json)
is exactly 10,728 bytes with SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`.
It explicitly supersedes the earlier v1 observation. The source-bound checker
is 138,046 bytes with SHA-256
`11b51c4ac91bb1819e3e1cfc8540e609dfdb90ea36b78d22f5f0c84818560aef`;
its fail-closed adversarial corpus passed 45/45.

The exact Cargo build command was:

```text
cargo build --release --locked -p aster-node --example live_blob_acceptance
```

The copied Cargo release-profile executable is 12,246,960 bytes with SHA-256
`e057c2046754de2fb0485b288b383031c49bbd05b96d34247bb72cefbdbcddb8`.
The exact run exited zero. Its stdout is 83,642 bytes/135 lines with SHA-256
`67dc8022901418beb406d409aebf7f35b7d7a4b76c126882a24cf263d66bab88`;
stderr is exactly empty. Stdout contains 11 READY, 32 CONTACT, and 11 STOP
records. The private raw 81-record transcript is 31,969 bytes with SHA-256
`bedf7b59d73ae4ec0664f1f18cd85065bebdaba98945dc1b832bdb5c29578df4`.
That transcript contains exact participant and object identifiers and remains
inside the owner-restricted raw root. The canonical public receipt excludes
those identifiers, paths, ports, PIDs, source bytes, plaintext payload bytes,
and ciphertext; the payload appears only through fixed metadata and SHA-256
commitments.

The retained acceptance facts are exact and bounded:

- Three participants used three distinct carrier identities and three distinct
  mission identities under one common authority with disjoint mission identity
  bindings and all six directed reciprocal expected-peer bindings.
- Eleven actor lifetimes ran across seven phase barriers: peerless publication,
  direct publisher-to-replica seeding, one-contact publisher-to-receiver
  partial transfer, peerless receiver reopen, one-contact replica-to-receiver
  continuation, replica-to-receiver finish, and final peerless receiver reopen.
  At most two actors ran concurrently. All 11 shut down gracefully, all 11
  retained handles closed with `StateUnavailable`, all three binds were
  reacquired, and every peerless/reopen phase recorded zero contacts. The
  interruption and reopens are actor/store/provider transitions within one OS
  process, not process-crash or power-loss recovery.
- The peerless publisher committed one 98,304-byte (96-KiB) Blob with payload
  SHA-256
  `8609fd29a7c72634fe10beaab26ab44441a97abf85fa428cba0898c69e1ed524`,
  counter and acceptance marker one, and exactly two canonical chunks. One
  exact publication retry inserted nothing. One changed-payload reuse returned
  Conflict and preserved the original publication.
- The publisher, seeded replica, completed receiver, and final reopened receiver
  each returned two exact pages: 65,536 bytes at offset zero with SHA-256
  `1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a`,
  then 32,768 bytes at offset 65,536 with SHA-256
  `256acbd5fca30ff42275d172630103a1f6f087426ead5881fe07e2a7fef2974f`.
  The eight pages and four whole-read commitments equal the original payload.
  Reads during the partial phase and first receiver reopen instead returned the
  typed unavailable result while ordinary publication remained hidden.
- All 32 connected `CONTACT` records were positive, direct-only, and error-free.
  The seeded replica fetched eight ranges and 98,638 carrier bytes. The
  receiver's one publisher contact fetched one 16,384-byte carrier range plus
  the source and retained exactly a non-public 16,384-byte prefix. Typed Store
  inspection after graceful shutdown and peerless reopen proves the same source,
  staging fingerprint, prefix object/index/length, exact next complement, and
  carrier total.
- One contact with the different eligible replica fetched no source and exactly
  one additional 16,384-byte carrier range, preserving the first prefix and
  advancing it to 32,768 bytes while publication remained unavailable. The
  finish phase fetched six ranges and 65,870 bytes. Exact contact-to-STOP
  aggregation reconstructs 16,384 + 16,384 + 65,870 = 98,638 carrier bytes,
  equal to the seed, before whole-Blob promotion. The receipt validates
  remaining-work accounting but deliberately does not retain
  `blob_remaining == 0` as completion proof; authenticated publication, typed
  prefix state, depot completion, whole-read, and page commitments establish
  the result.
- Every participant's final inventory has one publication, one acceptance
  marker, one finalized variant, and two committed chunks. Committed and
  reserved ciphertext file bytes are exactly 98,642 per participant. Event,
  State, Record, and control counters are zero throughout this Blob-only
  scenario.
- The producer reports removal of two application source files plus
  parent-directory synchronization before transfer. Transcript timing and this
  ordering, plus the typed intermediate Store inspection, are producer-attested
  rather than independently timed by the projector, and file removal is not
  physical sanitization or secure erasure.

The complete raw root remains outside source control in owner-restricted custody
on the validating host. Its exact inventory contains 15 directories and 23
regular one-link files with no aliases, including three participant directories,
three mission artifacts, three identity keys, three mesh databases, three depot
owner markers, three Blob variants, and six ciphertext chunks, exactly two
chunks and 98,642 ciphertext bytes per participant. Participant secret and
ciphertext files are validated by metadata only; the checker never opens, reads,
or hashes their contents. The raw root may contain credentials, exact
identifiers, or ciphertext and must not be copied into documentation, committed,
or treated as the public receipt.

Future review must use a separate clean checkout detached at the exact signed
source commit because this evidence/documentation commit is a descendant. With
the retained raw root available, replay the checked-in receipt byte-for-byte:

```sh
python3 tools/check-selected-live-blob-receipt.py \
  --raw-root /path/to/retained-owner-only-raw-root \
  --source /path/to/aster-source-worktree-detached-at-044d90ff07c8e754b3d490cb810d42de3c915e3d \
  docs/validation/evidence/selected-live-blob-044d90f.json
```

The source-bound producer is 88,859 bytes with SHA-256
`7db492f839e6fb5fbb211772a1b3a6dbf82c2e708af1d5fad99503b63f876b11`;
the runner is 22,194 bytes with SHA-256
`a2038160655d49bd5c778fd22835f416ca07f28250bdb064134063a135a88b25`;
the checker is 138,046 bytes with SHA-256
`11b51c4ac91bb1819e3e1cfc8540e609dfdb90ea36b78d22f5f0c84818560aef`;
and the adversarial test source is 91,717 bytes with SHA-256
`9128bffc43a96d77e37a2be49ccc54117893e91ea5cfab03ef07ccaef7daa567`.
The source-to-binary-to-execution link is explicitly operator-attested, not
cryptographically proven, and the admitted source list is not a complete
reproducible build closure.

This receipt claims only one-host loopback, same-implementation,
three-participant direct-Iroh graceful interruption/reopen and different-peer
continuation for one small live Blob. It does not claim distinct physical hosts,
NAT or Internet traversal, controlled/public relay, BTLE, arbitrary-peer or
route-only Blob resume/custody, independent-implementation interoperability,
scale beyond three participants, resource thresholds or long-duration soak,
Event/State/Record live acceptance, process-crash or power-loss recovery,
physical source sanitization, long-offline recovery, retained Blob-delivery
acceptance or Blob peer/convergence status,
Blob TTL/GC, a reproducible build, a product release, or release authorization.

Across v1 and v2, `DM-5.1-10` through `DM-5.1-13`, `DM-5.2-19` through
`DM-5.2-22`, and `DM-7-16` are now `observed-bounded`. The prior v1 receipt
had already moved `DM-5.1-10` through `DM-5.1-12` and `DM-7-16`; v2 newly
moves exactly `DM-5.1-13` and `DM-5.2-19` through `DM-5.2-22` from
`implemented-uncredited` to `observed-bounded`. It changes no `open` row.
`DM-5.3-04`,
`DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-18`, `DM-9-13`, and `DM-9-14`
remain `implemented-uncredited`; `DM-7-17` and `DM-7-20` were already
`observed-bounded` and gain no second status movement.

## Selected Linux Event custody retained receipt

On 2026-08-27, the selected Linux Event custody composition at signed source
commit `ade6ee1839997e14f479463d724e208a89ec8b89` and tree
`c12cc444edd3a1a40da53972b6d6edbcfbddeffd` passed the
`aster-selected-linux-event-custody-receipt/v1` contract. The source signature
verified Good for ED25519 fingerprint
`SHA256:wDJcS5jorC5+Dm3vvXdMrW/f38sqIl20hJXrt5B8s9E`. The checked-in canonical
[`aster-selected-linux-event-custody-receipt/v1` receipt](evidence/selected-linux-event-custody-ade6ee1.json)
is exactly 4,377 bytes with SHA-256
`a3ef10dc404795165cc6117041bf2fe060c42345ce2fd41efd940b0d5c981d10`.
The receipt was projected twice from the same retained raw root and exact signed
source and compared byte-for-byte. The source-bound checker adversarial corpus
passed 12/12; the pre-existing live Event checker corpus also remained 51/51.

The runner independently materialized the signed tree with `git archive`,
mounted that materialization read-only, and built the locked release example in
the pinned `linux/arm64` image
`rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`.
Dependency download required the explicit operator build-network flag; this is
not an offline or reproducible build. Execution used a distinct read-only
binary copy, a read-only container root, Docker network-none with only container
loopback available, non-root identity, all capabilities dropped,
no-new-privileges, a private cgroup
namespace, one CPU, one GiB memory with no additional swap, 128 PIDs, and a
bounded owner-only noexec tmpfs. The runtime binary is 12,285,216 bytes with
SHA-256
`af921351d6363e9c7bf25eb7482af85c4258c93fc680cb3115629100465f4b5b`.
The source-to-binary-to-execution link remains explicitly operator-attested,
not cryptographically proven or reproducible.

The exact runtime exited zero under one Linux aarch64 OrbStack kernel. It
reported `arch_sys_counter` and used suspend-inclusive Linux `CLOCK_BOOTTIME`
for finite Event custody. Stdout is 25,631 bytes with SHA-256
`23b0ea06b27ee5e09bcf3144637ff4e2c964e61429bf692fdea1794cc5924c71`;
stderr is exactly empty. The private 29-record transcript is 6,986 bytes with
SHA-256
`d386dc854558b8e3ea0ea1f7243a423049eadfb6f65473fd05e15e367d71fe74`.
The public receipt excludes participant identities, Event IDs, paths, ports,
PIDs, boot identity, and payload bytes; payloads appear only as SHA-256
commitments.

The retained acceptance facts are exact and bounded:

- Three actors used distinct carrier and mission identities: one content member
  origin, one route-only relay, and one content member receiver. The relay had
  one stopped Carry selector and the receiver one stopped Consume selector for
  the exact topic and scope.
- The peerless origin published six authenticated Events: one already-expired
  finite Flash Event, one finite Flash Event intended to expire at the relay,
  and durable Flash, Immediate, Priority, and Routine Events. Priority and TTL
  remained independent authenticated fields.
- Before the first contact, Linux custody maintenance collected the first
  expired Event. The origin then initiated one `AtLeast(Priority)` contact with
  the ReceiveOnly relay. Exactly four unexpired Events at or above Priority
  entered route-only custody; the authenticated Routine Event was withheld.
  The relay retained no content-readable Event and, while operating in
  ReceiveOnly, initiated no contact.
- The origin runtime stopped after that contact. During the later
  relay-to-receiver contact the origin runtime was inactive, although its prior
  UDP socket remained held; the receipt therefore does not prove direct
  connectivity to the origin was impossible.
- The relay reopened under the original four-item exact-scope quota and Linux
  `CLOCK_BOOTTIME` expired the second finite Flash Event. A separate explicit
  stopped-store pressure request retired exactly one lower-priority RouteEvent,
  the durable Priority Event. The store then persisted a two-item replacement
  quota before reopen. This is explicit stopped-store pressure followed by
  quota replacement, not automatic eviction caused by lowering a quota or
  automatic startup downsizing.
- The reopened relay held exactly two route-only Events under the two-item,
  one-MiB exact-scope quota. It initiated one Normal contact with the
  ReceiveOnly receiver and forwarded exactly the surviving Flash and Immediate
  Events. The receiver's exact poll returned Flash first and Immediate second.
  Neither expired Event, the pressure-retired Priority Event, nor the
  threshold-withheld Routine Event appeared at the receiver.
- While each downstream actor operated in ReceiveOnly, the retained receipt
  records zero initiated contacts and zero disclosed local Event data, State,
  Record, Blob, or control objects. Required authentication, acknowledgements,
  and apply results remain permitted, so this is not physical RF silence.
- Final inspection retained the expiry and pressure retirement fences, exactly
  two route items at the relay, and exactly two content Events at the receiver.
  Legacy, State, Record, Blob, and control namespaces remained exactly zero.

The checked-in receipt contains no raw identifiers or secret contents. The
complete raw root used for projection remains outside source control in
owner-restricted custody on the validating host. Its validated public inventory
is nine directories and 16 files: three participant directories, three mission
artifacts, three identity artifacts, and three stores plus the bounded public
run artifacts. Participant secret contents were checked by metadata only and
were never opened, read, or hashed by the checker. The raw root may contain
credentials and exact identifiers and must not be copied into documentation,
committed, or treated as the public receipt.

Future review must use a separate clean checkout detached at the exact signed
source commit because this evidence/documentation commit is a descendant. With
the retained raw root available, replay the checked-in receipt byte-for-byte:

```sh
python3 tools/check-selected-linux-event-custody-receipt.py \
  --raw-root /path/to/retained-owner-only-raw-root \
  --source /path/to/aster-source-worktree-detached-at-ade6ee1839997e14f479463d724e208a89ec8b89 \
  docs/validation/evidence/selected-linux-event-custody-ade6ee1.json
```

The source-bound producer is 83,534 bytes with SHA-256
`2f1badb80ff0326d100b20ec331447ac773c315844341b5bfa5dad10d74dee5c`;
the runner is 27,987 bytes with SHA-256
`e199ea17bf7a5ae944d0bb023993311890125d2216fdfb6b2db432f6ee83d40e`;
the checker is 59,030 bytes with SHA-256
`e7df18f7e553c72b4121d70ac12250187761ec9398446264432a92d1213fc49f`;
and the adversarial test source is 20,320 bytes with SHA-256
`edcfb6da4207615fa9ef9cf623d2cb17304fae6be1769db43712af097b6c8b5c`.
The admitted manifest covers 26 exact source files, but it is not a complete
reproducible-build closure.

This receipt moves `DM-5.4-05`, `DM-5.4-09`, `DM-5.4-12` through
`DM-5.4-16`, `DM-5.4-18`, `DM-5.4-22`, `DM-5.5-07`, `DM-9-24`, and
`DM-9-25` from `implemented-uncredited` to `observed-bounded`; moves
`DM-12-06` and `DM-12-07` from `open` to `observed-bounded`; and supports the
equivalence corrections moving `DM-11-13` and `DM-11-16` from `open` to
`implemented-uncredited`. It gives no additional credit to `DM-5.4-10`,
`DM-5.4-11`, `DM-5.4-17`, `DM-5.4-19`, `DM-5.4-21`, `DM-5.7-03`,
`DM-11-15`, `DM-11-17`, or `DM-12-05`.

The bounded result is one container, one kernel, one implementation, three
actors, two direct loopback contacts, one scope/topic, six Events, and a short
operator-staged schedule. It does not claim a negotiated protocol-version
observation, distinct physical hosts, constrained or impaired physical links,
NAT or Internet traversal, controlled/public relay, BTLE, suspend injection,
long partitions, process crash or power-loss recovery, generalized global or
cross-class eviction, State/Record/Blob custody or TTL, physical storage
accounting, mixed-implementation interoperability, scale, a reproducible build,
a product release, global convergence, or production authorization.

## Prior PR-C automated evidence

PR C was pinned to these exact source identities at its own stack freeze:

This freeze predates semantic v4 and v5; the current v5 source tree and its
separate bounded network evidence do not relabel it as current evidence.

```text
2ad1b080bfed2ba654b0d29c0cd6eab5f1eb6f4799dbb09203dc18a085b713d0  crates/aster-node/src/application.rs
81021e226bd413826e3afcea6adf7e8c6e0f22f547f59631a30238e1a015c6c2  crates/aster-node/src/runtime.rs
b3a684b32b474c5ee22d1c24e0e7bdb19ff2f9613ca42cf3cdf3ebda5262476c  crates/aster-node/src/lib.rs
e31a456a98950d5439b3b6ecd6492f0cbdfb50ad827856c97041b9645d278f82  crates/aster-node/examples/live_event_application.rs
59c858c0bc559944546e88eefee550523fd64905e4b2779a9a3d1a7eb2b8ce0e  crates/aster-node/tests/mesh_cli.rs
364e5a1d8d7f7b24ab75afe8ec2791023db83b11997bd07722c7d107a16a6a00  crates/aster-redb-store/src/lib.rs
```

At that PR-C freeze, the exact-byte gates included every-target `cargo check`,
Clippy with warnings denied, Rust formatting, and `git diff --check`. The
application module had seven passing tests. Focused runtime tests cover the
peerless live Event lifecycle, shutdown and live-zeroization admission closure,
rejection of an overflowing `run_for` before readiness or state mutation, queued
zeroization ahead of an already elapsed deadline, a nonzero operational window
under saturated application callers, and authenticated contact/status progress
under saturated callers plus continuously overdue one-nanosecond ticks. The
current-toolchain selected-code suite passed 499 of 499 tests: 336 core, 68
node-library, six node-binary, 13 `mesh_cli`, and 76 selected-store tests; the
examples had no tests.

A later timeout-only hardening gave the offline cell one shared 40-second
cold-start deadline across retries and kill/reap cleanup on publisher spawn
failure. Against the final test bytes, that exact Unix offline
publish, later authenticated synchronization, poll/acknowledge, and
receiver-restart cell then passed twice on the current toolchain and three
times on Rust 1.91.

The separate exact-tree Rust 1.91.0 matrix then passed 499 of 499: core 336/336
(126.48s), node library 68/68 (28.43s), node binary 6/6 (0.02s), `mesh_cli`
13/13 (148.26s), and selected store 76/76 (31.81s); the examples had no tests.
The current-toolchain and Rust 1.91 results are separate executions and their
timings are not pooled.

Representative focused commands and the selected CI gate are documented in
[Continuous integration](ci.md#selected-composition-coverage). The two
499-test totals above are recorded exact-tree validation results; this ledger
does not claim that the focused command excerpt is a complete transcript of
either matrix execution.

This is automated source/test evidence, not a retained execution receipt. No
PR-C root, log bundle, artifact identity, physical-system run, independent
implementation, or release artifact is claimed. `LastContactComplete` remains
only a process-local report about each active configured peer's most recent
bounded authenticated negotiation. Gap absence remains limited to freshly
verified positions already observed by the local store. Selector replacement
remains unsubscribe followed by subscribe, not an atomic update. These checks
alone do not close State/Record/Blob or any broader selected-lane capability.
The prior Blob evidence below is the historical stopped/local freeze; the newer
semantic-v5 network slice has separate current-code evidence and does not
relabel this PR-C result.

## Prior selected State and Record network automated evidence

At this prior freeze, the production-lane source ran State and Record networking
in semantic v4 and v5. The default offer was `[5, 4, 3, 2, 1]`; Event retained v1-v5
compatibility and v1-v3 contacts send, accept, reserve, and count no mutable
frames. V5 inherits the v4 State/Record behavior unchanged. In v4/v5,
class-tagged State and Record interest, inventory,
difference, Fetch/Offer, outcome, and Finish frames run after the existing
control/Event lanes. Both classes and both receiver directions are independent.
The receiver declares canonical topic/scope interests separately for each
class; empty means receive-none.

The repository-facing code/test freeze is the following exact ordered 26-file
`sha256sum` block. SHA-256 of the newline-terminated block itself is
`577a835d5bd85322bf8e5bddfc4c425446344714397ff9822f45ed4ba5482559`;
the unchanged `Cargo.lock` is
`9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f`.

```text
033b10cc48eb19e3d6e81c9942e6d7cfe2c36b3991b4a5ea67192419d638d70d  bindings/c/aster_mesh.h
e0bd3cea2d0ce1351695b1a3cce6dd571c4949a3c076874036ff0ce2cef85f4e  bindings/c/header_smoke.c
f1764b6d4aca157e7d6f477e2392d94c10705bf5ce7b4cdb03e299a25c2c3870  bindings/c/header_smoke.cpp
5736c259d932983e3cf1163a1e7a0164810acd34848d2e5993cc99f361426778  bindings/go/aster_test.go
6ed380b67e5bbbacb90c6b46aacf9b2a47d7b800f5845cc5b514f1bca5835e21  bindings/python/tests/test_binding.py
fc37299c9eb22a87b3e8b48c0d5bd9dd0abce42b75ec85f103792a4505c7a8a9  crates/aster-core/src/batch.rs
9175de40a0ab471a8e5f30f8e33daa16c6bf66af199267a044fa407ae04b905e  crates/aster-core/src/crypto.rs
cbd5452c71d9dbd2c16e636027ff852341ad8bae18fb5d822ac3ed228cccb040  crates/aster-core/src/crypto/reference.rs
e05d26baa88ae27b6473770065cbc25f006c80c38f431d3a14f06ca1cccb0861  crates/aster-core/src/lib.rs
a3011fba77c52014a63705f310adf3358b839ae158fbecb9b9db69f27237db2e  crates/aster-core/src/runtime.rs
f606f7052017bbae1e40494557098d99dac141005cc11f2dc9b6849fe7d39d7c  crates/aster-core/src/runtime/reference_semantic.rs
cf58edd83229d0f8609da5319e8a8cc82bf154cafa99981c96e0df63cb9773dc  crates/aster-core/src/source_event.rs
03ffd6e9adb5a2a0488cf76e0d9cb8f6d35ae2f2ba7d2fa263bb0dfc09abaf26  crates/aster-core/src/source_record.rs
1ccb1d8eb403a0e4f0f2901857787f80c5bed66232e7d0f60cf1fe749715a717  crates/aster-core/src/source_state.rs
57f6d237a5ee31aba7d1f6a85cfecadae8887e95670b358b95e8326bae8c0558  crates/aster-core/src/store.rs
0c1033f0a8c5d68fd3be60573a03c94881034ad8cac98baaecdbcfd5fc070c55  crates/aster-core/src/wire.rs
ab7668867ada6d31e8d929cf7fa5ebaac5d35f7a374a7e340b97b1e6192901ec  crates/aster-ffi/src/lib.rs
40479cb44dab91e8cd6332b4400dbf2f9b2054c2f5f38bc3d0ef93d1a7e1aaca  crates/aster-node/examples/custody_application.rs
c0755906768e80096f4e516812abeecf8b1c93ec9bcdb95f7d9ceebd8baa5354  crates/aster-node/src/application.rs
54410bafabd92124731c266c9e91452561b1d358ca321657b894ce4b5b7ae032  crates/aster-node/src/application/record.rs
9005b320d80782b371eccbe07f05f1b87ba82d9f0f8c78ded400afa4b77f4bd6  crates/aster-node/src/application/state.rs
b984e221ade2475ff5ce8a01702e2a6c9bb75b74ba25683f6a82352c42185a4e  crates/aster-node/src/frame.rs
bb9fafa7c25014651cb0eb58ec3631a366db553997f94994aa27bb8dc9d9a8da  crates/aster-node/src/runtime.rs
790b71ad0b51c730a2b22d91fbfd5867e9c1549576a62af67e88a8cad6637dfe  crates/aster-redb-store/src/lib.rs
2c089b401709aba7117b14e2686a7317e3bc2cdfeb9f699b7e027779252be42c  fuzz/fuzz_targets/selected_frame_decode.rs
84daaed0af0c09f1b9d73870b103d246245e9786eaaf81960f11baf055d82ecd  tools/check-implementation-requirements.py
```

The contact holds one control-policy read lease, filters both inventories
through current route/content authority and current source route lineage,
freshly verifies every source object before transfer and admission, rejects
stale/revoked/wrong-class/wrong-interest/wrong-lineage objects, and commits
remote rows idempotently under the exact current policy. A same-epoch route-key
replacement withholds historical lineage from ordinary current projection/query
and network inventory/transfer without deleting the row. Exact idempotent State
publish and Record publish/resolution retries may recover their committed
historical result only through the strict cached/projection/historical
verification path. Selected finite State/Record TTL is rejected; no mutable
forwarding-age or expiry path is claimed.

Offer returns exact `MutableApplyResult`. Fetch returns exact
`MutableFetchResult` and requires exact `MutableFetchResultAck` before another
Fetch or Finish. The tuple
binds class, direction, transfer ID, and `Inserted`, `Duplicate`, or
`DeferredCapacity` disposition. Finish/Finished bind the same exact remaining
count, including deferred work. Missing, duplicate, changed, cross-lane, or
out-of-order result/ack/finish fails the contact. `DeferredCapacity` applies
only to an otherwise-valid authenticated object blocked by effective
ordinary-aggregate or per-class item/byte capacity, the 1,024-version
per-logical-key projection bound, or the causal-frontier bound. An object over
1 MiB is structurally invalid and fatal, not deferred; integrity and policy
failures likewise remain fatal.

Each object is capped at 1 MiB and each class at 4,096 rows/16 MiB of encoded
source bytes. Existing mutable rows are not pruned. Repeated bounded contacts
rotate after a durable authenticated peer/class/local Offer/Fetch cursor. Cursor
metadata is reserved outside ordinary quota, capped at 256 configured peers and
1,024 rows, CAS-advanced only after the exact authenticated outcome, and pruned
for stale configured peers after mandatory startup proof and before sockets.
Normal and every AtLeast threshold run these lanes because AtLeast is Event-
only. ReceiveOnly initiates and discloses no mutable lane. Event last-contact
status deliberately remains separate and is not mutable convergence.

`runtime::tests::real_iroh_contact_converges_state_and_disconnected_record_siblings`
uses two independently bound redb stores and two independently authenticated
mission publishers. One publisher creates State plus Record `alpha`; the other
creates concurrent Record `bravo` for the same exact key while disconnected.
After one real direct-Iroh, hybrid-mission-authenticated contact under explicit
State/Record interests, the destination has the State and both stores have the
same two Record exact inventories and two causal heads. Ingest executes no
application merge callback. Store tests separately cover policy binding,
idempotent duplicate receipt, typed inventory, and preservation of disconnected
Record siblings without merge execution. Additional current-code real-Iroh
contacts saturate State and Record in both directions, observe exact deferral,
progress after reopen, and prove Offer/Fetch rotation prevents a fixed prefix
from starving later IDs. Focused frame/store/runtime tests cover the exact
result/ack/remaining protocol, fixed bounds, typed frontier deferral, cursor
CAS/reopen/prune/audit/terminal preservation, v1-v3 absence, policy modes, and
same-epoch current-lineage behavior.

On the current toolchain and Rust 1.91, locked all-target/all-feature workspace
check, strict Clippy with warnings denied, 17-target Rustdoc with warnings
denied, and the full all-feature workspace test matrix passed. In both full
test matrices, `aster-core` passed 385/385, `aster-node` passed 158/158 library
and 7/7 binary tests, `mesh_cli` passed 13/13 real-process tests, and
`aster-redb-store` passed 156/156; examples and doctests also passed, with one
explicit local reconciliation performance experiment ignored. The final Rust
1.91 `mesh_cli` and store cells took 160.79 and 88.49 seconds respectively.
Binding gates passed C and C++ syntax/link/runtime smoke, Python 12/12, and Go;
the conformance self-test, independent Python wire oracle, v0-r2 profile, and
162-test Python lab suite also passed.

The first full Rust 1.91 attempt hit the pre-existing intermittent
`aster-lab` `Sync(SnapshotMismatch)` volume-oracle failure. The exact failure
reproduced on untouched signed base `5cc0904d39220bdf4f70959b9ce5d190c39e11b0`,
whose test and synchronization reducer are byte-identical to this tree, and an
immediate identical base rerun passed. Isolated current and Rust 1.91 reruns and
the final full Rust 1.91 matrix all passed; no reconciliation-stability change
is attributed to this slice.

This was exact-freeze automated evidence, not a retained execution root. These
are same-implementation, one-host, two-node tests. The convergence case uses
one contact; capacity and fairness use bounded repeated contacts/reopens. They
include no long partition, complete restart/contact crash sweep,
relay/multi-hop custody, divergent State conflict, mixed implementation,
physical network, scale bracket, or release artifact.
The application State/Record handles remain stopped/exclusive; the live actor
reconciles already durable rows but exposes no live State/Record publish/query
or durable application delivery API. Because there is no retained execution
receipt, this bounded automation adds no `observed-bounded` credit.
`DM-5.1-09`, `DM-5.3-06`, and `DM-5.3-09` remain
`implemented-uncredited`, and all row statuses remain exactly as generated by
the requirements checker.

## Prior semantic-v5 direct Blob network automated evidence

At this prior freeze, the production lane offered `[5, 4, 3, 2, 1]`. Event v1-v4 behavior and
State/Record v4 behavior are inherited unchanged by v5; v1-v4 emit, accept,
reserve, and count zero Blob frames. Stable wire/profile and ABI remain version
1, and the established source envelopes, canonical manifests, strict kind-2
carrier IDs, and `ASTRBT01` carrier bytes are unchanged.

The repository-facing code/test freeze is the following exact ordered 16-file
`shasum -a 256` block. SHA-256 of the newline-terminated block itself is
`f234ea83859a24adbcc100bb7e655b80c35c1a13511a6d5c97cc4dcea28cd220`.

```text
ee531438eb5475fad73ea5cbb6ed5322e4abc4bc4ca1281690b9a9e52f80c02b  crates/aster-core/src/blob.rs
8d842cca04b46ed4c975251a45e3bebb428064b6cec3216754dd53fa126bc5c4  crates/aster-core/src/source_blob.rs
868b9f83c3dee97ca902aec06868ed12144f1af60aeb453ab64048ff4a68f50b  crates/aster-core/src/crypto.rs
5caeed2687c492603158a43160ae6df4019b060a4598b7f943b26aa675975288  crates/aster-core/src/crypto/reference.rs
97453907a0c93534354f5b9b2e0683622c359e6ca30feafa079a3ea57236d9a9  crates/aster-core/src/lib.rs
1cc175946855dde60e6bb81e15355cef80d098b649463ea101c81f5e9ff18cab  crates/aster-core/src/store.rs
7b2932a6a9e550403f10a99da6898eb8496f42915ced2acd37c50e0d7d246e16  crates/aster-core/src/wire.rs
8f8969b9a597a56fabd7732936914c562b6eba1dab9d020e872ba0f159d3c1fc  crates/aster-node/src/application.rs
3e927e158cebbfc204fc68d9449721f05cbf77429d792115a4f15e08985077c3  crates/aster-node/src/frame.rs
bd7b931b61a3b453e1ddecf072cae5bf4913643b15fd027ebca97e9656f884e4  crates/aster-node/src/main.rs
bd03bcbac1b0a4818b3fd5d7b969c032f43dbe73785f563098d44c23fe60c91c  crates/aster-node/src/runtime.rs
44e75e2f94dc2fac7fbacfc69f4ac6e74f4c4308db280d3bf8ee4e48e3dbc493  crates/aster-redb-store/src/blob.rs
0ac3920e942bafbffb0e61f6553cc46c50f359856df2784959a451a4abe942a5  crates/aster-redb-store/src/blob/depot.rs
6f883effa427a2bc07f141f58064a8f53247067b08a83f2be5f4b344201b468c  crates/aster-redb-store/src/lib.rs
bb63d3f7d11438eada510fb684a2dbe3984d9f384a3f1346a778f5e42149034f  fuzz/fuzz_targets/selected_frame_decode.rs
9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f  Cargo.lock
```

Core source-Blob tests passed 7/7. In particular,
`blob_peer_content_proof_is_exact_current_and_identity_bound` accepts only the
correct authenticated claimant with the current exact content grant and route,
and rejects route-only/no-content, wrong mission authority, peer, topic, scope,
epoch, same-epoch replacement, stale proof, and tampering. The schema
`schema_v14_migrates_and_v5_provenance_survives_restart` test preserves
semantic versions 1 through 4 while adding v5 provenance. The nonconstructible
transfer-plan, full-content-completion, and current-lineage capabilities bind
the exact source, manifest, canonical carriers, BlobID, physical lineage, and
mission authority without exposing content keys or raw grants.

The frame suite passed 18/18. It covers strict class-3 source identities,
kind-2 33-byte carrier IDs, canonical proof-bearing interest, bounded range,
exact Result/Ack, Finish/Finished tuple sequencing, malformed/cross-tuple
rejection, and legacy zero-Blob behavior. The maximum protected Blob interest
plaintext is 76,807 bytes and its two-frame exchange is 153,718 bytes. One
complete carrier settlement reserves 17,127 protected bytes: Fetch 123, Range
at most 16,480, two Result/Ack frames of 92, two Finish/Finished frames of 14,
and six 52-byte protection overheads. Finish echoes requester remaining for
sequencing; exact Result/Ack proves each accepted durable prefix, not an
independent responder assertion about receiver disk truth.

The final redb library suite passed 166/166, formatting/diff checks passed, and
all-target/all-feature Clippy passed with warnings denied. Focused tests cover
atomic invisible staging through carrier completion, freshly streamed
full-content/current-lineage promotion, ordinary and typed-frontier capacity
failure without mutation, competing reservation/reopen, terminal abort with
bounded quota-charged depot staging retained,
same-epoch `PhysicalLineageConflict`, and range service after reopen.
`network_blob_same_epoch_physical_lineage_requires_epoch_advance` now retires a
pending source and its carrier-prefix rows while retaining exactly one
unpublished import variant plus its existing finalized/chunk/file/reserved-byte
quota charge, permits exact-lineage restaging, rejects a different same-epoch
lineage without mutation, admits numeric epoch advance under the existing
bounded variant cap, and preserves the fence and quota charge through reopen.
Zero durable physical lineage is an audit failure. No table, schema, or capacity
class was added. The final cross-table/migration regressions are:

- `predecessor_nine_table_blob_schema_migrates_network_additively_with_owner_tokens`;
- `pending_blob_audit_binds_exact_manifest_route_and_carriers_on_all_open_paths`;
- `pending_blob_audit_rejects_self_consistent_missing_depot_plan_without_repair`;
- `pending_and_completed_blob_namespaces_are_exclusive_without_repair`.

Together they require an all-or-none writable nine-to-13-table network-schema
migration under the owner-token/binding rules, refuse read-only or partial-group
repair, bind pending source/manifest route/carriers to the exact depot plan on
every open mode, and forbid a pending/completed namespace collision. Network
admission is 64 MiB/1,024 chunks, one source is at most 1 MiB, and one carrier is
at most 128 KiB. Pending staging is 10,000 aggregate source/prefix rows and 64
MiB of prefix bytes; each durable peer-neutral extension is at most 16 KiB and
cursor state is bounded to 256 configured peers. Pending bytes and retained
non-public lineage fences remain absent from ordinary publication inventory,
query, read, and service until exact atomic promotion.

The isolated direct-Iroh gate
`blob_source_carrier_reopen_resumes_exact_complement_from_different_peer`
passed 1/1 in 76.77 seconds for one 96-KiB Blob. A completed B; A then sent C
the authenticated source plus one carrier range; all C runtime/store/provider-
cache ownership tore down and reopened; A was removed; and fresh eligible
content peer B sent no source retransmission and only C's exact missing
complement. The final state held one ordinary publication, no pending source or
prefix, and the exact decrypted plaintext. This is a different eligible peer,
not a route-only peer.

`stale_pending_blob_cleanup_removes_visibility_but_retains_reserved_staging`
passed 1/1 in 43.63 seconds on the repaired cleanup path. Same-epoch
route/physical-lineage replacement, numeric epoch advance, and publisher
revocation each begin with a pending source plus one durable range. Startup then
removes the exact pending source, authenticated-cache claim, carrier prefix, and
network-staging charge, but deliberately retains the bounded depot expected or
committed staging, backing files/chunks where present, reserved-byte quota
charge, and non-public retained physical-lineage fence until a future explicit
GC protocol. Valid later work succeeds while both the abandoned reservation and
new completed content remain charged, and a second reopen preserves that exact
accounting. Old source rows and peer proofs are withheld after same-epoch key
replacement; exact-lineage restaging succeeds, a different lineage for the same
`(BlobID, content group, numeric epoch)` fails without mutation, and numeric
epoch advance admits a new bounded variant.

The final runtime repair regressions are exact. The earlier concurrent-restage
case `pending_blob_abort_reconciles_concurrent_exact_restage_without_restart`
passed 1/1 in 0.68 seconds. The stronger
`blob_lifecycle_lock_serializes_delayed_projection_insert_and_abort` passed 1/1
in 0.90 seconds by pausing a freshly authenticated restage before cache
insertion while abort wins; the shared lifecycle lock leaves neither an orphan
claim nor an unclaimed durable source and requires no restart.
`terminal_blob_poison_advances_scheduler_past_source_to_later_candidate` passed
1/1 in 0.70 seconds with a multi-carrier plan whose manifest-last ID is below
its lexicographic maximum, then selected the later eligible source.
Independent final audit found no P0–P3: the lifecycle guard covers admission,
sender-cache repair, stale/terminal abort, startup/live cleanup, and promotion;
lock order is consistent, no production guard crosses an await or content
stream, nested acquisition is absent, and lock poisoning fails closed with a
fixed sanitized error.

The node Blob-focused suite passed 17/17 in 53.31 seconds. The corrected
`authenticated_peer_without_scope_grant_learns_no_event_id_and_cannot_fetch`
privacy/v5-empty-lane regression passed 1/1 in 63.51 seconds. Node all-target
no-run/check, strict all-target Clippy with warnings denied, selected-frame fuzz
target check, formatting, and diff check passed after the final lifecycle
repair. Strict workspace Rustdoc and a fresh isolated `aster-node` plus
`aster-iroh` documentation build passed; the earlier missing-helper diagnostic
was stale Cargo rmeta and required no source or hash change. Normal and AtLeast
run eligible v5 Blob work because AtLeast is Event-only; ReceiveOnly advertises,
requests, stages, promotes, and counts zero Blob work.

This was exact-freeze same-implementation automation on one host and in one OS
process, not a retained execution root. It moves exactly `DM-5.1-12`,
`DM-5.1-13`, and `DM-5.2-19` through `DM-5.2-22` from `open` to
`implemented-uncredited`; it creates no `observed-bounded` credit and does not
relabel any historical Event/control receipt at that prior freeze. The current
live mechanism supersedes the access absence, and the separate v2 retained
receipt above now advances `DM-5.1-12`, `DM-5.1-13`, and `DM-5.2-19` through
`DM-5.2-22` to `observed-bounded` without rewriting this historical source/test
identity. Retained Blob-delivery acceptance and Blob peer/convergence status,
route-only Blob relay/custody,
TTL/expiry/GC, pure-byte identity/deduplication, 100+ MiB and process-RSS
evidence, physical carriers, mixed implementations, and release authorization
remain open.

## Prior selected State stopped-slice automated evidence

The stopped/local selected State slice is pinned to these exact frozen Rust
source identities:

```text
1b33111f631ed417205849a7ec031ff7068f6b7f816d09392d146b0b8f3d57ea  crates/aster-core/src/source_state.rs
5da5c9bd7e36995e6315f29b7354a78d863ed97c94b33c10f5f7d9946d6a7a6b  crates/aster-core/src/lib.rs
835a508f56a4b07b6aa9301f6bbf2a9f3bb01717fff0bc218f02b58bc22e245c  crates/aster-node/src/application.rs
4f0d04afa2b5fe2b78ed1fdd88bd0a5e4007a05915e11bc08fedba9ba70e2982  crates/aster-node/src/application/state.rs
c45a02fdfe159a2da57f42145b0fbb0fcba25a71d2d722c0359ec9485d59d6b3  crates/aster-node/src/lib.rs
0151703349198128867f1751fbd33ca0a3e134a93d83ee5ed36c99869e811e1d  crates/aster-node/examples/state_application.rs
b973dc98bbde2d04555358f88c3b00a99180d059711bca7e2114c47749905424  crates/aster-redb-store/src/lib.rs
```

The documented two-node fixture and State example passed end to end on these
final bytes in a disposable root. The first run returned:

```text
STATE current=96e109dccac01630a0263cb00d8cfb97e0cc391c20ad6c9b759bc47bc26ff820 value=moving counter=3 ready_inserted=true moving_inserted=true recoverable=1
```

The immediate exact rerun returned the same semantic identity, value, publisher
counter, and recoverable count with both `ready_inserted` and `moving_inserted`
set to `false`. That is local executable evidence for durable operation replay
and causal projection, not State transfer or acceptance. The temporary root is
not retained as an execution receipt.

The final current-toolchain selected-code matrix passed 517 of 517 tests: core
library 342/342 (44.69s), node library 73/73 (4.64s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (136.20s), and selected store 83/83 (8.48s). The core basic
example and the Event, live Event, and State examples had no tests.

The separate exact Rust 1.91.0 matrix also passed 517 of 517: core library
342/342 (45.83s), node library 73/73 (4.70s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (135.07s), and selected store 83/83 (8.62s); the same examples
had no tests. Strict all-target/all-feature Clippy with warnings denied passed
on both toolchains. Rust formatting and `git diff --check` passed on the frozen
tree. These are separate executions; their timings and counts are not pooled.

Within those totals, five selected-node State tests exercise independent
reducer recomputation, restart-stable idempotent publication/query, visible
tombstones, Event-State shared counters with disjoint Event sequence positions,
and exact writer exclusion. The selected-store tests cover State operation
conflict and quotas, semantic/representation/cross-class collision, sequential
and concurrent reduction, deterministic full-ID tie-break, inactive-row
retention, stale/future epoch behavior, projection-plan races, schema/reopen
audit, and fail-closed aggregate invariant rejection.

Raw State operation lookup, stored rows, and projection plans remain privileged
structural data. Only the selected node's fresh source/content verification,
full request/header/payload/identity comparison, current-policy checks,
independent reducer recomputation, and exact plan recheck form the application
exposure boundary.

At that prior frozen slice there was no State reconciliation frame, carrier
path, live handle, or retained execution root. It moved only `DM-5.1-01`,
`DM-5.1-02`, `DM-5.3-01`, and `DM-5.3-02` to
`implemented-uncredited` and added no `observed-bounded` credit. That statement
is historical to the stopped slice: the later retained live v2 receipt moves
`DM-5.1-02` and `DM-5.3-01` to `observed-bounded`; the still-later retained
State subscription receipt moves `DM-5.1-01` to `observed-bounded`, and
`DM-5.3-02` was already moved by mutable v1.

## Prior selected Record stopped-slice automated evidence

The stopped/local selected Record slice is pinned to these exact frozen Rust
source and dependency-boundary identities:

```text
0942f0115e41eb901315ed93dab59a6bf90c0e039d2c81516d21e5884e39e4eb  crates/aster-core/src/source_record.rs
10292c32280dfe76d561404fe6e7bdb064ca5bd0fe968afbab052d1a15861263  crates/aster-core/src/lib.rs
abbd075bf8aaa331761c94cde8ec129441740b0e0d7197526af3a3cfad5458e3  crates/aster-redb-store/src/lib.rs
9f106a1879c6989399e97586c337232cf0bb2d291911c99b44030cc70d0839b0  crates/aster-node/Cargo.toml
de5a864e4eb81e2953761406b9036d987c6df8d69109e1e1d131d4f6070f7e1b  crates/aster-node/src/application.rs
2c2e19e702505988f667676c9569c13e983224b487022db4e03f8ebb634de735  crates/aster-node/src/application/record.rs
299da58603b0166100da51d589a9e08aad1297f6c8063e858fa36c4291d98132  crates/aster-node/src/lib.rs
bfac8e4c0e45fd3c573ca0ba51f9b86044fb52680a2b7074086f02e64aec2aff  crates/aster-node/examples/record_application.rs
2d4730bb12ea8a1e669228caff6fbf346df1cec1172660da1095f5a96f78d927  Cargo.lock
```

The focused Record suites passed on both the pinned current toolchain and exact
Rust 1.91.0: core Record 7/7, selected store Record 7/7, and selected-node
Record 8/8. Those tests cover typed route/content capability separation,
class/header/payload/TTL rejection, semantic-versus-exact identity, local
sequential and independently authenticated two-way/N-way heads, arrival and
complete-ID ordering, operation conflict/restart replay, ordinary-publish
conflict bypass rejection, exact guard-bound resolution, stale-plan atomic
rollback, changed-guard operation conflict, authorized exact retry after rekey,
visible tombstones without delete-wins, hidden-but-freshly-verified post-rekey
rows, tampered valid metadata with unchanged sealed bytes, cross-class causal
counter sharing/collision rejection, quotas, schema migration/reopen audit, and
terminal-store preservation. Application errors remained sanitized.

The documented two-node fixture completed in 27.21 seconds. On those final
bytes, the Record example's first run completed in 1.26 seconds and returned:

```text
RECORD current=4fa993318f7b61570f427afd644f8f6b4ab64289aa06dff5b49667c9ab89820c value=moving counter=3 ready_inserted=true moving_inserted=true concurrent=0 superseded=1 conflict=false
```

The immediate exact rerun completed in 0.84 seconds and returned the same
semantic identity, value, publisher counter, and projection counts with
`ready_inserted=false` and `moving_inserted=false`. That is local executable
evidence for durable Record operation replay and causal projection, not Record
transfer or acceptance. The disposable root is not retained as an execution
receipt.

The final current-toolchain selected-code matrix passed 539 of 539 tests: core
library 349/349 (44.44s), node library 81/81 (5.19s), node binary 6/6 (0.00s),
`mesh_cli` 13/13 (135.87s), and selected store 90/90 (8.75s). The five example
targets—core basic, Event, live Event, State, and Record—had no tests. The
test-harness time sum was 194.25 seconds;
the complete orchestration used 220.35 seconds wall, 425.76 seconds user, and
123.55 seconds system time.

The separate exact Rust 1.91.0 matrix also passed 539 of 539: core library
349/349 (45.77s), node library 81/81 (5.42s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (135.76s), and selected store 90/90 (8.61s), with the same five
zero-test targets. Its test-harness time sum was 195.57 seconds; complete
orchestration used 221.18 seconds wall, 426.45 seconds user, and 124.92 seconds
system time. These are separate executions; their timings and counts are not
pooled.

Strict all-target/all-feature Clippy with warnings denied passed on the current
toolchain in 10.32 seconds and on Rust 1.91 in 10.30 seconds. Rust formatting
passed on both toolchains in 0.73 and 0.85 seconds respectively, and
`git diff --check` passed in 0.03 seconds. The full dual-toolchain aggregate
validation took 463.76 seconds wall time.

Raw Record operation lookup, stored rows, causal dispositions, and projection
plans remain privileged structural data. Only the selected node's fresh
source/content verification of every candidate, complete
request/header/payload/identity comparison, current-policy checks, independent
head/disposition recomputation, exact plan recheck, and guard-bound commit form
the application exposure boundary.

At that prior frozen slice there was no Record reconciliation frame, carrier path, live handle,
automatic registered-policy merge, explicit-policy garbage collection, or
retained execution root. It initially moved `DM-5.1-08`, `DM-5.1-09`, and
`DM-5.3-06` through `DM-5.3-10` to `implemented-uncredited`. The newer bounded
network observation above advances `DM-5.1-09`, `DM-5.3-06`, and `DM-5.3-09`;
automatic merge, TTL/expiry/garbage collection, physical/mixed-implementation,
scale, and release gates remain open. `DM-5.3-05` remains `open`.

## Prior selected Blob automated evidence

The stopped/local selected Blob slice is pinned to these exact frozen Rust
source and dependency-boundary identities:

This freeze predates semantic v4; the current v4 source tree does not relabel it
as current evidence.

```text
c9750fa4f627f53c4084579a67bbd350c082de51fefd4c80777d509636b091df  crates/aster-core/src/blob.rs
38891bcfe7f40d148087781e723bea5c27714565b96f1fc5af8c3b07e3359d54  crates/aster-core/src/source_blob.rs
483c32c099b11d263bad500f6a0c6f21936b297e405f215c8f85321140dbff28  crates/aster-core/src/lib.rs
f9be1a1b3d8285e4ca47c531603ce692ad3db0502e3706270249517c4d88d0ec  crates/aster-core/src/crypto/reference.rs
56fa5d5e1c3b6745e34cd5369c3283bab67a0e4b88ac01911c176bac17cbd89c  crates/aster-redb-store/Cargo.toml
45be120b18261bd499705e42d8605802a27d45e6fad288d5b9feb546de0e6067  crates/aster-redb-store/src/lib.rs
92eb8a1f8ef291bf2293a4138c4107f3e3b7e3d6797ec6bcfc2c821335628c5e  crates/aster-redb-store/src/blob.rs
6cc85cbc387b75e3ef14980ba3c5e5583472155d8bfd0ddf8ee937319dd1b3bd  crates/aster-redb-store/src/blob/depot.rs
9f106a1879c6989399e97586c337232cf0bb2d291911c99b44030cc70d0839b0  crates/aster-node/Cargo.toml
b802c979691a6fb709239ca5861a73ca2c1742c9e5206ed00b1d74a82e37501a  crates/aster-node/src/application.rs
e0eb7d4cb2f7239e49fa1ee0bb93965cabd89669edbe5cd0987fd99dba83e1c0  crates/aster-node/src/application/blob.rs
0f36acd42b5b12177a1ee89868c887c9f964b991217d0b80e32dd8d3e16b162f  crates/aster-node/src/lib.rs
5d5fa063bd89f9bf4bb6f6949c282c979d05ff453576b23f6fd65ebef4639b9c  crates/aster-node/src/runtime.rs
3ac76a4d8bfdea6d486345e67cdfb46e4a7a92d0635bf4ceebf4ced0f9dea4b6  crates/aster-node/tests/mesh_cli.rs
407b7f3b4f0b3ee276a472deb389b73bf3766b69b6164f2e9ba7ccd260a5b721  crates/aster-node/examples/blob_application.rs
41932294316bd930b9d86c07392448e8dbb092355a8c0933b7b7b895faf98148  Cargo.lock
```

Focused current-toolchain runs passed the six typed source-Blob tests, the
dedicated core reader retry-state adversary, all 28 selected-store Blob tests,
and all seven selected-node Blob tests. The current tracked-Cargo-target matrix
passed 576 of 576: core library 351/351 (44.68s), node library 88/88 (11.29s),
node binary 6/6 (0.00s), `mesh_cli` 13/13 (153.69s), and selected store 118/118
(12.33s). The separate exact Rust 1.91.0 matrix passed the same 576 tests in
45.57, 28.63, 0.01, 153.99, and 12.44 seconds respectively. The core basic
example and five node examples had no tests. These totals count only the listed
tracked Cargo targets; no auxiliary non-workspace scratch harness is counted.

Strict workspace all-target Clippy with warnings denied passed on the current
and Rust 1.91 toolchains in 28.36 and 34.71 seconds. Current Rustdoc with
warnings denied, global formatting, and `git diff --check` passed. A
loopback-enabled current-toolchain workspace test also passed every runnable
suite; one performance experiment remained explicitly ignored. These are
separate executions, and no retained root or artifact is claimed.

The documented disposable fixture ran the compiled Blob example twice over
18,783 input bytes. The first run completed in 4.792 seconds and returned:

```text
BLOB id=85c3f98504cc9e671212256c994698ce2d8c1e947aa5b3841d61a943d3660fde bytes=18783 chunks=1 inserted=true media_type=application/octet-stream
```

The 0.714-second exact rerun returned the same ID, size, chunk count, and media
type with `inserted=false`. Both outputs matched the input byte-for-byte at
SHA-256 `f3d9ba32b0825abfec157aadf8c16581608220f48dd2a8f0a3a39bef29bdd966`.
That is local executable evidence for durable operation replay and verified
streaming, not Blob transfer, remote resume, physical-storage acceptance, or a
release receipt; the fixture is not retained.

Raw Blob imports, operation mappings, publications, chunk metadata, files, and
read plans remain privileged structural state. Only the selected node's current
policy and revocation checks, typed source/content capability verification of
every candidate, exact topic/scope/Blob-ID/variant comparison, deterministic
active-publication recomputation, exact plan recheck, private completion proof,
and synchronous verified reader form the application exposure boundary.

This slice has no Blob reconciliation frame, carrier path, live handle,
subscription, remote chunk transfer, any-peer resume, metadata-independent
whole-byte identity, explicit staging GC, complete physical allocation
accounting, or retained execution root. It moves only `DM-5.1-10`,
`DM-5.1-11`, `DM-5.3-04`, `DM-9-13`, and `DM-9-14` to
`implemented-uncredited`; it adds no `observed-bounded` credit and closes no
networked Blob, maximum-size acceptance, physical, mixed-implementation,
scale, custody/TTL, or release gate.

## Prior semantic-v3 selected Event custody automated evidence

This retained source-freeze section records the custody slice before semantic
v4 became the default. Semantic v4 now inherits these semantic-v3-format Event
mechanics, but that current-code inheritance does not change or relabel the
frozen identities, totals, or claim boundary below. The selected
Event/RouteEvent custody slice was pinned to the following exact source and
dependency-boundary SHA-256 identities:

```text
9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f  Cargo.lock
ceb4898bb8d21fa70d2f31ef0d45f8975c51135774c187c77d4c5bf4879aa8f0  crates/aster-core/src/custody.rs
2813d283d0295513418ee24134fbbe631aa8b4f7012284b769eb0f0eea683f62  crates/aster-core/src/crypto.rs
d306b541dc09e2ad96470c53f1e32917133b642266b60d04540991ce3e632e39  crates/aster-core/src/crypto/reference.rs
9e94c6d85468842f421cd38e075af53d5186f58cc054d7220520b88af1cdce3e  crates/aster-core/src/source_event.rs
c0b7cf943df149f2c37f3f1939b5dbbad790347e2beab7e9dcae2b4352373ab2  crates/aster-core/src/source_control.rs
b6b239329ae4ae34a1702f44a6221f0292e5278310233e7d4d5821e21fda4434  crates/aster-core/src/lib.rs
5584b0168879bc75c0c0debeded0ea881b5c26c42185887b29f0a87da4fb0a52  crates/aster-core/src/store.rs
9931a163bba38bb052c6baaf8a9f050b0839a04d8d459a17fb88c3542099a644  crates/aster-core/src/runtime/reference_semantic.rs
a2a1625bb5dca6e0369e40b3e84c0a7c25c5537c5472e4894578e0ed7faff316  crates/aster-core/src/batch.rs
592cd79b230fd8e7b506acd40382f0f5934dfa81eda04a8459a5b766f06ca981  crates/aster-core/src/bridge_service.rs
6ac2c4e75eddedfea39ca6e2a6dfee9f5b922ee90a133e30f226f0522cb91206  crates/aster-core/src/runtime.rs
aa757c12baf006a05c5f8fcdc41755eaef2a072a1bd7195ae028cff1fe9be84e  crates/aster-core/src/wire.rs
37fd985318a3837355273e1cbd5a47151c8908ff74e0016097024f0bc7471ff2  crates/aster-iroh/src/lib.rs
d927bda6172d58e01dcf99df99502dcd531d31ca8af1c2483b39432c0c50e83f  crates/aster-redb-store/src/lib.rs
55f8460e3b4cca534463cded90b9b90fa662fa78bdf8c26c98a86372ee0819aa  crates/aster-redb-store/src/custody.rs
c1decbe0e89c71a46c38ab6b67c49dc3ecdfedc6614ab21b2124d4d56b08be8d  crates/aster-redb-store/src/blob.rs
cbbd11f8a80acf46dbf396af4733801c7af8d8ce50614a649415133ecad3284d  crates/aster-node/Cargo.toml
0c6d4b59764992f1857bc3c27a538c208a51b8af3758abdd55365d162cac3ced  crates/aster-node/src/application.rs
acd6c5c80f374bc834adfd665819662454a0f41fe554c7263592b24b08f5bed3  crates/aster-node/src/frame.rs
c193db439513bf61c2cee0dead3621e6bee058c9f76e433bf8d388f3ab0a05d3  crates/aster-node/src/lib.rs
3d27d0d0ad37c032a7ec1905aa75274cedfecfa539ce18340a482b244b4eda9c  crates/aster-node/src/main.rs
44cebc7201ea6447d3b14110e433fbc8d168a52f97878cf81a6d534be36c304a  crates/aster-node/src/mission.rs
a30ae1e158a5fd8928d970d36c69939340c6a64cda3293a3f34110d91478942c  crates/aster-node/src/runtime.rs
f9d6531b3d1b53453b8449d2566dda80263d5810a77ee62c20c8cd12d9101c51  crates/aster-node/examples/custody_application.rs
e32c98edb74fa1560217d3d78c0fec2632045fab3bd99c948b2e4a8fbb5dee58  crates/aster-ffi/src/lib.rs
3d482bc238d9c75fd3a8e1e3cc7136e740a4fef48321233a48407957119e4455  bindings/c/aster_mesh.h
e1778498733672b3225f5eae19f3a9e6bd45a85142ed5d0358adaa9e9287f9e8  bindings/c/header_smoke.c
a3e951fb09d81533f9d631be5749eed681aa642b7b56d17610388012fc231496  bindings/c/header_smoke.cpp
c7224b04c031a36ef9e3c9c1aa7e4422a9833e0942a0cfb03d33c12671079996  bindings/go/aster_test.go
3cff2050fd3986ddf02eaa2e2eeb8486578ee0185ffaa227784e61209fe7b83b  bindings/python/tests/test_binding.py
5f3705bcdcf04cc1186b3860db59b6a90d6acbf63192b5129037c6ccad33a706  crates/aster-lab/src/lib.rs
e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987  data-mesh-requirements.md
57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2  docs/evaluations/0005/requirements-matrix.csv
e72e4fab25c0e327a1a4dd55ab87f05f641a0c4dae9f54ea7c178fc3ee352058  docs/implementation/requirements-implementation.csv
d88d9347362f5577efe60c916fc259c8ac73bb5ec44fbc815e79c0812265ee55  tools/check-implementation-requirements.py
```

The complete current-toolchain command

```sh
cargo test --workspace --all-features --all-targets -- --test-threads=1
```

passed every runnable workspace target in 1,178.21 seconds. Summing the
per-binary Cargo reports gives 895 passed tests and one explicitly ignored local
performance experiment. The separate exact Rust 1.91.0 command passed the same
895 tests plus the same one ignored experiment in 2,069.41 seconds, including an
11 minute 25 second clean compile. The nonzero selected counts included core
372/372, FFI 13/13, host 74/74, IP/relay 50/50, Iroh carrier 6/6, lab library
32/32, Negentropy 10/10, node library 117/117, node binary 6/6, real-process
`mesh_cli` 13/13, and selected redb store 137/137. All six node examples and
the other listed example targets compiled successfully and contained no tests.

Strict workspace all-feature/all-target Clippy with warnings denied passed on
the current and Rust 1.91 toolchains in 211.01 and 206.85 seconds. Current Cargo
also emitted its separate upstream future-incompatibility notice for
`proc-macro-error2 2.0.1`; no workspace warning escaped `-D warnings`. A final
exact-current selected-store rerun passed 137/137 in 71.65 test seconds
(114.93 seconds including compilation). The only source changes after the full
matrices were two Rustdoc-only comment corrections; exact-current and Rust 1.91
strict `aster-lab` Clippy then passed in 2 minutes 21 seconds and 3 minutes 30
seconds. A fresh-target locked/offline workspace Rustdoc build with warnings
denied passed all 17 workspace crate-target documents in 16.58 seconds. Rust
formatting, `git diff --check`, and the generated requirements validator passed.

Focused tests within those matrices cover checked custody age/overflow and the
exact TTL boundary; authenticated v3 claim and replay binding; same-clock
high-water concurrency; route-to-content promotion; startup source proof before
maintenance; priority/TTL/length/class tamper; exact-scope quota configuration
and aggregate quota enforcement/rejection; authority and tombstone reserves;
retirement, lease, retry, receipt, and crash/reopen accounting;
equal-priority multi-peer retry fairness; opaque selector-generation receipt
invalidation; Carry-to-Consume promotion in normal and blind ReceiveOnly
contacts; receiver-relative Satisfied/Pending settlement; common-set cleanup and
due-boundary retry; pre-open stale-work continuation; post-stream-open zero-byte
final rejection; final policy recheck; lane deferral; whole-contact budget
bounds; same-epoch historical lineage and legacy-witness migration; source
revocation/rekey; and v3 downgrade-transcript rejection.

The exact public example invocation was:

```sh
cargo run -p aster-node --example custody_application -- \
  /tmp/aster-custody-example.FEbSuK/mesh/node-0 \
  /tmp/aster-custody-example.FEbSuK/mesh/node-0/mission.unprotected-reference.bundle \
  demo/mesh mesh.ping-pong
```

On the Darwin arm64 host it completed a clean peerless lifecycle and printed:

```text
CUSTODY_APPLICATION finite_ttl=unsupported_on_this_platform,durable_fallback=true id=ea28599c6e8287132cc5293da33cebb2124e75f2c99c015242c80982e40cc41c inserted=true authenticated_ttl_ms=None initial_policy=AtLeast(Priority) initial_revision=1 updated_policy=Normal updated_revision=2 observed_revision=2 events=3
```

The Linux branch of the same compiled example requests a positive 60,000 ms
finite TTL; this Darwin run does not claim Linux expiry execution.

Native binding/version follow-ups passed the focused FFI version test on the
current and Rust 1.91 toolchains, strict FFI Clippy on both, native library
build, C11 and C++17 syntax plus linked-runtime smoke tests, Python 12/12, and
the complete Go suite. At that pre-v4 source freeze, ABI and wire versions were
1 and the default/highest semantic version was 3, with semantic versions 2 and
1 retained for negotiated compatibility. Current code instead offers
`[6, 5, 4, 3, 2, 1]`; v4 through v6 inherit the same Event custody mechanics
without changing this receipt, and v6 separately adds the opt-in Event-bridge
lane.

This evidence moves exactly `DM-11-15`, `DM-11-17`, `DM-5.4-05`,
`DM-5.4-09`, `DM-5.4-10`, `DM-5.4-12` through `DM-5.4-19`, `DM-5.4-21`,
`DM-5.4-22`, `DM-5.7-03`, `DM-9-24`, and `DM-9-25` from `open` to
`implemented-uncredited`; it strengthens the existing `DM-5.4-01` and
`DM-5.5-07` rows and adds no `observed-bounded` credit. At that source freeze,
the trace contained 348 requirements, 106 exact selected mappings, 68
implemented-uncredited, 37 observed-bounded, and 243 open.

The claim is deliberately limited to semantic-v3 selected Event/RouteEvent
custody, Linux finite TTL, the documented logical/accounted namespaces and hard
ledger caps, direct-Iroh loopback software tests, and the exact application and
binding surfaces above. Generic cross-class lowest-priority eviction
(`DM-5.4-11`), State/Record/Blob custody, non-Linux finite TTL, accepted-dot and
causal/frontier aggregate retirement, physical storage/RF/network behavior,
NAT/hosted relay/BTLE, mixed implementations, scale/resource acceptance,
operational protected provisioning/administration, independent interoperability/review,
FIPS validation, a retained externally anchored receipt, and release
authorization remain open.

## Current protected live startup and control automated evidence

The current source tree adds caller-provided protected live `NodeConfig`
construction and actor-owned `SelectedControlHandle` administration after the
historical stopped Step 4 freeze below. This section intentionally records no
signed documentation commit or retained execution root. The source freeze is
signed commit `164ccc1dbafd7fa954c06eb7cf555671ff597ba1`. It moves no status and grants no
additional `observed-bounded` credit; at that protected-source freeze the
generated totals were 78
`implemented-uncredited`, 37 `observed-bounded`, 233 `open`, and 119 exact
selected mappings.

The exact frozen source identities are:

```text
82e736ed113800cd1aa2aecfee2fb94d97524f5dfa579f489bca780a74bfb3e9  crates/aster-core/src/provisioning.rs
068d1ae37bf986aafa6dfd1f45cebfe14adcedbd1f22fb7d4b179dc433d6f017  crates/aster-node/src/control_admin.rs
438e4cc3d0a9c3d984d4344cfdf394b4968712af0715af09fc1a224f801e76b1  crates/aster-node/src/lib.rs
79be3dc2e718b24459176382f7a33f7abfb8fff576022370b10cd4335d56b602  crates/aster-node/src/mission.rs
ad7f4b54719fdc92edaa342e36e62950ab087e5ea1b711f221880f238e6b1c14  crates/aster-node/src/runtime.rs
68100051afaa92af67268b69527c23638150eec613eb1598f7edd90aff5a06ae  crates/aster-node/tests/protected_runtime.rs
```

At those identities, these exact reported current-code gates passed:

```sh
cargo test --locked -p aster-core --lib
# 380 passed; 0 failed; 45.21s
cargo test --locked -p aster-node --lib
# 180 passed; 0 failed; 69.94s
cargo test -p aster-node --test protected_runtime
# 12 passed; 0 failed; 0.15s
cargo check --locked -p aster-node --all-targets --all-features
# passed; 12m04s
cargo clippy --locked -p aster-node --all-targets --all-features -- -D warnings
# passed; 25.84s
env CARGO_TARGET_DIR=/private/tmp/aster-protected-admin-rustdoc-fresh RUSTDOCFLAGS=-Dwarnings \
  cargo doc --locked --workspace --all-features --no-deps
# passed from a fresh target; 17.97s
cargo fmt --all -- --check
git diff --check
# both passed
```

The final serialized gate over those source identities and the preceding frozen
documentation bytes ran outside the sandbox for real-Iroh loopback:

```sh
CARGO_TARGET_DIR=/private/tmp/aster-protected-admin-full-check CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 mise run check
# exit 0
```

The all-feature workspace tests and strict Clippy passed. Major test results
were core 388/388, node library 180/180, node main 12/12, `mesh_cli` 20/20,
`protected_runtime` 12/12, redb 166/166, `aster-iroh` 13/13, host 74/74, IP
50/50, lab 32/32, and FFI 13/13; all doctests also passed. C/C++ syntax,
conformance and Python wire checks, Python bindings 12/12, lab Python 162/162,
Go, license, dependency, and requirements gates were green. At that frozen
protected-source gate the requirements trace had 348 IDs, 119 mappings, 78
`implemented-uncredited`, 37
`observed-bounded`, and 233 `open`. This is a non-retained current-code CI
receipt: it creates no execution root, observed credit, status movement, or
signed documentation commit.

The Unix `crates/aster-node/tests/protected_runtime.rs` target names these twelve
exact cells:

- `protected_bytes_preserve_exact_options_and_origin_without_creating_state`
- `protected_artifact_invokes_provider_once_without_creating_state`
- `relative_state_is_bound_before_path_provider_and_loader_cwd_callbacks`
- `invalid_protected_options_do_not_invoke_provider_or_create_state`
- `uninspectable_state_fails_before_provider_invocation`
- `terminal_state_precedes_protected_provider_and_secret_loader_without_mutation`
- `raw_canonical_bundle_never_reaches_protected_provider`
- `protected_rejection_is_sanitized_and_source_free`
- `missing_protected_artifact_fails_before_provider_or_state_creation`
- `secret_loader_receives_exact_request_and_preserves_secret_origin`
- `secret_loader_rejects_mismatched_receipt_echoes_without_state_creation`
- `protected_state_witness_rejects_mutation_before_state_creation`

They cover exact option preservation; artifact/byte/opaque-reference origins;
one-call provider behavior; option, terminal-state, and filesystem prechecks
before state creation; sanitized rejection; exact load-receipt echoes; one
captured absolute lexical state pathname; and rejection of later public
`NodeConfig::state` mutation. They do not establish inode, parent-directory,
symlink-resolution, rename-history, database-replacement, or rollback binding.
Additional exact unit cells are
`secret_reference_is_bounded_canonical_versioned_and_redacted`,
`provisioning_origins_have_stable_nonidentifying_receipt_labels`,
`protected_state_witness_is_lexical_and_clone_local`,
`live_control_handle_retains_only_stable_identity_accessors`,
`closed_live_control_channel_returns_only_sanitized_state_unavailable`, and
`runtime_rejection_closes_live_control_call_with_fixed_category`.

The live actor's exact runtime cells are:

- `protected_live_controls_refresh_policy_retry_exactly_and_close_on_shutdown`
- `live_control_pending_gap_returns_policy_unsettled_and_preserves_exact_retry`
- `saturated_cloned_live_control_retries_do_not_starve_event_status_or_publish`
- `cancelled_enqueued_live_control_remains_actor_owned_and_exactly_retryable`
- `live_self_revocation_returns_receipt_before_actor_teardown`

Those cells bound a capacity-one control queue and four-command yield budget;
live rekey/revocation policy refresh; exact retry; nonfatal pending-policy
deferral; Event/status progress under cloned retry pressure; graceful shutdown;
self-revocation receipt-before-teardown; and one post-enqueue caller-cancellation
case whose committed receipt is recovered by stopped exact retry. Cancellation
may still commit, so it is not a rollback guarantee. A lost self-revocation
response requires stopped admin after teardown. The protected and
secret-reference origins can shut down gracefully, but the live local
zeroization path cannot destroy provider custody. The post-enqueue cancellation
cell is Unix-only.

Useful focused reproduction commands are:

```sh
cargo test --locked -p aster-core provisioning --lib
cargo test --locked -p aster-node mission::tests --lib
cargo test --locked -p aster-node control_admin::tests --lib
cargo test --locked -p aster-node --test protected_runtime -- --test-threads=1
cargo test --locked -p aster-node \
  protected_live_controls_refresh_policy_retry_exactly_and_close_on_shutdown --lib
cargo test --locked -p aster-node \
  live_control_pending_gap_returns_policy_unsettled_and_preserves_exact_retry --lib
cargo test --locked -p aster-node \
  saturated_cloned_live_control_retries_do_not_starve_event_status_or_publish --lib
cargo test --locked -p aster-node \
  cancelled_enqueued_live_control_remains_actor_owned_and_exactly_retryable --lib
cargo test --locked -p aster-node \
  live_self_revocation_returns_receipt_before_actor_teardown --lib
```

No production SecretStore/protection backend, stock protected CLI, selected-node
binding, cross-process live-admin IPC, issuance/recovery workflow, automatic or
atomic revoke-plus-rekey, coordinated drain/store-terminalization/provider-
destroy workflow, physical sanitization, or release authorization follows from
these tests.

## Prior protected provisioning and control administration automated evidence

Step 4 is source-frozen at the identities below. At that frozen Step 4 tree, the
current Rust 1.97.1 and minimum-supported Rust 1.91.0 executable workspace
matrices each passed 927 tests with zero failures and one deliberately ignored
local performance experiment. Both runs included every library, binary,
integration-test, and example target; their commands intentionally separated
doctests from the 927 executable-test count. Fresh-target Rustdoc with warnings
denied then generated all 17 workspace crate-target documents on each
toolchain.

That freeze predates semantic v4; the current v4 source tree does not relabel it
as current evidence.

This is an unreleased draft and must not be published under the retained
workspace version `0.1.0`. It intentionally removes the raw node control
publisher reexports, requires a nonzero registry-generation witness in the
rekey CLI, adds an opaque authenticated-plan capability to the unpublished
redb local-rekey commit seam, and expands unpublished redb control
records/errors for migration and rejection fencing. The wire profile and C ABI
do not change. Any release must increment the draft/package identifier and
record these Rust/CLI migrations in the release notes and compatibility matrix.

The exact whole-workspace commands were:

```sh
CARGO_TARGET_DIR=/private/tmp/aster-step4-current-tests \
  cargo test --locked --workspace --all-features \
  --lib --bins --tests --examples -- --test-threads=1
CARGO_TARGET_DIR=/private/tmp/aster-step4-rust191-tests \
  cargo +1.91.0 test --locked --workspace --all-features \
  --lib --bins --tests --examples -- --test-threads=1
CARGO_TARGET_DIR=/private/tmp/aster-step4-current-tests \
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
CARGO_TARGET_DIR=/private/tmp/aster-step4-rust191-tests \
  cargo +1.91.0 clippy --locked --workspace --all-targets --all-features -- -D warnings
CARGO_TARGET_DIR=/private/tmp/aster-step4-rustdoc-current \
  RUSTDOCFLAGS=-Dwarnings \
  cargo doc --locked --offline --workspace --all-features --no-deps
CARGO_TARGET_DIR=/private/tmp/aster-step4-rustdoc-191 \
  RUSTDOCFLAGS=-Dwarnings \
  cargo +1.91.0 doc --locked --offline --workspace --all-features --no-deps
```

The current run recorded core 382/382 (129.37s), FFI 13/13 (3.75s), host
74/74 (13.86s), IP 50/50 (2.21s), Iroh 6/6 (0.16s), lab library 32/32
(52.51s), node library 133/133 (66.13s), node binary 6/6 (0.01s), real-process
`mesh_cli` 13/13 (144.36s), and redb store 143/143 (79.71s). Rust 1.91
recorded the corresponding core 382/382 (135.14s), FFI 13/13 (3.89s), host
74/74 (14.34s), IP 50/50 (2.21s), Iroh 6/6 (0.15s), lab library 32/32
(53.78s), node library 133/133 (70.49s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (139.03s), and redb store 143/143 (81.73s). The smaller
workspace targets account for the remaining passing tests. The current and
Rust 1.91 results are separate executions; timings are not pooled.

The real-process harness raises the ordinary ready bound to 40 seconds. Its cold
offline-publication cell separately bounds worker startup at 90 seconds,
authenticated contact at 120 seconds, and overall worker completion at 150
seconds. Those are test-harness deadlines, not an operational availability or
offline-duration claim.

Focused development gates included:

```sh
cargo test -p aster-core provisioning --lib
cargo test -p aster-node control_admin::tests --lib
cargo test -p aster-node \
  relative_paths_remain_bound_across_path_provider_and_loader_cwd_changes --lib
cargo test -p aster-redb-store \
  authenticated_pending_predecessor_and_rollback_poison_is_purged_without_losing_gap_closer --lib
cargo test -p aster-redb-store \
  rejected_sequence_fence_blocks_replayed_descendants_until_valid_alternate_applies --lib
cargo test -p aster-redb-store \
  legacy_scope_epoch_is_historical_before_revocation_but_rejected_afterward --lib
cargo test -p aster-node \
  historical_local_control_receipts_survive_later_highwaters_but_remote_rows_do_not --lib
```

The provisioning filter passed 11 tests and the stopped control-admin filter
passed five; every focused regression above also appears in both complete
workspace matrices. They exercise checked operation/reference
receipt binding and zeroizing plaintext ownership; terminal-before-provider
ordering and sanitized admin failures; relative state/artifact binding across a
provider/loader current-directory change; authenticated control-poison purge
and durable descendant fencing; pre-revocation historical legacy scope state
versus post-revocation rejection; and exact same-signer historical publication
recovery without treating a remote row as locally emitted.

The final external-surface and policy gates also passed: native FFI build;
C11/C++17 warnings-denied header syntax; Rust conformance self-test; the Python
wire oracle's 10 accepted and 21 rejected vectors; standalone conformance
profile agreement 18/18; Python bindings 12/12; lab controller 162/162; the Go
binding suite and `gofmt`; Apache-2.0 project/package policy for 15 packages;
selected-node dependency isolation; the vendored netlink equivalence plus
13/13 tests; retained-libp2p boundary plus 16/16 regression tests; dependency
exception scope and its fail-closed regression; and the implementation trace
at 348 requirements and 109 exact selected mappings.

The frozen source identities are:

```text
e5c4201b70abae043dfa8bd2a8fe736f0b21aa4d10f3ff44deb00f0f828e8a4f  crates/aster-core/src/crypto/reference.rs
be66f9a3d83cd37c8d21a94bb7f62ed6722928ee7f888b06deb810f19ca4f91c  crates/aster-core/src/lib.rs
ae55f3a2dcd23af759a66c5152195e916b725a0158493b99d69c884333075970  crates/aster-core/src/provisioning.rs
070de70c8b484a6af5c461f9c4903a612091e10d7d4413149d5e63fdb53751ee  crates/aster-core/src/source_control.rs
ed7e95d57a6f17429639ff4ca3453952a43295ed027a98e5cce0b041f802c544  crates/aster-node/src/application.rs
7aa1fa7b50d73187d4fe7e0569d48303e7ecb74010e2516b751062570fa54103  crates/aster-node/src/control_admin.rs
095f26fa11c962ebc23b38573b170d7d7487abd8751d2433ad344f5459f3c5f4  crates/aster-node/src/lib.rs
d1eb655e15626b3e27fdbfd52d206124f63329ef2a5c5eb27d266da93bf76621  crates/aster-node/src/main.rs
0a65802f2bdcae9d41a756df8f3888faa6445b8edb4f9bc2a736c281e9836385  crates/aster-node/src/mission.rs
2dee780f04159fce4b4e368502e042bacb1eb903892d472fc72a6f688777d1a5  crates/aster-node/src/runtime.rs
b5e2928fdcfcb92765d14fa0c095bffb13760f4a42428acabceef58bab0506b2  crates/aster-node/tests/mesh_cli.rs
b3dea6db88e7eb64c8b309124bc63a35c1d6ad8b6461b0a715aaeed184735fe7  crates/aster-redb-store/src/lib.rs
9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f  Cargo.lock
```

The in-memory SecretStore test fixture is not a production backend or evidence
of backend durability, access control, at-rest secrecy, backup/recovery, or
physical erasure. The focused path tests establish a lexical current-directory
binding only. The focused control tests do not establish automatic or atomic
revocation remediation, physical/long-partition propagation, independent
interoperability, or release acceptance. This section moves no status: the
trace at that source freeze remained 348 requirements, 109 exact selected mappings, 68
implemented-uncredited, 37 observed-bounded, and 243 open.

## Reproducible receipt

Every retained root, binary identity, and source hash below belongs to the
parent PR-A/pre-subscription snapshot. PR B, PR C, the selected
State/Record/Blob and Event-custody slices, and the prior protected/admin
slice change store, frame, runtime, application, core, example, or
integration-test bytes; their credit in this ledger is limited to the exact
source/test boundaries mapped above. No fresh retained real-process receipt for
those slices is claimed.

The source-level invocation is:

```sh
ASTER_DEMO_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 3 --root "$ASTER_DEMO_PARENT/mesh"
```

The `--root` path must not already exist. On 2026-08-24 the final frozen-tree
binary used for these real-process receipts completed this three-node run with
exit status zero in 33.44 seconds:

```sh
target/debug/aster demo --nodes 3 \
  --root /private/tmp/aster-final-default-causal-20260824-n3.fPvORJ/mesh \
  --base-port 64000
```

Its terminal invariant block was:

```text
PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=ping-forward-0-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-1-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-2 transfer_id=4058145515bbe6b44ce5eb97af487d1b4c87b72cb0b4ab3d276eb950a260745d semantic_id=4d5104aba312faa316ab1e5098b7f82fe1f29d9df8cf9018d16f82e6ee521774 producer_process_absent=true source_authenticated=true ttl=none
PHASE status=pass name=pong-return-2-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-1-to-0 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
RELAY status=pass intermediates=1 exact_forward=true content_access=denied semantic_acceptance=none
PONG status=received emitted_by=destination-process producer_state=node-2 destination_state=node-0 correlation_semantic_id=4d5104aba312faa316ab1e5098b7f82fe1f29d9df8cf9018d16f82e6ee521774 transfer_id=9b1e72a60a664b157351d9d57b65c370bb7c716f8f07790ae3968e32f0be55e0 semantic_id=eeafea8fe3ceb0135ef3e1e8b295bba89ee086ea52e9e20feeb0ec2328071a4e source_authenticated=true causal_observation=verified ttl=none
PHASE status=pass name=noop processes=3 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
DEMO_RESULT status=pass scenario=ping-pong nodes=3 processes=13 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none root=/private/tmp/aster-final-default-causal-20260824-n3.fPvORJ/mesh
```

Read-only inspection on that retained root reported:

```text
node-0 zeroization=live opaque_items=0 events=2 event_acceptance_markers=2 event_sealed_bytes=21130 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
node-1 zeroization=live opaque_items=0 events=0 event_acceptance_markers=0 event_sealed_bytes=0 route_cached_events=2 route_cached_bytes=21130 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
node-2 zeroization=live opaque_items=0 events=2 event_acceptance_markers=2 event_sealed_bytes=21130 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
```

The environment was one host, direct loopback sockets, exact
carrier-to-mission bindings, a three-node line, three independent redb files,
and 13 child-process executions across seven (`2N+1`) causal cohorts. Node 0 and
node 2 had content grants for `mesh.ping-pong`; node 1 had only the corresponding
route grant. The peerless Ping publisher ran before the two isolated forward
edges; the peerless Pong publisher observed already-durable Ping before the two
isolated return edges. Each directed-edge cohort reconciled exactly one
pre-existing Event difference, emitted no application Event, and retained all
six control counters at zero. All 13 child stdout logs are nonempty (142 lines,
81,708 bytes), all 13 child stderr files are empty, and all terminal invariants
passed. The final no-op retained 36 passing contacts with all six control and
all five Event reconciliation counters zero. This single run's empty stderr is
observed receipt data, not a general zero-error guarantee.

The tracked [`mesh_cli` integration test](../../crates/aster-node/tests/mesh_cli.rs)
runs the same Ping/Pong invariants at four nodes with a 120-second bound. Omitting
`--scenario` must produce `scenario=ping-pong nodes=4 processes=18`; a separate
integration test selects the explicit four-node control scenario with a
120-second outer bound. The retained
default-N4 Ping/Pong root is
`/private/tmp/aster-final-default-causal-20260824-n4.wSr6so/mesh`;
it passed in 40.74 seconds and retained 18 nonempty child stdout logs (210 lines,
121,209 bytes) plus five transient no-op lines (1,067 bytes) across two stderr
files: two duplicate-concurrent-contact notices, two connection losses, and one
clean peer-close notice. Its final no-op retained 62 passing contacts with all
11 reconciliation counters zero.

The default receipt's Ping transfer ID was
`1748e202aafb841eab20bf54acc792bcec7df1de1972a6e0a1b7bd9bf0e6e903`
with semantic ID
`370b7e3c9b26ece4877eed6077664a987eee609384fbbb21ec94bc691d1deda3`.
Its Pong transfer ID was
`a4e9ce024127d7b36d4e5e08e3a67b84f6e7fef605f08e7c86a8e311bd3c3757`
with semantic ID
`1022ba758399a264e625782b96d58dd0efa26bab58497dad3e31a65ecff1afd6`
and the Ping semantic ID as its causal correlation.

```text
PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=ping-forward-0-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-1-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-2-to-3 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-3 transfer_id=1748e202aafb841eab20bf54acc792bcec7df1de1972a6e0a1b7bd9bf0e6e903 semantic_id=370b7e3c9b26ece4877eed6077664a987eee609384fbbb21ec94bc691d1deda3 producer_process_absent=true source_authenticated=true ttl=none
PHASE status=pass name=pong-return-3-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-2-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-1-to-0 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
RELAY status=pass intermediates=2 exact_forward=true content_access=denied semantic_acceptance=none
PONG status=received emitted_by=destination-process producer_state=node-3 destination_state=node-0 correlation_semantic_id=370b7e3c9b26ece4877eed6077664a987eee609384fbbb21ec94bc691d1deda3 transfer_id=a4e9ce024127d7b36d4e5e08e3a67b84f6e7fef605f08e7c86a8e311bd3c3757 semantic_id=1022ba758399a264e625782b96d58dd0efa26bab58497dad3e31a65ecff1afd6 source_authenticated=true causal_observation=verified ttl=none
PHASE status=pass name=noop processes=4 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
DEMO_RESULT status=pass scenario=ping-pong nodes=4 processes=18 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none root=/private/tmp/aster-final-default-causal-20260824-n4.wSr6so/mesh
```

The parent PR-A/pre-subscription receipt freeze identifies its composition and
real-process test sources by SHA-256:

```text
bf1555b8749454ae12ac39da284d0d7815a815b9fe957154dbfcdf31b1a15ae0  crates/aster-node/src/runtime.rs
5ae2d26abb08d40bc2d8e48eca2f065f17159db4f706301867ae455df5288165  crates/aster-node/src/main.rs
c3586133d1cee158ab20f9148d7787a4113beef2c182e0b792c240321c00ab5a  crates/aster-node/src/lib.rs
be99c4abdee33ffe92a369a958a84e37a905550f197ca6b390a175dce73d8131  crates/aster-node/tests/mesh_cli.rs
7efab9b8c2fd9a566d35bada2e0ee5865d9ef4f4033fb376b93d5eb26f54e697  crates/aster-node/src/mission.rs
3c33c90dd03c2bd8612e14a94af298164453ebcf53603e51af7b178f14ce3624  crates/aster-node/src/identity.rs
09c17d7fd4233834c783aafc7422869ed833f5e3de07a6685e615fdceedbde0c  crates/aster-redb-store/src/lib.rs
9d1686436d1bfab26ccefeea89b49d5104d30d303e5295d0b668cf525586b56f  crates/aster-redb-store/Cargo.toml
```

The debug artifact stayed byte-identical across the retained real-process
receipts:

```text
path=target/debug/aster
target=Darwin-arm64
format=Mach-O-64-bit
size_bytes=61742936
mtime=2026-08-24T05:45:49-0500
sha256=f7bf097c03d050d99fdfe0fdf83401db870279a300ecfc37d9d5631eea7dd16e
```

The locked/offline Darwin arm64 release build on the same frozen tree used Rust
1.91:

```sh
cargo +1.91.0 build --release --locked --offline -p aster-node --bin aster
```

```text
path=target/release/aster
target=Darwin-arm64
format=Mach-O-64-bit
size_bytes=8776928
mtime=2026-08-24T06:08:48-0500
sha256=c905ffadb6481b2fa947c88ba60141b8117094b0836271a05a23fc07ab4a0a65
```

This is artifact identity and bounded execution evidence, not release
authorization, supported-target coverage, reproducibility proof, signing, or a
cryptographic-module claim.

## Bounded scale probes

The same frozen-tree binary completed an eight-node line with exit status zero
in 84.32 seconds:

```sh
target/debug/aster demo --nodes 8 \
  --root /private/tmp/aster-final-default-causal-20260824-n8.uduyD4/mesh \
  --base-port 64400
```

```text
PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=ping-forward-0-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-1-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-2-to-3 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-3-to-4 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-4-to-5 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-5-to-6 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-6-to-7 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-7 transfer_id=71b8e4b43d39de9e69337692daa5132910f7c558afb532128cf0dfbe9024182c semantic_id=b315bc9207e3d4ba00b0a658a07cbcc54d625e13661447e1e7e3000d41fc34be producer_process_absent=true source_authenticated=true ttl=none
PHASE status=pass name=pong-return-7-to-6 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-6-to-5 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-5-to-4 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-4-to-3 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-3-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-2-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-1-to-0 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
RELAY status=pass intermediates=6 exact_forward=true content_access=denied semantic_acceptance=none
PONG status=received emitted_by=destination-process producer_state=node-7 destination_state=node-0 correlation_semantic_id=b315bc9207e3d4ba00b0a658a07cbcc54d625e13661447e1e7e3000d41fc34be transfer_id=2f2667a3d80866d85d5e90b5affbdee23a9bbbac4becd2967f54d362079b3d77 semantic_id=044c6d80c803e5c3c33ffd834d8d2e624868e9d28f977034066930545e746ef5 source_authenticated=true causal_observation=verified ttl=none
PHASE status=pass name=noop processes=8 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
DEMO_RESULT status=pass scenario=ping-pong nodes=8 processes=38 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none root=/private/tmp/aster-final-default-causal-20260824-n8.uduyD4/mesh
```

Both endpoints had two semantic Events, two acceptance markers, 21,130 sealed
bytes, and no route-cache row. Each of the six intermediates had zero semantic
Events, two route-cache rows, and 21,130 exact cached bytes. All eight nodes
reported `zeroization=live`, zero opaque items, and zero controls. The schedule
used 17 cohorts and 38 children. Every directed-edge cohort moved exactly one
pre-existing Event and retained all six control counters at zero. All 38 child
stdout logs are nonempty (572 lines, 331,748 bytes). Seven of 38 child stderr files retain
ten transient no-op lines (2,195 bytes): five duplicate-concurrent-contact
notices and five connection losses. All 228 passing no-op contacts reported all
11 reconciliation counters zero. Corresponding required contacts succeeded and
convergence passed; this is not a zero-error claim.

This parent-snapshot eight-node root is not the bracketed many-node target,
proof of the full 2–32 range, physical multi-system acceptance, throughput
evidence, or target-tier memory/CPU/power evidence. At that freeze, the formula
only predicted 65 cohorts and 158 children at N=32. The separate current-tree
receipt below supplies one bounded N=32 observation without relabeling this
historical root or satisfying those broader gates.

## Selected N=32 retained receipt

On 2026-08-25, one operator-attested Cargo release-profile binary run for the
signed source commit `6f280b680c0481faae5067e87cdc52d6597dc83c` completed
the selected Event Ping/Pong line at N=32. The retained local root token is
`aster-selected-n32.uEVcAg`; it remains under `/private/tmp` on the validating
host and is not a source artifact. The source tree was
`02167328f8c4dd04ca6f62992d983aff3d8127ff`, and the recorded build and run
were:

```sh
cargo build --release --locked -p aster-node --bin aster
/usr/bin/time -l target/release/aster demo --nodes 32 \
  --root /private/tmp/aster-selected-n32.uEVcAg/run \
  > /private/tmp/aster-selected-n32.uEVcAg/demo.stdout \
  2> /private/tmp/aster-selected-n32.uEVcAg/demo.stderr
```

The wrapper exited zero. The operator attests that the worktree was clean at
both build and execution and records rustc 1.97.1 at commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452` for
`aarch64-apple-darwin`. The validator independently requires the exact signed
Git commit and tree, exact checkout HEAD, public authority-file hashes, binary
size/hash, transcript shape, and every stated scenario invariant. It does not
derive the historical worktree cleanliness and does not cryptographically
prove the source-to-binary-to-execution link. Those two facts remain explicit
operator attestations. The binary is a Cargo release-profile build, not a
signed or product release artifact and not release authorization.

The checked-in
[`aster-selected-n32-receipt/v1` receipt](evidence/selected-n32-6f280b6.json)
is 6,069 bytes with SHA-256
`0138158300b7676efbe074b29b50c62017ab5e0b3cba11fb29ffbe3ee07721eb`.
It contains only bounded sanitized aggregates:

| Evidence dimension | Validated result |
|---|---|
| Topology and identities | One Darwin arm64 host; 32 loopback sockets, 32 mission identities, 32 carrier identities, 32 state directories, and 32 distinct store artifacts; same binary and implementation; one scope, authority, and topic; line topology |
| Schedule and processes | 65 exact phases; 158 exact-named child executions with 158 distinct nonzero READY PIDs; the 62 data-motion phases were serial two-process directed edges; the final no-op phase declared `processes=32` and contained 32 distinct READY PIDs |
| Event interest and relay boundary | Consume 2, Carry 30, 32 selectors; 30 intermediates; `payload_blind_relays=pass`; a terminal inventory of exactly two Event transfers (Ping and Pong) at every node |
| Final no-op | 31 authenticated edges, 451 mirrored cycles, and 902 endpoint receipts; all control, Event, mutable, and Blob reconciliation counters were zero |
| Outer transcript | 70 stdout lines/12,113 bytes; 18 stderr lines/777 bytes classified exactly as Darwin `time -l`; transcript-only safe manifest 318 records/33,102 bytes |
| Child transcripts | 158 stdout files, 1,594 lines, 1,417,290 bytes; 158 stderr files, all empty; 1,274 passing direct-contact receipts |
| Sensitive retained state | Parent mode `0700`, owned by the current validator UID; 32 state directories; 32 mission bundles, 32 identity keys, and 32 stores on 96 distinct inodes; every artifact `0600` or narrower; 33,997,190 aggregate bytes |

The READY-PID checks are log-observed process evidence. Distinct nonzero PIDs
bind each exact-named execution and the 32 final-no-op logs, but no overlap
timestamps or independent OS sampler prove that all 32 processes were running
simultaneously. The receipt makes no concurrency-performance claim.

The validator inspects sensitive state only with metadata operations needed to
bind exact regular-file names, ownership, modes, inode uniqueness, counts, and
sizes. It never opens, reads, or hashes mission bundles, identity keys, or redb
stores. The raw root and raw logs contain credentials or identity-bearing data
and must not be committed, copied into documentation, or treated as a shareable
receipt. The committed JSON contains no input path, PID value, socket, mission
or carrier identity, transfer identity, port, or secret-file digest.

The exact public and sanitized identities are:

```text
6f280b680c0481faae5067e87cdc52d6597dc83c  signed source commit
02167328f8c4dd04ca6f62992d983aff3d8127ff  source tree
5b26134242180affeeaa555175e7400f682c47e14b2e7d2df2decfe14ee5f90c  Cargo.lock
e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987  data-mesh-requirements.md
a0d520be34c6065b1cf482426c6c6800ae27188fb4af75e34a558eaf2c1321ea  target/release/aster; 11,962,608 bytes
fdc828b5bc0462e621a71f958537fe2778d4c5c9b928c5a6ebf8bf9907e24345  exact run argv
8a90c39e4c5eb876ca85274877755eb87e180db5449a64b0e3ec0d309ed08395  safe transcript manifest
72a0d2bda675984ebe85a05f4d1e93d6e77067030e180c14b518004cfd0de5c3  sanitized outer stdout
5eb12c6684037dafca13b2db94cd12a34b0bf50512b7d29ddc8e702952e3c1a6  sanitized Darwin time stderr
8a2e4a701c1fb93f5678a2a3ce2b8b988c87f1519cbed1a64e1309b53c1ade94  sanitized child-stdout aggregate
59e14b66b830621643c2fc478bcf604616983ad90838d340d1166e81dabe5362  empty child-stderr aggregate
d5ffdf083fb2d715098c8e15d2f879246f6a398947c40a18e2d9af20c042e965  tools/check-selected-n32-receipt.py
8ecb091f3b433a7e8938fb2042220f0fb3747a958a1ca87e8124fbbf9da2a092  tools/test-selected-n32-receipt.py
0138158300b7676efbe074b29b50c62017ab5e0b3cba11fb29ffbe3ee07721eb  sanitized checked-in receipt; 6,069 bytes
```

The original validator generation used these exact arguments while the source
checkout HEAD was the signed source commit:

```sh
python3 tools/check-selected-n32-receipt.py \
  --source . \
  --source-commit 6f280b680c0481faae5067e87cdc52d6597dc83c \
  --binary target/release/aster \
  --binary-sha256 a0d520be34c6065b1cf482426c6c6800ae27188fb4af75e34a558eaf2c1321ea \
  --binary-size 11962608 \
  --root /private/tmp/aster-selected-n32.uEVcAg/run \
  --stdout /private/tmp/aster-selected-n32.uEVcAg/demo.stdout \
  --stderr /private/tmp/aster-selected-n32.uEVcAg/demo.stderr \
  --transcript-manifest-sha256 8a90c39e4c5eb876ca85274877755eb87e180db5449a64b0e3ec0d309ed08395 \
  --build-command 'cargo build --release --locked -p aster-node --bin aster' \
  --run-argv '/usr/bin/time -l target/release/aster demo --nodes 32 --root /private/tmp/aster-selected-n32.uEVcAg/run' \
  --wrapper-exit-code 0 \
  --host-os Darwin \
  --host-arch arm64 \
  --rustc-version 1.97.1 \
  --rustc-commit 8bab26f4f68e0e26f0bb7960be334d5b520ea452 \
  --build-target aarch64-apple-darwin \
  --worktree-clean-at-build-and-run \
  --output /private/tmp/aster-selected-n32.uEVcAg/receipt-pid-bound.json
```

That block records the original pre-documentation-commit generation context:
the working checkout was still at `6f280b680c0481faae5067e87cdc52d6597dc83c`.
It must not be run unchanged from a later evidence checkout, whose HEAD includes
the checker and documentation and therefore differs from the signed source
commit. For a future review, invoke the checker from the current evidence
checkout, but pass `--source` a separate checkout or worktree detached exactly
at the signed source commit. Keep the retained binary and raw-root inputs, and
use a fresh nonexistent output path, for example:

```sh
python3 tools/check-selected-n32-receipt.py \
  --source /path/to/aster-source-worktree-detached-at-6f280b68 \
  --source-commit 6f280b680c0481faae5067e87cdc52d6597dc83c \
  --binary target/release/aster \
  --binary-sha256 a0d520be34c6065b1cf482426c6c6800ae27188fb4af75e34a558eaf2c1321ea \
  --binary-size 11962608 \
  --root /private/tmp/aster-selected-n32.uEVcAg/run \
  --stdout /private/tmp/aster-selected-n32.uEVcAg/demo.stdout \
  --stderr /private/tmp/aster-selected-n32.uEVcAg/demo.stderr \
  --transcript-manifest-sha256 8a90c39e4c5eb876ca85274877755eb87e180db5449a64b0e3ec0d309ed08395 \
  --build-command 'cargo build --release --locked -p aster-node --bin aster' \
  --run-argv '/usr/bin/time -l target/release/aster demo --nodes 32 --root /private/tmp/aster-selected-n32.uEVcAg/run' \
  --wrapper-exit-code 0 \
  --host-os Darwin \
  --host-arch arm64 \
  --rustc-version 1.97.1 \
  --rustc-commit 8bab26f4f68e0e26f0bb7960be334d5b520ea452 \
  --build-target aarch64-apple-darwin \
  --worktree-clean-at-build-and-run \
  --output /private/tmp/aster-selected-n32.uEVcAg/review-receipt.json
```

The output path is exclusive and is never overwritten. A replay output must be
6,069 bytes with the checked-in receipt hash above. The independent final audit
reran the 27-case synthetic falsification suite and the complete retained-root
validator to a fresh output; the receipt reproduced byte-for-byte. The
synthetic suite fails closed for truncation, missing/extra/duplicate artifacts
or phases, binary/transcript mismatch, cap overflow, unclassified stderr,
nonzero no-op counters or wrapper exit, unsafe symlinks/hard links/modes or
ownership, missing clean-worktree attestation, duplicate/zero READY PIDs,
secret reads or hashes, and output overwrite.

The outer Darwin `time -l` measurement recorded 309.79 seconds elapsed, 36.27
seconds user, 42.10 seconds system, and a 26,181,632-byte maximum resident-set
field. These are host-specific, measurement-only `wait4` resource-usage fields
for the timed orchestrator and its descendants; maximum RSS is a maximum, not
summed concurrent process RSS. No CPU, memory, disk, network, energy,
target-tier, or other resource threshold receives credit.

This receipt moves only `DM-9-21A` from `implemented-uncredited` to
`observed-bounded`. It is one same-build, same-implementation, one-host,
direct-loopback, one-scope/authority/topic line. It does not move the separate
`DM-9-21` at-least-100-node target and provides no distributed or physical
topology, representative NAT, controlled-relay, BTLE/cross-transport,
State/Record/Blob scale, independent-implementation, packet-capture, resource-
threshold, product-release, or release-authorization evidence.

## Mission-control revocation and rekey receipt

The control scenario is explicit; omitting `--scenario` continues to run the
configurable Ping/Pong demonstration. The frozen invocation was:

```sh
target/debug/aster demo --nodes 4 --scenario control \
  --root /private/tmp/aster-final-control-causal-v4-20260824.M8mlbv/mesh \
  --base-port 64600
```

The four role-bound nodes were authority/member node 0, route-only node 1,
surviving member node 2, and captured member node 3. Two short-lived authority
CLI processes first committed the exact chained controls:

```text
CONTROL status=emitted kind=revocation transfer_id=be65255a87fc078dd35a94a731628e6fe071198c8dd8d36ee40d10c4ffb2e2f1 sequence=1 subject=4978b65eab267816587ffe95b4ce02097a84043dafff50843d55a7dc547a9745 generation=1 activated=1 source_authenticated=true commit_before_activate=true emitted_by=authority-process
CONTROL status=emitted kind=scope-rekey transfer_id=22bb4f203bc6aaa5b7ffdbc70b7601dfe12695c2d7ce04704f7f9e424e08e74b sequence=2 scope=demo/mesh epoch=2 recipients=3 activated=1 source_authenticated=true recipient_filtered=true commit_before_activate=true emitted_by=authority-process
```

Node 0 seeded the route-only node, then both the authority CLI and carrier node
were absent while node 1 forwarded the exact controls to node 2. The demo next
ran node 2 alone with `peers=0` and `contacts=0`; it source-sealed and committed
epoch-two Ping only after its control high-water reached two. A separate
node-1/node-2 cohort then transferred that one exact Event with no control
transfer, making control convergence, local publication, and later forwarding
three distinct process barriers. Two later cohorts required the
node-2/node-3 contact to fail; node 3 could only source-seal one stale local
epoch-one Ping and received neither the control prefix nor epoch-two content.
Node 0 later returned as an ordinary eligible Event process. Four stopped-state
barriers first moved the already-durable Ping from node 1's route cache to node
0, then ran node 0 alone with `peers=0` and `contacts=0` to commit causal Pong,
then moved the already-durable Pong to node 1's route cache, and finally moved
it from node 1 to node 2. Each two-process transfer barrier reconciled one
pre-existing Event difference. The eligible line then restarted to an
equal-inventory no-op: every passing contact reported zero for all six control
counters and all five Event offer/fetch/insert/duplicate/remaining counters.
The terminal receipts were:

```text
PHASE status=pass name=control-authority-seed processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=control-authority-absent-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=control-authority-absent-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=control-authority-absent-event-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=captured-publication-denied processes=2 carrier_authenticated_edges=denied-as-required mission_authenticated_edges=denied-as-required provisioning=unprotected-reference
PHASE status=pass name=captured-rejoin-denied processes=2 carrier_authenticated_edges=denied-as-required mission_authenticated_edges=denied-as-required provisioning=unprotected-reference
PHASE status=pass name=pong-ping-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=pong-relay-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PING status=received emitted_by=surviving-member-process producer_state=node-2 destination_state=node-0 transfer_id=5a1a8436798aad16f2d583dfc7d48d70c7e5471063b9a783b1f4e3102bf43a59 semantic_id=2dd815a4b996957aab71ec2c4c5197483be26a508087dcda96a2d5c0acfba3c3 authority_absent_during_forwarding=true source_authenticated=true key_epoch=2 ttl=none
PONG status=received emitted_by=eligible-member-process producer_state=node-0 destination_state=node-2 correlation_semantic_id=2dd815a4b996957aab71ec2c4c5197483be26a508087dcda96a2d5c0acfba3c3 transfer_id=8cd6cf3245299839c12f398b53e85466713add41f37577221716fef05e8656f1 semantic_id=8e465990083848f1b3b96d0c3d8671700e6091f82e291cdcbdb24bd4d15cc381 source_authenticated=true causal_observation=verified key_epoch=2 ttl=none
RELAY status=pass intermediates=1 exact_forward=true content_access=denied semantic_acceptance=none key_epoch=2
PHASE status=pass name=noop processes=3 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
CONTROL_RESULT status=pass nodes=4 authority_processes=2 emitted_by=authority-process controls=2 control_priority=flash authority_absent_forwarding=pass route_only_forward=pass survivor_epoch=2 captured_node=3 captured_sync=denied captured_epoch2_read=denied captured_mesh_publication=denied captured_rejoin=denied captured_local_signing=stale-only commit_before_activate=true mission_auth=hybrid-pq root=/private/tmp/aster-final-control-causal-v4-20260824.M8mlbv/mesh
DEMO_RESULT status=pass scenario=control nodes=4 processes=23 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy authority_absent_during_forwarding=true authority_cli_absent_after_commit=true authority_carrier_restart=pass controls=source-authenticated-flash recipient_filtered=true payload_blind_relay=pass captured_exclusion=pass epoch2_ping_pong=pass restarts=pass atomic_reaction=pass equal_inventory_noop=pass eligible_transfers_each=2 epoch2_publisher=node-2 root=/private/tmp/aster-final-control-causal-v4-20260824.M8mlbv/mesh
```

Read-only inspection of the retained stores reported:

```text
node-0 zeroization=live events=2 route_cached_events=0 controls=2 applied_controls=2 pending_controls=0 control_highwater=2
node-1 zeroization=live events=0 route_cached_events=2 controls=2 applied_controls=2 pending_controls=0 control_highwater=2
node-2 zeroization=live events=2 route_cached_events=0 controls=2 applied_controls=2 pending_controls=0 control_highwater=2
node-3 zeroization=live events=1 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
```

The 53-second run retains the exact 16-line parent terminal stdout (3,851
bytes) and empty parent stderr, plus 23 nonempty child stdout files (128 lines,
72,159 bytes) and 23 child stderr files. Four child stderr files are nonempty
with 109 lines (26,431 bytes), all inside the two required captured-contact
denial cohorts: 30
durable-revocation errors, 25 duplicate-concurrent-carrier-contact notices, and
54 peer-close effects. Every successful cohort retained zero stderr.
This is not a general zero-error claim. It is also not physical capture,
protected provisioning, a zeroization receipt, generalized control
administration, multi-scope or repeated rekey, independent interoperability,
scale, or release evidence.

## Local software zeroization receipt

The bounded local hook is a separate acceptance path; it does not reinterpret
the control scenario's `captured_local_signing=stale-only` result. The retained
post-fsync frozen-tree root is:

```text
/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm
```

After the same binary completed a two-node Ping/Pong setup at base port 64800
with exit status zero in 20.31 seconds and eight causal child processes, node 0
contained two source-authenticated Events and one additional opaque
compatibility row. A
setup Ping used transfer ID
`27542ed3a77ec77dfdfbe8f9fed53db73a0dbd109027ff163ae35fd09a7d5b09`
and semantic ID
`b8603f5b41cd8a614dc104d74019408dab9db12d5ab90705b98b71980c2d67c4`;
Pong used transfer ID
`010703ba7dcf1240ca3bf121031d0aea94108b7fa5bc4036ee9aa8d70b333718`
and semantic ID
`0b9fc8310aacec4ce9549f912b9f9f2a1587f286d4b9a19854bdf63719a3f697`,
causally correlated to that Ping. A same-UID process then started node 0 with
no peers on port 64810 and invoked:

```sh
target/debug/aster zeroize \
  --state /private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0 \
  --mission-bundle-unprotected-reference \
    /private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0/mission.unprotected-reference.bundle \
  --wait-seconds 20
```

The live node and CLI emitted:

```text
READY selected=true pid=22080 carrier_id=69443fe89e3b54b1d97f6be1d4ee213d788c0b82d2abe8ac8012626a6fa8af78 mission_id=cec7fde3bb78ed74a584be51244bd025473bf3e81206b9d70a354e68f3e22f6f mission_authority=d0e5df62e9c8ca1aa5eb5cce201f4e60684bed215d500fcc40e25bd451699504 sockets=127.0.0.1:64810 state=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0 peers=0 application=relay mission_auth=hybrid-pq provisioning=unprotected-reference semantics=source-authenticated-event controls=source-authenticated-flash commit_before_activate=true content_admission=capability-gated
STOP lifecycle=zeroized sync_status=terminal-lockout carrier_id=69443fe89e3b54b1d97f6be1d4ee213d788c0b82d2abe8ac8012626a6fa8af78 mission_id=cec7fde3bb78ed74a584be51244bd025473bf3e81206b9d70a354e68f3e22f6f contacts=0 contact_errors=0 opaque_items=1 opaque_acceptance_markers=1 events=2 event_acceptance_markers=2 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0 mission_auth=hybrid-pq provisioning=unprotected-reference assurance=bounded-software physical_sanitization=not-claimed
ZEROIZE status=pass mode=live state=complete mission_destroyed=true carrier_identity_destroyed=true mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length data_rows_preserved=true opaque_items=1 events=2 route_cached_events=0 controls=0 assurance=bounded-software physical_sanitization=not-claimed local_authority=same-uid-operator state_root=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0
```

The zeroize CLI exited zero in 0.074759 seconds; the live node emitted its
terminal stop and exited zero in 0.164328 seconds. Read-only inspection then
reported:

```text
INSPECT status=pass state=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0 zeroization=complete opaque_items=1 opaque_acceptance_markers=1 opaque_bytes=11358 events=2 event_acceptance_markers=2 event_sealed_bytes=21130 route_cached_events=0 route_cached_bytes=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
ITEM id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Before destruction the owner-only mission bundle was 5,675 bytes at inode
266049362, `identity.key` was 32 bytes at inode 266049359, and `mesh.redb` was
184,320 bytes at inode 266049367. All three were on device 16777230, mode
`0600`, effective UID 502, and link count one. After the receipt, both secret
pathnames kept their exact device, inode, mode, owner, and single-link count but
had length zero and the empty-file SHA-256. The redb inode remained and held the
terminal marker and preserved rows. This is retained-inode content destruction,
not inode or pathname deletion.

The mission bundle moved from SHA-256
`36ae0f10f03dfbf965245d444619848acfccec205a3dc240c8d84d7dc080121c`
to the empty-file digest
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
The carrier identity moved from
`08423318e7dc663976c4ed043f6523fced1818a82668deb81a9dc83368728377`
to that same empty digest. Restoration and the later idempotent replay retained
the original digest for each exact inode. The retained store changed from
`9735f2704fbbac13c8a6cda69a58c91a7d1f05797c2ae450de5cd01184873555`
to `dd0114425580b39c06f9685a8987a757936c9856b8c9ab7b02e7be3c12a65ff2`
when it committed the terminal marker. The idempotent replay retained the same
device, inode, mode, owner, link count, size, terminal state, and data rows but
updated the redb file digest to
`ee7bf5d705cd25fdb16df22a702b351fcfc26cf960471e4f0c6459450449e9d0`.

The harness then restored the exact original credential bytes and hashes into
the same two inodes. A normal node restart exited one in 0.006637 seconds,
emitted no `READY` or contact, and returned:

```text
ERROR error=store%20is%20terminally%20locked%20out%20in%20Complete%20state
```

An idempotent replay exited zero in 0.032051 seconds, reported both pathnames as
`retained-external-change`, left the externally restored files untouched, and
left terminal inspection unchanged:

```text
ZEROIZE status=pass mode=stopped state=complete mission_destroyed=true carrier_identity_destroyed=true mission_pathname=retained-external-change carrier_identity_pathname=retained-external-change data_rows_preserved=true opaque_items=1 events=2 route_cached_events=0 controls=0 assurance=bounded-software physical_sanitization=not-claimed local_authority=same-uid-operator state_root=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0
```

The retained root contains 64 files totaling 467,815 bytes. Its receipt summary
has SHA-256
`fcf9d110253a7396af93c2e251883627c93e6a3b36a314f2eea59b866f507fd7`.
Its 62-entry file/byte manifest lists 448,617 bytes and has SHA-256
`450d97bc536d344efa5c85f93d248da4066e91a605a0fb4a236155ffda290066`;
the verified 63-entry evidence manifest has SHA-256
`c7ce69404b8e9463e81d1b8c56d61604d75f71b2b0694e850762f2785fbd8edb`.
The summary pins the unchanged frozen binary and both changed sources to the
digests recorded above. Its independent full-root scan found neither complete
credential encoded as hex nor complete credential encoded as base64;
`secret-scan.matches` is empty. The retained 11,358-byte `LICENSE` opaque row
has SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
A separate
integration child commits the
Immediate-durability terminal marker and exits abruptly before artifact
destruction; the later CLI resumes only the exact recorded inodes, reaches
`complete`, and preserves its preexisting row. Store and node tests also require
wrong authority, corrupt/partial marker, symlink, hard-link, owner/mode,
path/inode replacement, and phase-order failures to remain terminal and fail
closed without erasing replacement data.

This is `observed-bounded` evidence for DM-6-22 only. It covers same-UID Unix
software erasure of the selected unprotected-reference mission bundle and Iroh
carrier identity. The manual live receipt had no active peer or mid-flight
stream. It does not prove deterministic remote teardown observation, inode
deletion, physical flash or copy-on-write sanitization, snapshot/swap/backup
destruction, redb rollback or replacement resistance, non-Unix support, remote
triggering, protected provisioning, or independent platform assurance.

## Mission-authenticated runtime validation

The current verification lanes include:

```sh
cargo test --locked --offline -p aster-core --all-features
cargo test --locked --offline -p aster-redb-store
cargo test --locked --offline -p aster-node --all-features
```

On 2026-08-24 the parent PR-A/pre-subscription frozen tree passed 336 `aster-core` tests, 57 redb-store tests,
48 node-library tests, six node-binary tests, ten node integration tests
(including the default four-node Ping/Pong, explicit four-node control, live
zeroization, abrupt-marker recovery, and dirty-process recovery cells), and doc
tests. Current-toolchain formatting, Clippy with warnings denied, and the full
workspace check passed; every target and feature also checked on Rust 1.91.
Five fuzz campaigns completed 10,000 iterations each (50,000 total) over wire,
fragment, envelope, selected-frame, and selected-Negentropy decode paths with no
finding. Those counts and retained roots are historical parent evidence, not
current PR-B, PR-C, or selected State execution receipts.

The signed PR-B code baseline above passed the same current and exact
Rust 1.91.0 matrix with 336 `aster-core` tests, 73 redb-store tests, 62
node-library tests, six node-binary tests, and 11 real-process integration tests
(488 total per toolchain). Both strict Clippy gates and formatting passed. After
the directional Event-frame update, all five fuzz campaigns again completed
10,000 iterations each (50,000 total) with no crash. The documented two-node
capability tour passed, and the selected Event example demonstrated publish,
fresh query, durable subscribe/poll/ack, and an exact idempotent second run.
These are current code/test execution checks, not protected-provisioning,
physical-carrier, mixed-implementation, scale, or release evidence.

The runtime suite covers mission authentication before inventory, independent
carrier/mission binding, protected mechanics, exact negotiated Fetch/Offer
sets, source-authenticated control chains, control-before-Event admission,
pending control gaps, atomic commit-before-activate, control restart replay,
Event source/content verification, peer scope-route filtering, route-only relay
behavior, durable operation replay, and fail-closed stale-epoch and revoked-peer
cells. It also retains the negative cells for wrong carrier, wrong mission,
cross-mission credentials, tamper, plaintext mechanics, replay, and unauthorized
Fetch/Offer. The zeroization cells add live drain, terminal store lockout,
retained-inode destruction, restored-credential refusal, idempotent replay,
abrupt-marker resumption, fail-closed artifact/path adversaries, and an injected
Unix parent-directory synchronization failure before any writable store or
terminal cleanup handle becomes usable. This does not replace physical-network,
packet-capture, physical sanitization or power-loss acceptance, database
rollback resistance, non-Unix, independent interoperability, or cryptographic
review evidence.

## Dependency-admission gate

The Iroh-first implementation removed the active unmaintained `paste` package
instead of expanding the retained-pilot exception. The workspace path-patches
exact `netlink-packet-core` 0.8.2 with byte-identical Rust sources so its
dependency key resolves to maintained `pastey` 0.2.2. The root lock and active
graphs contain no `paste`; CI fails if it reappears. Patch provenance and the
upstream-removal condition are recorded in
[`ASTER-PATCH.md`](../../third-party/netlink-packet-core-0.8.2-aster/ASTER-PATCH.md).

Decision 0028 records stakeholder approval for exact-package deviations, and
`deny.toml` encodes them narrowly: `webpki-roots` 1.0.9 and
`webpki-root-certs` 1.0.9 under `CDLA-Permissive-2.0`, plus the browser-WASM-only
`async_io_stream` 0.3.3, `pharos` 0.5.3, and `ws_stream_wasm` 0.7.5 under the
OSI-approved `Unlicense`. Neither license is in the general allowlist; only
those exact package/version coordinates are excepted, and coordinate drift
fails closed. This admits the current dependency graph under the approved
exception policy. It does not establish literal `DM-8-05` compliance: the
frozen requirement says all dependencies must use OSI-approved licenses, so the
two CDLA data-package deviations require an express requirement revision or
disposition, or an approved technical alternative. The supported target matrix,
SBOM, packaging, and release authorization also remain open.

The controlled-relay slice adds a direct `rustls` 0.23.43 edge but no new
`rustls` package or version. The normal selected-node graph reaches Iroh's
client-side `iroh-relay` support without enabling its `server` or `test-utils`
features. The optional `aster-iroh/test-utils` dev/all-feature fixture enables
that local relay-server graph and adds its lockfile-only test dependencies.
Passing the serialized dependency/license gates records compliance with the
current exact-exception policy; it is neither a claim of normative `DM-8-05`
closure nor supported-target, SBOM, packaging, or release acceptance.

## Requirements still open in the selected lane

| Requirement class | Current state | What must be delivered before complete credit |
|---|---|---|
| Remaining data model | `implemented-uncredited` / `open` | Extend the retained bounded live State/Record and interrupted/reopened/different-peer Blob observations into longer partitions, relays, causally divergent State sequences, broader restart/crash windows, arbitrary-peer continuation, physical systems, and independent interoperability; preserve and broaden the retained bounded State positive-current-version acceptance and decide any required materialized-view/withdrawal contract; retain forced-process Record whole-projection delivery acceptance; retain equivalent Blob exact-publication delivery acceptance and add Blob peer/convergence status; design convergent registered-policy Record merge; add route-only Blob custody, multi-class retention/explicit GC, and broader conflict/deletion behavior |
| Source and mission security | `implemented-uncredited` / `observed-bounded` / `open` / `external-gate` | Operationalize the additive exact profile-`0x0002` provisioned policy/Event/control/Iroh mission mechanisms through a named stock runtime, protected provisioning, CLI/bindings, snapshot-resistant rollback, and representative packet-capture plus compute/memory/bandwidth/idle/energy evidence; retain profile `0x0001` without reinterpretation; extend the caller-provided protected live Rust config and stopped Event/admin seams through an admitted production backend, issuance/recovery, and a coordinated live-drain/store-terminalization/provider-destroy lifecycle; add generalized multi-family control policy plus automatic/atomic revocation remediation; verify multi-scope, repeated, longer-partition, and physical revocation/rekey propagation; add non-Unix and physical/copy-on-write/snapshot/swap/backup zeroization assurance, each profile's admitted FIPS boundary, mixed-implementation interoperability, and independent cryptographic review |
| Custody and constrained operation | `observed-bounded` / `implemented-uncredited` / `open` | Selected Event/RouteEvent has semantic-v3-format cumulative age inherited by v4/v5, Linux finite Event TTL, expiry/GC, priority scheduling/retry, bounded quotas, thresholds, and receive-only inbound. One retained Linux-container receipt now observes exact threshold withholding, route-only custody, two expiry points, explicit pressure retirement, persisted quota replacement, priority-ordered delivery, and ReceiveOnly ingestion with zero local-object disclosure. Normal and AtLeast run v4/v5 mutable work and may run the v5 Blob lane because AtLeast is Event-only; ReceiveOnly initiates/discloses neither mutable nor Blob work. Selected finite State/Record/Blob TTL remains rejected/open. Still required are retry-cadence acceptance, complete cross-class priority eviction/custody, route-only Blob custody, non-Linux Event age, physical RF silence and constrained-link evidence, bindings, scale, mixed implementations, and release authorization. |
| Scope and application policy | `implemented-uncredited` / `open` | Retain the static semantic-v6 Event hierarchy execution boundary; then add supported multi-scope join/leave administration, bandwidth and complete storage quotas, dynamic routing/interest and peer policy, revocation/rekey lifecycle, and cross-class bridge custody. Separately broaden State/Record application-selector evidence, decide materialized-view/withdrawal requirements, add automatic registered-policy Record merge and atomic subscription update, and provide equivalent live status/gap semantics beyond Event. |
| Blob behavior | `observed-bounded` / `implemented-uncredited` / `open` | One signed-source retained receipt covers bounded live Blob class support, immutability, peerless publication, direct seeding, exact partial progress across graceful reopen, different-eligible-peer continuation without source refetch, completion, and final reopen. Current code additionally has a durable metadata-only exact-publication delivery ledger with local counts; cleanup, race, and delivery-ledger cases remain automation only. Retain delivery acceptance and add class-specific peer/convergence status, process/crash and long-offline recovery, arbitrary-peer and route-only relay/custody behavior, TTL and an explicit staging-GC protocol; decide whether a metadata-independent pure-byte content ID is required; add complete physical accounting and hundreds-of-MiB/RSS acceptance. |
| Carrier portfolio | `implemented-uncredited` / `observed-bounded` / `open` / `external-gate` | Selected direct IP and one explicitly trusted singleton relay mechanism now exist, with one retained cone/direct and restrictive/controlled-relay software namespace-NAT observation. Still required are physical IP, representative NAT direct/fallback, discovery/punching policy, BTLE platform driver, smallest-MTU framing, link characteristics, State/Record/Blob-over-relay acceptance, mobility/outage recovery, mixed implementations, and future-carrier proof. |
| DDIL resilience | `open` / `external-gate` | Loss/bandwidth floors, long custody/offline interval, crash/corruption recovery, broader partial-contact durable progress and alternate-peer/carrier continuation beyond the one bounded direct Blob case, mobility, and power/emission measurements |
| Developer surface | `implemented-uncredited` / `open` | Preserve the documented live State positive-current-version, Record whole-key active-head, and Blob exact-publication delivery boundaries; add minimal compiled developer-facing State/Record/Blob delivery samples distinct from retained acceptance harnesses; add Blob peer/convergence status; add automatic merge only after a convergent design, atomic subscription update if required, C FFI and at least two selected-node bindings, broader multi-class examples including live privileged administration, carry caller-provided protected Rust startup and typed live/stopped control administration into the stock CLI/bindings with a production backend/recovery/destroy workflow, run an independent usability study, and decide the optional local agent |
| Scale and resources | `observed-bounded` / `open` / `external-gate` | Retain the one-host direct-loopback selected Event N=32 receipt as the bounded `DM-9-21A` observation; still obtain stakeholder-confirmed bracketed targets plus repeatable at-least-100-node, inventory-size, memory, CPU, binary, bandwidth, and energy evidence on target tiers |
| Interoperability and release assurance | `open` / `external-gate` | Independent conformant implementation, mixed-version/downgrade evidence, completed hostile-peer campaigns, admitted dependency/license/SBOM graph, physical acceptance, and signed release disposition |

The proven semantic implementation remains the source to migrate. Its existence
outside the selected composition alone is not selected-composition credit, and
research evidence cannot replace production-lane verification.
