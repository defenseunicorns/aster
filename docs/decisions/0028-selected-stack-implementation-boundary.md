# Decision 0028: Start the selected-stack implementation behind an isolated profile

> ****

- Status: accepted — Iroh-first implementation migration; release admission gates open
- Date: 2026-08-23
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Related: [Decision 0002](0002-dependency-admission.md),
  [Decision 0025](0025-requirements-first-foss-architecture-evaluation.md),
  [Proposal 0006](../../archive/research/proposals/0006-selected-foss-reference-stack.md), and
  [Proposal 0006 result](../../archive/research/evaluations/0006/README.md)

## Context

Proposal 0006 retained Iroh 1.0.3, Negentropy 0.5.1, and redb 4.2.0 as a
bounded engineering baseline. That result stops broad whole-stack substitution
research, but it explicitly does not admit the dependency graph or select a
production stack.

The existing `aster-core` owns a large SQLite schema and custom sparse-inventory
and synchronization implementation. Adding redb and Negentropy inside that
crate now would create overlapping persistence and reconciliation authorities.
Wrapping Iroh behind the existing IP seam would also preserve a boundary that
had zero selection weight in the requirements-first evaluation.

At the time of this decision, Decision 0002 still recorded redb as evaluated
but not adopted and Iroh as rejected pending a bounded exception. Iroh 1.0.3
also declared Rust 1.91 while the workspace minimum was Rust 1.90. The later
implementation update below records the stakeholder's explicit resolution;
the earlier proposal result alone did not supersede those gates.

## Implementation update — 2026-08-23

The stakeholder approved Iroh-first as the production implementation direction
and approved raising the workspace minimum to Rust 1.91. Iroh 1.0.3,
Negentropy 0.5.1, and redb 4.2.0 may therefore enter the active implementation
graph behind the boundaries in this decision. This is implementation authority,
not release authorization: exact license, advisory, SBOM, security, physical
carrier, interoperability, and operational acceptance gates remain binding.

## License-policy update — 2026-08-25

After review of the exact Iroh 1.0.3 graph, the stakeholder approved the
package-scoped license disposition below. This is an explicit deviation from
the frozen baseline's literal OSI-approved-only dependency rule for the two
CDLA data packages; it does not rewrite the requirements artifact or claim an
outside-counsel conclusion. `Unlicense` is OSI-approved, but is kept in the same
exact-package mechanism instead of expanding the repository-wide allowlist.

| Package | Exact version | Reachability | Disposition |
|---|---:|---|---|
| `webpki-roots` | 1.0.9 | native compiled Mozilla trust-root data through `iroh-relay` | admit `CDLA-Permissive-2.0` for this coordinate |
| `webpki-root-certs` | 1.0.9 | all-target trust-root inventory through Iroh's HTTP/TLS graph | admit `CDLA-Permissive-2.0` for this coordinate |
| `async_io_stream` | 0.3.3 | browser-WASM-only chain beneath `ws_stream_wasm` | admit `Unlicense` for this coordinate |
| `pharos` | 0.5.3 | browser-WASM-only chain beneath `ws_stream_wasm` | admit `Unlicense` for this coordinate |
| `ws_stream_wasm` | 0.7.5 | Iroh relay's browser-WASM transport | admit `Unlicense` for this coordinate |

`deny.toml` encodes five name-and-exact-version exceptions; neither license is
added to the general allowlist. Any package/version/license drift therefore
fails closed and requires a new review. [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md)
records the exact crates.io archive checksums and complete CDLA and Unlicense
texts. Distribution packaging must include that file; the project-license gate
hash-pins it and verifies its inclusion in the shipped lab image.

This disposition removes the exact dependency-license CI hold and permits the
implementation stack to merge. It does not declare browser-WASM a supported
release target, authorize hosted relay operation, satisfy independent
interoperability or physical acceptance, or make the selected composition a
production-authorized release. Requirement `DM-8-05` remains open and
uncredited against the frozen baseline unless its owner expressly revises that
normative rule; the deviation remains visible rather than being counted as
requirements compliance.

Iroh endpoint authentication is carrier evidence only. The hybrid-PQ session,
protected envelopes, source authentication, data classes, causality,
custody/TTL, scopes, and authorization already implemented and tested in
`aster-core` are the semantic migration source. They are to be ported onto the
new composition rather than independently reinvented. No old implementation
path is removed until its replacement passes equivalent tests.

## Decision

Begin the selected-stack implementation as an isolated migration lane:

1. Add dependency-free `aster-profile` as the requirements-owned semantic
   vocabulary shared by future replica, storage, reconciliation, policy, and
   security implementations.
2. Define stable item and publisher identifiers, the four current extensible
   data classes, the four current provisional priorities, topic, scope,
   perishability, a causal
   publisher-counter context, and a
   reconciliation ordering key derived only from the full item identifier.
3. Keep wall-clock time, replica-local insertion order, wire encoding,
   evaluator behavior, databases, and carriers outside this crate.
4. Introduce future `aster-redb-store` and Negentropy reconciliation crates as
   siblings that depend inward on the profile. A profile-agnostic Iroh carrier
   remains a separate sibling; the composition root depends on both layers.
   Each requires its own exact-graph dependency admission and evidence.
5. Permit only one selected durable acceptance/effect authority at a node.
   redb cutover must replace, not duplicate, the corresponding SQLite owner.
6. Treat the current SQLite/custom-sync/IP path as the proven semantic and test
   source during migration, without running a second selected persistence or
   reconciliation authority beside it. The libp2p path remains only the bounded
   retained oracle described by Decision 0029. This decision removes neither;
   each displaced mechanism stays until its replacement passes equivalent tests.

The evaluation profile-v0 wire corpus is seed material, not a product format.
No product encoder or decoder may copy its undeclared extension behavior.
The crate's initial ASCII name syntax and size ceilings are implementation work
bounds, not a frozen protocol or stakeholder limit. Item metadata remains
separate from its opaque identifier until a normative encoding and source
verifier define and test that binding.
Data-class and priority vocabularies are opaque and extensible; they assign no
numeric wire discriminants, preserving later registry evolution.

## Cutover gates

Before any selected mechanism becomes the default, a later decision must bind:

- the exact admitted dependency graph, Rust minimum, licenses, advisories,
  security process, SBOM, and support owner;
- the normative profile and an independently implemented conformance corpus;
- schema migration, rollback, mixed-version, and data-preservation behavior;
- parity for restart, duplicate delivery, crash boundaries, any-peer resume,
  bounded fallback, and hostile input;
- deletion of the displaced store, reconciliation, and carrier machinery; and
- the remaining security, Blob, policy, physical-carrier, target, and release
  gates recorded by Proposal 0006.

## Consequences

- The first implementation PR can establish a stable semantic dependency
  direction without expanding the runtime graph or weakening the MSRV.
- The dependency-free slice adds no committed package SBOM. Generation and
  review are explicitly deferred to the cutover/dependency-admission gate
  before any selected runtime dependency is admitted.
- Stable full-ID ordering is a profile prerequisite. The later Negentropy
  adapter must additionally prove that no timestamp or replica-local ordinal
  can override it before the selected-stack defect is considered prevented.
- Restart, crash-atomic effect, and provider-identity tests remain deferred
  until the real redb and Iroh implementations exist; mocks must not freeze
  invented production seams.
- Existing behavior and public APIs remain unchanged in this phase.

## Semantic-v4 State/Record cutover amendment (2026-08-25)

This amendment supersedes the earlier phase statement that existing selected
behavior remains unchanged. That statement remains above as the historical
boundary of the dependency-free implementation phase.

The selected stack now composes one semantic-v4-only State/Record
reconciliation authority behind the existing redb writer and hybrid mission
session. Event remains compatible across semantic versions 1 through 4; v1-v3
contacts contain no mutable frames. Stable wire/profile, handshake framing,
source-object formats, and suite remain version 1.

The mutable cutover preserves the one-authority rule. State and Record and both
receiver directions have independent protected lanes, while one contact policy
lease binds interest, inventory, serving, admission, exact result/
acknowledgement, finish remainder, and cursor advancement. The selected store
caps each object at 1 MiB and each class at 4,096 rows/16 MiB. Valid saturation,
including the bounded causal frontier, defers without pruning; malformed,
unauthorized, wrong-lineage, and integrity failures remain fatal.

Repeated partial contacts rotate after a durable authenticated peer/class/local
Offer/Fetch cursor. Reserved cursor metadata is capped at 256 configured peers
and 1,024 rows and is pruned before sockets after mandatory source proof. Normal
and AtLeast run mutable lanes; AtLeast is Event-only. ReceiveOnly initiates and
discloses no mutable lane. Event status is not mutable convergence.

Current route lineage is required. Same-epoch historical lineage is withheld
from ordinary current projection/query and network inventory/transfer, while
an exact idempotent State publish or Record publish/resolution retry may recover
its committed result only through strict cached/projection/historical
verification. Selected finite State/Record TTL is rejected. Blob networking,
physical carriers/NAT/relay,
BTLE, mixed implementations, N=32/resource brackets, and every release gate are
still outside this amendment.

## Semantic-v5 direct Blob continuation amendment (2026-08-25)

This amendment advances only the bounded direct-content Blob slice. The
semantic-v4 amendment above remains the historical State/Record cutover and its
formats and behavior are inherited unchanged.

The selected default offer is now `[5, 4, 3, 2, 1]`. Event remains compatible
across v1-v5; State/Record run in v4 and v5; only v5 allocates selected Blob
source and carrier frames. V1-v4 contacts emit and accept zero Blob frames.
Stable wire/ABI version 1, session framing, source envelopes, manifests,
`ASTRBT01` carriers, typed ObjectIDs, and cryptographic suite do not change.

The redb writer remains the sole visibility authority. V5 first reconciles and
atomically stages a fully authenticated Blob source and exact manifest plan,
then transfers at most 16-KiB contiguous carrier-prefix extensions. Pending
progress is keyed by source and carrier, not peer or session, so another
eligible authenticated content peer may resume the exact complement. The
requester's finish count is echoed only for sequencing; exact Result/Ack tuples
record accepted prefix progress.

Every inventory, source, and range send requires current route authorization,
durable nonrevocation, and an opaque peer/mission/selector/current-content-grant
proof. Selected route-only Blob relay is not enabled. Source route lineage and
a distinct physical content lineage are rechecked before service and promotion.
After same-epoch key replacement, old rows and proofs are withheld; a new
physical lineage for the same `(BlobID, content group, numeric epoch)` is also
rejected with `PhysicalLineageConflict`, so retry requires an epoch advance.
Terminal or stale source retirement preserves an exact non-public depot import,
which may be expected-only or already finalized, and any expected/committed
chunk staging while removing pending
source and prefix visibility. The retained rows, files, finalized digest, and
reserved/committed accounting consume the existing bounded byte, chunk, and
variant quotas, remain owner/backing-bound and open-path audited, permit only
exact-lineage resume at that epoch, and introduce no table or schema. A future
explicit GC protocol is required to reclaim them.

The selected network bounds are 64 MiB plaintext, 1,024 chunks, 10,000 pending
rows, 64 MiB of pending prefix bytes, and 16 KiB per range. No pending source or
carrier is ordinarily visible. Atomic promotion requires every canonical
carrier, depot completion, a fresh full-content proof, and a fresh current-
lineage proof to agree with the exact plan.

Read-only, writable, and terminal-preservation opens cross-audit pending source,
manifest route, carrier set, depot plan, and the completed namespace; mismatch
or pending/completed collision fails without repair. The predecessor nine-table
Blob schema gains the four v5 network tables only as one wholly absent group on
a writable owner-attributed migration. Read-only or partial-group open does not
migrate or repair state.

Durable source transitions and authenticated-cache transitions share one local
lifecycle lock, including staging, repair, retirement, and reconciliation. The
lock crosses no await or network work. Post-abort reconciliation rereads and
freshly authenticates any exact concurrent restage before restoring its cache
claim. A terminal multi-carrier source advances its scheduler cursor to the
lexicographically greatest carrier ID in the source, not manifest-last.

Normal and AtLeast run the lane; AtLeast remains Event-only. ReceiveOnly runs
zero Blob work. Live Blob application access/subscription, route-only relay or
custody, TTL/expiry/GC, pure-byte identity/deduplication, large-file and resource
acceptance, physical/multicarrier execution, mixed implementations, and release
authorization remain outside this amendment.

## Controlled Iroh connectivity-relay amendment (2026-08-25)

This amendment advances only the bounded selected carrier route beneath the
existing peer QUIC and hybrid mission session. A node may use its exact initial
direct locator with exactly one operator-pinned relay, or enter an explicit
relay-only mode. The relay is connectivity infrastructure: it owns no Aster
store, route grant, custody, semantic reconciliation, or application
authority. It is distinct from an Aster mission node performing payload-blind
Event route-only custody. Selected route-only Blob relay/custody remains
unimplemented.

The relay locator must be one HTTPS root origin with a host and no user
information, non-root path, query, or fragment, and is capped at 2 KiB. Trust
is explicit: either embedded WebPKI roots or one to eight operator-supplied DER
CA roots, each at most 64 KiB and at most 256 KiB combined. Explicit roots
replace WebPKI. There is no insecure TLS mode, WebPKI fallback from explicit
roots, public/default relay substitution, hosted lookup, or port mapping.

The carrier `PeerRoute` accepts at most eight sorted unique operator-supplied
initial direct candidates and at most 3,072 serialized bytes. The current node
CLI deliberately supplies one initial socket for each legacy `--peer` value. In
direct-plus-controlled-relay mode the node binds direct UDP/IP and does not
wait for relay readiness, so a dead relay does not block the exact direct
candidate. Relay-only mode waits for the pinned relay before reporting ready,
clears all IP transports, and supplies no direct candidate.

These are initial route hints, not lifetime address pins. Iroh may probe direct
and relay paths in parallel and, after authenticating the exact endpoint ID,
may derive later direct paths through its NAT negotiation. The endpoint ID and
sole relay origin remain exact; there is no direct-first chronology or temporal
fallback guarantee. Representative NAT behavior is not accepted by this
amendment.

The runtime reports only the most recently observed Direct, Relay, or Unknown
path plus a coalesced transition count capped at 1,024 and a saturation marker.
Ordinary close retains the last observation; event loss or continuity failure
produces Unknown and saturation. This witness is bounded diagnostic state only
and never establishes identity, mission membership, authorization, admission,
receipt validity, transfer success, or convergence.

The implementation is bound to signed code commit
`b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`. Focused carrier, CLI, and
real-process tests cover exact route/trust bounds, pinned TLS and no trust
fallback, direct and relay selection, dead-relay direct operation, identity
failure, bounded relay loss, flag redaction/fail-closed parsing, one-host Event
transfer over Relay, equal-inventory no-op, and unavailable-relay direct
operation. The final serialized repository gate passed 170 node-library, 12
node-binary, 20 `mesh_cli`, and 13 carrier tests plus workspace/doctests,
language, conformance, license, and dependency-boundary checks. A fresh
all-feature Rustdoc build also passed with warnings denied.

This is current-code software evidence and creates no retained receipt or new
`observed-bounded` credit. Physical systems, representative NAT, BTLE and
cross-transport operation, mixed implementations, N=32, resource brackets,
payload-blind Aster-relay behavior, capture/privacy acceptance, State/Record
or Blob over the controlled relay, route-only Blob custody, and every release
gate remain open. No
wire/profile, semantic, source-object, ABI, cryptographic-suite, or
`aster-carrier/1` framing version changes.

The normal node graph already contains Iroh's client-side `iroh-relay`
dependency without enabling `iroh-relay/server` or `test-utils`; only the
dev/all-feature `aster-iroh/test-utils` fixture adds that server/test graph and
its server/ACME packages. The direct `rustls` 0.23.43 edge adds no new locked
package/version. Exact graph/license, advisory, SBOM, supported-target,
security-process, support-owner, and release-admission gates remain binding.
