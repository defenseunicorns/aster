# Decision 0033: Select security properties through authenticated mission profiles

> ****

- Status: accepted; initial classical evaluation implementation present; release gates open
- Date: 2026-08-28
- Authority: stakeholder-approved applicability revision dated 2026-08-28 to
  the preserved [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Derived row mapping:
  [security-profile requirements disposition](../validation/security-profile-requirements-disposition.md)
- Related: [Decision 0001](0001-standards-and-provider-boundaries.md),
  [Decision 0003](0003-fips-production-gate.md),
  [Decision 0012](0012-content-committing-pq-batches.md), and
  [Decision 0028](0028-selected-stack-implementation-boundary.md)

## Context

The hash-bound requirements baseline made transport-independent metadata
protection and hybrid classical/post-quantum cryptography universal. The stock
selected implementation consequently uses complete hybrid suite `0x0001`, an
Aster hybrid mission handshake, and `ASTRFR01` record protection even when Iroh
already supplies authenticated encrypted QUIC.

That construction remains a useful high-assurance profile. It is not the only
credible operational choice. Applying every layer on every contact adds
handshake work, bytes, code paths, working memory, and potentially radio-on time
without always adding a distinct property. The baseline records no threat
horizon, harvest-now-decrypt-later decision, or compliance rule that requires
post-quantum protection for every mission. It also states metadata opacity as an
absolute even though endpoints, timing, sizes, and some carrier routing data are
necessarily observable.

The product intent is instead to keep payload protection and semantic authority
strong while making metadata and post-quantum costs explicit policy choices.

## Decision

### Profile-invariant guarantees

Every supported security profile must preserve these properties:

1. Every source item is encrypted and authenticated independently of its
   carrier, remains protected at rest and through store-and-forward custody,
   and is freshly verified before semantic consumption.
2. A carrier endpoint identity alone never grants mission membership, control
   authority, route access, content access, or source authority. Mission
   authority derives from an Aster credential or proof. For an interactive
   carrier, that proof is authenticated, replay resistant, and bound to the
   exact channel before inventory or protected synchronization metadata is
   disclosed. An offline/file carrier instead binds equivalent authority to the
   exact serialized exchange or bundle context.
3. Relays and bridges can perform their authorized role without payload
   plaintext access. Persistent source and forwarding objects are not silently
   rewritten into a weaker representation.
4. Every profile minimizes plaintext, declares its unavoidable metadata
   exposure, and makes the effective profile observable to operators without
   exposing secrets.
5. Profile selection is bound to the authenticated transcript and a
   mission-policy minimum. No peer retries a weaker profile after failure,
   treats missing post-quantum capability as permission to fall back, or accepts
   rollback without explicit authenticated policy.

### Classical and hybrid-PQ profiles

A security profile is a complete policy unit: it binds a cryptographic suite,
mission-authorization and source-object forms, adjacency/carrier protection,
metadata exposure, and compatibility rules. A suite identifier alone is not a
security profile.

Aster will support complete classical and hybrid classical/post-quantum
profiles. Mission policy decides which exact profiles are permitted and which
minimum is required for a contact, stored object, or release. A mission that
requires hybrid-PQ fails closed before inventory when no permitted hybrid
profile overlaps. A mission that permits a classical profile selects it
explicitly; classical operation is not a downgrade fallback.

Hybrid-PQ remains the recommended option for long confidentiality or
authenticity lifetimes, harvest-now-decrypt-later exposure, and other
high-assurance policies. It is a supported capability, not a universal runtime
requirement. Classical profiles still require the applicable NIST/FIPS
algorithm policy, end-to-end source encryption and authentication, versioned
agility, and downgrade protection.

### Metadata protection

Metadata protection is best effort within a declared profile:

- Source-stable routing and authorization descriptors that survive a contact
  remain independently protected where required for payload-blind storage and
  forwarding. Authorized route members may read only the fields needed for
  their role.
- Ephemeral contact metadata may rely on an authenticated encrypted carrier,
  an Aster adjacency-protection layer when the carrier is insufficient, or an
  explicit policy-permitted exposure. A secure carrier may provide frame
  confidentiality and integrity, but not Aster semantic authority.
- Persistent local indexes and operational metadata are minimized and use
  storage, key-custody, and platform protections where practical. This is not a
  blanket claim that every local metadata field is encrypted at rest.
- Endpoint identifiers needed by the carrier, addresses, timing, direction,
  packet sizes, and RF energy remain outside the confidentiality claim unless a
  named carrier mechanism demonstrably hides them.

Packet-capture acceptance therefore proves that payload plaintext is never
exposed and that metadata exposure does not exceed the declared profile. It no
longer assumes that every transport can reveal zero protected mesh metadata.

### Iroh carrier-protected implementation

The additive `classical-p256-iroh-quic-v1` profile (`0x0002`) uses QUIC's
authenticated encryption for ephemeral frame bytes and runs an Aster mission-
authorization exchange bound to that exact QUIC TLS exporter before inventory.
It does not add a second `ASTRFR01` record-encryption layer merely to repeat the
same classical adjacency property. Its bounded reference implementation and
exposure boundary are documented in the
[classical Iroh-QUIC profile](../classical-iroh-security-profile.md).

Iroh authentication still proves only the expected carrier endpoint. When
mission policy requires post-quantum confidentiality for contact metadata and
the selected QUIC profile cannot provide it, the contact must use a suitable
Aster hybrid record layer or another admitted post-quantum carrier profile.

Connections are not required to remain open. The profile-`0x0002` mission API
owns and closes the exact exporter-bound connection on failure, explicit close,
or drop; while retained, the pinned Iroh transport uses five-second keepalives.
A release profile must still declare its idle lifetime, reconnection policy,
and measured compute, memory, byte, and energy costs. Implementations should
avoid duplicated protection and amortize post-quantum work only when the
profile-invariant end-to-end guarantees remain intact.

## Compatibility and current implementation

The initial implementation adds new identifiers without changing current wire
bytes or retained evidence:

- Suite `0x0001` remains the existing complete hybrid-PQ cryptographic suite
  used by the current security construction. Both classical and post-quantum
  components remain mandatory inside that suite.
- Suite-`0x0001` `ASTRENV2`/`ASTRENV3`, profile-`0x0001` `ASTRHS01`,
  `ASTRFR01`, current hybrid credentials, delegated controls, rekey packages,
  and content-committing batch proofs keep their exact meanings.
- The classical carrier-protected path uses complete profile/suite `0x0002`,
  provisioning `ASTRPB04`, suite-`0x0002` source objects, exact profile-`0x0002`
  `ASTRHS01` flights, carrier ALPN `aster-carrier-iroh-quic/1`, and no Aster
  application record. Semantic protocol version `1` is not used as its security
  selector.
- Existing hybrid source objects remain verifiable and forwardable under
  profiles that admit their exact suite. They are never silently converted.
- The stock selected lane still performs Iroh authentication followed by the
  four-flight hybrid mission session and protected records. Profile `0x0002` is
  an additive library/two-node mission path, not a stock runtime or CLI switch.
  No retained receipt, requirement evidence credit, or release claim moves with
  this implementation.

Decisions 0001, 0003, and 0012 remain authoritative for suite `0x0001` and its
current mechanisms. This decision supersedes only their interpretation as a
universal product requirement across every future security profile.

## Follow-on gates

The profile-`0x0002` increment provides exact identifiers, authenticated
singleton policy and channel binding, stable principals, local durable
profile/generation binding, same-implementation failure tests, and a declared
metadata budget. Before it or another profile is released, the remaining gates
include:

- retained packet-capture, hostile-peer, mixed-implementation, restart, and
  stored-object compatibility evidence on declared targets;
- snapshot/backup-resistant rollback policy beyond the local database
  high-water seam;
- profile-specific compute, memory, bandwidth, connection-idle, and energy
  measurements on declared targets; and
- the cryptographic-module, independent-review, interoperability, dependency,
  platform, and release gates applicable to the profile's claims.

## Consequences

- Missions can pay for hybrid-PQ protection when their threat model warrants it
  without imposing that cost on every deployment.
- A secure carrier can protect ephemeral metadata without redundant classical
  record encryption, while source payloads and Aster authorization remain
  independently protected.
- Metadata confidentiality becomes an auditable exposure budget rather than an
  absolute claim the carrier cannot satisfy.
- Broader runtime selection/negotiation, snapshot-resistant policy rollback,
  and release compatibility remain explicit implementation work.
