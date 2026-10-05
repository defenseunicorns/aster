# Classical P-256 / Iroh-QUIC security profile


- Profile label: `classical-p256-iroh-quic-v1`
- Security-profile ID: `0x0002`
- Cryptographic-suite ID: `0x0002`
- Maximum semantic version: `1`
- Status: implemented reference/evaluation profile; not a production release
- Interoperability status: complete normative byte grammar and independent
  vectors remain open; this document bounds the reference implementation but
  is not sufficient by itself to build an independent conformant peer
- Policy authority: [Decision 0033](decisions/0033-policy-selected-security-profiles.md)

This document records the bounded reference implementation of Aster's first
carrier-protected classical profile. It is an additive path beside the
existing `hybrid-pq-aster-record-v1` profile (`0x0001`). It does not change any
profile `0x0001` bytes or make the stock selected-node runtime switch profiles.

## Bounded profile boundary

Profile `0x0002` combines these exact choices:

| Concern | Profile `0x0002` behavior |
|---|---|
| Mission and policy authority | Provisioned P-256 authority credential with a stable mission principal and nonzero policy generation; an opt-in local redb seam enforces its same-store high-water |
| Contact protection | Authenticated Iroh QUIC under ALPN `aster-carrier-iroh-quic/1` |
| Aster contact authorization | Four-flight P-256 mission handshake bound to the exact QUIC TLS exporter |
| Ordinary contact frames | Iroh QUIC AEAD only; no `ASTRFR01` record layer |
| Source object | Separately encrypted and P-256-authenticated semantic-v1 Event envelope |
| Protected forwarding metadata | Independently encrypted route wrapper; route-only members cannot open Event content |
| Controls | P-256-authenticated, encrypted revocation and pre-provisioned scope-epoch controls |
| Unsupported forms | State, Record, Blob, compact batch, bridge, forwarding wrapper, recipient rekey, and semantic versions 2–5 fail closed |

The profile uses P-256 ECDSA, P-256 ECDH, HKDF-SHA-256, SHA-256, and
AES-256-GCM. Its implementation module contains no ML-DSA or ML-KEM operation.
The combined workspace still builds the legacy hybrid implementation and its PQ
dependencies; this increment establishes a PQ-free runtime path, not yet a
PQ-free distribution artifact or code-size claim.

## Provisioned singleton policy

Selection happens through provisioned credentials, not peer preference or
numeric ordering. The exact receipt is:

```text
protocol_version       u16 = 1
suite_id                u16 = 2
semantic_version       u16 = 1
selected_profile_id    u16 = 2
required_profile_id    u16 = 2
policy_generation      u64, nonzero
mission_principal      b32
policy_authority_id    b32
policy_digest           b32
```

The P-256 policy authority signs credentials containing this receipt, the
stable node principal, serial, roles, P-256 verifying key, route-grant
commitments, and a domain-separated commitment to the node's exact local
control, route, and content keys with their canonical grant names and epochs.
This makes grant-row reordering and local-key substitution detectable even if
an attacker recomputes the bundle's unkeyed structural checksum.
`policy_authority_id` binds the mission principal to the exact authority
verifying key. `policy_digest` binds protocol, suite, semantic version,
selected and required profile, generation, mission principal, and policy
authority.

There is no list negotiation in profile `0x0002`: selected and required IDs
must both equal `0x0002`. A different ALPN, profile, suite, policy generation,
mission principal, authority, channel binding, or peer identity is rejected
before inventory. The profile-`0x0002` carrier/session APIs perform no automatic
retry to profile `0x0001` after that failure. Runtime-wide policy across
separate caller-initiated attempts remains an open integration boundary.
Numeric profile IDs are registry values and have no strength ordering.

The local secret bundle uses new magic `ASTRPB04` and version `4`. It contains
identity and grant secrets and is not an at-rest protection format. Operational
custody must pass its canonical bytes through the existing provisioning
protector/secret-store boundary. Debug output redacts secret material.

## QUIC channel binding and mission authorization

An Iroh endpoint advertises exactly one carrier ALPN. The legacy carrier keeps
`aster-carrier/1`; profile `0x0002` uses
`aster-carrier-iroh-quic/1`. A mixed pair therefore fails the QUIC handshake
and the tested endpoint-connect operation performs no automatic retry.

Both peers construct this role-ordered, 210-byte exporter context:

```text
magic                       b8 = "ASTRCB01"
profile_id                  u16 = 2
policy_generation           u64
policy_authority_id         b32
mission_principal           b32
initiator_carrier_id        b32
initiator_mission_id        b32
responder_carrier_id        b32
responder_mission_id        b32
```

The carrier additionally binds its selected ALPN and derives 32 bytes with the
TLS exporter label `EXPORTER-Aster-Iroh-Channel-Binding-v1`. Aster digests that
value into every public policy comparison, signature transcript, key schedule,
confirmation, and completed session identifier.

The `ASTRHS01` framing version remains `1`, but its exact profile field is
`0x0002`; this does not reinterpret a profile-`0x0001` flight. The four flights
use fresh P-256 ephemeral ECDH, fresh nonces, authority-signed P-256 node
credentials, P-256 transcript signatures, and explicit key confirmation.
Credentials travel inside Aster AEAD after the ephemeral secret exists. No
inventory or ordinary application frame is available until flight four and the
configured carrier-to-mission peer binding both succeed.

The completed session owns the exact QUIC connection whose exporter was
authenticated. Application exchanges use that connection's bounded raw byte
operations, so they receive QUIC protection once rather than QUIC plus
`ASTRFR01`. All handshake failures close the connection. Dropping or explicitly
closing the session also closes it and erases session-derived state.

Aster configures five-second connection and path keepalive intervals for the
`IrohQuicV1` carrier profile, so an idle connection can still generate traffic.
Close the session when the contact ends. Battery impact has not been measured
on target devices.

## Source Event and control protection

Profile `0x0002` reuses the registered `ASTRENV2` family only with an exact
suite field of `0x0002`. Suite `0x0001` meanings remain unchanged. The public
44-byte header is:

```text
magic                    b8 = "ASTRENV2"
envelope_format          u16 = 2
protocol_version         u16 = 1
suite_id                 u16 = 2
kind                     u8  = Event | Revocation | ScopeEpoch
reserved                 u8  = 0
random_route_selector    b16
route_ciphertext_len     u32
content_ciphertext_len   u64
```

An Event has two independent AES-256-GCM layers:

1. The content layer encrypts the complete canonical Event header and payload
   under the topic/content epoch grant.
2. The randomized route layer encrypts the authority credential, stable item
   ID, canonical Event header, content-group commitment, content nonce,
   ciphertext length and hash, and publisher P-256 signature under the scope
   route epoch grant.

The publisher signature commits to protected routing metadata and the content
ciphertext hash. A route-only member can authenticate the Event's required
forwarding fields and retain its unchanged sealed bytes but cannot create a
content-verified capability. No selected profile-`0x0002` redb/runtime Event
persistence path is claimed by this increment. A content member separately
authenticates the content layer before semantic consumption. Tamper, wrong
source, wrong mission, wrong grant, class confusion, and unsupported
representations fail closed.

Revocation and scope-epoch controls use protected plaintext magic `ASTRCA03`,
format `3`, the exact profile receipt, delegated P-256 credential and signature,
and the existing contiguous sequence/previous-control rules. Profile `0x0002`
does not distribute new recipient keys; scope-epoch controls can activate only
epochs already provisioned to that node.

## Declared metadata exposure

| Observer or custody role | Permitted observation |
|---|---|
| Passive carrier observer or relay | Carrier endpoint/address and relay use where applicable, timing, direction, packet sizes, connection behavior, and RF energy; not QUIC plaintext |
| Iroh-authenticated peer before Aster authorization | QUIC-decrypted handshake framing, sizes, and public profile/contact fields; not encrypted credentials, source payload, or inventory |
| Unprovisioned source-object holder | The 44-byte public envelope header above, total lengths, and equality properties visible from retained ciphertext; not route metadata or payload |
| Authorized route-only mission member | Authenticated Event routing/header fields and source credential needed for custody; not Event payload |
| Authorized content member | The granted Event metadata and payload after fresh verification |
| Local redb/operator boundary | The additive redb seam stores the policy binding. A future integrated Event path may keep verified headers, indexes, controls, accounting, and operational metadata in plaintext inside the database; filesystem, storage, backup, and platform controls remain required. |

This is best-effort metadata protection, not an anonymity claim. Unchanged
sealed source-object bytes keep payload and protected route metadata encrypted
at rest and through store-and-forward custody. The increment does not integrate
those objects with the selected redb/runtime path. Local indexes are minimized
but are not silently claimed to be encrypted by this profile.

## Durable binding and rollback boundary

A policy-aware redb open can bind a store to the exact mission authority,
opaque profile ID, and policy generation. Ordinary reopen accepts only the same
profile/generation, rejects a lower generation, and refuses to advance the
generation implicitly. A separate explicit bind call can advance to a higher
caller-authenticated generation but cannot change profile ID.

The store record is self-checking and prevents accidental detachment or mutation
inside the live database. It is not itself an authority signature, secure
counter, TPM witness, or defense against restoring an entire older filesystem
snapshot. The caller must supply a generation already authenticated by the
profile credential; physical/snapshot anti-rollback remains a release gate.
Legacy store-open APIs validate a binding if one is present but do not require
or advance it. Enforcing the generation high-water therefore requires the
policy-aware open APIs on every profile-`0x0002` operational path.

## Compatibility and implementation boundary

- Existing `ASTRPB03`, suite-`0x0001` `ASTRENV2`/`ASTRENV3`, hybrid
  `ASTRHS01`, and `ASTRFR01` bytes remain byte-for-byte unchanged.
- A profile-`0x0002` parser never accepts a profile-`0x0001` handshake or
  provisioning representation, and the Iroh ALPNs do not overlap.
- Stored objects are not converted between suites. Each exact sealer verifies
  only the representation and authority it was provisioned to accept.
- The public profile facade dispatches provisioning only by the exact canonical
  `ASTRPB03` or `ASTRPB04` magic; unknown values fail rather than probing both.
- `aster-node::mission` exposes a real two-node Iroh contact path for profile
  `0x0002`. The stock `run_node`/CLI remains on the selected hybrid
  profile-`0x0001` runtime until a separately reviewed runtime-selection and
  operational-provisioning increment is completed.

The tests cover canonical bundle round trips, exact policy and channel binding,
real-Iroh mutual authorization and raw QUIC exchange, role ordering, wrong
generation and peer context, mixed carrier profiles, source Event route/content
separation, controls, unsupported forms, legacy bytes, durable store mismatch
and generation high-water behavior, and exact four-flight byte accounting:
`[259, 712, 499, 78]` (1,548 bytes) for profile `0x0002` versus
`[1,317, 11,337, 10,142, 78]` (22,874 bytes) for the legacy reference handshake.
The mixed-profile tests establish no automatic retry by the tested API, not
runtime-wide policy across separate caller attempts. These are
same-implementation reference evidence, not retained packet-capture, target
energy, independent interoperation, FIPS-module, or production authorization
evidence.
