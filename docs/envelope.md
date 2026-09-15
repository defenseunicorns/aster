# Aster Fixed Binary Security Objects

- Specification version: 0.1.0-draft.1
- Stable wire/cryptographic profile: `1`, suite `0x0001`
- Negotiated semantic versions: default/highest `6`, compatibility `5`, `4`, `3`, `2`, and `1`
- Status: normative for the implemented reference profile
- Date: 2026-08-25

This document is normative only for profile/suite `0x0001`. The additive
profile/suite `0x0002` uses new exact provisioning, credential, Event/control,
and channel-bound handshake forms whose bounded reference implementation is
documented in
[classical-iroh-security-profile.md](classical-iroh-security-profile.md). A
decoder MUST use the exact profile/suite context and MUST NOT reinterpret a
failure under one specification as the other. A complete normative grammar for
profile `0x0002` remains an interoperability gate.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are normative. This document defines the base fixed binary security objects
emitted or accepted by the reference profile. The semantic-version-2/3/v4/v5/v6 batch
additions are defined normatively in [protocol.md](protocol.md) §6.1; together,
these sections are the interoperability authority for the fixed bytes. Rust
types and local database rows are not wire formats.

Replication messages are the deterministic-CBOR objects in `wire.cddl` and are
not redefined here. A decoder MUST know from its containing protocol state
whether the next object is deterministic CBOR or one of the fixed binary objects
below. It MUST NOT probe one encoding and then reinterpret a failure as another.

## Find a section

| Need | Sections |
|---|---|
| Implement the common encoding rules | [Byte notation](#1-byte-notation-and-canonical-rules) and [object registry](#2-complete-fixed-object-registry) |
| Provision a node | [Credentials and local provisioning](#3-credentials-and-local-provisioning) |
| Seal or verify application data | [Semantic item core](#4-semantic-item-core-and-identifiers) and [source envelope](#5-source-envelope) |
| Apply authority controls or custody | [Authority controls](#6-authority-control-objects) and [session custody claim](#71-semantic-v3-format-session-custody-claim) |
| Implement an authenticated session | [Handshake flights](#8-handshake-flights-and-transcript) and [transport records](#9-protected-transport-records) |
| Transfer Blob data | [Blob manifest and chunk cryptography](#10-blob-manifest-and-chunk-cryptography) |
| Enforce fail-closed parsing | [Required rejection behavior](#11-required-rejection-behavior-and-format-boundaries) |

## 1. Byte notation and canonical rules

All integers are unsigned and big-endian. Concatenation is written `||`.
Literal quoted strings are their ASCII bytes without a terminator. Arrays such
as `mission[32]` have exactly the displayed size.

| Notation | Bytes | Constraint |
|---|---|---|
| `u8`, `u16`, `u32`, `u64` | 1, 2, 4, 8 | unsigned big-endian |
| `b16(x)` | `u16(len(x)) || x` | length fits `u16` and the field bound |
| `b32(x)` | `u32(len(x)) || x` | length fits `u32` and the field bound |
| `b64(x)` | `u64(len(x)) || x` | length fits `u64` and the field bound |
| `bool(x)` | one byte | `0` false, `1` true; other values invalid |
| `opt64(x)` | `0`, or `1 || u64(x)` | other presence bytes invalid |

A decoder MUST reject truncation, integer overflow, a length greater than its
field bound before allocating, invalid UTF-8 where text is required, nonzero
reserved bytes, and trailing bytes. A fixed-width field carried in a length
prefix MUST have exactly the required length, not merely a length below its
maximum.

The common domain-separated hash is:

```text
HD(domain, input) =
  SHA-256(u64(len(domain)) || domain || u64(len(input)) || input)
```

`domain` is the exact case-sensitive ASCII byte string shown. `SHA-256(x)`
without `HD` means ordinary SHA-256 over exactly `x` and adds no prefix.

The provisioning KDF used by credentials, source envelopes, controls, and the
legacy `ASTRFWD1` forwarding-custody wrapper is:

```text
PKDF(root32, label, context, N) =
  HKDF-SHA-256(
    salt = "aster/reference-provisioning/v2",
    IKM  = root32,
    info = u16(len(label)) || label ||
           u32(len(context)) || context,
    L    = N)
```

All length conversions MUST succeed. No NUL terminator or implicit separator is
present unless shown.

### 1.1 Names

A topic is UTF-8 of 1 through 128 bytes and every byte is ASCII alphanumeric or
one of `.`, `_`, `-`. A scope has the same byte bound and alphabet plus `/`.
A scope MUST NOT start or end with `/` and each slash-delimited segment MUST be
nonempty and MUST NOT equal `.` or `..`.

### 1.2 Suite `0x0001` encodings

Suite `0x0001` is the AND-composed suite P-256 ECDH + ML-KEM-768, ECDSA P-256
with SHA-256 + ML-DSA-65, HKDF-SHA-256, AES-256-GCM, and SHA-256. Both signature
components are mandatory.

| Value | Canonical encoding |
|---|---|
| P-256 public key | 33-byte compressed SEC1 point |
| ECDSA P-256 signature | 64-byte IEEE P1363 `r || s`, each integer 32-byte big-endian |
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| ML-KEM-768 encapsulation key | 1,184 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| P-256 ECDH shared secret | 32-byte affine x-coordinate, big-endian |
| ML-KEM-768 shared secret | 32 bytes |
| AES-256-GCM nonce | 12 bytes |
| AES-256-GCM result | ciphertext followed by the 16-byte tag |

The encoded hybrid verifying key is:

```text
b16(p256_compressed[33]) || b32(ml_dsa_65_public[1952])
```

The encoded hybrid signature is:

```text
b16(ecdsa_p256_p1363[64]) || b32(ml_dsa_65_signature[3309])
```

Verification succeeds only when both signatures decode and verify over the
same specified message. A missing, empty, malformed, or invalid component fails
the whole signature. ECDSA uses SHA-256 over that message and emits P1363 bytes;
ML-DSA-65 uses its pure signing mode with an empty context over the same message.
Thus, where a later section names an `HD(...)` value as the signature message,
that 32-byte value itself is the input to both signature algorithms.

## 2. Complete fixed-object registry

| Object | Discriminator | Status and outer bound |
|---|---|---|
| Provisioning bundle | `"ASTRPB03"` | unprotected local provisioning-inner format; not a network object |
| Rekey recipient registry | `"ASTRRKR1"` | signed administrative artifact; at most 16 MiB; not a mesh replication object |
| Authority credential body | none; embedded with `b32` | network security object; embedded bound 16 KiB |
| Singleton source envelope | `"ASTRENV2"` | network/stable-store format-2 object; semantic versions 1 through 6 |
| Compact batch source envelope | `"ASTRENV3"`, kind `1` | semantic-version-2/3/v4/v5/v6 network/stable-store format-3 object; exact bytes in [protocol.md](protocol.md) §6.1 |
| Source-batch proof | `"ASTRENV3"`, kind `3` | semantic-version-2/3/v4/v5/v6 network/stable-store format-3 object; exact bytes in [protocol.md](protocol.md) §6.1 |
| Revocation control | source-envelope kind `2`, protected `"ASTRCA02"` | delegated-control format 2 inside `ASTRENV2` |
| Scope-epoch control | source-envelope kind `3`, protected `"ASTRCA02"` | delegated-control format 2 inside `ASTRENV2` |
| Bridge authorization | `"ASTRBA01"`, protected ObjectKind `4` | semantic-version-2/3/v4/v5/v6 authorization format 2; at most 65,536 bytes total |
| Bridge route wrapper | `"ASTRBW01"`, protected ObjectKind `5` | semantic-version-2/3/v4/v5/v6 wrapper format 1; at most 524,322 bytes total |
| Bridge edge enrollment | `"ASTRBE01"` | provider-authenticated administrative capability; at most 32 KiB; not a mesh replication object |
| Legacy per-hop forwarding wrapper | `"ASTRFWD1"` | provider-owned network object; protected body at most 64 KiB including tag |
| Semantic-v3-format custody claim, used by v3/v4/v5/v6 | `"ASTRCU03"` inside `"ASTRFR01"` | exact 150-byte plaintext; exact current outer record 202 bytes, hard bound 256 bytes |
| Handshake flight | `"ASTRHS01"` | network, at most 64 KiB per flight |
| Protected transport frame | `"ASTRFR01"` | network; plaintext at most 16 MiB |
| Blob manifest | `"ASTRBM01"` | canonical source-authenticated object, at most 1 MiB |
| Blob ciphertext chunk carrier | `"ASTRBT01"` | network/stable-store object; exact bounds in §10 |

Security-object kind registries are closed in this profile:

| Registry | Value |
|---|---|
| protocol version | `1` |
| suite | `0x0001` |
| source-envelope kind | `1` Data, `2` Revocation, `3` ScopeEpoch |
| handshake flight kind | `1` ClientHello, `2` ServerHello+ServerAuth, `3` ClientAuth, `4` ServerFinished |
| data class | `0` State, `1` Event, `2` Record, `3` Blob |
| priority | `0` Routine, `1` Priority, `2` Immediate, `3` Flash |
| credential role bit | `0x00000001` Relay, `0x00000002` Reader, `0x00000004` ControlAuthority |

Unknown values and unknown role bits MUST be rejected. There are no optional
extension bytes in these formats; adding bytes to an otherwise valid object is
a trailing-byte error.

## 3. Credentials and local provisioning

### 3.1 Authority and node identifiers

Given a mission and authority hybrid verifying key:

```text
AuthorityID = HD(
  "aster/authority/v1",
  mission[32] || p256_public[33] || ml_dsa_public[1952])
```

The raw public keys are concatenated here without their usual length prefixes.

An authority credential body is:

```text
protocol_version                 u16 = 1
suite_id                         u16 = 0x0001
mission                          32 bytes
serial                           u64, nonzero
roles                            u32, only registered bits
identity_hybrid_verifying_key    encoded hybrid verifying key
identity_p256_ecdh_public        b16(exactly 33 bytes)
identity_ml_kem_public           b32(exactly 1184 bytes)
route_commitment_count           u16, 1..256
route_commitments                count * 32 bytes
```

Route commitments MUST be in strictly increasing unsigned lexicographic byte
order, with no duplicate. The authority signature is the encoded hybrid
signature over the 32-byte message:

```text
HD("aster/credential-signature/v1", credential_body)
```

`NodeID` is:

```text
NodeID = HD("aster/node-credential/v1", credential_body)
```

The credential signature is not part of `NodeID`. A consumer validates the
mission, registered role bits, key encodings, ordered commitments, authority
identity, and both components of the authority signature before using the
credential.

For a routing grant `(mission, scope, epoch, route_seed)`:

```text
route_commitment_material =
  mission[32] || b16(scope) || epoch u64 || route_seed[32]

RouteCommitment =
  HD("aster/route-grant-commitment/v1", route_commitment_material)
```

### 3.2 Reference provisioning bundle — unprotected inner format, local only

`ASTRPB03` is a local persistence/ingestion format containing secret material.
It MUST NOT be sent on the mesh, logged, included in captures, or treated as a
cross-implementation provisioning protocol. Another implementation MAY use a
platform keystore and a different local representation. The exact reference
format is documented to make recovery and diagnostic inspection unambiguous:

```text
magic                            "ASTRPB03"                    8
bundle_version                   u16 = 3                        2
mission                          32 bytes                       32
authority_id                     32 bytes                       32
authority_hybrid_verifying_key   encoded hybrid verifying key  variable
node_identity_seed               32 secret bytes                32
serial                           u64, nonzero                    8
roles                            u32                             4
authority_credential_signature   encoded hybrid signature       variable
has_control_route_key            u8 = 0 or 1                     1
control_route_key                32 bytes iff flag = 1          0 or 32
route_grant_count                u16, 0..256                     2
route_grants                     repeated as below               variable
content_grant_count              u16, 0..256                     2
content_grants                   repeated as below               variable
checksum                         32 bytes                        32
```

Each route grant is `b16(scope) || epoch u64 || route_seed[32]`. Each content
grant is `b16(scope) || b16(topic) || epoch u64 || content_seed[32]`. Duplicate
`(scope, epoch)` route grants and duplicate `(scope, topic, epoch)` content
grants are invalid. The reference writer orders them lexicographically, but the
local reader does not assign interoperability meaning to record order. The
Relay role bit MUST be present exactly when the route-grant count is nonzero,
and the Reader role bit MUST be present exactly when the content-grant count is
nonzero. The ControlAuthority role is independent of both grant counts.

Version 3 contains no provisioning-root or authority-root signing seed. A
ControlAuthority bundle uses its unique `node_identity_seed` to sign controls;
the corresponding authority-root-signed credential carries the
ControlAuthority role. The checksum is:

```text
HD("aster/provisioning-check/v3", every preceding bundle byte)
```

The checksum detects accidental damage; it does not make this secret bundle
safe for an untrusted store. The exact maximum v3 bundle is 125,877 bytes under
the fixed key/signature sizes, 256 route grants, 256 content grants, and
128-byte scope/topic limits. The reference rejects larger input before checksum
work.

An operational deployment MUST protect these bytes at rest with an admitted
local provider and expose plaintext only for bounded ingestion. The provider-
owned outer artifact is local and implementation-specific: it is not sent on
the mesh and cannot alter `ASTRPB03`, NodeID, credentials, grants, or any
interoperable protocol byte. The reference's separate protection and
unprotection boundaries supply least-privilege, fail-closed, zeroizing
ingestion/export contracts, but no operational provider is shipped by the
boundary itself. Empty, oversized, and raw `ASTRPB03` outer inputs are rejected
before provider invocation. Checksum validity is never evidence of protected
custody.

The reference provisioner derives values with `PKDF` as follows:

| Result | Root | Label | Context |
|---|---|---|---|
| mission | provisioning root | not KDF: `HD("aster/mission/v1", root)` | — |
| authority signing seed (provisioner only; never placed in a bundle) | provisioning root | `authority-signing-seed` | empty |
| mission control-route key | provisioning root | `mission-control-route` | mission |
| scope route seed | provisioning root | `scope-routing-epoch` | `b16(scope) || 0 || epoch u64` |
| topic content seed | provisioning root | `topic-content-epoch` | `b16(scope) || 1 || b16(topic) || epoch u64` |

Identity signing, static key-agreement, and ML-KEM-768 keys are deterministically
expanded from the node identity seed. For the P-256 signing key, for counters
`0..255` in order, compute
`PKDF(identity_seed, "ecdsa-p256-signing-scalar", counter u16, 32)` and use the
first result that decodes as a valid nonzero P-256 secret scalar; failure of all
256 candidates fails provisioning. Independently, for the static P-256 ECDH
key, try `PKDF(identity_seed, "p256-static-ecdh-scalar", counter u16, 32)` for
the same counter range and select the first valid nonzero scalar. Its credential
field is the 33-byte compressed SEC1 public point. The ML-DSA-65 seed is
`PKDF(identity_seed, "ml-dsa-65-signing-seed", empty, 32)`. The ML-KEM-768 seed
is `PKDF(identity_seed, "ml-kem-768-seed", empty, 64)`. The offline
provisioner's authority signing keys use the same P-256 and ML-DSA expansion
from the derived authority signing seed. Those local key-generation steps do
not add network fields; interoperable peers depend only on the public credential
and proof bytes above. Capturing one fielded ControlAuthority bundle therefore
compromises that delegated identity, not the authority-root signing seed or
every other delegated identity.

## 4. Semantic item core and identifiers

The exact `ItemCore` is:

```text
class                            u8: 0..3
priority                         u8: 0..3
topic                            b16(UTF-8), 1..128 bytes
scope                            b16(UTF-8), 1..128 bytes
publisher_node_id                32 bytes
publisher_counter                u64, nonzero
context_count                    u32, 0..4096
context_entries                  count * (publisher[32] || counter u64)
event_sequence                   opt64
logical_key                      b32(bytes), 0..65536 bytes
blob_route_tag                   u8 = 0 or 1
blob_id                          32 bytes iff tag = 1
blob_chunk_count                 u64 iff tag = 1
blob_route_merkle_root           32 bytes iff tag = 1
ttl_ms                           opt64
declared_content_len             u64
tombstone                        bool
content_epoch                    u64
payload                          b64(bytes)
```

Context entries MUST be in strictly increasing lexicographic `publisher` order,
each counter MUST be nonzero, and the context entry for the publishing identity,
if present, MUST be less than `publisher_counter`. `event_sequence` MUST be
present and nonzero exactly for Event; it MUST be absent for every other class.

`ttl_ms` is a duration. An absent value is durable. For non-tombstone data, zero
is syntactically valid but already expired and therefore is not eligible for
delivery or forwarding. A tombstone is a durable retained marker regardless of
its optional TTL value; TTL does not make that marker ineligible.
`declared_content_len` MUST equal the payload length. A tombstone MUST have zero
payload length, and Blob MUST NOT be a tombstone.

`blob_route_tag` MUST be one exactly for Blob and zero for every other class.
When present, `blob_chunk_count` MUST be nonzero and `logical_key` MUST be
exactly the 32-byte `blob_id`. The root authenticates the route-verifiable Blob
chunk commitments defined in §10. The Blob payload is the canonical manifest;
the manifest's BlobID and chunk count MUST agree with this authenticated header.

The fixed-binary parser permits a logical key through 65,536 bytes. The current
durable reference store imposes the narrower semantic admission limit of 4,096
bytes and requires a nonempty key for State and Record. A sender targeting this
profile MUST satisfy the 4,096-byte limit.

The complete core, including its `b64` payload length, MUST be at most 512 MiB.

```text
ItemID = HD("aster/item/v1", exact_ItemCore_bytes)
```

The input-length word in `HD` is part of the identifier. ItemID is independent
of route selector, source-envelope wrapping, and forwarding custody.

## 5. Source envelope

### 5.1 Public carrier header

Every source envelope is exactly:

```text
public_header[44] || route_ciphertext[route_len] ||
content_ciphertext[content_len]
```

The 44-byte public header is:

```text
magic                    "ASTRENV2"            8
envelope_format_version  u16 = 2                2
protocol_version         u16 = 1                2
suite_id                 u16 = 0x0001           2
kind                     u8: 1, 2, or 3         1
reserved                 u8 = 0                 1
route_selector           16 bytes              16
route_ciphertext_len     u32                    4
content_ciphertext_len   u64                    8
```

`route_ciphertext_len` includes the 16-byte AES-GCM tag and MUST be 16 through
262,144 bytes. For Data, `content_ciphertext_len` includes its tag and MUST be at
least 16; for either control kind it MUST be zero. The two lengths MUST consume
the object exactly. The 512 MiB ItemCore bound consequently bounds generated
Data content ciphertext, though the public length field itself is `u64`.

`route_selector` is a fresh unpredictable 16-byte value. Its first 12 bytes are
the route AEAD nonce:

```text
RouteKey = PKDF(route_epoch_seed,
                "aster/route-key/v1", route_selector, 32)
RouteNonce = route_selector[0..12]
RouteCiphertext = AES-256-GCM(RouteKey, RouteNonce,
                              route_plaintext, public_header[44])
```

The complete public header, including both ciphertext lengths, is associated
data. The outer immutable identifier is ordinary, non-domain-separated SHA-256:

```text
EnvelopeID = SHA-256(exact_complete_source_envelope_bytes)
```

### 5.2 Content encryption

For a Data item:

```text
ContentKey = PKDF(content_epoch_seed,
                  "aster/content-key/v1", ItemID, 32)
nonce_material = PKDF(content_epoch_seed,
                      "aster/content-nonce/v1", ItemID, 32)
ContentNonce = nonce_material[0..12]
ContentAAD = protocol_version u16 || suite_id u16 ||
             content_epoch u64 || ItemID[32]
ContentCiphertext = AES-256-GCM(ContentKey, ContentNonce,
                                exact_ItemCore_bytes, ContentAAD)
```

### 5.3 Data route descriptor

The decrypted route plaintext for kind `1` is:

```text
kind                             u8 = 1
publisher_credential_body        b32(bytes), at most 16384 bytes
publisher_credential_signature   encoded hybrid signature
item_id                          32 bytes
semantic_header                  ItemCore fields class through content_epoch
content_group_id                 32 bytes
content_nonce                    12 bytes
singleton_batch_id               32 bytes
content_ciphertext_len           u64
publisher_item_signature         encoded hybrid signature
```

`semantic_header` is the exact ItemCore encoding from `class` through
`content_epoch`; it omits only `b64(payload)`. The protected route descriptor is
not a second source of truth. After decryption, the consumer MUST require:

- credential mission and authority match the local mission trust anchor;
- both credential signatures verify and the credential has the Relay role;
- publisher NodeID equals the semantic header's publisher;
- content group, content nonce, and ciphertext length recompute exactly;
- the singleton identifier and both publisher signatures verify;
- decrypted ItemCore hashes to `item_id`; and
- every repeated semantic-header field equals its ItemCore value; and
- for Blob, the authenticated manifest's BlobID, chunk count, content group,
  content epoch, and computed route root agree with the semantic header.

The source-envelope content-group identifier is:

```text
group_input = scope_bytes || 0x00 || topic_bytes
ContentGroupID = HD("aster/content-group/v1", group_input)
```

### 5.4 Format-2 singleton source authentication

Envelope format 2 implements a one-item authentication manifest:

```text
SingletonManifest(item_id, batch_id, header) =
  protocol_version u16 || suite_id u16 || item_id[32] || batch_id[32] ||
  b32(exact_semantic_header_bytes)

SingletonBatchID = HD(
  "aster/singleton-batch-id/v1",
  SingletonManifest(item_id, all_zero_32, header))

publisher signature message = HD(
  "aster/singleton-batch/v1",
  SingletonManifest(item_id, SingletonBatchID, header))
```

The publisher produces and the receiver requires both signature components.
The semantic-header bytes are the complete canonical fields from `class`
through `content_epoch`, including the Blob route tag and conditional fields;
they omit only `b64(payload)`. Binding the entire header prevents a manifest or
Blob route commitment from being substituted without invalidating the source
signature.

No multi-item batch certificate, proof, or credential cache reference is encoded
inside an `ASTRENV2` format-2 object. Semantic-version-2, semantic-version-3,
semantic-version-4, semantic-version-5, and semantic-version-6 sessions also support the separate `ASTRENV3` format-3 source-batch proof and
compact item representations defined in [protocol.md](protocol.md) §6.1. Those bytes MUST NOT
be inserted into or reinterpreted as an `ASTRENV2` object; format 2 remains the
singleton fallback for semantic-version-2/3/v4/v5/v6 peers and the only source-envelope
format accepted by semantic version 1.

## 6. Authority control objects

Control objects use the `ASTRENV2` public header, route encryption in §5.1, the
mission control-route key in place of a scope route seed, and no content
ciphertext. Delegated-control format 2 is the only accepted control plaintext;
the legacy root-signed shape is rejected. Its protected plaintext starts with:

```text
kind                            u8 = outer kind
control_magic                   "ASTRCA02"                    8
control_authentication_format   u16 = 2                        2
mission                         32 bytes
authority_id                    32 bytes
control_authority_credential    b32(credential_body), 1..16384 bytes
authority_credential_signature  encoded hybrid signature
control_sequence                u64, nonzero
has_previous                    u8 = 0 or 1
previous_envelope_id            32 bytes iff has_previous = 1
```

The embedded credential MUST validate under the configured hybrid root key whose
derived identifier equals `authority_id`, MUST name the same mission, MUST use
only registered role bits, and MUST contain the ControlAuthority role. Its
`NodeID` is the delegated control signer. The credential and its authority
signature are part of the signed control bytes, so credential or signer
substitution invalidates the control.

Sequence one MUST have no previous identifier. Every other sequence MUST have a
previous identifier. The current format thereby rejects sequence zero and also
rejects `(sequence == 1) != (has_previous == 0)`; chain/fork policy additionally
validates the referenced accepted control.

The kind-specific unsigned suffix is:

```text
Revocation (kind 2):
  subject_node_id       32 bytes
  generation            u64, nonzero

ScopeEpoch (kind 3):
  scope                 b16(UTF-8), 1..128 bytes
  epoch                 u64
  keying_format         u16 = 0 or 1
```

Revocation and ScopeEpoch format `0` end their unsigned suffix after the fields
shown. Format `0` activates an independently pre-provisioned epoch; it does not
exclude a captured holder of that future key. ScopeEpoch format `1` requires a
nonzero epoch and continues its unsigned suffix as follows:

```text
package_set_hash                  32 bytes
recipient_package_count           u16, 1..128
recipient_packages                count packages, defined below
```

After the complete kind-specific unsigned suffix, the delegated identity's
encoded hybrid signature ends the protected plaintext. Both components sign:

```text
HD("aster/delegated-control/v2", every preceding protected plaintext byte)
```

The signature is not included in its own message. Verification therefore
requires both the authority-root hybrid signature on the delegated credential
and the delegated identity's hybrid signature on the complete control.

Packages MUST be in strictly increasing `recipient_node_id` order. A package is:

```text
recipient_node_id                 32 bytes
credential_hash                   32 bytes
grant_commitment                  32 bytes
p256_ephemeral_public             b16(exactly 33 bytes)
ml_kem_768_ciphertext             b32(exactly 1088 bytes)
sealed_grants_nonce               12 bytes
sealed_grants                     b32(ciphertext || tag), 17..65536 bytes
```

All of these fields remain inside the control's route ciphertext; they are not
part of the 44-byte public envelope header. Every recipient credential MUST have
the Relay role, and a recipient with one or more topic grants MUST also have the
Reader role.

The P-256 point MUST be a valid compressed SEC1 point. `credential_hash` binds
the exact authority credential used for this recipient:

```text
FlightCredential = b32(credential_body) || encoded_hybrid_authority_signature
credential_hash = HD("aster/rekey-credential/v1", FlightCredential)
```

The credential body remains bounded at 16 KiB. Let each visible descriptor be
`recipient_node_id[32] || credential_hash[32] || grant_commitment[32]`. Then:

```text
package_set_input =
  protocol_version u16 || suite_id u16 || keying_format u16 ||
  recipient_package_count u16 ||
  descriptor[0] || ... || descriptor[count-1]

package_set_hash =
  HD("aster/rekey-package-set/v1", package_set_input)
```

The authority generates one fresh unpredictable 32-byte route key for the
`(scope, epoch)` and one fresh unpredictable 32-byte content key for every
distinct granted topic. It also generates a fresh random 32-byte `grant_salt`
independently for each recipient. The reference obtains all of these values from
the operating-system CSPRNG and zeroizes its transient copies on drop. Topic
lists are zero through 128 entries and strictly increasing. The sum of topic
entries across all recipients is at most 256; the distinct-topic union is
therefore also at most 256. The externally visible commitment is:

```text
grant_input =
  protocol_version u16 || suite_id u16 || b16(scope) || epoch u64 ||
  recipient_node_id[32] || credential_hash[32] || grant_salt[32] ||
  topic_count u16 || b16(topic[0]) || ... || b16(topic[n-1])

grant_commitment = HD("aster/rekey-grant/v1", grant_input)
```

The random salt occurs only inside the recipient's encrypted grant plaintext;
the visible commitment therefore does not expose a low-entropy topic list.

For each recipient, the authority creates a fresh P-256 ephemeral key and
encapsulates to the credential's ML-KEM-768 key. Let
`classical32` be the P-256 ECDH affine x-coordinate and `post_quantum32` the
ML-KEM shared secret. Define the exact package context:

```text
control_link = sequence u64 ||
               (0, or 1 || previous_envelope_id[32])

package_context =
  "aster/rekey-package-context/v1" ||
  protocol_version u16 || suite_id u16 || keying_format u16 ||
  mission[32] || authority_id[32] || b16(scope) || epoch u64 ||
  control_link || package_set_hash[32] ||
  recipient_node_id[32] || credential_hash[32] || grant_commitment[32] ||
  b16(p256_ephemeral_public[33]) ||
  b32(ml_kem_768_ciphertext[1088])

package_key = HKDF-SHA-256(
  salt = package_set_hash,
  IKM  = classical32 || post_quantum32,
  info = "ASTER-KDF-v1" ||
         u16(len("scope-rekey-recipient-wrap")) ||
         "scope-rekey-recipient-wrap" ||
         u32(len(package_context)) || package_context,
  L = 32)

package_aad =
  "aster/rekey-package-aad/v1" || b32(package_context)
```

`sealed_grants_nonce` is a fresh 12-byte AES-256-GCM nonce and `sealed_grants`
is AES-256-GCM under `package_key` over this exact plaintext:

```text
keying_format                     u16 = 1
mission                           32 bytes
authority_id                      32 bytes
scope                             b16(UTF-8), 1..128 bytes
epoch                             u64, nonzero
control_link                      as above
package_set_hash                  32 bytes
recipient_node_id                 32 bytes
credential_hash                   32 bytes
grant_commitment                  32 bytes
grant_salt                        32 bytes
fresh_route_key                   32 bytes
topic_count                       u16, 0..128
topic_grants                      count * (b16(topic) || content_key[32])
```

Every clear echo MUST match its authenticated enclosing control and package, the
topics MUST be strictly increasing, and recomputing the salted grant commitment
MUST succeed. Outer AEAD, the root-signed delegated credential, the delegated
control signature, chain syntax, bounds, ordering, and package-set hash are
checked before durable ingest. An out-of-order control remains pending and MUST
NOT mutate keys. Activation occurs only after the control becomes durably
applied, including when a newly contiguous predecessor causes a pending control
to become applied.

The durable row records both stable `authority_id` and delegated signer NodeID.
All delegated ControlAuthority identities for that authority append to the same
mission-wide sequence/head namespace keyed by `authority_id`; signer rotation
does not create a new chain. A control signed by an identity already revoked in
the applied prefix is rejected. If activation reaches a pending control whose
signer was revoked by an earlier link, that control and the entire unapplied
suffix depending on it are reported as rejected and removed from pending
activation and transmission. A live signer must reissue the suffix from the
last exact applied head.

This is a single-writer authenticated log, not consensus. A planned handoff
requires the new signer to possess a root-signed ControlAuthority credential and
the trusted exact current `(sequence, envelope_id)` head before it appends; the
old signer must stop writing and should be revoked in the contiguous history.
Two valid signers that concurrently claim the same next sequence create a fork,
which fails closed. The root provisioner does not bypass or reset the chain.
Recovery after loss of a delegated signer therefore requires another trusted
delegated signer plus the exact head. Recovery after total history loss, or
authorized replacement of a forked head, requires a separately specified
root-signed control epoch/cutover and an externally retained high-water mark;
this profile does not define either mechanism.

SQLite schema-11 rows persist the signer. Opening a schema-10 store that already
contains ordinary or bridge control rows fails closed because those legacy rows
cannot be safely attributed to a delegated identity. Such a store requires a
future signed cutover/import procedure or a fresh store; only an empty schema-10
control state is upgraded automatically.

A matching, nonrevoked recipient verifies its exact credential hash, performs
both P-256 agreement and ML-KEM decapsulation, opens the package, and validates
every echoed field, ordering rule, and commitment before mutating grants. Only
then does it remove any pre-placed route/content grants for this `(scope,
epoch)` and install the authenticated replacements. An omitted recipient, a
node for which no package matches its exact credential, or a locally revoked
node removes any pre-placed grants for the epoch and installs none. A rejected,
tampered, forked, or rolled-back control performs no activation. The signed
recipient list also becomes the dynamic `peer_can_route` authorization set for
that scope and epoch.

On reopen, the reference reauthenticates and replays every persisted applied
control, redecapsulating its matching package to recover the same grants. Old
epoch material already captured is not retroactively erased. Because the outer
control uses the old common mission control-route key, a captured holder of that
key can observe format-1 package metadata, recipient identifiers, and sizes. It
cannot recover the hidden salts, granted topics, or fresh epoch keys from an
omitted recipient package.

### 6.1 Rekey recipient registry — administrative, not replicated

The authority's recipient-key registry is a signed, append-only administrative
artifact containing public credential material only: it contains no identity
seed, grant key, or mission control-route key. It is not an `ASTRENV2` control
and the reference replication runtime does not distribute it. Its exact
`ASTRRKR1` version-2 encoding is:

```text
magic                              "ASTRRKR1"                   8
registry_version                   u16 = 2                       2
protocol_version                   u16 = 1                       2
suite_id                           u16 = 0x0001                  2
mission                            32 bytes
authority_id                       32 bytes
registry_generation                u64, nonzero
entry_count                        u16, 1..1024
entries                            repeated as below
registry_signature                 encoded hybrid signature
```

Each entry is `node_id[32] || b32(credential_body, at most 16 KiB) ||
encoded_hybrid_authority_signature`. Entries MUST be in strictly increasing
NodeID order; each credential MUST validate for the registry mission and
authority, contain the Relay role, and hash to the entry NodeID.
`registry_generation` MUST equal `entry_count`. The whole artifact MUST be at
most 16 MiB. The final registry signature is over:

```text
HD("aster/rekey-registry/v1",
   every registry byte from magic through the final entry)
```

An initialized authority accepts an equal generation only when the exact
`NodeID -> credential wrapper` map is identical; the outer registry signature
bytes need not be identical. It accepts a greater generation only when every
prior NodeID maps to the identical credential wrapper. It rejects rollback,
replacement, omission, wrong authority, duplicates, and noncanonical order
atomically. On a fresh authority instance, the artifact alone cannot prove that
a newer registry was deleted. A deployment MUST persist the last accepted
generation in independent durable state and supply it as the minimum generation
on import; using the zero-minimum convenience import after losing that state
does not provide rollback detection.

### 6.2 Semantic-v2/v3/v4/v5/v6 bridge delegated control authentication

A semantic-version-2, semantic-version-3, semantic-version-4,
semantic-version-5, or semantic-version-6 ObjectKind `4` bridge authorization
uses authorization format `2`. Its protected plaintext begins with the
following canonical fields; the enabled-only policy fields retain the bounds in
[protocol.md](protocol.md) §12:

```text
object_kind                       u8 = 4
authorization_format              u16 = 2
mission                           32 bytes
authority_id                      32 bytes
control_sequence                  u64, nonzero
has_previous                      u8 = 0 or 1
previous_authorization_id         32 bytes iff has_previous = 1
authorization_key                 32 bytes
generation                        u64, nonzero
enabled                           u8 = 0 or 1
bridge_node_id                    32 bytes
source_scope                      b16(UTF-8), 1..128 bytes
target_scope                      b16(UTF-8), 1..128 bytes
enabled_policy                    present iff enabled = 1
delegated_control_authentication  b32(bytes below)
```

When `enabled = 1`, `enabled_policy` is encoded in this order:

```text
source_route_epoch                u64, nonzero
target_route_epoch                u64, nonzero
source_route_commitment           32 bytes
target_route_commitment           32 bytes
allowed_priority_mask             u8, nonzero subset of 0x0f
max_total_hops                    u8, 1..8
topic_count                       u16, 1..128
topics                            count * b16(UTF-8), strictly increasing
bridge_credential                 b32(credential_body), 1..16384 bytes
bridge_authority_signature        encoded hybrid signature
```

The enabled bridge credential is distinct from the delegated control credential:
it MUST identify `bridge_node_id`, carry the Relay role, and bind the exact
source and target route commitments.

The delegated-control authentication bytes are:

```text
magic                            "ASTRBCA2"                    8
authentication_format            u16 = 2                        2
control_authority_credential     b32(credential_body), 1..16384 bytes
authority_credential_signature   encoded hybrid signature
delegated_control_signature      encoded hybrid signature
```

The embedded control credential MUST validate under the mission authority root
and carry the ControlAuthority role. Its NodeID is persisted as the bridge
control signer. The delegated signature verifies the 32-byte message:

```text
HD("aster/bridge-delegated-control/v2",
   authorization_format u16 = 2 ||
   semantic_protocol u16 = 2 ||
   suite_id u16 = 0x0001 ||
   every authorization plaintext byte before
     delegated_control_authentication ||
   b32(control_authority_credential) ||
   authority_credential_signature)
```

Authorization format `1` and the former bare root-signature authentication
shape are rejected at the cryptographic-provider boundary. Durable activation
uses one independently contiguous bridge-control chain keyed by the stable
`authority_id`, not one chain per delegated signer. An authorization is live
only when its exact bytes have been reauthenticated in the current process, it
is the applied enabled generation high-water for its authorization key, and the
authority root identifier, delegated control signer, and bridge node are all
unrevoked. Revoking any of those identities removes dependent active routes and
outbound work while retaining the authenticated history needed for recovery and
audit. A revoked-signing pending suffix is rejected and removed under the same
reissue-from-the-last-head rule as ordinary controls.

## 7. Legacy per-hop forwarding wrapper

Forwarding metadata is deliberately outside the stable source envelope. The
wrapper is:

```text
magic                    "ASTRFWD1"          8
wrapper_format_version   u16 = 1              2
protocol_version         u16 = 1              2
suite_id                 u16 = 0x0001         2
selector                 16 bytes            16
protected_len            u32                  4
protected_ciphertext     protected_len bytes
```

The public header is exactly 34 bytes. `protected_len` includes the 16-byte tag
and MUST be 16 through 65,536. The wrapper MUST end after those bytes.

```text
ForwardingKey = PKDF(mission_control_route_key,
                     "aster/forwarding-key/v1", selector, 32)
ForwardingNonce = selector[0..12]
protected_ciphertext = AES-256-GCM(
  ForwardingKey, ForwardingNonce, forwarding_plaintext,
  exact_34_byte_public_header)
```

The protected plaintext is:

```text
sender_credential_body        b32(bytes), at most 16384 bytes
sender_credential_signature   encoded hybrid signature
recipient_node_id             32 bytes
exchange_id                   u64
source_envelope_id            32 bytes
custody_age_ms                u64
sender_forwarding_signature   encoded hybrid signature
```

The sender signature message is:

```text
HD("aster/forwarding-signature/v1",
   mission[32] || sender_NodeID[32] || recipient_NodeID[32] ||
   exchange_id u64 || source_EnvelopeID[32] || custody_age_ms u64)
```

The receiver MUST require both credential signatures and both forwarding
signature components, the Relay role, the sender NodeID equal to the identity of
the authenticated pairwise session, and recipient, exchange, and EnvelopeID
equal to the surrounding exchange. The custody value is an authenticated
nondecreasing lower bound. A forwarding node adds only elapsed time that it can
measure with local monotonic continuity; this format contains no wall-clock
timestamp and cannot account for an unmeasured powered-off interval.

This provider-owned wrapper is not the semantic-v3-format session custody claim below.
It embeds a credential and hybrid forwarding signature, but it does not encode
the source TTL or priority, exact transfer length, per-hop monotonic sample and
delta, live emission-policy revision, or authenticated session transcript ID.
No decoder may reinterpret one format as the other.

### 7.1 Semantic-v3-format session custody claim

A selected semantic-v3, semantic-v4, semantic-v5, or semantic-v6 Event or RouteEvent offer carries exactly one custody
claim encrypted as an `ASTRFR01` record from §9. The application AAD is the
exact ASCII string `"aster/custody-wrapper/v3"`, distinct from normal transport
frames. The plaintext is exactly 150 bytes:

```text
magic                    "ASTRCU03"          8
claim_format_version     u16 = 1              2
semantic_version         u16 = 3              2
session_id               32 bytes            32
transfer_id              32 bytes            32
exact_len                u64                   8
exchange_id              u64                   8
policy_revision          u64                   8
prior_age_ms             u64                   8
sample_clock_id          16 bytes            16
sample_tick_ms           u64                   8
hop_delta_ms             u64                   8
source_priority          u8                    1
source_ttl_present       u8                    1
source_ttl_ms            u64                   8
```

`session_id` MUST equal the completed handshake `FinalTranscriptHash`.
`transfer_id` is the exact Event/RouteEvent transfer SHA-256. `exact_len` and
`policy_revision` MUST be nonzero; `exchange_id = 0` is canonical and valid.
The selected runtime supplies its live emission-policy revision as
`policy_revision`. `source_priority` MUST be `0..3`. When
`source_ttl_present = 0`, `source_ttl_ms` MUST be zero; when it is `1`, every
`u64` value, including immediate-expiry zero, is canonical. Other presence
values fail.

The authenticated forwarding age is the checked sum
`prior_age_ms + hop_delta_ms`; overflow fails. The receiver MUST compare the
transfer ID, exact length, exchange ID, source priority, and optional source TTL
with the live exchange and freshly source-verified header before constructing a
verified custody capability. The directional §9 channel authenticates the
session, sequence, nonce, and distinct AAD and rejects replay, cross-session
substitution, tampering, or use before semantic version 3. The embedded
`semantic_version` field deliberately remains the custody-format minimum `3`
inside v4, v5, and v6 sessions; the completed handshake transcript and traffic
keys bind the actually negotiated session. With the current §9
encoding the complete record is exactly 202 bytes; implementations MUST reject
an empty record or one larger than 256 bytes. Stable source bytes remain in the
ordinary peer-neutral transfer path and are not embedded in this claim.

## 8. Handshake flights and transcript

The reference adjacency handshake has four flights. Every flight starts with the
same 14-byte prefix:

```text
magic                       "ASTRHS01"     8
outer_framing_version       u16 = 1         2
outer_crypto_profile_id     u16 = 0x0001    2
flight_kind                 u8: 1..4        1
reserved                    u8 = 0          1
```

Each complete flight MUST be at most 65,536 bytes and MUST end after its defined
fields. Within this section, an AEAD field is:

```text
AEAD = nonce[12] || b32(ciphertext_and_tag)
```

The suite label used verbatim below is:

```text
"ASTER-v1/P256+ML-KEM-768/ECDSA-P256+ML-DSA-65/AES-256-GCM/HKDF-SHA256"
```

It is denoted `SuiteLabel`; it is never NUL terminated.

### 8.1 Flight 1 — anonymous ClientHello and mission proof

After the kind-`1` prefix:

```text
supported_version_count         u16, 1..16
supported_semantic_versions     supported_version_count * u16
offered_suite_count             u16, 1..16
offered_suite_ids               offered_suite_count * u16
initiator_nonce                 32 fresh random bytes
initiator_p256_ephemeral        b16(exactly 33 bytes)
initiator_ml_kem_768_public     b32(exactly 1184 bytes)
anonymous_mission_proof         AEAD with ciphertext exactly 16 bytes
```

Both offer lists MUST be nonempty, nonzero, duplicate-free, and in strictly
descending numeric order. The default semantic-version list is `[6, 5, 4, 3, 2, 1]`; a
v2 compatibility initiator may send `[2, 1]`, and a v1-only compatibility
initiator sends `[1]`. The suite list contains only
`[0x0001]`. An honest responder selects the highest common semantic version and
its locally preferred complete common suite.

The canonical ClientHello used by hashes is not the literal flight body because
both public-key lengths are `u32` in the canonical form:

```text
CanonicalClientHello =
  "ASTER-CLIENT-HELLO-v1" || SuiteLabel ||
  supported_version_count u16 || supported_semantic_versions ||
  offered_suite_count u16 || offered_suite_ids ||
  initiator_nonce[32] ||
  b32(initiator_p256_ephemeral[33]) ||
  b32(initiator_ml_kem_768_public[1184])

HelloHash = SHA-256(CanonicalClientHello)
```

The common mission control-route key from the local provisioning bundle is also
the mission-proof root. Session endpoint construction fails if that key is
absent. Derive:

```text
MissionProofKey = PKDF(mission_control_route_key,
  "aster/mission-proof-key/v1", HelloHash, 32)

MissionProofNonce = PKDF(mission_control_route_key,
  "aster/mission-proof-nonce/v1", HelloHash, 12)

MissionProofAAD = "aster/mission-proof-aad/v1" || HelloHash
```

The proof ciphertext is AES-256-GCM encryption of the empty string using those
values, so it is exactly the 16-byte tag. The transmitted proof nonce MUST equal
the derived nonce. A responder verifies the derived nonce and tag before parsing
the ML-KEM public key or performing P-256 agreement or ML-KEM encapsulation.

The proof is an anonymous shared-mission admission check, not an individual
signature. It is bound into later authentication as:

```text
EncodedMissionProof = MissionProofNonce[12] || b32(tag[16])
MissionProofCommitment = HD(
  "aster/mission-proof-transcript/v1", EncodedMissionProof)
```

A replayed captured flight can still pass this stateless admission check and
cause a fresh response; deployments MUST rate-limit handshake work.

### 8.2 Flight 2 — ServerHello and protected ServerAuth

After the kind-`2` prefix:

```text
selected_semantic_version       u16 = 1, 2, or 3
selected_suite_id               u16 = 0x0001
responder_nonce                 32 fresh random bytes
responder_p256_ephemeral        b16(exactly 33 bytes)
ml_kem_768_ciphertext           b32(exactly 1088 bytes)
protected_server_auth           AEAD, ciphertext longer than 16 bytes
server_key_confirmation         AEAD, ciphertext exactly 16 bytes
```

The initiator MUST require the selected semantic version and suite to occur in
its transmitted offers and to be locally supported.

### 8.3 Public transcript and hybrid secret combiner

The canonical unsigned ServerHello is:

```text
CanonicalServerHello =
  "ASTER-SERVER-HELLO-v1" || SuiteLabel ||
  selected_semantic_version u16 || selected_suite_id u16 ||
  responder_nonce[32] ||
  b32(responder_p256_ephemeral[33]) ||
  b32(ml_kem_768_ciphertext[1088])
```

Neither flight prefix, mission proof, protected authentication field, nor key-
confirmation field is included in these two canonical hello values. The public
transcript hash is:

```text
PublicTranscriptHash = SHA-256(
  "ASTER-HANDSHAKE-TRANSCRIPT-v1" ||
  b32(CanonicalClientHello) || b32(CanonicalServerHello))
```

P-256 ECDH produces the 32-byte affine x-coordinate described in §1.2.
ML-KEM-768 produces its 32-byte shared secret. Their AND-combiner is exact
concatenation in classical-then-PQ order:

```text
HybridIKM = P256SharedSecret[32] || MLKEMSharedSecret[32]

ScheduleContext =
  selected_semantic_version u16 || selected_suite_id u16 ||
  SuiteLabel || PublicTranscriptHash[32]

HandshakeKDF(label) = HKDF-SHA-256(
  salt = PublicTranscriptHash,
  IKM  = HybridIKM,
  info = "ASTER-KDF-v1" ||
         u16(len(label)) || label ||
         u32(len(ScheduleContext)) || ScheduleContext,
  L    = 32)
```

Seven independent 32-byte secrets are required:

| Use | Exact label |
|---|---|
| initiator-to-responder traffic | `initiator-to-responder` |
| responder-to-initiator traffic | `responder-to-initiator` |
| ServerAuth protection | `server-handshake-protection` |
| ClientAuth protection | `client-handshake-protection` |
| server key confirmation | `server-key-confirmation` |
| client key confirmation | `client-key-confirmation` |
| ServerFinished protection | `server-finished-confirmation` |

Failure of either ECDH or ML-KEM, or omission/reordering of either 32-byte shared
secret, fails the handshake. There is no classical-only or PQ-only result. The
full ClientHello offers and ServerHello selection feed the public transcript;
the selected semantic version also feeds the schedule context. Therefore an
unauthenticated on-path party cannot strip/reorder offers or rewrite an honest
selection while preserving the mission proof, confirmations, and hybrid endpoint
authentication.

This transcript property does not authenticate a responder capability list or
minimum policy. A valid older or modified responder can select offered semantic
version `1` and authenticate that selection. Downgrade-sensitive production use
MUST remain unauthorized until an authority-signed mission minimum, durable
per-identity high-water, explicit signed rollback authorization, and independent
mixed-version validation are provided. No new handshake bytes are assigned here.

### 8.4 Credential and protected-auth plaintexts

The handshake credential carried inside protected authentication is:

```text
FlightCredential =
  b32(credential_body, at most 16384 bytes) ||
  b16(authority_ecdsa_signature, exactly 64 bytes) ||
  b32(authority_ml_dsa_signature, exactly 3309 bytes)
```

The credential body and authority signatures are exactly those in §3.1. The
server and client credential contexts are:

```text
ServerCredentialContext =
  MissionProofCommitment[32] || responder_FlightCredential

ClientCredentialContext = initiator_FlightCredential
```

The server MUST reproduce the commitment to the proof it accepted. The
initiator MUST compare it byte-for-byte to its sent proof commitment.

The protected-auth plaintext has a handshake-specific encoding whose two
signature lengths are both `u32`:

```text
HandshakeAuth(context, handshake_signature) =
  b32(context) ||
  b32(handshake_ecdsa_signature[64]) ||
  b32(handshake_ml_dsa_signature[3309])
```

The core parser's context bound is 1,048,576 bytes; the reference wire profile's
65,536-byte whole-flight bound is tighter and therefore limits any transmitted
context before decryption/allocation. Suite `0x0001` still requires the two
signature fields to be exactly 64 and 3,309 bytes.

Both components of the responder's handshake signature sign this exact message:

```text
ServerAuthMessage =
  "ASTER-SERVER-AUTH-v1" || PublicTranscriptHash[32] ||
  b32(empty) || b32(ServerCredentialContext)
```

Let `EncodedServerAuth` be the exact resulting `HandshakeAuth` plaintext. It is
encrypted using the `server-handshake-protection` key, a transmitted unique
12-byte nonce, and:

```text
ServerAuthAAD =
  "ASTER-SERVER-AUTH-PROTECTION-v1" ||
  SuiteLabel || PublicTranscriptHash
```

The server key-confirmation field encrypts the empty string with the
`server-key-confirmation` key, a transmitted unique nonce, and:

```text
ServerConfirmationAAD =
  "ASTER-SERVER-CONFIRM-v1" || SuiteLabel || PublicTranscriptHash
```

The initiator verifies the server empty-plaintext confirmation, decrypts the
ServerAuth field, validates the authority credential and Relay role, compares
the mission-proof commitment, and requires both handshake signatures.

### 8.5 Flight 3 — protected ClientAuth and final transcript

After the kind-`3` prefix:

```text
protected_client_auth           AEAD, ciphertext longer than 16 bytes
client_key_confirmation         AEAD, ciphertext exactly 16 bytes
```

Both components of the initiator's handshake signature sign:

```text
ClientAuthMessage =
  "ASTER-CLIENT-AUTH-v1" || PublicTranscriptHash[32] ||
  b32(EncodedServerAuth) || b32(ClientCredentialContext)
```

Let `EncodedClientAuth` be the exact `HandshakeAuth` plaintext containing the
client context and this signature. It is encrypted using the
`client-handshake-protection` key, a transmitted unique nonce, and:

```text
ClientAuthAAD =
  "ASTER-CLIENT-AUTH-PROTECTION-v1" ||
  SuiteLabel || PublicTranscriptHash
```

The final authenticated transcript hash is:

```text
FinalTranscriptHash = SHA-256(
  "ASTER-FINISHED-v1" || PublicTranscriptHash[32] ||
  b32(EncodedServerAuth) || b32(EncodedClientAuth))
```

It therefore binds both anonymous hellos, both ephemeral mechanisms, proof
commitment, missions, roles, route-grant commitments, credentials, both
authority hybrid signatures, and both handshake hybrid signatures. The client
key-confirmation field encrypts the empty string with the
`client-key-confirmation` key, a transmitted unique nonce, and:

```text
ClientConfirmationAAD =
  "ASTER-CLIENT-CONFIRM-v1" || SuiteLabel || FinalTranscriptHash
```

The responder decrypts ClientAuth, recomputes and verifies the empty-plaintext
confirmation, validates the initiator credential and Relay role, and requires
both initiator handshake signatures.

### 8.6 Flight 4 — ServerFinished

After the kind-`4` prefix is one AEAD field:

```text
protected_finished = nonce[12] || b32(ciphertext[48])
```

This is a direct handshake AEAD, not a sequenced transport record. Its plaintext
is `FinalTranscriptHash[32]`; it uses the `server-finished-confirmation` key, a
transmitted unique nonce, and:

```text
ServerFinishedAAD =
  "ASTER-SERVER-FINISHED-v1" || SuiteLabel || FinalTranscriptHash
```

Only exact recovery of `FinalTranscriptHash` completes the initiator state.
Profile 1 permits no 0-RTT application data and exposes no application-capable
initiator session before this check. The two traffic keys from §8.3 initialize
the protected-record state in §9, and `FinalTranscriptHash` is the session's
authenticated transcript identifier.

### 8.7 Clear metadata and privacy boundary

No mission ID, NodeID, credential body, role, authority signature, or route-grant
commitment occurs in clear in any of the four flights. Clear handshake metadata
is limited to magic/kind/framing version/profile, ordered semantic and suite
offers, selected semantic version and suite, random nonces, ephemeral
P-256/ML-KEM bytes, anonymous mission-proof nonce/tag, ciphertext and flight
lengths, and observable timing/fragmentation. The runtime capture test
reassembles fragmented flights and scans all four for both peers' mission,
credential, NodeID, and route-grant commitment canaries.

This wire privacy does not hide link or network identifiers, rendezvous metadata,
or correlation established before the first Aster flight. A member holding the
common mission proof key can recognize or create valid mission proofs. A captured
valid flight 1 can be replayed to trigger bounded/rate-limited responder work.

## 9. Protected transport records

After the authenticated four-flight handshake, each application frame is:

```text
magic              "ASTRFR01"                  8
protocol_version   u16 = 1                       2
suite_id           u16 = 0x0001                  2
sequence           u64                           8
nonce              12 bytes                     12
ciphertext         b32(plaintext || GCM tag)     variable
```

Application plaintext is at most 16 MiB; ciphertext is therefore 16 through
`16 MiB + 16` bytes. The whole encoded frame is bounded by the reference decoder
at `16 MiB + 128` bytes. The sender sequence starts at zero in each direction,
increments by one for each encryption attempt, never repeats, and fails closed
after using `u64::MAX`.

The application AAD for normal transport frames is the exact ASCII string
`"aster/transport-frame/v1"`. Record AEAD associated data is:

```text
"ASTER-RECORD-AAD-v1" || sequence u64 || b32(application_aad)
```

AES-256-GCM uses the directional traffic key from §8 and the transmitted nonce.
The reference nonce generator chooses a fresh random 4-byte provider prefix and
a fresh random starting `u64`, emits `prefix || counter`, and fails before a
provider-lifetime wrap could repeat the starting value. Other implementations
MAY use another construction but MUST guarantee key/nonce uniqueness.

The receiver authenticates the record before mutating replay state. It maintains
a 128-sequence sliding window independently in each receive direction. A valid
sequence greater than the recorded maximum advances the window; an unseen
sequence within 127 below the maximum is accepted; a duplicate or a sequence
128 or more below the maximum is rejected. A forged high sequence cannot advance
the window.

`ServerFinished` is not a record and consumes no transport sequence; its direct
AEAD is specified in §8.6. The first normal protected frame in each direction
therefore uses sequence zero.

### 9.1 Semantic-v4 selected State/Record mechanics plaintext

The selected-node mechanics plaintext is protected as the ordinary §9
application record with AAD `"aster/transport-frame/v1"`. Semantics v4, v5, and v6 add no
new outer record, source envelope, or suite. Every selected mechanics plaintext
starts with `"ASM\x01" || tag u8`. The mutable tags are invalid unless the
completed session negotiated semantic version `4`, `5`, or `6`; class `3` is
valid only at v5 or v6, and v1-v3 Event-compatible sessions reject every
mutable class.

The common mutable fields are:

```text
class       u8: 1 State, 2 Record, 3 Blob source under semantic v5 or v6
direction   u8: 1 ToSessionInitiator, 2 ToSessionResponder
transfer_id 32 bytes; its typed class MUST equal class
disposition u8: 0 Duplicate, 1 Inserted, 2 DeferredCapacity
remaining   u64; at most the selected reconciliation cardinality bound
```

The mutable tag registry is closed:

| Tags | Plaintext after `"ASM\x01" || tag` |
|---|---|
| `0x69` Interest, `0x6a` InterestReply | `class || canonical bounded interest` |
| `0x71` InventoryQuery, `0x72` InventoryReply, `0x75` DifferenceQuery, `0x76` DifferenceReply | `class || direction || b32(negentropy frame)`; frame at most 16 KiB |
| `0x73` InventoryComplete, `0x74` InventoryCompleteAck, `0x77` DifferenceBound, `0x78` DifferenceBoundAck, `0x79` LaneDeferred, `0x7a` LaneDeferredAck | `class || direction` |
| `0x81` Fetch | `class || direction || transfer_id` |
| `0x82` Object, `0x83` Offer | `class || direction || transfer_id || b32(source envelope)`; object at most 1 MiB |
| `0x84` ApplyResult | `class || direction || transfer_id || disposition` |
| `0x85` FetchResult, `0x86` FetchResultAck | `class || direction || transfer_id || disposition` |
| `0x91` Finish, `0x92` Finished | `class || direction || remaining` |

`FetchResult` and `FetchResultAck` are each exactly 40 plaintext bytes. An
acknowledgement MUST echo the exact class, direction, transfer ID, and
disposition and MUST precede another Fetch or Finish on that lane. Finish and
Finished are each exactly 15 plaintext bytes and MUST echo the exact remaining
count. Truncation, trailing bytes, unknown class/direction/disposition, a typed
ID/class mismatch, or an out-of-order or changed result/acknowledgement fails
the contact. The exact sequencing, capacity meaning, fairness cursor, mode
behavior, and finite-TTL rejection are normative in
[protocol.md](protocol.md) §9.1.

### 9.2 Semantic-v5 selected Blob mechanics plaintext

Semantic v5 reuses the protected §9 record and the mutable source grammar
above with `class = 3` for Blob source envelopes. It reserves separate exact
Blob interest and carrier-range tags; v1-v4 sessions reject all of them. Source
and carrier formats remain `ASTRENV2`/`ASTRENV3` and `ASTRBT01` version 1.
Semantic v6 inherits these Blob mechanics byte-for-byte.

BlobInterest (`0x6b`) and BlobInterestReply (`0x6c`) encode:

```text
selector_count u16, 0..256
selectors selector_count times, strictly increasing by exact topic/scope:
  topic         b16(UTF-8), 1..128 bytes
  scope         b16(UTF-8), 1..128 bytes; exact, never descendants
  epoch         u64
  content_proof 32 opaque provider-owned bytes
```

The encoded interest body is at most 76,802 bytes, so each protected plaintext
including `"ASM\x01" || tag` is at most 76,807 bytes. One maximum-size interest
plus reply exchange is exactly 153,718 bytes after two 52-byte protected-record
overheads. An empty list means receive no Blob. Repeated exact topic/scope
selectors, noncanonical order, trailing bytes, or a proof of any other length
fail before source reconciliation.

Every range tuple is:

```text
direction     u8: 1 ToSessionInitiator, 2 ToSessionResponder
source_id     32-byte exact Blob source transfer ID
object_id     33 bytes: kind 2 || 32-byte carrier digest
total_len     u64, nonzero
offset        u64, less than total_len
range_len     u32, 1..16384; offset + range_len <= total_len
```

BlobRangeFetch (`0xa1`) appends the requester's exact 32-byte current content
proof to that tuple. BlobRange (`0xa2`) appends a disposition byte (`1` Data,
`2` Unavailable) and `b32(bytes)`; Data has exactly `range_len` bytes and
Unavailable has none. BlobRangeResult (`0xa5`) and BlobRangeResultAck (`0xa6`)
replace `range_len` with `accepted_len` and append disposition `1` Partial, `2`
Complete, `3` Duplicate, `4` DeferredCapacity, or `5` Unavailable. Partial and
Complete accept 1..16,384 bytes; Complete ends exactly at `total_len`, Partial
does not, and the other dispositions accept zero. Result and acknowledgement
are each exactly 92 plaintext bytes.

BlobCarrierFinish (`0xb1`) and BlobCarrierFinished (`0xb2`) encode `direction ||
remaining u64`; each is exactly 14 plaintext bytes and `remaining` is at most
the selected reconciliation cardinality bound. Finished echoes the requester's
remaining count for sequencing only; it is not independent proof of requester
disk state. The exact per-range Result/Ack tuples bind accepted durable-prefix
progress. The exact authorization,
sequencing, source-before-carrier, peer-neutral durable-prefix, completion, and
policy rules are normative in [protocol.md](protocol.md) §9.2.

The runtime reserves exactly 17,127 protected bytes for one full carrier-range
settlement: one 123-byte Fetch, one maximum 16,480-byte Range, two 92-byte
Result/Ack plaintexts, two 14-byte Finish/Finished plaintexts, and 52 bytes of
record protection for each of the six frames. This is three exchanges and does
not change any codec limit.

### 9.3 Semantic-v6 selected Event-bridge mechanics plaintext

Semantic v6 inherits every v5 ordinary mechanics plaintext byte-for-byte and
adds six Event-bridge tags under the same `"ASM\x01" || tag` prefix. They are
invalid unless the completed session negotiated semantic version `6`; v1-v5
sessions reject them. The lane proceeds beyond its hello only when both
authenticated endpoints send the canonical `enabled = 1` value.

| Tag | Plaintext after `"ASM\x01" || tag` |
|---|---|
| `0xc1` BridgeHello | `enabled u8`, exactly `0` or `1` |
| `0xc2` BridgeHelloAck | `enabled u8`, exactly `0` or `1` |
| `0xc3` BridgeRouteOffer | `wrapper_id[32] || b32(wrapper) || b32(source)` |
| `0xc4` BridgeRouteResult | `wrapper_id[32] || disposition u8` |
| `0xc5` BridgeFinish | `remaining u64` |
| `0xc6` BridgeFinished | `remaining u64` |

The wrapper is at most 524,322 bytes, the source is at most 1,048,576 bytes,
and the claimed `wrapper_id` MUST equal SHA-256 of the exact wrapper bytes. A
maximum BridgeRouteOffer plaintext is therefore 1,572,943 bytes. The result is
exactly 38 bytes and its disposition is `0` Duplicate, `1` Promoted, `2`
StoredInactive, or `3` NotSelected; every other value is invalid. Authentication
or current-policy failure has no disposition and fails the contact.

Finish and Finished are each exactly 13 bytes. `remaining` MUST NOT exceed the
selected reconciliation cardinality bound, and Finished MUST echo the exact
value. The selected runtime permits at most eight offers in each direction per
contact and sequences the initiator's offers before the responder's; a changed,
crossed, duplicate, or out-of-phase result or finish fails the contact. The
policy, durable-commit, payload-blind forwarding, and delivery rules are
normative in [protocol.md](protocol.md) §9.3.

## 10. Blob manifest and chunk cryptography

### 10.1 Canonical manifest bytes

A Blob manifest is a canonical, source-authenticated object with this exact
layout:

```text
magic                         "ASTRBM01"          8
manifest_version              u16 = 1              2
protocol_version              u16 = 1              2
suite_id                      u16 = 0x0001         2
blob_id                       32 bytes             32
total_plaintext_len           u64                  8
chunk_size                    u32                  4
chunk_count                   u64                  8
blob_content_group            32 bytes             32
content_epoch                 u64                  8
has_media_type                u8 = 0 or 1           1
media_type                    b16(UTF-8) iff flag  variable
schema_id                     b16(opaque bytes)    variable
chunk_records                 count * 72 bytes     variable
whole_plaintext_sha256        32 bytes             32
```

If present, media type is 1 through 255 UTF-8 bytes. `schema_id` is 0 through
1,024 bytes. Chunk size is 4,096 through 65,536 bytes inclusive. Default policy
uses 16,384. `chunk_count` MUST equal
`ceil(total_plaintext_len / chunk_size)`, with zero for an empty Blob. It MUST
also be at most 14,543. The exact manifest MUST be at most 1,048,576 bytes and
must end after the whole-content digest. Those chunk-count and chunk-size bounds
make 953,090,048 bytes the largest accepted nonempty plaintext Blob even though
the length field is `u64`.

Each 72-byte chunk record, in increasing zero-based chunk index order, is:

```text
plaintext_sha256       32 bytes
ciphertext_sha256      32 bytes
plaintext_len          u32
ciphertext_len         u32
```

For every non-final chunk, plaintext length equals `chunk_size`; the final
length is the remainder. Ciphertext length MUST equal plaintext length plus 16.
Both digests are ordinary SHA-256 over the exact corresponding bytes.

### 10.2 BlobID and manifest commitment

Blob-specific hashes use a prefix-only domain construction:

```text
BDH(domain, body) = SHA-256(u64(len(domain)) || domain || body)
```

Unlike `HD`, `BDH` has no `u64(len(body))` word. The Blob identity prefix is:

```text
manifest_version u16 || total_plaintext_len u64 || chunk_size u32 ||
chunk_count u64 ||
(
  0
  or 1 || u64(len(media_type)) || media_type
) ||
u64(len(schema_id)) || schema_id
```

Then:

```text
BlobID = BDH(
  "aster/blob-id/v1",
  identity_prefix ||
  plaintext_sha256[0] || ... || plaintext_sha256[chunk_count-1] ||
  whole_plaintext_sha256)

ManifestDigest = BDH("aster/blob-manifest/v1", exact_manifest_bytes)
```

BlobID deliberately excludes scope/content-group, content epoch, ciphertext
digests, and ciphertext lengths; access wrapping can change without changing
plaintext identity. ManifestDigest commits all of those manifest fields.

The Blob manifest uses the same content-group derivation as the source envelope:

```text
group_input = scope_bytes || 0x00 || topic_bytes
BlobContentGroup = HD("aster/content-group/v1", group_input)
```

### 10.3 Per-chunk protection

For zero-based `index`, define `chunk_context = BlobID[32] || index u64` and:

```text
BlobKDF(seed32, label, chunk_context, N) =
  HKDF-SHA-256(
    salt = "aster/blob-kdf/v1",
    IKM  = seed32,
    info = u16(len(label)) || label ||
           u32(40) || chunk_context,
    L    = N)

ChunkKey = BlobKDF(content_epoch_seed,
                   "aster/blob-chunk-key/v1", chunk_context, 32)
ChunkNonce = BlobKDF(content_epoch_seed,
                     "aster/blob-chunk-nonce/v1", chunk_context, 12)
ChunkAAD =
  "aster/blob-chunk-aad/v1" ||
  protocol_version u16 || suite_id u16 || BlobID[32] ||
  BlobContentGroup[32] || content_epoch u64 || index u64 ||
  plaintext_len u64

chunk_ciphertext = AES-256-GCM(
  ChunkKey, ChunkNonce, exact_plaintext_chunk, ChunkAAD)
```

The chunk ciphertext is exactly plaintext ciphertext followed by the 16-byte
GCM tag; it has no standalone header. Before durable acceptance, a receiver
MUST validate `(BlobID, index)`, manifest bounds, expected length, ciphertext
SHA-256, AEAD authentication, and plaintext SHA-256. Before delivery of a
complete Blob, it MUST additionally validate the whole-plaintext SHA-256 while
streaming chunks in order.

### 10.4 Source-authenticated route commitment

The canonical manifest is the encrypted payload of a Blob-class source envelope;
it is not a second replication object. That source envelope's semantic header
MUST have `logical_key = BlobID`, `blob_route_tag = 1`, the manifest's nonzero
chunk count, and the route Merkle root below. Because the singleton publisher
signature binds the complete semantic header, the commitment is source
authenticated before a relay or reader relies on it. Although `ASTRBM01` can
canonically encode an empty Blob, envelope format 2 requires a nonzero route
chunk count, so this network profile does not publish an empty Blob.

For chunk `index`, let `ciphertext_sha256` and `ciphertext_len` be the fields in
its manifest record:

```text
RouteLeaf(index) = BDH(
  "aster/blob-route-leaf/v1",
  protocol_version u16 || BlobID[32] || index u64 ||
  ciphertext_sha256[32] || ciphertext_len u32)

RouteParent(level, left, right) = BDH(
  "aster/blob-route-node/v1",
  protocol_version u16 || level u16 || left[32] || right[32])

EmptyRouteRoot = BDH(
  "aster/blob-route-empty/v1",
  protocol_version u16 || BlobID[32] || 0 u64)
```

Leaves are in increasing index order. At level zero, adjacent leaves are paired
left then right and hashed with `RouteParent(0, ...)`; the parent level is paired
with level one, and so on. An unpaired final node is promoted byte-for-byte,
without another hash. The last remaining value is the route root. A proof lists
only existing sibling hashes from the leaf level upward; left/right position and
levels with a promoted unpaired node are derived from `(index, chunk_count)`.
Proofs are limited to 16 hashes, and a verifier MUST consume the complete proof
and reproduce the signed root. `EmptyRouteRoot` defines the local zero-chunk
tree but, as stated above, is not accepted in a version-2 Blob source header.

The authorization tuple used by the runtime is:

```text
source_envelope_id[32] || BlobID[32] || chunk_count u64 || route_root[32]
```

The first value is raw `SHA-256(source_envelope_bytes)`; the remaining values
come from that envelope's verified, protected, source-signed header. The tuple is
conceptual state and adds no bytes to the envelope.

### 10.5 Blob ciphertext transfer object

One canonical independently ranged chunk carrier is:

```text
magic                    "ASTRBT01"                 8
protocol_version         u16 = 1                     2
source_envelope_id       32 bytes                   32
blob_id                  32 bytes                   32
chunk_index              u64                         8
ciphertext_sha256        32 bytes                   32
ciphertext_len           u32                         4
proof_count              u8, 0..16                   1
proof_hashes             proof_count * 32 bytes     variable
chunk_ciphertext         ciphertext_len bytes       variable
```

`chunk_index` MUST be below 14,543 and, when checked against its authenticated
route, below `chunk_count`. `ciphertext_len` is 17 through 65,552 bytes, includes
the 16-byte GCM tag, and MUST consume the object exactly. `ciphertext_sha256`
MUST equal ordinary SHA-256 over those exact ciphertext bytes. The carrier is at
most 66,183 bytes. The carrier carries no plaintext digest, content group,
topic, scope, epoch, key, suite selector, forwarding wrapper, or application
metadata.

The carrier's replication identity is:

```text
transfer_id_input =
  protocol_version u16 || source_envelope_id[32] || BlobID[32] ||
  chunk_index u64 || ciphertext_sha256[32] || ciphertext_len u32 ||
  proof_count u8 || proof_hashes

BlobTransferDigest =
  BDH("aster/blob-transfer-object/v1", transfer_id_input)

BlobChunkObjectID = 0x02 || BlobTransferDigest
```

The ciphertext bytes are committed through `ciphertext_sha256`; they are not
repeated in `transfer_id_input`. A source-envelope ObjectID is
`0x01 || EnvelopeID`. These fixed 33-byte typed ObjectIDs are the identifiers in
`wire.cddl` inventory, WANT, DATA, and RECEIPT messages and are ordered by all 33
bytes. Prefixes therefore range from zero through 66 nibbles.

A Blob DATA message ranges over the exact `ASTRBT01` bytes and MUST have an empty
forwarding field; authenticated custody wrappers apply only to source-envelope
kind `1`. The canonical initial request for a Blob carrier has unknown total
length, no ranges, and `need_forwarding = false`. Once DATA supplies the total,
subsequent WANTs name its exact sorted missing ranges; a WANT with no missing
ranges and no forwarding work is invalid. Before retaining a chunk, a
route-capable node MUST verify the complete
carrier identity, exact source-envelope association, BlobID, ciphertext hash and
length, Merkle proof against the source-authenticated route, and quota. A
route-only relay can perform all of those checks without a content key or
plaintext digest. A reader additionally requires the decrypted, authenticated
manifest record to match the ciphertext digest and length before making the
chunk reader-visible, and then applies the AEAD/plaintext/whole-Blob checks in
§10.3. Serving a retained carrier MUST repeat peer authorization against its
source envelope.

If completion ends in a terminal full-object failure, the receiver MUST NOT add
the ObjectID to inventory or issue a successful receipt. Terminal failures are:
an exact-length mismatch; a source-envelope full-ID mismatch; carrier identity,
proof, ciphertext-hash, route-commitment, or source-association failure; and a
backend-classified source-envelope authentication or policy failure. The
reference atomically aborts only that exact typed ObjectID, clears its in-memory
pending writes, hop forwarding, commit-pending state, known total, and received
ranges, and recreates the canonical unknown-total, empty-range WANT. A later
authorized peer therefore starts the same object again from byte zero. A
transient Store, I/O, or missing-chunk failure is not permission to abort and
MUST retain staging progress.

### 10.6 Network versus local Blob state

Network/stable bytes are the Blob manifest inside its `ASTRENV2` source envelope,
the source-signed route commitment, the `ASTRBT01` carriers, and their ranged
deterministic-CBOR replication messages. Typed ObjectID and durable range state
are peer- and session-neutral, permitting another authorized peer to continue a
partial carrier.

`ASTRBC01` encrypted chunk files, `ASTRBS01` summaries, `ASTRRT01` cached route
trees, directory names, temporary files, expected-record files, quota counters,
and atomic-rename procedures are local store details and are not network bytes.

The reference SQLite store maps the typed ObjectID to a domain-separated
fixed-width staging key. Its terminal abort is one transaction deleting that
object's WANT row; cascading deletion removes only the corresponding typed
identity, missing ranges, and sealed extents. Restart hydration therefore cannot
restore any byte, known total, or range from a rejected object.

Unauthenticated transfer staging is isolated from committed-record capacity. For
a configured nonzero `max_bytes`, define:

```text
staging_bytes = min(max(floor(max_bytes / 4), 1),
                    64 * 1024 * 1024,
                    max_bytes - 1)
committed_bytes = max_bytes - staging_bytes
```

The declared length of one staged object is at most
`min(staging_bytes, 4 MiB)`. Staged object rows are capped at
`min(max_items, 10,000)`, sealed extents at 4,095 per object and 65,536 globally,
and admitted sealed bytes at `staging_bytes` globally. A new extent that would
exceed a bound is rejected transactionally; neither existing staging nor a
committed item is evicted. Staged bytes are not inputs to committed-record
priority eviction or reported committed quota use. The 4 MiB staged-object limit
is a reference-runtime admission limit even though the fixed source-envelope
format can encode a larger non-Blob Data object.

The reference composite inventory is capped at 100,000 typed ObjectIDs per
contact and inserts authorized source envelopes before their Blob carriers. A
route-only store retains the quota-accounted `ASTRBT01` carrier. A
content-authorized store retains that carrier plus the canonical encrypted chunk
file, so both representations count against local byte quota. Because the
transfer digest is not invertible to `(source, BlobID, index, proof)`, enumerating
a locally generated ObjectID may require bounded reconstruction from the
authenticated route tree; implementations MUST NOT assume the digest itself
reveals a chunk index.

The high-level and FFI Blob deduplication/read path MUST re-inspect the retained
sealed source envelope and require both the exact authenticated
`BlobRouteCommitment` and exact manifest bytes. Equality of BlobID or manifest
bytes alone is insufficient; a different route root or chunk count is a hard
failure.

The selected semantic-v5 redb composition uses a narrower, nonportable local
layout: it atomically stages an exact authenticated source plan, then persists
one contiguous prefix per `(source transfer ID, kind-2 carrier ID)`. Prefix
ownership is peer- and session-neutral. Ordinary Blob publication rows remain
absent until every carrier is complete, depot completion agrees, a fresh
provider content-completion pass verifies every AEAD/plaintext/chunk/whole-Blob
binding, and a fresh current route/physical-lineage proof agrees in one
promotion transaction. The selected staging ceilings are 64 MiB and 10,000
rows; network admission additionally caps plaintext at 64 MiB, chunks at 1,024,
and each requested prefix extension at 16 KiB. These are local selected-store
invariants, not new stable envelope bytes.

## 11. Required rejection behavior and format boundaries

A conforming decoder rejects before semantic dispatch when any fixed magic,
version, suite, kind, reserved byte, exact component length, count, ordering,
cross-field length, hash, AEAD tag, required signature, or trailing-byte rule
above fails. Authentication errors exposed to an unauthenticated peer SHOULD be
indistinguishable.

Semantic-version-2/3/v4/v5/v6 multi-item source authentication and inclusion proofs are
implemented as the separate `ASTRENV3` format-3 objects defined normatively in
[protocol.md](protocol.md) §6.1. They are not unresolved extensions to
`ASTRENV2` and MUST be rejected by semantic-version-1 sessions.

The following are intentionally not specified as portable wire encodings:

- broadcast capsules, cookies, resumption tickets,
  or authority-signed downgrade authorizations; and
- any portable local database, keystore, partial-range, or Blob file layout.

Implementations MUST NOT assign ad hoc encodings to those features while
claiming wire-profile `1` conformance.
