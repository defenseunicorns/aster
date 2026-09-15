# Integrated security profile seed


- Status: research seed frozen by BVB-825; not a selected protocol or production
  security profile
- Sole product authority:
  [`data-mesh-requirements.md`](../../../data-mesh-requirements.md)
- Requirements SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Exact implementation graph: `coset` 0.4.2 plus `aws-lc-rs` 1.18.0 in
  explicit non-FIPS mode, frozen by BVB-722/BVB-723 and executed as the
  integrated corpus by BVB-825

This seed exists to make the remaining profile work small, explicit, and
falsifiable. It is not evidence that the composition is standardized,
independently interoperable, FIPS validated, or ready for dependency
admission. Private labels and encodings below are research values. A final
profile must replace or formally adopt them, publish canonical vectors, and
pass an independent implementation.

## Layer and reader model

The executed research object has three nested responsibilities:

1. A carrier-neutral UTF-8 wrapper carries one opaque tagged COSE object. It
   exposes only its profile marker, ciphertext length, and ciphertext bytes.
2. A mesh-member `COSE_Encrypt` layer protects generation, scope, topic,
   priority, route, object ID, and the complete source object. An admitted
   relay may open this layer and verify the source object but receives no
   content key.
3. A source `COSE_Sign` requires exactly two protected signature slots—ES256
   then ML-DSA-65—over an AES-256-GCM `COSE_Encrypt` item batch. The consumer
   verifies both slots before decrypting the batch.

The outer member reader and inner payload reader are deliberately different.
Possessing a mesh-member key does not imply scope payload read authority.

## Research wire rules

The archived carrier fixture used a private textual marker followed by a
lowercase hexadecimal tagged COSE object. Its experimental marker, content-type
strings, and cryptographic context labels are not a public protocol. Exact
research encodings remain in the separately retained experiment; this document
preserves the design observations only.

The member envelope has these constraints:

- tagged `COSE_Encrypt`;
- protected `alg=A256GCM`, content type
  an experimental member-envelope identifier, and critical private profile label
  `-65537=1`;
- unprotected header containing only a 96-bit IV;
- exactly one `direct` recipient with no key identifier, nested recipient, or
  recipient ciphertext; and
- an experimental member-envelope external-AAD context.

The encrypted member plaintext is a length-bounded, deterministic sequence:
kind, membership generation, scope, topic, priority, route, object ID, and
source-object bytes. Strings and byte strings use unsigned 32-bit big-endian
length prefixes. Generation uses unsigned 64-bit big-endian. The only frozen
kind values are `1` for an item batch and `2` for a membership control.

The source object has these constraints:

- tagged `COSE_Sign` with no unprotected header;
- critical protected profile, suite, publisher, object-ID, and kind fields;
- exactly two protected signature slots in fixed order: ES256 with publisher
  P-256 key ID, then ML-DSA-65 with publisher PQ key ID;
- no unprotected signature fields; and
- source AAD binding generation, kind, scope, topic, priority, route, and
  object ID.

For a batch, the signed payload is a tagged `COSE_Encrypt` using A256GCM, a
96-bit IV, one `direct` recipient, and the same source AAD. The encrypted
plaintext binds batch generation and an ordered, bounded item list. Every item
has its own stable ID, data class, topic, scope, priority, TTL, and payload.
The executed acceptance journal records stable item IDs, not only batch IDs.

For a membership control, the signed payload names prior and new generations,
removed and added members, and an authority-state digest. It contains no new
group key. The executed generation-two key was preprovisioned, so this seed
does not define or receive credit for key distribution.

## Acceptance state

The research acceptance state is an atomically replaced and directory-synced
journal containing:

- the highest accepted membership generation;
- every retained stable item ID; and
- the set of accepted removed-member identifiers.

An exact item ID is idempotent across batches and generations. A batch below
the accepted generation is stale. A control is accepted only when its prior
generation equals current state and its new generation is exactly current plus
one. These rules do not yet define compaction, tombstone retention, bounded
windows, concurrent authorities, or recovery after lost control state.

## Mandatory-both and batch rules

Classical and PQ signature slots are both mandatory. Missing, duplicated,
reordered, substituted, or invalid slots fail closed before content
decryption. `Hybrid` never means negotiation down to one component.

When signatures are amortized across a batch, the exact encrypted ordered
batch is the signed payload and each item retains an independent stable ID and
metadata. Omission, reordering, substitution, or cross-batch splicing changes
the signed bytes and must fail verification. A final profile must also specify
partial transfer, garbage collection, maximum batch cardinality, and how an
independent implementation reproduces canonical bytes.

## Hybrid establishment status

BVB-825 re-executed provider feasibility for P-256 ECDH plus ML-KEM-768. Both
shared secrets were mandatory inputs to a task-authored HKDF-SHA-256 combiner,
and an AES-GCM key-confirmation fixture failed on missing components, changed
suite input, and a tampered KEM path. This proves provider and composition
feasibility only.

The combiner, transcript, authentication, recipient discovery, key
confirmation, negotiation, and scope-key distribution are not an adopted
published hybrid profile. They must not be copied into a production protocol
without a registered standards decision, independent vectors, and review.

## Zeroization contract seed

The minimum application hook used by the corpus has three observable effects:

1. mark the application-owned secret handle unavailable;
2. overwrite the application-owned byte buffer and prevent subsequent use;
3. remove the logical persisted key path and report failure if any step fails.

The executed hook demonstrated those three effects for one application-owned
copy. It provides no guarantee for provider-internal key objects, compiler or
runtime copies, crash dumps, filesystem remnants, snapshots, backups, HSM or
OS-keystore handles, or physical media. A production hook needs an explicit
key/copy inventory and target-specific provider destruction adapters.

## Frozen positive vectors

The public files contain ciphertext and public keys only; no member, content,
or private signing keys are published:

| Vector | SHA-256 | Bytes | Role |
|---|---|---:|---|
| `epoch1.carrier` | `20ed2fc4aee4b44f84daa1bdf37e213a14bd951995a97e05165ae7fff42acc24` | 8,185 | Generation-one two-item source batch |
| `rekey.carrier` | `e8fd11c80bb13db09660bbc16cdba80d235a0700b2a61fc871dfdb3b0080f1ff` | 7,789 | Dual-signed generation-one-to-two control |
| `epoch2.carrier` | `46a279b6bcb1b91ccae973497f96f2e4e51e3e936c7ada232699d67f10dc1831` | 8,189 | Generation-two batch with one retained ID and one new ID |
| `source-p256.pub.hex` | `f7317ebbbd7d7fa829099d9993aeee359cf1a535e9ebc6d162b96b6d3367e2ff` | 131 | ES256 public verifier |
| `source-mldsa65.pub.hex` | `828d06738545849f8fc3de2aedd4f203543dba4a106f7dcb4826136fb0247213` | 3,949 | ML-DSA-65 public verifier |

These are byte-stable research fixtures, not deterministic KATs or sufficient
standalone verification vectors: the decryption/member keys remain ignored
raw evidence. Their safe cross-arm use is opaque byte carriage, corruption,
storage inspection, and byte-identity comparison. A carrier receives no
security ownership credit merely for preserving them.

## Unresolved normative decisions

A production profile still needs published or explicitly adopted definitions
for mission identity and authority, carrier-to-mission authentication,
multi-scope key derivation, hybrid key distribution, membership-control
authorization and conflict ordering, exact algorithm negotiation and
downgrade state, bridge rewrapping, replay-state bounds and compaction,
snapshot-rollback disposition, provider/HSM destruction, target-specific
FIPS/CMVP coverage, error behavior, parser/resource bounds, and mixed-version
interoperation.
