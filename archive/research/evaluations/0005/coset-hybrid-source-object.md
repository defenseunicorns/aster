# coset hybrid source-object feasibility

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

> ****
> Requirements-first research evidence only. Current Aster compatibility had
> zero selection weight. Raw sources, dependency archives, logs, keys, and
> build output remain candidate-local and ignored.

## Outcome

**BUY `coset` 0.4.2 as the Rust COSE object codec and compose it with a
replaceable primitive provider; do not buy a security profile from it.**

BVB-722 freezes the exact Apache-2.0 source. It provides a meaningful amount
of reusable object machinery: `COSE_Sign` with multiple signatures,
`COSE_Encrypt` with recipients, protected headers and external AAD, tagged
CBOR round trips, duplicate-header rejection, final ML-DSA algorithm IDs, and
an ML-DSA public-key representation. Cryptography is intentionally supplied by
closures, which is the desired provider seam rather than a defect.

BVB-723 freezes the 32-package `coset` plus `aws-lc-rs` graph. BVB-725 freezes
the locked, offline execution, which passed a nested source-object corpus:

- an AES-256-GCM `COSE_Encrypt` object with a fixed direct-recipient fixture;
- that exact encrypted object as the payload of `COSE_Sign`;
- exactly two protected, mandatory signature slots, ES256/P-256 and
  ML-DSA-65;
- byte-stable tagged serialization, public verification without the content
  key, then authenticated consumer decryption;
- absence of the known plaintext byte string from the serialized object; and
- rejection of all 23 stripping, duplication, reordering, algorithm, version,
  suite, publisher, item, ciphertext, signature, AAD, key, critical-header,
  unprotected-header, recipient, missing-ciphertext, nonce, and duplicate-map
  negative cases.

The visible result is
archived `summary.json`
and the exact hashes and commands are in
archived `execution.md`.
The exact source, binary, summary, and raw-log hashes are registered by
BVB-725.

## Requirement credit

| Requirement outcome | Result | Credit boundary |
|---|---|---|
| Source encryption and consumer authentication (`SEC-H03`) | **Mechanism feasibility passes.** Known plaintext was encrypted; consumer authenticated both source signatures and the AEAD before obtaining plaintext. | One local fixture, not carrier or independent-interoperability evidence. |
| Authenticated publisher (`SEC-H04`) | **Mechanism feasibility passes.** Publisher, item, version, suite, ciphertext, and both key identifiers are in the protected commitment. | Identity enrollment, credential lifecycle, and authority policy remain open. |
| Relay payload blindness (`SEC-H05`) | **API seam passes.** Public verification receives public keys and no content key. | No relay process/storage/capture or hostile-carrier run occurred here. |
| Mandatory hybrid signatures (`SEC-H20`) | **Encoding and fail-closed validation pass.** Missing, duplicate, swapped, rewritten, tampered, or wrong-key components reject. | The fixed validation rule is experiment scaffolding, not yet a published hybrid profile or independent implementation. |
| NIST algorithms (`SEC-H18`, `SEC-H21`) | AES-256-GCM, P-256 ECDSA, and ML-DSA-65 are named provider operations. | Operation approval provenance is separate; this does not cover hybrid KEM. |
| Downgrade prevention (`SEC-H23`) | Version, suite, algorithm, critical-field, publisher, item, and external-AAD rewrites reject in this fixed profile. | No offer/selection protocol, minimum-policy store, mixed-version behavior, or rollback test. |
| Metadata privacy (`SEC-H06`, `SEC-H07`) | **No credit.** | This is the inner source object. Topic/scope/priority/routing protection needs a separately keyed outer member-readable envelope. |
| Revocation, rekey, replay, zeroization | **No credit.** | `coset` is stateless. These are membership, durable acceptance-state, and provider/storage responsibilities. |
| Hybrid key establishment (`SEC-H19`) | **No credit.** | The direct recipient and random content key are test scaffolding; no ML-KEM or recipient-key distribution ran. |
| FIPS/CMVP (`SEC-SD02`) | **No credit.** | The exact build is explicitly `non-fips`; BVB-713 qualifies only the package license. |

## Measured curve, not a gate

One run produced a 3,785-byte protected object for a 55-byte plaintext. The
inner ciphertext including its AEAD tag was 71 bytes; the P-256 signature was
64 bytes and ML-DSA-65 signature 3,309 bytes. These are reproducibility facts,
not performance samples or hard size limits. The requirements allow PQ cost to
be amortized if every item retains an unambiguous authenticated commitment, so
batching remains an explicit later corpus rather than an elimination reason.

## Exact custom delta

The composition still needs a small but security-critical normative profile:

1. freeze signing/encryption order, exact protected fields, canonical tagged
   bytes, external-AAD derivation, and fixed algorithm/key-slot validation;
2. replace the direct fixture with a registered hybrid establishment or group
   key distribution mechanism and authenticated key confirmation;
3. define publisher credentials, membership epochs, partitioned removal/rekey,
   replay/rollback persistence, no-clock ordering, and zeroization boundaries;
4. add the outer member-readable metadata envelope and bridge rewrap policy;
5. bound object, header, signature, recipient, and nesting sizes before parse or
   persistent effect; and
6. publish vectors and pass an independent implementation.

That delta is substantially smaller than inventing COSE object syntax and
encoding from scratch, but it is not optional application glue.

## Next decisive composition

Carry the exact opaque serialized object through the leading p2panda-native
temporal arm: A creates, B verifies publicly and persists without a content
key, B fully restarts, and C verifies/decrypts while A is absent. Inspect B's
API-visible state, durable store, logs, and carrier capture. Keep the already
frozen classical p2panda fixture as an independent baseline; introduce this
COSE object only in a separately registered composition. In parallel, compare
OpenMLS only for membership/epoch evolution—not as a substitute for the source
object or outer metadata layer.
