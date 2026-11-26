# Decision 0001: Standards profiles and provider boundaries

- Status: accepted for reference implementation
- Date: 2026-08-18

## Decision

The wire authority is a project-owned RFC 8949 core deterministic CBOR profile,
not a Rust type layout or serializer default. Cryptography, persistence, and
transport are provider boundaries. The conformance provider uses only the NIST
algorithms selected in the protocol; replacing it with a validated provider does
not change item or synchronization semantics.

The initial suite is a complete, non-mixable selection: SHA-256, HKDF-SHA-256,
AES-256-GCM, P-256 ECDH, ML-KEM-768, ECDSA P-256/SHA-256, and ML-DSA-65. Hybrid
authentication requires both signatures to verify. Negotiation offers and the
selected complete suite are signed and included in the KDF transcript. A suite
is never assembled algorithm-by-algorithm on the wire.

The hybrid key combiner remains a security-review gate. SP 800-227 requirements
for validation, context binding, key confirmation, and implicit-rejection-safe
failure handling apply. A revision to an adopted external hybrid construction
receives a new suite identifier.

## Consequences

- Byte-for-byte encoding vectors are mandatory.
- Unknown optional extension keys can be ignored; unknown critical keys fail.
- RustCrypto crates are interoperability tools, not production authorization.
- Secret-bearing types use zeroization where feasible; copies and OS/runtime
  behavior are documented limitations.
