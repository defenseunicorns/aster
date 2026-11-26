# Decision 0005: Own narrow, purpose-specific deterministic codec profiles

- Status: historical for the removed CBOR codec; fixed security objects retained
- Date: 2026-08-18

`minicbor` 2.3.0 was evaluated. Its BlueOak-1.0.0 license is OSI approved, but the
audited public material did not establish the required vulnerability-reporting
channel and its default behavior is not proof of this protocol's deterministic
profile.

The core originally implemented the small RFC 8949 subset used by the sync
CDDL: unsigned/signed integers, definite byte/text, arrays, and maps. That unused
codec, its CDDL, and its vectors have been removed. Runtime replication uses a
separate binary frame encoding; removing the CBOR codec does not change it.

Security objects are not modeled as an open CBOR vocabulary. Credentials,
source envelopes, handshake flights, custody wrappers, controls, and Blob
manifests use their own fixed, length-prefixed deterministic binary profile.
That profile admits only the fields and bounds specified in `envelope.md` and
rejects trailing bytes and nonzero reserved values. Separating these profiles
matches their different evolution and parsing needs; a value from one profile
is never accepted in the other.

These codecs are not cryptographic primitives. The original buy-over-build
exception was limited to these frozen protocol profiles; reconsidering an
admitted codec cannot alter wire bytes.
