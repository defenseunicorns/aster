# Decision 0005: Own narrow, purpose-specific deterministic codec profiles

- Status: accepted
- Date: 2026-08-18

`minicbor` 2.3.0 was evaluated. Its BlueOak-1.0.0 license is OSI approved, but the
audited public material did not establish the required vulnerability-reporting
channel and its default behavior is not proof of this protocol's deterministic
profile.

The core therefore implements only the small RFC 8949 subset used by the sync
CDDL: unsigned/signed integers, definite byte/text, arrays, and maps. It rejects
all indefinite, floating, tagged, duplicate, nonminimal, deep, and oversized
input. Golden and negative vectors are the authority.

Security objects are not modeled as an open CBOR vocabulary. Credentials,
source envelopes, handshake flights, custody wrappers, controls, and Blob
manifests use their own fixed, length-prefixed deterministic binary profile.
That profile admits only the fields and bounds specified in `envelope.md` and
rejects trailing bytes and nonzero reserved values. Separating these profiles
matches their different evolution and parsing needs; a value from one profile
is never accepted in the other.

Neither codec is a cryptographic primitive. The buy-over-build exception is
limited to these frozen protocol profiles; reconsidering an admitted codec
cannot alter wire bytes.
