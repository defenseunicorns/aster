# Compatibility and Deprecation Policy

- Policy version: 1
- Applies beginning with protocol 1.0

Protocol 1.x additions are limited to optional fields/messages, new registry
values whose absence has defined behavior, and new complete cryptographic suites.
A 1.x reader must continue accepting every valid, policy-permitted 1.0 object.
Semantic changes require a new major version.

The project will support the latest two minor releases of an active major and no
less than 24 months from each minor release, whichever is longer. A published
major remains readable for at least five years after its successor is released;
adopting programs should retain the conformance corpus and source-envelope
reader for the lifetime of mission data they must recover.

A deprecation announcement includes:

- affected protocol, suite, ABI, binding, or registry values;
- security/operational reason and threat consequence;
- first release that warns, earliest release that may stop producing it, and
  earliest release that may stop consuming it;
- migration and rollback-safe stored-data procedure;
- updated conformance vectors and mixed-version evidence.

Unknown optional extensions remain ignorable throughout a major version.
Unknown critical values fail only the containing object/session and never cause
silent reinterpretation. Stable replication-wire, credential/envelope, crypto-
profile, and handshake-framing encodings remain version `1`. The current
hybrid handshake negotiates semantic version `9` and complete suite `0x0001`.
Its default offer is `[9]`; older semantic versions are rejected in both
handshake roles, including adapter capability-ceiling entry points. Offer and
selection are transcript, KDF, confirmation, and hybrid-authentication bound.
The separate classical security profile has its own semantic policy.

Semantic v9 uses the authenticated per-lane transfer-profile exchange. Event
uses `EventPagesV1`, Blob uses `BlobStreamV1` (profile 5), and State, Record,
and EventBridge retain `LegacyV6`. An incompatible offer fails negotiation;
there is no Event fallback in the v9 offer. Stable wire/profile, handshake
framing, suite, and source-object formats are not renumbered by this policy.
Protocol draft.4 and fixed-security-object draft.3 record this incompatible draft change. Historical vector IDs
retain their original bytes; regenerated protected profile-5 fixtures use v2 IDs.
Unsupported stores fail without mutation, migration, or automatic reset.
Historical qualification receipts remain evidence only for their recorded
semantic version and executable; they do not qualify the v9 implementation.

Cryptographic emergency response may prohibit producing or accepting a broken
suite sooner than the ordinary window. Such a change requires a signed mission
policy/control update, an advisory, explicit loss-of-connectivity impact, and a
replacement suite; it must never introduce a silent classical-only fallback.

The C ABI is versioned independently. Existing functions and structure prefixes
remain source/binary compatible within ABI major 1; callers set both ABI version
and structure size. Removing a binding method requires the same announcement
window and cannot remove the underlying protocol capability.

Draft 0.x artifacts may change incompatibly. Every such change increments the
draft/specification identifier, replaces rather than mutates vector IDs, and is
recorded in release notes and the compatibility matrix.
