#

# Proposed DM-8-05 disposition for Linux Event MVP Evaluation Profile v0.1

- Requirement: `DM-8-05`
- Profile: [`aster-linux-event-mvp-evaluation-v0.1`](linux-event-mvp-evaluation-profile-v0.1.md)
- Status: proposed for exact-candidate approval; this document records no specialist approval
- Evaluation effect: blocking until dependency, legal, and release owners approve
- Production effect: remains blocking after evaluation approval
- General allowlist effect: none

| Package | Version | crates.io archive SHA-256 | License |
|---|---:|---|---|
| `webpki-root-certs` | `1.0.9` | `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` | `CDLA-Permissive-2.0` |
| `webpki-roots` | `1.0.9` | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | `CDLA-Permissive-2.0` |

## Disposition limits

- only these tuples and only non-production v0.1 evaluation;
- no general license allowlist;
- no WebPKI trust or public/default relay authorization;
- mandatory SBOM and third-party-notice presence;
- fail closed on package, version, source, checksum, reachability, graph, or
  license drift;
- dependency, legal, and release owners separately record identity, role,
  decision, date, exact coordinates/checksums/licenses, and the reviewed
  disposition digest; the later candidate annex separately binds the artifact
  dependency graph;
- evaluation approval does not close the formal production requirement;
- missing record, drift, missing notice/SBOM, public trust/relay use, or a
  production claim refuses the exception;
- no requirements or evidence status changes.

This docs lane owns the exact proposal text only. It does not insert
signatures, claim legal approval, edit dependency policy, regenerate notices,
or speak for the artifact or release lanes.
