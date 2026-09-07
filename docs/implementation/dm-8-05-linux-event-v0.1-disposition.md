#

# Proposed DM-8-05 disposition for Linux Event MVP Evaluation Profile v0.1

- Requirement: `DM-8-05`
- Profile: [`aster-linux-event-mvp-evaluation-v0.1`](linux-event-mvp-evaluation-profile-v0.1.md)
- Status: proposed for pre-candidate profile approval; this document records no specialist approval
- Evaluation effect: blocking until dependency, legal, and release owners approve
- Production effect: remains blocking after evaluation approval
- General allowlist effect: none

| Package | Version | crates.io archive SHA-256 | License |
|---|---:|---|---|
| `webpki-root-certs` | `1.0.9` | `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` | `CDLA-Permissive-2.0` |
| `webpki-roots` | `1.0.9` | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | `CDLA-Permissive-2.0` |

## Proposed resolution

Resolve `P0-1-D15` only for the bounded, non-production Linux Event v0.1
evaluation after Dependency, Legal, and Release each approve the two exact
tuples above and this complete disposition. Approval permits those exact
archives to remain in the evaluation artifact dependency graph under their
recorded license; it does not reinterpret `DM-8-05`, declare general
requirements compliance, or authorize another package, version, source,
checksum, license, profile, or production release.

The current repository facts supporting review are:

- `Cargo.lock` contains both exact registry coordinates and checksums;
- `deny.toml` contains name-and-exact-version exceptions for only these two
  `CDLA-Permissive-2.0` packages;
- `THIRD_PARTY_NOTICES.md` records both exact tuples and the applicable notice;
- Decision 0028 records their selected-stack reachability; and
- the evaluation profile disables WebPKI trust and public/default relay use.

These are review inputs, not approval records or a legal conclusion. No
dependency, lockfile, policy, notice, requirement status, or evidence mapping
changes as part of this proposal.

## Requested role approvals

All three decisions are independently required. Missing, conditional,
ambiguous, or refusing input leaves D15 Open.

| Role | Required review and decision | Current status |
|---|---|---|
| Dependency/license owner | Confirm the exact packages, versions, registry sources, archive checksums, selected-target reachability, license identifiers, SBOM presence, and notice coverage; approve or refuse this exact evaluation-only disposition | **Pending** |
| Legal/compliance owner | Review `CDLA-Permissive-2.0` for distribution of only the two exact tuples within the named non-production evaluation; confirm that no general allowlist or production conclusion is granted; approve or refuse | **Pending** |
| Release owner | Confirm the exception is bound to the exact profile and later candidate graph, that drift fails closed, and that production `DM-8-05` remains blocking; approve or refuse | **Pending** |

Each role publishes a separate immutable approval record containing:

1. reviewer identity and exact role;
2. `approve` or `refuse`;
3. RFC 3339 UTC decision time;
4. both package/version/registry-source/checksum/license tuples;
5. the SHA-256 digest of this complete disposition;
6. an explicit statement that approval is evaluation-only, creates no general
   allowlist, and leaves production `DM-8-05` open; and
7. the signed record reference and record digest.

The three records are pre-candidate P0-1 prerequisites. Every later candidate
annex includes their immutable references and digests but does not replace or
re-sign them as final candidate approvals.

## Decision outcomes

- If all three roles approve the same disposition digest and exact tuples,
  D15 may be marked `Resolved` with P0 blocker `no`; Decision 0042 still needs
  its explicit ratification authorization.
- If any role refuses, D15 remains Open and the profile remains Proposed until
  the dependency is removed/replaced or a revised disposition is reviewed.
- Any package, version, registry source, checksum, license, selected-target
  reachability, SBOM, notice, or candidate-graph drift invalidates the bounded
  approval and blocks the affected candidate.
- Evaluation approval never closes production `DM-8-05`; its production
  resolution or technical alternative remains separately owned.

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
