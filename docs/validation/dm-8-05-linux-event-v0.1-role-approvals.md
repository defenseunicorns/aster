#

# Internal role approvals of the Linux Event v0.1 DM-8-05 disposition

- Recorded: 2026-09-08
- Decision scope: P0-1 Linux Event MVP Evaluation Profile v0.1
- Register row: `P0-1-D15`
- Disposition: [`dm-8-05-linux-event-v0.1-disposition.md`](dm-8-05-linux-event-v0.1-disposition.md)
- Disposition SHA-256: `a6fe15f39fb553f87bc1224fe7f266e7c906d451d8140402d3bc1620011bfa53`
- Candidate release authorization: not granted
- Production authorization: not granted

The project owner reported the following internal decisions against the exact
disposition and dependency tuples. The underlying approver identities and
communications are retained internally rather than published in this
repository.

| Required role | Decision | Recorded rationale |
|---|---|---|
| Dependency/license owner | **Approved** | The bounded treatment is correct and the two exact packages are already explicitly exempted in repository dependency policy. |
| Legal/compliance owner | **Approved** | The exact evaluation-only exemption is accepted without creating a general allowlist or production conclusion. |
| Release owner | **Approved** | The exemption is bound to this profile and exact tuples; drift fails closed and production `DM-8-05` remains blocking. |

These three role decisions resolve `P0-1-D15` and permit adoption of the Linux
Event MVP Evaluation Profile v0.1. For public repository traceability, this
file is the consolidated record of the three separately reported internal role
outcomes. A candidate annex must bind the committed version and digest of this
record; it does not replace the final candidate approvals or G6 disposition.

The approvals apply only to these exact tuples:

| Package | Version | crates.io archive SHA-256 | License |
|---|---:|---|---|
| `webpki-root-certs` | `1.0.9` | `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` | `CDLA-Permissive-2.0` |
| `webpki-roots` | `1.0.9` | `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a` | `CDLA-Permissive-2.0` |

These approvals do not:

- create a general license allowlist;
- authorize another package, version, source, checksum, license, or profile;
- authorize WebPKI trust or public/default relay use;
- close production requirement `DM-8-05`; or
- assert that any implementation, artifact, or candidate conforms to the
  profile.

Any drift in the exact tuples, selected-target reachability, SBOM, notices, or
candidate dependency graph invalidates the bounded approval and reopens D15
for the affected profile or candidate.
