#

# Decision 0043: Authorize bounded Linux Event MVP validation

- Status: Accepted
- Accepted: 2026-09-15
- Scope: team-internal, non-production Linux Event MVP validation
- Evidence: [CM4 CI-package validation record](../validation/evidence/2026-09-15-cm4-ci-package-mvp-validation.md)

## Decision

All approvals required to continue the bounded Linux Event MVP validation are
team-internal and accepted. No additional stakeholder or external approval is
required for this MVP validation increment.

The v0.1 annex boundary and the two-node CM4 inventory are frozen for this
increment. Run-specific configuration and observed results belong in the
evidence record; they do not reopen the approved inventory or require another
approval.

Validation uses the actual `arm64` Debian package produced by CI. Direct
functional observations from that installed package are sufficient evidence
for this engineering increment; a separate device-validation harness or
synthetic receipt framework is not required.

The package name `aster` is accepted for the MVP. Renaming it is a post-MVP
improvement.

## Deferred beyond this increment

The following work is explicitly post-MVP or a later validation increment:

- a 24-hour soak and a true network-partition exercise;
- package/archive signing and independent reproducibility replay;
- package renaming;
- independent implementation, external review, FIPS, and production
  authorization; and
- additional validation automation beyond focused CI and direct device checks.

Deferral does not convert an unrun check into a pass. The evidence record must
distinguish completed observations, failed checks, unavailable checks, and
acceptance criteria that were not fully measured.

## Claim boundary

This decision authorizes and simplifies internal MVP validation. It does not
authorize production use, broaden the supported platform, change atomic
requirement status, or claim that every technical scenario has passed.
