# Decision 0026: Scope lock-only Hickory advisories

- Status: accepted with fail-closed scope gates
- Date: 2026-08-23
- Supersedes: only the raw-lock no-waiver disposition for the focused,
  mDNS-disabled libp2p profile in Proposal 0003
- Related: [Decision 0002](0002-dependency-admission.md) and
  [CI policy](../validation/ci.md)

## Context

The workspace exact-pins the `libp2p` 0.56.0 aggregate crate with default
features disabled. Its selected feature list excludes both `dns` and `mdns`;
Aster-owned provisioned discovery remains the only automatic-discovery source
for this provider profile.

Cargo nevertheless records the aggregate crate's disabled optional dependency
closure in `Cargo.lock`. That closure includes `hickory-proto` and
`hickory-resolver` 0.25.2. Raw-lock scanners therefore report two findings even
though neither package is in the resolved executable graph:

- [RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)
  affects DNSSEC NSEC3 validation. Aster does not enable a Hickory package or a
  DNSSEC feature.
- [RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html)
  affects Hickory message encoding. Aster does not compile or execute the
  package.

The affected lock entries cannot be updated directly to Hickory 0.26.1 because
the optional libp2p 0.56 DNS/mDNS components require the 0.25 line. Replacing
the aggregate crate with component crates or adopting a later compatible
libp2p release remains a separately reviewed dependency change.

## Decision

Permit the raw-lock root `cargo audit` invocation to ignore exactly
`RUSTSEC-2026-0118` and `RUSTSEC-2026-0119` only while a fail-closed scope gate
proves all of the following:

1. the only matching lock entries are `hickory-proto` 0.25.2 and
   `hickory-resolver` 0.25.2;
2. neither package appears in the workspace dependency graph with every Aster
   workspace feature, dependency edge, and target enabled; and
3. neither package appears in the independent fuzz dependency graph.

The gate runs before the root audit invocation and again in the offline policy
phase. A regression wrapper injects an active Hickory package and requires the
gate to reject it. CI also retains a current RustSec refresh, so every other
advisory remains unsuppressed. The feature-aware `cargo deny` graph does not
contain these inactive packages and therefore carries neither Hickory ID in
`deny.toml`; listing them there would be an unnecessary
`advisory-not-detected` exception.

## Consequences

- This decision does not admit libp2p DNS, mDNS, Hickory, or DNSSEC and grants
  no runtime or production-security claim for them.
- Enabling a feature that reaches either Hickory package fails the scope gate
  before the scanner ignore is applied.
- Changing either lock version or adding another Hickory version fails the
  exact package-set assertion and requires a new review.
- The independent fuzz lock remains fully audited without these two ignores.
- The exceptions must be deleted when the aggregate lock no longer includes
  the affected disabled optional dependencies.
- `RUSTSEC-2026-0173` remains a separate, age-pilot-only informational
  exception governed by Decision 0018.
- Active libp2p-pilot dependency policy is governed separately by
  [Decision 0027](0027-libp2p-pilot-dependency-policy.md).
