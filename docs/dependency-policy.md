# Dependency policy

## Admission

Review total assurance cost, not dependency count: security-sensitive code
replaced, public format/API stability, maintenance, adoption, vulnerability
handling, independent review and interoperability, enabled features and transitive
code, target support, operational recovery, and replacement cost. Adoption alone
does not approve a package or its enabled surface.

Production-security claims require a verified private vulnerability-reporting
channel. A missing `SECURITY.md` alone need not block a time-boxed non-production
pilot, provided its review records:

- An isolated, replaceable boundary that cannot become the operational default
  without approval.
- Exact package, version, registry checksum, source, license, features,
  advisories, and locked dependency graph; disable unused execution-capable and
  ambient-discovery features.
- A published behavior contract and a separately maintained implementation for
  claimed interoperability.
- Automated advisory/license checks, a review point, removal or patch/fork path,
  and prohibited production claims.

A reporting channel for another implementation of the same format does not
satisfy the selected library's gate. Implementation approval and passing CI do
not establish production admission, supported targets, or release authorization.

## Licenses and exact-package exceptions

[deny.toml](../deny.toml) defines the external license allowlist, exact-package
exceptions, advisory dispositions, and registry/source restrictions. Manifests
and lockfiles define package pins; do not infer admission for another version
from this page. External dependency permissions do not change the Apache-2.0
rule for first-party packages and distributed project files.

The stakeholder's 2026-08-25 license disposition permits Mozilla trust-root data
under `CDLA-Permissive-2.0` as an explicit deviation from the frozen baseline's
OSI-approved-only rule. It makes no outside-counsel claim. `Unlicense` is
OSI-approved, but its browser-WASM dependency exceptions also remain
package-and-version scoped rather than general permission. See the exact
coordinates in `deny.toml` and checksums and license texts in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), which distribution packaging
must include. Package, version, or license drift requires a new review.

The 2026-10-20 trust-root maintenance review moved the existing data-package
exceptions to replacement coordinates without broadening permission. It did not
extend the 2026-09-08 Linux Event evaluation approval to those replacements.
Neither disposition grants browser-WASM support, hosted-relay authorization,
physical or interoperability acceptance, or production compliance with `DM-8-05`.
The [license-policy follow-up](https://github.com/defenseunicorns/aster/issues/202)
remains separate from these implementation permissions.

## Age provisioning pilot

`aster-provisioning-age` is an isolated, disabled-by-default Rust pilot for binary
age-v1 classic-X25519 artifacts. It replaces a custom encrypted-file construction;
it is not persistent key custody, a production default, a PQ profile, or a
FIPS-validated path. The [security boundary](security.md#provisioning-artifact-and-persistent-key-custody)
defines recipient/stanza bounds, authenticated EOF, fail-closed behavior, the
unknown-stanza residual, and Aster-owned-only memory clearing.

The admitted maintenance line limits the cryptographic surface to the pilot's
classical needs. A newer series is not automatically admitted. Keep default
features disabled and do not enable plugin, SSH, armor, asynchronous, CLI-common,
or unstable features. The direct `age-core` dependency uses the documented
custom-identity extension point to bound stanza work before unwrap; it adds no
separate format. Bidirectional reference-Go interoperability covers only the
outer artifact, not Aster mesh interoperability or custody.

The age-specific advisory exceptions in [deny.toml](../deny.toml) cover
unmaintained build-time localization dependencies, not reported vulnerabilities
or production approval. The scope check binds their exact versions, registry
sources, checksums, and complete reverse graphs, including inspection of the
separate fuzz lock. Offline validation does not remove build-time supply-chain
exposure, and the proc-macro future-incompatibility finding remains a blocker.
A compatible published upstream migration, maintained narrow patch, replacement,
or removal must eliminate both pilot exceptions before production-readiness
review. An unreleased moving upstream revision is not an acceptable substitute
for the checksum-locked package.

Pilot admission expires at the first production-readiness review or any change
to the exact `age`/`age-core` pins, features, or age advisory dispositions.
Continuation requires a recorded review. Production also requires a verified
reporting route or approved maintained fork, independent integration review,
recipient issuance and recovery, protected-by-default application paths,
persistent platform/hardware custody, review of upstream plaintext/key
intermediates, deployment memory and backup controls, and the applicable
cryptographic/FIPS approval. If those gates cannot be met, remove or replace the
provider without changing the canonical bundle or application boundary.

## Provenance

These retained rules derive from [dependency admission (2026-08-18)](https://github.com/defenseunicorns/aster/blob/a4c934b09b3e190f9bbdadaed1130e4cc18a6a2e/docs/decisions/0002-dependency-admission.md),
[external license permissions (2026-08-23)](https://github.com/defenseunicorns/aster/blob/a4c934b09b3e190f9bbdadaed1130e4cc18a6a2e/docs/decisions/0027-libp2p-pilot-dependency-policy.md),
[exact-package license dispositions (2026-08-25; amended 2026-10-20)](https://github.com/defenseunicorns/aster/blob/a4c934b09b3e190f9bbdadaed1130e4cc18a6a2e/docs/decisions/0028-selected-stack-implementation-boundary.md),
and [age pilot admission (2026-08-21; amended 2026-10-20)](https://github.com/defenseunicorns/aster/blob/a4c934b09b3e190f9bbdadaed1130e4cc18a6a2e/docs/decisions/0018-age-provisioning-provider.md).
Historical package inventories and retired exceptions do not override the
current manifests, lockfiles, or `deny.toml`.
