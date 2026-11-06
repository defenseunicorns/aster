# Decision 0002: Dependency admission and rejections

- Status: accepted with recorded gates
- Date: 2026-08-18

## Admission rule

Dependencies are evaluated by total assurance cost rather than by dependency
count. The review includes the custom security-sensitive code displaced, public
format or API stability, maintenance and adoption, vulnerability handling,
independent review and interoperability, exact feature and transitive surface,
target support, operational recovery, and the cost of replacing the component.
Wide adoption is useful evidence, but is neither an automatic approval nor a
substitute for reviewing the exact version and enabled surface.

A discoverable private vulnerability-reporting channel is required before a
dependency can support a production-security claim. A missing `SECURITY.md`
does not automatically prohibit a **time-boxed, non-production pilot** when all
of these conditions are recorded:

- the experiment is isolated behind a replaceable boundary and cannot silently
  become the default operational path;
- package, version, registry checksum, features, license, source, known
  advisories, and the complete locked dependency graph are reviewed;
- unused execution-capable or ambient-discovery features are disabled;
- a published behavior contract is identified and, where interoperability is
  claimed, a separately maintained implementation can check it;
- automated advisory and license checks cover the admitted graph; and
- the decision records a removal or patch/fork path, an explicit review point,
  and the production claims that remain prohibited.

If neither a formal policy nor an equivalent verified reporting channel can be
found, that remains a production blocker. The limited pilot exception does not
transfer a security process from a different implementation of the same format
to the selected library.

## Adopted

- RustCrypto `aes-gcm`, `hkdf`, `sha2`, `p256`, `ml-kem`, `ml-dsa`, and
  `zeroize`, exactly pinned, for the non-validated conformance provider.
- `getrandom`, exactly pinned with only its OS `sys_rng` feature, to bridge the
  operating system random source into the private provider.
- `rusqlite`, exactly pinned with only bundled SQLite, behind `RecordStore`.
  The Rust wrapper is MIT. SQLite 3.53.2 is public-domain software rather than
  code under an OSI-approved license; because the binding requirement literally
  says dependencies use OSI-approved licenses only, legal/release review must
  confirm that license-free public-domain software satisfies that policy. It is
  not treated as a silently approved exception.

The IP adapter directly reuses the already admitted `getrandom`, `hkdf`, and
`sha2` packages for unlinkable authenticated local-discovery proofs. All other
adapter and binding code uses the standard library and `aster-core`; this adds
no component or version beyond the admitted workspace graph.

The BTLE Ring 2 increment path-patches exact `hmac` 0.13.0 to zeroize its
constructor derived-key temporary. Because Cargo patching is workspace-wide,
the qualification covers every exact 0.13.0 consumer rather than treating the
change as discovery-local. [Decision 0046](0046-btle-ring2-vendored-dependency-patches.md)
records the source pedigree, affected graph, tests, maintenance owner, and
removal gate. This does not admit a custom MAC or change protocol bytes.

## Adopted for a bounded pilot only

- `jni` 0.22.4 is an exact direct dependency only of the isolated Android
  Ring-1 validator library. The same package and version already exists in the
  selected locked graph; the direct edge adds no package or transitive code.
  It is confined to copying bounded configuration into Rust, transferring one
  process-local descriptor, and delivering sanitized callbacks around the
  existing transport-neutral node. This grants no production, general binding,
  background Android, discovery, packaging, or supported-platform claim. The
  dependency and JNI surface remain removable with the evaluation app.

- `bluer` 0.17.4 is admitted only for the Linux `BleL2capV1` Ring 1
  evaluation driver, exact-pinned with the `l2cap` feature and the minimum
  `bluetoothd` surface needed for a generic connectable advertisement. BlueR is
  the official BlueZ Rust binding, declares BSD-2-Clause, publishes an upstream
  security policy, and exposes Tokio-style LE L2CAP client/listener streams.
  The common carrier remains in a dependency-light platform-neutral crate, so
  this Linux binding owns no mission, protocol, store, or durable-progress
  authority. This admission grants no production, cross-platform, discovery,
  GATT, dynamic-role, or support-row claim. Exact locked graph, license,
  advisory, cross-build, cancellation, resource, and physical CM4 evidence are
  exit gates; failure closes or removes the replaceable Linux driver.
  Ring 2 retains that claim limit while adding a minimal, exact-source fork for
  acknowledged advertisement/discovery ownership and bounded D-Bus ingress.
  [Decision 0046](0046-btle-ring2-vendored-dependency-patches.md) owns the patch
  pedigree and removal gate; it does not by itself promote BlueR or BTLE to a
  production-supported transport.

- Proposal 0004 is closed with no provider selected. Its focused
  `aster-libp2p-provider` graph remains only as publish-disabled, opt-in test
  evidence, not a selected carrier or continuing experiment.
  [Decision 0027](0027-libp2p-pilot-dependency-policy.md) records its exact
  active `paste` 1.0.15 path, dated removal/review gate, fuzz exclusion, and the
  reviewed `BSD-2-Clause`, `ISC`, and `Zlib` external dependency license
  expressions. [Decision 0029](0029-close-proposal-0004-libp2p-pilot.md) closes
  the selection lane. The exception expires before any default, release,
  deployment, or production use and grants no provider-selection or
  production-security claim.
- Rust `age` 0.11.5, exactly pinned with `default-features = false`, is admitted
  only in the isolated `aster-provisioning-age` crate for the classic X25519
  age-v1 provisioning-artifact profile. Its exact crates.io archive checksum is
  recorded in [Decision 0018](0018-age-provisioning-provider.md); upstream
  declares `MIT OR Apache-2.0`. The plugin, SSH, armor, asynchronous, CLI-common,
  and unstable features are not enabled. This is not admission for a production
  default, persistent key custody, a post-quantum profile, or a FIPS-validated
  path. Decision 0018 records the full exception and exit gates.
- `age-core` 0.11.0, already required transitively by `age`, is also an exact
  direct dependency of that isolated crate. It is used only through age's
  documented custom-identity extension point to require 1–16 X25519 stanzas,
  reject scrypt and more than one extension stanza, and bound work before
  identity unwrap. One unknown stanza remains necessary for age's mandatory
  GREASE behavior. Direct use adds no lockfile package and does not admit a
  separate file format.
- This pilot carries one exact dependency-policy exception:
  `RUSTSEC-2026-0173` for transitive build-time `proc-macro-error2` 2.0.1 via
  `age` 0.11.5 → `i18n-embed-fl` 0.9.4. RustSec classifies the advisory as
  informational/unmaintained, reports no vulnerability and no patched release,
  and current Rust also emits future-incompatibility diagnostic `E0365`. The
  exception applies only to this non-production pilot; exact registry checksums,
  locked/offline builds, and every other dependency-policy rule remain enforced.
  It expires with the pilot and is itself a production blocker.
- Memory-clearing claims stop at Aster-owned containers and provider buffers.
  Rust `age` 0.11.5 does not comprehensively clear its internal plaintext
  encryption buffer or all X25519 identity-decoding intermediates; complete
  process-memory erasure is not an admitted pilot property.
- The test-only Go interoperability oracle exact-pins `filippo.io/age` 1.3.1
  and runs on Go 1.26.7. Its canonical non-CGO Linux/amd64 compiled external
  graph is limited to `filippo.io/age`, `filippo.io/hpke`,
  `golang.org/x/crypto`, and
  `golang.org/x/sys`; a committed coordinate/SPDX/path/SHA-256 receipt fails
  closed on graph or license-file changes. Exact `govulncheck` 1.6.0 fails on
  reachable vulnerabilities while leaving imported-but-unreachable findings
  visible as upstream informational output. This admits only test tooling, not
  a production runtime dependency.

## Evaluated but not adopted

- `redb` 4.2.0 was considered as a pure-Rust ACID store. It was not adopted
  because the reference's multi-index transactional/query workload mapped more
  directly to SQLite; replacing SQLite remains possible behind `RecordStore`.
- Tokio 1.51.4 LTS was considered for adapter scheduling. The MVP adapters use
  nonblocking standard-library I/O and require no runtime dependency.
- `minicbor` 2.3.0 was considered. BlueOak-1.0.0 is OSI-approved, but the narrow
  deterministic decoder needed strict non-minimal, ordering, duplicate, depth,
  and critical-extension behavior. The protocol-owned bounded subset is used
  and tested byte-for-byte instead.
- Rust `age` 0.12.1 was reevaluated but not admitted. The attempted workspace
  lock selected an `ml-kem`/`kem` combination that failed to compile alongside
  Aster's current cryptographic graph. The result applies only to that attempted
  lock state; a coordinated dependency update could yield a compatible graph
  and would require a separate assurance review. Those changes were outside
  this bounded pilot. More importantly, 0.12.1 makes ML-KEM, P-256/HPKE, and
  later recipient profiles non-optional even though this provider admits only
  classic X25519.
  Patched 0.11.5 is the current 0.11-line maintenance release and has the
  smaller classical surface that matches the pilot. This is a scoped
  assurance/surface decision, not a security finding or a claim that 0.11.5 is
  the latest Rust `age` series.

## Rejected

Iroh 1.0.3 was evaluated because it is explicitly permitted as a public example
in the requirements. It is not admitted: the evaluated project surface had no
discoverable vulnerability-reporting policy or equivalent verified channel,
its default presets use hosted discovery/relay services, and there was no
bounded transport pilot whose benefit justified that combined assurance cost.
Reconsideration requires a locally controlled configuration and either
security-process evidence or a separately recorded, time-boxed pilot exception
that satisfies the rule above.

No dependency owns data semantics, causality, key hierarchy, or synchronization
correctness. All versions and transitive sources are locked and audited subject
only to the explicit active pilot exceptions above and the disabled, lock-only
scanner disposition in
[Decision 0026](0026-lock-only-hickory-advisories.md).

## Historical clarification — 2026-08-25

The present-tense Iroh rejection above records the 2026-08-18 dependency state
and remains unchanged as historical rationale. It is no longer a statement that
no bounded implementation exists. [Decision 0028](0028-selected-stack-implementation-boundary.md)
subsequently authorized Iroh 1.0.3 for active selected-stack implementation,
and signed code commit `b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`
adds one explicitly controlled Iroh relay route with exact TLS trust, no hosted
lookup, no public/default relay substitution, no insecure trust mode, and no
port mapping.

That implementation authority is not dependency or release admission. The
missing security-process disposition; exact enabled-graph and license
treatment, including `CDLA-Permissive-2.0` and `Unlicense`; SBOM;
supported-target evidence; support owner; advisory disposition;
independent interoperability, physical acceptance, and release authorization
remain open. Current software tests therefore cannot be cited as a
production-security or production-relay approval.

The normal `aster-node` graph already reaches Iroh's client-side `iroh-relay`
dependency but enables neither `iroh-relay/server` nor its `test-utils`
feature. The optional `aster-iroh/test-utils` feature is dev/all-feature test
surface: it enables the self-hosted relay fixture, the server/test feature
graph, and associated server/ACME packages. The new direct `rustls` 0.23.43
edge reuses an already locked package/version. Those distinctions keep server
code out of the normal node graph; they do not waive review of the expanded
test/lock graph or admit any dependency for a shipped relay server.

### Go acceptance journal filesystem wrappers

The test-only `conformance/agent-go` module exact-pins
[`golang.org/x/sys` v0.46.0](https://cs.opensource.google/go/x/sys/+/refs/tags/v0.46.0:).
Its BSD-3-Clause-licensed `unix` package supplies descriptor-relative
`Openat`, `Renameat`, and `Unlinkat` wrappers on Linux and macOS, where Go's
frozen `syscall` package does not expose the same API set. The journal retains
no-follow traversal, exclusive creation, descriptor-bound replacement, and
parent synchronization. This dependency is outside the Rust product graph;
platform/filesystem qualification and requirements evidence remain unchanged.
