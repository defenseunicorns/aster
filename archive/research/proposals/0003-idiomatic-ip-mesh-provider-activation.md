# Proposal 0003 Phase 0: Idiomatic IP mesh provider activation


- Status: **completed — preliminary preflight retained below; signed freeze and
  final disposition appended**
- Date: 2026-08-21
- Parent proposal:
  [0003 — Idiomatic IP mesh provider comparison](0003-idiomatic-ip-mesh-provider-comparison.md)
- Observed worktree base:
  `56ea19d89e537a351ceded446c2d38f5313d118b`
- Observed branch: `codex/mesh-host-libp2p-spike`
- Observed worktree state: dirty experiment worktree; not a reproducible
  candidate receipt
- Workspace package MSRV: Rust `1.90`
- Experiment toolchain: Rust `1.97.1`
- Preliminary workspace `Cargo.toml` SHA-256:
  `61a81403fab3178c7090610d83fc50f4ae2f5e0f5d217480ee5a342907558ef4`
- Preliminary `crates/aster-lab/Cargo.toml` SHA-256:
  `0a9d0647b859f8bfad951db2534458f0767ddfdb32c39658aab48c1e60846207`
- Preliminary `Cargo.lock` SHA-256:
  `7c9a26a8915d5acec46508374a70258fa569533afe1b34c7e149d7f74294963e`
- Preliminary lock size: 589 package records

The hashes above identify the dirty worktree dependency split inspected in this
preflight. They are not the Phase-0 freeze required by Proposal 0003. The final
record must replace them with a signed clean candidate commit, exact target
trees, SBOMs, binary hashes, and container/network receipts.

## Activation outcome

No provider is admitted or selected by this record.

- **Native** may continue as the technical control. Its active profile passes
  the declared Rust 1.90 floor and its feature-specific advisory and license
  checks.
- **rust-libp2p with Aster protected discovery** may continue as the bounded
  requirements-oriented carrier lane. It does not compile libp2p mDNS or
  Hickory, but unmaintained `paste`, the current license allowlist, and the
  alpha `libp2p-stream` API still block production selection.
- **rust-libp2p with provider mDNS** may continue only as a clearly labeled
  technical characterization. It activates vulnerable `hickory-proto` 0.25.2
  and an upstream pre-host discovery cache without a hard entry limit, so it is
  not a requirements-eligible arm.
- **Iroh with Aster protected discovery** may continue only on the experiment's
  Rust 1.97.1 toolchain. It avoids the separate Iroh mDNS package, but Iroh's
  Rust 1.91 floor, unmaintained `paste`, the current license allowlist, and
  unfrozen owned-relay infrastructure block production selection.
- **Iroh with provider mDNS** may continue only as a clearly labeled technical
  characterization on Rust 1.97.1. The provider adds an uncapped pre-host peer
  address book, so this profile is not requirements-eligible even though it
  adds no new known advisory or rejected license class beyond core Iroh.

These are permissions to gather technical evidence, not waivers. A resource,
reliability, or mechanism-deletion result cannot compensate for an unresolved
Phase-0 or hostile-input gate.

## Raw lock versus active build

The workspace uses one lockfile. Cargo records optional dependency graphs in
that file even when a particular binary feature does not activate them.
Accordingly, this record uses two distinct terms:

- **raw lock** means all 589 package records scanned by the repository's normal
  lockfile command; and
- **active build graph** means normal and build edges reachable from
  `aster-lab` for one exact feature and target profile, excluding dev edges.

An inactive package is not a runtime reachability claim. It still matters when
the repository's mandatory policy scans the raw lock. Conversely, choosing
`aster-protected` at runtime inside an mDNS-enabled binary does not remove mDNS
from that binary's active build graph. Requirements-oriented runs must use the
base protected-discovery build, not merely disable provider mDNS at runtime.

All external dependencies remain optional behind `aster-lab` features and the
lab default feature set remains empty.

## Exact preliminary build profiles

Package counts below are unique package identities in `cargo tree` normal and
build edges, including the `aster-lab` root and excluding dev dependencies.

| Build profile | Exact feature selection | Automatic source under test | macOS ARM64 packages | Linux ARM64 packages |
|---|---|---|---:|---:|
| Native | `--no-default-features` | existing Aster protected IP discovery | 79 | 79 |
| Iroh protected | `ip-mesh-iroh` | `aster-protected` | 304 | 291 |
| Iroh provider mDNS | `ip-mesh-iroh-mdns` | `provider-mdns` | 308 | 295 |
| libp2p protected | `ip-mesh-libp2p` | `aster-protected` | 223 | 226 |
| libp2p provider mDNS | `ip-mesh-libp2p-mdns` | `provider-mdns` | 232 | 235 |

For a compact integrity check, each tree was reduced to a sorted unique package
identity list, Cargo's duplicate `(*)` marker was removed, and the absolute
checkout prefix was normalized to `$WORKSPACE/`. The resulting SHA-256 values
are:

| Build profile | macOS ARM64 package-set SHA-256 | Linux ARM64 package-set SHA-256 |
|---|---|---|
| Native | `5503c64c0fb4607ea08909b7db1fc32ae72a8e0ad2bfdf21be5fe7380cb7ff62` | `5503c64c0fb4607ea08909b7db1fc32ae72a8e0ad2bfdf21be5fe7380cb7ff62` |
| Iroh protected | `bce98b3464c14b3d91d59781e6ff564de3817a0523ca6f6c761f1641477ffa35` | `4cbe0f1705b0b4a9e2fab50042d1ad27d6aa3aa7c9fa687b644583db84e81e87` |
| Iroh provider mDNS | `91a3fccab2a79215c3c8a358a12f6876915104a2e479053d8bed8f09e18d8da2` | `40366f0fd8d4b274526819ccbb04de3ea9d0ea41f4b76859601d4e7605e2dad6` |
| libp2p protected | `9a5fa606f8416c39e9798c9b0ff5fb8b52fe8ddaac61dd942d353d8ceb101fb4` | `f65533a3b538d35967e0bb3092fb1d28c15bea07fff2ebd4d617cce173e7dec0` |
| libp2p provider mDNS | `5f7ee219156c8ace971896bcd858de8414538361aee34c8c1ca4c8e1f9d363b6` | `5d734d62a2cc30d27f60940016af97857b94bc2017e3aee444a7e9cd92aa6c2d` |

The CLI source selector is explicit and accepts only `aster-protected` or
`provider-mdns`. A protected-only binary rejects `provider-mdns` because the
provider package is absent. The mDNS-enabled binary can select either source,
but that convenience does not make its compiled graph equivalent to the
protected-only binary.

### Native control

| Item | Exact preliminary value |
|---|---|
| Lab feature | `default = []`; no provider feature |
| Aster crates | `aster-lab`, `aster-host`, `aster-ip`, and `aster-core` `0.1.0` |
| `aster-core` feature | `adapter-sdk` |
| `aster-ip` features | none |
| Source/license | project workspace source; Apache-2.0 |
| Declared MSRV | Rust 1.90 |

`cargo +1.90.0 check --locked --offline -p aster-lab
--no-default-features` passed in this preliminary state. This is a dependency
and compiler-floor result, not a frozen binary or operational mesh result.

### rust-libp2p profiles

Shared direct packages are:

| Direct package | Exact version | Registry checksum | Enabled features |
|---|---:|---|---|
| `libp2p` | `0.56.0` | `ce71348bf5838e46449ae240631117b487073d5f347c06d434caddcb91dceb5a` | `dcutr`, `macros`, `noise`, `relay`, `tcp`, `tokio`, `yamux`; defaults disabled |
| `libp2p-stream` | `0.4.0-alpha` | `1d6bd8025c80205ec2810cfb28b02f362ab48a01bee32c50ab5f12761e033464` | no crate features |

Both libp2p profiles activate `libp2p-core` 0.43.2,
`libp2p-swarm` 0.47.1, `libp2p-identity` 0.2.14,
`libp2p-noise` 0.46.1, `libp2p-tcp` 0.44.1,
`libp2p-yamux` 0.47.0, `libp2p-relay` 0.21.1,
`libp2p-dcutr` 0.14.1, and `libp2p-connection-limits` 0.6.0.
Neither profile activates Identify, AutoNAT, request/response, DNS, QUIC,
Gossipsub, Kademlia, rendezvous, UPnP, or a public bootstrap service.

The protected profile does not activate `libp2p-mdns` or either Hickory 0.25.2
package edge. It deliberately composes Aster's bounded authenticated discovery
with an otherwise idiomatic persistent libp2p `Swarm` and generic substream.
That composition is a distinct hypothesis from the literal provider-mDNS arm;
results must not combine them.

The provider-mDNS feature adds these nine packages to the Linux ARM64 graph:
`libp2p-mdns` 0.48.0, `hickory-proto` 0.25.2, `async-trait` 0.1.92,
`critical-section` 1.2.0, `enum-as-inner` 0.6.1, `portable-atomic` 1.15.0,
`socket2` 0.5.10, `tinyvec` 1.12.0, and `tinyvec_macros` 0.1.1.
Its exact additional registry checksums include:

| Package | Exact version | Registry checksum |
|---|---:|---|
| `libp2p-mdns` | `0.48.0` | `c66872d0f1ffcded2788683f76931be1c52e27f343edb93bc6d0bcd8887be443` |
| `hickory-proto` | `0.25.2` | `f8a6fe56c0038198998a6f217ca4e7ef3a5e51f46163bd6dd60b5c71ca6c6502` |

The active Hickory features are `mdns`, `std`, `futures-io`, and `socket2`;
no DNSSEC feature is active. The upstream libp2p mDNS behaviour nevertheless
retains one `(PeerId, Multiaddr, expiry)` entry in a growable `SmallVec` for
every observed pair until expiry, with a default TTL of six minutes and no
configurable hard entry cap. This allocation occurs before `MeshHost` can apply
its candidate ceiling. A bounded downstream adapter therefore cannot make this
profile pass the hostile-discovery requirement.

The direct libp2p crates declare Rust 1.83. Both protected and provider-mDNS
profiles pass full locked, offline `aster-lab` checks under Rust 1.90 in this
preliminary worktree. Those checks must be repeated from the signed freeze and
do not resolve the advisory, license, boundedness, or alpha-API blockers.

### Iroh profiles

Shared direct packages are:

| Direct package | Exact version | Registry checksum | Enabled features |
|---|---:|---|---|
| `iroh` | `1.0.3` | `460de6bc52163b41b1646931f2897e5ab986f0966ade444467fec25024751a72` | `tls-ring`; defaults disabled |

Both Iroh profiles activate `iroh-base` 1.0.3, `iroh-dns` 1.0.3,
`iroh-relay` 1.0.3, `iroh-metrics` 1.0.1, `noq` 1.1.1,
`netwatch` 0.19.1, and patched `hickory-proto`/`hickory-resolver` 0.26.1.
The Iroh metrics feature, `fast-apple-datapath`, and `portmapper` are not
enabled; Gossip, Blobs, and Documents are not added. Compiled DNS and relay
support is not permission to use public N0 services. Preliminary runtime source
inspection shows the experiment using a stable secret key and the Minimal
endpoint preset, but the signed candidate and network capture must still prove
that public defaults remain absent.

The provider-mDNS profile additionally activates:

| Direct package | Exact version | Registry checksum | Enabled features |
|---|---:|---|---|
| `iroh-mdns-address-lookup` | `0.5.0` | `cad3dfcaddd5c3681bf0a42606498fc6e8891de793408dfbc46a9fbe76f370b3` | no crate features; defaults disabled |

On Linux ARM64 that feature adds only `iroh-mdns-address-lookup` 0.5.0,
`swarm-discovery` 0.6.3, `acto` 0.8.2, and `smol_str` 0.1.24. The protected
profile contains none of those four packages.

The local lookup's command channel and subscriber delivery channels are
bounded. Its actor still keeps discovered endpoints in an uncapped `HashMap`,
while `swarm-discovery` keeps peers in an uncapped `BTreeMap`; neither exposes a
hard maximum that can be set to the Aster candidate ceiling. This state exists
before the event reaches `MeshHost`, so the provider-mDNS profile is a useful
idiomatic characterization but not a hostile-input-qualified candidate.

Iroh 1.0.3, its support crates, `netwatch` 0.19.1, and the local lookup provider
0.5.0 declare Rust 1.91. Both exact profiles fail immediately under Rust 1.90.
Both pass locked, offline checks under Rust 1.97.1. Iroh cannot be selected while
the workspace package metadata continues to promise Rust 1.90.

The active Iroh graph contains relay-client support but no frozen self-hosted
relay server binary, configuration, access policy, limits, image, or checksum.
That infrastructure remains a prerequisite for the owned-relay lane.

## Advisory status

The normal preliminary command
`cargo audit --no-fetch --file Cargo.lock` loaded 1,225 RustSec advisories,
scanned all 589 lock records, and failed with two vulnerabilities. It also
reported two unmaintained warnings.

| Finding | Raw-lock status | Exact active lab profiles | Interpretation and disposition |
|---|---|---|---|
| RUSTSEC-2026-0118, `hickory-proto` 0.25.2 | present; raw audit fails | libp2p provider mDNS only | Cargo's package/advisory match is active. Its described DNSSEC validation path is not feature-reachable because no DNSSEC feature is enabled, but the normal policy still fails and grants no waiver. |
| RUSTSEC-2026-0119, `hickory-proto` 0.25.2 | present; raw audit fails | libp2p provider mDNS only | Message encoding is in the active mDNS package; blocks this profile. Upgrade requires a published compatible libp2p mDNS graph using Hickory 0.26.1 or later. |
| RUSTSEC-2024-0436, `paste` 1.0.15 | present; unmaintained | both libp2p profiles through TCP → `if-watch`; both Iroh profiles through `netwatch` | No provider exception exists; production selection is blocked pending removal, replacement, or an explicit bounded disposition. |
| RUSTSEC-2026-0173, `proc-macro-error2` 2.0.1 | present; unmaintained | absent from all five `aster-lab` profiles | Existing Decision 0002 exception applies only to the age pilot and is not a provider waiver. |

Feature-specific `cargo deny` advisory checks against Linux ARM64 metadata
produced:

| Profile | Result |
|---|---|
| Native | pass; no active advisory |
| Iroh protected | fail; RUSTSEC-2024-0436 |
| Iroh provider mDNS | fail; RUSTSEC-2024-0436 |
| libp2p protected | fail; RUSTSEC-2024-0436 |
| libp2p provider mDNS | fail; RUSTSEC-2026-0118, RUSTSEC-2026-0119, and RUSTSEC-2024-0436 |

Feature non-reachability is relevant technical evidence, but it does not make
the repository's exact current raw-lock audit pass. Phase 0 must produce a clean
lock/profile whose mandatory policy command succeeds or obtain an expressly
approved feature-aware policy. This experiment does neither.

## License status

The native Linux ARM64 and macOS ARM64 profiles pass the current license policy.
Feature-specific metadata checks for every external profile fail the current
`deny.toml` allowlist:

| Profile | Rejected license classes | Representative active packages |
|---|---|---|
| Iroh protected | Zlib, ISC, BSD-2-Clause, CDLA-Permissive-2.0 | `foldhash` 0.2.0, `ring`, `rustls-webpki`, `spez`, `untrusted`, `webpki-roots` |
| Iroh provider mDNS | same as Iroh protected | same active roots; the four mDNS additions introduce no new rejected class |
| libp2p protected | BSD-2-Clause, Zlib, ISC | `arrayref`, `foldhash` 0.1.5, `ring`, `untrusted` |
| libp2p provider mDNS | same as libp2p protected | same active roots; the nine mDNS additions introduce no new rejected class |

The `ring` expression is `Apache-2.0 AND ISC`, so ISC must itself be allowed.
BSD-2-Clause, Zlib, and ISC are OSI-approved licenses; their failure is an
allowlist decision, not evidence of legal incompatibility. The
CDLA-Permissive-2.0 root-certificate data needs a separate release/legal
disposition because it is neither currently allowed nor software-license
classified by the policy tool. No allowlist change or exception is granted
here. The stale all-feature result that mentioned Unlicense does not describe
either exact Iroh split profile and has been removed from this record.

## Governance and infrastructure status

| Profile family | Upstream/source status | Preliminary governance disposition |
|---|---|---|
| Native | Aster project source, Apache-2.0, owned by this project | may continue; normal project review, security, and release controls apply |
| rust-libp2p | libp2p 0.56.0 and libp2p-stream 0.4.0-alpha are MIT; rust-libp2p publishes a security policy and private reporting path for supported releases | technical lanes may continue; alpha API stability/update owner, advisory closure, licenses, and owned relay operations block selection |
| Iroh | Iroh and its local lookup provider are MIT OR Apache-2.0; GitHub private reporting and a 1.x support policy are published, but no repository SECURITY.md is present | Decision 0002 permits only a recorded isolated pilot; MSRV, licenses, security-process disposition, and owned infrastructure block selection |

Neither external profile may contact a public DNS/Pkarr discovery service, DHT,
bootstrap node, or public relay during acceptance runs. Runtime configuration,
owned relay addresses, relay credentials, access controls, rate/connection
limits, container images, and network receipts remain unfrozen.

## Technical lanes that may continue

`Continue` means evidence gathering is permitted after candidate freeze; it
never means a requirement or production gate has passed.

| Proposal 0003 lane | Native | libp2p protected | libp2p provider mDNS | Iroh protected | Iroh provider mDNS |
|---|---|---|---|---|---|
| Phase 1 ownership, bounds, and persistent-stream proof | Continue | Continue; alpha/stability blocker remains | Characterize only; pre-host cache is uncapped | Continue on Rust 1.97.1 | Characterize only on Rust 1.97.1; pre-host maps are uncapped |
| Manual/pre-provisioned LAN contact | Continue | Continue | May characterize | Continue | May characterize |
| Automatic LAN discovery | Continue | Continue with Aster protected discovery | Nonqualifying: Hickory and boundedness blockers | Continue with Aster protected discovery | Nonqualifying: boundedness blocker |
| Controlled direct/relay/path-change work | Continue with accepted native mechanisms | Limited: relay and DCUtR compiled; actual service/path evidence required | Same, with mDNS blockers attached | Limited: core direct/relay path machinery compiled; owned relay is unfrozen | Same, with mDNS blocker attached |
| Impairment, hostile input, capture, idle, and resource measurement | Continue | Continue | Technical characterization only | Continue on Rust 1.97.1 | Technical characterization only on Rust 1.97.1 |
| Production selection or requirement closure | Pending all functional gates | **Blocked** | **Blocked and nonqualifying** | **Blocked** | **Blocked and nonqualifying** |

The protected-discovery external profiles answer a different and important
question from provider mDNS: whether the provider's persistent carrier,
multiplexing, authentication hints, path handling, and relay machinery improve
Aster while the project retains its bounded discovery. Reports must preserve
that distinction rather than call the hybrid lane fully provider-native.

## Items required to finalize Phase 0

- [ ] Record a signed clean candidate commit and prove the worktree is clean.
- [ ] Replace all preliminary manifest and lock hashes with hashes from that
  commit.
- [ ] Rerun all five feature profiles from the signed commit, including full
  Rust 1.90 checks for both libp2p builds and Rust 1.97.1 checks for both Iroh
  builds.
- [ ] Build exact native, split rust-libp2p, and split Iroh binaries and record
  command, target, toolchain, features, size, and SHA-256.
- [ ] Retain host, Linux, and macOS target-specific Cargo trees, archive
  checksums, SBOMs, and complete license inventories for each arm separately.
- [ ] Make the repository's normal raw-lock advisory command pass or record an
  approved feature-aware policy change; no implicit waiver is permitted.
- [ ] Resolve or explicitly reject every provider license-policy finding.
- [ ] Decide whether the repository's Rust floor is raised, Iroh is repinned to
  an admissible graph, or Iroh is terminated.
- [ ] Assign an update owner and stability/exit policy for
  `libp2p-stream` 0.4.0-alpha.
- [ ] Resolve the provider-mDNS pre-host boundedness failures or retain those
  arms only as nonqualifying characterizations.
- [ ] Freeze runtime configuration proving public services are absent.
- [ ] Freeze locally operated relay binaries, images, configuration, access
  controls, and resource limits.
- [ ] Freeze common topology, thresholds, impairment schedule, and expected
  mechanism-deletion manifest.

Until every applicable item is complete, this document cannot support a
dependency admission, provider selection, release claim, or requirement-status
change.

## Evidence provenance and exact commands

This record relies on the registered public-source reviews in
`evidence/SOURCE_REGISTER.csv`, especially BVB-459, BVB-624, and BVB-630 through
BVB-642. No new external source was needed for this correction. The split
results were independently verified against the checksummed registry source
already covered by BVB-634 through BVB-642 and the local dirty worktree.

The exact local command shapes were:

```text
shasum -a 256 Cargo.toml Cargo.lock crates/aster-lab/Cargo.toml
rg -c '^\[\[package\]\]' Cargo.lock

cargo tree --locked --offline -p aster-lab --no-default-features \
  [--features PROFILE] --target TARGET -e normal,build \
  --prefix none --format '{p}'

cargo metadata --manifest-path crates/aster-lab/Cargo.toml \
  --no-default-features [--features PROFILE] \
  --filter-platform aarch64-unknown-linux-gnu --locked --offline \
  --format-version 1

cargo deny --manifest-path crates/aster-lab/Cargo.toml \
  --metadata-path PROFILE.metadata.json \
  --target aarch64-unknown-linux-gnu --exclude-dev --offline \
  check advisories

cargo deny --manifest-path crates/aster-lab/Cargo.toml \
  --metadata-path PROFILE.metadata.json \
  --target aarch64-unknown-linux-gnu --exclude-dev check licenses

cargo audit --no-fetch --file Cargo.lock

cargo +1.90.0 check --locked --offline -p aster-lab \
  --no-default-features [--features PROFILE]

cargo +1.97.1 check --locked --offline -p aster-lab \
  --no-default-features --features ip-mesh-iroh
cargo +1.97.1 check --locked --offline -p aster-lab \
  --no-default-features --features ip-mesh-iroh-mdns
```

`PROFILE` was empty, `ip-mesh-iroh`, `ip-mesh-iroh-mdns`,
`ip-mesh-libp2p`, or `ip-mesh-libp2p-mdns`. `TARGET` was
`aarch64-apple-darwin`, `aarch64-unknown-linux-gnu`, and, as a cross-check,
`x86_64-unknown-linux-gnu`. The x86-64 Linux package counts were respectively
79, 292, 296, 227, and 236; those are preliminary dependency resolutions, not
frozen binary receipts.

No result from these checks changes Decisions 0002, 0022, or 0023.

## Final signed freeze and disposition

The experiment later froze clean, signed commit
`15f99c37c7310ba7d8f6a3a2f927d7b1a8ddfe2c`. The preliminary workspace,
lab-manifest, and lock hashes above matched that checkpoint. Linux ARM64
protected-profile release artifacts were:

| Profile | Active packages | Binary bytes | Binary SHA-256 |
|---|---:|---:|---|
| Native | 79 | 4,345,600 | `82438a75538687d32660ea1df4b72354cdb081ad1a6570bafefb7f9ddbe34957` |
| Iroh protected | 291 | 11,907,368 | `755582545f4aed3f58b51578cbc91a195f813e195b21004419d986987c373d21` |
| libp2p protected | 226 | 6,378,896 | `2b3a8c820284de692155d9c70007f78a21a81f0f78c4fe813df108e938db8407` |

The signed source passed the common host/runtime test suite, strict linting,
formatting, provider-focused tests, real one-stream 10,000-frame tests, and the
provider-specific compiler-floor checks described above. Those results froze
the technical candidates; they did not clear the unresolved advisory, license,
MSRV, provider-mDNS, relay-infrastructure, or mechanism-deletion items in the
preflight checklist.

More importantly, independent Phase-1 review found that every arm constructed
an independent durable backend per contact before fresh Aster authentication,
shared one store through multiple authorities with instance-local quota and
control state, and lacked a node-global resource budget. Iroh also retained an
upstream pre-`Incoming` pool that the public builder could not reduce. These
mandatory failures stopped the later NAT, relay/path-change, impairment, and
scale phases.

The complete measurements, stopped cells, rollback proof, and recommendation
are in the [Proposal 0003 result](0003-idiomatic-ip-mesh-provider-results.md).
[Decision 0024](../decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md)
selects no provider and requires a single process-owned durable authority before
another comparison. The experimental Iroh and libp2p Rust adapter modules,
Cargo features, and dependency graphs were removed from the continuing branch;
Python evidence tooling remains. No dependency, requirement, or production
capability was admitted by this activation record.
