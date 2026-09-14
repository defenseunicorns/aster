# Decision 0027: Bound the active libp2p pilot dependency exceptions

- Status: retained non-production test oracle only; provider selection lane
  closed; `paste` advisory exception retired 2026-08-23
- Date: 2026-08-23
- Review deadline: 2026-11-23, or before any production selection or release,
  whichever comes first
- Related: [Decision 0002](0002-dependency-admission.md),
  [Decision 0023](0023-mesh-host-contract-no-libp2p-selection.md),
  [Decision 0029](0029-close-proposal-0004-libp2p-pilot.md),
  [Proposal 0003](../proposals/0003-idiomatic-ip-mesh-provider-activation.md),
  and [CI policy](../validation/ci.md)

## Context

The focused `aster-libp2p-provider` experiment activates an exact libp2p
0.56.0 graph. Its dependency-policy scan identifies four third-party license
expressions that are compatible with the bounded research use but were not in
the repository allowlist:

| Package | Version | License expression | Active path |
| --- | --- | --- | --- |
| `arrayref` | 0.3.9 | `BSD-2-Clause` | `multiaddr` → `libp2p` |
| `foldhash` | 0.1.5 | `Zlib` | `hashbrown` → `hashlink` → `libp2p-dcutr`/`libp2p-swarm` |
| `ring` | 0.17.14 | `Apache-2.0 AND ISC` | `snow` → `libp2p-noise` |
| `untrusted` | 0.9.0 | `ISC` | `ring` → `snow` → `libp2p-noise` |

`BSD-2-Clause`, `ISC`, and `Zlib` are OSI-approved licenses. Allowing these
expressions for external dependencies does not change the repository's
Apache-2.0-only rule for first-party packages and distributed project files.

At adoption, the same active graph contained `paste` 1.0.15 beneath
`netlink-packet-core` 0.8.2. Its reviewed reverse graph reaches `if-watch`
3.2.2 directly and through `netlink-packet-route`, `netlink-proto`, and
`rtnetlink`, then reaches `libp2p-tcp` 0.44.1.
[RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html)
classifies `paste` as unmaintained. It reports no vulnerability and no patched
release. The exact libp2p pilot could not remove that path without changing its
transport dependency graph. The remediation recorded below now supplies a
source-compatible patched dependency and removes `paste` from the lock and
active graphs.

## Decision

1. Add `BSD-2-Clause`, `ISC`, and `Zlib` to the external dependency license
   allowlist.
2. Permit `RUSTSEC-2024-0436` only for the exact active path rooted at
   `paste` 1.0.15 and terminating in the non-production
   `aster-libp2p-provider`/`aster-lab` experiment.
3. Require a fail-closed reverse-dependency check covering the exact package
   and version set. Any new consumer, package version, or path blocks CI and
   requires a new review.
4. Require `paste` to remain absent from the separately audited fuzz graph.
5. Keep rust-libp2p unselected and production-blocked. This disposition makes
   the bounded pilot auditable; it does not admit the provider for production.

The separate lock-only Hickory disposition in
[Decision 0026](0026-lock-only-hickory-advisories.md) is not part of this
active-graph exception. Raw lockfile audit ignores remain limited to Hickory.
At adoption, the feature-aware dependency-policy scanner carried only this
`paste` ignore and the age-pilot exception from Decision 0018; the remediation
below retires the former.

## Removal and review gates

- Prefer an upstream `if-watch`/netlink/libp2p update that removes `paste`.
  After that update passes the complete test and dependency-policy suite,
  remove `RUSTSEC-2024-0436` from `deny.toml` and delete its scope assertion.
- Re-review this exception no later than 2026-11-23. It expires immediately if
  the provider is proposed for a default, release, deployment, or production
  path.
- A changed reverse graph, changed advisory classification, vulnerability
  report, or new license expression fails closed rather than inheriting this
  decision.
- Production selection still requires the independent carrier, recovery,
  security, operational-relay, target, and supply-chain gates recorded by the
  research proposal. A green dependency-policy job alone grants none of those
  claims.

## Consequences

- CI can distinguish a reviewed non-production dependency hold from an
  unreviewed policy failure.
- The dated exception remains visible in this decision, while the remediation
  removes the unmaintained package rather than broadening its allowed graph.
- First-party license enforcement remains byte-for-byte Apache-2.0 and is
  unaffected by the external dependency allowlist.

## Post-closure scope — 2026-08-23

[Decision 0029](0029-close-proposal-0004-libp2p-pilot.md) closes Proposal 0004
with no provider selected. This decision now governs retained test evidence
only. The provider must remain `publish = false`, absent from default features,
and have no workspace consumer other than the optional dependency activated by
the opt-in `aster-lab/libp2p-candidate` feature.
No new Proposal 0004 experimental cohort or selection-phase execution is
authorized; routine retained-oracle CI validation remains permitted.
The provider remains an independently buildable workspace test package, so
explicit and workspace-wide validation may compile it without activating it in
any default or shipping consumer.

The 2026-11-23 review deadline and the earlier-use expiry remain unchanged for
the retained pilot and its license disposition. Closure did not convert the
temporary `RUSTSEC-2024-0436` disposition into general or permanent policy;
the remediation below retires that advisory exception before the deadline.

## Advisory remediation — 2026-08-23

The selected Iroh graph reached the same unmaintained `paste` package through
`netwatch`, so expanding the pilot-only exception would have violated this
decision. Instead, Aster vendors the exact MIT-licensed
`netlink-packet-core` 0.8.2 source and changes only its dependency declaration:
the dependency key `paste` now resolves to exact `pastey` 0.2.2, RustSec's
maintained drop-in replacement. No vendored Rust source or public macro API is
changed. [`ASTER-PATCH.md`](../../third-party/netlink-packet-core-0.8.2-aster/ASTER-PATCH.md)
binds the upstream archive, revision, license, and local delta.

Consequently, `paste` is absent from `Cargo.lock`, the full workspace graph,
and the fuzz graph. `RUSTSEC-2024-0436` is removed from `deny.toml`; the scope
gate now fails if any `paste` version reappears instead of permitting an exact
reverse path. The patch may be removed only after all active netlink consumers
can use an upstream release that no longer depends on `paste`, with the same
workspace, retained-oracle, and dependency-policy gates passing.
