# Decision 0046: BTLE Ring 2 vendored dependency patches

- Status: accepted for the bounded Ring 2 implementation increment
- Date: 2026-11-06
- Review owner: Aster maintainers
- Mandatory re-review: before production admission or 2027-02-06, whichever
  occurs first

## Decision

Aster path-patches exact crates.io `hmac` 0.13.0 and `bluer` 0.17.4. The
versions and licenses remain their upstream values; `-aster` names identify
repository directories, not new package versions.

| Package | Archive SHA-256 | Upstream revision | Enabled production features | Manifest license |
|---|---|---|---|---|
| `hmac` 0.13.0 | `6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f` | `0236c8eb50098dd7f277a71ab89caaeb1e7314df` | `default-features = false`, `zeroize` | `MIT OR Apache-2.0` |
| `bluer` 0.17.4 | `af68112f5c60196495c8b0eea68349817855f565df5b04b2477916d09fb1a901` | `8072d9cc6d034f1bfc464dda338d19a14f9badaf` | `default-features = false`, `bluetoothd`, `l2cap` | `BSD-2-Clause` |

The manifest field is not the complete BlueR payload inventory. Its retained
`LICENSE` additionally assigns the Bluetooth assigned-number database used by
`build.rs` to `BSD-3-Clause` and copied/adapted BlueZ API documentation to
`GPL-2.0-only`. The notice is retained byte-for-byte with SHA-256
`da053620434ccd59747d44b04e87e06464763f22db320bc71dc9b00b1e4db460`.
This bounded source snapshot preserves that notice and source. Production
packaging remains gated on release review of the database and documentation
obligations; this decision does not infer a binary license solely from the
manifest declaration.

The HMAC delta changes only `src/block_api.rs`: both constructor paths put
the derived key/IPAD/OPAD temporary in `Zeroizing` when the already selected
feature is enabled. It changes no result bytes or public API.

The BlueR delta changes only `src/adapter.rs`, `src/adv.rs`, `src/lib.rs`, and
`src/session.rs`: it adds cancellation-independent advertisement/discovery
owners with acknowledged stop, persistent termination notification, and a
256-item first ingress bound whose overflow terminates the session. Existing
shared discovery/drop APIs remain compatible. No mission, roster, durable
store, transport-selection, or Aster protocol policy enters the fork.

## Buy versus build

- Maintaining the small HMAC constructor patch preserves RustCrypto's tested
  MAC implementation and vectors. Writing a custom HMAC would replace a
  one-file memory-hygiene delta with security-sensitive cryptographic code.
- Maintaining the four-file BlueR ownership patch preserves the official
  BlueZ Rust binding, its D-Bus mapping, and L2CAP socket implementation.
  A bespoke BlueZ/D-Bus binding would multiply Linux lifecycle and compatibility
  surface without improving Aster's onion boundary.
- Waiting for upstream would leave Ring 2 unable to prove cancellation-safe
  cessation or bounded ingress. Both patches are exact, source-reconstructible,
  and have explicit removal triggers, so they remain replaceable.

## Affected graph

`bluer` is a Linux-only normal dependency of `aster-ble-linux`. The crates.io
patch for `hmac` is workspace-wide: direct consumers include
`aster-ble-linux` and `aster-host`, and transitive consumers include `hkdf`,
`rfc6979`, and the selected P-256 graph. Therefore HMAC qualification is not
claimed as discovery-local. Root and fuzz manifests and lockfiles must all
resolve the exact path forks; registry `hmac` 0.12.1 remains a separate package
and is not covered by this decision.

## Security and maintenance review

Review snapshot: 2026-11-06.

- RustCrypto HMAC 0.13.0 was released 2026-03-29 and is the current documented
  release. RustCrypto accepts private GitHub security advisories and applies
  security updates to its most recent release.
  <https://docs.rs/crate/hmac/0.13.0>,
  <https://github.com/RustCrypto/MACs/security/policy>
- BlueR 0.17.4 was released 2025-06-06 and remains the latest documented
  release. The project is the official BlueZ Rust binding. Vulnerability
  reports for the underlying BlueZ stack use BlueZ's private GitHub advisory
  channel; dependency review must continue to cover both the binding and the
  deployed BlueZ daemon.
  <https://github.com/bluez/bluer/releases/tag/v0.17.4>,
  <https://github.com/bluez/bluez/security/policy>
- The RustSec database reviewed on 2026-11-06 contains no advisory naming
  `hmac` or `bluer`. The production lock selects `ctutils` 0.4.5, above the
  `RUSTSEC-2026-0385` patched floor 0.4.4, and Tokio 1.53.3, at the
  `RUSTSEC-2026-0386` patched floor. BlueR still calls the now-deprecated
  `AsyncFd::new` with owned descriptors; this is visible as a compiler warning
  and must be removed or requalified before a warning-free production gate.
  <https://rustsec.org/advisories/RUSTSEC-2026-0385.html>,
  <https://rustsec.org/advisories/RUSTSEC-2026-0386.html>
- CI pins `cargo-audit` 0.22.2 and `cargo-deny` 0.20.2, refreshes advisory data,
  and audits both root and fuzz locks. This dated review does not replace that
  per-change gate. The standalone upstream HMAC test lock retains upstream
  `ctutils` 0.4.0 only in a non-shipping test graph; production and fuzz locks
  use the reviewed workspace resolution.

## Provenance and removal gates

Each vendor directory retains the exact archive file receipt, canonical patch,
patch digest, upstream revision, and complete license files. The source checker
reverse-applies each patch, rejects every undeclared or generated file,
rejects Git attribute filters that change upstream bytes, validates the
retained notice digest and inventory markers, and recomputes the deterministic
source-archive hashes.
CycloneDX pedigree input and deterministic source-archive hashes are recorded
under `docs/release/sbom/`.

Remove a fork when an exact upstream release provides equivalent behavior and
passes the same vectors, lifecycle tests, root/fuzz policy checks, and Linux
qualification. Any patch expansion, version movement, advisory, license
change, or missed review deadline requires a new decision.

The qualification script gives every positive and negative lane an isolated
Cargo target. It independently removes HMAC `Zeroizing`, bypasses advertisement
cleanup, bypasses discovery cleanup, removes definite discovery-absence
handling, and changes the 256-item ingress capacity. Each focused test must
fail under its own mutation. This distinguishes test presence from evidence
that every patch-specific contract is exercised.

## Claim limits

This decision admits only the Ring 2 implementation increment. It does not
grant production BTLE admission, change the Aster protocol, authorize a
release, complete physical radio qualification, or turn discovery locators
into mission identity.
