# Executable SBOM observation — 2026-09-08



**Scope qualification added 2026-09-09:** these are historical evaluation
artifacts. Their cargo-cyclonedx inventories include SQLite packages due to
workspace feature unification; they are accepted as overinclusive inventories,
not exact binary-composition evidence. The current [selected workflow](README.md)
uses cargo-cyclonedx with an ordinary stable build. It does not require this
observation's cargo-auditable setup or change the recorded artifact hashes.

This records the accepted, bounded experiment behind the [workflow](README.md).
It is not a fresh build of the MR base revision, release approval, or an
attestation of source-to-binary identity. The build source revision and complete
build-input snapshot were not retained as verified provenance.

## Observed documents

cargo-cyclonedx 0.5.9 produced CycloneDX 1.5 JSON. cdx-ev 0.34.0 applied the
[retained set-list](2026-09-08-netlink-pedigree.set.json). The edited documents
passed schema validation. Counts below exclude the root application:

| Check | aster | aster-agent |
|---|---:|---:|
| Components with declared licenses and purls | 359 | 372 |
| Components with registry archive checksums | 353 | 365 |
| Required / excluded scope | 349 / 10 | 355 / 17 |
| Dependency graph nodes, including root | 360 | 373 |
| Dependency edges | 1086 | 1163 |

Registry checksums matched Cargo.lock. No duplicate graph identifiers,
dangling references or unreachable components were found. Editing preserved
the component inventory, licenses, graph and application root. It changed only
the local netlink component's pedigree/external references, plus document
revision, serial number and editor metadata. The document revision became 2;
both application versions remain 0.1.0. Root executable hashes are absent.

Syft 1.51.1 binary scans found 327 / 333 components and zero licenses. All its
name/version pairs were present in the Cargo documents, including the root.
This is not proof that the dependency graphs or linked machine code match.
Grant was researched but not installed or run.

## Retained artifact identities

SHA-256 values for the retained evaluation artifacts:

| File | SHA-256 |
|---|---|
| auditable `aster` | `380d0b593c904e8f98569ea7554c19df35768d5615cc162a997ba19a00f79fbf` |
| auditable `aster-agent` | `80f67824a99a6d99c82ab55eded07ef4feb2101cb9aa8900d4b5d52b226fbcc4` |
| edited `aster.cdx.json` | `594f804a355780f166cb7258f24deb3128b60552734882559ccde9783e7d3160` |
| edited `aster-agent.cdx.json` | `d8e02fa4f3161ffe429afa584a5606f907af2baf52427fe4a1546e89439c7322` |
| `netlink-packet-core-0.8.2-aster.tar` | `bb5df952e94d0635397c492710fbe887dab55dc478c4f5b5c8753f05015bc612` |
| original `netlink-pedigree.set.json` | `27c5293d7a8b25038bb839fbfdc7ce5bf6de4cde5195784306f3e5ce6a067e83` |

The set-list is checked in under its dated filename. Generated SBOMs and the
source archive are handoff artifacts, not checked-in source. Keep the tar
beside the edited SBOMs so their relative distribution reference resolves.
These checksums identify separate files; they are not signed provenance.

Original files in the evaluation chroot:

- Executables: `/build/target-auditable/x86_64-unknown-linux-gnu/release/`.
- Generator outputs: `/build/aster/crates/aster-node/aster_bin.cdx.json` and
  `/build/aster/crates/aster-agent/aster-agent_bin.cdx.json`.
- Initial Cargo SBOM copies: `/build/sbom/cyclonedx/`.
- Syft outputs: `/build/sbom/aster.spdx.json`, `aster.syft.json`,
  `aster-agent.spdx.json`, `aster-agent.syft.json`.

## Patch qualification

The local netlink-packet-core 0.8.2 manifests replace `paste` with the `pastey`
0.2.2 package alias. The retained Rust files match the upstream hash receipt.
The chroot copy lacks `Cargo.toml.orig`, so the full repository patch checker
fails there. The retained snapshot explicitly records this omission; it was
not silently repaired or represented as a complete upstream source copy.
The checked-out repository has that file and is a different source snapshot.

cdx-ev replaced the external-reference array, removing the previous upstream
website/VCS links. The ancestor retains the original crate identity, checksum
and VCS revision in its description. Future set-lists should explicitly retain
all desired references. The dated set-list is evidence for this snapshot only.

## Executable audit and limits

The operator reported successful `--help` and retained `.dep-v0` sections
(5452 / 5699 bytes) after release stripping. The reported `cargo audit bin`
run on the auditable paths found embedded data for 360 / 373 dependencies.
It loaded 1242 advisories and reported two allowed yanked warnings in each:
`chacha20 0.10.1` and `wnaf 0.14.0`. No vulnerability was reported in that
pasted output. Audit tool version, advisory database revision, exit status and
an original audit log were not retained; this is operator-reported historical
evidence, not a fresh audit or current vulnerability assurance.

An earlier audit of `/build/aster/target/.../aster` used a different,
non-auditable executable and recovered only 128 dependencies. It does not
describe the auditable artifacts above.

Build/runtime role precision, statically included Rust standard-library and
native-code coverage, executable hashes inside SBOMs, automatic provenance,
repeatable builds and packaging remain open. No atomic requirement status or
roadmap completion claim changes in this increment.
