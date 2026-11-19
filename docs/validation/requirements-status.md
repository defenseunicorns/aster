# Production implementation requirements status

- Requirements authority: [`DESIGN.md`](../../DESIGN.md)
- Planning view: [`capability-roadmap.md`](capability-roadmap.md)
- Atomic requirements index: [`requirements-matrix.csv`](requirements-matrix.csv)
- Exhaustive cross-lane trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Release status: **not production-authorized**

This document summarizes implementation status and remaining gaps.
Implementation does not imply production readiness.

## Trace vocabulary

The `selected_status` column uses only `observed-bounded`,
`implemented-uncredited`, and `open`. The remaining values below describe
separate source, evidence, or gate dimensions.

| Trace value              | Meaning                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `observed-bounded`       | Real production-lane code passed a stated, reproducible test, but only within the recorded environment and claim boundary       |
| `implemented-uncredited` | A mechanism exists, but the complete requirement has not been demonstrated                                                      |
| `open`                   | The selected production composition does not yet implement the obligation                                                       |
| `semantic-source`        | Proven current semantic code or tests remain an equivalence source until the selected composition passes the replacement tests  |
| `research-only`          | Evaluation informed implementation, but its result is not production acceptance                                                 |
| `external-gate`          | Completion requires target hardware, independent authorship/review, an admitted cryptographic module, or stakeholder-set values |

## Adopted security-profile applicability

[Decision 0033](../decisions/0033-policy-selected-security-profiles.md) and the
[security-profile requirements disposition](security-profile-requirements-disposition.md)
define security-profile applicability for planning and release review:

- source payload encryption/authentication, payload-blind forwarding, Aster
  mission authorization, plaintext minimization, algorithm agility, and
  downgrade resistance remain hard profile-invariant boundaries;
- metadata protection is best effort within a declared exposure budget, may use
  an admitted authenticated encrypted carrier for ephemeral contact metadata,
  and protects persistent forwarding metadata independently where practical;
- Aster must support complete classical and hybrid-PQ profiles, while mission
  policy decides which are permitted or required and a required hybrid profile
  fails closed before inventory; and
- packet-capture and validated-module gates apply to the exact profile and
  claims under review rather than assuming universal PQ and zero metadata on
  every carrier.

The current selected implementation remains the
fixed hybrid-PQ path. An additive profile-`0x0002`
reference/two-node mission path exists, but no stock runtime/CLI selector
or general profile negotiation exists.

## Production-lane requirements trace

The CSV tracks each requirement separately. Row counts include repeated phase and
acceptance requirements; they are not a product completion percentage.

<!-- ASTER-REQUIREMENTS-TOTALS:BEGIN -->

Generated selected-status totals: implemented-uncredited=53; observed-bounded=84; open=211; exact-selected-mappings=140.

| Requirement family | Implemented, not fully credited | Observed, bounded | Open    | Total   |
| ------------------ | -------------------------------:| -----------------:| -------:| -------:|
| DM-1               | 0                               | 3                 | 4       | 7       |
| DM-2               | 1                               | 0                 | 13      | 14      |
| DM-3               | 1                               | 1                 | 11      | 13      |
| DM-5               | 26                              | 50                | 46      | 122     |
| DM-6               | 4                               | 18                | 14      | 36      |
| DM-7               | 6                               | 3                 | 12      | 21      |
| DM-8               | 2                               | 2                 | 15      | 19      |
| DM-9               | 2                               | 3                 | 27      | 32      |
| DM-10              | 0                               | 0                 | 6       | 6       |
| DM-11              | 9                               | 0                 | 24      | 33      |
| DM-12              | 0                               | 4                 | 7       | 11      |
| DM-13              | 2                               | 0                 | 9       | 11      |
| DM-14              | 0                               | 0                 | 23      | 23      |
| **Total**          | **53**                          | **84**            | **211** | **348** |

<!-- ASTER-REQUIREMENTS-TOTALS:END -->

## Implementation overview

Detailed requirement statuses are maintained in
[`requirements-implementation.csv`](requirements-implementation.csv).

| Area | Implemented | Remaining work |
|---|---|---|
| **Events** | Offline publication, synchronization, subscriptions, acknowledgements, gap detection, and forwarding through intermediate nodes. | Broader validation across long disconnections, constrained links, and target devices. |
| **State and Records** | Live publication, queries and subscriptions; deterministic State resolution; preservation and explicit resolution of Record conflicts. | Automatic Record merging, finite TTL and garbage collection, dynamic network interests, peer/contact/convergence status, and broader recovery and relay validation. Decide whether State subscriptions need notifications when a value disappears. |
| **Blobs** | File and streaming publication, authenticated reads, resumable transfer, local progress reporting, finite TTL, and storage-pressure handling. | Forwarding through nodes without content access; peer synchronization status; subscription administration through the agent/CLI; CLI download resume; FFI lifetime controls; metadata-independent whole-byte identity; broader crash-recovery, long-offline, lifecycle, and resource validation. Incompatible unreleased depots require reset or reimport. |
| **Network connectivity** | Direct IP, an explicitly configured HTTPS relay, and optional LAN discovery. | Representative NAT and multi-device validation, mobility and outage recovery, production BTLE integration, and interoperability testing. |
| **Priorities and resource limits** | Event priorities, quotas, receive-only operation, Linux Event expiration, and Blob lifecycle controls. | Consistent policies across data classes, broader platform support, complete storage accounting, and validation on constrained links. |
| **Scopes and hierarchy** | Topic/scope filtering and static, payload-blind Event forwarding between scopes. | Dynamic membership, routing and interest updates; protected hierarchy provisioning; bounded chain verification and restart-persistent cursors; broader quota administration and cross-class custody; physical, hostile-discovery, and bridged-scale/resource validation. |
| **Security and administration** | Source and mission authentication, live/stopped Rust revocation and rekey operations, protected Rust provisioning interfaces, bounded Compose provisioning, and local software zeroization. | Production key custody and recovery; protected stock CLI/bindings and cross-process administration IPC; coordinated revocation/rekey with affected-scope discovery and a durable rekey-required fence; coordinated live drain, store terminalization and provider destruction; filesystem identity/rollback and restore/rebind assurance; operational security-profile selection, platform assurance, and independent review. |
| **Compose credential provider** | Statically composed provider, immutable generation administration, schema v2, hardened image/Compose definitions, daemon-free policy validation, a manual operator procedure, and a manually triggered release-artifact workflow. | Identity issuance and recovery, a general production custody backend, independent review, broad platform support, host qualification, retained SBOM/license artifacts, and production authorization; Docker lifecycle behavior remains unverified here, and a generated Compose release bundle is not available. |
| **Application integration** | Rust APIs for Event, State, Record, and Blob; agent Event operations and Blob inspection, publication, and reading. | Agent State/Record operations, Blob subscription RPCs, selected-node language bindings, and simpler multi-class examples. |
| **Scale and release readiness** | Partial implementation and limited validation; no production-readiness claim. | Confirm resource targets; validate scale and supported hardware; complete interoperability, dependency/license review, release packaging, and authorization. |

State/Record validation remains limited to two participants on one host using
direct connections. Arbitrary-peer and process-crash Blob resume, networked
and long-retention Blob delivery, and mixed-implementation behavior still
require validation.
