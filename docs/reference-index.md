# Aster reference index

This page catalogs the primary project documentation and design records.
For a shorter path based on what you are trying to accomplish, start at the
[documentation home](README.md).

## Tutorials and integration

- [Aster Field Notes human hello](quickstart/hello.md)
- [Three-host trusted-LAN Event MVP](quickstart/lan-mvp.md)
- [Concurrent LAN scale baseline](quickstart/lan-scale.md)
- [Static three-segment Event hierarchy MVP](../docker/hierarchy-mvp/README.md)
- [Generated hierarchy scale diagnostic](quickstart/hierarchy-scale.md)
- [Capability tour](quickstart/capability-tour.md)
- [Real-process Event message playground](quickstart/message-playground.md)
- [Live mesh CLI](quickstart/mesh-cli.md)
- [Local ConnectRPC agent](quickstart/connect-agent.md)
- [Aster agent configuration version 1](reference/aster-agent-config-v1.md)
- [Selected Event API](quickstart/selected-event-api.md)
- [Selected State API](quickstart/selected-state-api.md)
- [Selected Record API](quickstart/selected-record-api.md)
- [Selected Blob API](quickstart/selected-blob-api.md)
- [Language quickstarts](quickstart/README.md)
- [Application recipes](application-recipes.md)
- [Carriers and contacts](transports.md)
- [Binding design pattern](bindings/pattern.md)
- [C ABI reference](../bindings/c/README.md)
- [Go binding reference](../bindings/go/README.md)
- [Python binding reference](../bindings/python/README.md)
- [Non-production binding fixture](../bindings/testdata/README.md)

## Concepts, protocol, and security

- [Core concepts](concepts.md)
- [Selected production-lane architecture](architecture.md)
- [Protocol specification](protocol.md)
- [Envelope and security-object specification](envelope.md)
- [Wire grammar](wire.cddl)
- [Security model](security.md)
- [Classical P-256 / Iroh-QUIC security profile](classical-iroh-security-profile.md)
- [Security-profile requirements disposition](implementation/security-profile-requirements-disposition.md)
- [Compatibility and deprecation policy](deprecation-policy.md)
- [Source requirements](../data-mesh-requirements.md)

## Validation and evidence

- [Capability roadmap and merge-review model](implementation/capability-roadmap.md)
- [Production implementation requirements status](implementation/requirements-status.md)
- [Conformance and acceptance](conformance.md)
- [CI and local validation](ci.md)
- Retained live-application receipts: [Event](implementation/evidence/selected-live-event-c464129.json),
  [State/Record convergence](implementation/evidence/selected-live-mutable-6cabb4c.json),
  [State durable delivery](implementation/evidence/selected-live-state-subscription-8912fc3.json),
  [Record durable delivery](implementation/evidence/selected-live-record-subscription-0c11344.json),
  and [Blob](implementation/evidence/selected-live-blob-044d90f.json)
- [Fuzzing guide](../fuzz/README.md)
- [Lab guide](../lab/README.md)
- [Reconciliation FOSS bake-off](reconciliation-bakeoff.md)
- [Requirements-first FOSS evaluation record](evaluations/0005/README.md)
- [Selected FOSS reference-stack validation](evaluations/0006/README.md)
- [Public development provenance record](provenance/independent-development-record.md)
- [Public source register](provenance/public-source-register.csv)

## Proposals and results

Proposals scope experiments. They do not change the protocol or establish a
capability claim until a later decision and implementation evidence do so.

- [Proposal index and lifecycle](proposals/README.md)
- [0001 — Operational IP mesh vertical-slice experiment](proposals/0001-ip-mesh-vertical-slice.md)
- [0001 result — LAN mesh proven; operational IP profile not selected](proposals/0001-ip-mesh-vertical-slice-results.md)
- [0002 — Provider-neutral mesh host and focused rust-libp2p profile](proposals/0002-provider-neutral-mesh-host.md)
- [0002 result — Host contract retained; rust-libp2p profile not selected](proposals/0002-provider-neutral-mesh-host-results.md)
- [0003 — Idiomatic IP mesh provider comparison](proposals/0003-idiomatic-ip-mesh-provider-comparison.md)
- [0003 activation — Provider comparison execution plan](proposals/0003-idiomatic-ip-mesh-provider-activation.md)
- [0003 result — No provider selected; refactor durable node ownership first](proposals/0003-idiomatic-ip-mesh-provider-results.md)
- [0004 — Shared-node rust-libp2p retest](proposals/0004-shared-node-libp2p-retest.md)
- [0004 result — Provider-free Gate H retained; no provider selected](proposals/0004-shared-node-libp2p-retest-results.md)
- [0005 — Requirements-first FOSS architecture evaluation](proposals/0005-requirements-first-foss-architecture-evaluation.md)
- [0006 — Selected FOSS reference stack build and validation](proposals/0006-selected-foss-reference-stack.md)

## Architecture decisions

The specifications define behavior. These records explain why the current
design chose its major boundaries.

- [0001 — Standards and provider boundaries](decisions/0001-standards-and-provider-boundaries.md)
- [0002 — Dependency admission](decisions/0002-dependency-admission.md)
- [0003 — FIPS production gate](decisions/0003-fips-production-gate.md)
- [0004 — Radio-silence semantics](decisions/0004-radio-silence-semantics.md)
- [0005 — Deterministic codec](decisions/0005-deterministic-codec.md)
- [0006 — SQLite store](decisions/0006-sqlite-store.md)
- [0007 — IP and BTLE links](decisions/0007-ip-and-btle-links.md)
- [0008 — Local-agent phasing](decisions/0008-local-agent-phasing.md)
- [0009 — Public API boundary](decisions/0009-public-api-boundary.md)
- [0010 — Authenticated Blob transfer](decisions/0010-authenticated-blob-transfer.md)
- [0011 — Recipient-filtered rekey](decisions/0011-recipient-filtered-rekey.md)
- [0012 — Content-committing post-quantum batches](decisions/0012-content-committing-pq-batches.md)
- [0013 — Protected provisioning boundary](decisions/0013-protected-provisioning-boundary.md)
- [0018 — age X25519 provisioning-provider pilot](decisions/0018-age-provisioning-provider.md)
- [0022 — No IP mesh substrate selected from Proposal 0001](decisions/0022-ip-mesh-experiment-no-selection.md)
- [0023 — Retain the mesh-host contract without selecting rust-libp2p](decisions/0023-mesh-host-contract-no-libp2p-selection.md)
- [0024 — Refactor durable node ownership before selecting an IP provider](decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md)
- [0025 — Requirements-first FOSS architecture evaluation](decisions/0025-requirements-first-foss-architecture-evaluation.md)
- [0026 — Scope lock-only Hickory advisories](decisions/0026-lock-only-hickory-advisories.md)
- [0027 — Bound the active libp2p pilot dependency exceptions](decisions/0027-libp2p-pilot-dependency-policy.md)
- [0028 — Start the selected-stack implementation behind an isolated profile](decisions/0028-selected-stack-implementation-boundary.md)
- [0029 — Close Proposal 0004 without selecting rust-libp2p](decisions/0029-close-proposal-0004-libp2p-pilot.md)
- [0030 — Admit a bounded Event-first local ConnectRPC agent](decisions/0030-event-first-local-connect-agent.md)
- [0031 — Keep live tour presentation separate from raw receipts](decisions/0031-live-tour-presentation.md)
- [0032 — Keep interactive Event exploration separate from acceptance tours](decisions/0032-interactive-event-message-playground.md)
- [0033 — Select security properties through authenticated mission profiles](decisions/0033-policy-selected-security-profiles.md)
- [0034 — Use short-lived Iroh mDNS only for nearby evaluation](decisions/0034-short-lived-iroh-nearby-discovery.md)
- [0035 — Introduce Aster through staged Field Notes](decisions/0035-field-notes-human-introduction.md)
- [0036 — Admit discovered LAN peers through mission authentication](decisions/0036-mission-authenticated-lan-discovery-mvp.md)
- [0037 — Measure the flat LAN ceiling before adding hierarchy](decisions/0037-bound-concurrent-lan-scale-baseline.md)
- [0038 — Select an Event bridge foundation before the live hierarchy](decisions/0038-select-an-event-bridge-foundation.md)
- [0039 — Compose a static Event hierarchy over semantic v6](decisions/0039-compose-a-static-event-hierarchy-over-semantic-v6.md)
- [0040 — Bound a generated hierarchy scale diagnostic](decisions/0040-bound-generated-hierarchy-scale-diagnostic.md)
- [0041 — Harden the local Event agent for customer operation](decisions/0041-customer-operable-event-service.md)
