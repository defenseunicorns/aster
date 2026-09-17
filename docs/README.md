# Aster documentation

Start with the [project README](../README.md) for Aster's purpose, current
implementation boundary, and quickest working examples. This page maps the
current product documentation; historical plans, designs, and research are not
part of the normal reading path.

## Start here

1. Read [Core concepts](concepts.md) for items, topics, scopes, data classes,
   and contacts.
2. Run [Aster Field Notes](quickstart/hello.md) for a human-driven introduction
   or the [capability tour](quickstart/capability-tour.md) for deterministic
   local observations.
3. Choose an application path: the
   [local ConnectRPC agent](quickstart/connect-agent.md), the selected Rust
   [Event](quickstart/selected-event-api.md),
   [State](quickstart/selected-state-api.md),
   [Record](quickstart/selected-record-api.md), or
   [Blob](quickstart/selected-blob-api.md) API, or the
   [language bindings](quickstart/README.md).
4. Read [Architecture](architecture.md), [Security](security.md), and
   [Carriers and contacts](transports.md) before changing deployment or network
   boundaries.

## Current documentation map

| Area | Current documents |
|---|---|
| Protocol | [Protocol](protocol.md), [wire grammar](wire.cddl), [security objects](envelope.md), [classical Iroh profile](classical-iroh-security-profile.md), and [deprecation policy](deprecation-policy.md) |
| Application APIs | [Application recipes](application-recipes.md), [ConnectRPC agent](quickstart/connect-agent.md), [selected Rust APIs](quickstart/README.md), [agent configuration](reference/aster-agent-config-v1.md), and [binding pattern](bindings/pattern.md) |
| Implementation | [Architecture](architecture.md), [Security](security.md), [Carriers and contacts](transports.md), and component README files under `crates/` |
| MVP operation | [Operator runbook](mvp/linux-event-mvp-runbook.md) and [credential-provider operations](mvp/raspberry-pi-provider-v2-operations.md) |
| Validation | [Validation and readiness map](validation/README.md) for capability planning, requirements trace, conformance, the Linux Event MVP profile, and retained evidence |
| Customer feedback | [Customer feedback index](customer-feedback/README.md) for advisory input and separate product recommendation reviews; feedback is not requirements or evidence |
| Decisions | [`docs/decisions/`](decisions/) records the rationale for boundaries that still constrain the product; specifications and current references remain authoritative for behavior |

## Document authority

- `protocol.md`, `wire.cddl`, and `envelope.md` define profile `0x0001`
  interoperable behavior.
- The [classical Iroh profile](classical-iroh-security-profile.md) defines the
  additive evaluation-only profile `0x0002` boundary.
- The [requirements status](validation/requirements-status.md) is the
  evidence authority; the [capability roadmap](validation/capability-roadmap.md)
  is the planning and PR-review view.
- The Linux Event MVP profile and register define a bounded, non-production
  evaluation. They do not authorize a release.
- Code and tests are authoritative for implemented behavior when a guide
  becomes stale; fix the guide rather than relying on historical design notes.

## Contributing

Read [CONTRIBUTING.md](../CONTRIBUTING.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md) before changing Aster.
