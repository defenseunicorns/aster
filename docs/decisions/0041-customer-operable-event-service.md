# Decision 0041: Harden the local Event agent for customer operation

> ****

- Status: Accepted for implementation; deployment and release gates remain open
- Date: 2026-09-05
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Supersedes: only the load-once, health, lifecycle, and local-security
  follow-on statements in [Decision 0030](0030-event-first-local-connect-agent.md)
- Related: [Decision 0009](0009-public-api-boundary.md),
  [Decision 0013](0013-protected-provisioning-boundary.md), and the
  [customer-operable Event-service design](../superpowers/specs/2026-09-05-customer-operable-event-service-design.md)

## Context

Decision 0030 intentionally selected an alpha loopback application agent. The
working Event surface already provides bounded authenticated publication,
query, durable subscription, polling, streaming, acknowledgement, deletion,
gap query, and status operations over the selected node. It does not yet define
the stable configuration, explicit health behavior, credential rotation,
process lifecycle, isolated local deployment, protected provisioning
integration, crash-oriented acceptance, or public failure contract needed for
customer operation.

The first customer MVP is narrower than the complete mesh roadmap. It is
single-scope and Event-only, admits exact peers manually, and permits at most
one customer-controlled pinned connectivity relay. It excludes multi-scope
forwarding, Event bridges, and dynamic bridge administration.

## Decision

1. Incrementally harden `aster-agent`. Do not add another daemon, database,
   journal, reconciliation engine, mesh protocol, or durable Event authority.
2. Add strict version-one JSON configuration and a side-effect-free
   `--check-config` mode. Reject unknown or duplicate fields, mixed legacy
   flags, State or Record interests, automatic LAN discovery, public/default
   relay selection, and multi-scope or bridge configuration.
3. Reuse `ProvisioningSecretRef`, `ProvisioningSecretLoader`, and
   `NodeConfig::open_secret_ref`. JSON points to an owner-only file containing
   the canonical secret reference; the customer binary supplies exactly one
   loader. The unprotected mission-file adapter remains development and
   migration only.
4. Require aggregate `StoreLimits` values and derive the global Event custody
   quota with `CustodyQuota::for_store_limits`. Do not add per-scope, bridge,
   or Blob-depot quota configuration in this MVP.
5. Retain loopback TCP for generated-client compatibility, but authenticate
   bearer headers before reading or decoding request bodies and enforce
   node-global bounds on unauthenticated connections, header bytes, and
   authentication time.
6. Support customer operation only in a dedicated network namespace containing
   the agent and its intended trusted application. Bearer authentication
   remains required. No unrelated sidecar, Service, host port, ingress, remote
   tunnel, or other listener exposure is permitted. Unisolated loopback use is
   development-only.
7. Add separate loopback, detail-free `/livez` and `/readyz` endpoints.
   Readiness represents the ability of the local durable Event authority to
   accept operations and does not depend on current network reachability.
8. Reload only the client bearer token on `SIGHUP`, from the same validated
   file, by atomic replacement. A failed reload retains the prior token and
   readiness state.
9. Define `Starting`, `Ready`, `Draining`, `Stopped`, and `Failed` lifecycle
   states. `SIGINT` and `SIGTERM` initiate bounded draining; deadline expiry or
   a second termination signal forces a distinct unsuccessful exit. Restart
   reopens the existing durable authority and preserves its recovery rules.
10. Preserve the existing Event RPCs, idempotency and acknowledgement
    semantics, redelivery rules, hard bounds, generated-client surface, and
    sole-authority architecture. Add only stable sanitized public reason and
    retry-guidance details.

### Direct dependency admission for pre-body serving

The pre-body gate and bounded application accept loop directly admit Hyper
1.11.0, hyper-util 0.1.20, and Tower 0.5.3, together with the helper crates
bytes 1.12.1, http 1.5.0, http-body-util 0.1.5, Tokio 1.53.1, and tower-service
0.3.3. Each is an MIT-licensed public crates.io dependency, and every admitted
version was already present transitively under the pinned ConnectRPC 0.9.0
dependency. These dependencies provide the generic Tower pre-body service
boundary, empty replacement and permit-owning response bodies, protocol-aware
Hyper connection serving, bounded timers and semaphores, and the Tower-to-Hyper
adapter. The custom accept loop is necessary because the pinned ConnectRPC
server's public serve method accepts `ConnectRpcService`, rather than a wrapped
generic Tower service where authentication can run before the network body is
polled or decoded.

## Ownership and acceptance

The Event-service workstream owns runtime configuration, pre-body
authentication, lifecycle, health, token reload, public errors, and black-box
process acceptance. The provisioning workstream owns concrete protected-loader
backends and credential lifecycle. The deployment workstream owns
service-manager artifacts, namespace and token-file isolation,
multi-architecture execution, packaging, and deployment acceptance. Security
and release owners qualify the combined customer profile.

The application quickstart is updated only after the runtime behavior exists,
so its commands continue to describe executable repository behavior.

## Consequences and claim boundary

- The ordered bridge increments remain their own capability lane and do not
  block this single-scope Event-service work.
- Health endpoints disclose lifecycle status only and carry no mesh authority.
- Loopback TCP plus bearer authentication alone is not a supported customer
  deployment; namespace isolation is mandatory for this profile.
- Logical item and payload limits do not claim total disk, redb overhead,
  process RSS, or complete cross-class lifecycle bounds.
- This decision authorizes implementation. It does not close protected
  provisioning, deployment, physical-network, mixed-implementation,
  packaging, security-review, or release gates.
