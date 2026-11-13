# Decision 0041: Harden the local Event agent for customer operation

> ****

- Status: Accepted for implementation; deployment and release gates remain open
- Date: 2026-09-05
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Supersedes: only the load-once, health, lifecycle, and local-security
  follow-on statements in [Decision 0030](0030-event-first-local-connect-agent.md)
- Related: [Decision 0009](0009-public-api-boundary.md),
  [Decision 0013](0013-protected-provisioning-boundary.md), and the
  [current agent operational contract](../../crates/aster-agent/README.md)

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

1. Incrementally harden the single deployable `aster-agent` component. Its
   customer Event service is an internal module over `SelectedEventHandle`, not
   a second daemon or executable. Keep process facilities such as bounded
   serving, lifecycle, health, signals, and credential access separate from
   the Event RPC adapter so later selected data types can reuse them without
   adding a generic runtime-selection or plugin framework in this MVP. Do not
   add another database, journal, reconciliation engine, mesh protocol, or
   durable Event authority.
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
11. Require restart-selected `normal` or `receive_only` Event emission. In
    receive-only mode the node remains locally ready and accepts authenticated
    inbound work, but initiates no contacts and discloses no local Event or
    control inventory/objects. This is zero transfer of locally held selected
    objects, not physical radio silence.
12. Extend authenticated status with configured/effective mode and audited
    aggregate-store, Event-operation, and pending-delivery capacity. Retain
    hard operation ceilings of 4,096 rows/524,288 bytes, with profile warning
    at 512 and profile stop boundary at 1,024; retain the delivery profile
    workload boundary of 256 and implementation hard ceiling of 262,144.
    Dedicated Event-operation hard-cap refusal is a distinct non-retryable
    public reason. No online operation-map reclamation is introduced.
13. In the Raspberry Pi reference 2026-06-18 evaluation composition (Debian
    GNU/Linux 13 (trixie), Raspberry Pi Compute Module 4 Rev 1.1, `aarch64`,
    kernel `6.18.39+rpt-rpi-v8`, systemd `257.13-1~deb13u1`, credential
    executable `/usr/bin/systemd-creds`, local `ext4`, and TPM2 excluded),
    statically link the first-party
    `aster-systemd-credentials` runtime loader for provider contract
    `aster-systemd-credential-store/v2` into the same `aster-agent`
    executable. `--config` selects only that loader. It opens the fixed
    `aster-provisioning.bundle` systemd service credential through
    `CREDENTIALS_DIRECTORY`, requires systemd's `secure` boundary (single-link
    regular file, effective service owner, exact `0400`, Linux `ramfs`),
    validates the provider envelope and canonical inner bundle, and completes
    protected bootstrap before state or either listener is opened. It invokes
    no credential CLI and has no runtime provider or plaintext fallback.

    The mode-`0400`/`ramfs` description remains the original accepted
    presentation. The exact systemd 257 profile additionally uses the narrowly
    pinned root-owned ACL/read-only-`tmpfs`/`noswap` presentation defined in
    the [2026-09-09 credential-presentation amendment](../validation/inputs/systemd-257-credential-presentation-amendment.md).
    That amendment requires separate Security and Deployment approval at E01
    and creates no generic Debian, `tmpfs`, or production support claim.

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

### Independent Go acceptance dependencies

The black-box customer-process acceptance additionally admits
`connectrpc.com/connect` 1.20.0 under Apache-2.0 and
`google.golang.org/protobuf` 1.36.11 under BSD-3-Clause as direct dependencies
of the isolated `conformance/agent-go` module. They are test and
interoperability evidence only: checked-in code is generated from the local
public schema with Buf 1.72.0 and exact-version local generator binaries. They
do not enter the Rust runtime, customer package, deployment lane, or protocol
authority. The final admitted module pins are in
[`conformance/agent-go/go.mod`](../../conformance/agent-go/go.mod), the local
generation recipe is
[`conformance/agent-go/buf.gen.yaml`](../../conformance/agent-go/buf.gen.yaml),
and [`tools/check-agent-go-generated.sh`](../../tools/check-agent-go-generated.sh)
reproduces and byte-compares the checked-in generated client.

### Bounded process-acceptance evidence

[`tools/check-aster-agent-process.py`](../../tools/check-aster-agent-process.py)
is the packaged-process contract and
[`conformance/agent-go/cmd/agent-smoke`](../../conformance/agent-go/cmd/agent-smoke)
is its separately generated Go client. One bounded same-host execution emitted
14 passing receipts: unsupported-schema and non-loopback application/health
refusals without state/listener effects; five readiness transitions; exact
all-field Event recovery after forced process loss; higher-attempt redelivery;
acknowledgement persistence; token reload; exact unary and stream drain
outcomes; and combined process/client canary absence. Exact token bytes and
mode were restored after the run.

This is bounded runtime and client evidence only. The packaged agent in that
run was the repository's explicitly unprotected test fixture. It is not a
customer provider, representative deployment, retained physical/mixed-network
result, supported-target package, independent server implementation, or
release authorization. The exact supported configuration and operational
semantics are documented in the
[`v1 configuration reference`](../reference/aster-agent-config-v1.md) and
[`Event agent quickstart`](../quickstart/connect-agent.md).

### D06 provider-lifecycle increment

The stacked D06 implementation adds provider contract
`aster-systemd-credential-store/v2` in
[`aster-systemd-credentials`](../../crates/aster-systemd-credentials/README.md).
Its canonical provider reference and zeroizing envelope bind one nonzero
generation, exact Aster secret reference, exact load-operation identifier, and
one validated `ASTRPB03` bundle. The production customer invocation constructs
the systemd loader directly; missing, weak, insecure, changed, oversized, or
mismatched credentials fail through fixed sanitized categories before the
node can create state or bind health/application listeners.

The stacked implementation now includes the complete code-level provider
lifecycle: crash-recoverable install, atomic mission/provider rotation with one
retained Previous generation, host-bound backup, same-host current-generation
recovery through a narrow recovery open, and durable logical destruction. The
root administration CLI exposes five exact, operation-bound commands with
sanitized text output and a binary-only backup stdout. The
[operator procedure](../mvp/raspberry-pi-provider-v2-operations.md)
composes those commands with the existing Event-agent bearer-token SIGHUP
reload and stopped-authority revoke/rekey workflow to describe all seven
operations without duplicating either authority.

The five provider lifecycle CLI commands are executable, but code completion
does not make the Event-agent integration executable end to end or qualify the
provider candidate. The provider-internal Active reference remains root-only;
the future package must atomically hand successful INSTALL/ROTATE output to a
separate mode-`0600`, final-service-UID-owned reference file. Configuration
checking and runtime validation run as that final service UID, while provider
administration remains root-only. E01, packaged E09 qualification, the exact
handoff path and ownership setup, service UID, hardened unit/control values,
readiness check, native package integration, G3/G4, protected authority
issuance, cross-host recovery, snapshot rollback, physical erasure,
production, and general-platform support remain open. Persistent v1 provider
state is deliberately rejected rather than migrated.

## Ownership and acceptance

The Event-service workstream owns the Event module and its selected
`aster-agent` composition: runtime configuration, pre-body authentication,
lifecycle, health, token reload, public errors, and black-box process
acceptance. The provisioning workstream owns concrete protected-loader backends
and credential lifecycle. The deployment workstream owns service-manager
artifacts, namespace and token-file isolation, multi-architecture execution,
packaging, and deployment acceptance. Security and release owners qualify the
combined customer profile.

The application quickstart is updated only after the runtime behavior exists,
so its commands continue to describe executable repository behavior.

## Consequences and claim boundary

- The ordered bridge increments remain their own capability lane and do not
  block this single-scope Event-service work.
- `aster-agent` remains the only deployed service component. “Event service”
  names its selected internal application module and customer capability, not
  another process or independently persistent service.
- Focused process modules are reusable implementation units, but this decision
  does not promise runtime service selection, a plugin ABI, or simultaneous
  Event/State/Record/Blob application modules.
- Health endpoints disclose lifecycle status only and carry no mesh authority.
- Loopback TCP plus bearer authentication alone is not a supported customer
  deployment; namespace isolation is mandatory for this profile.
- Logical item and payload limits do not claim total disk, redb overhead,
  process RSS, or complete cross-class lifecycle bounds.
- Capacity status is an operator coordination surface, not automatic profile
  enforcement: the harness/operator stops work at the lower profile boundaries
  while the implementation hard ceilings remain fail-closed safeguards.
- This decision authorizes implementation. It does not close protected
  provisioning lifecycle, deployment, physical-network,
  mixed-implementation, packaging, security-review, or release gates.
