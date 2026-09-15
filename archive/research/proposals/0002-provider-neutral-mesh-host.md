# Proposal 0002: Provider-neutral mesh host and focused rust-libp2p profile


- Status: completed — host contract retained; rust-libp2p not selected
- Date: 2026-08-21
- Owner: Aster Clean Team — execution authorized in the designated project task
- Starting commit: `6d199d8176091360012dd8d5bcca1fd638248f7b`
- Requirements baseline SHA-256:
  `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Decision target: amend or preserve [Decision 0022](../decisions/0022-ip-mesh-experiment-no-selection.md)
- Related experiment: [Proposal 0001](0001-ip-mesh-vertical-slice.md)

## Question

Can Aster define the missing long-lived IP-mesh lifecycle once, prove it with a
deterministic provider-neutral state machine, and then use one minimal
rust-libp2p provider to satisfy manual peering, fair multi-contact scheduling,
reconnect/status, emission-linked discovery, and controlled direct/relay path
selection without replacing Aster identity, custody, synchronization, or
application semantics?

The result selects rust-libp2p for this boundary or keeps the existing
no-selection decision. It does not reopen the Iroh or Quinn arms.

## Accepted architecture boundary

The provider-neutral `MeshHost` owns:

1. bounded candidate and locator state;
2. automatic and manual candidate provenance;
3. Aster-authenticated candidate-to-NodeID bindings with expiry and fail-closed
   rebinding;
4. bounded concurrent contacts and fair contact quanta;
5. reconnect backoff, address changes, direct-first and relay-fallback policy;
6. discovery enablement derived from Aster emission policy; and
7. high-level candidate/contact status that makes no global convergence claim.

A connectivity provider owns listeners, dials, carrier authentication,
addresses, connection handles, and direct/relay path events. It exchanges only
bounded lifecycle events and actions with `MeshHost`.

The Aster runtime remains the sole authority for mission NodeID authentication.
A provider identity is supplemental channel evidence and never grants topic,
scope, content, or synchronization authority. Aster frames and application
data do not enter the host policy state machine.

## Focused dependency profile

Use the latest registry-published rust-libp2p aggregate release, currently
`0.56.0`, with exact pins and only the features needed by the executable lanes.

The Proposal 0001 `mdns` feature is removed. Its `hickory-proto 0.25.2` graph is
the source of `RUSTSEC-2026-0118` and `RUSTSEC-2026-0119`. LAN discovery instead
uses Aster's existing provisioned-token discovery as a separate candidate
source; libp2p supplies authenticated transport, the bounded Swarm, and Aster
streams. No public DHT, Gossipsub data path, or public infrastructure is used.

The `paste` unmaintained advisory is recorded rather than waived. It may remain
in a technical experiment, but a production selection is blocked until the
exact path is removed/replaced or a later decision records a time-bounded
maintenance disposition and update owner.

## Executable phases

### Phase A — contract

Mandatory deterministic fixtures:

- normal emission enables provider discovery; threshold and receive-only modes
  suppress it;
- manual peers remain available when automatic discovery is suppressed;
- receive-only accepts inbound contacts but initiates none;
- an expected manual NodeID mismatch is rejected;
- one carrier identity cannot be rebound to a different Aster NodeID;
- automatic candidates expire while manual peers persist;
- direct failure selects a configured relay locator and later retries direct;
- reconnect backoff is bounded; and
- 100 candidates receive opportunities with at most the configured active
  contacts and a service-count skew no greater than one.

### Phase B — one provider

Mandatory three-process lanes:

- automatic protected LAN discovery with no configured IP address or port;
- manual/pre-provisioned peering with discovery disabled;
- staged A→B, B restart, B→C custody and application acknowledgement using the
  original ItemID and EnvelopeID;
- B simultaneously authenticates A and C within its contact bound;
- address change and process restart reconnect without inherited carrier trust;
- emission-mode change disables discovery at the provider;
- direct locator failure selects an experiment-owned connectivity-relay path;
  relay loss causes bounded reconnect and direct-path reconsideration; and
- unauthorized Aster identity and carrier-identity reuse fail closed.

### Phase C — measurements

For a surviving provider, measure:

- stripped binary and incremental dependency/SBOM component count;
- net Aster custom code added and deleted at the replaceable host/IP boundary;
- ten-minute and one-hour idle CPU, RSS, traffic, tasks, descriptors, and
  wakeups;
- sustained 1 KiB, 64 KiB, and 1 MiB transfers with p50/p95/p99 custody and
  application-delivery latency;
- CPU-seconds and carrier bytes per useful MiB, separating discovery,
  connection, Aster authentication/reconciliation, and object data;
- 10- and 100-peer memory, queue, fairness, and reconnect high-water; and
- direct NAT, relay fallback, relay loss, and address-change success rates.

The deterministic 3 kbps/50%-loss gate must use a reproducible loss mechanism;
the unsupported `netem seed` syntax from Proposal 0001 is not retried as though
it were deterministic evidence.

## Pass, stop, and selection rules

- Every Phase-A fixture must pass before provider work is credited.
- Functional/security lanes require every scheduled repetition to pass; a
  single authorization, custody, identity, or redelivery violation fails the
  candidate.
- Missing tooling is `blocked`, not a semantic pass or failure.
- Resource measurements cannot compensate for a functional failure.
- A provider may be selected only if its exact dependency graph has no
  unresolved vulnerability and the result records any maintenance exception.
- Selection also requires demonstrated net mechanism reduction; wrapper LOC
  without deletion is not a buy-over-build benefit.
- If mandatory NAT/fallback, scheduling, emission, assurance, or rollback gates
  remain absent, preserve Decision 0022 and remove the experiment provider from
  the continuing default graph.

## Evidence and outcome

Commands, exact binaries, manifests, dependency audits, packet captures,
measurements, and failures are append-only project evidence. The final
result must update requirements traceability only for behavior actually
implemented and must produce a new decision selecting one provider or none.

## Outcome

Completed on 2026-08-21. The provider-neutral contract passed its deterministic
fixtures. The focused rust-libp2p profile failed clean trial 14 after 13 passes,
exceeded the idle-CPU gate, did not implement NAT/relay lanes, and produced no
net custom-mechanism reduction. No provider or dependency was admitted. See the
[full result](0002-provider-neutral-mesh-host-results.md) and
[Decision 0023](../decisions/0023-mesh-host-contract-no-libp2p-selection.md).
