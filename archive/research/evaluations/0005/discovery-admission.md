# Discovery and runtime admission arm

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

Status: **complete bounded policy arm; automatic discovery remains open**

Authority: `data-mesh-requirements.md` only, SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Current Aster compatibility received zero weight, and no product architecture or
product source was inspected. No new public source was needed: this arm uses the
registered exact connectivity graphs and execution in BVB-746 through BVB-780,
plus the task-authored evaluator registered by BVB-798, compile-corrected by
BVB-800, and hostile-input-hardened by BVB-805.

## Outcome first

Treat discovery as a **thin, replaceable address-hint responsibility**, not as
the mesh, membership, authorization, or security layer. Buy the selected
connectivity candidate's native provider identity, address type, authenticated
carrier, and native/platform discovery mechanics. Keep one small common policy
gate above it for emission mode, provisioned identity intent, current
membership, bounded candidate retention, stale/duplicate suppression, dial
backoff, and optional operator bootstrap.

This deletes a standalone discovery protocol and a second authentication
session. An advertisement is only an untrusted hint. It cannot authorize data,
assert mission membership, or become durable peer truth. The required binding
is local:

```text
untrusted provider/address hint
        -> bounded candidate
        -> candidate-native mutually authenticated carrier identity
        -> provisioned mission identity plus current membership decision
        -> application exchange admitted
```

The previous single-host automatic-discovery result is still unresolved. Iroh
produced the expected identity/address hint but the discovered dial timed out.
rust-libp2p emitted no matching mDNS event. The fixed Quinn/mdns-sd control
resolved no address. The policy evaluator does not convert any of those results
into a pass.

The selected-stack follow-on now implements the official Iroh provider behind a
default-off feature for an exclusive, maximum-30-second demo/evaluation window.
It accepts only a pre-provisioned carrier-to-mission roster, publishes no Aster
mission or application metadata, and tears down on expiry, shutdown, or a move
away from normal emission policy. A separately selected invitation route
remains the zero-idle, multicast-blocked baseline; there is no silent fallback.
This is implementation of the bounded evaluation seam, not closure of the
automatic-discovery result. See
[nearby-discovery-selection.md](nearby-discovery-selection.md).

## What the exact candidates can buy

| Responsibility | Iroh 1.0.3 arm | rust-libp2p 0.56.0 arm | fixed Quinn 0.11.11 control |
|---|---|---|---|
| Provider identity | Native `EndpointId` | Native `PeerId` authenticated by Noise | Exact certificate identity under rustls mTLS |
| Manual target | Native `EndpointAddr` | Native `Multiaddr` plus expected peer | `SocketAddr` plus custom provisioned certificate map |
| Local automatic mechanics | Separate exact Iroh mDNS lookup provider; partial run | Native mDNS behavior; failed run and exact graph has two hickory-proto blockers | `mdns-sd` primitive plus evaluator-owned TXT schema; failed run |
| Authentication before application frames | Passed bounded provider-auth slice | Passed bounded provider-auth slice | Passed bounded mTLS slice |
| NAT/direct upgrade and connection relay | Candidate owns static mechanisms; runtime open | Behaviors instantiated but inert; runtime open | Missing from the fixed composition |
| Mission admission, emission, stale/duplicate, and hostile bounds | Common residual policy | Common residual policy | Common residual policy, plus more discovery composition |

Iroh remains the conditional leading buy for this responsibility because it is
the only arm that emitted the expected native discovery hint and it owns the
widest connected NAT/relay surface. It does not earn automatic-discovery credit
until a real discovery-to-authenticated-delivery chain passes. rust-libp2p stays
an oracle until the exact advisory-blocked graph is repaired. Quinn remains the
narrow control: `mdns-sd` is a useful primitive, but the host still owns the
schema, lifecycle, provider binding, NAT, and relay composition.

Do not add another general membership/discovery stack merely to repair the
single-host mDNS result. First run the native mechanisms on a topology where
multicast is known to work. If the selected native provider still fails, replace
only the advertisement adapter; keep the common admission gate unchanged.

## Candidate-neutral executable policy

BVB-798 freezes a standard-library-only Rust evaluator with one local package,
zero registry packages, zero Git sources, and zero path dependencies. BVB-800
preserves the first no-credit compile stop. BVB-805 prevents rejected
over-limit addresses from refreshing candidate age and proves that a saturated
automatic table does not remove the provisioned manual fallback. The final
release binary SHA-256 is
`dbbf97994ecbce6f26470ce3be942fa0ca97c61c030aa690e78a9c8bbfefb695`
at 405,888 bytes on the research host.

Two unit tests, format checking, and Clippy with warnings denied passed. The
nine-case binary ran twice and emitted byte-identical 1,299-byte results,
SHA-256
`dca920d27e26d20ca032315954d622e1d6af400e67b1076b0e4b2bbc58f89151`.

The cases prove only evaluator semantics:

1. A provisioned manual target remains usable with no bootstrap service.
2. Only an explicitly configured operator bootstrap name is queried or
   accepted; unconfigured infrastructure is ignored.
3. Constrained and receive-only modes originate no discovery advertisement,
   active query, or dial action, while the policy still permits an inbound
   carrier/authentication observation and ingestion.
4. A discovered provider claim grants no admission; exact two-way carrier-auth
   observation must match the provisioned provider binding.
5. One hundred identical hints retain one address, schedule no dial inside an
   eight-tick backoff, and expire after a locally measured 30-tick lifetime.
6. Unique admitted-provider hints were varied at 1, 16, 128, 1,024, and 4,096.
7. One hundred thousand unknown-provider hints retain zero candidates; one
   hundred thousand addresses claiming one known provider retain four.
8. A full candidate table can create at most two concurrent dial actions.
9. Ephemeral discovery hints and authenticated-session state do not silently
   become restart authority.

The constants—128 candidates, four addresses per candidate, 192 address bytes,
two dial tasks, 30 lifetime ticks, and eight backoff ticks—are **evaluation
points**, not requirements or elimination thresholds. Around the provisional
100-node-per-scope quantity, the retained-candidate curve was:

| Offered unique provisioned identities | Retained | Capacity drops |
|---:|---:|---:|
| 1 | 1 | 0 |
| 16 | 16 | 0 |
| 128 | 128 | 0 |
| 1,024 | 128 | 896 |
| 4,096 | 128 | 3,968 |

This is a structural state bound, not a memory benchmark. At most 98,304 bytes
of retained address text fit under the chosen constants, but container,
provider-ID, roster, allocator, parser, and task memory were not measured. The
caller had already allocated each synthetic hint; therefore the 100,000-hint
cases do not prove ingress-parser, CPU, RSS, or allocation resistance. A
first-come cap also bounds damage rather than preventing starvation: an attacker
who can spoof provisioned provider references can occupy the table and force
availability loss. Fair scheduling, reservations, rate limits, and telemetry
remain policy work.

## Emission and authentication boundary

The evaluator's “no outbound action” result means no **discovery-originated**
advertisement, query, automatic dial, or manual dial. It is not a claim of zero
packets. A real inbound mutually authenticated QUIC, TCP/Noise, or BTLE session
can require acknowledgements and handshake traffic. The requirements combine a
“radio-silent receive-only” mode with inbound synchronization, so physical
acceptance must define which link and transport-control emissions are permitted.
Only packet capture and carrier instrumentation can close that ambiguity.

Likewise, the evaluator accepts a `MutualAuthObservation`; it does not perform
cryptography. BVB-767 proves a narrow provider-auth carrier slice and wrong-peer
rejection. It does not prove pre-mission mission identity lifecycle, scope
authorization, revocation, rekey, hybrid/FIPS cryptography, metadata protection,
source-object security, or durable replay protection.

Duplicate and stale advertisements are scheduling hints only. Repeated hints do
not create unbounded retained work, and old hints are pruned using local
monotonic age rather than wall-clock truth. A captured advertisement replayed
after expiry can become a hint again. It still cannot authorize data, but it can
cause another bounded dial. `DM-6-23` freshness therefore receives no credit.

## Requirement disposition

| Requirement | Result | Exact boundary |
|---|---|---|
| `DM-5.7-01` automatic discovery | Open | No candidate completed advertise → discover → authenticate → deliver. Synthetic hints grant no credit. |
| `DM-5.7-02` manual peering | Met for connectivity slice | All three exact arms passed provisioned local manual delivery without infrastructure; not full conformant sync. |
| `DM-5.7-03` discovery emission | Partial | Common policy suppresses discovery-originated actions; no packet/radio-silence result. |
| `DM-5.7-04` pre-exchange mutual authentication | Partial provider slice | Carrier mechanisms and exact binding gate passed; mission security lifecycle remains outside this arm. |
| `DM-5.4-15/17/18` constrained and receive-only behavior | Partial policy | Fixed action matrix and logical inbound admission passed; no priority threshold, real inbound sync, or physical silence. |
| `DM-5.6-02`, `DM-5.8-10` infrastructure-free local operation | Met for connectivity slice | Manual local carriers needed no server, public service, or relay. |
| `DM-6-23` freshness/replay | No credit | Stale hints are bounded, not cryptographically replay-protected. |
| `DM-9-09A` controlled RAM | Structural partial only | Retained counts are bounded; no RSS, allocator, parser, or task measurement. |
| `DM-9-21` provisional per-scope scale | Decision curve only | Hint-table counts are not mesh scale and 128 is not a requirement threshold. |

The detailed atomic mapping is preserved in
[`requirements-map.csv`](../../../../docs/evaluations/0005/requirement-maps/discovery.csv).

## Delete/delete/delete disposition

Buy:

- the selected candidate's provider identity, manual address representation,
  carrier lifecycle, and authenticated connection;
- its native or platform-native mDNS/BTLE advertisement implementation after a
  physical acceptance pass; and
- self-hosted/operator-configured lookup or relay mechanics only when required,
  with manual/local operation remaining independent.

Keep bespoke, but small and wire-free:

- a three-mode discovery emission gate;
- the local provider-identity → mission-identity/current-membership binding;
- bounded ephemeral candidates, addresses, dial tasks, backoff, and stale
  pruning;
- fairness and observability under spoof/flood conditions; and
- an explicit allowlist for optional operator-owned bootstrap infrastructure.

Delete:

- a custom mDNS/DNS-SD or BTLE advertisement packet protocol;
- discovery as a durable peer database;
- advertisement-carried topic, scope, priority, or mission authorization;
- a second authentication handshake above a candidate-native authenticated
  carrier; and
- any required public discovery or relay service.

## Remaining physical/runtime acceptance

The next valid run is not another policy simulation. It is a common real-adapter
corpus on at least two distinct hosts or devices:

1. With no public service and no relay, complete native automatic advertisement
   through authenticated opaque delivery; repeat on multicast-enabled and
   multicast-blocked IP networks and verify manual fallback in the latter.
2. Capture both normal and constrained/receive-only runs. Prove advertisement
   suppression and state exactly which handshake, acknowledgement, and
   transport-control emissions remain.
3. Flood the real parser/provider with unknown identities, spoofed known
   identities, duplicate addresses, semantic address aliases, stale replays,
   and connect failures while measuring RSS, CPU, file descriptors, tasks, and
   recovery of a provisioned manual peer.
4. Exercise optional operator-owned bootstrap with the service absent, lost,
   restarted, stale, and malicious; local/manual operation must remain usable.
5. Run BTLE advertising and discovery on physical target platforms under the
   same admission and silence policy.
6. Keep NAT hole-punch and connection-relay topologies in the connectivity arm;
   this discovery policy grants no NAT or relay credit.

Until those pass, discovery is architecturally isolated and its common policy
is bounded, but `DM-5.7-01` remains open.

Evidence summary:
archived `summary.json`.
