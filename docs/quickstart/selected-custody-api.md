# Selected Event custody, priority, and constrained operation

The selected runtime applies source-authenticated priority and finite TTL to
Event and route-only Event custody. It also exposes aggregate logical-store
limits, exact-scope custody quotas, a minimum emitted priority, and receive-only
operation. State, Record, and Blob remain outside Event custody, priority, and
TTL pressure. Their independent semantic-v4/v5 lanes still run during `Normal`
and `AtLeast` contacts; `AtLeast` is an Event threshold only. `ReceiveOnly`
initiates or discloses none of those lanes. See the selected State, Record, and
Blob API guides for their application surfaces and limits.

Semantic v7 does not weaken this custody contract. When both peers negotiate
`EventPagesV1`, durable Events, tombstones, and finite-TTL non-tombstones use
receipt-free Event pages. Every finite entry carries session-authenticated
cumulative custody age and is checked for continuity, policy, and expiry before
send and during atomic receiver admission; it creates no peer lease, apply
result, suppression, or retry settlement. A v1-v6 peer retains the complete
`LegacyV6` custody path. ReceiveOnly discloses no local Event difference, but it
can accept bounded blind pages whose entries independently satisfy its interest,
route grant, local policy, and custody checks.

This is an additive configuration surface. Existing callers of `start_node`
retain durable Event publication, default store limits, and normal emission.
Use `start_node_with_forwarding` when an operator must set the Step 3 policy.

## Run the public example

The shipped
[`custody_application.rs`](../../crates/aster-node/examples/custody_application.rs)
opens a real generated mission with no peers, installs limits and one scope
quota, publishes an Immediate Event, reads the initial `AtLeast(Priority)`
policy, changes it to `Normal`, verifies the new revision, and shuts down.

```sh
mise install
ASTER_CUSTODY_ROOT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 2 --root "$ASTER_CUSTODY_ROOT/mesh"

cargo run --locked -p aster-node --example custody_application -- \
  "$ASTER_CUSTODY_ROOT/mesh/node-0" \
  "$ASTER_CUSTODY_ROOT/mesh/node-0/mission.unprotected-reference.bundle" \
  demo/mesh mesh.ping-pong --initialize-publication-journal
```

Initialize the private application journal once with the flag above. On later
runs, omit the flag and retain the same state directory and journal. Recovery
precedes publication; failed or uncertain work retains its full intent. A
completed run advances the numbered sequence without adding a client identity.

On Linux, the output reports `finite_ttl_ms=60000` and
`authenticated_ttl_ms=Some(60000)`. On other platforms the example states the
contract explicitly and uses a durable fallback:

```text
CUSTODY_APPLICATION finite_ttl=unsupported_on_this_platform,durable_fallback=true id=<64 hex characters> inserted=true authenticated_ttl_ms=None initial_policy=AtLeast(Priority) initial_revision=<n> updated_policy=Normal updated_revision=<n> observed_revision=<n> events=<n>
```

The fixture contains an explicitly unprotected reference mission bundle. It is
for a disposable demonstration, not operational provisioning or a network,
finite-TTL, or physical-emission test.

## Configure the bounded runtime

```rust,no_run
use aster_node::{
    CustodyQuota, EventEmissionPolicy, NodeConfig, SelectedForwardingConfig,
    StoreLimits, start_node_with_forwarding,
};
use aster_node::application::{Priority, Scope};

# async fn configure(config: NodeConfig, scope: Scope) -> Result<(), Box<dyn std::error::Error>> {
let limits = StoreLimits::new(20_000, 128 * 1024 * 1024)?;
let scope_quota = CustodyQuota::for_scope(scope, 2_000, 16 * 1024 * 1024)?;
let forwarding = SelectedForwardingConfig::new(
    EventEmissionPolicy::at_least(Priority::Priority),
    limits,
)
.with_scope_quota(scope_quota)?;

let running = start_node_with_forwarding(config, forwarding).await?;
let (policy, revision) = running.event_emission_policy()?;
assert_eq!(policy, EventEmissionPolicy::at_least(Priority::Priority));
assert!(revision > 0);

// A live change is atomic. Any in-flight contact using the older revision
// closes before another object-bearing frame can be written.
running.set_event_emission_policy(EventEmissionPolicy::ReceiveOnly)?;
running.shutdown().await?;
# Ok(())
# }
```

`StoreLimits` bounds logical retained rows and encoded bytes in the selected
store's accounted aggregate namespaces. It does not measure redb allocation,
filesystem blocks, snapshots, swap, backups, Blob-depot files, or the separate
selector, delivery, custody-ledger, and causal/frontier tables. Those tables use
their stated independent hard caps where defined; accepted-dot/frontier
accounting remains a separately documented open boundary. The store preserves a
separate bounded authority reserve;
ordinary data cannot consume the capacity promised to retained controls and
selected Event tombstones. An exact-scope `CustodyQuota` further limits ordinary
accepted and route-only Event custody for that scope.

Configuration is installed before readiness. Invalid, duplicate-conflicting,
or over-capacity state fails closed rather than starting with a partially
applied policy.

## Publish a finite Event

```rust,no_run
use aster_node::application::{
    EventPublishOptions, EventPublishRequest, Priority, Scope, SelectedEventHandle,
    Topic,
};

# async fn publish(events: &SelectedEventHandle, topic: Topic, scope: Scope) -> Result<(), Box<dyn std::error::Error>> {
let result = events
    .publish_with_options(
        EventPublishRequest {
            operation_key: b"example/finite-reading/v1".to_vec(),
            predecessor: None,
            topic,
            scope,
            priority: Priority::Immediate,
            logical_key: b"sensor-7".to_vec(),
            payload: b"ready".to_vec(),
            tombstone: false,
        },
        EventPublishOptions::finite_ttl_ms(30_000)?,
    )
    .await?;

assert_eq!(result.priority, Priority::Immediate);
assert_eq!(result.ttl_ms, Some(30_000));
# Ok(())
# }
```

`publish` remains the durable shorthand. `publish_with_options` adds an exact
positive TTL in milliseconds; zero is rejected. The TTL and priority are
inside the source-authenticated Event header. A relay or receiver cannot raise
priority, reset age, or extend lifetime without invalidating the object.

Finite custody is enabled only on Linux, where the selected runtime uses the
suspend-inclusive boot clock. Other targets continue to support durable
semantic-v3/v4/v5 custody, but finite publication fails closed until a suitable
suspend-inclusive clock and restart contract are integrated. This is not a
wall-clock timestamp protocol.

## Understand age and expiry

Each semantic-v3/v4/v5 hop carries a session-authenticated custody wrapper. It binds
the exact transfer, exchange, policy revision, prior cumulative age, local
clock sample, hop delta, source TTL, and source priority. The receiver verifies
that wrapper before its atomic custody admission.

- `age >= TTL` is expired. An expired Event is never advertised or sent.
- For a finite row, known elapsed residence is accumulated; duplicates can only
  raise the durable age lower bound. Every v3 send also authenticates a conservative
  `32 + ceil(exact sealed Event bytes / 1024)` millisecond finalization charge.
  A finite transfer is withheld if that charged age reaches TTL, and an actual
  overrun observed at the carrier-adjacent post-store sample abandons the frame
  before application bytes are written.
- A changed clock domain or arithmetic overflow makes finite age continuity
  unknown and sticky. The Event is withheld rather than guessed fresh.
- Durable Events and tombstones do not expire or charge idle local residence;
  their v3 wrappers retain the maximum authenticated age and add the per-send
  finalization charge.
- Expired or pressure-retired exact transfers leave permanent receiver fences,
  so identical source bytes cannot be resurrected by a selector change. The
  publisher must issue a new source revision.

Application query, gap, and poll paths run custody maintenance and perform a
final sender-visibility check before exposing plaintext. A finite Event that
crosses its boundary during the operation is withheld.

## Understand priority, retry, and pressure

The source-authenticated levels are `Routine`, `Priority`, `Immediate`, and
`Flash`. Eligible outbound Event work is ordered by priority, remaining TTL,
acceptance order, and exact identity. Retry delay is also priority-sensitive.
Per-contact work remains bounded; semantic v3 can close a lane with a protected
`EventLaneDeferred`/ack exchange and resume later. That lane-control exchange is
not a durable custody receipt.

The custody retry ledger retains at most 128 backoff hints. Higher priority
replaces lower priority first. At a full equal-priority ledger, a new send may
replace one deterministic inactive hint—preferring another hint owned by the
same peer—while the durable Event remains eligible. Active leases are never
replacement victims, so one peer cannot pin every Routine retry slot and block
all other peers.

A protected v3 apply result is receiver-relative. `Satisfied` intentionally
does not reveal whether Carry retained route bytes or Consume accepted content.
`ContentAcceptancePending` reveals only that this offered object is still
route-only despite Consume, removes any suppression receipt, and retains the
lease-created bounded retry/backoff while the exact item remains live and
retryable; expiry or retirement drains settlement without a retry or receipt.
For a still-live item, `Satisfied`, or authenticated normal common-set proof,
installs the sender-local suppression receipt. The send lease
binds that receipt to the receiver's protected opaque selector generation. A
Carry/Consume selector-mode change therefore permits one reoffer without
disclosing the new mode. An unchanged blind ReceiveOnly contact suppresses a
duplicate while its exact receipt remains retained; the bounded 262,144-hint
table may deterministically replace a receipt at saturation and permit a later
bounded duplicate offer.

Pressure fixes its candidate partition once at admission start. If the exact
scope is short, every same-scope candidate ranks ahead of every off-scope
candidate for that transaction; otherwise all candidates form one aggregate
cohort. Within each cohort, an expired row is removed regardless of priority.
Thus a simultaneous aggregate shortage can consume a same-scope live row before
an off-scope expired row. For ordinary Event/RouteEvent admission,
a live row is eligible only when its priority is strictly lower than the
incoming demand; equal- or higher-priority live rows are not displaced.
Emergency aggregate authority/control or selected-tombstone admission may
bypass only that live-priority cutoff. Eligible victims then use this exact
order:

1. same-scope cohort before off-scope when that scope was initially short;
2. expired rows within the cohort;
3. route-only rows before content-accepted rows;
4. lower priority;
5. nearer expiry;
6. older acceptance;
7. exact object key.

Protected live delivery, causal, tombstone, and equivocation rows are not
ordinary victims; absolute expiry may still retire them. This route-first
policy and the absence of State/Record/Blob custody
mean the implementation does **not** claim the broader requirement that every
store class always evicts the globally lowest priority first.

## Understand emission modes

| Policy | Contact initiation | Event/control object emission | Semantic-v4/v5 State/Record and v5 Blob | Authenticated inbound work |
|---|---|---|---|---|
| `Normal` | yes | every eligible priority | full interested mutable lanes plus v5 Blob work | accepted within policy and quota |
| `AtLeast(p)` | yes | only Events at or above `p`; required contact/control work continues | full interested mutable lanes plus v5 Blob work; `p` is Event-only | accepted within policy and quota |
| `ReceiveOnly` | no | no discovery or local inventory disclosure, control object, or Event object | zero State/Record/Blob interest, inventory, source, object, range, staging, promotion, or accounting | protected empty inventory replies and semantic-v3/v4/v5 blind-Event-offer acknowledgements/results may be emitted; bounded Event offers may be accepted within policy and quota |

The selected direct-Iroh endpoint disables hosted discovery in every mode;
`AtLeast` does not dynamically control discovery and still initiates configured
contacts. `ReceiveOnly` additionally forbids contact initiation.

`ReceiveOnly` is a protocol object-emission boundary, not physical RF silence.
An already accepted connection may still emit the mandatory authenticated
handshake, acknowledgement, and bounded result needed to ingest peer data. It
cannot initiate a configured contact, disclose its local inventory, or send a
local application/control object. A live policy revision is rechecked at every
object-bearing send and receive-commit boundary; a mismatch closes the contact.
Its protected Event interest includes an opaque selector generation so durable
receipts can detect a hidden receive-policy change; that number reveals a
change, not Carry/Consume mode or unrelated inventory.

## Compatibility and claim boundary

Finite Event custody requires semantic version 3, 4, or 5. Explicit version-1 and
version-2 sessions remain compatible with durable Event transfer only. The
protected lane-defer exchange, receiver-relative apply disposition, and
generation-scoped suppression-receipt accounting are v3-format mechanisms
inherited by v4 and v5; no
equivalent deterministic whole-contact partial claim is made for v1/v2.

The selected implementation covers Event and RouteEvent custody only. It does
not add State/Record custody; their cloneable live handles and separate
semantic-v4/v5 mutable reconciliation run outside this custody policy in `Normal`
and `AtLeast`, as do the live Blob application surface and semantic-v5 direct
Blob work. This guide adds no finite State/Record TTL or Blob custody/TTL/GC.
See the selected [State](selected-state-api.md),
[Record](selected-record-api.md), and [Blob](selected-blob-api.md) API guides for
those independent application boundaries.

This guide also makes no claim about cross-class priority eviction, physical
radio silence or media sanitization, protected provisioning, representative NAT
or Internet paths, controlled relays, BTLE, crash/power-loss recovery, scale,
mixed implementations, or release authorization. Current implementation and
validation boundaries are tracked in the
[requirements status](../validation/requirements-status.md).
