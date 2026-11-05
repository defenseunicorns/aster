# Unattended Linux BTLE Event evaluation

This guide exercises the evaluation-stage Linux/BlueZ lifecycle around the
existing semantic-v9 ordered Event contact. It covers exactly two Linux
processes, one configured controller per process, one provisioned peer per
process, and Event data. It is not a production deployment guide.

The lifecycle runs in the same process as the transport-neutral node. The node
starts first and remains usable when BlueZ or the configured controller is
absent. The BTLE supervisor observes controller availability, opens one contact
when possible, and drains before node shutdown.

## Boundary

This path has no discovery, pairing workflow, controller selection, transport
selection or fallback, multi-peer operation, daemon mode, or State, Record, or
Blob transfer. It does not change the Aster protocol and grants no requirement
credit, production authorization, platform-support promise, or performance
claim. The fixed-role Android/Linux and Linux/Linux Ring-1 procedures remain
separate evidence paths.

## Prerequisites

Prepare two Linux hosts with:

- a separately provisioned reference mission bundle and owner-only state
  directory for each node;
- the other node's exact mission `NodeId`;
- one BlueZ controller name, exact local and peer Bluetooth addresses and LE
  address types, and one unprivileged dynamic LE PSM (`0x80` through `0xff`)
  per process; and
- compatible Linux kernel, BlueZ, controller, and driver support for LE L2CAP
  connection-oriented channels.

The two mission node IDs must differ. The lower complete 32-byte mission node
ID initiates and the higher ID listens. This deterministic role choice is a
Linux implementation detail; it is not a protocol rule. There is no `--role`
option.

Build the evaluator:

```console
cargo build --locked -p aster-ble-linux --bin aster-btle-event
```

For the standalone preparation and query procedure below, also build the
existing loopback application tools:

```console
cargo build --locked \
  -p aster-agent -p asterctl \
  --bin aster-agent --bin asterctl
```

## Prepare standalone application state on each target

The ordered Event contact honors durable application selection; it does not
copy every Event merely because a transport became available. Prepare the
publisher and receiver state through application-owned handles before starting
the standalone evaluator:

- commit the evaluation Event in the publisher state; and
- create one exact durable `Consume` subscription in the receiver state for
  the Event topic and scope.

Create and first open each state directory on the target host. An initialized
store is deliberately bound to its canonical path and filesystem backing.
Copying an initialized state directory to another path or host is expected to
fail integrity validation. Evaluation credentials may be provisioned on the
target, or copied before that state is first opened, but every node still
requires its own mission bundle and identity.

An embedding should prepare both sides directly through its retained
application handles. For a standalone evaluation, a peerless loopback agent
can prepare the receiver without creating a mesh contact. Replace the paths,
topic, and scope below with the exact evaluation values:

```console
umask 077
openssl rand -hex 32 > /owner-only/receiver/client.token

target/debug/asterctl publication-init \
  --journal /owner-only/receiver/subscriber.redb \
  --client-id btle-evaluation-consumer/v1

target/debug/aster-agent \
  --state /owner-only/receiver/state \
  --mesh-bind 127.0.0.1:0 \
  --listen 127.0.0.1:8181 \
  --mission-bundle-unprotected-reference /owner-only/receiver/mission.bundle \
  --client-token-file /owner-only/receiver/client.token
```

After the agent reports `AGENT status=ready`, run in another terminal:

```console
target/debug/asterctl --token-file /owner-only/receiver/client.token \
  subscribe \
  --journal /owner-only/receiver/subscriber.redb \
  --client-id btle-evaluation-consumer/v1 \
  --scope EVENT_SCOPE \
  --operation-key btle-evaluation-consume/v1 \
  EVENT_TOPIC
```

Stop the agent cleanly and wait for it to exit before starting
`aster-btle-event` against the same state. The subscription is durable across
that restart. Prepare the publisher with its application-owned Event API or
the peerless publication procedure in the
[Android/Linux Ring-1 quickstart](btle-android-ring1.md#publish-one-event-while-linux-has-no-peer),
then stop that application process before starting the evaluator.

The loopback agent is only an evaluation preparation and query tool. It is not
a BTLE lifecycle dependency, fallback carrier, or daemon recommendation; it
does not participate in the BTLE contact or add another protocol path.

## Start with controllers unavailable

Leave both configured controllers detached or powered off. On each host, run
the evaluator with that host's values:

```console
target/debug/aster-btle-event \
  --adapter hciN \
  --local-address AA:BB:CC:DD:EE:FF \
  --local-address-type public \
  --peer-address 11:22:33:44:55:66 \
  --peer-address-type public \
  --psm 0x81 \
  --state /owner-only/path/to/state \
  --mission-bundle /owner-only/path/to/mission.bundle \
  --mission-peer PEER_MISSION_NODE_ID_HEX64 \
  --contact-cadence-seconds 60
```

Use `random` instead of `public` where provisioned. The cadence option accepts
1 through 86,400 seconds and defaults to 60. It schedules the next initiator
contact after a successful contact; it is not retry policy or a wire or
compatibility value.

Configuration and mission provisioning are validated before node startup. A
valid process then starts its transport-neutral node before the BTLE
supervisor. While the controller is absent or powered off, expect a sanitized
line such as:

```text
BTLE_EVENT status=unavailable reason=ControllerAbsent
```

The category may instead report BlueZ unavailable, unpowered, unauthorized, or
an identity mismatch. Output does not include configured Bluetooth addresses
or mission identities.

## Durable publication while BTLE is unavailable

Transport availability is not required for local durability. An embedding can
start `RunningNode` with `start_transport_neutral_node`, retain its
`SelectedEventHandle`, start `LinuxBtleEventSupervisor` second, and publish an
Event while the supervisor reports `Unavailable`. The successful publication
receipt records a local durable commit; it does not claim peer delivery.

`aster-btle-event` is a narrow evaluator, not a daemon or application service,
and exposes no external publication endpoint. With this standalone binary,
use Events already committed in its state. Use an in-process embedding or the
focused node integration test when the evaluation must create a new Event
while the controller is absent:

```console
cargo test --locked -p aster-node --lib \
  running_node_accepts_and_accounts_ordered_event_contacts -- --nocapture
```

That test starts transport-neutral nodes with no bound carrier sockets,
publishes durably before contact, then admits an adapter-neutral ordered
contact and verifies later semantic-v9 reconciliation. It does not access a
radio.

## Attach or power the controllers

Attach or power on each provisioned controller using the host's normal
operator procedure. The evaluator does not mutate controller state. It
subscribes to BlueZ events, validates the complete configured controller
identity, and starts one role-correct contact without restarting the process.

Expected sanitized transitions include:

```text
BTLE_EVENT status=available
BTLE_EVENT status=opening role=Initiator
BTLE_EVENT status=listening role=Listener
BTLE_EVENT status=contact-complete offered=N fetched=N inserted=N
```

If the receiver has no matching durable `Consume` subscription, an
authenticated contact can correctly complete with `offered=0`, `fetched=0`,
and `inserted=0`. That result proves the protected contact path only; it is not
an Event-transfer or convergence result.

A matching Bluetooth address is only locator evidence. The protected session
must also authenticate the exact provisioned mission peer before profile,
inventory, or Event work. Confirm the reconciled Event through the embedding's
application query or retained evaluation harness evidence; contact-complete
counters alone are not a global convergence claim.

## Power-cycle recovery

During an open or active contact, power off or detach one configured
controller. The current open/contact is cancelled and drained, availability
returns to an unavailable category, and no second attempt overlaps it. Restore
the same provisioned controller. A new availability epoch starts with fresh
peer backoff and can reconcile retained Event work without restarting either
node. After one successful transfer, require a later contact to report zero
offered, fetched, and inserted Events. That second contact is bounded
deduplication evidence. Wait for the configured successful-contact cadence, or
perform a second bounded controller power-cycle after the successful transfer.
The restoration that produced the transfer is not itself the deduplication
contact.

This source path and its deterministic tests implement that recovery. Retain a
bounded physical observation before treating a particular kernel, BlueZ,
controller, and driver combination as verified hardware.

## Clean shutdown

Send SIGINT or SIGTERM to each evaluator. Shutdown cancels and joins the BTLE
monitor and contact loop before shutting down the node. Expect:

```text
BTLE_EVENT status=stopped
```

Verify with host Bluetooth tooling that the process left no advertisement or
listener. A forced process kill is not clean-shutdown evidence.

On the bounded CM4/BlueZ 5.82 observation, both evaluators stopped cleanly but
BlueZ continued to report the unpaired peer ACL as connected. Fresh processes
reached `Available` but timed out until the receiver controller entered a new
power epoch. Treat process-only recovery as unverified for a platform until a
retained run proves otherwise. The evaluator deliberately does not disconnect
other controller users or change controller power to hide this platform state.
The exact observation is retained in the
[CM4 Ring-1 evidence record](../validation/evidence/2026-11-05-cm4-btle-ring1-event-validation.md).

## Verify the application receipt

After the evaluators stop and release their state, restart the same peerless
loopback agent against the receiver state. Query the exact selector locally:

```console
target/debug/asterctl --token-file /owner-only/receiver/client.token \
  --json query \
  --topic EVENT_TOPIC \
  --scope EVENT_SCOPE \
  --limit 2
```

Require exactly one Event. Compare its Event ID with the source
`publication.json`, then decode the query's Base64 payload and compare its
bytes or SHA-256 digest with the retained source `event.bin`. Stop the agent
cleanly. The query is local application proof; it opens no BTLE contact. A
preceding zero-work contact plus exactly one matching application result
demonstrates durable deduplication for this bounded run.

## Evidence to retain

For each bounded run, retain:

- source commit and build/toolchain identity;
- Linux distribution and kernel, BlueZ version, controller chipset/firmware,
  and kernel driver;
- configured address types, PSM, derived role, negotiated send/receive MTUs,
  Event size, and cadence;
- timestamps for unavailable, available, contact start/completion, controller
  loss/restoration, and clean shutdown;
- proof that local publication committed before contact, plus application-level
  proof of later receipt and durable deduplication; and
- sanitized failure categories, resource observations, and cleanup receipt.

Keep exact Bluetooth addresses, mission node IDs, state paths, credentials, and
payloads in access-controlled local records. Redact them from shared logs and
reports. Evidence for one hardware/driver combination does not verify another.
