# Unattended Linux BTLE Event evaluation

This guide exercises the evaluation-stage Linux/BlueZ lifecycle around the
existing semantic-v9 ordered Event contact. It covers exactly two Linux
processes, one configured controller per process, one provisioned mission peer
per process, and Event data. It is not a production deployment guide.

The lifecycle runs in the same process as the transport-neutral node. The node
starts first and remains usable when BlueZ or the configured controller is
absent. The selected BTLE supervisor owns only its adapter, opens one contact
when possible, and drains before node shutdown.

## Boundary

The evaluator has two explicit, mutually exclusive adapters:

- `--transport fixed` retains the provisioned peer locator and PSM path; and
- `--transport rostered` uses a dynamic listener PSM plus authenticated,
  transient discovery records.

Neither adapter is fallback for the other. A rostered failure leaves that
adapter unavailable; it never starts the fixed adapter or any IP carrier.
There is no pairing workflow, automatic controller selection, multi-peer
operation, daemon mode, or State, Record, or Blob transfer. This does not
change the Aster protocol and grants no requirement credit, production
authorization, platform-support promise, or performance claim. The
Android/Linux Ring-1 procedure remains a separate fixed-locator evidence path.

## Prerequisites

Prepare two Linux hosts with:

- a separately provisioned reference mission bundle and owner-only state
  directory for each node;
- the other node's exact mission `NodeId`;
- one BlueZ controller name plus its exact local Bluetooth address and LE
  address type; and
- compatible Linux kernel, BlueZ, controller, and driver support for LE L2CAP
  connection-oriented channels.

Fixed mode also requires the exact peer address and address type plus one
unprivileged dynamic LE PSM (`0x80` through `0xff`) per process. Rostered mode
instead requires the shared discovery artifact and deployment-scope ID
described below; the kernel allocates its listener PSM.

Clean process restart additionally requires a kernel containing the fix for
[CVE-2026-72333](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/ffaa1b4ec1ea8813a90a5a6f9f577958c848a33c/cve/published/2026/CVE-2026-72333.mbox).
Affected kernels leak L2CAP signaling identifiers on LE flow-credit commands;
after exhaustion, a fresh CoC request uses invalid identifier zero and stalls.
Upstream records Linux 6.18.21 through 6.18.39 as affected and 6.18.40 as the
first fixed 6.18 release. Other stable series have different affected and fixed
versions. Bind qualification to the distribution's fix or source, not only its
version string, because vendors may backport the change.

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
  --transport fixed \
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

## Start the rostered discovery evaluator

Rostered mode removes the peer Bluetooth address, peer address type, and PSM
from configuration. Both nodes bind a backlog-one dynamic LE CoC listener,
advertise its authenticated PSM, and scan for the other node. The lower mission
NodeId opens the newest recent proof-valid candidate; the higher mission NodeId
admits only an inbound locator that it observed recently. The existing mission
handshake still authenticates the exact configured mission peer before Event
reconciliation.

Provision the same owner-protected discovery-group artifact and independent
nonzero 32-byte deployment-scope ID on both evaluation hosts. The artifact is
separate from mission identity and contains no command-line secret. This
unprotected-reference option is evaluation-only: the file must be an
effective-UID-owned, mode-`0600`, one-link regular file in the canonical
`ASTRBD02` artifact format. The evaluator reads it once through the host
credential authority and a private temporary checkpoint. It does not accept a
raw discovery secret through arguments or the environment.
The evaluator resamples paired wall and monotonic time every 60 seconds using
the same continuity rule as the production credential authority. A backward
step or divergence greater than five minutes cancels the adapter and requires
a fresh authenticated load; it never extends the loaded lease.

Run on each host with its local controller and the other node's mission ID:

```console
target/debug/aster-btle-event \
  --transport rostered \
  --adapter hciN \
  --local-address AA:BB:CC:DD:EE:FF \
  --local-address-type public \
  --state /owner-only/path/to/state \
  --mission-bundle /owner-only/path/to/mission.bundle \
  --mission-peer PEER_MISSION_NODE_ID_HEX64 \
  --discovery-scope-id DEPLOYMENT_SCOPE_ID_HEX64 \
  --discovery-credential-unprotected-reference /owner-only/path/to/discovery.credential \
  --contact-cadence-seconds 60
```

Do not provide `--peer-address`, `--peer-address-type`, or `--psm` in rostered
mode. Conversely, fixed mode rejects rostered credential options. Credential
lease expiry stops and drains the current rostered epoch; it is an unavailable
adapter condition, not invalid protocol data and not a fallback trigger. The
rostered supervisor then remains parked until shutdown or a future embedding
replaces it with freshly authenticated credentials. The transport-neutral node
continues serving local durable publication while the adapter is parked.

Configuration and mission provisioning are validated before node startup. A
valid process then starts its transport-neutral node before the BTLE
supervisor. While the controller is absent or powered off, fixed mode reports a
sanitized line such as:

```text
BTLE_EVENT status=unavailable reason=ControllerAbsent
```

The fixed category may instead report BlueZ unavailable, unpowered,
unauthorized, or an identity mismatch. Rostered mode currently exposes only
the coarse `BluezUnavailable` category for its complete private platform
epoch. Output does not include configured Bluetooth addresses, discovery
material, or mission identities.

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
BTLE_EVENT status=contact-complete offered=N fetched=N inserted=N
```

Fixed mode additionally reports `status=opening role=Initiator` or
`status=listening role=Listener`. Rostered mode does not expose transient peer
locators or dynamic PSMs in lifecycle output.

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
controller. The selected adapter drains the current owned work and reports an
unavailable category; no second attempt overlaps it. Fixed mode observes the
controller epoch directly. Rostered mode reconstructs its private BlueZ
advertisement, scan, listener, and candidate state after owned-platform loss.
Restore the same provisioned controller. A new adapter epoch can reconcile
retained Event work without restarting either node. After one successful
transfer, require a later contact to report zero offered, fetched, and inserted
Events. That second contact is bounded deduplication evidence. Wait for the
configured successful-contact cadence, or perform a second bounded controller
power-cycle after the successful transfer. The restoration that produced the
transfer is not itself the deduplication contact.

This source path and its deterministic tests implement that recovery. Retain a
bounded physical observation before treating a particular kernel, BlueZ,
controller, and driver combination as verified hardware.

## Clean shutdown

Send SIGINT or SIGTERM to each evaluator. Shutdown cancels and joins the BTLE
monitor and contact loop before shutting down the node. Expect:

```text
BTLE_EVENT status=stopped
```

Rostered shutdown allows owned platform cleanup 35 seconds. If it has not
completed, the supervisor explicitly closes its BlueZ D-Bus session to force
advertisement and discovery owner loss, then allows five more seconds for the
owned cleanup tasks to join. A successful forced path reports
`status=stopped owner_loss=forced`. If cleanup still cannot be proven within
the total 40-second bound, shutdown returns an error and reports:

```text
BTLE_EVENT status=cleanup-unconfirmed
```

Treat `cleanup-unconfirmed` as failed shutdown evidence; inspect BlueZ state
before restarting the adapter process.

The current Linux adapter also gives an admitted Event contact up to five
seconds to observe cancellation after the contact is closed. This matches the
owned BlueZ stop allowance and prevents a stuck admission task from retaining
expired discovery credentials indefinitely. It is an implementation safety
bound, not a wire-protocol deadline or a requirement on other transports.

In fixed mode only, after an owned contact has closed, its admission future has
drained, and the last supervisor-held contact reference has been dropped, the
evaluator emits one read-only peer-link diagnostic:

```text
BTLE_EVENT peer_acl=absent
BTLE_EVENT peer_acl=disconnected
BTLE_EVENT peer_acl=connected
```

Only one line is emitted after an opened-contact attempt drains. `unavailable`,
`timeout`, or `cancelled` can appear when the bounded BlueZ query cannot
complete. These are closed, sanitized categories: no adapter name, Bluetooth
address, or BlueZ error text is retained. The query never connects,
disconnects, removes, pairs, trusts, advertises, or changes controller state.

This diagnostic describes only BlueZ's view of the provisioned peer ACL at
that instant. `connected` does not mean an L2CAP channel exists, does not
authenticate the mission peer, and does not prove that an Aster contact can be
opened or reused. It grants no authority and cannot change node readiness or
retry behavior.

Verify with host Bluetooth tooling that the process left no advertisement or
listener. A forced process kill is not clean-shutdown evidence.

On the bounded CM4/BlueZ 5.82 observation, both evaluators stopped cleanly but
BlueZ continued to report the unpaired peer ACL as connected. Fresh processes
reached `Available` but timed out because affected Linux 6.18.39 had exhausted
its L2CAP signaling identifiers. The
[clean-restart diagnostic](../validation/evidence/2026-11-06-cm4-btle-clean-restart-diagnostic.md)
binds the invalid identifier-zero requests and kernel allocation errors to
CVE-2026-72333. Treat process-only recovery as unverified for a platform until
a retained run on a fixed kernel proves otherwise.

The evaluator deliberately does not disconnect the peer, reset the adapter, or
change controller power to hide this kernel state. Those actions can disrupt
other controller users, and `Device1.Disconnect` can disable future inbound LE
connections for an untrusted peer. The adapter also does not reject kernels by
parsing `uname`: a vendor backport can fix an older version string, while a
newer vendor build is not evidence without its package/source relationship.

## Clean process restart

After a successful or zero-work contact, stop both evaluators cleanly and
require `BTLE_EVENT status=stopped` plus process exit. Leave both controllers
powered and make no peer, trust, pairing, advertisement, or controller change.
For fixed mode, start the listener and then the initiator with the same
provisioned values. For rostered mode, start both explicit rostered adapters
with the same discovery inputs. Require another authenticated zero-work
contact. A listener advertisement or BlueZ `Connected` ACL alone is not
success; both sides must report `status=contact-complete`.

Retain the installed kernel package/source relationship to the CVE fix, the
exact evaluator digest, controller/driver/BlueZ versions, first post-restart
contact results, and cleanup. If the restarted open times out and the kernel
reports `Bluetooth: Unable to allocate ident: -28`, the platform is not a
clean-restart candidate until its kernel is fixed. Do not convert that failure
into an Aster peer-wide or controller-wide reset.

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
- selected adapter mode, configured address types, fixed or kernel-allocated
  PSM as applicable, derived role, negotiated send/receive MTUs, Event size,
  and cadence;
- timestamps for unavailable, available, contact start/completion, controller
  loss/restoration, and clean shutdown;
- proof that local publication committed before contact, plus application-level
  proof of later receipt and durable deduplication; and
- sanitized failure categories, resource observations, and cleanup receipt.

Keep exact Bluetooth addresses, mission node IDs, state paths, credentials, and
payloads in access-controlled local records. Redact them from shared logs and
reports. Evidence for one hardware/driver combination does not verify another.
