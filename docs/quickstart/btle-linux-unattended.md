# Unattended Linux BTLE Event evaluation

This runbook exercises two provisioned Linux nodes, one controller and one
mission peer per process, and semantic-v9 Event data. The transport-neutral
node starts before its Linux/BlueZ supervisor and remains usable while BTLE is
absent. This is evaluation, not a production deployment.

This explicit-controller evaluator remains separate from the packaged agent.
The current local agent may retain prepared optional BTLE custody and register
a `BLE_L2CAP_V1` lane, but that lane is fixed `Unavailable`, never selected,
and performs no BlueZ, Bluetooth, or controller work. Package sources specify
a custody-only tmpfiles anchor; the base service does not bind the BTLE roster
or gain `AF_BLUETOOTH` or Linux capabilities, and the package adds no BlueZ,
D-Bus, or Polkit policy. This does not prove that the service identity cannot
reach the system bus. The disposable-VM package assertions have not been
executed, and this runbook does not close the automatic-controller,
support-matrix, exact-confinement, or physical production gates.

## Modes and limits

- `--transport fixed`: exact provisioned peer address/type and PSM.
- `--transport rostered`: authenticated transient discovery and a
  kernel-allocated listener PSM.

Modes are explicit and mutually exclusive. Failure never starts the other mode
or an IP carrier. There is no pairing workflow, automatic controller choice,
multi-peer operation, daemon mode, State/Record/Blob transfer, requirement
credit, support promise, or production authorization.

The lower complete 32-byte mission `NodeId` initiates; the higher listens. This
Linux role rule is not protocol behavior and there is no `--role` option.

## Prerequisites and build

Each host needs:

- its own mission bundle and owner-only state directory;
- the exact peer mission `NodeId`;
- one controller name, exact local address, and LE address type; and
- a compatible Linux kernel, BlueZ, controller, and LE L2CAP CoC driver.

Fixed mode additionally needs exact peer address/type and PSM `0x80`–`0xff`.
Rostered mode needs the shared `ASTRBD02` discovery artifact and independent
nonzero 32-byte deployment-scope ID.

Clean restart requires a kernel containing the fix for
[CVE-2026-72333](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/ffaa1b4ec1ea8813a90a5a6f9f577958c848a33c/cve/published/2026/CVE-2026-72333.mbox).
Linux 6.18.21–6.18.39 are affected; 6.18.40 is the first fixed 6.18 release.
Qualify the installed distribution source/backport, not only `uname` output.

```console
cargo build --locked \
  -p aster-ble-linux -p aster-agent -p asterctl \
  --bin aster-btle-event --bin aster-agent --bin asterctl
```

## Prepare durable application state

The receiver must have an exact durable `Consume` subscription before contact;
the publisher Event must already be committed. An initialized state directory
is bound to its canonical path and filesystem, so do not copy it after first
open.

An embedding should prepare both through retained application handles. For a
standalone run, prepare the receiver with a peerless loopback agent:

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

After `AGENT status=ready`, in another terminal:

```console
target/debug/asterctl --token-file /owner-only/receiver/client.token \
  subscribe \
  --journal /owner-only/receiver/subscriber.redb \
  --client-id btle-evaluation-consumer/v1 \
  --scope EVENT_SCOPE \
  --operation-key btle-evaluation-consume/v1 \
  EVENT_TOPIC
```

Stop the agent cleanly before starting `aster-btle-event` against the same
state. Prepare the publisher through its Event API or the
[Android quickstart's peerless procedure](btle-android-ring1.md#publish-the-linux-event-before-contact).
The loopback agent is a preparation/query tool, not a BTLE dependency or
fallback.

## Run fixed mode

Start with controllers detached or powered off to prove node readiness without
BTLE. On each host substitute its local and peer values:

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

Use `random` where observed. Cadence accepts 1–86,400 seconds and defaults to
60; it is implementation policy, not a wire or performance value.

## Run rostered mode

Rostered mode has no peer address/type or PSM. Both nodes bind a dynamic
listener, advertise its authenticated PSM, and scan. The lower mission
`NodeId` opens the newest recent proof-valid candidate; the higher admits only
a recently observed inbound locator. The mission handshake still authenticates
the exact configured peer before Event work.

The evaluation-only credential file must be an effective-UID-owned, mode-0600,
one-link regular `ASTRBD02` artifact. It is read once through the credential
authority; raw secrets are never command-line or environment values.

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

Fixed mode rejects rostered options and rostered mode rejects fixed peer
locator options. Credential expiry drains the rostered epoch and parks the
adapter; it does not trigger fallback or stop local durable operations.

## Attach controllers and verify Event delivery

Attach or power each exact controller using the normal host procedure. The
evaluator does not mutate controller state. Expected transitions include:

```text
BTLE_EVENT status=available
BTLE_EVENT status=contact-complete offered=N fetched=N inserted=N
```

Fixed mode also reports the derived opening/listening role. Rostered mode does
not print transient locators or PSMs. A matching address or discovery proof is
only locator evidence; mission authentication remains mandatory.

Require the source contact to offer the Event, the receiver contact to fetch
and insert it, and a later contact to report zero offered/fetched/inserted work.
Confirm the application receipt after shutdown; contact counters alone are not
convergence evidence.

To exercise controller recovery, remove or power off one controller during an
open or active contact. The current attempt must drain with no overlap. Restore
the same controller and require a fresh epoch, successful contact, and later
zero-work contact without restarting the process.

## Clean shutdown and restart

Send SIGINT or SIGTERM. Require `BTLE_EVENT status=stopped` and process exit.
With stock BlueR, this proves only local RAII/handle release; it does not prove
BlueZ unregistration, RF cessation, or a bounded upstream D-Bus ingress queue.
`cleanup-unconfirmed` is failed evidence. When cleanup is under evaluation,
inspect BlueZ and RF state separately before restarting and record that as an
external observation, not an Aster-proven result.

For clean restart, leave controllers powered and make no peer, trust, pairing,
advertisement, or controller change. Start fresh processes with the same mode
and configuration and require `status=contact-complete` on both sides. A BlueZ
ACL or listener advertisement alone is not success.

If the open times out with `Bluetooth: Unable to allocate ident: -28`, the
kernel is affected by CVE-2026-72333. Do not add peer disconnect, controller
reset, or power mutation as Aster recovery.

## Verify the durable application result

After evaluators stop, reopen the receiver with the peerless loopback agent and
query the exact selector:

```console
target/debug/asterctl --token-file /owner-only/receiver/client.token \
  --json query \
  --topic EVENT_TOPIC \
  --scope EVENT_SCOPE \
  --limit 2
```

Require exactly one Event whose ID and payload bytes/digest match the source
publication. A preceding zero-work contact plus this result is bounded durable
deduplication evidence.

## Evidence and claim boundary

Retain source/artifact identity; Linux, kernel, BlueZ, controller/firmware, and
driver versions; mode, address types, PSM, role, MTUs, Event size, cadence;
availability/contact/recovery/shutdown timestamps; application receipt; and
sanitized cleanup/resource observations. Keep addresses, mission IDs, paths,
credentials, and payloads out of shared records.

See the concise [Ring-1 Event](../validation/evidence/2026-11-05-cm4-btle-ring1-event-validation.md),
[affected-kernel diagnostic](../validation/evidence/2026-11-06-cm4-btle-clean-restart-diagnostic.md),
and [fixed-kernel restart](../validation/evidence/2026-11-06-cm4-btle-clean-restart-validation.md)
summaries. One hardware stack does not qualify another, and this procedure does
not establish discovery support, multi-peer/controller operation, other data
classes, packaging, performance thresholds, or production readiness.
