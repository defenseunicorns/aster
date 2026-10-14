# Three-host trusted-LAN Event MVP


This quickstart exercises one evaluation-only path: three Aster Event nodes on
a real multicast-capable LAN discover one another without operator-supplied
peer IDs or socket addresses, then carry one Event from A through B to C across
two separate contacts. It also checks restart persistence at C and rejection
of D, a node provisioned by a different mission authority.

This is a try-it guide, not retained acceptance evidence. The discovery mode is
feature-gated, default-off, and limited to a trusted LAN. It does not establish
hostile-LAN resistance, physical qualification, NAT or WAN traversal,
production authorization, or support for State, Record, or Blob.

## Fast one-host Docker rehearsal

On a native Linux Docker Engine with the Compose plugin, run the complete
staged flow from the repository root with one command:

```sh
mise run lan-mvp-compose
```

The first run builds a discovery-enabled image; later runs reuse Docker's build
cache.

The controller creates fresh project-scoped state volumes, provisions A/B/C
under one authority and D under another, creates subscriptions with discovery
off, and publishes while A is isolated. It then proves the exact Event at B
after rosterless A/B discovery, correlates D's carrier ID with a mission-auth
rejection and empty application query, stops A and D, proves the same Event at
C through B, and finally force-recreates C without discovery to prove durable
local reopen. Clean `STOP` receipts and zero container exit codes are required
between phases. A finalizer removes only that run's containers, bridge,
volumes, and uniquely named image; Docker's build cache remains for the next
run.

This rehearsal passes no peer identity or address, but all four containers run
on one Docker bridge. It is a fast same-implementation development check, not
the three-host physical-LAN result below. Native Linux bridge multicast is the
supported rehearsal environment; Docker Desktop, alternative container VMs,
and networks that suppress multicast may not carry mDNS. There is no fallback
to static peers. Validate the Compose model without contacting the daemon with:

```sh
python3 tools/aster_lan_mvp_compose.py --config-only
```

## What you need

- Three Ubuntu 24.04 x86_64 hosts, A, B, and C, on the same multicast-capable
  layer-2 LAN. Use a fourth host for D, or run D on C's host while C is stopped.
- The same Aster checkout and Python 3 on every host. A host that builds the
  binaries also needs [Mise](https://mise.jdx.dev/) so it can install and use
  the repository-pinned Rust/Cargo toolchain.
- Bidirectional LAN reachability for mDNS multicast on UDP port 5353 and for
  the selected mesh UDP port. The commands below use UDP port 4433.
- A private way to move each provisioned node directory to its host while
  preserving owner-only permissions.

The application API stays on `127.0.0.1:8181`; do not expose it to the LAN.
Host firewalls and network equipment must pass IPv4 or IPv6 mDNS multicast and
the chosen mesh UDP port between these trusted hosts. Guest isolation, client
isolation, routed VLANs, and multicast suppression can prevent discovery.

## Build the discovery-enabled binaries

Run this from the repository root on each host, or build once and copy these
exact release artifacts plus `tools/aster_lan_mvp.py` to each host:

```sh
mise install
mise exec -- cargo build --locked --release \
  -p aster-node -p aster-agent \
  --features aster-node/nearby-discovery,aster-agent/nearby-discovery
python3 tools/aster_lan_mvp.py --help
```

The resulting binaries are `target/release/aster` and
`target/release/aster-agent`. A build without the feature does not expose
`--discover-lan`.

## Provision A, B, C, and outsider D

On one administration host, create a fresh three-member evaluation mission and
a separate mission authority for D:

```sh
ASTER_LAN_STAGE="$(mktemp -d)"
target/release/aster playground-init \
  --nodes 3 --root "$ASTER_LAN_STAGE/mission"
target/release/aster playground-init \
  --nodes 2 --root "$ASTER_LAN_STAGE/outsider"
```

Use `mission/node-0` as A, `mission/node-1` as B, and `mission/node-2`
as C. Use only `outsider/node-0` as D; the second outsider bundle exists
because `playground-init` requires at least two members. Move each whole node
directory to its assigned host and preserve its owner-only permissions. These
are explicitly unprotected reference bundles for evaluation, not protected
operational provisioning.

The provisioning output prints carrier and mission identifiers for audit, but
no peer identity or address is copied into a configuration or supplied to
discovery. The ABC bundles share mission authority and current authorization
material; D has a different authority. The operator supplies no neighbor
roster, carrier-to-mission binding, or network locator to `--discover-lan`.

On every host, name the received directory and create a separate owner-only
application bearer token. Substitute the local directory for that node. If D
shares C's host, keep two distinct directories such as `lan-node-c` and
`lan-node-d`, and complete this setup once for each directory:

```sh
ASTER_NODE_ROOT="$PWD/lan-node"
ASTER_APP_URL="http://127.0.0.1:8181"
python3 tools/aster_lan_mvp.py token \
  --file "$ASTER_NODE_ROOT/client.token"
```

These variables are intentionally shell-local. Repeat the two assignments in
every new agent or operator terminal before using the function or helper below.
For D on C's host, set `ASTER_NODE_ROOT` to D's separate directory in both of
D's terminals; never reuse C's root or token.

Use this shell function on each host to keep the agent command identical. It
takes optional discovery arguments after the common configuration:

```sh
run_aster_agent() {
  target/release/aster-agent \
    --state "$ASTER_NODE_ROOT" \
    --mesh-bind 0.0.0.0:4433 \
    --listen 127.0.0.1:8181 \
    --mission-bundle-unprotected-reference \
      "$ASTER_NODE_ROOT/mission.unprotected-reference.bundle" \
    --client-token-file "$ASTER_NODE_ROOT/client.token" \
    "$@"
}
```

Do not add `--peer` or `--nearby-peer`. `--discover-lan` rejects either
combination.

## Create durable subscriptions before any contact

Complete this step separately on A, B, C, and D. Start the agent with no
discovery arguments:

```sh
run_aster_agent
```

After `AGENT status=ready`, use another terminal on that host to create the
subscription. First repeat that node's `ASTER_NODE_ROOT` and `ASTER_APP_URL`
assignments in the new terminal. Give each node its own stable operation key
by replacing `A` below with `B`, `C`, or `D` as appropriate:

```sh
python3 tools/aster_lan_mvp.py subscribe \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --url "$ASTER_APP_URL" \
  --operation-key "demo/consume/A"
```

The helper defaults to topic `mesh.messages` and scope `demo/playground`, the
exact route provisioned by `playground-init`. Stop each agent with Ctrl-C after
its subscription succeeds. No node has contacted another yet.

## Phase 1: publish at isolated A

Keep B, C, and D stopped. Start A without discovery:

```sh
run_aster_agent
```

In A's second terminal, publish one Event and capture its canonical base64 ID:

```sh
python3 tools/aster_lan_mvp.py publication-init \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --journal "$ASTER_NODE_ROOT/publication.redb" --client-id lan-source-a

ASTER_EVENT_ID="$(python3 tools/aster_lan_mvp.py publish \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --url "$ASTER_APP_URL" \
  --journal "$ASTER_NODE_ROOT/publication.redb" --client-id lan-source-a \
  --logical-key message/1 \
  --payload 'hello from isolated A' \
  --id-only)"
printf '%s\n' "$ASTER_EVENT_ID"
```

Copy that Event ID into the operator shell on B and C for the later exact-ID
checks. It is an application receipt, not peer discovery configuration. Stop A
after publication. The application journal survives those agent restarts.
Initialize it once and preserve it with the stable client ID. The helper leaves
the numbered receipt retained; use `asterctl publication-recover`,
`publication-retry --sequence 1`, and `publication-ack --sequence 1` with the
same journal and identity to recover or finish the operation. A missing journal
must be repaired explicitly; it is not a reason to invent another client ID.

## Phase 2: A meets B while C is absent

Leave C stopped. Start A and B with automatic LAN discovery:

```sh
run_aster_agent --discover-lan --nearby-window 10
```

Start D with the same command on the fourth host, or on C's host while C is
still stopped. In the latter case, set `ASTER_NODE_ROOT` to D's separate
directory in both terminals before starting it or querying it. D advertises
and discovers like the other nodes, but its separate mission authority cannot
authorize an Aster contact with A or B.

The agents repeat bounded discovery windows, so the starts need not be
simultaneous. A discovered locator first appears as an untrusted candidate:

```text
DISCOVERY status=candidate ... authorization=pending-mission-handshake
```

A successful A/B contact has a `CONTACT` line with a `mission_peer` and
`status=pass`. D may complete carrier authentication, but its independent
mission handshake must produce `CONTACT ... status=error` before inventory.
Correlate those error lines with the carrier ID in D's own `READY` line; that
ID is an observation, never an input to another node.

On B, set the copied ID and require an exact application query match:

```sh
ASTER_EVENT_ID='PASTE_THE_ID_FROM_A'
python3 tools/aster_lan_mvp.py wait \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --url "$ASTER_APP_URL" \
  --event-id "$ASTER_EVENT_ID" \
  --logical-key message/1 \
  --wait-seconds 60
```

On D, this query must return no copy of `message/1`:

```sh
python3 tools/aster_lan_mvp.py query \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --url "$ASTER_APP_URL" \
  --logical-key message/1
```

Stop A and D. Keep B running. A must be absent before C starts; that makes B,
not a renewed A-to-C contact, the only available carrier for the next phase.

## Phase 3: B meets C, then C restarts

Start C with the same discovery command:

```sh
run_aster_agent --discover-lan --nearby-window 10
```

On C, use the ID copied from A:

```sh
ASTER_EVENT_ID='PASTE_THE_ID_FROM_A'
python3 tools/aster_lan_mvp.py wait \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --url "$ASTER_APP_URL" \
  --event-id "$ASTER_EVENT_ID" \
  --logical-key message/1 \
  --wait-seconds 60
```

After it succeeds, stop B, then stop C cleanly. Restart C without discovery or
any peer configuration:

```sh
run_aster_agent
```

Query the reopened local store:

```sh
python3 tools/aster_lan_mvp.py query \
  --token-file "$ASTER_NODE_ROOT/client.token" \
  --url "$ASTER_APP_URL" \
  --logical-key message/1
```

The returned Event must have exactly the same `id` captured at A. This final
query is local: A and B are stopped, and C was restarted without discovery or
a peer, so it demonstrates durable reopen rather than a fresh network fetch.

## Acceptance checklist

- No agent command contains `--peer`, `--nearby-peer`, a remote address, or a
  remote identity.
- C is stopped while A and B contact; A is stopped while B and C contact.
- A and B are both stopped before C's persistence restart.
- The exact Event ID published at A is returned by B, then C, then C again
  after restart.
- D was provisioned under a separate authority, produces no successful A/B
  mission contact, and its application query does not return the Event.
- Discovery candidate lines are not counted as delivery. Only the helper's
  exact-ID Event query establishes application presence.

## Bounds and non-claims

`--nearby-window` is a whole-second value from 1 through 30; its default is 10.
In `--discover-lan` mode the runtime opens repeated windows until shutdown or
until its emission policy is no longer Normal. Discovery publishes the Iroh
carrier ID and direct address hints, never mission identity, mission authority,
topic, scope, membership, inventory, or application payload. On-link presence,
carrier identity, address, timing, and packet size remain observable.

The runtime retains at most 32 outbound locator candidates from automatic
discovery and at most 32 distinct mission-authenticated identities for
automatic admission before inventory. It runs at most 16 inbound contact
workers and 16 outbound contact workers concurrently. Those are separate
bounds: they are not a global cardinality cap on discovered or inbound
carriers, and they do not bound what the upstream mDNS implementation can
observe and retain. This mode therefore makes no hostile-LAN or
resource-exhaustion claim.

Carrier authentication does not authorize mission data. A candidate must pass
the existing hybrid-PQ mission handshake and current mission authorization
before inventory or application exchange. That proof is scoped to the same
contact; this MVP does not bind it to a TLS exporter and does not prove common
ownership of the carrier and mission keys.

This flow uses unprotected reference provisioning and local bearer tokens. It
does not establish protected provisioning, physical-network evidence,
independent interoperability, NAT/WAN discovery or traversal, global
convergence, resource/soak qualification, or release authorization. See
[Carriers and contacts](../transports.md) and
[ADR 0036](../decisions/0036-mission-authenticated-lan-discovery-mvp.md) for the
design boundary.
