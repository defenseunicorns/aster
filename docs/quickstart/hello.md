# Aster Field Notes: the human hello

> ****

Aster Field Notes is a small, human-driven way to feel the offline-first mesh
instead of watching an automation claim that it worked. You activate named real
node processes, write durable notes through one node, take nodes offline, and
watch each exact Event appear through the other nodes' local application APIs.

Every run is a disposable three-node story:

    atlas --- beacon --- cove

Beacon makes store-and-forward movement visible. A note can begin at Atlas
before Cove exists, reach Beacon, and later reach Cove after Atlas sleeps.

## Start

Install the pinned tools and launch:

    mise install
    mise run hello

Field Notes asks how this run should obtain carrier locators. The choice is
explicit and never changes automatically:

- **nearby** opens official Iroh mDNS lookup for ten seconds whenever a node is
  added or woken. The runtime receives only the already-provisioned neighbor
  carrier IDs and mission IDs, never a socket address.
- **invitation** uses controller-known one-host loopback invitation routes.
  It requires no multicast and creates no recurring discovery traffic.

For a scripted or noninteractive launch, name the route:

    mise run hello -- --network invitation
    mise run hello -- --network nearby

Nearby is an evaluation mode, not the reliable default hidden behind a
fallback. If multicast is unavailable, exit and explicitly choose invitation.

## Tell the three-node story

No process is running when the prompt first appears. The disposable roster and
credentials exist, but you decide when each real node comes alive:

    field-notes> add atlas
    field-notes> note written before anyone else exists
    field-notes> add beacon
    field-notes> add cove
    field-notes> sleep atlas
    field-notes> use cove
    field-notes> note reply from the edge
    field-notes> wake atlas
    field-notes> status

The main commands are:

| Command | Effect |
|---|---|
| add NAME | Start the next pre-provisioned field node; names are atlas, beacon, and cove. |
| use NAME | Select the node used by the next note command. |
| note TEXT | Publish one durable Event through the selected running node. |
| sleep NAME | Stop that real process without deleting its store. |
| wake NAME | Restart it from the same retained store. In nearby mode this visibly opens another ten-second window. |
| status | Render the current constellation and exact observed-note matrix. |
| help | Show Field Notes and advanced playground commands. |
| quit | Stop and reap processes while retaining the disposable run directory. |

Advanced send, isolate/rejoin, wait-seen, assert-unseen, plain, and raw
interfaces remain available for deterministic exploration and tests.

## What the display means

A filled node means its process is ready. An edge becomes solid only from
authenticated contact observations. A note checkmark appears only after an
exact QueryEvents result from that node contains that exact Event. Time,
silence, topology, and presenter state are never converted into a delivery or
global-convergence claim.

The friendly names exist only in the controller and display. Nearby DNS-SD
records contain no name, mission NodeId, authority, topic, scope, priority,
membership, inventory, or message. They expose Iroh carrier identity, direct
address, presence, timing, and packet shape to the local network. That is
best-effort metadata minimization, not metadata secrecy.

The selected runtime still authenticates the exact Iroh carrier identity and
then performs the independent Aster mission handshake before inventory or
application data. Discovery is a locator hint, never authorization.

## Why discovery turns off

Continuous discovery is not free. An earlier continuous Iroh arm measured
55,258 bytes per node per minute and material idle CPU/memory, above its
provisional traffic screen. The upstream provider also has peer maps that are
not hostile-cardinality bounded. Field Notes therefore opens a visible
ten-second window, with a runtime hard maximum of 30 seconds, and tears the
provider down at expiry, shutdown, or a move away from normal emission policy.

An open QUIC connection can still exchange transport keepalives or
acknowledgements; closing discovery does not close an authenticated connection.
An idle open connection is not a promise of zero radio or battery cost.

See the [nearby discovery decision](../decisions/0034-short-lived-iroh-nearby-discovery.md)
for the alternatives, measured caveats, and physical qualification plan.

## Exact claim boundary

Field Notes is an evaluation-only, one-host, same-build, Event-only experience.
It uses one pre-provisioned three-member mission, one topic and scope,
all-content-member access, independent redb stores, and disposable
unprotected-reference credentials. Invitation routes are controller-known
loopback locators. Nearby mode exercises the selected lookup integration but
has not completed a retained two-host automatic-discovery acceptance run.

It does not establish global convergence, production discovery, physical or
multi-host networking, NAT traversal, BTLE, resource/energy limits, hostile
input resistance, protected operational provisioning, mixed implementations,
scale, release authorization, or an end-user messaging product.
