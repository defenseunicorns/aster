# Nearby discovery FOSS selection


Status: **implemented for an explicit demo/evaluation profile; production
automatic discovery remains open**

## Outcome

Aster uses the official iroh-mdns-address-lookup 0.5.0 provider for one
short-lived **Find nearby** mode. It is default-off, feature-gated, limited to
30 seconds per process start, and available only under the normal emission
policy. The provider supplies ephemeral carrier address hints for carrier
identities that the mission roster already names. It never supplies membership,
authorization, or an Aster mission identity.

The universal low-idle bootstrap remains an explicit Iroh invitation route.
The hello experience labels invitation and nearby operation separately and
never silently changes from one to the other.

This selection implements a useful evaluation seam. It does not close
DM-5.7-01: the retained candidate comparator and a 2026-08-28 development
rerun did not complete nearby discovery through authenticated delivery.

## FOSS options considered

| Option | Use | Resource and operational posture | Decision |
|---|---|---|---|
| Iroh invitation / endpoint address | Human-mediated bootstrap with no idle discovery | No recurring discovery traffic; route includes an exact expected carrier identity | Keep as the reliable, explicit baseline and multicast-blocked fallback |
| Official Iroh mDNS provider | Local IP address hints for already provisioned EndpointIds | Native Iroh lookup integration, but active multicast while enabled and uncapped upstream peer maps | Implement only as a short-lived demo/evaluation mode |
| Platform/standard DNS-SD adapter (mdns-sd) | Possible future replacement for advertisement mechanics | Standard mDNS/DNS-SD semantics, but Aster would own more schema and lifecycle composition | Retain as an adapter candidate if the native provider fails physical qualification |
| Operator-owned Iroh DNS/Pkarr directory | Optional discovery across routed networks | Requires explicitly operated infrastructure and has a different privacy/availability boundary | Defer; never make it required for local/manual operation |
| Mainline DHT | Wide-area rendezvous | More traffic, state, metadata exposure, and public-network dependence | Opt-in research only |
| rust-libp2p mDNS / discv5 | Second carrier/discovery stack | Duplicates identity, session, dependency, and lifecycle ownership | Do not add to the selected runtime |
| Custom Aster mDNS/authentication protocol | Product-owned discovery packets and another trust path | Largest maintenance and security surface | Reject |

The detailed candidate results and the common admission policy remain in
[connectivity-comparison.md](connectivity-comparison.md) and
[discovery-admission.md](discovery-admission.md).

## Exact selected boundary

The selected runtime binds Iroh with address lookup, public/default relays, and
port mapping cleared. A discovery-enabled build may then install exactly one
Iroh mDNS lookup service for an operator-visible window:

    provisioned EndpointId -> ephemeral mDNS IP/port hint
                           -> Iroh TLS identity authentication
                           -> provisioned EndpointId-to-mission-NodeId binding
                           -> Aster mission handshake
                           -> reconciliation

Both the carrier session and selected-node configuration enforce a whole-second
window from 1 through 30 seconds, so retaining a raw session guard cannot turn
the provider into an indefinite background service.

The service uses the fixed aster-nearby-v1 DNS-SD label and publishes only
Iroh carrier identity plus direct IP transport addresses. Aster sets no Iroh
lookup user data. Node name, mission NodeId, authority, topic, scope, priority,
membership, inventory, and payload are not advertised. On-link observers can
still learn service presence, carrier identity, IP/port, timing, and packet
sizes; this is best-effort metadata reduction, not metadata secrecy.

Direct routes and a controlled relay are rejected when nearby mode is active,
so there is no implicit locator fallback. The runtime accepts only exact
pre-provisioned carrier identities, and successful carrier authentication still
precedes the independent mission handshake. The lookup registry is cleared
when the window expires, the node stops, or startup is cancelled.

## Cost and hostile-input limits

The earlier Iroh arm measured 55,258 discovery bytes per node per minute,
0.670% core utilization, and a 10.00 MB idle-memory delta, about 13.5 times the
proposal's provisional 4 KiB/min screen. Those measurements came from an older
continuous discovery arm and are not a prediction for the new ten-second hello
window. They explain why discovery is explicit and time-boxed rather than
always on.

The Iroh provider has bounded command/subscriber queues, but its peer map and
the underlying swarm-discovery peer map are uncapped. Aster bounds its roster
and provider lifetime, not allocations an attacker can cause inside those
upstream maps during the window. This prevents a production hostile-input or
memory claim. A production candidate needs upstream/forked cardinality caps,
early expected-ID filtering, packet/RSS/CPU/task/file-descriptor measurements,
and recovery tests under multicast flood.

An already-started QUIC attempt has its own connection deadline; clearing the
lookup registry does not retroactively cancel a dial that already received an
address.

## Current execution result

The registered comparator previously emitted an expected Iroh identity/address
hint but its authenticated dial timed out. On 2026-08-28 the current project
development host reran both exact local controls:

- Iroh manual direct delivery and wrong-identity rejection passed; its automatic
  mDNS case timed out before a discovery event.
- Quinn plus mdns-sd manual delivery and wrong-identity rejection passed; its
  automatic mDNS case resolved no address.

These are useful failure observations, not retained acceptance evidence. They
show why the hello experience offers a visibly selected invitation route and
why this PR does not move automatic-discovery status.

## Required qualification

Before production selection or requirement credit:

1. Run two physical hosts on a known multicast-enabled LAN and retain
   advertise → discover → carrier-authenticate → mission-authenticate → Event
   delivery evidence.
2. Repeat with multicast blocked and prove that only a human-selected
   invitation route is used.
3. Capture normal, constrained, and receive-only traffic and state which
   transport acknowledgements remain.
4. Measure bytes, CPU, RSS, battery/energy, tasks, and file descriptors across
   idle windows, peer churn, duplicate/stale hints, and hostile unknown IDs.
5. Add hard upstream cardinality/work bounds or replace only the advertisement
   adapter.

Until then, nearby discovery is a useful local evaluation capability and
DM-5.7-01 remains open.
