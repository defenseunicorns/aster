# Decision 0036: Admit discovered LAN peers through mission authentication

> ****

- Status: Accepted for the Event mesh MVP
- Date: 2026-08-31
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0030](0030-event-first-local-connect-agent.md) and
  [Decision 0034](0034-short-lived-iroh-nearby-discovery.md)

## Context

The existing nearby mode resolves addresses for an exact pre-provisioned list
of carrier and mission identities. That is useful locator discovery, but it
does not demonstrate a node discovering previously unknown mesh members. The
MVP must form a real IP LAN Event mesh without an operator supplying neighbor
addresses or identities.

The selected hybrid mission handshake already validates authority-issued
credentials and returns the authenticated remote mission identity. Carrier
identity and mDNS data are therefore unnecessary as membership assertions.

## Decision

1. Add a separate `--discover-lan` evaluation mode. A node receives only its
   own mission credential, its persistent carrier identity, and a mesh bind.
   It receives no per-neighbor carrier ID, mission ID, or socket address.
2. Advertise and browse the existing private Aster DNS-SD service using direct
   IP address hints only. Discovery metadata contains no mission identity,
   topic, scope, membership, or application data.
3. Treat every discovered carrier ID as an untrusted locator candidate. QUIC
   authenticates that carrier ID; the complete four-flight mission handshake
   then independently authenticates an authority-issued mission identity over
   that contact. Authorization uses only the mission result. No inventory or
   application frame is read or emitted before that succeeds.
4. Admit any active, non-revoked identity authenticated by the node's mission
   authority. A credential from another authority, malformed probe, or revoked
   mission identity fails the contact before inventory exchange.
5. Keep discovery work bounded at Aster's runtime boundary: retain at most 32
   outbound locator candidates and at most 32 authenticated mission identities,
   use the existing maximum of 16 concurrent inbound and 16 concurrent outbound
   contacts, scan in repeated windows of at most 30 seconds, and stop permanently
   if the Event emission policy leaves `Normal`. An authenticated inbound carrier
   need not already be present in the outbound locator set; this trusted-LAN mode
   therefore makes no global hostile-cardinality claim.
6. Preserve exact rostered nearby discovery and direct routes as separate
   modes. Dynamic LAN discovery cannot be combined with either of them or with
   controlled relay routing.

## MVP acceptance

The operator flow must demonstrate with three separately persisted nodes:

1. start on real IP interfaces with no peer arguments and discover/authenticate
   one another;
2. reject a fourth node provisioned by a different mission authority before
   inventory exchange;
3. publish an Event at A while C is absent, retain it at B, then deliver it from
   B after A is stopped and C starts; and
4. restart C and query the same durably retained Event.

Focused seam and process tests are the development loop. The full repository
check runs once after the coherent increment, not after each edit.

An opt-in Docker Compose controller rehearses this staged acceptance shape on
one native Linux bridge, including outsider correlation and peerless C reopen.
That shortens the developer loop but does not satisfy the real-host acceptance
condition or create retained physical evidence.

## Claim boundary

This is a trusted-LAN, Event-first MVP. The selected upstream mDNS provider has
bounded delivery channels but does not impose a hard global bound on every
peer it observes internally, so this decision does not claim hostile-LAN
resource-exhaustion resistance or production discovery qualification. It also
does not claim routed-WAN rendezvous, NAT traversal acceptance, global
convergence, or automatic trust establishment. Mission trust is provisioned;
neighbor identities and addresses are not.

The selected hybrid record profile is not bound to the QUIC TLS exporter. Its
carrier and mission identities are therefore same-contact observations, not a
durable proof of common ownership or a reusable carrier-to-mission trust
binding. A future exporter-bound profile may make a stronger claim.

## Consequences

- Three hosts can form a genuine discovered mesh without an external registry
  or manually exchanged peer coordinates.
- Discovery remains a replaceable locator mechanism, never an authorization
  database.
- The MVP can show offline store-and-forward and restart persistence with the
  existing durable Event and local ConnectRPC surfaces.
- Production discovery still requires a hard-bounded provider or an admitted
  upstream change plus physical hostile-input evidence.
