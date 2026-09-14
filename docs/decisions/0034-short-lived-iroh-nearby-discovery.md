# Decision 0034: Use short-lived Iroh mDNS only for nearby evaluation

> ****

- Status: Accepted for a default-off demo/evaluation profile
- Date: 2026-08-28
- Authority: [data-mesh-requirements.md](../../data-mesh-requirements.md)
- Related: [Decision 0028](0028-selected-stack-implementation-boundary.md) and
  [nearby discovery selection](../evaluations/0005/nearby-discovery-selection.md)

## Context

The selected Iroh runtime deliberately disables hosted address lookup, public
relays, and port mapping. Operators currently provision every peer's carrier
identity, socket address, and independent mission identity. Discovery should
remove locator entry without becoming a membership, authorization, or second
authentication protocol.

Continuous mDNS has material traffic, energy, and hostile-cardinality concerns.
The exact native and control comparators have also not completed an automatic
discovery-to-authenticated-delivery path on retained evidence.

## Decision

1. Keep discovery absent from default builds and default runtime behavior.
2. Add the official iroh-mdns-address-lookup 0.5.0 provider behind the
   nearby-discovery feature.
3. Accept nearby peers only as an exact, provisioned
   EndpointId-to-mission-NodeId roster. Discovery supplies no identity or
   authority.
4. Allow one exclusive provider for a whole-second window from 1 through 30
   seconds. Enforce that deadline inside the carrier session as well as the
   selected-node composition.
   Reject direct peer routes, controlled relays, and non-normal emission policy
   in the same configuration.
5. Publish direct carrier addresses only, set no lookup user data, use no
   public/default relay or hosted directory, and clear the entire lookup
   registry at expiry and shutdown.
6. Preserve an explicit invitation route for multicast-blocked environments.
   Presentation must name the selected route and must never silently fall back.
7. Keep DM-5.7-01 open until two physical hosts retain the complete
   advertise-to-authenticated-delivery chain and resource/hostile-input
   qualification.

## Consequences

- A demo user can select nearby lookup without entering socket addresses.
- Mission metadata and content stay out of DNS-SD records, but on-link carrier
  identity, address, presence, and traffic shape remain observable.
- The short lifetime bounds exposure duration, not upstream hostile
  allocations. The provider remains unsuitable for production until those
  maps are capped and measured.
- Iroh offers only whole-registry clear, not provider-specific removal. This
  is safe only while selected endpoints start with an empty registry and nearby
  mode is exclusive.
- Invitation mode has no recurring discovery traffic and remains the reliable
  one-host introduction. It is a locator exchange, not authorization.
