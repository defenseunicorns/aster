# BTLE Ring 1 evaluation profile

- Status: implementation profile; no requirement credit or production approval
- Owner: Aster implementation owner
- Review date: 2026-11-03
- Semantic boundary: exact selected semantic v9 with v1-v8 compatibility bytes
- Carrier: initial `BleL2capV1` implementation revision, Linux only

## Users and outcome

This profile validates that the selected node can carry one protected Event
over a non-IP LE L2CAP contact while preserving offline-first publication,
mission-only authorization, existing v9 negotiation, and durable deduplication.
It is engineering evidence for the carrier seam, not a supported deployment.

## Fixed topology and policy

- Two rostered Linux Tier-2 nodes with separately provisioned mission bundles.
- One provisioned initiator and one provisioned listener; no dynamic role.
- One explicitly configured controller, peer address/type, and LE PSM per node.
- Iroh contact disabled for this peer; no alternate carrier or fallback.
- `HybridPqAsterRecordV1` (`0x0001`) only. The classical Iroh-bound profile
  (`0x0002`) is rejected before inventory.
- Pairing and Bluetooth link encryption are not required and grant no authority.
- One session CoC; no additional DATA/CONTROL attempt channel is opened.

## Initial finite implementation bounds

- One active BTLE session and one serialized request/response turn per process.
- Protected carrier frame: at most 2 MiB.
- Complete contact accounting: at most 8,192 frames, 3,500 items, and 64 MiB,
  reusing the selected runtime's existing ceilings.
- Authenticated progress deadline: 30 seconds; each platform operation is
  cancelled or closed when its enclosing deadline expires.
- Transient locator: 1-256 bytes under the adapter-neutral contract.
- Queued session operations: one active operation; overlap fails closed.
- Controller recovery: process restart or explicit reconfiguration only.

These are evaluation ceilings, not production performance claims or a declared
minimum supported CoC MTU. The physical test records the actual negotiated send
and receive MTUs and sends an Event larger than the smaller value.

## Required evidence

- Deterministic framing, bounds, timeout, truncation, close, and mission-order
  tests, including no inventory or Event bytes before mission authentication.
- Exact v9 transfer-profile offer and digest parity, including dormant Profile
  5 with zero Blob attempt pairs.
- Two physical Linux targets: Event larger than negotiated CoC MTU,
  disconnect/reconnect, controller loss plus restart, and process restart with
  no silent loss or duplicate semantic delivery.
- Exact source/build identity, controller/kernel/BlueZ data, configuration,
  logs, resource observations, and cleanup receipt.

## Explicit exclusions

Discovery proof or grammar, dynamic roles, duplicate-contact reduction,
event-driven hot-plug, production MTU floor, constrained-emission qualification,
State, Record, Blob execution, GATT, cross-platform interoperability,
multi-controller operation, automatic carrier selection, downgrade resistance,
packaging, support rows, and production authorization are excluded.
