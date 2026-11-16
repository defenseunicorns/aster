# BTLE Ring 1 evaluation profile

- Status: bounded physical evidence; no requirement credit, support row, or
  production approval
- Owner: Aster implementation owner
- Review date: 2026-11-05
- Semantic boundary: selected semantic v9 with v1–v8 compatibility bytes
- Carrier: initial `BleL2capV1`; official Ring-1 exit remains Linux-only

## Outcome

Validate that the selected node carries one protected Event over a non-IP LE
L2CAP CoC contact while preserving offline-first publication, mission-only
authorization, v9 negotiation, and durable deduplication. This is engineering
evidence for the carrier seam, not a supported deployment.

## Fixed Linux topology and bounds

- Two provisioned Linux Tier-2 nodes; one initiator and one listener.
- One controller, exact peer address/type, and LE PSM per process.
- Iroh disabled for this peer; no alternate carrier or fallback.
- `HybridPqAsterRecordV1` (`0x0001`) only; profile `0x0002` is rejected before
  inventory. Pairing and link encryption grant no authority.
- One session CoC, one active serialized turn, and no Blob DATA/CONTROL pair.
- Protected frame at most 2 MiB; complete contact at most 8,192 frames, 3,500
  items, and 64 MiB.
- Authenticated progress deadline 30 seconds; transient locator 1–256 bytes;
  overlapping session operations fail closed.
- Event payload exceeds the smaller negotiated directional MTU. Negotiated MTU
  is an observation, not a supported floor.

Linux may reduce an unsuccessfully queued, previously unproven SDU size for the
current contact. That per-contact adaptation is not a protocol constant or a
cross-platform MTU claim.

## Android foreground extension

The evaluation-only Android initiator uses the public LE L2CAP CoC API and the
same mission, semantic-v9, Event, and durable-store path. Before Bluetooth work,
it durably commits or reuses one non-empty text Event of at most 1,024 UTF-8
bytes and prepares its exact durable subscription. The fixed Linux listener
prepares the complementary subscription and prints one newly inserted matching
Event as terminal-safe JSON.

The app is foreground-only, manually configured with Linux address and PSM, and
requests no scan, advertise, Internet, service, or receiver capability. One
preparation/contact operation is active at a time under the 30-second deadline;
the dedicated native preparation worker has an 8 MiB stack. These are
evaluation implementation bounds, not protocol or support guarantees.

The retained
[Android/Linux summary](evidence/2026-11-09-android-linux-btle-text-event-validation.md)
records warm-state bidirectional text/large-Event success on a Pixel 9 Pro XL
and a Realtek/Linux host. The same host's cold-controller path is unqualified:
inbound ACL data could precede HCI Connection Complete and be discarded by the
evaluated kernel. A mouse warm-up, controller reset, protocol fallback, or
kernel-version heuristic is not an Aster remedy. Reproduce the path with the
[Android quickstart](../quickstart/btle-android-ring1.md).

## Unattended Linux extension

`aster-btle-event` starts the transport-neutral node before its Linux/BlueZ
supervisor. It tolerates controller absence, observes lifecycle changes without
polling, derives complementary roles from complete mission `NodeId`s, owns at
most one open or active contact, and cancels/drains that contact before a new
controller epoch or node shutdown.

Fixed and rostered adapters are explicit and mutually exclusive; neither is
fallback for the other. Retry from 250 ms to 30 seconds and the default
60-second successful-contact cadence are local policy. Local publication stays
durable with no transport; the standalone evaluator exposes no application
endpoint.

The retained Linux evidence is deliberately split by claim:

- [Ring-1 Event summary](evidence/2026-11-05-cm4-btle-ring1-event-validation.md):
  protected 65,536-byte Event delivery, application receipt, deduplication, and
  controller-epoch recovery on two CM4 devices.
- [Affected-kernel diagnostic](evidence/2026-11-06-cm4-btle-clean-restart-diagnostic.md):
  restart failure on Linux 6.18.39 bound to CVE-2026-72333 L2CAP signaling-ID
  exhaustion, not Aster state.
- [Fixed-kernel restart](evidence/2026-11-06-cm4-btle-clean-restart-validation.md):
  zero-work process restart on Linux 6.18.60 without controller mutation; Event
  delivery was not repeated.

Clean-restart qualification requires a distribution kernel containing the fix
(6.18.40 is the first fixed 6.18 release) and a physical post-stop contact
without a controller epoch change. Aster adds no peer-wide disconnect,
controller reset, or version-string heuristic. Follow the
[Linux quickstart](../quickstart/btle-linux-unattended.md).

## Evidence required for this profile

- No inventory or Event data before mission authentication.
- Exact semantic-v9 profile offer and digest parity, including dormant Profile
  5 with zero Blob attempts.
- Physical Event delivery larger than negotiated MTU, disconnect/reconnect,
  controller loss/recovery, process restart, no silent loss, and no duplicate
  semantic delivery.
- Source/build identity, exact platform/controller versions, negotiated MTUs,
  sanitized receipts, application-level result, resource observations, and
  cleanup.

The retained records cover these only for their exact stacks and stated
limitations. They are not reproducible build provenance or reusable hardware
support rows.

## Exclusions

Production discovery qualification, multi-peer/controller operation,
duplicate-contact arbitration, production MTU floor, constrained-emission
qualification, State/Record/Blob execution, GATT, automatic carrier selection,
cross-transport fallback, daemon packaging, broad Android/Linux support,
performance thresholds, requirement credit, and production authorization
remain open.
