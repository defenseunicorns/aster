# BTLE Ring 1 evaluation profile

- Status: bounded Linux evaluation evidence retained; no requirement credit or
  production approval
- Owner: Aster implementation owner
- Review date: 2026-11-05
- Semantic boundary: exact selected semantic v9 with v1-v8 compatibility bytes
- Carrier: initial `BleL2capV1` implementation revision; official exit remains
  Linux-only

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
- Fixed-role Ring-1 controller recovery: process restart or explicit
  reconfiguration only. The separate unattended Linux/Linux extension below
  adds event-driven recovery without changing this physical-evidence profile.

These are evaluation ceilings, not production performance claims or a declared
minimum supported CoC MTU. The physical test records the actual negotiated send
and receive MTUs and sends an Event larger than the smaller value.

### Linux platform-write adaptation

The Linux adapter does not impose a fixed BTLE payload or SDU ceiling. Linux
segments one LE CoC SDU into peer-MPS-sized socket buffers and allocates the
complete SDU before queueing any byte. On the evaluated Pixel contact, a
65,535-byte negotiated send MTU combined with the Pixel's 247-byte peer MPS
could not fit one full-MTU SDU within the host's default 212,992-byte socket
send-memory budget, so the nonblocking platform write returned `EAGAIN` before
transmitting data.

The initial adapter implementation responds only to an unsuccessful,
previously unproven platform write by halving that contact's attempted SDU
size. Halving is binary backoff from the failed negotiated value, not a
protocol constant or supported-MTU claim: the observed first retry was 32,767
bytes, which queued successfully, and that proven size was retained through
ordinary backpressure. A peer that successfully queues the full negotiated
MTU is never reduced. This is why the evaluated CM4/Linux contacts needed no
extra bound: their negotiated MTU/MPS/socket-memory combination already queued
successfully. The behavior is per contact and makes no assumption about Pi,
PC, phone, or controller model.

## Optional Android foreground extension

The tree also contains an evaluation-only Android initiator scaffold and a
narrow Rust JNI adapter. It uses Android's public LE L2CAP CoC socket, bridges
the socket streams through a process-local Unix socket pair, and then runs the
same transport-neutral mission, v9 profile, Event, and durable-store path. The
local socket pair is an Android implementation detail, not a carrier or
fallback. Before requesting Bluetooth permission, inspecting adapter
availability, or opening a socket, the
native adapter idempotently commits or reuses a non-empty text Event of at most
1,024 UTF-8 bytes and prepares one private exact durable `Consume` subscription
through existing application APIs. The Linux harness prepares the complementary
exact subscription, snapshots the retained selector before contact, and prints
only a newer matching Android Event durably inserted by that authenticated
contact as one terminal-safe JSON string. This adds no
protocol or public configuration field: selectors, journal locations, and the
text bound are evaluation implementation policy. Local preparation is
cancellable and uses the existing 30-second foreground operation deadline for
the cooperatively asynchronous native lifecycle, including graceful node
shutdown. This is not hard preemption for a kernel-blocked syscall while JNI
joins the worker. The value matches the existing maximum foreground adapter
operation and remains
implementation policy. Full node/store preparation runs on one dedicated native
worker with an 8 MiB stack. The bound matches the conventional Linux and
existing native full-node test stack after a smaller Android JVM executor stack
overflowed on a Pixel during this path. It is a conservative implementation
bound, not a measured minimum or protocol field. Only one preparation can be
active, so one fixed virtual-memory reservation exists only for that operation;
the allocation does not scale with Event input. A successful text receipt has
zero remaining,
deferred-lane, and unscheduled Event work; a bounded partial contact retains
progress but must be retried. The app uses manual Linux
address/PSM input and requests no scan,
advertise, location, Internet, service, or receiver capability.

This optional path does not widen the fixed Linux-to-Linux Ring-1 exit or move
requirement credit. Its source and portable Rust tests exist. The
[bounded Pixel/Linux record](evidence/2026-11-06-android-linux-btle-ring1-validation.md)
additionally exercises Android compilation, APK packaging, JNI ABI loading,
real-controller connection, and matching Android/Linux terminal receipts;
those observations remain evaluation evidence rather than a support claim.
The later
[text Event record](evidence/2026-11-09-android-linux-btle-text-event-validation.md)
adds a clean-install Android publication, matching Linux terminal text and
digest, the reciprocal retained large Event, and the bounded native preparation
stack correction. It is warm-state evidence and does not qualify this host's
cold-controller path.
The separate
[early-ACL diagnostic](evidence/2026-11-09-android-linux-btle-early-acl-diagnostic.md)
shows that the evaluated Realtek USB controller on Linux 7.0.0-42 can deliver
inbound ACL data before its HCI Connection Complete event after a cold
controller epoch. Linux then discards the Pixel's already-sent CoC request.
That exact host stack is therefore not qualified for unattended cold Android
initiation; no mouse warm-up, shared-controller reset, protocol fallback, or
kernel-version heuristic is part of the adapter design.
Follow the
[Android BTLE Ring-1 quickstart](../quickstart/btle-android-ring1.md) to produce
that evidence without changing the protocol.

## Unattended Linux/Linux lifecycle extension

The tree also contains a separate `aster-btle-event` evaluation executable.
It starts a transport-neutral node before a Linux/BlueZ supervisor, tolerates
BlueZ or configured-controller absence, and observes add, remove, power, and
identity changes without polling. For exactly one configured controller and
one provisioned peer per process, complete mission node IDs derive
complementary Linux roles. One open or active ordered Event contact is owned at
a time; controller loss and shutdown cancel and drain it before another epoch
or node shutdown.

This extension reuses the existing semantic-v9 Event contact and the Ring-1
frame, exchange, and deadline ceilings. Its 250 ms to 30 second peer retry and
60-second default successful-contact cadence are local implementation policy,
not protocol constants. Local publication remains durably available with no
transport, and a later admitted contact reconciles retained Event work when
the receiver has matching durable application selection. The standalone
evaluator exposes no application endpoint. Its physical procedure prepares
the publisher Event and receiver `Consume` subscription through application
handles before starting the evaluator; a peerless loopback agent is only an
evaluation preparation/query tool, not a BTLE dependency or fallback.
Publication during unavailability is exercised through an in-process node
embedding or the focused adapter-neutral node integration test.

Deterministic unit and lifecycle tests cover controller absence/recovery,
single-attempt ownership, capped backoff, admission classification, drain on
shutdown, and independent fresh supervisor instances. The
[bounded two-CM4 observation](evidence/2026-11-05-cm4-btle-ring1-event-validation.md)
retains one Linux/Linux Event transfer, zero-work deduplication, controller
power-cycle recovery, process restart, application-level receipt, point
resource observations, and cleanup. The later
[clean-restart diagnostic](evidence/2026-11-06-cm4-btle-clean-restart-diagnostic.md)
bound the process-only failure on that exact stack to CVE-2026-72333 in Linux
6.18.39: the kernel exhausted L2CAP signaling identifiers and emitted invalid
identifier-zero CoC requests. It was not an Aster lifecycle or advertisement
restart defect.

Clean-restart qualification therefore requires a distribution kernel containing
the upstream fix (6.18.40 is the first fixed 6.18 release), plus a physical
post-stop contact without a controller epoch change. Aster deliberately adds
no peer-wide disconnect, controller reset, or runtime kernel-version heuristic.
The [fixed-kernel CM4 record](evidence/2026-11-06-cm4-btle-clean-restart-validation.md)
observes that exact zero-work process restart on Raspberry Pi Linux 6.18.60,
including nonzero signaling identifiers and no kernel allocation errors. It
does not repeat Event payload or application-receipt validation.
This mechanism does not alter the fixed-role Android/Linux evidence above and
gives no requirement credit or production approval. The operator procedure is
in the [unattended Linux BTLE Event quickstart](../quickstart/btle-linux-unattended.md).

## Required evidence

The retained CM4 record above partially satisfies this section for its exact
hardware and stated limitations. It covers the functional Event receipt,
controller lifecycle, application receipt, point resource observations, and
cleanup. It does not retain independently reproducible source-to-artifact
provenance, secret-bearing exact configuration, or repository-retained raw or
machine-readable logs. It is not a reusable hardware support row or release
qualification.

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

Discovery proof or grammar, negotiated/dynamic role selection, production MTU
floor, constrained-emission qualification, State, Record, Blob execution,
GATT, credited cross-platform interoperability, multi-controller operation,
automatic carrier selection or fallback, daemon packaging, support rows, and
production authorization are excluded. The unattended Linux/Linux extension
implements deterministic local role derivation, single-contact ownership, and
event-driven controller recovery in source; those mechanisms are not added to
the fixed physical Ring-1 claim without retained target evidence.
