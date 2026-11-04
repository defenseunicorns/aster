# BTLE Ring 1 Event Continuation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Complete the initial semantic-v9 non-IP Event slice after the green
ordered-contact foundation: run the hybrid mission session and selected Event
lane over one fixed-role Linux LE L2CAP CoC contact without changing protocol,
storage, or application bytes.

**Architecture:** `aster-ble-l2cap` owns a bounded, class-neutral ordered
contact over injected asynchronous byte streams. `aster-ble-linux` owns only
BlueZ/Linux controller selection and BlueR LE L2CAP socket adaptation. The
selected runtime consumes an owned adapter-neutral contact and retains an
Iroh-only capability for the existing Profile-5 attempt pair. Ring 1 admits
only the hybrid record-protected profile; an unauthenticated Bluetooth locator
gains no identity authority before the mission handshake.

**Spec:** `docs/superpowers/specs/2026-11-03-production-btle-design.md`

## Approaches

- **Selected: common carrier plus Linux platform crate.** This preserves the
  onion and allows later CoreBluetooth/Android drivers to reuse framing and
  contact behavior.
- One Linux-specific monolith was rejected because it would mix carrier state,
  framing, and BlueZ lifecycle.
- Raw `AF_BLUETOOTH` calls were rejected because BlueR 0.17.4 already provides
  the required safe Tokio-style L2CAP client/listener surface under BSD-2-Clause.
- External `bluetoothctl`/`btmgmt` subprocesses remain diagnostics only; they
  are not a runtime adapter boundary.

## Global Constraints

- Keep all work local. Do not push, open a PR, or change external state beyond
  isolated test-device runs explicitly requested by the owner.
- Semantic versions 1-9, profile offers/digests, v9 Event frames, application
  APIs, stores, and durable progress remain byte-for-byte unchanged.
- No GATT fallback, discovery grammar, dynamic roles, hot-plug recovery,
  cross-carrier failover, new adapter allocation, or production claim.
- `ClassicalP256IrohQuicV1` remains Iroh-only and must fail before inventory on
  an unauthenticated-locator contact.
- Publication and readiness remain successful with no transport, no controller,
  or an unavailable configured controller.
- Every parser/framer bound receives RED/GREEN tests and fuzz-smoke coverage.

## Review Focus

- Locator evidence must never be converted to an Iroh `EndpointId` or stable
  carrier identity.
- Mission rejection must release no inventory or Event bytes.
- Length, aggregate exchange, queue, deadline, and close bounds must fail
  closed without partial application delivery.
- The v9 profile offer/digest must remain complete even though Blob execution
  is dormant on the BTLE contact.
- Iroh behavior and the complete workspace gate must remain green.

### Task 1: Adopt the bounded Ring 1 governance and dependency record

**Files:**
- Modify: `docs/decisions/0007-ip-and-btle-links.md`
- Modify: `docs/decisions/0002-dependency-admission.md`
- Create: `docs/validation/btle-ring1-evaluation-profile.md`

Record only the asynchronous ordered selected-node seam, path-specific
framing ownership, fixed roles/topology, hybrid-only profile, finite bounds,
BlueR 0.17.4 admission, and exclusions required before implementation. Keep
Decision 0007's semantic/reference `BleRadio` path intact.

Verify:

```sh
python3 tools/check-implementation-requirements.py
git diff --check
```

### Task 2: Add the bounded common `BleL2capV1` contact

**Files:**
- Create: `crates/aster-ble-l2cap/Cargo.toml`
- Create: `crates/aster-ble-l2cap/LICENSE`
- Create: `crates/aster-ble-l2cap/src/lib.rs`
- Create: `crates/aster-ble-l2cap/fuzz/*`
- Modify: workspace and fuzz lockfiles

Write failing Tokio duplex tests first for: request/response and completion;
an Event-sized frame larger than the injected platform-write ceiling;
truncated length/body; oversized frame before allocation; aggregate limit;
wrong turn marker; timeout; peer close; initiator/responder finish; handler
rejection; and unauthenticated locator evidence. Implement one serialized
session queue and bounded length framing over `AsyncRead + AsyncWrite`. The
carrier-local revision and tags are private constants and explicitly not v9
wire allocations.

Verify:

```sh
cargo test --locked -p aster-ble-l2cap
mise run fuzz-smoke
```

### Task 3: Generalize the hybrid mission session to `OrderedContact`

**Files:**
- Modify: `crates/aster-node/src/mission.rs`
- Modify: `crates/aster-node/src/lib.rs`
- Modify: `crates/aster-node/Cargo.toml`

Introduce carrier-neutral peer expectation/observation types containing typed
`CarrierPeerEvidence` plus the authority-authenticated mission `NodeId`.
Preserve the existing `MissionPeerBinding` and `*_over_iroh` APIs as Iroh
compatibility wrappers. Add contact-generic hybrid initiate/respond functions.
Classical carrier-bound APIs remain concrete Iroh APIs.

Write RED tests proving an unauthenticated locator authenticates only the
mission identity, a wrong rostered mission ID fails before inventory, a fake
stable identity mismatch fails before flight one, classical profile selection
is rejected for locator evidence, and Iroh receipts remain four exact flights.

Verify:

```sh
cargo test --locked -p aster-node mission::tests --lib
```

### Task 4: Move the selected Event/control runtime onto an owned contact

**Files:**
- Create: `crates/aster-node/src/contact.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify focused runtime submodules that consume session request/respond

Add an owned `SelectedContact` enum/handle that implements `OrderedContact` and
optionally exposes the exact Iroh connection only to existing Blob stream
attempt code. Convert handshake, profile offer, control, Event, State/Record
request/response helpers, completion, accounting, and close paths to the
neutral contract. Preserve the concrete Iroh path for Profile-4/5 transport
operations that require it; BTLE Ring 1 fails closed before Blob execution.

Write RED tests proving zero transport does not affect local publish/readiness,
mission rejection emits no inventory, exact v9 profile digest parity, one
Event over a fake locator contact, disconnect/reconnect without duplicate
semantic delivery, and dormant Blob Profile 5 opens no attempt pair.

Verify:

```sh
cargo test --locked -p aster-node mission::tests --lib
cargo test --locked -p aster-node runtime::tests --lib
```

### Task 5: Add the fixed-role Linux BlueZ L2CAP driver

**Files:**
- Create: `crates/aster-ble-linux/Cargo.toml`
- Create: `crates/aster-ble-linux/LICENSE`
- Create: `crates/aster-ble-linux/src/lib.rs`
- Create: `crates/aster-ble-linux/src/bin/aster-btle-ring1.rs`
- Modify: workspace and fuzz lockfiles

Use exact-pinned BlueR 0.17.4 with `l2cap` and only the minimum BlueZ feature
needed for a generic connectable advertisement. Configuration fixes one local
controller/address, public/random address type, peer address, dynamic LE PSM,
role, frame/exchange bounds, and deadlines. The driver never powers a
controller implicitly. Missing/removed controllers are `Unavailable`; Ring 1
recovery is restart or explicit reconfiguration. The binary is an evaluation
harness, not an installed daemon or public application API.

Write RED tests for validation, absent controller, client/listener address
construction, error mapping, cancellation, and injected socket factories.

Verify:

```sh
cargo test --locked -p aster-ble-linux
cargo test --locked -p aster-ble-l2cap
sh tools/check-cargo-lockfiles.sh
```

### Task 6: Local and physical Ring 1 verification

Run formatting, Clippy, focused suites, requirements checker, lockfile check,
fuzz smoke, `mise run check`, and ARM64 cross-build. On two currently available
CM4 devices, use fixed roles and only the temporary harness: verify one
protected Event larger than negotiated CoC MTU, wrong identity/profile
rejection before inventory, disconnect/reconnect, controller loss plus restart,
process restart, no duplicate semantic delivery, complete v9 profile digest,
and bounded resource observations. Preserve installed services and remove all
temporary artifacts. Retain a local receipt but move no requirement credit and
make no production/support-row claim.
