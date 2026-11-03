# BTLE Ring 1 Contact Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the adapter-neutral ordered-contact contract required by Ring 1 and make the existing Iroh connection conform without changing v9 bytes or selected-runtime behavior.

**Architecture:** A new dependency-light `aster-contact` crate owns typed peer evidence, bounded locator and channel-binding values, a closed carrier error taxonomy, and the object-safe ordered request/response contact contract. `aster-iroh::Connection` implements that contract in a focused module by delegating to its existing bounded operations. The selected node remains on its existing Iroh entry points in this increment; a later plan migrates mission/runtime consumers and adds the Linux L2CAP CoC implementation.

**Tech Stack:** Rust 2024, boxed `Future` trait methods, Tokio loopback integration tests, existing `aster-iroh` carrier.

**Spec:** `docs/superpowers/specs/2026-11-03-production-btle-design.md`

## Global Constraints

- Semantic versions 1 through 9, transfer-profile offers, transcript digests, framing bytes, and application APIs remain unchanged.
- The contract transports opaque bounded bytes and owns no store, mission policy, reconciliation, or durable progress.
- An unauthenticated BTLE locator cannot be represented as an authenticated stable carrier identity.
- The first implementation is in-process; no helper daemon or IPC protocol is introduced.
- Additional DATA/CONTROL channel pairs remain optional and outside this increment.
- No BTLE discovery encoding, adapter-ID registry allocation, v10 profile, tag, or record is introduced.
- Existing Iroh behavior and exact error bounds remain covered by parity tests.

## Review Focus

- Empty or oversized transient locators must fail construction rather than allocate unbounded carrier state; Task 1 tests both boundaries.
- Unauthenticated locator evidence must never expose a stable carrier identity or channel-binding capability; Task 1 tests both observations.
- Oversized ordered-contact requests must preserve the existing bounds failure instead of being relabeled retryable; Task 2 tests the mapped error kind.
- A handler rejection must close/fail the exchange without reporting a completed session; Task 2 tests the real Iroh loopback path.
- Finish ordering must preserve the existing initiator-consumed/responder-close behavior; Task 2 tests both sides on a real loopback contact.

---

### Task 1: Adapter-neutral ordered-contact contract

**Files:**
- Create: `crates/aster-contact/Cargo.toml`
- Create: `crates/aster-contact/LICENSE`
- Create: `crates/aster-contact/src/lib.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `fuzz/Cargo.lock`

**Interfaces:**
- Consumes: only `std`; no Aster protocol, store, Iroh, Bluetooth, or async-runtime types.
- Produces: `StableCarrierId`, `TransientLocator`, `ChannelBindingCapability`, `CarrierPeerEvidence`, `ContactErrorKind`, `ContactError`, `ContactFuture<'a, T>`, `ContactRequestHandler<'a>`, and object-safe `OrderedContact`.

- [ ] **Step 1: Write failing contract tests in `crates/aster-contact/src/lib.rs`**

Add tests named:

- `transient_locator_rejects_empty_and_oversized_values`
- `unauthenticated_locator_exposes_no_stable_identity_or_channel_binding`
- `authenticated_evidence_exposes_exact_stable_identity_and_binding_capability`

Use literal 32-byte stable IDs and `MAX_TRANSIENT_LOCATOR_BYTES + 1`; assert the public observation methods rather than enum debug text.

- [ ] **Step 2: Run the new crate test and verify RED**

Run: `/home/andrii/.cargo/bin/cargo test -p aster-contact`

Expected: FAIL because the workspace package and contract types do not exist.

- [ ] **Step 3: Implement the minimal contract**

Create the crate and define:

- `StableCarrierId::new([u8; 32]) -> Self` and `as_bytes(&self) -> &[u8; 32]`.
- `TransientLocator::new(Vec<u8>) -> Result<Self, ContactError>` with the inclusive bound `1..=MAX_TRANSIENT_LOCATOR_BYTES`, plus `as_bytes`.
- `ChannelBindingCapability::{Unavailable, Derivable}`.
- `CarrierPeerEvidence::{AuthenticatedCarrier { stable_carrier_id, channel_binding }, UnauthenticatedLocator { transient_locator }}` with `stable_carrier_id() -> Option<StableCarrierId>` and `channel_binding_capability() -> ChannelBindingCapability`.
- Closed `ContactErrorKind::{Configuration, Unavailable, Timeout, Transport, Bounds, Unauthorized, Protocol, Unsupported}` and a bounded-detail `ContactError` whose public behavior is kind plus `Display`.
- `ContactFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ContactError>> + Send + 'a>>`.
- `ContactRequestHandler<'a> = Box<dyn FnOnce(&[u8]) -> Result<(Vec<u8>, bool), ContactError> + Send + 'a>`.
- Object-safe `OrderedContact` methods for peer evidence, maximum frame bytes, request with total limit, respond once with total limit, initiator/responder finish, and synchronous close.

Keep the crate free of wire encodings and runtime dependencies.

- [ ] **Step 4: Run tests and lockfile checks**

Run: `/home/andrii/.cargo/bin/cargo test -p aster-contact && sh tools/check-cargo-lockfiles.sh`

Expected: all `aster-contact` tests pass and both committed lockfiles validate.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock fuzz/Cargo.lock crates/aster-contact docs/superpowers/specs/2026-11-03-production-btle-design.md docs/superpowers/plans/2026-11-03-btle-ring1-contact-foundation.md
git commit -m "feat(contact): add adapter-neutral ordered contact contract"
```

### Task 2: Iroh ordered-contact parity adapter

**Files:**
- Create: `crates/aster-iroh/src/contact.rs`
- Modify: `crates/aster-iroh/src/lib.rs`
- Modify: `crates/aster-iroh/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `fuzz/Cargo.lock`

**Interfaces:**
- Consumes: Task 1's `OrderedContact` contract and the existing `aster_iroh::Connection` bounded request/response, channel-binding, finish, close, identity, and frame-ceiling operations.
- Produces: `impl OrderedContact for aster_iroh::Connection` and a conservative `CarrierError` to `ContactErrorKind` mapping for the closed adapter-neutral categories.

- [ ] **Step 1: Write failing Iroh contact tests**

In `crates/aster-iroh/src/contact.rs`, add real loopback tests named:

- `ordered_contact_reports_authenticated_iroh_evidence`
- `ordered_contact_preserves_bounded_request_response_and_finish`
- `ordered_contact_maps_oversized_request_to_bounds`
- `ordered_contact_handler_rejection_never_reports_completion`

The first test asserts the remote `EndpointId` bytes exactly and
`ChannelBindingCapability::Derivable`. The exchange test sends literal request
and response bytes through `OrderedContact`, observes `complete == false` for
the first exchange, then exercises `finish_as_initiator` and
`finish_as_responder`. The bounds test uses the connection's existing maximum
plus one. The rejection test returns `ContactErrorKind::Protocol` from the
handler and asserts neither side reports a successful completed exchange.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `/home/andrii/.cargo/bin/cargo test -p aster-iroh contact::tests --lib`

Expected: FAIL because `Connection` does not implement `OrderedContact`.

- [ ] **Step 3: Implement the Iroh adapter**

Add `aster-contact` as a path dependency and implement each trait method by
delegating to the existing `Connection` operation. Map errors as follows:

- configuration → `Configuration`
- generic transport operation failure → `Transport` (retry classification remains outside this layer)
- timeout → `Timeout`
- unauthorized peer → `Unauthorized`
- frame/turn too large → `Bounds`

Map handler errors through a side channel so an exact `ContactError` returned by
the higher layer is not converted into an Iroh transport string. Peer evidence
uses the exact remote endpoint bytes as `StableCarrierId` and reports derivable
channel binding. Do not add an alternate framing or request grammar.

- [ ] **Step 4: Run focused and existing Iroh tests**

Run: `/home/andrii/.cargo/bin/cargo test -p aster-iroh contact::tests --lib && /home/andrii/.cargo/bin/cargo test -p aster-iroh --lib`

Expected: all tests pass; loopback tests may require execution outside the network sandbox.

- [ ] **Step 5: Commit**

```bash
git add crates/aster-iroh Cargo.lock fuzz/Cargo.lock
git commit -m "feat(iroh): implement ordered contact contract"
```

### Task 3: Compatibility and next-slice boundary

**Files:**
- Modify: `docs/validation/capability-roadmap.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Tasks 1–2 and the approved BTLE design claim boundary.
- Produces: an explicit implemented-uncredited foundation statement without claiming BTLE, runtime migration, or physical evidence.

- [ ] **Step 1: Add the bounded implementation statement**

Record that the class-neutral ordered-contact contract and Iroh parity adapter
exist, while Linux L2CAP, selected-runtime migration, BTLE Event exchange,
discovery, physical evidence, and requirement-credit movement remain open. Do
not modify `docs/validation/requirements-status.md` or the generated atomic
trace because this increment changes no evidence boundary.

- [ ] **Step 2: Run repository validation**

Run:

```bash
/home/andrii/.cargo/bin/cargo fmt --check
/home/andrii/.cargo/bin/cargo test -p aster-contact
/home/andrii/.cargo/bin/cargo test -p aster-iroh --lib
/home/andrii/.cargo/bin/cargo test -p aster-node mission::tests --lib
python3 tools/check-implementation-requirements.py
sh tools/check-cargo-lockfiles.sh
```

Expected: all commands pass. The mission suite may require execution outside the network sandbox for loopback sockets.

- [ ] **Step 3: Run the complete project gate**

Run: `mise run check`

Expected: PASS. If local mise trust prevents the wrapper from running, invoke the exact tasks/toolchain from `mise.toml` and record that limitation rather than weakening the checks.

- [ ] **Step 4: Commit**

```bash
git add docs/validation/capability-roadmap.md CHANGELOG.md
git commit -m "docs: record BTLE contact foundation boundary"
```

The next plan begins only after this foundation is green: migrate hybrid mission
handshake/runtime consumers to `OrderedContact`, add a test-only unauthenticated
locator contact proving mission-only roster admission, and then implement the
in-process Linux/BlueZ L2CAP CoC contact for Ring 1.
