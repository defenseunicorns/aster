# Aster Agent Event Module Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the draft customer-operable Event work unambiguously one `aster-agent` executable with an internal `event_service` module, while restoring the crate's default-feature test build.

**Architecture:** Preserve every existing RPC, process, storage, and mesh behavior. Rename only the Event-domain adapter module, keep bounded serving/lifecycle/health/credential facilities as focused sibling modules, and feature-gate only the generated-client test helpers that cannot compile without the crate's `client` feature. Do not add another binary, daemon, store, runtime selector, or plugin framework.

**Tech Stack:** Rust 2024, Cargo features, ConnectRPC 0.9.0, Tokio 1.53.1, existing `aster-agent` tests and repository verification tasks.

**Spec:** `docs/superpowers/specs/2026-09-05-customer-operable-event-service-design.md`

## Global Constraints

- The only deployed service executable remains exactly `aster-agent`.
- The selected Event RPC adapter module is named exactly `event_service` and remains crate-private.
- `SelectedEventHandle` and the running `aster-node` remain the sole Event authority; add no database, journal, reconciliation engine, or mesh protocol.
- Keep `config`, `credentials`, `health`, `lifecycle`, `runtime`, and `server` as focused sibling modules; do not introduce a generic runtime selector or plugin ABI.
- Preserve the legacy CLI as development/migration-only and the acceptance fixture as test-only.
- Do not change protobuf schemas, generated Rust or Go code, RPC behavior, public error values, or requirement/evidence status.
- Default-feature tests must compile without enabling client code in the production default feature set; generated-client procedure tests remain required under `--all-features`.
- Run with `CARGO_TARGET_DIR=/home/andrii/code/aster/target` in this `/tmp` worktree to avoid the temporary-filesystem quota.
- Preserve the Project label and use no OPI source or dependency.

---

### Task 1: Restore default-feature test compilation

**Files:**
- Modify: `crates/aster-agent/src/server.rs:568-800`
- Modify: `crates/aster-agent/src/server.rs:1092-1103`
- Test: `crates/aster-agent/src/server.rs`

**Interfaces:**
- Consumes: Cargo feature `client`, generated `api::AsterApplicationServiceClient`, and the existing in-process `PreBodyGate` tests.
- Produces: a default-feature test target that compiles without generated client symbols, while retaining `every_event_procedure_preserves_structured_authentication_across_protocols` when `client` is enabled.

- [ ] **Step 1: Reproduce the default-feature compile failure**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --no-run
```

Expected before the fix: FAIL with `could not find AsterApplicationServiceClient in api` at the `unauthenticated_client` and `assert_every_procedure_rejected` helpers.

- [ ] **Step 2: Gate only generated-client imports and helpers**

Replace the test imports with the following split so non-client server tests remain compiled by default:

```rust
use connectrpc::{ConnectRpcService, ErrorCode, Router};
#[cfg(feature = "client")]
use connectrpc::{
    ConnectError, Protocol,
    client::{ClientConfig, ServiceTransport},
};
```

Add `#[cfg(feature = "client")]` immediately above all three generated-client-only helpers:

```rust
#[cfg(feature = "client")]
fn assert_authentication_error(
    error: &ConnectError,
    expected_type_url: &str,
    procedure: &str,
) {

#[cfg(feature = "client")]
fn unauthenticated_client(
    protocol: Protocol,
) -> api::AsterApplicationServiceClient<
    ServiceTransport<PreBodyGate<ConnectRpcService<Router>>>,
> {

#[cfg(feature = "client")]
async fn assert_every_procedure_rejected(
    client: &api::AsterApplicationServiceClient<
        ServiceTransport<PreBodyGate<ConnectRpcService<Router>>>,
    >,
    expected_type_url: &str,
) {
```

Only insert the attributes; retain the existing function bodies byte-for-byte.

Gate the single test that calls those helpers:

```rust
#[cfg(feature = "client")]
#[tokio::test]
async fn every_event_procedure_preserves_structured_authentication_across_protocols() {
    for (protocol, expected_type_url) in [
        (Protocol::Connect, api::PublicErrorDetail::FULL_NAME),
        (Protocol::GrpcWeb, api::PublicErrorDetail::TYPE_URL),
        (Protocol::Grpc, api::PublicErrorDetail::TYPE_URL),
    ] {
        assert_every_procedure_rejected(&unauthenticated_client(protocol), expected_type_url)
            .await;
    }
}
```

- [ ] **Step 3: Prove both feature compositions compile**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --no-run
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features --no-run
```

Expected: both commands exit `0`; the default build has no generated-client symbol error, and the all-feature test executable still contains the cross-protocol procedure test.

- [ ] **Step 4: Run the affected non-network test set**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features \
  server::tests::every_event_procedure_preserves_structured_authentication_across_protocols
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features \
  server::tests::unauthenticated_request_is_rejected_without_polling_body
```

Expected: both tests pass. These use the in-process service boundary and require no listener bind.

- [ ] **Step 5: Commit the isolated build correction**

```bash
git add crates/aster-agent/src/server.rs
git commit -m "fix(agent): gate generated-client server tests"
```

---

### Task 2: Name the selected Event adapter explicitly

**Files:**
- Rename: `crates/aster-agent/src/service.rs` to `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/src/lib.rs:1-90`
- Modify: `crates/aster-agent/src/runtime.rs:12-20`
- Modify: `crates/aster-agent/src/server.rs:225-236`
- Modify: `docs/superpowers/plans/2026-09-06-customer-operable-event-service.md`
- Test: `crates/aster-agent/src/event_service.rs`
- Test: `crates/aster-agent/tests/real_node_connect.rs`
- Test: `crates/aster-agent/tests/customer_runtime.rs`

**Interfaces:**
- Consumes: the unchanged crate-private functions `application_service`, `configured_service`, and `rejection_router` currently defined in `service.rs`.
- Produces: crate-private module path `crate::event_service`, with the same function signatures and the same single `aster-agent` binary surface.

- [ ] **Step 1: Record the structural test failure before the rename**

Run:

```bash
test -f crates/aster-agent/src/event_service.rs
```

Expected before the rename: nonzero exit because the explicitly named Event module does not exist.

- [ ] **Step 2: Rename the file without changing its implementation**

```bash
git mv crates/aster-agent/src/service.rs crates/aster-agent/src/event_service.rs
```

Do not modify RPC handlers, request parsing, response mapping, streaming, bounds, or tests inside the renamed file.

- [ ] **Step 3: Update the crate-private module paths**

In `crates/aster-agent/src/lib.rs`, replace:

```rust
mod service;
```

with:

```rust
mod event_service;
```

Replace the compatibility adapter call with:

```rust
let service = event_service::application_service(events, shutdown.clone());
```

In `crates/aster-agent/src/runtime.rs`, import:

```rust
event_service::application_service,
```

In `crates/aster-agent/src/server.rs`, build rejection routes through:

```rust
let rejected = crate::event_service::configured_service(
    crate::event_service::rejection_router(),
);
```

- [ ] **Step 4: Clarify the crate-level ownership without promising plugins**

Replace the opening documentation in `crates/aster-agent/src/lib.rs` with:

```rust
//! Process-local application agent for a running Aster node.
//!
//! The crate contains focused process facilities for bounded serving,
//! credentials, health, lifecycle, and supervision. The selected customer MVP
//! statically composes one crate-private Event application module over
//! `SelectedEventHandle`; it does not provide runtime module selection, a
//! plugin ABI, another durable authority, or a second service executable.
```

Remove the stale `Task 6 replaces this adapter` wording from `BoundAgent` and describe it as the development/migration compatibility entry point that delegates to the same bounded server and Event module.

- [ ] **Step 5: Keep the completed implementation plan's file map usable**

In `docs/superpowers/plans/2026-09-06-customer-operable-event-service.md`, replace every exact source-path occurrence of:

```text
crates/aster-agent/src/service.rs
```

with:

```text
crates/aster-agent/src/event_service.rs
```

Add this note after that plan's header metadata:

```markdown
> **Boundary clarification (2026-09-07):** The implemented `service.rs` was
> subsequently named `event_service.rs` to make clear that Event service is an
> internal module of the single `aster-agent` component. No second executable,
> durable authority, runtime selector, or plugin framework was introduced.
```

- [ ] **Step 6: Prove the rename is complete and behavior compiles unchanged**

Run:

```bash
test -f crates/aster-agent/src/event_service.rs
test ! -e crates/aster-agent/src/service.rs
rg -n "crate::service|service::application_service|mod service|src/service\.rs" \
  crates/aster-agent docs/superpowers/plans/2026-09-06-customer-operable-event-service.md
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --no-run
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features --no-run
```

Expected: both file assertions and both Cargo commands exit `0`; `rg` prints no stale module or exact source-path reference.

- [ ] **Step 7: Run focused behavior tests**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features lifecycle::tests
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features credentials::tests
CARGO_TARGET_DIR=/home/andrii/code/aster/target \
  cargo test --locked -p aster-agent --all-features config::tests
```

Expected: every selected test passes. Full listener/process acceptance remains for Task 3 because the managed sandbox denies listener creation.

- [ ] **Step 8: Commit the module-boundary rename**

```bash
git add crates/aster-agent/src/lib.rs \
  crates/aster-agent/src/runtime.rs \
  crates/aster-agent/src/server.rs \
  crates/aster-agent/src/event_service.rs \
  docs/superpowers/plans/2026-09-06-customer-operable-event-service.md
git commit -m "refactor(agent): name the Event service module"
```

---

### Task 3: Verify and publish the corrected PR boundary

**Files:**
- Verify: `crates/aster-agent/**`
- Verify: `docs/decisions/0041-customer-operable-event-service.md`
- Verify: `docs/superpowers/specs/2026-09-05-customer-operable-event-service-design.md`
- Verify: `docs/superpowers/plans/2026-09-07-aster-agent-event-module-boundary.md`
- Update externally: draft PR description for `feature/customer-operable-event-service`

**Interfaces:**
- Consumes: the corrected default/all-feature test composition and crate-private `event_service` path from Tasks 1 and 2.
- Produces: one pushed draft PR whose code, design, ADR, and team-facing description state the same deployable component boundary.

- [ ] **Step 1: Run repository document and source checks**

Run:

```bash
git diff --check origin/feature/customer-operable-event-service...HEAD
python3 tools/check-implementation-requirements.py
CARGO_TARGET_DIR=/home/andrii/code/aster/target cargo fmt --all -- --check
```

Expected: no whitespace or formatting output; requirements report `requirements trace valid: 348 matrix IDs, 137 exact selected mappings`.

- [ ] **Step 2: Run the full repository gate outside the listener-restricted sandbox**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target mise run check
```

Expected: exit `0`. If the known Go semantic-version expectation still differs from core/FFI semantic version 6, retain the exact output as a pre-existing release-gate blocker and do not broaden this PR with that unrelated correction.

- [ ] **Step 3: Confirm the diff contains no second service component**

Run:

```bash
git diff --name-status origin/feature/customer-operable-event-service...HEAD
git diff --stat origin/feature/customer-operable-event-service...HEAD
rg -n "aster-event-service|generic runtime selector|plugin ABI" \
  Cargo.toml crates docs/decisions/0041-customer-operable-event-service.md \
  docs/superpowers/specs/2026-09-05-customer-operable-event-service-design.md
```

Expected: no `aster-event-service` crate or binary appears; the selector/plugin matches occur only in explicit non-goal text.

- [ ] **Step 4: Push the corrected commits to the existing draft PR branch**

```bash
git push origin feature/customer-operable-event-service
```

Expected: the remote branch advances without force-push.

- [ ] **Step 5: Update the draft PR description with the clarified boundary**

Use `.github/pull_request_template.md` and add this exact summary near the top of the existing body without deleting its evidence or limitations:

```markdown
## Component boundary clarification

- `aster-agent` remains the single deployed service executable.
- The customer Event service is the crate-private `event_service` module over
  `SelectedEventHandle`; it is not a second daemon or durable authority.
- Bounded serving, credentials, health, lifecycle, and supervision remain
  focused sibling modules that may be reused later, without introducing an MVP
  runtime selector or plugin ABI.
- The unprotected acceptance fixture remains test-only. D06 will statically
  compose the selected protected loader into the same `aster-agent` startup
  path.
```

Expected: the draft PR description gives deployment, provisioning, device-test, and release-gate owners one consistent boundary.

- [ ] **Step 6: Record the handoff**

Report the pushed commit IDs, focused and full verification results, any retained pre-existing gate failure, and that D06 planning may now target the single `aster-agent --config` composition.
