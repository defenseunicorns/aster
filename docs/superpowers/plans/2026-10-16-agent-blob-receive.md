# Public Agent Blob Receive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a Blob published through one public `aster-agent` API readable through another public agent by adding bounded, static Blob receive configuration.

**Architecture:** Extend the shared strict systemd-v1/Compose-v2 configuration with exact Blob receive selectors and explicit Blob-depot limits, then pass both through the existing `NodeConfigOptions` and `SelectedForwardingConfig` paths. Keep application access separate from mesh authority: selectors are restart-only operator configuration, absent selectors receive nothing, and existing mission authorization and `ReceiveOnly` suppression remain authoritative.

**Tech Stack:** Rust, Serde JSON, Tokio, existing Aster node/agent APIs, Markdown operator documentation.

**Spec:** `docs/quickstart/selected-blob-api.md` (exact semantic-v7/v8 Blob interest behavior) and the approved public-agent configuration design for this task.

## Global Constraints

- Produce one non-stacked capability PR from `origin/main` and one signed commit for the complete increment.
- Preserve existing v1/v2 configuration behavior when new fields are absent: Blob receive interests remain empty.
- Accept restart-only exact `TOPIC@SCOPE` selectors; reject malformed values, duplicate canonical selectors, descendant-scope intent, and more than 256 selectors before startup side effects.
- Require explicit nonzero `storage.blob_depot` byte/chunk/variant limits whenever `mesh.blob_interests` is nonempty; allow the limits when interests are empty so local Blob publication can also be bounded.
- Do not change wire formats, semantic/profile versions, Protobuf RPCs, application subscriptions, Blob identity, stream deadlines, size limits, or benchmark/performance files.
- Preserve current `ReceiveOnly` behavior: configured selectors grant no Blob network activity while receive-only is selected.
- Keep configuration errors sanitized and free of operator-supplied selector values.
- Do not move requirement status or claim retained, physical, performance, convergence, subscription, or release evidence from automated tests alone.
- Use resource-bounded focused tests locally; CI remains the complete repository gate because prior full local suites were repeatedly killed by the OS.

## Review Focus

- An old configuration without either new field still opens a node with empty Blob interests and the established default depot limits.
- A configured selector reaches the running-node configuration exactly; it is not converted into an application subscription or broadened to descendants.
- Malformed, duplicate, and 257-selector configurations fail during validation with a fixed public category and no input echo.
- A nonempty selector list without explicit depot limits fails closed instead of enabling the implicit 512-MiB receive depot.
- `ReceiveOnly` keeps existing zero-Blob network behavior even though the validated restart configuration retains selectors for a later normal-mode restart.

---

### Task 1: Strict configuration and node wiring

**Files:**
- Modify: `crates/aster-agent/src/config.rs`
- Test: `crates/aster-agent/src/config.rs`
- Test: `crates/aster-agent/tests/customer_runtime.rs`

**Interfaces:**
- Consumes: `MutableSourceInterests::with_blob(Vec<SourceInterestSelector>)`, `NodeConfigOptions::with_mutable_interests`, `BlobDepotLimits::new`, and `SelectedForwardingConfig::with_blob_depot_limits`.
- Produces: optional `mesh.blob_interests: Vec<String>`, optional `storage.blob_depot`, validated exact selectors, and node/forwarding options carrying those values.

- [ ] **Step 1: Write failing configuration tests**

  Add focused tests proving legacy v1/v2 JSON defaults to no Blob interests; valid exact selectors and explicit depot limits reach the opened `NodeConfig`; and depot limits reach `SelectedForwardingConfig`.

- [ ] **Step 2: Run the focused tests and verify RED**

  Run the new exact tests with `cargo test -p aster-agent <test-name> -- --exact --nocapture`; confirm failure is caused by the unknown fields or absent wiring.

- [ ] **Step 3: Write failing validation-boundary tests**

  Add literal fixtures for malformed syntax, duplicate canonical selectors, 257 selectors, zero depot dimensions, and nonempty interests without depot configuration. Assert fixed `ConfigReason` categories and that rendered errors contain none of the canary values.

- [ ] **Step 4: Run the boundary tests and verify RED**

  Run each new exact test and confirm it fails because the validator does not yet implement the approved rules.

- [ ] **Step 5: Implement the minimal parser and wiring**

  Add strict raw config structs, fixed error categories, a maximum of 256 selectors, exact `TOPIC@SCOPE` parsing through `Topic::new`/`Scope::new`, duplicate rejection, `MutableSourceInterests` storage in `ValidatedRuntimeConfig`, `NodeConfigOptions` wiring, and explicit `BlobDepotLimits` wiring.

- [ ] **Step 6: Verify GREEN and existing focused regressions**

  Run all `aster-agent` config tests plus the focused customer-runtime bootstrap/config tests. Confirm zero failures and no warnings.

### Task 2: Legacy development CLI parity

**Files:**
- Modify: `crates/aster-agent/src/main.rs`
- Test: `crates/aster-agent/src/main.rs`

**Interfaces:**
- Consumes: the existing `parse_source_interest` helper and `MutableSourceInterests::with_blob`.
- Produces: repeatable `--blob-interest TOPIC@SCOPE` in legacy development mode only.

- [ ] **Step 1: Write failing CLI tests**

  Add tests showing the help/argument surface accepts repeatable exact Blob interests, rejects malformed values with the Blob class in the fixed error, and does not alter State/Record selectors.

- [ ] **Step 2: Run the focused tests and verify RED**

  Run each exact unit test and confirm failure comes from the currently unsupported flag or missing help/wiring.

- [ ] **Step 3: Implement minimal CLI parsing and wiring**

  Parse `--blob-interest` beside existing State/Record flags, call `.with_blob(blob_interests)`, and update help text to distinguish restart-only mesh receive interests from application API access.

- [ ] **Step 4: Verify GREEN**

  Run the `aster-agent` binary unit tests and confirm zero failures.

### Task 3: Operator documentation and focused verification

**Files:**
- Modify: `docs/reference/aster-agent-config-v1.md`
- Modify: `docs/reference/aster-agent-config-v2.md`
- Modify: `docs/quickstart/connect-agent.md`
- Modify: `crates/aster-agent/README.md`
- Modify: `docker/compose-agent/agent.example.json`
- Modify only if exact implementation-boundary wording changes: `README.md`, `docs/validation/capability-roadmap.md`, `docs/validation/requirements-status.md`

**Interfaces:**
- Consumes: the exact field names and validation behavior from Tasks 1 and 2.
- Produces: copyable v1/v2 examples and an explicit operational distinction between public Blob API access, network receive interests, and application subscriptions.

- [ ] **Step 1: Update examples and references**

  Document empty receive-none defaults, exact selector syntax, the 256-selector cap, duplicate rejection, explicit depot accounting, older-agent fail-closed rollback behavior, mission-authorization filtering, metadata visibility, and `ReceiveOnly` suppression.

- [ ] **Step 2: Run documentation/config consumers**

  Run Compose example validation, focused package/config tests, `cargo fmt --check`, `cargo clippy -p aster-agent --all-targets -- -D warnings`, and `python3 tools/check-implementation-requirements.py` only if traceability text changed.

- [ ] **Step 3: Run targeted functional verification**

  Run the focused `aster-agent` test target serially and build the ARM64 agent/package path used by the test devices. Do not run the full local workspace suite; use CI for that complete gate.

- [ ] **Step 4: Create one signed commit**

  Stage the complete capability increment and create one signed commit named `feat(agent): configure Blob receive interests`.

- [ ] **Step 5: Independent review and physical validation**

  Obtain an independent whole-branch review. After fixes and fresh focused verification, validate on the two clean CM4 devices: public API publish on one agent, exact-byte public API read on the interested peer, and no transfer for empty/nonmatching interest. Restore device state afterward and retain only sanitized observations.
