# D06 systemd runtime loader implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the first coherent D06 implementation increment: a bounded,
versioned `aster-systemd-credential-store/v1` reference/envelope, a Linux
runtime loader that accepts only a `secure` systemd service credential, and
static composition into the single `aster-agent --config` executable.

**Architecture:** A new first-party `aster-systemd-credentials` crate owns the
provider reference/envelope codec and implements `ProvisioningSecretLoader`.
At runtime it opens the absolute `CREDENTIALS_DIRECTORY` without symlink
traversal, opens only the fixed `aster-provisioning.bundle` entry relative to
that directory descriptor, requires a regular single-link `0400` file owned by
the effective service identity on `ramfs`, reads one bounded envelope, and
checks its reference, load operation, generation, and inner length. The
existing `aster-agent` customer runtime opens the protected bundle before any
listener or state side effect; its production binary statically selects this
loader. The administration binary, durable ledger, mutation lifecycle,
packaging, and device qualification remain later D06 increments.

**Tech Stack:** Rust 2024, `aster-core` persistent-secret contracts, `rustix`
descriptor-relative Linux filesystem APIs, `zeroize`, Tokio.

**Spec:**
`docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md` on
`feature/p0-1-linux-event-mvp-profile`.

## Global constraints

- Target only the approved Ubuntu 24.04/systemd 255.4 profile boundary.
- Use provider contract `aster-systemd-credential-store/v1`, fixed credential
  name `aster-provisioning.bundle`, and no runtime provider selection.
- Never invoke `systemd-creds` from the runtime and never add raw, age, file,
  TPM2, or alternate-provider fallback.
- Treat `ramfs` plus exact mode `0400` as `secure`; reject `tmpfs`/other mounts
  as weak and any other mode as insecure.
- Keep errors fixed and sanitized; do not retain paths, references, operation
  IDs, provider strings, parser details, or plaintext in errors or debug text.
- Use TDD and focused tests with `CARGO_BUILD_JOBS=2`, `RUST_TEST_THREADS=1`,
  and `umask 0077`; do not run the full workspace gate during iteration.
- Do not claim install, rotation, backup/recovery, destruction, package, or
  physical-device evidence in this increment.

---

### Task 1: Define the canonical provider reference and envelope

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/aster-systemd-credentials/Cargo.toml`
- Create: `crates/aster-systemd-credentials/src/lib.rs`

**Interfaces:**
- Produces a v1 opaque provider reference carrying an exact nonzero generation
  and fixed-size random reference identity.
- Produces a canonical provider envelope carrying the canonical Aster secret
  reference, load-operation ID, matching generation, and bounded `ASTRPB03`
  plaintext.
- Returns only `ProvisioningSecretStoreError` categories.

- [x] Add literal-fixture tests for canonical provider-reference and envelope
  round trips through the public Aster contracts.
- [x] Add one table-driven rejection test covering wrong magic/version,
  nonzero reserved fields, zero generation, noncanonical reference,
  reference/generation/operation mismatch, empty/oversized inner plaintext,
  trailing bytes, and integer-length disagreement.
- [x] Run `cargo test -p aster-systemd-credentials envelope -- --nocapture` and
  observe failure because the crate/API does not exist.
- [x] Add the crate to the workspace and implement the minimum bounded codec;
  own transient buffers with `Zeroizing` and construct
  `UnprotectedProvisioning` only after every outer check passes.
- [x] Run the same focused provider tests until green.
- [x] Commit as `feat(credentials): define systemd provider envelope`.

### Task 2: Implement the secure systemd credential source and loader

**Files:**
- Modify: `crates/aster-systemd-credentials/src/lib.rs`

**Interfaces:**
- Adds `SystemdCredentialLoader::from_environment()` for the production
  `CREDENTIALS_DIRECTORY` contract.
- Implements `ProvisioningSecretLoader` for one fixed credential.
- Uses Linux `openat2`/`openat`, `fstat`, and `fstatfs` through safe `rustix`
  APIs; it does not concatenate a credential pathname.

- [x] Add tests naming the production failures for missing/non-absolute or
  traversing credential directories, final symlinks, non-regular files,
  multiple links, wrong owner/mode, changed metadata, oversized data, and
  non-`ramfs` filesystem classification.
- [x] Add a loader-contract test with a controlled credential source proving
  the exact successful operation/reference echo and zeroizing plaintext.
- [x] Run only the new loader tests and observe the expected missing behavior.
- [x] Implement the minimum descriptor-relative source, security policy,
  bounded read, and loader mapping. Recheck security metadata after reading.
- [x] Run all `aster-systemd-credentials` tests until green.
- [x] Commit as `feat(credentials): load secure systemd credential`.

### Task 3: Enforce protected bootstrap before any listener

**Files:**
- Modify: `crates/aster-agent/src/runtime.rs`
- Modify: `crates/aster-agent/tests/customer_runtime.rs`

**Interfaces:**
- `run_customer_agent` loads and validates the protected node configuration
  before binding health or application listeners and before opening state.
- Startup still invokes the loader exactly once.

- [x] Change the existing blocked-loader test to prove both listener addresses
  remain unbound until protected bootstrap completes.
- [x] Add/retain a rejecting-loader assertion proving no state directory and no
  listener exists after protected bootstrap failure.
- [x] Run those exact customer-runtime tests and observe failure because the
  health listener currently binds before `open_node_config`.
- [x] Move protected bootstrap ahead of health binding without broadening
  failure output or changing ready-state semantics.
- [x] Run the two focused customer-runtime tests until green.
- [x] Commit as `fix(agent): bootstrap before opening listeners`.

### Task 4: Statically compose the provider into `aster-agent --config`

**Files:**
- Modify: `crates/aster-agent/Cargo.toml`
- Modify: `crates/aster-agent/src/main.rs`
- Create: `crates/aster-agent/tests/systemd_provider_binary.rs`

**Interfaces:**
- The existing `aster-agent` binary loads strict config, constructs exactly
  one `SystemdCredentialLoader`, translates process signals, and calls
  `run_customer_agent`.
- `--check-config` remains a non-starting configuration/ordinary-credential
  preflight and the legacy development invocation remains unchanged.

- [x] Add a process test with a valid strict config and no
  `CREDENTIALS_DIRECTORY`; assert the binary now fails with the fixed provider
  unavailable category and never emits the old `protected provider required`
  placeholder or creates state.
- [x] Run the exact process test and observe the old placeholder failure.
- [x] Add the provider dependency and wire `CustomerConfig` to the systemd
  loader and existing customer runtime in the same executable.
- [x] Run the process test and the affected production binary until green;
  skip a redundant second large-bin link after the tmpfs-backed linker emitted
  SIGBUS under confirmed storage/swap pressure.
- [x] Commit as `feat(agent): compose systemd credential provider`.

### Task 5: Document and narrowly verify the increment

**Files:**
- Create: `crates/aster-systemd-credentials/README.md`
- Modify: `docs/decisions/0041-customer-operable-event-service.md`

**Interfaces:**
- Documents the implemented loader boundary and explicitly lists the remaining
  D06 admin/ledger/lifecycle/package/device work.
- Makes no requirements-status or profile-qualification change.

- [ ] Document the fixed credential name, provider identity, environment and
  filesystem requirements, static composition, sanitized failures, and all
  non-claims.
- [ ] Update Decision 0041 only to replace the runtime provider placeholder
  with the exact implemented boundary and retain its stacked-branch status.
- [ ] Run `cargo test -p aster-systemd-credentials` plus only the affected
  `aster-agent` runtime/binary tests.
- [ ] Run `cargo fmt --all -- --check`, `cargo clippy -p
  aster-systemd-credentials --all-targets -- -D warnings`, and
  `git diff --check`.
- [ ] Do not run `mise run check` during iteration. Before a substantive code
  handoff, decide with the owner whether the full gate belongs here or in the
  deterministic release-gate lane already in progress.
- [ ] Request focused code review; do not claim G3/G4 or close D06 overall.
