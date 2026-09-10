# D06 Raspberry Pi systemd credential provider v2 adaptation implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adapt draft PR #4's existing systemd runtime-loader and initial-install
increment to the exact Raspberry Pi `aster-systemd-credential-store/v2`
profile without broadening its implemented lifecycle claim.

**Architecture:** Preserve the existing first-party
`aster-systemd-credentials` crate, static `aster-agent` composition, fixed
credential name, descriptor-relative runtime loader, root-only administration
command, and crash-recoverable initial-install transaction. Advance every
provider-owned durable/envelope schema to version 2 so a v2 binary fails closed
on v1 state, then align the crate and Event-service decision documentation with
the exact approved Raspberry Pi environment. Keep rotation, same-host
backup/recovery, revoke/rekey orchestration, logical destruction, hardened
unit, package identity, and G4 evidence in later focused increments.

**Tech Stack:** Rust 2024, `aster-core` provisioning contracts, `rustix`,
`zeroize`, `sha2`, Linux systemd credentials, Markdown decisions.

**Spec:**
[`docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md`](../specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md)

## Global Constraints

- Provider contract is exactly `aster-systemd-credential-store/v2`.
- Target only Raspberry Pi reference image `2026-06-18`, Debian GNU/Linux 13
  `trixie`, Raspberry Pi Compute Module 4 Rev 1.1, `aarch64`, kernel
  `6.18.39+rpt-rpi-v8`, systemd `257.13-1~deb13u1`, and local `ext4`.
- Credential name remains exactly `aster-provisioning.bundle`.
- Administration invokes only `/usr/bin/systemd-creds encrypt
  --with-key=host --name=aster-provisioning.bundle - -`.
- Runtime loading still requires the systemd-managed secure credential surface,
  exact mode `0400`, effective-service ownership, regular single-link type, and
  one bounded read.
- There is no raw-bundle, age, plaintext-file, TPM2, alternate-provider, old
  generation, or v1 fallback.
- v1 provider references, envelopes, manifests, and ledgers fail closed under
  the v2 binary; no in-place migration is supported for an unissued candidate.
- Preserve protected bootstrap before state/listener side effects, sanitized
  failures, zeroizing plaintext ownership, atomic install/retry behavior, and
  existing Event wire/API behavior.
- Do not claim E01 approval, complete E09 lifecycle, G3 package freeze, G4
  physical qualification, generic Debian/Raspberry Pi OS support, or
  production readiness.
- Do not modify the historical v1 design or its two completed implementation
  plans; they remain evidence of how the existing branch was built.
- Use focused verification with `CARGO_BUILD_JOBS=1` and
  `RUST_TEST_THREADS=1`. Do not run `mise run check`; run the repository's
  parser-specific `mise run fuzz-smoke` gate because provider codecs change.

---

### Task 1: Version every provider-owned format and reject v1 state

**Files:**
- Modify: `crates/aster-systemd-credentials/src/lib.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/ledger.rs`
- Modify: `crates/aster-systemd-credentials/src/admin/files.rs`
- Test: tests embedded in the three files above

**Interfaces:**
- Consumes: current v1 provider reference, envelope, manifest, and ledger
  codecs from draft PR #4.
- Produces: contract `aster-systemd-credential-store/v2`; schema version `2`
  for every provider-owned codec; unchanged public Rust function signatures.

- [ ] **Step 1: Add failing contract and v1-rejection tests**

Add a provider identity test in `src/lib.rs`:

```rust
#[test]
fn provider_contract_is_exact_raspberry_pi_v2() {
    assert_eq!(super::PROVIDER_CONTRACT, "aster-systemd-credential-store/v2");
}
```

Extend the reference/envelope rejection tables to mutate their encoded version
field to `1` and assert `ProvisioningSecretStoreError::Rejected`. Extend the
manifest and ledger codec tests in the same way. Keep literal assertions that
new canonical encodings contain version `2`.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -p aster-systemd-credentials --lib
```

Expected: the new exact-contract/version assertions fail because the current
implementation still emits and accepts version 1.

- [ ] **Step 3: Advance the contract and all provider schemas to v2**

Make these exact changes without renaming the stable credential or public
functions:

```rust
pub const PROVIDER_CONTRACT: &str = "aster-systemd-credential-store/v2";
const PROVIDER_REFERENCE_VERSION: u16 = 2;
const CREDENTIAL_ENVELOPE_VERSION: u16 = 2;
```

In `admin/ledger.rs` set `LEDGER_VERSION` to `2`. In `admin/files.rs` set
`MANIFEST_VERSION` to `2`. Update version-oriented Rust documentation from v1
to v2. Do not accept both versions and do not add a migration path.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the Task 1 command again.

Expected: every provider library test passes, including explicit rejection of
version-1 provider state.

- [ ] **Step 5: Commit the v2 format boundary**

```bash
git add crates/aster-systemd-credentials/src/lib.rs \
  crates/aster-systemd-credentials/src/admin/ledger.rs \
  crates/aster-systemd-credentials/src/admin/files.rs
git commit -m "feat(credentials): advance systemd provider to v2"
```

### Task 2: Align executable and integration tests with the v2 contract

**Files:**
- Modify: `crates/aster-systemd-credentials/src/admin.rs`
- Modify: `crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs`
- Modify: `crates/aster-agent/tests/systemd_provider_binary.rs`
- Test: existing provider crate and binary integration tests

**Interfaces:**
- Consumes: Task 1's v2 codecs with unchanged Rust signatures.
- Produces: a v2-only initial-install/admin path and an `aster-agent` process
  probe that protects the static provider selection and pre-listener failure
  boundary.

- [ ] **Step 1: Add failing executable-level v2 assertions**

In the admin binary tests, assert that the compiled provider contract exposed
to the invocation layer is exactly v2 without printing it in successful or
failed command output. In `systemd_provider_binary.rs`, retain the missing
`CREDENTIALS_DIRECTORY` process test and add a source-level contract assertion:

```rust
#[test]
fn customer_binary_uses_the_v2_provider_contract() {
    assert_eq!(
        aster_systemd_credentials::PROVIDER_CONTRACT,
        "aster-systemd-credential-store/v2"
    );
}
```

- [ ] **Step 2: Run affected binary tests**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -p aster-systemd-credentials --bin aster-credential-admin
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -p aster-agent --test systemd_provider_binary
```

Expected after Task 1: all assertions pass. If an invocation-layer assertion
cannot compile because the binary does not import the library constant, add
that private import and no output or CLI option.

- [ ] **Step 3: Remove stale v1/Ubuntu implementation comments**

Search the implementation files and replace only active claims:

```bash
rg -n "Ubuntu|255\.4|credential-store/v1|exact v1|v1 provider" \
  crates/aster-systemd-credentials crates/aster-agent/tests/systemd_provider_binary.rs
```

Every remaining match must be an explicit historical/rejection test. Do not
change Event API/config schema v1 references; they are unrelated public
interfaces.

- [ ] **Step 4: Run the complete focused provider suite**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -p aster-systemd-credentials
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -p aster-agent --test customer_runtime
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  cargo test -p aster-agent --test systemd_provider_binary
```

Expected: all provider, customer-runtime, and provider-composition tests pass
with one build job and one test thread.

- [ ] **Step 5: Commit executable alignment**

```bash
git add crates/aster-systemd-credentials/src/admin.rs \
  crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs \
  crates/aster-agent/tests/systemd_provider_binary.rs
git commit -m "test(credentials): bind agent and admin to provider v2"
```

If Task 2 requires no production-code edit, commit only the tests that changed.

### Task 3: Align documentation without expanding the lifecycle claim

**Files:**
- Modify: `crates/aster-systemd-credentials/Cargo.toml`
- Modify: `crates/aster-systemd-credentials/README.md`
- Modify: `docs/decisions/0041-customer-operable-event-service.md`

**Interfaces:**
- Consumes: the approved v2 design and Tasks 1–2's exact implementation.
- Produces: reviewable implementation claims for PR #4 while keeping E01,
  E09, G3, and G4 open.

- [ ] **Step 1: Replace the crate's active platform identity**

Set the Cargo description to:

```toml
description = "Raspberry Pi systemd credential store provider for Aster provisioning"
```

Update the README title/body to identify exactly:

```text
provider = aster-systemd-credential-store/v2
image = Raspberry Pi reference 2026-06-18
distribution = Debian GNU/Linux 13 (trixie)
hardware = Raspberry Pi Compute Module 4 Rev 1.1
architecture = aarch64
kernel = 6.18.39+rpt-rpi-v8
systemd = 257.13-1~deb13u1
credential executable = /usr/bin/systemd-creds
filesystem = ext4
TPM2 = excluded
```

State that the current code implements runtime load and crash-recoverable
generation-one install only. List rotation, backup/recovery, revoke/rekey,
logical destruction, hardened unit, package/executable freeze, and two-node G4
qualification as open. Link the approved v2 design on `main`; retain a short
historical note that v1 state is deliberately rejected rather than migrated.

- [ ] **Step 2: Update Decision 0041's stacked-provider paragraph**

Replace active Ubuntu/v1 wording with the exact v2 contract and Raspberry Pi
profile. Preserve the Event-service decision itself, its evidence status, and
all implementation exclusions. Add no claim that E01, E09, G3, or G4 passed.

- [ ] **Step 3: Check documentation scope**

Run:

```bash
rg -n "aster-systemd-credential-store/v2|Raspberry Pi reference 2026-06-18|Debian GNU/Linux 13|Compute Module 4|257.13-1~deb13u1|aarch64|TPM2" \
  crates/aster-systemd-credentials/README.md \
  docs/decisions/0041-customer-operable-event-service.md
rg -n "Ubuntu|255\.4|credential-store/v1|generic Debian|generic Raspberry Pi" \
  crates/aster-systemd-credentials/README.md \
  docs/decisions/0041-customer-operable-event-service.md
git diff --check
```

Expected: all target identifiers appear. Any old/generic platform match is
only an explicit historical or non-claim statement. Whitespace check passes.

- [ ] **Step 4: Commit documentation alignment**

```bash
git add crates/aster-systemd-credentials/Cargo.toml \
  crates/aster-systemd-credentials/README.md \
  docs/decisions/0041-customer-operable-event-service.md
git commit -m "docs(credentials): align initial provider with Raspberry Pi v2"
```

### Task 4: Run required parser checks and update draft PR #4

**Files:**
- Modify only if verification exposes a defect: provider/tests/docs from Tasks
  1–3
- External update: draft PR #4 title and description

**Interfaces:**
- Consumes: complete v2 adaptation.
- Produces: a pushed draft provider branch whose PR accurately describes the
  implemented and open boundaries.

- [ ] **Step 1: Run formatting, focused lint, and parser verification**

Run:

```bash
cargo fmt --all -- --check
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials \
  CARGO_BUILD_JOBS=1 \
  cargo clippy -p aster-systemd-credentials --all-targets -- -D warnings
MISE_JOBS=1 CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 mise run fuzz-smoke
git diff --check origin/feature/customer-operable-event-service...HEAD
```

Expected: formatting, Clippy, all deterministic fuzz-smoke targets, and the
stacked-range whitespace check pass. Do not run `mise run check` in this
increment.

- [ ] **Step 2: Verify claim-boundary integrity**

Run:

```bash
rg -n "aster-systemd-credential-store/v1|Ubuntu Server 24\.04|systemd 255\.4" \
  crates/aster-systemd-credentials docs/decisions/0041-customer-operable-event-service.md
python3 tools/check-implementation-requirements.py
git status --short --branch
```

Expected: old-provider matches are limited to explicit rejection/history;
requirements trace remains valid without evidence-status changes; only planned
files and commits differ.

- [ ] **Step 3: Push the existing provider branch**

```bash
git push origin feature/ubuntu-systemd-credential-provider
```

Do not rename the remote branch during this increment; retaining it avoids
breaking PR #4 and existing team links. The PR title provides the current
identity.

- [ ] **Step 4: Update draft PR #4**

Set the title to:

```text
feat(credentials): add Raspberry Pi systemd credential provider v2
```

Update the body using `.github/pull_request_template.md`. It must say:

- PR #4 remains stacked on Event-service PR #2;
- profile PR #3 merged at `b7fe15eac194629b6530b7c4b3411e1a25d48641`;
- the exact v2 contract/platform boundary;
- implemented: v2 codecs, secure runtime load, pre-listener bootstrap,
  generation-one atomic install/retry/reconciliation;
- open: E01 role approval, rotation, backup/recovery, revoke/rekey, logical
  destruction, hardened unit, G3 package freeze, and two-node G4 evidence;
- no age, plaintext-file, TPM2, alternate-provider, or v1 fallback;
- focused test counts and the intentionally omitted full `mise run check`.

Keep the PR draft. Do not mark E01, E09, G3, G4, or requirements evidence as
complete.

- [ ] **Step 5: Verify remote PR state**

Run:

```bash
gh pr view 4 --repo edgesoftops/astertech \
  --json url,title,state,isDraft,baseRefName,headRefName,headRefOid,body
```

Expected: PR #4 is open and draft, based on
`feature/customer-operable-event-service`, points to the local pushed HEAD,
and describes the Raspberry Pi v2 boundary.
