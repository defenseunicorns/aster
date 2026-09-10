# D06 Initial systemd Credential Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first root-admin lifecycle increment: one crash-recoverable initial install, exact idempotent retry, and changed-input conflict for the fixed encrypted systemd credential.

**Architecture:** Keep the runtime loader unchanged. A new administration module owns a versioned root-only ledger and a staged active-generation directory; it validates the canonical bundle, builds the existing provider envelope, invokes the fixed `systemd-creds` interface through pipes, and commits intent, active generation, and completion in recoverable order. A small `aster-credential-admin` binary accepts secret bytes only on standard input and exposes only sanitized outcomes.

**Tech Stack:** Rust 2024, `aster-core` provisioning contracts, `rustix`, `getrandom`, `sha2`, Linux `systemd-creds`.

**Spec:** `feature/p0-1-linux-event-mvp-profile:docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md`; local runtime boundary in `crates/aster-systemd-credentials/README.md`.

## Global Constraints

- The supported profile remains Ubuntu Server 24.04 with the systemd 255.4 credential interface; Debian 13/257 device runs are development compatibility checks only.
- Provider contract is exactly `aster-systemd-credential-store/v1`; credential name is exactly `aster-provisioning.bundle`.
- Encryption invokes `/usr/bin/systemd-creds encrypt --with-key=host --name=aster-provisioning.bundle - -`; no automatic, TPM2, age, alternate-provider, or plaintext-file fallback exists.
- Provisioning plaintext is accepted only from an already-open descriptor or standard input, never arguments, environment values, or a plaintext pathname.
- This increment implements initial install only. Mission-reference rotation, backup/recovery, revoke/rekey, and logical destruction remain later increments.
- Every filesystem mutation is owner-only, descriptor-relative/no-follow where supported, synchronized before visibility, and represented by an intent/completion ledger transition.
- One root-owned lock descriptor serializes administration operations for the provider namespace; a concurrent invocation fails closed without reading stdin.
- Output and errors contain no plaintext, paths, operation identifiers, provider output, envelope commitment, or ciphertext.

---

### Task 1: Versioned install ledger and reconciliation state

**Files:**
- Create: `crates/aster-systemd-credentials/src/admin.rs`
- Create: `crates/aster-systemd-credentials/src/admin/ledger.rs`
- Modify: `crates/aster-systemd-credentials/src/lib.rs`
- Modify: `crates/aster-systemd-credentials/Cargo.toml`

**Interfaces:**
- Consumes: `ProvisioningInstallId`, `ProvisioningLoadId`, `ProvisioningSecretRef`, and `provisioning_secret_ref(generation, reference_id)`.
- Produces: private `InstallRecord`, `InstallPhase::{Intent, Complete}`, `encode_record`, `decode_record`, and `classify_retry` used by the filesystem transaction.

- [x] **Step 1: Write failing canonical-ledger and retry tests**

```rust
#[test]
fn ledger_round_trip_preserves_exact_install_binding() {
    let record = fixture_record(InstallPhase::Complete);
    assert_eq!(decode_record(&encode_record(&record)).unwrap(), record);
}

#[test]
fn exact_retry_is_existing_and_changed_input_conflicts() {
    let record = fixture_record(InstallPhase::Complete);
    assert_eq!(classify_retry(&record, record.install, record.load, record.envelope_commitment).unwrap(), Retry::Existing);
    assert_eq!(classify_retry(&record, record.install, record.load, [9; 32]).unwrap_err(), ProvisioningSecretStoreError::OperationConflict);
}
```

- [x] **Step 2: Run the focused tests and verify RED**

Run: `CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials admin::ledger::tests --lib`

Expected: compilation fails because the ledger module and types do not exist.

- [x] **Step 3: Implement the bounded canonical record**

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallPhase { Intent = 1, Complete = 2 }

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstallRecord {
    phase: InstallPhase,
    install: ProvisioningInstallId,
    load: ProvisioningLoadId,
    secret_ref: ProvisioningSecretRef,
    generation: u64,
    envelope_commitment: [u8; 32],
    ciphertext_digest: [u8; 32],
}
```

Encode and decode a fixed-magic, version-1, length-delimited record. Reject zero generation, unknown phase/version, reserved bytes, noncanonical references, trailing bytes, and records whose reference generation differs from `generation`. `classify_retry` returns `Existing` only for the exact install/load/commitment tuple and `OperationConflict` otherwise.

- [x] **Step 4: Run focused tests and verify GREEN**

Run: `CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials admin::ledger::tests --lib`

Expected: all ledger tests pass.

- [x] **Step 5: Commit the ledger model**

```bash
git add crates/aster-systemd-credentials/Cargo.toml crates/aster-systemd-credentials/src/lib.rs crates/aster-systemd-credentials/src/admin.rs crates/aster-systemd-credentials/src/admin/ledger.rs
git commit -m "feat(credentials): define durable install ledger"
```

### Task 2: Staged encryption and crash-recoverable initial install

**Files:**
- Create: `crates/aster-systemd-credentials/src/admin/files.rs`
- Create: `crates/aster-systemd-credentials/src/admin/encrypt.rs`
- Modify: `crates/aster-systemd-credentials/src/admin.rs`

**Interfaces:**
- Consumes: Task 1 ledger codec and the existing `encode_credential_envelope`.
- Produces: `SystemdCredentialAdmin::open()`, `SystemdCredentialAdmin::install(operation, load, plaintext)`, and an internal bounded `CredentialEncryptor` seam.

- [x] **Step 1: Write failing install/reopen/fault tests**

```rust
#[test]
fn install_commits_ciphertext_reference_manifest_and_ledger() {
    let fixture = AdminFixture::new();
    let receipt = fixture.admin().install(INSTALL, LOAD, fixture.bundle()).unwrap();
    assert_eq!(receipt.disposition(), ProvisioningInstallDisposition::Installed);
    fixture.assert_complete_active_generation(receipt.secret_ref());
}

#[test]
fn reopen_replays_exact_install_without_encrypting_again() {
    let fixture = AdminFixture::new();
    let first = fixture.admin().install(INSTALL, LOAD, fixture.bundle()).unwrap();
    let second = fixture.reopen().install(INSTALL, LOAD, fixture.bundle()).unwrap();
    assert_eq!(second.disposition(), ProvisioningInstallDisposition::Existing);
    assert_eq!(second.secret_ref(), first.secret_ref());
    assert_eq!(fixture.encrypt_calls(), 1);
}

#[test]
fn intent_with_matching_active_generation_reconciles_to_complete() {
    let fixture = AdminFixture::new_with_fault(FaultPoint::ActiveRenamed);
    assert_eq!(fixture.install_once().unwrap_err(), ProvisioningSecretStoreError::Unavailable);
    let receipt = fixture.reopen_without_fault().install(INSTALL, LOAD, fixture.bundle()).unwrap();
    assert_eq!(receipt.disposition(), ProvisioningInstallDisposition::Existing);
    fixture.assert_ledger_complete();
}
```

Add separate tests for changed plaintext/load operation conflict, invalid bundle before mutation/encryption, ciphertext over one MiB, unsafe/symlinked roots, intent without matching active generation, and faults after each synchronization/rename boundary.

Also prove that a second administrator cannot acquire the namespace lock, an
orphan stage without an intent is discarded, a matching intent plus staged
generation is promoted without a second encryption, and a matching intent plus
active generation is completed without a second encryption. An intent whose
stage and active generation both mismatch is rejected and retained for manual
inspection; it is never silently discarded or overwritten.

- [x] **Step 2: Run the focused install tests and verify RED**

Run: `CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials admin::tests --lib`

Expected: compilation fails because `SystemdCredentialAdmin` and transaction types do not exist.

- [x] **Step 3: Implement minimal staged transaction and recovery**

```rust
pub struct SystemdCredentialAdmin {
    provisioning_root: OwnedFd,
    ledger_root: OwnedFd,
    namespace_lock: OwnedFd,
    encryptor: SystemdCredsEncryptor,
}

impl SystemdCredentialAdmin {
    pub fn open() -> Result<Self, ProvisioningSecretStoreError>;
    pub fn install(
        &mut self,
        operation: ProvisioningInstallId,
        load: ProvisioningLoadId,
        plaintext: UnprotectedProvisioning,
    ) -> Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError>;
}
```

Acquire a nonblocking exclusive `flock` on the root-owned ledger lock before
reading secret input. Validate the canonical bundle before any mutation,
generate a 32-byte reference identity from `SysRng`, encode the generation-1
envelope, hash it, and invoke the encryptor once. Create a same-filesystem
owner-only fixed staging directory containing `credential.cred`, `reference`,
and `manifest`; synchronize each file and the directory. Atomically persist an
intent ledger record, rename staging to `active`, synchronize the provisioning
parent, then atomically persist the complete ledger record.

On reopen, reconcile before accepting a new operation. A matching active
generation advances intent to complete. Otherwise, a matching staged
generation is renamed to active and then completed. An orphan stage with no
ledger is removed before a fresh install. Any mismatched active/stage/intent
combination returns `Rejected` while retaining the evidence. This makes every
retry either reuse the already encrypted bytes or fail closed; it never
silently re-encrypts an in-flight operation.

The production encryptor executes only:

```rust
Command::new("/usr/bin/systemd-creds")
    .args(["encrypt", "--with-key=host", "--name=aster-provisioning.bundle", "-", "-"])
```

Pipe the zeroizing envelope to stdin, capture at most `MAX_PROTECTED_PROVISIONING_BYTES + 1` bytes from stdout, discard stderr, and map all child/process failures to fixed store categories.

- [x] **Step 4: Run focused install tests and verify GREEN**

Run: `CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials admin::tests --lib`

Expected: all transaction, retry, safety, and fault tests pass.

- [x] **Step 5: Commit the initial install transaction**

```bash
git add crates/aster-systemd-credentials/src/admin.rs crates/aster-systemd-credentials/src/admin/files.rs crates/aster-systemd-credentials/src/admin/encrypt.rs
git commit -m "feat(credentials): install systemd credential atomically"
```

### Task 3: Root-operated install command and development-device smoke

**Files:**
- Create: `crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs`
- Modify: `crates/aster-systemd-credentials/Cargo.toml`
- Modify: `crates/aster-systemd-credentials/README.md`

**Interfaces:**
- Consumes: `SystemdCredentialAdmin::open` and `install`.
- Produces: `aster-credential-admin install --operation <64 lowercase hex> --load-operation <64 lowercase hex>`, reading the bundle only from stdin.

- [x] **Step 1: Write failing parser/output tests**

```rust
#[test]
fn install_parser_accepts_only_exact_lowercase_operation_ids() {
    assert!(Invocation::parse(["install", "--operation", &"11".repeat(32), "--load-operation", &"22".repeat(32)]).is_ok());
    assert!(Invocation::parse(["install", "--operation", "11", "--load-operation", &"22".repeat(32)]).is_err());
}

#[test]
fn parser_rejects_secret_paths_and_unknown_arguments() {
    assert!(Invocation::parse(["install", "--input", "/tmp/bundle"]).is_err());
}
```

- [x] **Step 2: Run the binary tests and verify RED**

Run: `CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials --bin aster-credential-admin`

Expected: the binary target or parser does not exist.

- [x] **Step 3: Implement the minimal root-only command**

```rust
fn main() -> ExitCode {
    match run() {
        Ok(disposition) => { println!("INSTALL disposition={disposition}"); ExitCode::SUCCESS }
        Err(error) => { eprintln!("ERROR {error}"); ExitCode::FAILURE }
    }
}
```

Reject non-root execution before reading stdin, accept no environment configuration or input pathname, read at most `MAX_UNPROTECTED_PROVISIONING_BYTES + 1`, and print only `installed` or `existing`. Keep opaque reference material out of this first command's stdout until its supported owner-only handoff format is implemented.

- [x] **Step 4: Run focused crate and CLI verification**

Run:

```bash
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials
CARGO_TARGET_DIR=/home/andrii/code/aster/target/d06-systemd-credentials CARGO_BUILD_JOBS=1 cargo clippy -p aster-systemd-credentials --all-targets -- -D warnings
cargo fmt --all -- --check
```

Expected: all focused tests pass, Clippy reports no warnings, and formatting is unchanged.

- [ ] **Step 5: Run non-qualifying hardware smoke**

Build the aarch64 artifact through the reproducible-artifact lane, install only a non-production fixture on one CM4/Debian 13 development node, and record the run explicitly as `development-compatibility-only`. Confirm `systemd-creds` accepts the exact fixed command, the encrypted file contains no plaintext canary, the runtime credential appears only during service activation, and an exact retry performs no second encryption. Do not attach this result to G4 or claim Ubuntu/Debian qualification.

Compatibility preflight on 2026-09-08 initialized the previously absent systemd
host key on `rpi4-1`, `rpi4-2`, and `rpi4-3`, then passed the exact
`--with-key=host`/fixed-name in-memory encrypt/decrypt round trip on systemd
257.13. Systemd reported that the host key is not on encrypted media. This is
environment feedback only: no Aster artifact was installed, and this step
remains incomplete until the reproducible aarch64 artifact runs the complete
command/runtime/retry checks.

- [x] **Step 6: Commit the command and documentation**

```bash
git add crates/aster-systemd-credentials/Cargo.toml crates/aster-systemd-credentials/src/bin/aster-credential-admin.rs crates/aster-systemd-credentials/README.md
git commit -m "feat(credentials): add initial install command"
```
