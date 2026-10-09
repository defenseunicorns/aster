# Docker Compose secret provider implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a bounded Linux Docker Compose profile in which a non-root Aster agent consumes one immutable, file-backed credential generation without systemd or Docker Swarm.

**Architecture:** Keep the existing `aster-agent` package binary as the systemd-backed Debian entry point. Add a separate `aster-compose-credentials` package whose Docker-specific binary is also named `aster-agent`; it parses schema v2, loads the three fixed Compose secret mounts, and calls provider-neutral runtime seams in the `aster-agent` library. The provider uses canonical activation/envelope formats, descriptor-based mount validation, and exact generation binding. Separate scratch runtime and administration images support preflight, state initialization, generation creation, verification, and recreate-based rotation.

**Tech Stack:** Rust 1.97.1 workspace, Tokio, rustix/libc Linux APIs, serde/serde_json, ConnectRPC protobuf, Docker Compose v2, Python 3.13 daemon-free delivery validation, CycloneDX tooling, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-07-compose-secret-provider-design.md`

## Global Constraints

- Do not add Swarm manifests, Swarm secrets, systemd to the runtime image, a runtime provider selector, a raw-bundle fallback, or automatic rollback.
- Preserve schema v1 and the systemd provider for Debian/package builds. The Docker binary accepts only schema v2; the systemd binary accepts only schema v1.
- Preserve `cargo clippy --workspace --all-targets --all-features`: package boundaries and `required-features` must provide static selection without a mutually exclusive-feature `compile_error!`.
- Runtime secret paths are fixed to `/run/secrets/aster-client-token`, `/run/secrets/aster-mission-activation`, and `/run/secrets/aster-provisioning-bundle`.
- Secret bytes must not enter arguments, environment variables, stdout/stderr, lifecycle/health output, manifests, Compose render output, image layers, or build logs.
- The only supported activation is `docker compose up -d --force-recreate`; documentation and validators must reject `docker compose restart` as a rotation procedure.
- Do not claim that this increment qualifies any Docker host profile. Real-Docker lifecycle qualification is deferred; current automation is daemon-free and operator execution follows documented manual procedures.
- Apply test-driven development in every task: add the focused failing test first, run it and capture the expected failure, make the smallest implementation, then run focused and regression checks.
- Do not edit requirement status optimistically. Update implementation evidence only after the real artifact exists; keep incomplete production obligations open or explicitly `implemented-uncredited`.

## Review Focus

1. `/proc/self/mountinfo` parsing must fail closed on escaped paths, malformed records, duplicate targets, missing targets, and any writable target.
2. Token, activation, and envelope from different generations must never compose successfully, even when individual files are valid.
3. Runtime UID ownership must match the effective nonzero UID; documentation must not imply that rootless, user-remapped, Desktop, remote-context, or non-Linux profiles were qualified.
4. Manual rotation and rollback instructions must preserve the user-owned state directory; rollback must be explicit and valid only while the prior generation remains authorized.
5. Known canary secrets must be absent from retained static output surfaces, including rendered Compose, image history/layers, manifests, SBOMs, and provenance.

---

## Task 1: Introduce the Compose credential formats and fail-closed file boundary

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/aster-compose-credentials/Cargo.toml`
- Create: `crates/aster-compose-credentials/LICENSE`
- Create: `crates/aster-compose-credentials/README.md`
- Create: `crates/aster-compose-credentials/src/lib.rs`
- Create: `crates/aster-compose-credentials/src/format.rs`
- Create: `crates/aster-compose-credentials/src/secret_file.rs`
- Create: `crates/aster-compose-credentials/src/mountinfo.rs`
- Create: `crates/aster-compose-credentials/tests/provider.rs`
- Create: `crates/aster-compose-credentials/tests/secret_boundary.rs`

- [ ] **Step 1: Add failing canonical-format tests.**

  Specify these exact binary formats in `format.rs` tests:

  ```text
  provider reference = "ASTRCSRF" || u16be(1) || u16be(0) || generation[32] || reference_id[32]
  activation         = "ASTRCSAC" || u16be(1) || u16be(0) || load_id[32]
                       || u32be(reference_len) || canonical_reference
  envelope           = "ASTRCSEN" || u16be(1) || u16be(0) || load_id[32]
                       || u32be(reference_len) || u32be(bundle_len)
                       || canonical_reference || canonical_ASTRPB03_bundle
  ```

  Add table tests for round trip, each magic/version/reserved field, zero/oversized lengths, truncation, trailing bytes, invalid inner `ASTRPB03`, wrong provider, wrong reference, wrong load ID, and wrong generation. Assert errors expose only fixed `ComposeCredentialReason` variants and all credential-bearing `Debug` implementations print redacted placeholders.

- [ ] **Step 2: Run the format tests and verify they fail for the missing crate/API.**

  Run: `cargo test -p aster-compose-credentials --test provider`

  Expected: FAIL because the crate and canonical types do not exist.

- [ ] **Step 3: Implement the smallest canonical parser and loader.**

  Add:

  ```rust
  pub const PROVIDER_CONTRACT: &str = "aster-compose-secret-store/v1";
  pub struct ComposeCredentialGeneration([u8; 32]);
  pub struct ComposeActivation { /* redacted fields */ }
  pub struct ComposeProvisioningLoader { /* one envelope, consumed once */ }
  pub enum ComposeCredentialReason {
      UnsupportedPlatform, FileAccess, InvalidMountBoundary, Changed,
      NotRegular, LinkCount, Ownership, Permissions, TooLarge,
      InvalidActivation, InvalidEnvelope, InvalidBundle, ProviderMismatch,
      GenerationMismatch, ReferenceMismatch, OperationMismatch, AlreadyConsumed,
  }
  ```

  Parse the provider reference into Aster's existing `ProvisioningSecretRef`, parse the load ID into `ProvisioningLoadId`, and implement `ProvisioningSecretLoader` so the envelope can be consumed exactly once. Retain bundle bytes only in Aster-owned zeroizing storage. Never fall back to interpreting the envelope as a raw bundle.

- [ ] **Step 4: Add failing Linux file/mount-boundary tests.**

  In `secret_boundary.rs`, cover regular files, final and parent symlinks, FIFO, directory, hard link, wrong owner, root UID, modes other than exactly `0400`/`0600`, oversized/truncated/changed files, and read-only versus writable mount records. Add pure parser fixtures for mountinfo escapes (`\040`, `\011`, `\012`, `\134`), malformed lines, duplicate exact targets, prefix-confusion targets, missing targets, and `ro` in the wrong option field.

- [ ] **Step 5: Run the boundary tests and verify the intended failures.**

  Run: `cargo test -p aster-compose-credentials --test secret_boundary`

  Expected: FAIL because descriptor opening and mountinfo checks are absent.

- [ ] **Step 6: Implement descriptor-based bounded reads.**

  On Linux, open the fixed `/run/secrets` directory and each basename with `openat2` using `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`; open files with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`. Before and after a bounded read, compare device, inode, UID, mode, link count, size, mtime, and ctime. Require effective UID to be nonzero and equal the file owner, a regular file, link count one, and mode exactly `0400` or `0600`.

  Parse `/proc/self/mountinfo` with a 1 MiB total bound, decode only the defined octal escapes, and require one unique exact `ro` mount target for each fixed file. Keep test-only path and mountinfo injection crate-private so production has no alternate secret root.

- [ ] **Step 7: Run focused and workspace regressions.**

  Run:

  ```bash
  cargo test -p aster-compose-credentials
  cargo clippy --locked -p aster-compose-credentials --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```

  Expected: PASS; known fixture bytes do not occur in captured diagnostics.

- [ ] **Step 8: Commit.**

  ```bash
  git add Cargo.toml Cargo.lock crates/aster-compose-credentials
  git commit -m "feat: add Compose credential provider"
  ```

## Task 2: Add immutable credential-generation administration

**Files:**

- Create: `crates/aster-compose-credentials/src/generation.rs`
- Create: `crates/aster-compose-credentials/src/bin/aster-compose-credential-admin.rs`
- Create: `crates/aster-compose-credentials/tests/admin_generation.rs`
- Modify: `crates/aster-compose-credentials/Cargo.toml`
- Modify: `crates/aster-compose-credentials/README.md`

- [ ] **Step 1: Add failing generation tests.**

  Test `create --output-parent PATH --token-file PATH` with the canonical mission bundle supplied only on stdin. Require a fresh random generation/reference/load ID, final name `generation-<64-lowercase-hex>`, files named `aster-client-token`, `aster-mission-activation`, `aster-provisioning-bundle`, and `manifest.json`.

  Assert the manifest schema is `aster-compose-secret-generation/v1` and contains only provider contract, generation hex, UTC and Unix creation time, bounded sizes, and SHA-256 file digests. Assert secret canaries are absent from argv/environment/stdout/stderr/manifest, an existing final directory is refused, interrupted staging is not activated, and existing generations are byte-for-byte unchanged.

- [ ] **Step 2: Run the tests and verify the missing-command failure.**

  Run: `cargo test -p aster-compose-credentials --test admin_generation`

  Expected: FAIL because the admin binary and atomic writer do not exist.

- [ ] **Step 3: Implement atomic same-filesystem generation creation.**

  Require the admin container to run as the selected nonzero runtime UID/GID and create the staging directory beneath a parent writable by that identity. Use exclusive, no-follow file creation; write and sync all files; verify their owner is the effective UID and set exact `0400` or `0600` modes; write and sync the non-secret manifest; rename to the unique final name; then sync the parent. Reject root execution, cross-device or pre-existing destinations, and report only fixed categories. Do not grant the admin image `CAP_CHOWN` merely to repair host ownership.

  Success stdout is exactly:

  ```text
  CREATE disposition=created generation=<64-lowercase-hex>
  ```

  Do not print the output parent or any credential path.

- [ ] **Step 4: Verify zeroization and interruption behavior.**

  Add test-only fault points after each write/sync/rename boundary. Assert partial sensitive buffers are zeroized, incomplete directories retain a `.staging-` name, and no manifest or output claims activation before the final rename and parent sync complete.

- [ ] **Step 5: Run focused checks.**

  Run:

  ```bash
  cargo test -p aster-compose-credentials --test admin_generation
  cargo clippy --locked -p aster-compose-credentials --all-targets -- -D warnings
  ```

  Expected: PASS with no dynamic paths or secret values in error output.

- [ ] **Step 6: Commit.**

  ```bash
  git add crates/aster-compose-credentials
  git commit -m "feat: create immutable Compose credential generations"
  ```

## Task 3: Separate systemd and Compose binary composition

**Files:**

- Modify: `crates/aster-agent/Cargo.toml`
- Modify: `crates/aster-agent/src/config.rs`
- Modify: `crates/aster-agent/src/credentials.rs`
- Modify: `crates/aster-agent/src/runtime.rs`
- Modify: `crates/aster-agent/src/main.rs`
- Modify: `crates/aster-agent/tests/customer_runtime.rs`
- Modify: `crates/aster-agent/tests/systemd_provider_binary.rs`
- Create: `crates/aster-compose-credentials/src/bin/aster-agent.rs`
- Create: `crates/aster-compose-credentials/tests/compose_binary.rs`
- Modify: `crates/aster-compose-credentials/Cargo.toml`
- Modify: `debian/build.sh`

- [ ] **Step 1: Add failing tests for strict schema and static provider selection.**

  Preserve `load_and_validate_config` as schema-v1-only. Refactor its result into `ValidatedSystemdAgentConfig { runtime: ValidatedRuntimeConfig, credentials: CredentialPaths }`. Add `load_and_validate_compose_config`, returning `ValidatedComposeAgentConfig { runtime: ValidatedRuntimeConfig }`, which admits only schema v2 with exactly:

  ```json
  "credentials": {
    "client_token_file": "/run/secrets/aster-client-token",
    "mission_activation_file": "/run/secrets/aster-mission-activation"
  }
  ```

  Test v1 accepted/v2 rejected by the systemd binary, v2 accepted/v1 rejected by the Compose binary, unknown/duplicate/alternate path fields rejected, and `--check-config` performing credential preflight without touching state or binding a listener.

  Extend binary inspections to prove the Compose binary has no systemd provider strings/symbols/admin command and the Debian binary has no Compose-provider contract. Test that no CLI/environment option can select a provider.

- [ ] **Step 2: Run the tests and confirm schema-v2 and binary-boundary failures.**

  Run:

  ```bash
  cargo test -p aster-agent --test systemd_provider_binary
  cargo test -p aster-compose-credentials --test compose_binary
  ```

  Expected: FAIL because the agent library owns only the schema-v1/systemd startup path.

- [ ] **Step 3: Extract provider-neutral runtime seams.**

  Add these public APIs with redacted/debug-safe types:

  ```rust
  pub enum TokenReloadPolicy { Disabled, ReloadFrom(PathBuf) }

  pub struct CredentialGeneration([u8; 32]);

  pub async fn run_customer_agent_with_credentials<L>(
      config: ValidatedRuntimeConfig,
      credentials: StartupCredentials,
      loader: &mut L,
      signals: Receiver<AgentSignal>,
      reload: TokenReloadPolicy,
  ) -> Result<AgentExit, AgentRuntimeError>;
  ```

  Keep `run_customer_agent` as the schema-v1 wrapper that accepts `ValidatedSystemdAgentConfig`, calls `load_startup_credentials`, and selects `ReloadFrom`. Provide constructors for `StartupCredentials` rather than exposing mutable credential fields; the Compose constructor converts `ComposeCredentialGeneration::as_bytes()` into the provider-neutral `CredentialGeneration`. With `Disabled`, SIGHUP must retain the current token and emit one fixed, non-sensitive unsupported-reload lifecycle outcome.

- [ ] **Step 4: Make provider choice a package/binary property.**

  Make `aster-systemd-credentials` optional behind `systemd-provider`; declare the existing `src/main.rs` explicitly as `[[bin]] name = "aster-agent"` with `required-features = ["server", "systemd-provider"]`; include that feature in `aster-agent` defaults. The new package declares its own `[[bin]] name = "aster-agent"` and depends on `aster-agent` with `default-features = false, features = ["server"]`.

  The Compose binary loads schema v2, obtains the token/activation/envelope through Task 1, constructs startup credentials, and invokes `run_customer_agent_with_credentials(..., TokenReloadPolicy::Disabled)`. It has no legacy unprotected CLI mode. Update `debian/build.sh` to request `systemd-provider` explicitly and preserve package output.

- [ ] **Step 5: Run all feature combinations that CI exercises.**

  Run:

  ```bash
  cargo check --locked -p aster-agent --no-default-features --features server
  cargo check --locked -p aster-agent --all-features --all-targets
  cargo check --locked -p aster-compose-credentials --all-targets
  cargo test --locked -p aster-agent --all-features
  cargo test --locked -p aster-compose-credentials
  ```

  Expected: PASS. In particular, `--all-features` does not create a false mutually-exclusive-feature failure.

- [ ] **Step 6: Commit.**

  ```bash
  git add crates/aster-agent crates/aster-compose-credentials debian/build.sh Cargo.lock
  git commit -m "feat: statically compose the Docker credential provider"
  ```

## Task 4: Expose the public credential generation in ready status

**Files:**

- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `proto/aster/application/v1alpha1/aster.fds.bin`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.pb.go`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.connect.go`
- Modify: `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/src/lifecycle.rs`
- Modify: `crates/aster-agent/src/runtime.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/tests/customer_runtime.rs`
- Modify: `crates/aster-agent/tests/real_node_connect.rs`
- Modify: `crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs`
- Modify: `crates/aster-agent/README.md`

- [ ] **Step 1: Add failing status and lifecycle tests.**

  Add `bytes credential_generation = 12;` to `GetStatusResponse`. Test that a Compose startup reports exactly 32 generation bytes over authenticated status and a 64-character lowercase generation hex only on the `ready` lifecycle record. Assert systemd/legacy starts report an empty protobuf field and omit the lifecycle key. Assert no reference ID, load ID, path, digest, token, activation, or envelope appears.

- [ ] **Step 2: Run protocol and runtime checks and capture expected failures.**

  Run:

  ```bash
  sh tools/check-agent-proto.sh
  cargo test -p aster-agent --test customer_runtime
  cargo test -p aster-agent --test real_node_connect
  ```

  Expected: FAIL until generated bindings and service plumbing include field 12.

- [ ] **Step 3: Thread generation metadata through status without making it authorization.**

  Store `Option<CredentialGeneration>` in `StartupCredentials` and pass a copy into the application service/status construction. Do not pass the generation into mesh messages, state keys, provider authorization, or `ASTRPB03`. Update `status_response` and the single ready lifecycle emission; leave other lifecycle records structurally unchanged.

- [ ] **Step 4: Regenerate and verify protocol artifacts.**

  Use the repository's pinned protobuf generation commands from `tools/check-agent-proto.sh` and `tools/check-agent-go-generated.sh`. Do not hand-edit generated Go or descriptor bytes.

  Run:

  ```bash
  sh tools/check-agent-proto.sh
  sh tools/check-agent-go-generated.sh
  go -C conformance/agent-go test ./...
  cargo test -p aster-agent --all-features
  ```

  Expected: PASS with the new field backward-compatible at tag 12.

- [ ] **Step 5: Commit.**

  ```bash
  git add proto conformance/agent-go crates/aster-agent
  git commit -m "feat: report the active credential generation"
  ```

## Task 5: Build hardened runtime/admin images and the Compose model

**Files:**

- Create: `crates/aster-compose-credentials/src/bin/aster-compose-healthcheck.rs`
- Create: `crates/aster-compose-credentials/src/bin/aster-compose-verify.rs`
- Create: `crates/aster-compose-credentials/tests/helper_binaries.rs`
- Create: `docker/compose-agent/Dockerfile.agent`
- Create: `docker/compose-agent/Dockerfile.agent.dockerignore`
- Create: `docker/compose-agent/Dockerfile.admin`
- Create: `docker/compose-agent/Dockerfile.admin.dockerignore`
- Create: `docker/compose-agent/compose.yaml`
- Create: `docker/compose-agent/agent.example.json`
- Create: `docker/compose-agent/README.md`
- Modify: `crates/aster-compose-credentials/Cargo.toml`

- [ ] **Step 1: Add failing helper and Compose-model tests.**

  Test that the delivery validator accepts only an absolute, non-symlinked state directory owned by the exact numeric runtime UID/GID with private mode. Test healthcheck against the configured local readiness endpoint. Test verifier using `network_mode: service:aster-agent`: it reads the token secret, selected manifest, and configured application listener, calls authenticated `GetStatus`, and succeeds only when the 32-byte status generation matches the manifest.

  Parse `compose.yaml` and assert exactly three file-backed runtime secrets from `${ASTER_CREDENTIAL_GENERATION_DIR:?required}`, fixed targets, no secret environment source, no Docker socket, one exact user-owned state bind, bounded tmpfs/logging/restart, and digest-form image variables.

- [ ] **Step 2: Run focused tests and verify the missing artifact failures.**

  Run:

  ```bash
  cargo test -p aster-compose-credentials --test helper_binaries
  python3 tools/aster_compose_delivery.py docker/compose-agent/compose.yaml
  ```

  Expected: FAIL because helper binaries, Compose files, and the validator do not yet exist. Implement the Rust helpers in this task; the Python validator is completed in Task 6.

- [ ] **Step 3: Implement least-privilege helper binaries.**

  No service runs as UID 0 or receives added capabilities. Healthcheck and verifier run as the same nonzero UID/GID as the agent and derive their endpoints from the reviewed configuration. All helpers use fixed output categories and bounded timeouts. The verifier treats the manifest only as an operator comparison value, never runtime authorization.

- [ ] **Step 4: Create reproducible multi-stage images.**

  Pin the existing official Rust base by digest. Build release binaries with `--locked`; copy only the Docker agent and healthcheck plus notices into an agent `FROM scratch` final stage. Copy only generation admin and verifier into a separate admin `FROM scratch` image. Use numeric `USER` in both images. Do not copy Cargo caches, compiler, shell, package manager, systemd artifacts, admin tooling, or secret fixtures into final layers.

- [ ] **Step 5: Encode the ordinary Compose deployment.**

  Define:

  - `preflight`: runtime UID/GID, `network_mode: none`, no state mount, three read-only secrets, `--check-config`, and the reviewed `ASTER_AGENT_CONFIG_SHA256`;
  - `aster-agent`: non-root, `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, bounded tmpfs, exact `ASTER_STATE_DIR` bind, three fixed secrets, the same reviewed config digest, `stop_signal: SIGTERM`, 40-second grace, `restart: on-failure:3`, bounded `json-file` logs;
  - `verify`: same non-root identity, token plus manifest, `network_mode: service:aster-agent`, no state.

  Keep application and health listeners loopback-only and do not publish them by default. Use a separate mesh port only where the existing Aster config requires it.

- [ ] **Step 6: Build and inspect both images locally.**

  Run the exact Docker build commands documented in `docker/compose-agent/README.md`, then inspect config/history/filesystems. Expected: numeric nonzero runtime user; no `/bin/sh`, package database, systemd unit/library/string, credential admin, compiler, or cache in the runtime image; no secret fixture in either image.

- [ ] **Step 7: Commit.**

  ```bash
  git add crates/aster-compose-credentials docker/compose-agent
  git commit -m "feat: add hardened Compose container artifacts"
  ```

## Task 6: Add a deterministic daemon-free delivery validator

**Files:**

- Create: `tools/aster_compose_delivery.py`
- Create: `tools/test_aster_compose_delivery.py`
- Modify: `mise.toml`

- [ ] **Step 1: Add failing no-daemon validator tests.**

  Model fixtures must reject: unset/empty generation directory, relative or sibling secret sources, mixed-generation sources, mutable image tags, missing security controls, root runtime, UID/GID mismatch, secret env values, Docker socket, extra secret grants, writable root/mounts, unbounded logs/restarts, `restart` rotation instructions, and Swarm keys/commands.

  Tests must also prove accepted render plans redact generation paths when reporting errors and never include fixture secret bytes.

- [ ] **Step 2: Run tests and confirm failure.**

  Run: `python3 tools/test_aster_compose_delivery.py`

  Expected: FAIL because the validator is absent.

- [ ] **Step 3: Implement plan mode.**

  Default execution parses inputs, validates the exact static model, emits a deterministic operation plan, and exits without invoking Docker. Resolve paths with `realpath`, require all three files and manifest under one exact immutable generation directory, require numeric nonzero `ASTER_UID`/`ASTER_GID`, and reject execution flags. The validator does not inspect or contact a Docker endpoint.

- [ ] **Step 4: Keep execution outside the validator.**

  The tool must not expose `--execute`, contact a Docker endpoint, mutate Docker resources, or emit a host-qualification receipt. It validates the checked-in canonical model and emits a deterministic redacted operator plan only.

- [ ] **Step 5: Wire static checks into the normal foundation gate.**

  Add `python3 tools/test_aster_compose_delivery.py` to `check-foundation` and add the `compose-agent-plan` mise task. Ordinary `mise run check` must not require or contact a Docker daemon.

- [ ] **Step 6: Run focused checks.**

  Run:

  ```bash
  python3 tools/test_aster_compose_delivery.py
  mise run compose-agent-plan
  python3 tools/check-project-license.py
  ```

  Expected: PASS and byte-identical plan output on repeated runs with the same public inputs.

- [ ] **Step 7: Commit.**

  ```bash
  git add tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py mise.toml
  git commit -m "test: validate the Compose delivery profile"
  ```

## Task 7: Docker-host lifecycle qualification deferred

Real-Docker creation, activation, rotation, failure, rollback, leak inspection,
and host-profile receipts are intentionally outside this implementation. They
may be added later as a separate qualification effort. The current delivery
contains manual operator procedures and daemon-free validation only.

## Task 8: Produce release evidence and CI gates

**Files:**

- Create: `.github/workflows/build-compose-images.yml`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/release/docker-compose.md`
- Create: `docs/reference/aster-agent-config-v2.md`
- Modify: `docker/compose-agent/README.md`
- Modify: `crates/aster-agent/README.md`
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/validation/ci.md`
- Modify: `docs/validation/requirements-implementation.csv`
- Modify: `docs/validation/requirements-status.md`
- Modify only if regenerated by repository tooling: `docs/evaluations/0005/requirements-matrix.csv`
- Create: `docs/decisions/0044-compose-file-secret-provider.md`

- [ ] **Step 1: Add failing workflow/documentation policy tests.**

  Extend the delivery validator to require digest-pinned release images, OCI archives, per-image CycloneDX SBOMs, dependency/license notices, Compose digest, architecture, source revision, builder versions, and provenance. Require workflow concurrency/timeouts, least-privilege permissions, pinned actions, and artifact retention. Check docs contain the exact recreate command and warnings about bind-mount ownership, host custody, revocation/rollback, and unsupported profiles; reject Swarm and `docker compose restart` instructions.

- [ ] **Step 2: Run policy tests and observe missing release evidence.**

  Run:

  ```bash
  python3 tools/test_aster_compose_delivery.py
  python3 tools/check-implementation-requirements.py
  ```

  Expected: FAIL until workflows, docs, and traceability evidence exist.

- [ ] **Step 3: Add reproducible release workflow.**

  Build agent/admin images from pinned inputs, export OCI archives, calculate digests, generate and validate CycloneDX SBOMs with license inventory, retain `LICENSE` and `THIRD_PARTY_NOTICES.md`, produce provenance and a release manifest, and run image/static leak inspections. Reference release images by digest in the published Compose example. Do not add a Docker-host lifecycle qualification job or imply that any runtime environment passed one.

- [ ] **Step 4: Write operator and schema documentation.**

  Document generation creation, host ownership/mode preparation, state initialization, no-state/no-network preflight, render inspection, `up -d --force-recreate`, authenticated generation verification, bounded prior-generation retention, explicit authorized rollback, cleanup, and incident handling. State that Compose file-backed secrets are bind mounts, do not provide encryption, and ignore Compose `uid`/`gid`/`mode` controls.

- [ ] **Step 5: Update requirement traceability conservatively.**

  Review and update only the evidence fields for `DM-3-11`, `DM-6-14`, `DM-8-12`, `DM-8-13`, `DM-11-18`, `DM-11-19`, and `DM-13-11`. Keep identity issuance, general production backend, independent review, broad platform support, and complete MVP claims open. Use `implemented-uncredited` where the Compose mechanism exists but the requirement's retained qualification or governance evidence is incomplete.

- [ ] **Step 6: Run the complete verification set.**

  Run:

  ```bash
  cargo fmt --all -- --check
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  sh tools/with-test-resources.sh cargo test --locked --workspace --all-features
  sh tools/check-agent-proto.sh
  sh tools/check-agent-go-generated.sh
  python3 tools/test_aster_compose_delivery.py
  python3 tools/check-project-license.py
  python3 tools/check-implementation-requirements.py
  mise run check
  git diff --check
  ```

  Expected: all static/workspace checks pass without Docker-host lifecycle execution. Review all retained output again for canary values.

- [ ] **Step 7: Request security-focused review before claiming completion.**

  Use `superpowers:requesting-code-review` and explicitly direct review to the five Review Focus items at the top of this plan. Resolve findings, rerun the affected focused tests, then rerun the complete verification set.

- [ ] **Step 8: Commit.**

  ```bash
  git add .github README.md docs docker/compose-agent crates/aster-agent/README.md tools mise.toml
  git commit -m "docs: publish the Compose container delivery profile"
  ```

## Final completion criteria

- [ ] The Docker runtime binary has one statically selected Compose provider and no systemd provider or unprotected customer fallback.
- [ ] The package binary retains one statically selected systemd provider and schema v1 behavior.
- [ ] All three secret files are fixed-path, owner-matched, exact-mode, link-count-one, stable, read-only mounts from one bound generation.
- [ ] Preflight is stateless/networkless; every service is non-root/read-only/capability-free; verification has no state access.
- [ ] Rotation uses recreation, preserves durable state, publishes the expected generation, and never silently falls back.
- [ ] Failure handling and explicit authorized rollback are documented without claiming automated Docker-host demonstration.
- [ ] Runtime image, admin image, OCI archives, SBOMs, notices, provenance, and Compose digest are retained and digest-linked.
- [ ] The full daemon-free workspace gate passes after review; Docker-host lifecycle qualification remains deferred.
