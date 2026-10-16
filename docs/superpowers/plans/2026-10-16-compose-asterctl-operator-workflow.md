# Compose `asterctl` Operator Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `asterctl` in the existing Compose admin artifact and validate a no-local-build operator workflow between a local Docker node and one packaged test device.

**Architecture:** Add the static CLI to the exact-allowlisted admin image, expose it through a hardened one-shot Compose service, and ship a separate opt-in UDP publishing override for physical peering. Extend artifact policy and operator documentation, then retain bounded mixed-device evidence.

**Tech Stack:** Rust/Cargo, Docker Buildx and Compose, Python policy validators, GitHub Actions, CycloneDX, ZeroTier/IP transport.

**Spec:** `docs/superpowers/specs/2026-10-16-compose-asterctl-operator-workflow-design.md`

## Global Constraints

- Keep the long-running agent image unchanged; add `asterctl` only to `aster-compose-admin`.
- Use only CI-produced Compose deployment artifacts in operator acceptance; no local image build.
- Keep default Compose host-port exposure closed; remote mesh exposure is an explicit override bound to `ASTER_MESH_BIND_ADDRESS`.
- The CLI service receives only the client token and the operator-selected transfer directory.
- Preserve the evaluation-stage claim boundary and do not commit secrets, private endpoints, mission data, or generated binaries.
- Produce signed commits, ideally one commit per independently reviewable increment.

## Review Focus

- A missing or non-writable `ASTER_TRANSFER_DIR` must fail before an operator mistakes a Blob command for success; Task 2 pins the required variable and preflight guidance.
- `docker compose run` argument replacement must retain the fixed token-file prefix; Task 2 tests the rendered entrypoint and command separately.
- The remote override must never bind all host interfaces implicitly; Task 3 requires an explicit bind address and tests missing-variable failure.
- The admin image allowlist and SBOM set must reject an image or manifest that omits or unexpectedly adds `asterctl`; Task 1 pins both lists.
- Examples must use commands supported by the shipped CLI and preserve byte identity for Blob reads; Task 4 runs every local example and Task 5 repeats the data path physically.

---

### Task 1: Add `asterctl` to the Existing Admin Artifact

**Files:**
- Modify: `docker/compose-agent/Dockerfile.admin`
- Modify: `tools/inspect_aster_compose_oci.py`
- Modify: `tools/test_inspect_aster_compose_oci.py`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `.github/workflows/build-compose-images.yml`
- Modify: `docs/release/docker-compose.md`
- Modify: `docker/compose-agent/README.md`

**Interfaces:**
- Consumes: existing `aster-compose-admin` exact-rootfs and release-manifest profiles.
- Produces: an admin image containing `/usr/local/bin/asterctl` mode `0555` and an admin `sbom_set` containing `asterctl_bin.cdx.json`.

- [ ] **Step 1: Extend policy tests to require the CLI binary and SBOM**

Add assertions that the admin rootfs allowlist contains exactly the two admin
helpers, `asterctl`, and license files; that Dockerfile validation expects
three `0555` installs; and that release workflow/manifest policy includes
`asterctl_bin.cdx.json` bound to the admin OCI digest.

- [ ] **Step 2: Run focused policy tests and verify they fail**

Run: `python3 tools/test_inspect_aster_compose_oci.py && python3 tools/test_aster_compose_delivery.py`

Expected: FAIL because the current image and workflow omit `asterctl`.

- [ ] **Step 3: Build and enumerate the CLI in the admin artifact**

Update `Dockerfile.admin` to build locked release binaries from
`aster-compose-credentials` and `asterctl`, install `asterctl` as mode `0555`,
and update exact allowlists. Generate `crates/asterctl/asterctl_bin.cdx.json`,
copy it into `target/compose-release`, bind it to the admin digest, include it
in the release manifest and canary scan, and describe it as part of the
existing admin artifact.

- [ ] **Step 4: Run focused artifact-policy tests**

Run: `python3 tools/test_inspect_aster_compose_oci.py && python3 tools/test_aster_compose_delivery.py && sh tools/check-cargo-lockfiles.sh`

Expected: all commands exit 0.

- [ ] **Step 5: Commit the artifact increment**

```bash
git add docker/compose-agent/Dockerfile.admin tools/inspect_aster_compose_oci.py tools/test_inspect_aster_compose_oci.py tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py .github/workflows/build-compose-images.yml docs/release/docker-compose.md docker/compose-agent/README.md
git commit -S -m "feat: ship asterctl in compose admin artifact"
```

### Task 2: Add the Hardened One-Shot CLI Service

**Files:**
- Modify: `docker/compose-agent/compose.yaml`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `docker/compose-agent/README.md`
- Modify: `docs/release/docker-compose.md`

**Interfaces:**
- Consumes: `/usr/local/bin/asterctl` from Task 1 and the existing client-token secret.
- Produces: Compose service `asterctl`, environment input `ASTER_TRANSFER_DIR`, mount `/transfer`, and invocation `docker compose run --rm asterctl [GLOBAL_OPTIONS] COMMAND`.

- [ ] **Step 1: Add failing exact-model and failure-path tests**

Assert the service uses the admin digest, shares the agent network namespace,
depends on agent health, has the fixed token-file entrypoint, defaults to
`status`, receives only the client-token secret, and bind-mounts the required
transfer directory. Assert rendering without `ASTER_TRANSFER_DIR` fails.

- [ ] **Step 2: Run the delivery tests and verify they fail**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: FAIL because service `asterctl` is absent.

- [ ] **Step 3: Add the service and operator contract**

Add the service to `compose.yaml`, mirror it in `_expected_compose_model()`,
and update deployment docs with transfer-directory ownership and command
replacement behavior.

- [ ] **Step 4: Render and validate the Compose model**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: PASS, including exact model and missing-variable coverage.

- [ ] **Step 5: Commit the client-service increment**

```bash
git add docker/compose-agent/compose.yaml tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py docker/compose-agent/README.md docs/release/docker-compose.md
git commit -S -m "feat: add compose asterctl service"
```

### Task 3: Ship Explicit Remote-Mesh Exposure

**Files:**
- Create: `docker/compose-agent/compose.remote-mesh.yaml`
- Modify: `.github/workflows/build-compose-images.yml`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `docs/release/docker-compose.md`
- Modify: `docker/compose-agent/README.md`

**Interfaces:**
- Consumes: canonical agent service and its UDP port 8183.
- Produces: opt-in override using `${ASTER_MESH_BIND_ADDRESS:?required}:${ASTER_MESH_PUBLISHED_PORT:-8183}:8183/udp`, included by digest in the release artifact.

- [ ] **Step 1: Add failing override policy tests**

Assert the override contains only the intended service/port change, requires an
explicit bind address, defaults only the published port, is copied into the
release artifact, is checksum-covered, and is recorded in the release
manifest. Assert rendering without the bind address fails.

- [ ] **Step 2: Run focused tests and verify they fail**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: FAIL because the override is absent.

- [ ] **Step 3: Add and package the opt-in override**

Create the override and extend release workflow, manifest policy, provenance,
and documentation. Document host firewall responsibility and configuration of
the published endpoint as the peer address.

- [ ] **Step 4: Validate closed-default and explicit-open models**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: PASS with no default `ports`, exact opt-in UDP publishing, and a
missing-bind-address failure.

- [ ] **Step 5: Commit the remote-mesh increment**

```bash
git add docker/compose-agent/compose.remote-mesh.yaml .github/workflows/build-compose-images.yml tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py docs/release/docker-compose.md docker/compose-agent/README.md
git commit -S -m "feat: add opt-in compose mesh exposure"
```

### Task 4: Replace Compose Limitations with Verified Operator Examples

**Files:**
- Modify: `docs/operator-guide.md`
- Modify: `docker/compose-agent/README.md`
- Modify: `docs/release/docker-compose.md`
- Test: `tools/test_aster_compose_delivery.py`

**Interfaces:**
- Consumes: Tasks 1–3 operator commands and released files.
- Produces: concise Event, durable Blob, finite-TTL Blob, restart, and remote-peer runbook procedures requiring no build tools.

- [ ] **Step 1: Add documentation contract assertions**

Require the runbook to name both Compose files, `ASTER_TRANSFER_DIR`, the
released admin image, `docker compose run --rm asterctl`, Event publish/query,
Blob publish/read, TTL, byte comparison, and agent replacement. Reject the old
claim that Compose has no supported interactive Event/Blob example.

- [ ] **Step 2: Run the documentation policy test and verify it fails**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: FAIL on missing examples or retained obsolete limitation text.

- [ ] **Step 3: Write the concise artifact-only runbook**

Keep setup variables in one copyable block, use `/transfer` paths consistently,
separate local API exercises from opt-in remote peering, and state expected
results and cleanup. Preserve the deployment's evaluation-stage and authority-
provisioning boundaries.

- [ ] **Step 4: Validate every example without substituting a local image**

Check every command against the rendered Compose model and `asterctl` argument
tests. Do not build a convenience client image or describe a local build path;
runtime execution is deferred to Task 5 and must use the downloaded CI
deployment artifact.

- [ ] **Step 5: Run documentation and CLI regressions**

Run: `python3 tools/test_aster_compose_delivery.py && cargo test -p asterctl --all-targets`

Expected: PASS.

- [ ] **Step 6: Commit the runbook increment**

```bash
git add docs/operator-guide.md docker/compose-agent/README.md docs/release/docker-compose.md tools/test_aster_compose_delivery.py
git commit -S -m "docs: add compose event and blob runbook"
```

### Task 5: Validate One Docker and One Packaged Device

**Files:**
- Create: `docs/validation/evidence/2026-10-16-compose-device-asterctl-validation.md`
- Modify: `docs/operator-guide.md` only if execution reveals a reproducible correction.

**Interfaces:**
- Consumes: exact CI artifact for this revision, packaged test-device build, opt-in override, and existing protected mission provisioning.
- Produces: sanitized bounded acceptance evidence and corrected copy-paste commands.

- [ ] **Step 1: Establish the exact test boundary**

Push the implementation revision, wait for the Compose packaging workflow,
download and checksum its architecture-matched deployment artifact, and load
its Docker archives. Then verify ZeroTier and SSH readiness, identify the
selected test device, record resource baselines, bind the Docker UDP port only
to the local ZeroTier IP, and record source/package/image/config digests
without recording secrets.

- [ ] **Step 2: Execute authenticated two-node Event and Blob checks**

Verify mutual contact, Event transfer both directions, durable Blob transfer
and byte identity both directions, finite-TTL availability then expiry, Docker
agent replacement and durable access, and expected unauthorized/missing-file
failures. Use only the downloaded Compose deployment artifact for Docker-side
commands.

- [ ] **Step 3: Measure one representative Blob transfer**

Record size, elapsed monotonic duration, effective throughput, retries or
failures, and peak RSS on both nodes. Label the result as one bounded
observation, not a supported threshold.

- [ ] **Step 4: Restore and sanitize**

Stop the evaluation deployment, restore the device's prior configuration and
service state byte-for-byte where applicable, confirm no test process remains,
and inspect the proposed evidence for credentials, mission material, private
endpoints, host access details, or generated binaries.

- [ ] **Step 5: Commit retained evidence**

```bash
git add docs/validation/evidence/2026-10-16-compose-device-asterctl-validation.md docs/operator-guide.md
git commit -S -m "docs: retain compose device workflow evidence"
```

### Task 6: Final Review and Integration Gate

**Files:**
- Modify: only files required by verified review findings.

**Interfaces:**
- Consumes: all preceding signed increments.
- Produces: a review-ready usability branch with CI-equivalent evidence and no broadened claim.

- [ ] **Step 1: Run focused checks serially**

Run: `python3 tools/test_inspect_aster_compose_oci.py`, then
`python3 tools/test_aster_compose_delivery.py`, then
`cargo test -p asterctl --all-targets`, then
`sh tools/check-cargo-lockfiles.sh`.

Expected: every command exits 0.

- [ ] **Step 2: Run the repository gate serially**

Run: `mise run check`

Expected: exit 0. If resource pressure recurs, retain focused results, let CI
run the full matrix, and report the local limitation without claiming the full
gate passed.

- [ ] **Step 3: Review security, artifact, and documentation diffs**

Confirm exact rootfs contents, digest/SBOM coverage, service credential
isolation, closed default networking, explicit override exposure, runnable
commands, clean restoration, and conservative evidence language.

- [ ] **Step 4: Verify commit signatures and branch state**

Run: `git log --show-signature --oneline <base>..HEAD && git status --short --branch`

Expected: every new commit has a good signature and the worktree is clean.
