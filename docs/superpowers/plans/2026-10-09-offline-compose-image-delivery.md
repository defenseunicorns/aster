# Offline Multi-Architecture Compose Image Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce manually triggered, architecture-specific Aster Compose bundles that operators can verify, load into local Docker, and deploy without building or contacting a registry.

**Architecture:** A native-runner GitHub Actions matrix builds `amd64` and
`arm64` images and exports each as a provenance-bearing OCI inspection archive
and a Docker-loadable archive using a fixed export epoch. The strict OCI
inspector binds the selected platform, image manifest, Docker-archive config
digest, provenance, and scratch filesystem; Compose accepts either registry
manifest digests or verified local Docker image IDs and never pulls implicitly.

**Tech Stack:** GitHub Actions, Docker Buildx/BuildKit, Docker Compose, Python `unittest`, canonical JSON-form YAML, CycloneDX JSON.

**Spec:** `docs/superpowers/specs/2026-10-09-offline-compose-image-delivery-design.md`

## Global Constraints

- The release workflow is manual-only: its checked-in trigger is exactly `workflow_dispatch`.
- Release platforms are exactly native Linux `amd64` and native Linux `arm64`; no QEMU release evidence.
- Each architecture produces a separate 14-day artifact containing OCI and Docker archives for both images.
- Mutable image tags remain forbidden as deployment inputs; accepted forms are registry `name@sha256:<manifest>` or local `sha256:<config>`.
- All Compose services use `pull_policy: never`.
- Docker Swarm, registry publication, Docker-host qualification, macOS qualification, and runtime lifecycle testing remain out of scope.
- No service gains root, `sudo`, capabilities, Docker socket access, or new host-path custody.
- Every repository commit created by this work is signed.

## Review Focus

- A bundle whose filename, manifest architecture, OCI platform, or image config architecture disagrees must fail before upload; Task 2 tests this.
- A Docker archive that imports to a config digest different from its paired OCI archive must fail before upload; Tasks 2 and 4 test this.
- A missing local image must fail without a registry request; Task 3 pins `pull_policy: never` in all three services.
- Repeated or mutable scratch-layer paths must remain rejected; Task 1 preserves strict overlap rejection while changing image construction.
- A temporary pre-merge `push` trigger must never enter the PR branch; Task 6 verifies exact final workflow bytes before integration.

---

### Task 1: Build One Exact Scratch Filesystem Layer

**Files:**
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `docker/compose-agent/Dockerfile.agent`
- Modify: `docker/compose-agent/Dockerfile.admin`

**Interfaces:**
- Consumes: the inspector's existing rejection of duplicate paths across layers.
- Produces: each final image as one scratch rootfs layer with directories mode `0755`, binaries mode `0555`, and notices mode `0444`.

- [ ] **Step 1: Add failing Dockerfile-policy tests**

Add `test_runtime_dockerfiles_copy_one_prepared_rootfs` to assert that each runtime stage has one `COPY --from=build /out/rootfs /`, no individual final-stage file copies, and explicit build-stage installation of exact directory and file modes.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `python3 -m unittest tools.test_aster_compose_delivery.RepositoryPolicyTests.test_runtime_dockerfiles_copy_one_prepared_rootfs -v`

Expected: FAIL because each Dockerfile currently emits four overlapping final-stage layers.

- [ ] **Step 3: Stage and copy one exact rootfs**

In each build stage, create `/out/rootfs/usr/local/bin` and `/out/rootfs/usr/share/licenses/aster` with mode `0755`, install the exact binaries with mode `0555`, and install `LICENSE` and `THIRD_PARTY_NOTICES.md` with mode `0444`. Replace the four final-stage copies with one `COPY --from=build /out/rootfs /`; preserve all existing binary checks and runtime configuration.

- [ ] **Step 4: Run focused and inspector suites and verify GREEN**

Run: `python3 tools/test_aster_compose_delivery.py && python3 tools/test_inspect_aster_compose_oci.py`

Expected: all tests pass, including strict duplicate-path rejection.

- [ ] **Step 5: Commit the task**

```bash
git add docker/compose-agent/Dockerfile.agent docker/compose-agent/Dockerfile.admin tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py
git commit -S -m "fix: build exact Compose scratch rootfs"
```

### Task 2: Make OCI Inspection Architecture- and Config-Bound

**Files:**
- Modify: `tools/test_inspect_aster_compose_oci.py`
- Modify: `tools/inspect_aster_compose_oci.py`

**Interfaces:**
- Consumes: `--profile`, OCI archive, Buildx OCI index digest, and expected Docker config digest.
- Produces: `inspect_oci_archive(path, profile, architecture, expected_digest, expected_config_digest, artifacts=...) -> InspectionResult` and CLI options `--architecture` plus `--expected-config-digest`.

- [ ] **Step 1: Add failing architecture and config-binding tests**

Parameterize `OciFixture` by architecture. Add tests that accept exact `amd64` and `arm64` fixtures, reject descriptor/config architecture disagreement, reject unsupported architectures, accept the matching expected config digest, and reject a different expected config digest.

- [ ] **Step 2: Run the inspector suite and verify RED**

Run: `python3 tools/test_inspect_aster_compose_oci.py`

Expected: FAIL because the inspector hard-codes `amd64` and has no config-digest input.

- [ ] **Step 3: Implement exact architecture and config binding**

Add an architecture allowlist `("amd64", "arm64")`, require the selected descriptor and config to match the requested value, authenticate the config descriptor digest against `--expected-config-digest`, and include architecture and config digest in `InspectionResult` and the success record. Do not relax layer metadata, path, mode, provenance, closure, or canary checks.

- [ ] **Step 4: Run the suite and verify GREEN**

Run: `python3 tools/test_inspect_aster_compose_oci.py`

Expected: all inspector tests pass.

- [ ] **Step 5: Commit the task**

```bash
git add tools/inspect_aster_compose_oci.py tools/test_inspect_aster_compose_oci.py
git commit -S -m "feat: inspect Compose images by architecture"
```

### Task 3: Support Immutable Offline Image IDs in Compose

**Files:**
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `docker/compose-agent/compose.yaml`

**Interfaces:**
- Consumes: `ASTER_AGENT_IMAGE_DIGEST` and `ASTER_ADMIN_IMAGE_DIGEST`.
- Produces: acceptance of exact registry manifest-digest or local Docker config-digest syntax, with `pull_policy: never` on `preflight`, `aster-agent`, and `verify`.

- [ ] **Step 1: Add failing reference and pull-policy tests**

Add tests that accept `sha256:` plus 64 lowercase hex characters for both images, retain acceptance of registry digests, reject tags/uppercase/short/bare names, and require `pull_policy: never` on all three Compose services.

- [ ] **Step 2: Run the focused delivery tests and verify RED**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: FAIL because local IDs are rejected and the Compose model lacks pull policy.

- [ ] **Step 3: Implement immutable local references**

Replace the single registry-reference regex with a predicate accepting exactly one of the two approved forms. Add `pull_policy: "never"` to all three canonical Compose service objects and expected-model fixtures; preserve variable names for compatibility.

- [ ] **Step 4: Run the suite and verify GREEN**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: all delivery tests pass.

- [ ] **Step 5: Commit the task**

```bash
git add docker/compose-agent/compose.yaml tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py
git commit -S -m "feat: support offline Compose image IDs"
```

### Task 4: Package Native AMD64 and ARM64 Offline Bundles

**Files:**
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `.github/workflows/build-compose-images.yml`

**Interfaces:**
- Consumes: exact matrix entries `{arch: amd64, runner: ubuntu-24.04, platform: linux/amd64}` and `{arch: arm64, runner: ubuntu-24.04-arm, platform: linux/arm64}`.
- Produces: `aster-compose-images-${arch}-${GITHUB_SHA}` artifacts and release manifest schema `aster-compose-image-release/v2` with per-image OCI digest, manifest digest, config digest, transport tag, OCI filename, Docker filename, and SBOM set.

- [ ] **Step 1: Add failing workflow-policy tests**

Replace the amd64-only assertions with exact two-entry matrix assertions.
Require separate provenance-enabled OCI and provenance-disabled Docker exports,
architecture-qualified filenames and artifact names, Docker archive import,
exact imported image-ID inspection, architecture/config-bound OCI inspection,
v2 manifest fields, checksum coverage, native runners, manual-only trigger,
and no QEMU or registry publication. Add negative mutations for each contract.

- [ ] **Step 2: Run the delivery suite and verify RED**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: FAIL because the workflow is amd64-only and emits only OCI archives.

- [ ] **Step 3: Implement the native matrix and dual exports**

Use the exact native matrix and `${{ matrix.platform }}`. For each agent/admin
image, retain a provenance-bearing OCI output and make a separate
provenance-disabled Buildx invocation for the deterministic tagged Docker
archive. The invocations share BuildKit cache and a fixed `SOURCE_DATE_EPOCH`;
the later config/manifest identity checks prove transport equivalence.
Architecture-qualify all four
archive filenames. Do not add registry login or push steps.

- [ ] **Step 4: Bind imported Docker images to OCI configs**

Read each Docker archive's canonical config-blob digest and pass it with
`${{ matrix.arch }}` to the OCI inspector. Load both archives, inspect each
deterministic transport tag, require the engine-reported image ID to equal the
authenticated config or selected-manifest digest, and record the observed ID
in the v2 release manifest. Fail before upload on any mismatch.

- [ ] **Step 5: Retain architecture-bound release evidence**

Bind SBOM properties to image digest and architecture, record runner/platform/tool versions, include both archive forms and all metadata in `SHA256SUMS`, and upload one 14-day artifact per architecture only after every check passes.

- [ ] **Step 6: Run daemon-free workflow policy tests and verify GREEN**

Run: `python3 tools/test_aster_compose_delivery.py && python3 tools/test_inspect_aster_compose_oci.py`

Expected: all tests pass with the checked-in manual-only workflow.

- [ ] **Step 7: Commit the task**

```bash
git add .github/workflows/build-compose-images.yml tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py
git commit -S -m "feat: package offline multi-arch Compose images"
```

### Task 5: Document Download, Verification, Import, and Deployment

**Files:**
- Modify: `tools/test_aster_compose_delivery.py`
- Modify: `tools/aster_compose_delivery.py`
- Modify: `docker/compose-agent/README.md`
- Modify: `docs/release/docker-compose.md`
- Modify: `docs/decisions/0044-compose-file-secret-provider.md`
- Modify: `docs/validation/ci.md`

**Interfaces:**
- Consumes: the v2 release manifest and architecture artifact names from Task 4.
- Produces: one copy-paste offline operator path that performs no local build and deploys only verified local image IDs.

- [ ] **Step 1: Add failing documentation-policy tests**

Require documentation for host architecture selection, artifact download, checksum verification before import, `docker image load` for both archives, imported image-ID comparison to the manifest, local-ID environment variables, `pull_policy: never`, manual workflow triggering, and retained no-host-qualification language.

- [ ] **Step 2: Run the delivery suite and verify RED**

Run: `python3 tools/test_aster_compose_delivery.py`

Expected: FAIL because current documentation only describes local builds and registry digests.

- [ ] **Step 3: Write the offline operator procedure**

Lead with the download-and-run path; retain local build instructions as a developer alternative. Give exact commands for `amd64` and `arm64` artifact naming, `sha256sum --check`, manifest review, both `docker image load` operations, `docker image inspect` ID comparison, environment setup, static validation, Compose rendering, preflight, activation, and verification.

- [ ] **Step 4: Update decision and CI documentation**

Record both immutable reference forms, dual archive roles, native architecture boundary, manual-only workflow, and the distinction between packaging validation and Docker-host qualification.

- [ ] **Step 5: Run documentation policy and full focused suites**

Run: `python3 tools/test_aster_compose_delivery.py && python3 tools/test_inspect_aster_compose_oci.py`

Expected: all tests pass.

- [ ] **Step 6: Commit the task**

```bash
git add docker/compose-agent/README.md docs/release/docker-compose.md docs/decisions/0044-compose-file-secret-provider.md docs/validation/ci.md tools/aster_compose_delivery.py tools/test_aster_compose_delivery.py
git commit -S -m "docs: add offline Compose image deployment"
```

### Task 6: Verify Real Packaging, Integrate the PR, and Remove Temporary Triggering

**Files:**
- Verify: all files changed by Tasks 1-5
- Temporarily modify only on verification branch: `.github/workflows/build-compose-images.yml`

**Interfaces:**
- Consumes: completed manual-only implementation and temporary fork branch `ci/pr52-compose-images`.
- Produces: successful `amd64` and `arm64` artifacts, a signed single-commit PR update based on latest upstream `main`, and deletion of the temporary trigger branch.

- [ ] **Step 1: Run focused tests and static checks**

Run: `python3 tools/test_aster_compose_delivery.py && python3 tools/test_inspect_aster_compose_oci.py && git diff --check`

Expected: all tests pass; no whitespace errors.

- [ ] **Step 2: Run repository tests proportionate to the change**

Run the repository's normal Python/Compose policy checks and the relevant Rust tests identified by CI. Report any unrelated failures by exact name; do not hide them.

- [ ] **Step 3: Verify exact signed commits and manual-only final bytes**

Run: `git verify-commit HEAD`, verify every new commit signature, and assert that the workflow starts with only `on:\n  workflow_dispatch:` and contains no checked-in `push:` trigger.

- [ ] **Step 4: Trigger pre-merge packaging only on the temporary fork branch**

Add a signed temporary commit enabling `push` only for `ci/pr52-compose-images`, push that branch, and wait for both native matrix jobs. Confirm both artifacts exist, names match architecture and commit, and all build, SBOM, OCI inspection, Docker load, config-ID binding, manifest, and checksum steps pass.

- [ ] **Step 5: Restore manual-only workflow before PR integration**

Remove the temporary trigger commit from the implementation diff. Re-run the exact workflow-policy suites against the manual-only file.

- [ ] **Step 6: Rebase onto latest canonical `main` and produce the signed PR commit**

Resolve only in-scope conflicts, preserve the approved implementation, create the required signed commit history, and verify the PR diff contains no temporary trigger or unrelated material.

- [ ] **Step 7: Push with an exact lease and wait for PR CI**

Update the fork PR branch using `--force-with-lease` against the previously observed SHA, then wait for every public PR check. Investigate and fix any failure before reporting success.

- [ ] **Step 8: Clean up temporary verification resources**

Delete remote and local `ci/pr52-compose-images` branches and its worktree only after the PR branch and public CI are healthy. Preserve GitHub Actions run artifacts for their configured 14-day retention.
