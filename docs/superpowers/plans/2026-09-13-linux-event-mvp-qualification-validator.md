#

# Linux Event MVP Qualification Validator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to execute this plan task by task.

**Goal:** Add the read-only E06 validator that deterministically decides whether
a local Linux Event MVP candidate receipt bundle is structurally conformant,
nonconformant, or indeterminate against profile v0.1.

**Architecture:** A small standard-library Python package owns canonical JSON,
descriptor-relative input reads, exact schema checks, binding/gate evaluation,
and deterministic report generation. A thin CLI maps dispositions to public
exit codes. Synthetic tests build bundles in temporary directories and mutate
one contract fact at a time; no test fixture is qualification evidence.

**Tech Stack:** Python 3.13 standard library, canonical JSON, SHA-256, `unittest`,
and `mise` task integration.

**Spec:**
`docs/implementation/linux-event-mvp-qualification-receipt-validator-spec.md`

## Global constraints

- [ ] Read only explicitly supplied bundle and optional artifact roots.
- [ ] Reject traversal, symlinks, special files, duplicate JSON keys, unknown
      fields, non-canonical bytes, malformed digests, and files that change
      while read.
- [ ] Never use network, subprocesses, devices, credential providers, private
      keys, or secret-bearing inputs.
- [ ] Validate detached record bytes, hashes, roles, times, ordering, and
      bindings; do not claim cryptographic signature verification.
- [ ] Treat missing required local bytes as `indeterminate` and malformed or
      mismatched present bytes as `nonconformant`.
- [ ] Keep global candidate-ID uniqueness explicitly unassessed.
- [ ] Do not change `P0-1-E06` from Open before owner review.

## Task 1: Freeze the executable machine contract

**Files:**

- Create: `docs/implementation/schemas/linux-event-mvp-qualification-v0.1.json`
- Modify:
  `docs/implementation/linux-event-mvp-qualification-receipt-validator-spec.md`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] Add one schema document with `$defs` for the canonical candidate body,
      receipt index, detached approval, and release decision. Every object uses
      `additionalProperties: false`; values use integers, never JSON numbers
      with fractions.
- [ ] Record the approved resolutions for D06 record handling, sanitized device
      binding, direct/direct-plus-one-relay choice, nominal 1 GiB memory,
      workload labels/node assignment, and bundle-local candidate consistency.
- [ ] Freeze canonical JSON as sorted compact ASCII-safe UTF-8 with one trailing
      LF and reject duplicate keys.
- [ ] Freeze resource caps: 4 MiB body, 8 MiB index, 256 KiB detached record,
      128 MiB referenced artifact, 4,096 index entries, 64 detached approvals,
      and 512 MiB aggregate referenced bytes.
- [ ] Add a test that the implementation schema identity and digest match the
      committed schema bytes.

## Task 2: Build canonical and safe local input handling

**Files:**

- Create: `tools/linux_event_mvp_qualification/__init__.py`
- Create: `tools/linux_event_mvp_qualification/io.py`
- Create: `tools/linux_event_mvp_qualification/model.py`
- Create: `tools/check-linux-event-mvp-qualification.py`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] First add failing tests for duplicate keys, non-canonical JSON, `..`,
      absolute paths, symlinks, non-regular files, oversize inputs, and a
      before/after identity change.
- [ ] Implement retained-root-descriptor traversal using `O_NOFOLLOW`, regular
      file checks, bounded streaming SHA-256, and before/open/after identity and
      size comparisons.
- [ ] Implement canonical JSON loading and scalar grammar for SHA-256 digests,
      40-character Git commits, RFC 3339 UTC, typed results, and typed blockers.
- [ ] Add deterministic `Finding` and report models that never include source
      values or filesystem paths.

## Task 3: Validate exact document shapes and local receipt bytes

**Files:**

- Create: `tools/linux_event_mvp_qualification/schema.py`
- Create: `tools/linux_event_mvp_qualification/validator.py`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] Add failing tests for missing/unknown fields, wrong scalar types,
      unsupported schema versions, duplicate index paths/digests, and missing
      indexed bytes.
- [ ] Implement exact field/type/key validation for body, index, approval, and
      decision records from the committed schema.
- [ ] Read every indexed receipt locally, verify its size and digest, and retain
      only derived verification facts.
- [ ] Classify absent required bytes as `QVF` unresolved findings and present
      malformed/mismatched bytes as deterministic `QVF` rejection findings.

## Task 4: Enforce candidate, artifact, and gate bindings

**Files:**

- Create: `tools/linux_event_mvp_qualification/bindings.py`
- Modify: `tools/linux_event_mvp_qualification/validator.py`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] Add failing mutation tests for candidate/root/G2/G3/G4/G5 drift,
      incomplete G3 attempt manifests, false global no-output, forward blockers,
      downstream execution after a blocking failure, and decision cycles.
- [ ] Recompute each canonical binding from its declared predecessor and selected
      facts and compare it with the supplied binding.
- [ ] Require all G3 outputs, authenticated ARM64 package, and complete artifact
      set for `issue`; preserve typed partial-attempt facts for `refuse`/`defer`.
- [ ] Validate ordered G1-G6 execution and exact blocker references.

## Task 5: Enforce the Linux Event MVP v0.1 overlay

**Files:**

- Create: `tools/linux_event_mvp_qualification/profile.py`
- Modify: `tools/linux_event_mvp_qualification/validator.py`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] Add failing mutations for OS/provider identity, CM4 participant roles,
      mission/security suite, direct/relay selection, topology/configuration,
      workload values, resource bounds, and ledger accounting.
- [ ] Enforce canonical workload labels `api_boundary`, `two_node_topology`,
      `offline_soak`, and `capacity_warning_probe` with exact node assignments.
- [ ] Enforce the 240-operation-per-node soak and 512-plus-exact-retry capacity
      probe without turning the 1,024 profile stop into a runtime ceiling.
- [ ] Evaluate nominal installed memory at 1 GiB and report kernel-visible bytes
      as a separate measurement.
- [ ] Validate D06 and D15 immutable prerequisite references without claiming
      that their detached signatures were cryptographically verified.

## Task 6: Validate detached candidate approvals and release decision

**Files:**

- Modify: `tools/linux_event_mvp_qualification/validator.py`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] Add failing tests for duplicate/missing roles, wrong body/candidate/schema/
      G3 bindings, non-bytewise approval ordering, decision mismatch, and an
      `issue` with any unresolved or failing prerequisite.
- [ ] Require the eight final roles for `issue`; permit typed downstream
      `not-run` roles only for `refuse`/`defer`.
- [ ] Bind the release decision to the canonical body digest, sorted detached
      approval digests, candidate ID, schema digest, and global G3 binding.
- [ ] Report signature authenticity as not assessed regardless of otherwise
      conformant reference metadata.

## Task 7: Freeze report and CLI behavior

**Files:**

- Modify: `tools/check-linux-event-mvp-qualification.py`
- Modify: `tools/linux_event_mvp_qualification/model.py`
- Test: `tools/test-linux-event-mvp-qualification.py`

- [ ] Add tests proving dispositions `conformant`, `nonconformant`, and
      `indeterminate` map to exit codes `0`, `2`, and `3`; operational faults map
      to `70`.
- [ ] Apply precedence: any deterministic rejection wins over unresolved input;
      otherwise unresolved wins over conformance.
- [ ] Sort stable finding codes and checked-binding names, produce byte-identical
      repeated reports, and include the exact structural-only non-claim.
- [ ] Prove reports contain no candidate values, device identifiers, addresses,
      keys, bearer values, source paths, or raw receipt content.

## Task 8: CI integration and final evidence

**Files:**

- Modify: `mise.toml`
- Modify: `docs/implementation/linux-event-mvp-qualification-receipt-validator-spec.md`

- [ ] Add `python3 tools/test-linux-event-mvp-qualification.py` to `mise run
      check` and a focused `qualification-validator` task.
- [ ] Run the focused validator suite throughout development.
- [ ] Run `git diff --check` and
      `python3 tools/check-implementation-requirements.py` after documentation
      changes.
- [ ] Run `mise run check` once before handoff.
- [ ] Record exact commands/results in the PR without calling synthetic fixtures
      qualification evidence and without changing E06 status.
