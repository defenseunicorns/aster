#

# Aster Documentation and Archive Refactor Design

- Status: approved direction; written design awaiting review
- Date: 2026-09-14
- Scope: documentation architecture and lifecycle only
- Runtime effect: none
- Requirements effect: none; no requirement status or evidence claim changes

## Purpose

Aster's documentation contains valuable protocol, implementation, validation,
research, and project-history material, but it presents too much of that
material as one current engineer-facing corpus. A reader must distinguish
current authority from completed plans, superseded designs, experiment reports,
and historical evidence by reading the documents themselves.

The refactor will make `docs/` a compact guide to the system that exists now and
will move historical material into a separate, frozen `archive/` tree before
the remaining current documentation is consolidated. MVP operation and
validation will become separate concerns. Historical material will remain in
Git and retain its evidentiary value.

## Baseline

At `814e549` the repository contains 220 Markdown files with 55,234 lines.
Three obviously historical/process-heavy areas account for 73 files and 21,409
lines:

| Area | Markdown files | Lines | Present concern |
|---|---:|---:|---|
| `docs/superpowers/` | 18 | 8,315 | completed plans mixed with active designs |
| `docs/proposals/` | 12 | 4,778 | closed research presented beside current docs |
| `docs/evaluations/` | 43 | 8,316 | historical evidence mixed with live validation inputs |

Two other large areas need reclassification rather than wholesale archival:
`docs/quickstart/` has 19 files and 5,379 lines, while
`docs/implementation/` has 14 Markdown files and 7,896 lines. Both contain
current material, but MVP operation, qualification, coordination, status, and
reference content are interleaved.

The current path layout is also part of the repository's implementation:
scripts, manifests, tests, requirements mappings, Markdown links, and recorded
digests refer to exact documentation paths. Moving a document safely therefore
requires migrating its consumers and preserving any hash-bound evidence.

## Goals

1. Keep the default engineer-facing documentation focused on current protocol,
   architecture, public interfaces, operating procedures, and implementation
   boundaries.
2. Establish the in-repository archive first, then use it as the destination
   for completed, rejected, experiment-only, or superseded material.
3. Separate MVP use and operation from validation, qualification, evidence,
   and traceability.
4. Extract durable decisions or constraints from completed plans before
   archiving their full design history.
5. Preserve the hash-bound requirements baseline, historical receipts, and
   exact evidence needed to audit prior decisions.
6. Give each current fact one canonical owner and make navigation reveal that
   owner quickly.

## Non-goals

This work does not change protocol, API, wire, runtime, security, or deployment
behavior. It does not revise `data-mesh-requirements.md`, inflate implementation
claims, or move requirement rows merely because documentation moves. It does
not discard Git history, delete retained evidence, or move the archive to an
external service. It also does not rewrite every current document in one pull
request.

## Authority model

Every document belongs to one of the following classes.

| Class | Location | Authority |
|---|---|---|
| Repository overview | root `README.md` | current entry point and implementation boundary summary |
| Concept or architecture | `docs/` | current explanatory model |
| Protocol or security profile | `docs/protocol/` | current normative behavior |
| API or integration guide | `docs/api/` | current public integration contract |
| MVP operation | `docs/mvp/` | current bounded product profile and operator workflow |
| Validation and evidence | `docs/validation/` | current commands, schemas, qualification, and traceability |
| Roadmap and implementation status | `docs/implementation/` | current capability planning and evidence boundary |
| Governing decision | `docs/decisions/` | active architectural constraint and rationale |
| Historical research or design | `archive/` | non-normative retained history |

A document in `archive/` is not current authority unless a current document
explicitly cites a retained historical fact. Current behavior must never be
specified only in the archive.

## Target hierarchy

```text
README.md
data-mesh-requirements.md
docs/
  README.md
  concepts.md
  architecture.md
  protocol/
  api/
  mvp/
  validation/
  implementation/
  decisions/
archive/
  README.md
  MANIFEST.sha256
  research/
    proposals/
    evaluations/
  design-history/
    plans/
    superseded-specs/
    retired-decisions/
```

The hierarchy describes ownership, not a requirement to rename every file at
once. Moves should be small enough that path consumers and claims can be
reviewed coherently.

## Canonical ownership rules

- Root `README.md` explains what Aster is, states the current implementation
  boundary briefly, and gives the shortest supported route to first use.
- `docs/README.md` is navigation, not a second status report.
- `docs/concepts.md` defines stable vocabulary; `docs/architecture.md` explains
  the current component model without retaining implementation chronology.
- `docs/protocol/` owns normative wire, envelope, transport, conformance, and
  security-profile material.
- `docs/api/` owns public application and language binding guidance. Crate
  READMEs continue to own code-local details.
- `docs/mvp/` owns the current Linux Event MVP profile, setup, operations, and
  troubleshooting. It does not own evidence acceptance criteria.
- `docs/validation/` owns qualification procedures, receipt schemas, current
  evaluation inputs, traceability, and evidence interpretation.
- `docs/implementation/capability-roadmap.md` remains the planning and PR-review
  view. A compact generated status view should replace repeated prose where
  structured mappings can be authoritative.
- `docs/decisions/` contains only decisions that still constrain the current
  system. Rejected alternatives and decisions wholly superseded by a later
  authority belong in the archive.

## Archive contract

The archive is an in-repository, frozen historical collection. Admitted files
are immutable; the collection may grow as work completes.

`archive/README.md` will define its non-normative status, admission rules, and
correction policy. `archive/MANIFEST.sha256` will bind every regular archive
file except the manifest itself by relative path and content digest. Entries
will use SHA-256, bytewise path ordering, and paths relative to the repository
root so regeneration is deterministic. Files will normally enter through
`git mv` so that history remains easy to follow, and archived content remains
byte-for-byte intact.

Archived documents are excluded from normal documentation navigation and from
default human-facing size metrics. PR review and the documentation refactor
enforce this information-architecture policy; CI does not parse Markdown
navigation. Corrections are made in current authority or
in a new, clearly labeled archive erratum; historical claims are not silently
rewritten. Archive entries may be reorganized only with a manifest update and
the same path-consumer verification required for initial admission.

Archiving is not deletion. A later external-history repository may be
considered separately after the in-repository model has demonstrated that no
build, test, evidence, or audit workflow depends on ambient historical paths.

## Admission decision

Classification follows this order:

1. Keep a document current when it defines current behavior, supports an active
   operator workflow, governs an open capability gate, or is consumed by live
   validation and traceability.
2. Archive it when its outcome is completed, rejected, superseded, or retained
   only to explain how a decision was reached.
3. For a mixed document, first move its still-current constraints into the
   canonical current owner, update citations, and only then archive the
   original.
4. When authority or consumers are ambiguous, leave the document current until
   the ambiguity is resolved. Uncertainty never justifies a destructive move.

## Initial disposition

The first archive pass targets self-contained, closed material:

- completed implementation plans under `docs/superpowers/plans/`;
- design specifications whose implementation is merged and whose lasting
  constraints have been absorbed into current protocol, architecture, MVP, or
  validation documentation;
- closed provider proposals and their result narratives;
- rejected or experiment-only evaluations that are not current qualification
  inputs; and
- ADRs describing discarded alternatives or demonstrations that no longer
  constrain current code.

The first pass explicitly keeps these materials current:

- `data-mesh-requirements.md` and its hash-bound baseline;
- the capability roadmap, requirement mappings, and requirement status view;
- current protocol, security, transport, envelope, conformance, API, schema,
  release, and deployment material;
- the Linux Event MVP profile, operator runbook, coordination material, current
  qualification procedures, receipts, and SBOM evidence; and
- any evaluation matrix or design specification still consumed by a checker,
  test, manifest, qualification command, or active evidence claim.

In particular, `docs/evaluations/0005/requirements-matrix.csv` remains a live
validation input even though it currently sits below an evaluations path. It
must move to `docs/validation/` only in the same change that updates all code,
tests, mappings, and documentation that consume its exact path. The recently
merged Linux Event MVP qualification receipt validator specification remains
current until its lasting contract is represented in the validator and current
qualification documentation.

## Migration sequence

### Phase 1: archive foundation and inventory

Create the archive hierarchy, policy, manifest generator or deterministic
manifest procedure, and a reviewed classification inventory. Add checks for
archive filesystem shape, manifest integrity, and inventory grammar, state,
and exact Git coverage. Review navigation and references to candidate paths
as part of the documentation refactor. The archive checker does not read or
validate Markdown navigation documents. No ambiguous or hash-bound document
moves in this phase.

### Phase 2: low-risk historical moves

Move self-contained completed plans and closed research with `git mv`. For each
batch, update current inbound links, scripts, and manifests before the move;
regenerate the archive manifest afterward. Keep each pull request focused on
one historical group.

### Phase 3: current hierarchy and MVP/validation split

Create the current directories and move live documents by responsibility.
Separate the Linux Event MVP operator journey from qualification acceptance,
receipt schemas, and evidence interpretation. Update exact path consumers in
the same commits as their documents.

### Phase 4: consolidation

Reduce root and docs navigation to short entry points; consolidate duplicate
architecture, status, CI, API, and reference prose; and archive the originals
only after their durable content has a canonical current owner. Move the HTML
product presentation out of the engineering-doc navigation or generate it from
an explicitly owned site source.

### Phase 5: lifecycle enforcement

Use contribution guidance and human review for document class, owner, status,
links, and archive admission. Repository archive checks validate manifest
integrity and inventory grammar, state, and coverage. Completed plans should move
to `archive/design-history/plans/` as part of completing their capability, not
accumulate indefinitely in current docs.

## Safe move transaction

Each moved batch follows one fail-closed transaction:

```text
inventory exact inbound consumers
  -> classify and extract durable current content
  -> update code, tests, links, mappings, and manifests
  -> git mv the historical source
  -> regenerate archive/MANIFEST.sha256
  -> run focused and repository-wide verification
```

If a required consumer cannot be updated, a recorded digest would be invalid,
or current authority is unclear, the move does not land. The requirements
checker remains authoritative for traceability. Requirement IDs and evidence
statuses change only when their actual implementation or evidence boundary
changes, never as a side effect of path cleanup.

## Verification

Every archive or current-hierarchy pull request includes human review of
Markdown navigation and exact path consumers, and runs:

- `git diff --check`;
- `python3 tools/check-documentation-archive.py` for archive and inventory
  validation;
- `python3 tools/check-implementation-requirements.py`;
- focused tests for every changed script, manifest, schema, or lab workflow;
- archive manifest regeneration followed by an independent digest check; and
- `mise run check` before handoff.

`mise run fuzz-smoke` is not required for path-only documentation changes. It
becomes required if a change also modifies parsers, framing, envelopes,
fragmentation, or another hostile-input boundary.

The baseline `mise run check` for this design branch passed formatting, lint,
traceability, Python tooling, and most Rust tests but failed 28 `aster-node`
tests. The failures include secure temporary-directory checks rejecting the
runner's `/tmp` ownership or permissions, followed by related actor and timeout
failures. Because the run preceded this document, the baseline failure must
remain visible in handoff and must not be attributed to this documentation
change.

## Success criteria

The refactor is complete when:

- a new engineer can understand the product boundary and reach the primary MVP
  workflow through at most five documents totaling no more than 1,500 lines;
- normal navigation exposes no completed implementation plan, rejected
  proposal, or experiment-only report;
- current human-facing Markdown under `docs/`, excluding generated/machine
  evidence, is at most 35 documents and 15,000 lines;
- MVP operation and validation have distinct navigation and canonical owners;
- the implementation boundary and requirement state each have one canonical
  current representation;
- every regular archive file except the manifest itself is present in
  `archive/MANIFEST.sha256` and every digest verifies;
- human review confirms navigation and exact path consumers have no stale
  internal paths or broken current links;
  and
- requirements traceability and all retained evidence remain valid without
  broadening any implementation claim.

## Design lifecycle

This design remains under `docs/superpowers/specs/` while the refactor is
active. After the hierarchy and lifecycle checks are complete and current
documentation owns all lasting rules, this document becomes its own final
archive-admission test and moves to
`archive/design-history/superseded-specs/`.
