#

# Aster Documentation Refactor Design

- Status: approved
- Date: 2026-09-14
- Scope: documentation architecture and lifecycle only
- Runtime effect: none
- Requirements effect: none

## Purpose

Aster's current documentation is difficult for a human engineer to consume
because product documentation, implementation plans, experiment reports,
validation evidence, and project history are presented together.

The refactor makes `docs/` a compact description of the product that exists
now. Material that is no longer needed to understand or operate the current
product moves to a separate, passive `archive/`. Experiment material that is
not reflected in the codebase and has no durable evidence value is removed.

The archive is not another documentation product. It is historical storage.
Git remains the mechanism for history and integrity; normal review remains the
mechanism for checking documentation changes.

## Principles

1. `docs/` contains only information a human engineer needs for the current
   product.
2. Code and tests are the source of truth for implemented behavior. Current
   documentation explains protocol, public interfaces, operation, and
   non-obvious implementation constraints without duplicating the code.
3. Completed implementation plans and designs do not remain in the current
   documentation after their durable decisions are reflected in code or a
   current reference.
4. MVP operation and validation are separate concerns and have separate
   sections.
5. Archived material is non-normative and is not linked from the normal
   product-documentation path.
6. The refactor introduces no custom documentation enforcement framework.

## Target hierarchy

```text
README.md                         short entry point and current boundary
docs/
  README.md                       current documentation map
  protocol/                       wire rules and protocol semantics
  api/                            public interfaces and integration contracts
  implementation/                 current architecture and constraints
  mvp/                            minimal-product setup and operation
  validation/                     qualification, evidence, and traceability
  operations/                     non-MVP production operation, when needed
  decisions/                      only decisions that still govern the product
archive/
  README.md                       brief non-normative notice
  design-history/                 completed or superseded plans and designs
  research/                       closed evaluations, proposals, and experiments
```

The hierarchy is a destination, not a requirement to create empty directories.
A section exists only when current retained material needs it.

The root `README.md` points readers into current documentation. It does not
make the archive part of the normal reading path. `archive/README.md` states
only that archived files are historical, non-normative, and may describe
behavior that no longer exists.

## Classification rules

Each document is reviewed by its present value, not merely its current path.

### Keep in current documentation

Keep a document in `docs/` when a human engineer needs it to understand,
integrate, operate, validate, or safely change the current product. The
document must have a distinct current purpose that is not already better
expressed by code, tests, or another canonical document.

Examples include:

- current protocol rules and public API contracts;
- current architectural boundaries and non-obvious implementation constraints;
- MVP setup and runbooks that match working code;
- current validation procedures and requirements traceability;
- decisions that still constrain implementation choices.

### Move to the archive

Move a document to `archive/` when it is no longer needed for current product
work but remains useful as project history or retained evidence.

Examples include:

- completed implementation plans;
- superseded designs;
- rejected proposals with durable decision context;
- closed evaluations or experiments retained as historical evidence;
- old coordination and milestone records.

If a historical document mixes obsolete narrative with a durable current
constraint, first place the constraint in its current canonical document, then
archive the historical document intact.

### Remove

Remove a document when it describes an abandoned experiment or proposal that
is absent from the codebase, has no current consumer, and is not required as
historical requirements evidence. Git history is sufficient for recovery.

Removal requires ordinary human review of references and evidentiary use. It
does not require a custom tool or a permanent classification record.

## Requirements and evidence boundary

The refactor preserves `data-mesh-requirements.md`, the 348 atomic requirement
IDs, the hash-bound baseline, and historical evidence required by repository
policy. Documentation location alone does not change a requirement's status or
expand an implementation claim.

The current requirements status and capability roadmap belong under
`docs/validation/` because they describe qualification and traceability rather
than implementation design. Any relocation updates exact path consumers and
recorded hashes in the same focused change. Exact requirement IDs are updated
only when their implementation or evidence boundary genuinely changes.

## Migration approach

The work proceeds in small, reviewable pull requests:

1. Remove the abandoned archive-specific checker, tests, manifest, permanent
   inventory, and task/CI integration.
2. Create a short current-documentation map and make the root `README.md` the
   clear entry point.
3. Review completed plans, proposals, evaluations, and experiments; extract
   any durable current constraints; then archive or remove the source material.
4. Separate MVP operation from validation and relocate current documents into
   the target hierarchy.
5. Consolidate overlapping current documents and remove descriptions already
   made redundant by code and tests.
6. Finish by removing any temporary local inventory used during the refactor.

Use `git mv` when retaining a file in the archive so its history remains easy
to follow. Use `git rm` only after checking current references and evidence
roles. Each pull request fixes affected links and repository consumers as part
of the same coherent move.

## No archive tooling

The final repository has none of the following:

- an archive manifest or digest registry;
- an archive checker or checker test suite;
- a permanent documentation-refactor inventory;
- archive-specific `mise` tasks or CI gates;
- a custom Markdown navigation or link parser.

These mechanisms would add another system that engineers must understand and
maintain. They do not make the documentation itself easier to read.

During the refactor, maintainers may use ordinary Git diffs, `rg`, and a local
ignored scratch list to plan batches. The scratch list is not product
documentation and is deleted when the migration is complete.

## Verification

Each documentation pull request is reviewed as documentation by a human. The
author also runs checks appropriate to the files whose repository role changed:

- `git diff --check` for patch hygiene;
- `rg` searches for stale paths and broken repository references;
- `python3 tools/check-implementation-requirements.py` whenever requirements
  evidence or traceability changes;
- focused tests for scripts or code whose inputs moved;
- `mise run check` before handing off a substantive code change, as required
  by repository policy.

No archive-specific verification is added.

## Success criteria

The refactor is complete when:

- a new engineer can enter through `README.md` and reach current protocol,
  implementation, MVP, and validation material without reading project history;
- `docs/` contains no completed plans, superseded designs, abandoned
  experiments, or historical coordination records;
- MVP operation and validation have distinct, obvious homes;
- each retained current document has one clear purpose and canonical owner;
- `archive/` is visibly non-normative and absent from normal navigation;
- no custom archive tooling or permanent migration inventory remains;
- the requirements baseline and retained historical evidence remain valid.

## Non-goals

This work does not change protocol, API, runtime, security, or deployment
behavior. It does not broaden requirements claims, replace existing repository
verification, build a general documentation linter, or rewrite every current
document in a single pull request.
