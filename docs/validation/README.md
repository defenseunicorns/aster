# Validation and readiness

> ****

This area separates implementation evidence and qualification work from
product concepts, protocol rules, and operator procedures. It does not by
itself authorize a production release.

## Product progress

- [Capability roadmap](capability-roadmap.md) — planning and PR-review view.
- [Current implementation boundary](../../README.md#current-implementation-boundary) — capabilities and limitations.
- [Requirements migration #203](https://github.com/defenseunicorns/aster/issues/203) — discussion and revalidation of remaining work.
- [Requirements matrix notes](requirements-matrix-notes.md) — immutable
  requirements atomization rules and final-stack flags.
- [Conformance](conformance.md), [security-profile disposition](security-profile-requirements-disposition.md),
  and [CI](ci.md) — verification boundaries and remaining gates.
- [Blob streaming engineering runbook](blob-streaming-engineering-runbook.md)
  — large-object application, selected-contact, CM4, and diagnostic examples.

## Linux Event MVP qualification

The accepted profile is hash-bound and remains the exact authority. Its
original design links resolve through compatibility pointers: superseded
designs live in the archive, while active approval inputs live in this
validation package.

- [Coordination guide](linux-event-mvp-coordination-guide.md) — human-oriented
  sequence, ownership, blockers, and definition of done.
- [Evaluation profile](linux-event-mvp-evaluation-profile-v0.1.md) — exact
  claim boundary.
- [Decision register](linux-event-mvp-evaluation-profile-v0.1-register.md) and
  [candidate annex](linux-event-mvp-evaluation-profile-v0.1-annex-template.md)
  — gate status and candidate evidence shape.
- [Qualification receipt validator](linux-event-mvp-qualification-receipt-validator-spec.md)
  — receipt contract.
- [Immutable inputs](inputs/) and [retained evidence](evidence/) — exact
  approval records and bounded observations.

## Requirements tracking pending migration

The CSV files remain pending [#203](https://github.com/defenseunicorns/aster/issues/203). The following
vocabulary and totals are preserved from the retired status report, not
a new assessment of current implementation or production readiness. Historical
CSV report anchors remain pending migration; see the
[original report](https://github.com/eshcheglov-aster/aster/blob/727264b04247be085ec5f24a91111b056b1b5a6e/docs/validation/requirements-status.md).

### Trace vocabulary

The `selected_status` column uses only `observed-bounded`,
`implemented-uncredited`, and `open`. The remaining values below describe
separate source, evidence, or gate dimensions.

| Trace value              | Meaning                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `observed-bounded`       | Real production-lane code passed a stated, reproducible test, but only within the recorded environment and claim boundary       |
| `implemented-uncredited` | A mechanism exists, but the complete requirement has not been demonstrated                                                      |
| `open`                   | The selected production composition does not yet implement the obligation                                                       |
| `semantic-source`        | Proven current semantic code or tests remain an equivalence source until the selected composition passes the replacement tests  |
| `research-only`          | Evaluation informed implementation, but its result is not production acceptance                                                 |
| `external-gate`          | Completion requires target hardware, independent authorship/review, an admitted cryptographic module, or stakeholder-set values |

### Production-lane requirements trace

The CSV tracks each requirement separately. Row counts include repeated phase and
acceptance requirements; they are not a product completion percentage.

<!-- ASTER-REQUIREMENTS-TOTALS:BEGIN -->

Generated selected-status totals: implemented-uncredited=53; observed-bounded=84; open=211; exact-selected-mappings=140.

| Requirement family | Implemented, not fully credited | Observed, bounded | Open    | Total   |
| ------------------ | -------------------------------:| -----------------:| -------:| -------:|
| DM-1               | 0                               | 3                 | 4       | 7       |
| DM-2               | 1                               | 0                 | 13      | 14      |
| DM-3               | 1                               | 1                 | 11      | 13      |
| DM-5               | 26                              | 50                | 46      | 122     |
| DM-6               | 4                               | 18                | 14      | 36      |
| DM-7               | 6                               | 3                 | 12      | 21      |
| DM-8               | 2                               | 2                 | 15      | 19      |
| DM-9               | 2                               | 3                 | 27      | 32      |
| DM-10              | 0                               | 0                 | 6       | 6       |
| DM-11              | 9                               | 0                 | 24      | 33      |
| DM-12              | 0                               | 4                 | 7       | 11      |
| DM-13              | 2                               | 0                 | 9       | 11      |
| DM-14              | 0                               | 0                 | 23      | 23      |
| **Total**          | **53**                          | **84**            | **211** | **348** |

<!-- ASTER-REQUIREMENTS-TOTALS:END -->
