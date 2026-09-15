# Requirements-matrix notes

> ****

## Authority and provenance

The sole semantic authority for the matrix is
[`data-mesh-requirements.md`](../../data-mesh-requirements.md), version 0.1,
dated 2026-08-17, with SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
That exact input is registered as `SRC-001` in the project source ledger.
The hash was recomputed before generating the matrix and matched `SRC-001`.
This labeled sidecar binds the exact companion
`requirements-matrix.csv` artifact at SHA-256
`57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2`;
the Phase 0 validator rejects a different matrix hash.

Every CSV row derives its provenance from three fields together:

- `source_lines` identifies the authoritative line or line range;
- `section` identifies the requirements section; and
- `id` provides a stable local identifier for the atomic interpretation.

No row uses current Aster behavior, architecture, wire formats, APIs, test
results, or external candidate facts as authority. No public or external source
was needed or consulted for this artifact. The project contribution rules
were consulted only as process instructions, not as semantic requirements.

## Atomization rules

The matrix follows these rules:

1. One row states one independently assessable capability, constraint, target,
   phase obligation, acceptance outcome, deliverable, or open decision.
2. A source bullet containing multiple independently testable effects is split.
   For example, at-least-once delivery, deduplication, and idempotent application
   are separate atoms.
3. Explicit `Must`, `Should`, `May`, and `Future` clauses never share a row.
   Conditions attached to an optional action remain binding atoms when the source
   uses `Must`; for example, optional cryptographic amortization is separate from
   the requirement to preserve end-to-end protection if amortization is used.
4. Every bracketed quantitative placeholder is separated from its capability.
   The value is stored in `provisional_value`, classified as
   `provisional_target`, and has `final_stack_invariant=false` until stakeholder
   validation. The corresponding unquantified capability remains independently
   represented when the source makes it binding.
5. MVP, Post-MVP, Future, release-acceptance, and governance statements retain
   their own rows even when they restate an earlier capability. This preserves
   source traceability and phase intent; counts therefore represent source atoms,
   not deduplicated product features.
6. Examples do not silently become requirements. Example priority names,
   candidate binding languages, and example algorithms are retained only as
   notes, selection constraints, or open decisions when the source treats them
   that way.
7. Section 4 definitions are not emitted as requirement atoms because they define
   vocabulary rather than impose independently assessable obligations. The
   defined terms are used consistently in the capability statements.

Atomization is a traceability technique, not a work-breakdown structure. An
atom can be a repeated phase statement, provisional value, future candidate,
assumption, evidence outcome, deliverable, or open decision. Counts must not be
used as backlog size, completion percentage, estimate, or release score. The
[capability roadmap](capability-roadmap.md) is the planning
and PR-review view.

## Column conventions

### `id`

IDs use `DM-<section>-<two-digit ordinal>` in authoritative source order, with a
letter suffix where a capability/value split shares the same source position.
These IDs are immutable once introduced. A later requirements revision should
append a suffix or a new ordinal rather than renumber existing rows.

### `level`

- `must`: an explicit source `Must`.
- `should`: an explicit source `Should`.
- `may`: an explicit source `May` or an explicitly optional allowance.
- `future`: a source item explicitly tagged Future.
- `binding`: a declarative obligation in the project brief, requirement body,
  MVP definition, or deliverable list that does not repeat a modal word.
- `scope`: an explicit in-scope or non-goal boundary.
- `assumption`: an operating-environment condition the design must tolerate.
- `provisional`: the capability-independent row for a bracketed value.
- `open`: a stakeholder or team decision explicitly left unresolved.

### `phase`

- `baseline`: applies independently of a named delivery phase.
- `mvp`: required or evaluated for the first release.
- `post-mvp`: binding work explicitly deferred until after MVP.
- `future`: a candidate or compatibility constraint for a future profile.
- `release`: an acceptance scenario whose equivalent the release must pass.
- `governance`: a validation or selection action assigned to stakeholders or the
  team.

### `class`

- `hard_invariant`: correctness, security, interoperability, resource, or
  operating behavior that a final composition must preserve.
- `product_scope`: a required product surface, delivery artifact, phase scope, or
  explicit non-goal.
- `provisional_target`: a bracketed quantitative value or its explicit
  stakeholder-validation action.
- `preference_or_future`: a `Should`, `May`, Future candidate, or non-binding
  architecture preference.

The class is evaluation metadata, not a replacement for the source modality.
`level`, `phase`, the exact normalized statement, and the source lines remain
visible so reviewers can revise a classification without changing the authority.

### `final_stack_invariant`

`true` means the source imposes a binding final-composition capability, security
or correctness property, product boundary, deliverable, or eventual Post-MVP
obligation. `false` marks provisional values, open decisions, preferences,
optional behaviors, and Future candidates. A `false` value does not mean the row
is irrelevant; it means it is not a non-compensable final-stack gate in its
current source form.

## Coverage and validation

The CSV contains **348 atomic rows** plus its header. All 348 IDs are unique.

### Rows by section

| Section | Rows |
|---|---:|
| 1 Project Brief | 7 |
| 2 Scope | 14 |
| 3 Operating Environment | 13 |
| 5.1 Data Model | 24 |
| 5.2 Synchronization and Consistency | 22 |
| 5.3 Conflict Handling | 12 |
| 5.4 Priority and Constrained Operation | 22 |
| 5.5 Scoping and Propagation Control | 14 |
| 5.6 Peer-to-Peer and Store-and-Forward | 6 |
| 5.7 Discovery and Peering | 4 |
| 5.8 Transports | 18 |
| 6 Security | 36 |
| 7 Developer Experience and Embeddability | 21 |
| 8 Implementation Constraints | 19 |
| 9 Performance and Resource Targets | 32 |
| 10 Compatibility and Evolution | 6 |
| 11 MVP Definition and Phasing | 33 |
| 12 Acceptance Scenarios | 11 |
| 13 Deliverables | 11 |
| 14 Open Items | 23 |

### Rows by level

| Level | Rows |
|---|---:|
| must | 165 |
| should | 14 |
| may | 13 |
| future | 14 |
| binding | 73 |
| scope | 12 |
| assumption | 11 |
| provisional | 21 |
| open | 25 |

### Rows by phase and class

| Dimension | Value | Rows |
|---|---|---:|
| phase | baseline | 230 |
| phase | mvp | 59 |
| phase | post-mvp | 6 |
| phase | future | 17 |
| phase | release | 11 |
| phase | governance | 25 |
| class | hard_invariant | 183 |
| class | product_scope | 78 |
| class | provisional_target | 38 |
| class | preference_or_future | 49 |
| final stack invariant | true | 259 |
| final stack invariant | false | 89 |

Mechanical validation confirmed:

- the exact requested eleven-column header and eleven fields in every row;
- RFC 4180-compatible CSV parsing;
- 348 rows and 348 unique stable IDs;
- allowed `level`, `phase`, `class`, and boolean values only;
- a nonempty `provisional_value` for every `provisional_target` and no value in
  any other class;
- `final_stack_invariant=false` for every provisional target; and
- coverage of every requirement-bearing source line in sections 1 through 3 and
  5 through 14.
