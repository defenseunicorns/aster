# Customer feedback

This section records customer and potential-customer feedback alongside a
separate Aster product recommendation review. It preserves what was actually
heard without silently turning feedback into product requirements.

## Authority boundary

Customer feedback is **advisory input**. A feedback record or recommendation:

- is not a requirement, roadmap commitment, acceptance criterion, evidence
  receipt, or release authorization;
- does not change `data-mesh-requirements.md`, an atomic requirement status,
  capability maturity, or a supported profile;
- may identify alignment with existing capability actions without advancing
  those actions or their evidence; and
- becomes authoritative only through the normal reviewed artifact for the
  decision being made, such as a requirements disposition, decision record,
  evaluation or production profile, capability-roadmap change, or approved
  implementation increment.

If a recommendation is adopted, link the authoritative follow-up artifact from
the recommendation. Do not rewrite the original feedback to make it resemble
the adopted decision.

## Structure

Each feedback package has its own dated directory and two documents:

```text
YYYY-MM-DD-descriptive-topic/
├── feedback.md
└── recommendation.md
```

- `feedback.md` is the factual intake record: provenance, confirmed feedback,
  source boundaries, and unanswered questions. It contains no Aster planning
  recommendation.
- `recommendation.md` is the separate product review: interpretation,
  value/effort ranking, roadmap alignment, dependencies, non-recommendations,
  and disposition.

Use the files under [`templates/`](templates/) when adding a package. Keep
customer labels anonymous unless the approved source and intended audience
permit identification.

## Workflow

1. Assign a stable feedback ID and create one package from the templates.
2. Record only confirmed feedback in `feedback.md`. Separate observations from
   questions, assumptions, and Aster-authored implications.
3. Record source type, date, provenance boundary, and a digest when a stable
   source artifact exists. Do not commit credentials, mission data, personal
   data, or a restricted source merely to preserve provenance.
4. Write `recommendation.md` as an independent Aster review. State uncertainty
   and score value against remaining effort rather than treating every request
   as equally urgent.
5. Review the recommendation as `Proposed`, `Accepted`, `Deferred`, `Rejected`,
   or `Superseded`. Acceptance approves the recommendation only; it does not
   alter requirements or evidence without the linked authoritative follow-up.
6. Add the package to the index below. Preserve prior records when later
   feedback changes the recommendation; link superseding packages instead of
   erasing history.

## Status vocabulary

| Field | Values | Meaning |
| --- | --- | --- |
| Feedback state | `Captured`, `Reviewed`, `Superseded` | Whether the factual record has been checked and whether a later record replaces its context |
| Recommendation status | `Proposed`, `Accepted`, `Deferred`, `Rejected`, `Superseded` | The disposition of Aster's review, not the authority or evidence status of a product requirement |

## Feedback index

| Feedback ID | Date | Customer label | Topics | Feedback state | Recommendation status |
| --- | --- | --- | --- | --- | --- |
| [`CF-2026-09-10-01`](2026-09-10-potential-client-retention-sync/feedback.md) | 2026-09-10 | Potential client | Retention, synchronization cost, constrained links, higher-capacity custody | Reviewed | [Proposed](2026-09-10-potential-client-retention-sync/recommendation.md) |
| [`CF-2026-09-16-01`](2026-09-16-anonymous-integration-workflows/feedback.md) | Date not supplied | Anonymous external feedback | Protected delivery, application integration, operational visibility, onboarding | Reviewed | [Proposed](2026-09-16-anonymous-integration-workflows/recommendation.md) |

## Maintenance rules

- Correct factual transcription errors in place and explain material
  corrections in the file.
- Put new or changed customer input in a new package when it changes context,
  priority, or scope materially.
- Update recommendation status only after the responsible reviewers make that
  disposition.
- Update exact requirement IDs or the capability roadmap only when their own
  implementation, evidence, applicability, or planning boundary genuinely
  changes.
