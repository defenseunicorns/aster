# Final bakeoff validation receipt

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


Validated through `BVB-950`: **PASS**.

- Source-register snapshot SHA-256:
  `2953bf3573b12d97b33855b26332138fcdb12f35b3779359695e73245a127b32`
- Register structure: nine fields per row; `BVB-001` through `BVB-950`
  unique as a contiguous set; one preserved historical order descent.
- Controls-only contract: pass.
- Corrected comparison JSON parse and 14-row CSV shape: pass.
- Scoped local links and trailing whitespace: pass.
- Independent comparison review: no P0/P1; all three P2 wording/scope findings
  corrected in `BVB-948` without changing the decision.

Decision: G—explicit Iroh 1.0.3 + Negentropy 0.5.1 + redb 4.2.0 under a
requirements-owned profile—is the bounded research baseline. P2panda remains a
conditional component and semantic reference. BPv7 remains conditional on a
named hard delta. `production_selected=false`.

This receipt validates local evidence consistency. It does not grant a general
exactly-once claim, production admission, legal clearance, requirements
completion, physical qualification, release authorization, or an external
immutable evidence anchor. Endpoint and durable-domain comparisons are scoped
to the task-authored evaluated compositions.

The machine-readable receipt is
archived `final-validation-receipt.json`.

