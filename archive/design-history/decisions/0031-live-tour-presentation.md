# Decision 0031: Keep live tour presentation separate from raw receipts

- Status: Accepted
- Date: 2026-08-27

## Context

The capability-tour wrapper retained the `aster demo` stdout and stderr, then
printed both only after the process exited. That protected the exact receipt
but made the longer relay and control demonstrations appear idle before
releasing dense key/value records all at once.

A shell `tee` pipeline would stream output, but portable POSIX `sh` cannot also
recover the left-hand demo status reliably. An updating view must not weaken
receipt fidelity, become a second pass/fail authority, or orphan the demo's
child processes when interrupted.

## Decision

Use the already-pinned Python standard library as a presentation boundary
around the unchanged CLI:

- launch each build or demo in its own process group and return its exact exit
  status;
- write stdout and stderr bytes to exclusive raw receipt files before parsing
  them for display;
- show an updating dashboard on capable terminals and progressively printed
  human summaries otherwise;
- retain an explicit raw view for structured-stdout consumers;
- derive friendly progress only from known tour phases and child-log creation,
  while marking a phase verified only after its passing structured receipt;
  and
- render stopped-node inspection as a role-oriented table without changing the
  underlying inspection receipt.

Unknown or malformed display records are retained and may fall back to raw
presentation. A missing or inconsistent terminal receipt is shown as a warning,
not a presenter-authored pass. Presentation failures do not replace demo or
inspection status. Receipt-write failure remains fatal because the tour
promises retained artifacts.

## Consequences

The normal commands now provide visible progress and a concise terminal result
without adding a package, crate, or external source. Raw receipt names and CLI
semantics remain unchanged. The presenter adds signal, terminal-restoration,
plain-output, receipt-fidelity, and failure-propagation tests.

This is operator and developer presentation only. It changes no wire or public
application API, implementation status, requirement mapping, retained
acceptance result, or production-authorization boundary.
