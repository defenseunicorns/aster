# PR #1 Blob lifecycle corrections

Clean Room — Privileged.

Scope: retain PR #1 fixes (exclusive pack writers, shared host v8 ceiling,
qualified operation keys, Profile-5 GC) and correct the independently reproduced
remaining defects. Base: c2b8118806a82c7174024c5e6d275d1b00125940.
Evidence: artifacts/pr1-findings-validation-20261030/REPORT.txt (workspace root).

Constraints: preserve wire/storage compatibility, bounded maintenance, no
contiguous counter requirement, no repeated full download for existing content,
32-bit support. No unrelated requirements or protocol redesign.

1. Make maintenance recognize all valid pack lifecycle states; test provisional
   and deletion-pending packs without stalling active-pack GC.
2. Bind writer acquisition to current Store checkpoint under exclusive ownership;
   reject delayed stale reservations before any truncation. Keep unacknowledged
   tail recovery and concurrent-writer exclusion.
3. Validate physical identity before publishing a reservation intent; conflicting
   authenticated physical stream IDs must not poison reopen or existing uploads.
4. Protect reused packs durably while an upload is pending, including restart,
   expiry, abort, promotion and quota reclamation. Use existing bounded authority
   if possible instead of introducing a storage migration.
5. Release page-cache ownership when idle while preserving bounded sequential
   reads, revalidation, cancellation and expiry/GC behavior.
6. Make publication status authorization and hidden/missing behavior consistent
   for active, pending and expired publications.
7. Run focused regressions and affected suites, whole local check, hostile-input
   smoke and native32 checks. Review complete branch with an independent reviewer.

Each correction requires a reproduced failing regression and passing result.
Retain command receipts in artifacts/pr1-lifecycle-fix. Delivery must separate
confirmed results from environments/scenarios not exercised.

Implementation decisions:
- Serialize current-checkpoint validation and writer acquisition in the Store;
  retain that writer in any detached blocking checkpoint transaction.
- Use an additive derived pending-reuse index, capped by the existing 4096-upload
  limit. Derive it on first writable open after recovery; audit existing indexes
  exactly. No upload/pack encoding or payload rewrite is required.
- Physical identity ownership lasts until its durable upload/lifecycle row is
  removed, including when cleanup has already removed the directory.
- Preserve the authorized publication-status contract. Authorization precedes
  identity lookup for ungranted selectors; indistinguishability across two
  granted selectors and older-binary rollback are not qualified here.

Independent review reproduced cancellation/queued-checkpoint and absent-candidate
identity races. Deterministic regressions now cover those paths, deletion after
unlink, multiple pending reuse owners, and missing-index recovery after abort.
Commands, source hashes, red/green results and final verification limits are
retained in the local artifacts/pr1-lifecycle-fix report and receipts.

The full gate also exposed PR1's stale Gate-H constructor-name assertions.
Update the two exact expected method names for semantic-ceiling constructors,
retaining all occurrence counts and authority-ownership checks. The 196-test
lab suite passes after this correction; no historical evidence files change.
