# Evaluation 0005 final clean validation receipt

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

Date: 2026-08-23

Verdict: **PASS — P0 0 / P1 0 / P2 0**

This receipt records the clean replacement validation required by BVB-909. The
validator was read-only and stayed inside the explicit allowlist:
`data-mesh-requirements.md`, `docs/evaluations/0005`, the archived experiment collection,
`evidence/SOURCE_REGISTER.csv`, and the three named project governance
files. It did not inspect Proposal 0004, any excluded experiment subtree,
product architecture, or product code.

## Validated baseline

- Source register through BVB-911: 1,005 data rows, 9 columns, 911 unique and
  contiguous BVB IDs, live tail BVB-911.
- Register SHA-256:
  `74cd14f08e7f0b8208ea9366c3c4c2e1ae55637e82d1bba933992441f6b5eb52`.
- The only duplicate IDs are the documented legacy `SRC-001` and `SRC-002`.
- The harmless historical physical-order descent `BVB-626` → `BVB-613` does
  not create a numeric gap or duplicate.
- BVB-910 was verified 9/9 before the BVB-911 correction; its seven
  unsuperseded bindings remain exact. BVB-911 verifies 2/2.

## Mechanical result

- Controls-only contract: pass; no candidate executed.
- Visible JSON: 50/50 parsed.
- SHA-256 sidecars: 13 files and 172/172 targets verified.
- Markdown: 41 sources and 173 local links, with zero failures.
- Ignore boundary: 317 visible lab files and 158,370 ignored entries; zero
  sensitive raw/run/trial/target/archive/deb/closure/quarantine leaks.
- Topology accounting: 13/13 ordinary cases passed; all three upstream-ignored
  hard-cross cases failed the direct wait as bounded; 16/16 began relayed;
  zero infrastructure failures in the decisive run.
- Historical-envelope wording, BVB-865/BVB-909 containment, Phase 0 misses,
  Phase 2 architecture-collapse accounting, confidence/residual bands,
  no-production/full-work-order claim guards, and scoped whitespace: pass.

The validator found one P1 documentation omission during its first pass: the
rust-libp2p row did not explicitly disposition request-response. BVB-911 fixed
that row to state that request-response and pub/sub remain libp2p-owned source
candidates only; neither received exact application limits, execution, or
credit. The clean final rerun then returned P0 0 / P1 0 / P2 0.

## Bounded exceptions

- Two Phase 5 hashes intentionally describe historical snapshots rather than
  current documents.
- One Phase 5 work-order target was outside the validator allowlist and was not
  opened.
- Fourteen identity/provenance TSV ledgers were structurally parsed but do not
  define generic target-path verification contracts.

These exceptions do not create a validation failure and do not broaden any
candidate credit. The result remains bounded research evidence: it is not a
requirements-complete architecture, production selection, physical/public
qualification, legal clearance, release authorization, or external
project-owner disposition.

Machine-readable receipt: archived `final-validation-receipt.json` (archived)

Canonical validator payload SHA-256:
`178d32dd1ed43f8261f0880209739329e456f6bba3361f4347b2799303a0c123`.
