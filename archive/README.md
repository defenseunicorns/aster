# Aster documentation archive

This tree is retained, non-normative project history. Current Aster behavior is
defined under `docs/`, the root `README.md`, and
`data-mesh-requirements.md`; archive content must not be used as current
implementation or evidence authority unless a current document explicitly
cites one retained historical fact.

## Admission

Only completed, rejected, superseded, or experiment-only material enters this
tree. Mixed documents stay current until durable constraints have been moved to
their current canonical owner and all path consumers have been migrated.

## Immutability and corrections

Admitted historical files remain byte-for-byte unchanged. Corrections belong in
current authority or a new, clearly labeled erratum. Every regular archive file
except `archive/MANIFEST.sha256` is SHA-256 bound by that manifest.

## Layout

- `research/`: closed proposals and evaluation history.
- `design-history/`: completed plans, superseded specifications, and retired
  decisions.

The collection grows through reviewed `git mv` batches. It is excluded from
normal engineer-facing navigation.
