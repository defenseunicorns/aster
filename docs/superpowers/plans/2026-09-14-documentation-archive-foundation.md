# Documentation Archive Foundation Implementation Plan

> 

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish Aster's in-repository archive policy, deterministic manifest,
reviewed candidate inventory, and fail-closed repository checks without moving
any existing documentation.

**Architecture:** A small standard-library Python checker owns deterministic
archive enumeration, SHA-256 manifest verification, inventory coverage and
state validation. PR review and the documentation refactor keep historical
material out of normal engineer navigation; the checker does not read or
validate Markdown navigation documents. The repository initially contains
only archive policy/index files; later plans use the validated inventory and
manifest interface to move one coherent historical batch at a time.

**Tech Stack:** Python 3.13 standard library (`argparse`, `csv`, `hashlib`,
`pathlib`, `subprocess`, `unittest`), SHA-256, Markdown, CSV, Git, and `mise`.

**Spec:**
`docs/superpowers/specs/2026-09-14-documentation-refactor-design.md`

## Global Constraints

- [ ] This plan implements only design Phase 1. Do not move, rename, rewrite,
      or delete any existing document.
- [ ] Keep `docs/` authoritative and `archive/` non-normative.
- [ ] Preserve `data-mesh-requirements.md`, its hash-bound baseline, all 348
      requirement IDs, and all existing evidence statuses.
- [ ] Treat paths used by scripts, tests, manifests, mappings, qualification,
      or evidence as implementation dependencies, not prose-only links.
- [ ] Manifest every regular file under `archive/` except
      `archive/MANIFEST.sha256` itself.
- [ ] Use SHA-256, repository-relative POSIX paths, UTF-8 bytewise path order,
      lowercase hexadecimal digests, two ASCII spaces before each path, and one
      trailing LF for the manifest.
- [ ] Reject archive symlinks, special files, duplicate paths, malformed
      manifest entries, path traversal, stale digests, and unmanifested files.
- [ ] Keep `archive/` out of root `README.md` and `docs/README.md` navigation.
      Enforce this through human review. Other current documents may cite an
      archived historical fact explicitly in later phases.
- [ ] The reviewed inventory must cover every Git-tracked candidate file below
      the current history roots or their matching archive leaf roots exactly
      once. Coverage follows each row's `current_path` after a move while its
      original `source_path` remains stable.
- [ ] Ambiguous material remains current through `keep-current`,
      `extract-current-first`, or `migrate-consumers-first`; uncertainty never
      becomes `archive-ready`.
- [ ] Do not run `mise run fuzz-smoke`; this plan changes no parser, framing,
      envelope, fragmentation, or hostile-input runtime boundary.

---

## File and interface map

| File | Responsibility |
|---|---|
| `archive/README.md` | Archive authority, immutability, admission, correction, and navigation policy |
| `archive/research/README.md` | Scope of retained proposals and evaluations |
| `archive/design-history/README.md` | Scope of completed plans, superseded specs, and retired decisions |
| `archive/MANIFEST.sha256` | Deterministic integrity inventory for the three archive policy files |
| `docs/implementation/documentation-refactor-inventory.csv` | Reviewed disposition and future destination of every candidate file |
| `tools/check-documentation-archive.py` | Read-only validation plus explicit `--write-manifest` maintenance command |
| `tools/test-documentation-archive.py` | Isolated manifest, inventory, and CLI regression tests |
| `mise.toml` | Focused `documentation-archive` task and inclusion in `mise run check` |

The checker exposes these stable interfaces for later archive-move plans:

```text
ArchiveViolation < ValueError
InventoryRow(source_path: str, current_path: str, target_path: str,
             document_class: str, disposition: str, batch: str, reason: str)
archive_files(repository_root: Path) -> tuple[Path, ...]
render_manifest(repository_root: Path) -> str
validate_manifest(repository_root: Path, actual: str) -> int
write_manifest(repository_root: Path) -> int
parse_inventory(text: str) -> tuple[InventoryRow, ...]
tracked_candidate_paths(repository_root: Path) -> tuple[str, ...]
validate_inventory(rows: tuple[InventoryRow, ...],
                   candidate_paths: tuple[str, ...]) -> None
```

`python3 tools/check-documentation-archive.py` is read-only and returns `0`
only when both archive and inventory boundaries pass. The sole write mode is
`python3 tools/check-documentation-archive.py --write-manifest`, which rewrites
only `archive/MANIFEST.sha256` with an atomic same-directory replacement and
then validates the written bytes.

## Follow-on plan boundaries

This plan deliberately leaves four independently reviewable plans:

1. move completed plans and closed research in path-safe batches;
2. create the current `docs/protocol/`, `docs/api/`, `docs/mvp/`, and
   `docs/validation/` hierarchy and separate MVP operation from qualification;
3. consolidate duplicate navigation, architecture, status, CI, API, and
   reference prose; and
4. enforce the completed-document lifecycle in contribution and PR guidance.

### Task 1: Publish the frozen archive contract

**Files:**

- Create: `archive/README.md`
- Create: `archive/research/README.md`
- Create: `archive/design-history/README.md`
- Create: `archive/MANIFEST.sha256`

**Interfaces:**

- Consumes: authority model, archive contract, and target hierarchy from the
  approved design.
- Produces: the exact policy that `tools/check-documentation-archive.py` and all
  later archive batches enforce.

- [ ] **Step 1: Create the archive root policy**

Use `apply_patch` to create `archive/README.md` with these normative sections
and statements:

```markdown
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
```

- [ ] **Step 2: Create the two category policies**

Create `archive/research/README.md` stating that `proposals/` and
`evaluations/` material is historical and cannot establish current dependency,
security, protocol, or qualification choices. Create
`archive/design-history/README.md` stating that `plans/`, `superseded-specs/`,
and `retired-decisions/` preserve rationale but cannot override current code,
tests, protocol docs, or active ADRs. State that leaf directories materialize
with their first admitted batch because Git does not retain empty directories.

- [ ] **Step 3: Bind the initial archive policy files**

Run this read-only digest command from the repository root:

```bash
LC_ALL=C sha256sum archive/README.md archive/design-history/README.md archive/research/README.md
```

Use `apply_patch` to create `archive/MANIFEST.sha256` from the exact output.
Expected: three lowercase SHA-256 entries, sorted bytewise by the displayed
repository-relative path, with two spaces between each digest and path.

- [ ] **Step 4: Check the policy-only diff and manifest**

Run:

```bash
git diff --check
rg -n "current|non-normative|byte-for-byte|MANIFEST.sha256" archive
sha256sum --check archive/MANIFEST.sha256
```

Expected: `git diff --check` exits `0`; the search shows the authority,
immutability, and manifest rules in the root and category policy files; all
three digest entries report `OK`.

- [ ] **Step 5: Commit the policy skeleton**

```bash
git add archive/README.md archive/research/README.md archive/design-history/README.md archive/MANIFEST.sha256
git commit -m "docs: establish archive policy"
```

### Task 2: Implement deterministic archive manifests

**Files:**

- Create: `tools/check-documentation-archive.py`
- Create: `tools/test-documentation-archive.py`
- Modify: `archive/MANIFEST.sha256`

**Interfaces:**

- Consumes: the three policy files from Task 1.
- Produces: `ArchiveViolation`, `archive_files`, `render_manifest`,
  `validate_manifest`, `write_manifest`, and the stable manifest grammar used
  by all later move batches.

- [ ] **Step 1: Write failing manifest tests**

Load the hyphenated checker with `importlib.util.spec_from_file_location`, as
`tools/test-retained-libp2p-oracle-boundary.py` does. Add `unittest` cases that
construct a temporary `archive/` and assert:

```python
def test_manifest_is_bytewise_sorted_and_excludes_itself(self) -> None:
    self.write("archive/research/z.md", b"z\n")
    self.write("archive/research/a.md", b"a\n")
    self.write("archive/MANIFEST.sha256", b"ignored\n")
    rendered = CHECKER.render_manifest(self.root)
    paths = [line.split("  ", 1)[1] for line in rendered.splitlines()]
    self.assertEqual(paths, ["archive/research/a.md", "archive/research/z.md"])
    self.assertTrue(rendered.endswith("\n"))

def test_digest_mismatch_fails(self) -> None:
    self.write("archive/README.md", b"policy\n")
    actual = CHECKER.render_manifest(self.root)
    self.write("archive/README.md", b"changed\n")
    with self.assertRaisesRegex(CHECKER.ArchiveViolation, "manifest differs"):
        CHECKER.validate_manifest(self.root, actual)
```

Also test an absent manifest, uppercase/malformed digest, duplicate path,
unsorted entries, missing trailing LF, unmanifested file, manifest self-entry,
symlinked file, symlinked directory, FIFO/special file where supported, and a
manifest entry outside `archive/`. Tests must compare the whole rendered
string, not a set of entries.

- [ ] **Step 2: Run the tests and observe the missing checker failure**

Run:

```bash
python3 tools/test-documentation-archive.py -v
```

Expected: FAIL while importing the absent
`tools/check-documentation-archive.py`.

- [ ] **Step 3: Implement exact archive enumeration**

Create the checker with the repository copyright/SPDX header and the interfaces
from the file map. `archive_files` must:

```python
MANIFEST_RELATIVE = Path("archive/MANIFEST.sha256")
sort_key = lambda path: path.relative_to(repository_root).as_posix().encode("utf-8")
```

Use `os.scandir` recursively so a symlinked directory cannot be followed
silently. Reject filenames containing LF, CR, or the two-space manifest
separator. Require every enumerated path to remain below the resolved archive
root.

- [ ] **Step 4: Implement rendering and read-only validation**

`render_manifest` must stream each file in 1 MiB chunks and emit exactly:

```python
f"{digest.hexdigest()}  {relative_path.as_posix()}\n"
```

`validate_manifest` must parse each line with a strict full-match expression,
reject all non-canonical encodings before comparing bytes, and then compare the
entire supplied string with `render_manifest`. Return the number of manifested
files on success. The default CLI reads and validates the committed manifest;
it never repairs failure automatically.

- [ ] **Step 5: Implement explicit atomic manifest writing**

`write_manifest` writes the rendered UTF-8 bytes to
`archive/.MANIFEST.sha256.tmp`, flushes and `os.fsync`s the file, calls
`os.replace` onto `archive/MANIFEST.sha256`, syncs the archive directory where
supported, and validates the resulting bytes. Refuse to overwrite a symlink or
non-regular existing manifest. Remove only the exact temporary file after a
failed write.

- [ ] **Step 6: Run manifest tests**

Run:

```bash
python3 tools/test-documentation-archive.py -v
```

Expected: all manifest tests PASS, including rejection cases.

- [ ] **Step 7: Generate and independently verify the initial manifest**

Run:

```bash
python3 tools/check-documentation-archive.py --write-manifest
sha256sum --check archive/MANIFEST.sha256
python3 tools/check-documentation-archive.py
```

Expected: three policy files are listed; `sha256sum` reports all three `OK`;
the checker reports `3 archive files` and exits `0`.

- [ ] **Step 8: Commit the manifest boundary**

```bash
git add archive/MANIFEST.sha256 tools/check-documentation-archive.py tools/test-documentation-archive.py
git commit -m "test: enforce archive manifest integrity"
```

### Task 3: Add the reviewed candidate inventory

**Files:**

- Modify: `tools/check-documentation-archive.py`
- Modify: `tools/test-documentation-archive.py`
- Create: `docs/implementation/documentation-refactor-inventory.csv`

**Interfaces:**

- Consumes: `InventoryRow` schema and review roots from this plan.
- Produces: exact candidate coverage plus safe, reviewable dispositions for the
  later historical-move and current-hierarchy plans.

- [ ] **Step 1: Write failing inventory parser tests**

Freeze this exact CSV header:

```csv
source_path,current_path,target_path,document_class,disposition,batch,reason
```

Add tests for one valid row of every disposition and rejection of a wrong
header, blank cell where prohibited, CRLF, duplicate source/current/target
paths, unsorted source paths, absolute paths, `.`/`..`, backslashes, missing
tracked candidate, unexpected row, nonexistent current path, and invalid
class/disposition/prefix combinations.

Allowed values are exact:

```python
DOCUMENT_CLASSES = {
    "decision", "design-history", "implementation", "research", "validation"
}
DISPOSITIONS = {
    "keep-current", "relocate-current", "archive-ready",
    "extract-current-first", "migrate-consumers-first", "archived"
}
BATCHES = {
    "retain", "archive-plans", "archive-research", "archive-decisions",
    "current-hierarchy", "consolidation"
}
```

- [ ] **Step 2: Run the new inventory tests and observe failure**

Run:

```bash
python3 tools/test-documentation-archive.py -v
```

Expected: FAIL because the inventory interfaces are not implemented.

- [ ] **Step 3: Implement strict CSV parsing and path invariants**

Use `csv.DictReader(io.StringIO(text, newline=""), strict=True)`. Reject a UTF-8
BOM, NUL, CR, non-canonical header, extra columns, empty reason, whitespace
padding, and non-POSIX repository-relative paths. Preserve commas in quoted
reasons, but require `csv.writer(..., lineterminator="\n")` round-tripping to
reproduce the exact input bytes.

Enforce these state rules:

| Disposition | `current_path` | `target_path` |
|---|---|---|
| `keep-current` | equals existing `source_path` below `docs/` | empty |
| `relocate-current` | equals existing `source_path` below `docs/` | canonical `docs/` path |
| `archive-ready` | equals existing `source_path` below `docs/` | class-compatible `archive/` path |
| `extract-current-first` | equals existing `source_path` below `docs/` | class-compatible `archive/` path |
| `migrate-consumers-first` | equals existing `source_path` below `docs/` | class-compatible `archive/` path |
| `archived` | existing class-compatible `archive/` path | empty |

Class-compatible archive prefixes are
`archive/research/{proposals,evaluations}/` for `research`,
`archive/design-history/{plans,superseded-specs}/` for `design-history`, and
`archive/design-history/retired-decisions/` for `decision`. `implementation`
and `validation` may only remain or relocate within `docs/`.

- [ ] **Step 4: Implement exact tracked-candidate coverage**

`tracked_candidate_paths` covers both the original current roots and their
eventual archive roots, then runs one command without a shell:

```python
REVIEW_ROOTS = (
    "docs/superpowers/plans",
    "docs/superpowers/specs",
    "docs/proposals",
    "docs/evaluations",
    "docs/decisions",
    "archive/research/proposals",
    "archive/research/evaluations",
    "archive/design-history/plans",
    "archive/design-history/superseded-specs",
    "archive/design-history/retired-decisions",
)
subprocess.run(
    ["git", "-C", str(repository_root), "ls-files", "-z", "--", *REVIEW_ROOTS],
    check=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
```

Decode strict UTF-8, reject command failure and non-regular tracked entries,
and sort by UTF-8 bytes. `validate_inventory` requires the `current_path` set to
equal this result exactly. It also requires unique stable `source_path` values,
every `current_path` to exist, every future target to be unique and absent, and
every `archived` current path to be covered by the manifest.

- [ ] **Step 5: Produce the candidate path list for review**

Run:

```bash
git ls-files -- docs/superpowers/plans docs/superpowers/specs docs/proposals docs/evaluations docs/decisions
```

Expected: the list includes the documentation-refactor design and this plan;
save one bytewise-sorted CSV row for every output path using `apply_patch`.

- [ ] **Step 6: Classify every candidate without an unresolved state**

For each source, inspect its status/outcome and exact inbound consumers with:

```bash
rg -n -F "SOURCE_PATH" --glob '!docs/implementation/documentation-refactor-inventory.csv' .
git log --follow --oneline -- SOURCE_PATH
```

Apply these fail-closed decisions:

- keep this design and plan, the Event operation-ledger design and plan, and
  any other still-open capability work as `keep-current`;
- classify implemented specs/plans as `extract-current-first` until their
  durable constraints have a verified canonical current owner;
- classify proposal/evaluation history with live links, scripts, manifests,
  hashes, or evidence mappings as `migrate-consumers-first`;
- classify `docs/evaluations/0005/requirements-matrix.csv` as
  `relocate-current` to `docs/validation/requirements-matrix.csv` with class
  `validation`, batch `current-hierarchy`;
- classify another evaluation artifact as `relocate-current` only when a live
  checker, qualification workflow, or current evidence claim consumes it;
- keep active ADRs current; use `archive-ready` for a decision only when a
  later governing ADR explicitly retires it and no current authority depends
  on it; and
- use `archive-ready` only after the inbound-consumer search is empty outside
  the candidate itself and its inventory row.

Every reason must name the current authority, completion evidence, consumer,
or blocking extraction that justifies the disposition. Do not use generic
reasons such as "old", "done", or "historical".

- [ ] **Step 7: Run inventory and requirements validation**

Run:

```bash
python3 tools/test-documentation-archive.py -v
python3 tools/check-documentation-archive.py
python3 tools/check-implementation-requirements.py
```

Expected: all archive tests pass; the checker reports exact candidate-row and
manifested-file counts; requirements remain valid with `348 matrix IDs` and
`137 exact selected mappings`.

- [ ] **Step 8: Commit the reviewed inventory**

```bash
git add docs/implementation/documentation-refactor-inventory.csv tools/check-documentation-archive.py tools/test-documentation-archive.py
git commit -m "docs: inventory documentation archive candidates"
```

### Task 4: Integrate manifest and inventory checks into CI

**Files:**

- Modify: `tools/check-documentation-archive.py`
- Modify: `tools/test-documentation-archive.py`
- Modify: `mise.toml`

**Interfaces:**

- Consumes: validated manifest and candidate inventory from Tasks 2 and 3.
- Produces: a CLI limited to those two boundaries, a focused
  `documentation-archive` task, and default CI enforcement.

Navigation remains a human-reviewed information-architecture outcome.
Neither the checker nor CI parses or validates Markdown navigation documents.

- [ ] **Step 1: Write the CLI boundary regression**

Construct a temporary Git repository with a valid archive and an empty
canonical inventory, without root `README.md` or `docs/README.md`. Call
`main([])` and assert return code `0`, empty stderr, and exactly:

```text
documentation archive passed: 1 archive files, 0 candidate rows
```

This regression catches an accidental dependency on navigation documents.
Preserve every manifest and inventory regression, including stale-manifest
rejection and manifest-write failure injection.

- [ ] **Step 2: Observe the regression before removing the extra boundary**

Run:

```bash
python3 tools/test-documentation-archive.py DocumentationInventoryTests.test_cli_succeeds_without_navigation_readmes -v
```

Expected against a checker that still reads navigation: FAIL because the
root README is absent.

- [ ] **Step 3: Limit the CLI to manifest and inventory validation**

Remove navigation parsing, its dedicated helpers, and its parser test class.
The CLI validates in this order:

```text
manifest -> inventory
```

Success output is one line containing only the archive-file and candidate-row
counts. Do not change manifest hardening or inventory grammar, state, and
exact Git coverage.

- [ ] **Step 4: Run the complete focused suite**

Run:

```bash
python3 tools/test-documentation-archive.py -v
python3 tools/check-documentation-archive.py
```

Expected: all tests PASS and the live repository check exits `0`.

- [ ] **Step 5: Add focused and default `mise` integration**

Add these entries without reordering unrelated checks; preserve them when
already present:

```toml
[tasks.documentation-archive]
description = "Verify the frozen documentation archive and candidate inventory"
run = [
  "python3 tools/test-documentation-archive.py",
  "python3 tools/check-documentation-archive.py",
]
```

Insert the same two commands in `[tasks.check].run` immediately after
`python3 tools/check-implementation-requirements.py` so policy failures stop
the full check before expensive Rust compilation.

- [ ] **Step 6: Run focused integration and traceability checks**

Run:

```bash
mise run documentation-archive
python3 tools/check-implementation-requirements.py
git diff --check
```

Expected: all three commands exit `0`; requirement counts remain exactly 348
matrix IDs and 137 selected mappings.

- [ ] **Step 7: Commit CI enforcement**

```bash
git add mise.toml tools/check-documentation-archive.py tools/test-documentation-archive.py
git commit -m "ci: enforce documentation archive boundaries"
```

### Task 5: Verify the foundation as one reviewable increment

**Files:**

- Verify only: all files changed by Tasks 1-4

**Interfaces:**

- Consumes: the complete archive foundation.
- Produces: a clean branch whose next plan can perform the first `git mv`
  batch without redefining policy or tooling.

- [ ] **Step 1: Prove that no existing document moved**

Run:

```bash
git diff --diff-filter=DR --name-status 4ea7c6e..HEAD
```

Expected: no output. There are no deleted or renamed paths, so no existing
documentation moved during the foundation increment.

- [ ] **Step 2: Independently verify archive bytes**

Run:

```bash
sha256sum --check archive/MANIFEST.sha256
python3 tools/check-documentation-archive.py
```

Expected: all three policy files report `OK`; the checker passes manifest and
inventory validation.

- [ ] **Step 3: Run focused tests and requirements validation**

Run:

```bash
python3 tools/test-documentation-archive.py -v
python3 tools/check-implementation-requirements.py
git diff --check
```

Expected: tests pass, the requirements trace remains valid, and the diff has no
whitespace errors.

- [ ] **Step 4: Run the repository check**

Run:

```bash
mise run check
```

Expected: PASS. If the known secure-`/tmp` baseline recurs, record the exact
failed tests and output without weakening or skipping them; do not attribute a
pre-existing runner failure to this documentation-only change.

- [ ] **Step 5: Review the final history and status**

Run:

```bash
git status --short
git log --oneline 4ea7c6e..HEAD
```

Expected: clean status and four focused implementation commits after the design
checkpoint, plus this implementation-plan checkpoint. Do not push or create a
PR unless the user separately requests it.
