# Bounded runtime-volume diagnostic candidate

**Instrumented diagnostic only; not qualification.**

This manual-only candidate observes one test against immutable historical source
`14d795390a84d425681d7d40ee4c0e1072be0fb9`. The original integration failure
`34861840402` and identical-tree exact-head success `34861860694` remain distinct.
No isolated result clears CI or diagnoses a cause by itself. No product source,
Cargo manifest, lockfile, oracle, workload, or stock CI file is changed by this
proposal. The telemetry patch applies only inside the disposable job checkout.

## Review and dispatch gates

1. Independently review the exact candidate patch and file manifest. Local
   Python/static checks do **not** establish Rust compilation or runtime success.
2. Obtain/retain accountable approval for the existing CI source routes and the
   exact historical diagnostic graph. Enter its SHA-256 as
   `source_admission_receipt_sha256`. A syntactically valid hash is an operator
   attestation, **not machine verification of approval**. Do not invent a receipt.
   Namespace screening or public availability alone is not admission. The owner
   must separately approve the new local-mirror installer procedure and supply
   `reviewed_rustup_sha256` for the **existing runner rustup 1.28.2 executable**.
   This exact executable pin is not the source-admission receipt hash. If that
   version/byte identity is unavailable on the selected runner, stop: this
   candidate neither downloads another installer nor permits another version.
3. GitHub requires this new `workflow_dispatch` file on the default branch
   (`main`) before it can be dispatched. Proposal route: a separate reviewed PR,
   followed by an **explicit parent/owner decision** about default-branch
   registration. This proposal grants no merge authority. Do not add automatic
   triggers or repurpose existing CI to bypass the prerequisite.
4. Only after those gates and publication authorization, select the exact reviewed
   immutable workflow commit and supply the matching `reviewed_candidate_sha`.
   Confirm the single diagnostic. Attempts greater than one are refused.
   The parent must track the one authorized dispatch across distinct run IDs:
   the workflow cannot enforce a cross-run ledger with contents-read permission.
5. Stop after the one run, retain evidence and review it. No retries, failed-CI
   reruns, product repairs, timeout increases, package changes or release claims.

## Execution contract

- Ubuntu 24.04 x86_64 hosted runner; isolated job-owned Rust/Cargo directories.
- Existing checkout/upload action commits; contents-read only and no persisted
  checkout credentials. No new setup action, external service or dependency.
- Rust 1.97.1 installed only through `installer.py`'s verified-input mirror
  (procedure below; owner admission still pending). Reuse current CI's
  pinned cargo-deny 0.20.2 / cargo-audit 0.22.2, registry route, exception-scope,
  patch-boundary and advisory gates. No new advisory exceptions. A fresh advisory
  failure on the historical lock stops preparation, not a reason to change it.
- All-features **workspace** no-run build: 1200 seconds separately bounded.
  Compilation stdout is Cargo JSON; select exactly one `aster_lab` library test
  artifact by target kind, test profile and manifest path. No guessed executable.
- One direct exact test invocation, with `--exact --nocapture`, through the
  unchanged `tools/with-test-resources.sh`; external 400-second deadline plus
  a separate 10-second TERM/KILL/reap budget. Only bounded capture operations
  run before termination; parsing/hash/receipt work follows group cleanup. These
  are process-control deadlines, not a host-scheduling or blocked-filesystem
  wall-clock guarantee. Original current-thread Tokio 300 seconds,
  select branches, 1 ms timer, concurrency and all test oracles remain unchanged.
- Actual command exit, timeout and process-group absence are retained separately.
  A zero-test harness, absent final telemetry, timeout, cancellation, capture
  overflow/incomplete drain, invalid telemetry, receipt error or uncertain
  cleanup fails. Handled SIGTERM/SIGINT/SIGHUP latch during spawn, registration
  and cleanup, including repeated signals; they cannot interrupt reaping. Owned
  runtime state is retained whenever group absence is unconfirmed.
  No `continue-on-error`; upload uses `always()` without masking failure.
- Raw compiler/test output and scratch databases stay private to the job, outside
  the upload path. Only fixed-format allowlisted numeric telemetry, test-count
  summaries and bounded provenance JSON are retained for seven days. Cancellation
  or runner loss can prevent upload; no workflow can guarantee artifact delivery
  after host loss. The workflow never uploads credentials, payloads or full env.

## Telemetry dictionary and observation limits

`counters` is a fixed 22-value array:

| Indices | Meaning |
| --- | --- |
| 0–4 | A→C: runtime accepted, provider submitted, sent, peer received, runtime consumed |
| 5–9 | C→A: runtime accepted, provider submitted, sent, peer received, runtime consumed |
| 10–11 | A/C runtime-to-provider queue occupancy |
| 12–13 | A/C provider submission credit: 1024 minus submitted−sent |
| 14–15 | A/C outbound queue high-water |
| 16–17 | A/C full-queue backpressure count |
| 18–19 | A/C opened stream count |
| 20–21 | A/C selected stream role: 1 outbound, 0 inbound (not key/peer material) |

The provider-to-runtime backlog is received minus consumed at each destination;
accepted minus submitted is the runtime-to-provider boundary gap. Neither raw
frames nor a backlog estimate proves unique-item progress or packet loss.
`durable` contains C-first/C-second at A, then A-first/A-second at C. Values:
0 not sampled, 1 absent, 2 present, 3 query error. Observational queries discard
error text and do not introduce earlier error propagation. They run only at the
existing 10-second progress point; the original short-circuited completion
predicate is unchanged. On predicate completion all four are recorded present
because that exact original predicate has just succeeded.

`costs` has five [count, sum_ns, max_ns] rows: A drive, C drive, A flush,
C flush and combined select/service wait. Select cost includes waiting, chosen
handler execution and timer branches; it is **not per-adapter CPU attribution**.
`outer_ms` includes setup, the original timeout and final cleanup; subtract
`loop_started_ms` only after the volume phase begins. Phase records delimit
prepare/supervisor/adapter/listen/connect/contact/activation/volume/oracle/cleanup
milestones. `sampled_ms` and `durable_sampled_ms` explicitly expose stale samples.
Counters are refreshed at loop boundaries, not synchronously on every frame.

An outer RAII guard emits last-known state on ordinary success/error, cooperative
Tokio timeout and unwind. On synchronous stalls/forced termination, that guard may
not run: the supervising process retains last-known counters and process
CPU/RSS/I/O sampled during execution. Parsing and receipt creation happen only
after termination; the resource sample remains last-known, not a new pre-kill
measurement. Unknown/stale state is never relabeled as
fresh. At most 64 regular diagnostic snapshots plus one final snapshot, bounded
observation-cost records and 160 sanitized output records are retained. /proc
samples are five-second, finite-budget process snapshots, not full-runner load.

Each combined stdout/stderr capture is limited to **16 MiB**, read through a
nonblocking pipe in at-most-64-KiB turns, with bounded draining during cleanup.
Only captured bytes are hashed and written privately after termination. Parsing
is incremental over that bounded capture: **64 KiB per line**, **20 digits per
telemetry numeric token**, and **160 retained telemetry records**, including an
explicit failure marker if the record budget is exceeded. Raw/Cargo overflow is
never accepted as successful truncation, even if a matching artifact appears
earlier. These are conservative diagnostic budgets, not claims that every
compiler output will fit. No full-log splitlines or uncapped raw-file read is
used. Receipt-write failure can prevent the receipt itself; it cannot prevent
termination/reaping, and the returned controller result remains failure.

Observation changes timing: thread-local numeric snapshots occur twice per loop;
Instant reads surround four synchronous operations and one select; four read-only
durable queries and output occur at existing progress points. `observation_ns`
measures the additional periodic queries/output, not all per-loop bookkeeping.
There is no claim of zero overhead or equivalence to the original CI binary.

## Traceability

Bounded CI maintenance outside the product capability register. No atomic
requirement IDs, evidence credit, roadmap status, wire/API/storage contract,
production dependency graph or docs PR22 change. The exact 10,000 minimum **plus**
both five-boundary equalities, four durable items, 1 MiB×2 each direction, MTU128,
credit1024, authentication/contact/stream/backpressure/resource assertions and
original timeout are preserved byte-for-byte after stripping marked additions.


## Exact installer-input binding (R4 correction; owner-pending)

`installer.py` first checks the original 1.97.1 TOML against the literal manifest
SHA-256. It compares all three target component records with the reviewed JSON,
refuses unsupported component/compression shapes, and downloads only their
pinned `.tar.xz` URLs. Each download has a byte cap, socket timeout and finite
read-loop deadline; redirects, alternate origins and retries are refused. No
component is executed or extracted by this Python preparation code.

The original manifest bytes (not rewritten TOML), a locally derived checksum
sidecar, and the three verified immutable archive byte buffers form an in-process
loopback HTTP allowlist. There is no filesystem lookup or upstream forwarding in
the server. Unknown paths, queries, ranges and excess requests fail closed. The
installer uses fresh isolated Rustup/Cargo homes; no old download/toolchain cache
can replace these inputs. Rustup's documented `RUSTUP_DIST_SERVER` local-mirror
interface redirects component URLs while preserving the official distribution
installation semantics. `--no-self-update`, a denied update root and zero
component retries prevent an implicit alternate installer path. Exact served
paths, installer exit/group cleanup and hashes are retained; every expected
manifest/archive path must be served and any denied request fails preparation.

Before any installer invocation, the existing runner executable is copied and
verified against `reviewed_rustup_sha256`; its observed version must be 1.28.2.
Later Cargo/rustc proxies are aliases of those verified installer bytes, not a
new downloaded executable. The accountable owner must approve both those bytes
and this procedure. A user-supplied digest is an attestation input, not proof of
approval. **No matching installer hash has been supplied or approved here.**
The procedure stops on an unavailable/mismatched installer; changing the version
requires another source review and candidate, not an automatic fallback.

The mirror stores at most three 256-MiB compressed archives plus a 2-MiB manifest
(and bounded copying overhead); actual 1.97.1 archives were not downloaded in
local verification. These are preparation memory limits, separate from the
16-MiB controller capture cap. Rustup remains the trusted, owner-admitted
installer: this is input binding, not a sandbox against a malicious approved
installer or a reproducible compiler-build claim.

Authoritative public references: Rustup [environment variables](https://rust-lang.github.io/rustup/environment-variables.html),
[profiles](https://rust-lang.github.io/rustup/concepts/profiles.html), and 1.28.2
[manifestation](https://github.com/rust-lang/rustup/blob/1.28.2/src/dist/manifestation.rs)
and [download](https://github.com/rust-lang/rustup/blob/1.28.2/src/dist/download.rs)
source (MIT/Apache-2.0). The minimal profile contains rustc, cargo and target std;
its global manifest list also names Windows-only rust-mingw, which is not a Linux
component. This candidate only admits x86_64-unknown-linux-gnu's three archives.

Local verification uses harmless Python children, real POSIX signals and tiny
synthetic integrity/local-HTTP fixtures. It does **not** exercise Rustup, compile
Rust, install policy tools, or establish hosted-workflow compatibility. Independent
review, accountable admission, default-branch registration/publication decisions
and supported compilation remain separate pending gates. The instrumented Rust
patch and all workload/oracle/300-second scheduling-source bytes are unchanged.

## Resource log

| Resource | Version / identity | Public source and admission basis |
| --- | --- | --- |
| Aster baseline | immutable source SHA above; SHA-256s in manifest.json | https://github.com/edgesoftops/astertech ; approved Clean Team source, Apache-2.0 |
| checkout | v7.0.1, `3d3c42e5aac5ba805825da76410c181273ba90b1` | https://github.com/actions/checkout ; MIT, existing current CI pin |
| upload-artifact | v4.6.2, `ea165f8d65b6e75b540449e92b4886f43607fa02` | https://github.com/actions/upload-artifact ; MIT, existing manual build pin |
| Rust/cargo/std | 1.97.1, exact distribution hashes in rust-distribution.json | https://static.rust-lang.org/dist/channel-rust-1.97.1.toml ; Rust distribution license inventory, typically MIT/Apache-2.0 plus component notices; existing CI route, not a new blanket license admission |
| Existing runner rustup | 1.28.2 plus owner-supplied exact executable SHA-256; pending | https://github.com/rust-lang/rustup/tree/1.28.2 ; MIT/Apache-2.0; no installer download, new binding procedure requires accountable admission |
| cargo-deny | 0.20.2, installed binary hash retained at runtime | https://crates.io/crates/cargo-deny/0.20.2 ; MIT/Apache-2.0, current CI pin |
| cargo-audit | 0.22.2, installed binary hash retained at runtime | https://crates.io/crates/cargo-audit/0.22.2 ; MIT/Apache-2.0, current CI pin |
| RustSec advisory data | refreshed snapshot used by existing CI gates | https://github.com/RustSec/advisory-db ; existing policy source, not frozen historical safety |
| Cargo graph | exact original Cargo.lock, each name/version/source/checksum in runtime resources.json | https://crates.io ; current deny.toml source/license policy plus narrowly preserved exceptions and fresh audits, not full release admission |
| Runner Python | existing Ubuntu runner Python, actual version in provenance | https://www.python.org ; PSF, stdlib-only controller, no pip/install |
| Ubuntu/Bash/Git/curl/coreutils | existing ubuntu-24.04 runner; actual OS/arch retained | https://ubuntu.com ; existing CI platform/tooling, no apt or native host installation in this increment |

Published distribution archive hashes are not installed-binary authenticity or
reproducible-build evidence. Current policy and accountable source designation
remain prerequisites even when these resources are public or already used by CI.
