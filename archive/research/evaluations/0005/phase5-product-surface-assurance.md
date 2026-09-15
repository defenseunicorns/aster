# Phase 5 product surface, assurance, and physical-carrier arm

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

>
> Requirements-first research evidence only. `data-mesh-requirements.md` is
> the sole architecture authority. Proposal 0005 is only the work order.
> Current product implementation and architecture received zero weight and
> were not inspected. Proposal 0004 was not consulted. Bracketed values are
> curves, not candidate-elimination thresholds.

Status: **arm complete; material failures found; no component admitted**

## Outcome first

The Phase 5 work closes the executable research that this host can support and
leaves four clear decisions:

1. **Keep every surviving architecture class in the carrier comparison.** The
   exact A-, G-, and conditional B1-class byte fixtures all compose through the
   same compact/wide carrier envelope across 20 through 1,500-byte MTUs. This
   says a carrier boundary can remain architecture-neutral; it does not select
   or validate any architecture.
2. **Do not claim BTLE.** Swift and Objective-C CoreBluetooth adapters both
   compiled and executed, but the host independently reported central and
   peripheral state `unsupported`. No Bluetooth controller, second radio,
   discovery, GATT exchange, packet capture, energy, or RF curve existed.
   Physical BTLE is **environment-blocked** and the acceptance scenarios remain
   **untested**.
3. **Fix the specification before expanding the implementation.** A genuinely
   independently written parser agrees with the frozen Rust outcome on only
   13/18 vectors. Every positive vector depends on critical extension ID 1,
   while neither the frozen CDDL nor prose defines ID 1 as known. The reference
   and vectors therefore contain behavior unavailable to a spec-built
   implementation. This fails the independent-interoperability gate by design,
   and is exactly the kind of defect that a second implementation is meant to
   expose.
4. **Buy the product-surface tooling but keep the contract small.** The frozen
   generator and assurance stack builds a zero-dependency cdylib, C smoke
   executable, Swift/Python/Ruby bindings, package, and CycloneDX document.
   Cargo-deny then correctly rejects the fixture because it has no declared
   license. That failure must be fixed at the package source, not waived.
   Kotlin is environment-blocked and the local agent cannot execute because
   this executor denies Unix-socket binding in both temporary and workspace
   paths.

Delete-first consequence: do not create one fragmentation, repair, resume,
binding, or conformance stack per architecture. Keep one protocol authority,
one carrier envelope, one generated product surface, and one release gate. The
custom residue is the requirements-specific semantics that a tool cannot
decide.

## Disposition vocabulary

This report uses four gate dispositions deliberately:

| Disposition | Meaning |
|---|---|
| **pass** | The exact bounded evaluation gate completed as specified. Product requirement credit may still be partial or decision data. |
| **fail** | The gate executed and found a substantive mismatch or policy violation. |
| **environment-blocked** | The strongest safe host attempt could not exist here; no pass credit is assigned. |
| **untested** | No executable evidence was produced for that behavior. |

The full cell-by-cell distinction, including requirement-credit boundaries, is
in
[`requirements-map.csv`](../../../../docs/evaluations/0005/requirement-maps/product-assurance.csv).

## Exact scope and final receipt

The final registered run is `phase5-005`, authorized by BVB-837 after the prior
failed trials were preserved. The host was macOS 26.5.2 build 25F84 on arm64.
The final driver executed 34 gates: 30 exited zero, one discovery-process probe
returned absence, Kotlin was unavailable, the local-agent bind was denied, and
cargo-deny rejected the missing license.

The final receipt manifest verifies completely. Its SHA-256 is
`f5873416805733ec766d2e885cd351099c296e0147447bb02c0d352b77f83ab7`.
The exact authority, source, fixture, binary, and result identities are in
archived `source-freeze.tsv`.

No network access, new dependency resolution, product files, or unregistered
source consultation occurred. Raw source copies, module caches, builds, failed
trials, and receipts remain locally preserved under ignored run directories.

## Physical carrier preflight

The hardware/host preflight found:

- an empty Bluetooth `system_profiler` object;
- no `IOBluetoothHostControllerUSBTransport` entry;
- no USB device entry in the exposed host view; and
- no visible `bluetoothd` process.

The Swift adapter then compiled to a 148,592-byte executable with SHA-256
`071d687f34805701faeb6703b9b8d1b7dd403f9caca74a4e62eae225ffda70d9`.
During an 8-second run it received both manager callbacks, and both states were
`unsupported`. It never attempted service creation, advertising, or scanning.

The separately authored Objective-C adapter compiled with warnings denied to a
59,680-byte executable with SHA-256
`88a8a932ff3b8017784c138d26168e55d7c8df138b917e6d5b2d6d57740a8c43`.
Its independent 8-second run produced the same result: central and peripheral
callbacks arrived, both states were `unsupported`, and no scan, advertisement,
or discovery occurred.

This is the strongest host-platform evidence available here:

| Gate | Disposition | Credit |
|---|---|---|
| Swift CoreBluetooth compile and callback path | **pass** | Host API and adapter source compile/run only |
| Objective-C CoreBluetooth compile and callback path | **pass** | Independent host API confirmation only |
| Exposed Bluetooth controller | **environment-blocked** | None; both APIs report unsupported |
| Second physical radio and peer discovery | **environment-blocked** | None |
| GATT application-byte exchange | **untested** | None |
| Broadcast RF behavior and tiny-MTU throughput | **untested** | None |
| Android and Windows target adapters | **untested** | None |
| Background/suspend, screen-off, wakeup, and energy | **untested** | None |

Compilation is not physical evidence. Simulation below is kept separate and
receives no BTLE, RF, or platform acceptance credit.

## Faithful architecture-neutral carrier composition

The exact registered carrier control framed each exact architecture fixture in
two evaluation layouts over nine MTUs. For every one of the 54 rows, reverse
delivery reconstructed identical bytes, duplicate frames were idempotent, and
file records at 1-, 7-, and 64-byte read sizes parsed back to the same frames.

| Architecture class | Exact fixture | Compact at MTU 20 | Wide at MTU 20 | Compact at MTU 1,500 |
|---|---:|---:|---:|---:|
| A — p2panda-centered | 259 B | 24 frames / 475 B / 45.5% header | 37 / 740 B / 65.0% | 1 / 268 B / 3.4% |
| G — explicit components | 158 B | 15 / 293 B / 46.1% | 23 / 457 B / 65.4% | 1 / 167 B / 5.4% |
| B1 — conditional BPv7 | 189 B | 18 / 351 B / 46.2% | 27 / 540 B / 65.0% | 1 / 198 B / 4.5% |

This passes the bounded composition gate and strongly favors a compact
tiny-MTU profile. It does **not** establish that either evaluation header is
practical once security, discovery, feedback, and lower-layer overhead are
included. No framing format is selected.

The formula-only size sweep extended payloads from 16 bytes through 100 MiB.
At a 20-byte MTU, compact framing asymptotically used 1.818 wire bytes per
payload byte while wide framing used 2.857. At a 1,500-byte MTU, the 100 MiB
ratios were 1.006 and 1.009. These are arithmetic bounds, not allocations or
whole-stack measurements.

## Broadcast repair curve

The evaluator explicitly counted data, feedback, and completion bytes for
unicast, unsuppressed broadcast feedback, and feedback-suppressed broadcast.
It covered independent and four-frame burst loss, payloads of 471, 4,096, and
65,536 bytes, MTUs 20/64/247, receiver slices 2/8/32, and loss through 70%.
An adaptive point at 20% burst loss was inserted when suppressed-broadcast
amplification crossed 3× between the frozen 10% and 30% points.

Representative 4 KiB, MTU-64, eight-receiver independent-loss results are:

| Loss | Strategy | Complete | Total bytes | Wire / payload | Rounds |
|---:|---|:---:|---:|---:|---:|
| 0% | suppressed broadcast | yes | 4,803 | 1.173 | 1 |
| 0% | unsuppressed broadcast | yes | 4,803 | 1.173 | 1 |
| 0% | per-peer unicast | yes | 38,200 | 9.326 | 1 |
| 30% | suppressed broadcast | yes | 13,739 | 3.354 | 8 |
| 30% | unsuppressed broadcast | yes | 13,785 | 3.365 | 7 |
| 30% | per-peer unicast | yes | 55,642 | 13.584 | 6 |
| 50% | suppressed broadcast | yes | 21,329 | 5.207 | 8 |
| 50% | unsuppressed broadcast | yes | 22,932 | 5.599 | 10 |
| 50% | per-peer unicast | yes | 78,829 | 19.245 | 13 |
| 70% | suppressed broadcast | yes | 40,212 | 9.817 | 19 |
| 70% | unsuppressed broadcast | **no** | 46,837 | 11.435 | 32 |
| 70% | per-peer unicast | yes | 122,689 | 29.953 | 16 |

One-to-many repair is materially smaller in this control, but suppression is
not merely an optimization at the severe endpoint: unsuppressed feedback did
not finish within the bound for the 4 KiB cell above or the matching 64 KiB
cell. In total, 115/117 cells completed. The two failures were both
unsuppressed, 70%-loss, MTU-64, eight-receiver cells, at 4 KiB and 64 KiB.

The result supports **retaining** feedback suppression and broadcast repair as
a physical-test hypothesis. It does not select Trickle parameters, ARQ, NACK
ranges, or FEC. The deterministic model omits RF capture effects, correlated
receivers, asymmetric feedback, RTT, scheduling, interference, encryption,
lower-layer retries, energy, and contact-window expiry.

## Rate, offline, priority, quota, and resource curves

The rate projection combines the suppressed-broadcast independent-loss cells
with decimal link rates 1, 3, 10, 30, and 100 kbps. It is serialization time
only. Selected 3 kbps endpoints show why the bracket must remain decision data:

| Protected payload | Modeled loss | Counted wire bytes | Projected serialization time |
|---:|---:|---:|---:|
| 471 B | 50% | 2,932 | 7.82 s |
| 471 B | 70% | 4,872 | 12.99 s |
| 4 KiB | 50% | 21,329 | 56.88 s |
| 4 KiB | 70% | 40,212 | 107.23 s |
| 64 KiB | 50% | 342,880 | 914.35 s |
| 64 KiB | 70% | 640,612 | 1,708.30 s |

Across all 75 rate rows, projected serialization time ranged from 0.04672 to
5,124.896 seconds. “Useful” therefore depends on item size, priority, contact
window, and alternative carriers; 3 kbps or 50% loss cannot be a universal
binary exclusion rule.

The other provisional curves are intentionally policy arithmetic:

- offline days: 1, 7, 14, 30, 60, 90;
- durable-retention windows: 14, 30, 60, 90 days;
- TTLs: 1, 14, 30, 60, 90 days;
- retained membership-generation caps: 2, 8, 32 against generation distances
  0, 1, 4, 16, 64;
- priority-level counts: 3, 4, 5, 7; and
- logical storage quotas: 8 KiB, 32 KiB, 128 KiB, 1 MiB.

All 16 priority/quota controls stayed within their logical quota and evicted
lowest priority first. This is not proof of physical storage bounds; manifests,
indexes, temporary files, incomplete work, orphan work, and filesystem reserve
remain outside the counter. Likewise, the offline cells do not represent a
node that actually slept for days or resynchronized.

The Python sweep process rose from 26,755,072 to 28,508,160 bytes maximum RSS.
That is a harness resource point only. The imported registered Blob curve keeps
its prior result: split redb metadata plus files stayed near 3.4–5.3 MiB resume
RSS through 256 MiB, while storing complete Blob bytes in redb scaled to
hundreds of MiB. This run did not re-execute or broaden that registered Blob
evidence.

## Independent parser and conformance oracle

The Python parser was implemented from the frozen `profile-v0.cddl` and prose
without consulting the Rust runner source. It is dependency-free and has its
own deterministic-CBOR reader. Its result is more valuable than another Rust
decoder inside the reference evaluator because it applies the written profile
as an independent implementer would.

The frozen Rust binary replayed all 18 vectors exactly: five accepted and 13
rejected. The independent parser agreed on every negative vector and rejected
all five positives, producing **13/18 agreement**.

The mismatch is specification-defined:

- the CDDL says an extension is `uint => [critical, bytes]`;
- the prose defines unknown noncritical ID 99 as accepted and critical ID 99 as
  rejected;
- neither artifact contains a registry or semantics for a known critical ID;
  yet
- every positive vector includes critical ID 1, which the Rust implementation
  treats as known.

An independent implementation has no normative basis for accepting ID 1. The
correct remedy is to define the registry, critical behavior, canonical bytes,
and version ownership in the protocol specification—or delete ID 1 from the
base profile and vectors. Teaching the Python oracle the reference's hidden
constant would invalidate the independence gate.

The same oracle passed all 17 hostile boundary cases:

- 64 parents accepted and 65 rejected;
- 32 extensions accepted and 33 rejected;
- 4,096-byte extension value accepted and 4,097 rejected;
- 65,536-byte protected object accepted and 65,537 rejected;
- 128 KiB input cap, definite-length containers, canonical integers, ordered
  keys, no trailing data, valid UTF-8, and bounded tokens enforced.

Across 518 deterministic mutations it raised zero unexpected exceptions. In
the final run, the largest single hostile parse was 7,083 ns and the 1-byte
through 64 KiB protected-object medians were roughly 5.7–6.5 microseconds,
with process RSS plateauing near 28.36 MB. These timings are host-specific and
apply only to this Python control.

Nine independently modeled mixed-version cases also passed: highest common
version selection, empty intersection, gaps, duplicate/unsorted rejection, and
an offer-count bound. This is **decision data**, not DM-10-02 completion. There
is no negotiation wire, downgrade binding, reference implementation behavior,
or second mesh implementation.

## SDK, packaging, SBOM, and observability

The final packaging result is intentionally mixed:

| Gate | Disposition | Exact result |
|---|---|---|
| Zero-dependency Rust release build | **pass** | 17,008-byte cdylib; SHA-256 `af5ac371f485030dde73252ce86df239cfbe9d125d05f0cc883c8b7365401aca` |
| Strict C17 ABI smoke | **pass** | version/context/error statuses matched; zero failures |
| Swift generated binding typecheck | **pass** | Host compiler accepted frozen UniFFI output |
| Python generated binding syntax | **pass** | Bytecode compile succeeded in isolated cache |
| Ruby generated binding syntax | **pass** | Syntax check succeeded |
| Kotlin generated binding compile | **environment-blocked** | `kotlinc` unavailable |
| Cargo package | **pass with warning** | 5 files; 4.2 KiB raw; 1,712 B compressed; no license/description metadata |
| CycloneDX 1.5 generation | **pass structure / fail inventory** | Valid JSON, but no license expression exists to inventory |
| cargo-deny bans and sources | **pass** | Exact zero-dependency fixture |
| cargo-deny licenses | **fail** | Root crate is unlicensed |
| cargo-audit no-fetch | **pass with dated boundary** | Loaded 1,225 cached advisories and scanned one root crate; no external dependencies |

The package SHA-256 is
`45f0361dc7777bf0d934953277dc2acc74c0b7e6df84b77b493c299f63e68c5b`.
The CycloneDX receipt SHA-256 is
`c80b97d895c809fb4540484403ce38cd76698b3932dcaebdddcf59a8245a864e`.

The missing license is a real release-gate failure. A syntactically valid SBOM
does not satisfy the license inventory when the package source omits the
license. The fix is to choose and declare the package license, regenerate the
SBOM, and rerun policy—not to suppress cargo-deny.

The optional local-agent control attempted a mode-0600 Unix socket, same-UID
peer authorization, fsync-before-ack publishing, restart recovery, interrupted
and oversized request rejection, bounded queues, and an observability
allowlist. It received no runtime credit because the server could not bind:

1. the first trial exposed an overlong macOS Unix path and was corrected;
2. `/tmp/p5-agent-…sock` then failed `bind` with `EPERM`; and
3. a short endpoint inside the writable project workspace also failed
   `bind` with `EPERM`.

After two independently writable locations produced the same host denial, the
gate is final **environment-blocked**. Restart, wrong-UID rejection, durable
publish, redaction, CPU/idle, and cancellation are **untested**. Static source
shape receives no runtime pass.

## Buy, build, delete

| Responsibility | Decision | Rationale |
|---|---|---|
| C header generation | **Buy cbindgen** | Frozen deterministic generator and drift mechanism; no value in handwritten duplicate headers |
| Kotlin/Swift/Python/Ruby wrappers | **Buy UniFFI** | One frozen interface model feeds several targets; three host-static gates now pass |
| Optional local gRPC runtime | **Retain tonic conditionally** | Prior registered source supports the role; caller authorization, restart, resources, and platform packaging remain unproved |
| Structured diagnostics | **Buy tracing conditionally** | Use typed pre-redacted fields; keep export outside the deterministic core |
| SBOM/license/advisory gates | **Buy cargo-cyclonedx, cargo-deny, cargo-audit** | This run demonstrates that the tools catch a real missing-license defect |
| BTLE platform access | **Use native OS APIs behind one adapter boundary** | Platform APIs are necessary surfaces, not FOSS admissions; physical multi-host tests remain mandatory |
| Architecture-specific carrier framing | **Delete** | One opaque-byte envelope composed with every surviving class |
| Per-peer unicast on broadcast media | **Delete as default** | One-to-many repair is materially smaller in the control; retain explicit fallback only |
| Hidden critical extension behavior | **Delete or specify** | Reference-only knowledge violates spec authority and independent interoperability |
| Handwritten wrappers per language | **Delete** | Generator output is feasible; custom code belongs only at semantic/platform seams |
| Normative version/extension/security profile | **Build or find a standards-backed owner** | No frozen tool can decide protocol semantics; must become the authority before implementation expands |
| Stable C ABI and high-level semantic API | **Build minimally** | Ownership, errors, cancellation, callbacks, panic containment, and deprecation remain requirements-specific |
| Broadcast repair policy | **Build only after physical curves** | Current model advances suppression as a hypothesis, not a selected algorithm |
| Local-agent authorization/store ownership | **Build minimally around bought runtime** | gRPC does not supply OS caller authorization or single-store lifecycle |

The product-surface stack should therefore be smaller than the earlier
handwritten instinct: generator + thin semantic seam + platform package, not a
parallel SDK implementation for every language.

## Requirement outcome highlights

- `DM-5.8-03`/`04`: **pass in the carrier control, partial requirement credit**.
  Exact fixtures reassemble across 20–1,500-byte MTUs; real carriers and
  security overhead remain.
- `DM-5.8-05`: **decision data only**. Compact is much better than wide at tiny
  MTU, but no practicality criterion exists.
- `DM-5.8-11`, `DM-13-05`, and `DM-12-01`:
  **environment-blocked or untested**, never pass.
- `DM-5.6-04`: **partial**. One-to-many repair is substantially smaller in the
  deterministic control; two unsuppressed severe-loss cells fail the bound.
- `DM-8-17` through `DM-8-19` and `DM-12-11`: **fail**. The independent parser
  exposes hidden reference semantics.
- `DM-10-02`: **isolated decision data**. Nine oracle cases are not mixed-mesh
  interoperation.
- `DM-8-12`: **partial pass** for SBOM generation; `DM-8-13` and the inventory
  half of `DM-13-11` **fail** because the package is unlicensed.
- `DM-7-09`/`10`: **environment-blocked** on this executor; runtime semantics
  remain untested.
- `DM-9-19`/`20`: **decision data**. Link-rate and loss values are curves, not
  hard elimination gates.

## Remaining release gates

The next product-bearing phase should not add more architecture breadth. It
should close these exact gaps:

1. publish a normative versioned profile with a complete extension registry,
   security binding, error behavior, limits, and deprecation policy; then have
   a fresh independent implementation reach full positive and hostile-vector
   agreement without consulting reference source;
2. run two physical BTLE devices through discovery, mutual authentication,
   GATT framing, disconnect/resume, background/suspend, screen-off, packet
   capture, energy, and tiny-MTU curves; then move the same durable item over
   IP without changing protocol state;
3. run broadcast suppression, unsuppressed feedback, unicast, range repair,
   and optional FEC on real broadcast-capable links under correlated/asymmetric
   loss and bounded contacts;
4. select the two MVP binding targets, build on their real SDK/toolchains,
   package and execute publish/subscribe/query, and measure the integration
   example rather than only typechecking generated wrappers;
5. declare all package and dependency licenses, regenerate the full product
   CycloneDX inventory, and make cargo-deny/audit policy non-optional;
6. execute the optional local agent in an environment that permits local IPC,
   including wrong-UID rejection, restart, fsync-before-ack, bounded queues,
   cancellation, redaction, idle CPU, and mobile packaging; and
7. replace arithmetic offline, quota, rate, and resource controls with the
   selected stack while preserving the current curve axes instead of treating
   30 days, 3 kbps, or 50% loss as binary gates.

## Receipt history

Failed trials remain evidence rather than being overwritten:

- `phase5-001`: provisional receipt manifest SHA-256
  `01be31b3a65b6af13eee78538c919df9c8c37469a003a5517827a136c362107d`;
  it exposed module-cache, Unix-path, and tool-home issues.
- `phase5-002`: intentionally incomplete, exit 130, no manifest; the initial
  Swift run-loop lifecycle failed to terminate and receives no credit.
- `phase5-003`: manifest SHA-256
  `e32827150ff6929566990b7f4a64eb171e78a7068af7ff4aeef6a6499785702b`;
  it bound the native adapters and exposed remaining IPC/tooling behavior.
- `phase5-004`: manifest SHA-256
  `83632408c4f92838cdcf8126bd9ccf7b0e95389af0bc057805a3f915d4948500`;
  it proved `/tmp` bind denial and the substantive license failure.
- `phase5-005`: final manifest SHA-256
  `f5873416805733ec766d2e885cd351099c296e0147447bb02c0d352b77f83ab7`;
  it proved the second socket denial and closes the host execution frontier.

The reviewable machine-readable summary is
archived `summary.json`.
