# SDK, FFI, local agent, observability, and assurance arm

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.

Status: **research arm complete; buy the generators, keep the contract small**

Authority: `data-mesh-requirements.md` only, SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.

## Outcome first

The developer-facing part of the stack should not be hand-written once per
language. Buy:

- **cbindgen 0.29.4** for C-header generation and deterministic drift checks;
- **UniFFI 0.32.0** for built-in Kotlin, Swift, Python, and Ruby generation;
- **tonic 0.14.6** as an optional local-agent runtime, isolated from the
  embedded core;
- **tracing 0.1.44** for typed internal diagnostics behind a redaction
  allowlist, with OpenTelemetry export in an optional operations adapter; and
- cargo-cyclonedx, cargo-deny, and cargo-audit as standard release gates.

The custom residue is the part generators cannot decide: one semantic
high-level API; opaque-handle ownership; error and cancellation semantics;
panic containment; callback/threading rules; ABI version/deprecation policy;
platform packaging; local-agent authorization; and integration/conformance
examples.

## Exact executable evidence

BVB-774 freezes all four exact source archives and their upstream locks.
cbindgen's 73-package lock and UniFFI's 116-package lock contain no git sources.
BVB-775 authorized exact checksum-locked tool acquisition after the first
offline build found one missing registry package; neither lock changed.

The `sdk-tools-003` run used exact release binaries:

- cbindgen SHA-256
  `eaa2bf3c0055102c81bab7661eac06c464a4c06057f2c980498e2493bf3acbae`;
- UniFFI bindgen SHA-256
  `dc518e2e54ecf0bb23ae568f1d6baf714d037401cb7b9a18dcc70a66d7c23cc3`.

The fixture named only the required high-level categories—publish, subscribe,
query/conflict annotations, and peer status—and exposed no crypto,
fragmentation, transport choice, or sync internals. cbindgen generated a
1,521-byte / 66-line C header and its own `--verify` drift check passed. UniFFI
generated Kotlin, Swift, Python, and Ruby wrappers plus the Swift FFI header and
module map. Their content manifest SHA-256 is
`ab33b358effe0e22000c26ffba427e9ec67cec2e87f47070b3b9cd578006fa3a`.
The language artifacts from the partially summarized `sdk-tools-002` run were
byte-identical to the complete `sdk-tools-003` run; only the earlier receipt
walker mishandled Kotlin's nested directory.

This proves generator feasibility, not usable SDKs. None of the generated
bindings was compiled or exercised on Android, iOS, Python, or Ruby, and the
fixture functions intentionally have no mesh implementation.

## Binding decision

UniFFI's exact frozen source says Kotlin, Swift, Python, and Ruby are built in.
Go, C#, Java, Node, and other generators named by upstream are separate
third-party projects and receive no credit from this freeze.

For the open `DM-7-07` choice, **Kotlin + Swift** is the leading MVP hypothesis
because Tier 2 explicitly includes mobile and one maintained generator owns
both. Python is the lowest-friction third built-in binding for test and mission
system integration. This is decision data, not a stakeholder decision; a
different platform priority can change the pair without changing the core API.

Use one versioned interface model to generate the chosen high-level bindings.
Do not independently design a C API, UDL API, protobuf API, and each language
wrapper. The C ABI needs a deliberately smaller stable surface if UniFFI's
generated ABI remains an implementation detail.

## Optional local agent

The exact tonic 0.14.6 source is MIT, non-yanked, Rust 1.88, and contains both a
custom connector path and Unix-domain-socket support. That is enough to retain
it as the leading local gRPC mechanism for `DM-7-09`/`DM-7-10`, not enough to
ship an agent. Its upstream lock has 149 packages, so it belongs behind an
optional process feature and must not inflate the default linked library.

The remaining agent work is requirement-specific: use local-only endpoints,
authenticate the calling OS identity, define ownership of the single durable
store, bound streaming and queues, preserve offline publish behavior, expose
the same high-level contract, and test restart/cancellation. Local TLS is not a
substitute for caller authorization.

## Observability and assurance

Buy tracing's structured spans/events, but expose only typed, pre-redacted
fields. Automatic argument capture can leak topic, scope, identity, key, or
payload metadata and must be prohibited at the boundary. Keep OpenTelemetry
export outside the deterministic core so disconnected operation never depends
on a collector.

The evaluation already exercises cargo-cyclonedx, cargo-deny, and cargo-audit.
Standardize those tools in the release pipeline for `DM-8-12`, `DM-8-13`, and
`DM-13-11`; an SBOM describes the chosen graph but does not prove runtime
correctness or license acceptability.

## Requirements boundary

This arm gives component-level feasibility toward `DM-7-02` through
`DM-7-10`, `DM-7-11` through `DM-7-15`, and the SBOM/inventory deliverables.
Every product cell remains partial until a real reference API, binding template,
two target-platform builds, packaging, examples, and the optional-agent decision
are validated.

It grants no credit for API behavior, stable ABI, language-runtime safety,
platform packaging, the under-one-day integration target, agent security or
resources, telemetry redaction enforcement, or production admission.

Evidence summary:
archived `summary.json`.

