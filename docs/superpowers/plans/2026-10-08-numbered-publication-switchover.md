# Numbered-only Event publication switchover

> Clean Room — Privileged

- Baseline: refreshed `origin/main` at `23be27e`
- Branch: `feature/numbered-publication-switchover`
- Outcome: one numbered application-publication model, retaining native HTTP/2
  pipelining, shared durable commits, bounded retry/backpressure, finite Event
  custody, and the current semantic-v7 source/transfer behavior.
- Alignment: P1-1 bounded data lifecycle and P1 offline-first Event exchange.
- Status: complete; final repository verification passed. Application RPCs and normal native APIs expose only numbered
  publication. CLI, playground, demos, examples, Go acceptance producers,
  deployment tools and lab producers retain complete publication journals.
  Historical fixture writers are explicitly unavailable in normal node builds.

## Current baseline and scope

PR #54 merged ordinary publication pipelining at `1a356b5`. PR #53 merged
semantic-v7 receipt-free Event pages and custody authority integration in the
current baseline. Subscription listing, unsubscribe, query upper-bound,
bounded custody maintenance, and send-authorization changes are also present.
The earlier ownership-plan branch belongs to old history and is not a merge
base for this work. Preserve current content and retained historical receipts.

This is completion of the publication-model transition before Increment 2.
It does not add session ownership to subscription/delivery mutations, client
retirement, lost-journal recovery, or identity reclamation. It does not change
State/Record/Blob operation models or mesh source identity, causality, content
cryptography, reconciliation version, or carrier semantics.

There are no released consumers requiring compatibility with ordinary
publication. Remove the supported arbitrary-key Event publication path instead
of retaining a shim that maps keys to sequences or to permanent client IDs.
The latter would reintroduce unbounded history or exhaust client capacity.
Reject incompatible legacy publication stores without deleting or silently
migrating their contents, and document fresh-state initialization.

## Capabilities to preserve

- Native HTTP/2 bidirectional publication with ordered per-input outcomes,
  bounded in-flight windows, disconnect retry, and healthy session rotation.
- Unary publication and browser concurrent-unary fallback, subject to ordered
  first admission within each numbered client.
- Actor collection of already-admitted adjacent compatible work, bounded
  fairness, no artificial batching delay, Flash singleton behavior, and
  finite/durable cohort separation.
- One writer commit for a successful compatible cohort; custody continuity,
  TTL result retirement, result records, source counters, and recovery frontier
  commit consistently. Count writer commits that occur before an error.
- Exact retry and conflict detection while a result is retained; permanent
  rejection after acknowledgement compacts it. Preserve
  `Committed + Retired(reason)` after content expires.
- Independent synchronization following local durable admission, shutdown and
  zeroization boundaries, current policy/revocation checks, response bounds,
  capacity accounting, and source-route cache maintenance.

## Numbered pipeline semantics

The SDK journals complete intents and assigned sequences before transmission
and durably records committed results before exposing them. Transport failure
never means abandonment: replay the same client, session, sequence, and intent,
then reconcile with the agent after process restart. Stream reconnection alone
must not claim a new client session.

The server admits new operations only at `allocated_through + 1`. Therefore a
known precommit failure at N blocks later first admission for that same client
until N is repaired or explicitly abandoned. Failures for one client must not
block another client's valid first admission. Never advance the frontier merely
because a request was rejected or a stream disconnected.

Current SDK policy: preserve rejected work for explicit repair or abandonment.
The journal-backed pipeline stops at the first rejected response without
advancing its frontier or deleting that intent. An opt-in abandon-and-continue
policy remains a separate product choice; it is not required for the numbered
model transition. Ambiguous transport or postcommit failure always requires
recovery rather than abandonment. A failure-isolation claim must state this
per-client sequence boundary.

Bound first-admission ordering in the SDK and service rather than depending on
response ordering alone. If later inputs arrive ahead of an unresolved earlier
input, return a sequence-gap outcome without mutation and retry only after the
frontier is resolved. Multi-client results remain paired with their original
inputs. A failure for an already committed operation must not be reported as
proof of noncommit.

## Implementation stages

1. **Grouped numbered durable authority.** Add numbered prepared-cohort commits
   sharing current reservations, verified Events, policy/custody guards, and
   stage logic. Validate session, sequence, intent, capacity, and recovery inside
   the writer. On cohort failure, roll back before ordered singleton isolation.
   Route admitted numbered actor work through that path and retain exact writer
   diagnostics. This foundation is implemented and committed.
2. **Numbered stream and durable SDK.** Carry numbered request/receipt types
   through the existing pipeline. Journal windows and responses transactionally;
   pair every response with its sequence; handle partial/lost responses without
   duplicate publication. Define the explicit rejection/abandonment policy.
   Keep reconnects within a process session and process recovery fenced.
3. **Application-facing caller transition.** Move CLI publication, Rust/Go
   examples, Atlas/Beacon/Cove controller, native node demos, agent acceptance
   clients, telemetry/path/Compose tools, and their fixtures to durable client
   sequences. Give each application a stable bounded identity and surviving
   journal. Distinguish application-journal recovery from node restart. Keep
   simple demo commands; do not expose session management to demo users.
4. **Legacy removal and store boundary.** Remove ordinary application RPCs,
   pipeline types, public native methods, arbitrary-key Event admission, and
   active legacy mode/counters. Retain only what is necessary to diagnose/refuse
   incompatible existing stores and preserve historical evidence. Search every
   live caller, generated client, example, CLI help/manpage, capacity report,
   and protocol document; do not relabel old evidence as numbered execution.
5. **Verification and evidence.** Run failure-path tests, full checks and fuzz,
   then update current documentation and exact requirement trace only where its
   claim boundary genuinely changes. No production or physical performance
   credit follows from retaining the old pipeline's source mechanisms.

## Required regression matrix

- Same-client contiguous cohort: one durable writer, original ordered receipts,
  frontier/result/reverse/accounting consistency, exact replay without writes.
- Failed/gapped or conflicting sibling: no partially committed cohort; ordered
  fallback; later same-client gap remains explicit; other clients remain usable.
- Takeover before or during commit: fenced mutations never advance source or
  client counters, and committed work remains recoverable by the successor.
- Lost stream result, partial session, healthy rotation, dropped HTTP/2 stream,
  process replacement, and journal fsync/commit failure.
- Durable/finite cohorts, TTL cleanup before result acknowledgement, retirement
  under an active transfer lease, custody continuity transitions, and Flash.
- Capacity saturation, exact snapshot/response bounds, result acknowledgement
  while an older operation remains outstanding, and count/byte headroom reuse.
- Source authorization failure, revoke/rekey/policy races, mixed-client and
  interleaved non-publication actor commands, shutdown and zeroization.
- Missing/corrupt journal, incompatible legacy store refusal without mutation,
  all public entry points numbered-only, CLI/demo restart and smoke acceptance.

Implemented regressions cover contiguous one-writer admission, exact replay,
rollback before gap fallback, stale-session isolation, lost and partial stream
responses, rotation/backpressure, journal persistence failures, and native/CLI/
Go/application restart. Legacy startup refusal checks all historical tables and
preserves original bytes, including unclean stores requiring allocator repair.
A private disposable copy supplies crash preflight inspection; both normal
startup checks and the acquired-writer check remain in place.

Historical Event, custody and NAT receipt validators remain frozen under
`tools/historical`. Current numbered executions use v2 evidence schemas without
relabeling retained v1 receipts. The shared state-subscription checker retains
its original exact inventory and empty-stderr boundary. No requirements IDs or
hash-bound baseline were changed, and no physical-host or performance credit is
added.

Verification status: strict workspace Clippy and strict normal node/store Clippy
passed. All 1,724 workspace tests passed, with two platform skips; documentation
tests passed. Fuzz smoke passed all seven macOS-supported targets at 10,000 runs
each; two systemd targets require Linux. The migrated Connect shell example
passed explicit initialization and journal reopening against a real agent.
`mise run check` passed in full, including real three-node playground and hello
sessions; Go SIGKILL/restart, exact replay, conflict, acknowledgement and bounded
load journal reopening; bindings, conformance, 202 lab tests and regenerated
Go checks. Requirements trace validation passed: 348 baseline IDs and 137 exact
selected mappings.

The separate customer-agent process smoke gate
cannot execute with this macOS Python: `os.POSIX_SPAWN_CLOSEFROM` is unavailable.
The process-launch safety requirement is retained. Linux custody/NAT/packaged
qualification has not been performed.

Final gates: `mise run check`, `mise run fuzz-smoke`, generated proto/Go checks,
applicable real-process smoke tests, and
`python3 tools/check-implementation-requirements.py` when traceability changes.
Preserve the hash-bound baseline and historical manifests/receipts.
