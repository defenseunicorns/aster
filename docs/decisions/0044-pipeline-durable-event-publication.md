# Decision 0044: Pipeline durable Event publication without changing mesh semantics

- Status: accepted, implemented, and physically compared within a bounded
  two-CM4 engineering matrix
- Date: 2026-10-04
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Related: [Decision 0009](0009-public-api-boundary.md),
  [Decision 0012](0012-content-committing-pq-batches.md),
  [Decision 0030](0030-event-first-local-connect-agent.md), and
  [Decision 0042](0042-adopt-linux-event-mvp-evaluation-profile-v0-1.md)

## Numbered publication amendment — 2026-10-08

The current application surface is numbered-only. `PublishNumberedEvent` and
`PublishNumberedEvents` replace the ordinary publishing RPCs; the historical decision below records
the original PR #34/#54 pipeline. Its actor FIFO, fairness, compatible grouped
commits, ordered fallback, Flash urgency, bounded HTTP/2 window, and healthy
rotation remain. The SDK now journals complete intents and persists results
before freeing slots. Exact replay uses client/session/sequence. A failed next
sequence blocks that client until explicit repair or abandonment; independent
configured clients continue. Browsers use ordered unary numbered calls.
Nonempty old Event publication ledgers require fresh state and remain available
for read-only inspection. This amendment changes application publication
ownership, not v7 mesh page semantics or historical performance evidence.

## Context

Aster separates local publication from mesh synchronization. An application
publishes into the running selected node's sole durable authority. After that
local commit, the mesh independently reconciles the resulting source object
over available contacts. A successful local publication has never meant that a
remote node returned a receipt.

The unary local-agent API preserved this contract but allowed a sequential
telemetry producer to keep only one durable publication in flight. Each
ordinary publication also performed its own store transaction and custody
maintenance. Removing remote Event-page receipts from mesh synchronization did
not remove either local cost: the receipt-free page change and this decision
operate on different sides of the durable boundary.

The explicit content-committing cryptographic batch in Decision 0012 is not a
general publication buffer. It intentionally has a separate atomic API and
wire representation. Reusing it for ordinary telemetry would change failure,
authentication, compatibility, and urgency semantics.

## Decision

1. Keep `PublishEvent` compatible and add the native HTTP/2 bidirectional
   `PublishEvents` local-agent method. Each input remains an independent
   ordinary Event publication with its own operation key and outcome.
2. Emit a stream response only after that input's Event and idempotency mapping
   are committed by the selected node's local durable authority. Preserve
   request order and represent a valid per-input application failure as a
   sanitized in-band outcome so later inputs can continue.
3. Keep the selected-node actor as the sole mutable owner. It may collect only
   adjacent ordinary non-Flash Event commands that are already admitted in its
   bounded application lane. It never waits for a future command to enlarge a
   group and never skips other work.
4. Commit compatible adjacent publications in one durable store transaction.
   Split incompatible inputs into ordered cohorts, and fall back to the
   existing singleton path after an exceptional cohort failure so one invalid
   input does not discard valid siblings.
5. Keep Flash Events and experimental numbered publication on their existing
   paths. Grouped ordinary Events retain the singleton source representation;
   grouping does not create a Decision 0012 `BatchProof` or atomic application
   batch.
6. On native stream interruption, retry every sent input whose durable response
   was not observed with its unchanged operation key. The existing operation
   ledger decides whether the original commit occurred. Do not add a second
   journal, store, receipt ledger, or reconciliation authority to the agent.
7. Reject request-streaming over gRPC-Web. Browser clients use a bounded number
   of concurrent unary `PublishEvent` calls and retain the same durability and
   retry rule.

## Bounds and compatibility

The source schema addition is backward compatible: existing unary clients and
servers keep their previous behavior. Native Connect and gRPC over HTTP/2 can
use the bidirectional method. A caller must treat gRPC-Web request streaming as
unsupported and select the unary fallback.

The reference SDK currently keeps at most eight publications active and
rotates a healthy publication session after eight seconds, before the server's
existing ten-second default deadline. The actor's application lane remains 32
commands and its fairness budget remains eight. These are private bounded
implementation choices, not mesh protocol fields, telemetry-rate limits,
deployment promises, or newly validated physical thresholds. The public stream
adds no batch-size, page-size, wait-time, or rate field.

The SDK caller supplies the consecutive disconnect retry budget. Normal healthy
session rotation does not consume it. Responses without a declared outcome are
not accepted as durable progress.

## Failure and lifecycle behavior

A process failure before a cohort transaction commits exposes none of that
cohort. A failure after commit but before the response can make the outcome
temporarily unknown to the caller; replay with the original operation key
returns the durable result without creating a second Event.

Once admitted to the actor, caller cancellation does not cancel the durable
operation. Shutdown closes further admission and may finish the adjacent group
already selected for the synchronous actor turn. It does not promise to drain
all queued work. The agent holds no detached store writer.

The actor emits one identifier-free, bounded `event_publication_group`
diagnostic per collected group. Its numeric counts describe the implementation
work performed; they are neither protocol receipts nor correctness authority.
This one bounded diagnostic remains available through the customer agent's
otherwise legacy-receipt-suppressing output policy.

## Architectural consequences

- Local publication remains synchronously durable while mesh reconciliation
  remains asynchronous. Pipelining overlaps independent local requests; it
  does not acknowledge volatile memory and does not wait for remote delivery.
- State, Event, Record, and Blob remain distinct application data classes with
  class-specific reducers and lifecycle semantics. Describing their durable
  changes as streams is a useful model, but it does not collapse their public
  APIs or authorize Event-specific behavior for the other classes.
- No semantic mesh version, stable source-envelope format, reconciliation
  frame, or migration is introduced.
- The change can reduce committing work per accepted ordinary Event and remove
  client-side unary serialization. It does not by itself prove an accepted
  rate, latency, CPU, RSS, or synchronization improvement on target hardware.

## Evidence boundary

Host tests establish ordered durable outcomes, exact replay after disconnect,
bounded backpressure, native Connect and gRPC interoperability, gRPC-Web
rejection plus unary fallback, group rollback/fallback, actor fairness,
shutdown behavior, and a real-node durable publication path.

The [bounded physical comparison](../validation/evidence/2026-10-05-pipelined-event-publication-cm4-validation.md)
records the exact upstream baseline and candidate commits and binaries, device
preflight, offered and accepted rates, publication and synchronization
percentiles, exactly-once observed remote delivery, errors, normalized CPU,
RSS, writer commits, and observed group sizes. It observes an admission
improvement only under saturation, mixed latency and synchronization results,
nearly flat peak RSS, and normalized CPU within -10.7% to +2.7% of the baseline
rows. It therefore supports only the bounded physical observations stated in
that record and makes no supported-target, general efficiency, capacity,
qualification, requirement-completion, or release-authorization claim.
