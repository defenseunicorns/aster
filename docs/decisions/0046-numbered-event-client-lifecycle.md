# Numbered Event client loss and lifecycle operations

Clean Room — Privileged

Status: implemented in Increment 3, rebased onto main after Increment 2 (PR #118).
Profile: alpha/local numbered Event APIs; roadmap P1 causal correctness and
bounded data lifecycle. Retained physical acceptance remains a separate gate.

## Partial reconstruction

`NumberedEventSdk::reconstruct(client, new_path, client_id)` and
`asterctl publication-reconstruct --journal NEW_PATH --client-id ID` are explicit
loss-recovery operations. They observe the registered client's current session,
create an exclusively opened new journal, durably record the reconstruction
state and claim nonce, and use the existing compare-and-swap takeover and
recovery-completion protocol. A concurrent claimant causes rejection; the SDK
never silently retakes ownership. Failed RPCs leave the new journal available
for ordinary `open`/`recover`, including a lost claim or completion response.
Reconstructed journals use version 2 so older SDKs refuse result-only entries
rather than presenting a placeholder as an original intent. New SDKs still
open ordinary version-1 journals. An existing destination is never overwritten.
Ordinary opening still refuses a
missing or corrupt journal.

Only `allocated_through` and the agent's retained committed receipts survive.
Reconstruction saves receipts durably before completing recovery. These are
result-only entries: the SDK exposes no invented original intent and cannot
replay a guessed publication. Locally queued work the agent never received,
previously acknowledged receipts, and application business effects cannot be
reconstructed. The CLI explicitly labels its report partial and lists these
losses. Applications must reconcile their own business records and apply
retained receipts idempotently before acknowledging them. The next allocation
is above the agent's proven frontier; there is no promise to preserve sequence
assignments that existed only in the lost journal.

Reconstruction retains the current Rust journal limits: eight retained entries
and a 1 MiB logical serialized-state budget. The journal transaction rejects an over-limit
snapshot before recovery completion, without storing a partial set or dropping
receipts to fit. The new journal retains its incomplete reconstruction and claim
for explicit recovery.

Subscription ownership and delivery state survive takeover. Existing client
sessions are fenced using Increment 2's contracts. Reconstruction is exposed
through the Rust agent SDK and CLI; native demonstration and Go journals retain
their ordinary fail-closed opening behavior and do not infer missing work.

## Irreversible retirement

Retirement is local operator administration, distinct from SDK takeover.
`Store::retire_event_client` requires the reviewed current session as a CAS.
The offline `aster event-client-retire` command additionally requires
`--irreversible`. Node/agent writers must be stopped; filesystem authority and
redb writer exclusion protect this administrative surface. No retirement RPC
is granted to ordinary holders of the shared mission bearer token.

One writer transaction removes owned Consume/Carry selectors, pending and
acknowledged deliveries and custody dependency edges, sparse publication
results and reverse edges, and the internal application checkpoint. It retains
an immutable 17-byte fence (tag, last session, allocation frontier), charged
alongside the client ID. It preserves committed Events and their ordinary
transport/TTL/custody lifecycle. A failure rolls back the whole transaction;
repeating the same retirement is an idempotent no-op. The fence permanently
rejects session claims, recovery completion, publications, abandonment, result
acknowledgement, subscription mutations and checkpoint writes. Read-only status
reports `Retired`, including when no session or a stale session is observed.
The application protocol preserves `Unregistered = 4` and adds `Retired = 5`.

Retirement discards recovery receipts and subscriptions intentionally. It does
not acknowledge application effects, recall messages already authorized and in
flight, or erase mesh Event content. Stop the application and settle needed
receipts before retiring its identity. The client count never decreases;
retirement does not reclaim a slot, purge an identity, permit ID reuse or make
aggregate client history unbounded. Safe reclamation remains future work.

Active records retain their existing encoding. The new retired record tag is an
explicit storage extension; older binaries cannot reopen a retired-client
store. Downgrading after retirement is unsupported. Audit rejects retained
results or subscriptions belonging to retired clients.

## Admission configuration and capacity

`EventClientLimits` persists client-count, per-client outstanding-result,
numbered record-count and logical-byte admission limits in one transaction.
`aster event-client-limits` configures them offline; capacity inspection is
read-only and reports current clients, retired clients, outstanding results,
reverse edges, logical bytes and effective limits. These are local publication
ledger measurements (record admission counts clients plus outstanding results;
reverse edges are reported separately and charged to logical bytes), not total
disk use, Event content quotas, network status
or release fitness.

Client and outstanding limits cannot exceed the existing hard ceilings of
1,024 and 4,096. Global tuning narrows the runtime's existing
`EventOperationLimits`; it cannot expand them. An absent configuration preserves
the runtime's prior limits. Lowering limits below existing usage does not evict
records or invalidate startup. It rejects new clients/results while exact
retries, takeover, recovery, result acknowledgement, TTL transition and
retirement remain available. The 2 MiB recovery response bound is unchanged.
Retired clients continue to consume client slots and record/byte capacity.
Offline CLI capacity uses the stock runtime ceilings; embedded callers with
custom runtime limits use `Store::event_client_capacity` on their live store.

## Validation and nonclaims

Focused tests cover partial receipts, unknown original intents, lost claim and
completion replies, restart, existing destination refusal, real-agent takeover,
unsent-work loss, permanent fences, retirement rollback, sparse-edge accounting,
CLI writer exclusion and capacity inspection without writes. Publication
compaction, pipelining and v7 semantics are unchanged. This is code/local-test
evidence; no new physical receipts, atomic requirement credit, client-ID
reclamation, lost application-effect recovery or production release is claimed.
