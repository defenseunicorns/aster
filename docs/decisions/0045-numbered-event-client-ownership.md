# Numbered Event client ownership

Clean Room — Privileged

Status: implemented in the stacked Event client ownership increment; retained
physical acceptance evidence remains an external validation task.

## Outcome

Extend the numbered publication client's stable identity and recovered session
to every persistent Event subscription mutation: create/delete, poll cursor
advancement, durable delivery attempts, and delivery acknowledgements. This is
Increment 2 of the allocated-through compaction proposal. Publication sequence
allocation, sparse result acknowledgement, HTTP/2 pipelining, receipt-free v7
pages, and transport/custody policy retain their existing contracts.

## Decisions

`EventClientContext` contains a bounded client ID (1–64 bytes) and a positive
session. The current session must have completed publication recovery before
any subscription mutation can commit. Validate inside the same store writer
transaction as the mutation, before returning an idempotent result. A poll
prepared under an earlier incarnation must revalidate at commit; rejection
cannot advance a cursor, record an attempt or recreate delivery dependencies.
The native actor also checks before poll custody maintenance.

A subscription's owner is the stable client ID, never its transient session.
Its ID hashes the mission authority, client ID and immutable operation key.
Two clients can use the same key independently. Takeover preserves selectors,
cursors, pending deliveries and acknowledgement receipts. Another client cannot
mutate a present subscription owned by that identity.

Delete removes the owned selector and its delivery rows atomically. A current,
recovered caller can repeat an absent deletion as a no-op; no deleted-owner
history is retained. A stale session is rejected even when the subscription is
already absent or a delivery was already acknowledged. Ownership coordinates
cooperating processes; the shared mission bearer credential is not a separate
per-client security isolation boundary.

`StreamEvents` validates the captured context before each buffered item and
before each new durable poll. A fenced stream clears buffered delivery and ends
with the existing session-fenced error. Its durable pending rows remain for the
current owner. Authorization is the linearization point: an already authorized
message in flight cannot be recalled if takeover commits before network arrival.
Application effects must remain idempotent by Event identity. TTL, shutdown,
bounded polling/backoff and delivery acknowledgement semantics remain intact.

Read-only queries, gaps, subscription listing and `GetEventClientStatus` remain
available to a fenced caller. Status reports the current session, caller
disposition (unregistered/current/fenced/recovery-required), owned subscription count, pending
and acknowledged delivery counts, and ownership metadata bytes. It neither
claims a session nor changes recovery or publication state. The status-specific
request supplies a client ID and an optional positive observed session. A journal
still stores zero before its first claim; the SDK omits that value from the
status request. Unknown clients return unregistered, no current session, and
zero counts. Registered clients with no observed session return their current
session and recovery-required; a matching observation distinguishes completed
from incomplete recovery, and an older observation reports fenced. Status never
claims a session for the caller. Mutation contexts still require positive
sessions and completed recovery. This deliberately revises the prerelease
status request (the old context field is reserved); journal formats are unchanged. Subscription-owner
bytes are bounded by the existing 256-subscription cap: at most 256 × 65 bytes,
with no per-session ownership history.

Subscription records use mandatory version-2 ownership encoding and IDs use the
version-2 client namespace domain. Missing, old or unregistered owners fail
closed. Startup preflight refuses populated unowned subscription state before
opening the original for writes; unclean redb repair is confined to a disposable
copy for compatibility inspection. Empty subscription state can initialize.
This is an intentional alpha API/storage change; no compatibility mutation lane
or speculative owner inference is provided.

Native and Rust SDK consumer methods derive context from the retained durable
journal. SDK methods never reclaim ownership implicitly. CLI subscription
commands explicitly recover the requested journal before mutation;
`client-status` is read-only. The Go/process acceptance consumers and shipped
native examples use the same journal context across restarts. Initialization is
explicit, once, during fresh provisioning; a missing established journal is
never silently replaced.

## Boundaries and evidence

Store tests exercise every stale mutation, wrong-owner access, namespaced keys,
incomplete recovery, restart-preserved attempts/acknowledgements, transactional
poll/takeover races, owner-byte reclamation and byte-preserving startup refusal.
Native regressions cover existing custody, bridge, pipelining and v7 capabilities.
Connect/SDK tests exercise missing context, fenced SDK mutation without automatic
takeover, read-only status/listing and continued use by a recovered owner.
Stream tests exercise buffered pages and empty-poll backoff under takeover.
These are current-code/local-test claims, not new physical acceptance receipts.
The 348-row requirements baseline, exact mappings and retained historical
receipts remain unchanged.

Increment 3 remains separate: lost-journal reconstruction, administrative client
retirement and client-ID reclamation. This increment does not alter the earlier
choice to repair and retry an unadmitted publication or explicitly abandon it;
SDK abandonment policies and server-recorded terminal rejection remain alternate
future paths, not automatic behavior of subscription ownership.
