# Propagation and constrained-operation policy arm

> Historical experiment summary. Detailed harnesses, raw logs, and execution
> records are retained separately; only linked public summaries and active tests
> are maintained in this repository.


Status: **component research arm complete; evaluation profile passes; final
stack ownership remains open**

Authority: `data-mesh-requirements.md` only, SHA-256
`e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`.
Current Aster compatibility had zero weight. The `[4]` priority count, link
rates, loss, storage sizes, and durations were evaluated as curves, not used as
elimination gates.

## Outcome first

No reviewed FOSS candidate owns the complete propagation-policy contract.
Build **one thin mission-policy owner** above the selected replica/store and
below every carrier, while buying candidate-native mechanics already present
in the selected stack:

- p2panda topic sessions and duplicate suppression in Arm A;
- Zenoh key-expression interest and priority queues in Arm D;
- BPv7 bundle age/lifetime only when BP is the selected temporal carrier;
- Trickle only for broadcast redundancy suppression;
- one selected durable store for policy state; and
- a rate-limiter primitive such as Governor only after an exact freeze proves
  its graph and embedded cost are justified.

Do not introduce p2panda Spaces merely to rename it “scope,” Zenoh merely to
obtain queues, Tower in the disrupted data path, or a second database under a
candidate that already owns durable state. Those additions duplicate
responsibility without buying the missing semantics.

The leading evaluation policy is deterministic weighted priority rather than
unbounded strict priority. Both deliver a high-priority item first in the
acceptance corpus. At the illustrative 3 kbps / 50% loss point, strict priority
delivered 22 items—16 rank 3 and 6 rank 2, with no rank 0 or 1 progress.
Weighted priority delivered 21—9/6/4/2 from ranks 3/2/1/0. One seeded simulation
is not a benchmark, but it exposes the real choice: strict precedence can
starve lower ranks; static weighted service gives every rank a predictable
opportunity at almost the same observed throughput.

## What was executed

`policy-001` is a deterministic Python 3.13.7 standard-library model with no
external package graph. It contains no candidate or Aster code. The profile is
explicitly evaluation-only and defines:

- exact-match topic and joined-scope checks as orthogonal gates;
- no implicit parent/child membership for hierarchical scopes;
- a relay path for in-scope, unconsumed items under storage and bandwidth
  quota;
- a bridge gate requiring joined source and destination scopes, an allowed
  topic, and a minimum priority;
- publisher priority with optional topic default, integrator cap, or override;
- priority-driven scheduling, retry limit/backoff, and durable eviction;
- TTL as source TTL minus accumulated monotonic age and local residence time;
- expired-first collection and lowest-priority-first pressure eviction;
- open, threshold, and zero-outbound receive-only emission modes; and
- discovery suppression in threshold and receive-only modes.

The modeled gate deliberately interprets “radio-silent” as **no outbound
traffic**, not merely no application items. Real carriers and sync protocols
must still prove they can ingest useful unsolicited inbound traffic without
ACKs, discovery, advertisements, keepalives, or other responses. This arm does
not grant that credit.

All 18 requirement-linked acceptance cases passed:

| Acceptance group | Observed result | Bounded requirements |
|---|---|---|
| Priority set | 3/4/5/7 fixed-set curves accepted every in-range rank and rejected the first out-of-range rank | DM-5.4-01/02/21/22 |
| Topic/scope | matching topic+scope admitted; wrong topic and wrong scope rejected independently | DM-5.5-01/02/03 |
| Relay boundary | unconsumed in-scope item admitted by a relay; the same topic in an unjoined scope rejected; store remained bounded | DM-5.5-04/05/06/07 |
| Scope hierarchy | joining `unit` did not implicitly join `unit/team` | DM-5.5-03/14 |
| Bridge | allowed source/destination/topic/rank passed; wrong topic, low priority, and unjoined destination failed closed | DM-5.5-09/10/11 |
| Assignment | publisher, topic default, cap, and override produced the expected ranks | DM-5.4-05/06/07/08 |
| Ordering/retry | strict and weighted began with the highest rank; FIFO negative control began with arrival-order low rank; higher ranks received more attempts and shorter backoff | DM-5.4-09/10, DM-12-06 |
| Storage pressure | expired-first collection and lowest-priority-first eviction kept bytes within quota | DM-5.4-11/14, DM-5.5-07, DM-9-24/25 |
| TTL | an expired highest-rank item was rejected while a live lowest-rank item remained eligible | DM-5.4-12/13/14 |
| Emission | below-threshold outbound was blocked; at-threshold outbound passed | DM-5.4-15/16, DM-12-07 |
| Receive-only | eligible inbound was stored while outbound and discovery were suppressed | DM-5.4-17/18, DM-5.7-03, DM-12-07 |
| Bandwidth/dedup | deterministic token bucket stayed within burst+refill; duplicate item ID consumed one storage entry | DM-5.5-08, DM-5.2-05/06 |
| Time | backwards monotonic ticks were rejected; no wall-clock input controlled expiry | DM-5.2-09/10, DM-5.4-13 |

This is model evidence for policy coherence. It is not candidate-daemon,
process-restart, radio, interoperability, or security evidence.

## Operating curves

The impairment corpus held 160 mixed-size items and a 120-second contact window
constant, then varied one modeled link over 1/3/10/50 kbps and 0/25/50/70% loss.
Every one of the 48 scheduler points began **zero** transmissions after item
expiry. Selected points show the policy trade:

| Rate / loss | FIFO delivered by rank 3/2/1/0 | Strict delivered by rank 3/2/1/0 | Weighted delivered by rank 3/2/1/0 |
|---|---:|---:|---:|
| 1 kbps / 50% | 1 / 2 / 2 / 1 | 5 / 0 / 0 / 0 | 3 / 0 / 1 / 1 |
| 3 kbps / 50% | 7 / 6 / 5 / 4 | 16 / 6 / 0 / 0 | 9 / 6 / 4 / 2 |
| 10 kbps / 50% | 16 / 16 / 11 / 7 | 22 / 15 / 7 / 6 | 21 / 15 / 11 / 4 |
| 50 kbps / 70% | 21 / 19 / 14 / 6 | 26 / 23 / 6 / 3 | 28 / 14 / 12 / 8 |

FIFO is not a candidate: its even-looking distributions occur because arrival
order, not priority, governs it. Strict and weighted results differ because
loss, retry backoff, item TTL, item size, and the 120-second window interact.
The same seeded random stream is used at each loss point for all three
schedulers; these figures remain decision data, not statistical confidence.

The 3/4/5/7-level curve at 3 kbps / 50% loss reinforced the same result. Strict
service delivered only the top one or two ranks at 3, 5, and 7 levels. Weighted
service made lower-rank progress at every count, though short-TTL and contact
limits still left some ranks without delivery. The number and names of
priorities therefore remain stakeholder decisions; no curve endpoint was
declared a winner or gate.

Storage curves inserted 320 mixed-size records into 8/32/128 KiB quotas. Across
all 12 combinations of quota and 3/4/5/7 ranks, bytes stayed within the
configured bound and every pressure eviction selected a currently
lowest-priority candidate. For four ranks:

| Quota | Bytes retained | Survivors | Survivors by rank 3/2/1/0 |
|---:|---:|---:|---:|
| 8 KiB | 6,560 | 7 | 6 / 1 / 0 / 0 |
| 32 KiB | 32,032 | 19 | 19 / 0 / 0 / 0 |
| 128 KiB | 130,464 | 79 | 76 / 3 / 0 / 0 |

This is the specified “lowest priority first” behavior, but it also shows that
sustained pressure can eliminate an entire lower rank. Per-scope reservations,
admission control, or a bounded minimum share may be useful Post-MVP policy;
they should not be smuggled into the small MVP operator matrix without a
stakeholder decision.

The offline/TTL matrix used 1/14/30/60-day TTLs against 0.5/14/30/60-day
offline ages. A 30-day item remained eligible after 14 days; a 14-day item was
expired at 14 days. Thus “works at 14 days” remains useful decision evidence
and is not an elimination against the `[30 days]` placeholder. This matrix
tests expiry arithmetic only, not offline resynchronization or durable
retention.

## Candidate audit and buy boundary

Exact consulted surfaces and hashes are retained in
`source-audit.tsv`. No new external source was opened and no new dependency
graph was resolved for this arm.

| Candidate | Buy | Do not infer |
|---|---|---|
| p2panda v0.7.1 | Topic subscription/session mapping and two duplicate-suppression points when Arm A is selected | A topic is not an administrative scope; its topic handshake, Spaces encryption context, and sync manager do not supply bridge, priority, TTL, quotas, or emission policy |
| p2panda Spaces v0.7.1 | Dynamic group membership, nested groups, access levels, group encryption context, and idempotent control processing for the separate security decision | A “Space” is not the requirement propagation scope. The crate requires caller-owned causal ordering and explicitly recommends caller scheduling/throttling for repair redundancy |
| Zenoh 1.10.0 | Seven public QoS ranks, one transport queue per rank, strict priority service, bounded queue batches, key-expression interest, namespace/QoS/ACL/filter building blocks when Arm D is selected | Seven ranks do not settle `[4]`; key expressions and namespaces are not joined mission scopes; no source-audited priority bridge gate, item TTL/GC, durable lowest-rank eviction, receive-only ingestion, or policy-state persistence was found |
| Governor E1 | Candidate token bucket for admission and bandwidth accounting | Exact version/graph, keyed-state bound, persistence, fairness, mission authorization, and policy semantics remain open |
| Tower E1 | Timeout, concurrency, load-shed, and retry middleware for local request/response control paths | Disrupted streaming data-plane scheduling, durable retry, TTL, quota, scope, bridge, or emission behavior |
| BPv7 / RFC 9171 | Bundle lifetime and bundle-age mechanics when BP owns temporal carriage | Application item TTL, mission priority, eviction, topic/scope/bridge, and emission policy |
| Trickle / RFC 6206 | Broadcast redundancy-suppression timing below the emission gate | Permission to transmit, priority, TTL, quota, bridge, or authorization |
| redb component | One transactional substrate for durable policy records in the greenfield composition | The policy schema or any replication/scheduling semantics |

Zenoh's strict queue implementation is a particularly useful mechanism and a
particularly important boundary. The exact source services lower numeric Zenoh
ranks first across seven public ranks, plus a reserved internal Control rank.
If Arm D advances, the protocol profile must publish one explicit mapping from
mission rank to Zenoh rank and define what happens to unused ranks. If another
arm wins, importing Zenoh solely for that scheduler would be architectural
regrowth.

## One policy owner

The minimum custom layer has one responsibility sequence:

1. accept only authenticated membership-layer metadata from the security
   owner;
2. validate the item profile, exact joined scope, and consumer-or-relay topic
   interest;
3. update monotonic age, purge expiry, deduplicate, and transact durable quota;
4. on a bridge, apply joined source/destination, topic, and priority rules;
5. apply the atomic emission mode and per-scope/bridge bandwidth budget;
6. schedule eligible frames by priority and retry policy; and
7. expose all rejection, expiry, eviction, and policy-change outcomes for
   audit and application status.

Carriers may optimize how an already-eligible frame is queued, retransmitted,
or broadcast. They must not each reimplement scope, expiry, bridge, and
emission decisions. The durable store may transact bytes, but it must not
become a second policy authority. This deletes duplicate ownership across IP,
BTLE, BP, file, and future carriers.

## Requirements disposition

| Requirement family | Arm disposition | Final-stack status |
|---|---|---|
| DM-5.4-01 through 22 | Coherent fixed-set, assignment, scheduling, retry, eviction, TTL, threshold, and receive-only profile; quantitative choices curved | **Partial/open** — executable reference integration, crash persistence, carrier control traffic, operator transitions, and stakeholder naming/count remain |
| DM-5.5-01 through 11 | Exact topic/scope/relay/bridge/quota model passes | **Partial/open** — normative identifiers, authorization binding, protected metadata, distributed policy update, and real relay/bridge execution remain |
| DM-5.5-12/13 | Aggregation and summarization not added | **Future, intentionally open** |
| DM-5.5-14 | Explicit hierarchy representation does not imply membership inheritance | **Optional mechanism modeled; final syntax open** |
| DM-5.7-03 | Threshold and receive-only nodes report undiscoverable in the model | **Partial/open** — every real discovery and keepalive path must be captured and proven silent |
| DM-9-24/25 | All storage points remain within configured quota | **Partial/open** — crash-safe database integration and per-scope accounting remain |
| DM-12-06 | Higher priority begins first and expired items never start transmission in the model | **Partial/open** — real constrained carrier execution remains |
| DM-12-07 | Threshold and receive-only acceptance passes in the model | **Partial/open** — unsolicited inbound sync with truly zero outbound traffic remains a hard experiment |

## Residual design and executable gates

The following work cannot be delegated to the reviewed generic components:

- specify canonical topic and scope identifiers, explicit hierarchy, and their
  binding to mission authorization and protected metadata;
- specify deny-by-default bridge policy updates and rollback behavior under
  intermittent connectivity;
- choose priority count/names and publish mappings for every candidate carrier;
- settle strict versus deterministic weighted scheduling, retry budgets,
  admission behavior, and same-rank ordering;
- define clock-independent accumulated age, transport-time accounting,
  tombstone interaction, and protection against a compromised member resetting
  age;
- make quota, expiry, eviction, retry, and policy changes atomic and durable;
- specify whether token buckets persist across restart or deliberately regain a
  bounded burst;
- prove a receive-only node emits no discovery, ACK, retry, session, keepalive,
  or security-control traffic while still ingesting useful inbound data; and
- demonstrate metadata confidentiality while relays and bridges can still read
  exactly the policy fields they need.

Before production selection, freeze and measure Governor against a minimal
standard-library token bucket, then run this common corpus through the actual
Arm A, Arm D, and greenfield adapters. Add process restart during pressure,
disk-full, policy update/fork, hostile metadata, and real IP/BTLE capture. No
component receives production or security admission from this arm.

Evidence:

- archived `profile-v0.json`
- archived `source-audit.tsv`
- archived `acceptance.json`
- archived `curves.json`
- archived `summary.json`

