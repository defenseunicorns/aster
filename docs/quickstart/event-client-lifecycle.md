# Event client loss and offline lifecycle administration

Clean Room — Privileged

Keep the stable client ID outside the publication journal. Normal restart uses
the surviving journal and `publication-recover`. A missing/corrupt journal still
fails closed; do not initialize an established identity as if it were new.

For explicit partial loss recovery, preserve any damaged journal, stop competing
application processes, and choose a new protected path:

```sh
asterctl --token-file ./agent.token publication-reconstruct \
  --client-id chat-controller --journal ./reconstructed.redb
```

The agent must still know that identity. The report includes its frontier and
retained committed receipts. There are no original intents for these receipts;
`publication-show` refuses them. Unsent intents, compacted receipts and business
effects are unrecoverable. Apply retained receipts idempotently using application
records, then use `publication-ack`. Subsequent commands use the new journal.
If an RPC fails after creation, use `publication-recover` on that path. The
current Rust journal retains at most eight entries within its 1 MiB logical
budget. An oversized reconstruction snapshot is refused without dropping
receipts or completing recovery; retrying requires a snapshot within those
limits.

Retirement is permanent and discards the identity's retained receipts and
subscriptions. Settle needed application effects first, record the current
session using `client-status`, then stop the application, agent and node writers:

```sh
aster event-client-capacity --state ./node-state
aster event-client-retire --state ./node-state \
  --client-id chat-controller --expected-session 4 --irreversible
aster event-client-capacity --state ./node-state
```

For binary SDK client IDs, use `--client-id-hex HEX` instead of `--client-id`.
Choose the actual observed session, not the example value. A competing takeover
invalidates this CAS. Retirement keeps Events and their mesh lifecycle, removes
owned delivery/publication bookkeeping, and retains a permanently charged fence.
The ID can never be reused and its client slot is not reclaimed.

To narrow admission limits while writers are stopped:

```sh
aster event-client-limits --state ./node-state \
  --max-clients 256 --max-outstanding 512 \
  --max-records 50000 --max-bytes 16777216
```

Client and outstanding ceilings remain 1,024 and 4,096. Global values are
additionally constrained by the runtime's existing operation limits. Lowering
limits below usage blocks growth without eviction; recovery and cleanup remain
usable. Capacity inspection is read-only and does not represent total disk use.
Commands require access to the existing local mission-bound store and never
provision a new node. See [the decision](../decisions/0046-numbered-event-client-lifecycle.md)
for format, privilege and evidence boundaries.
