# Generated Go application-protocol clients

> Clean Room — Privileged

These acceptance clients use the generated numbered publication API independently
of the Rust SDK. `internal/numbered` retains one configured client ID, its session
claim, monotonic sequence frontier, complete intents and committed receipts in a
protected durable journal. Initialization is explicit; missing, corrupt,
mismatched or concurrently owned journals fail before publication. Failed or
ambiguous intents remain available for recovery. Tokens never enter the journal.

`agent-smoke publication-init` reads `journal_path` and `client_id_hex` from JSON
stdin. `publish` adds the topic, scope, priority, logical key and payload fields.
It retains the committed result for inspection and retry. A positive
`operation_sequence` explicitly targets an existing retained operation; changed
intent probes cannot replace its original journaled intent. `publication-ack`
accepts the identity and positive sequence after the caller has applied the
result. Publisher counters and topic sequence metadata are read from Event
content rather than invented from the minimal numbered receipt.

The client-only subscription recovery example retains its existing first-delivery,
process replacement, second-attempt, acknowledgement and quiet-window checks.
Publication uses an explicitly initialized journal and a numbered exact retry;
publication acknowledgement follows delivery of the validated receipt.

`agent-load` requires `--journal-dir` and `--initialize-journals true|false`.
The configured `--operation-prefix` identifies a stable worker namespace. Each
of the bounded workers has one client and contiguous durable sequences. Resume
resolves retained intents before scheduling new load. Keep the prefix and worker
count when reopening these journals. At most four sampled results remain
available for exact-retry and changed-intent probes. Other results are applied
and acknowledged during the run; sampled results are acknowledged after the
observation receipt is durably committed. Recovery work is excluded from the
new-workload observation.

Current load observations use `aster-agent-load/v2`. Historical v1 receipts and
qualification evidence remain unchanged. Local observations do not qualify a
rate or representative hardware. `tools/test-aster-numbered-go-real.sh` checks
real-agent restart, exact receipt recovery, conflict rejection, acknowledgement
and bounded load with the unprotected test provisioning provider.
