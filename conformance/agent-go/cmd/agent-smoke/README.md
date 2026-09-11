# Generated-Go Event client-only recovery example

**** This is a bounded integration example, not a
production application or an exactly-once delivery guarantee. It uses the
checked-in generated Go client and the unchanged alpha Event API. No runtime,
provider, schema, or generated-code changes are needed.

## What the two processes demonstrate

1. `recovery-begin` publishes one fixed operation key, retries the identical
   request, and compares every durable protobuf receipt field. The per-call
   `inserted` flag must change from `true` to `false`; the full responses are
   **not** byte-identical.
2. It creates one fresh durable subscription, validates exactly one caught-up
   delivery at attempt 1 against every exposed Event field, then exits normally
   without acknowledging it. This is intentional client replacement, not an
   agent crash or a forced client kill.
3. A **new OS process** runs `recovery-resume` against the same live agent and
   the same subscription ID, without deleting or recreating the subscription.
   It validates the same Event at exactly attempt 2 and acknowledges using the
   subscription and Event IDs. The API exposes no delivery token.
4. Successful empty, caught-up polls must span at least 500 ms. The window
   begins **after the first successful empty response**. A further successful
   poll must be **initiated at or after the window end**: neither a delayed
   first response nor a response crossing the boundary substitutes for that
   final observation. Polls back off 50 ms and share the command deadline.
5. A final bounded query must return exactly the retained Event, unchanged.

The example is intentionally strict: use one fresh Event in the selected
exact topic/scope and an exclusive consumer. Other Events, concurrent consumers,
old operation keys, missing subscriptions, incomplete pages, unexpected
attempts, RPC failures, cancellation, or deadline expiry fail closed and emit
no success receipt. Do not use retrying this entire acceptance scenario as an
application recovery strategy: `recovery-begin` requires a fresh first insert.
Normal application retries retain their original operation key and request.

## Run against an already ready agent

Use the repository-pinned Go toolchain. Keep the same agent running throughout.
`TOKEN_FILE` is the path to the owner's regular mode-0600 token file, never the
token value. Inputs contain application content; keep inputs and receipts
owner-only. The example writes only IDs, counters, process IDs and fixed
verification fields to stdout, not topic, scope, logical key, payload or token.

```sh
go -C conformance/agent-go build -o "$HOME/agent-smoke" ./cmd/agent-smoke
export AGENT_URL=http://127.0.0.1:8181
export TOKEN_FILE=/absolute/path/to/client.token
umask 077
mkdir "$HOME/event-recovery-example"
cd "$HOME/event-recovery-example"
```

Save this as `begin.json` before publishing (the key is fixed for this one
synthetic demonstration):

```json
{
  "publish": {
    "operation_key_hex": "6578616d706c652d7265636f766572792d7631",
    "topic": "chat.events",
    "scope": "mission/team/alpha",
    "priority": "immediate",
    "logical_key_hex": "7265636f76657279",
    "payload_hex": "68656c6c6f"
  },
  "subscription_operation_key_hex": "6578616d706c652d7375627363726962652d7631"
}
```

Run client one synchronously so it has exited before client two starts:

```sh
"$HOME/agent-smoke" recovery-begin --url "$AGENT_URL" \
  --token-file "$TOKEN_FILE" --timeout-seconds 10 \
  < begin.json > first.json
```

Only after that command succeeds, construct `resume.json` from the saved
publication and receipt; do not republish or create another subscription:

```sh
python3 - <<'PY'
import json
from pathlib import Path
p = json.loads(Path('begin.json').read_text())['publish']
r = json.loads(Path('first.json').read_text())
expected = {k: p[k] for k in ('topic', 'scope', 'priority', 'logical_key_hex', 'payload_hex')}
expected.update(id_hex=r['event_id_hex'], publisher_hex=r['publisher_id_hex'],
                publisher_counter=r['publisher_counter'], event_sequence=r['event_sequence'],
                acceptance_marker=r['acceptance_marker'], tombstone=False)
Path('resume.json').write_text(json.dumps(dict(
    subscription_id_hex=r['subscription_id_hex'], expected=expected)))
PY
"$HOME/agent-smoke" recovery-resume --url "$AGENT_URL" \
  --token-file "$TOKEN_FILE" --timeout-seconds 10 \
  < resume.json > second.json
```

Both invocations use the normal 1..30-second command limit, bounded JSON input,
owner-only no-follow token-file checks, and authenticated generated gRPC client.
Never ACK merely because a message was received in a real application: first
commit the application's idempotent effect, deduplicated by stable Event ID.
Attempt counts are observations, not deduplication keys.

## Automated verification and claim boundary

```sh
go -C conformance/agent-go test ./...
go -C conformance/agent-go test -race ./cmd/agent-smoke -run TestRecovery -count=1
python3 tools/test-aster-agent-process.py \
  ProcessCheckerContractTests.test_client_recovery_requires_distinct_processes_and_unchanged_live_agent
mise run agent-process-smoke
```

The process checker compares client-reported PIDs with actual reaped child
PIDs and rejects reused PIDs or a replaced/stopped agent. Client-only recovery
runs on a separate peerless fixture with fresh privately owned state; the same
agent stays live across both clients, with its subscription intact. That fixture
is stopped and reaped before the original crash/restart scenario starts on its
unchanged state/configuration. The original publication must report
`inserted=true` immediately before SIGKILL, without another RPC or delay; the
client-only publication cannot turn this crash-boundary write into a replay.
Provisioning and listeners are reused sequentially, not policy-expanded or
concurrently shared. The test-only fixture uses
an **unprotected non-production provider**; it is not a supported customer
credential backend.

Private configuration/state outlive every owned-process cleanup attempt,
including interrupted startup, shutdown timeout, and output-scanning failure.
If cleanup cannot be confirmed, the checker fails and retains its mode-0700
`aster-agent-process-*` directory under the Python temporary-directory root
(`TMPDIR` when set). Its mode-0600 `process-recovery.json` records unresolved
owned PIDs; paths and process output are not printed. Preserve this directory
until process absence is independently confirmed. PIDs can be reused: the
receipt is recovery information, not authority to signal an arbitrary process.
The original failure remains the reported failure when cleanup also fails.

Protocol-peer and deterministic-clock tests validate client checks, including
slow-response boundaries and cancellation; they do not establish real-agent
durability. Actual process evidence is a separate gate. The stock harness
requires its safe-spawn platform support and must not have that protection
weakened to run on an unsupported Python/platform. A native alternate exercise
is evidence only, never a stock-gate PASS.

No physical network, agent restart during this scenario, power-loss, long-offline,
independent implementation, deployment qualification, protected-provider,
application exactly-once, or production-readiness claim is made. No atomic
requirement credit changes.
