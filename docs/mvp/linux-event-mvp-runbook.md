# Linux Event MVP operator runbook

> ****

This is the shortest operator path through the currently implemented Linux
Event evaluation profile. It is for engineering evaluation, not production or
release authorization.

## Know the boundary

The repository currently provides the Event application service and its
source-level tests. It supports authenticated status, offline-first publish,
query, durable subscription, poll or stream, acknowledgement, gap inspection,
restart recovery, and restart-selected Normal or ReceiveOnly operation.

The protected provider is already statically composed into `aster-agent`;
see the [provider implementation boundary](../../crates/aster-systemd-credentials/README.md#current-implementation-boundary).
For a first Ubuntu 24.04 amd64 package installation, use the
[provider operations package annex](raspberry-pi-provider-v2-operations.md#ubuntu-2404-amd64-package-annex).
It defines the candidate's service, paths and credential handoff. Native ARM64
and final device qualification remain separate deliverables. Source integration
does not close Security/Deployment approval or packaged acceptance. The local
development path below remains available for API evaluation. Use the documented
candidate procedure; do not invent service names, installed paths, or credential
handoff steps.

## Run the local API smoke test

Use only disposable, non-production provisioning material:

```sh
mise install
ASTER_AGENT_ROOT="$(mktemp -d)"
install -m 600 bindings/testdata/non-production-provisioning.bundle \
  "$ASTER_AGENT_ROOT/mission.unprotected-reference.bundle"
openssl rand -hex 32 > "$ASTER_AGENT_ROOT/client.token"
chmod 600 "$ASTER_AGENT_ROOT/client.token"
```

Start the development adapter in one terminal:

```sh
cargo run --locked -p aster-agent -- \
  --state "$ASTER_AGENT_ROOT/state" \
  --mesh-bind 127.0.0.1:0 \
  --listen 127.0.0.1:8181 \
  --mission-bundle-unprotected-reference \
    "$ASTER_AGENT_ROOT/mission.unprotected-reference.bundle" \
  --client-token-file "$ASTER_AGENT_ROOT/client.token"
```

In another terminal, run:

```sh
./examples/connect_agent.sh "$ASTER_AGENT_ROOT/client.token"
```

A successful run gets status, creates a durable subscription, publishes one
Event while offline, polls it, and acknowledges it. This proves the local API
path only; it is not protected-provider, packaging, physical-transfer, or
release evidence.

## Operate a provider-composed candidate

Use this section only after the OS engineer supplies the exact binary,
configuration, service identity, and supervisor procedure.

1. Validate configuration as the final service user:

   ```sh
   aster-agent --check-config "$ASTER_AGENT_CONFIG"
   ```

   Exit zero is silent validation. It does not prove provider loading or
   readiness.

2. Start the agent with the deployment-owned supervisor procedure. Do not run
   it as root.

3. Require both checks before application traffic:

   ```sh
   curl --fail --silent --output /dev/null http://127.0.0.1:8182/livez
   curl --fail --silent --output /dev/null http://127.0.0.1:8182/readyz
   ```

4. Make an authenticated `GetStatus` call. Confirm the configured emission
   mode, store use, durable operation headroom, and pending-delivery pressure.

5. Run the publish/subscription flow with the generated Rust reference client,
   then the generated Go compatibility client. Preserve operation keys across
   uncertain retries and acknowledge only after the application commits its
   effect durably.

6. Stop with the supervisor procedure and confirm process termination. A
   graceful stop first removes readiness, drains bounded accepted work, and
   preserves durable state for restart.

## Select Normal or ReceiveOnly

Set `mesh.emission_policy` in the strict configuration to `normal` or
`receive_only`, then restart the process. The setting is not reloadable.

ReceiveOnly accepts authenticated inbound mesh work but does not initiate
contacts or disclose locally held Event or control inventory. It is not radio
silence: carrier, authentication, acknowledgement, and response traffic may
still be emitted. Use deployment or network controls when literal silence is
required.

## React to health and capacity

| Observation | Operator action |
| --- | --- |
| `/livez` is unavailable or `503` | Inspect sanitized service telemetry; do not send work. |
| `/readyz` is `503` | Wait for Ready or resolve startup/draining failure. |
| Distinct accepted publish-operation keys reach 512 | Plan intervention; this is the profile warning level, separate from configured-ledger occupancy warnings. |
| Distinct accepted publish-operation keys reach 1,024 | Stop new publication; preserve existing operation keys and the state directory for inspection. |
| Pending deliveries reach 256 | Stop increasing workload and drain or repair consumers. |
| `OPERATION_CAPACITY_EXHAUSTED` | Do not retry with new keys; escalate for controlled recovery. |
| Unacknowledged Event returns after restart | Commit idempotently, then acknowledge the stable Event identity. |

The 1,024-key boundary counts distinct accepted publish-operation keys over the
entire state-directory lifetime, including restarts. It is an operator/harness
stop, not an enforced store admission limit. The
[accepted containment contract](../validation/linux-event-mvp-evaluation-profile-v0.1.md#durable-publish-operation-containment)
selects a separate permanent ledger quota:

- `storage.operations.max_records = 1_000_000` records;
- `storage.operations.max_logical_bytes = 201_326_592` logical ledger and
  reverse-index bytes (192 MiB); and
- `storage.operations.emergency_reserve = 10_000` records, with corresponding
  byte headroom reserved from ordinary publication.

Confirm these configured ceilings and ordinary/emergency headroom in
authenticated `GetStatus`, separately from profile headroom and warning state.
The aggregate Event/control store quota is separate and can stop admission
earlier. These are logical quotas, not physical database-size limits or
qualification of a workload above 1,024 operations. The
[register records the selected capacity boundary](../validation/linux-event-mvp-evaluation-profile-v0.1-register.md#selected-operation-ledger-capacity-boundary).

Configured-ledger exhaustion returns Connect `ResourceExhausted` with
`OPERATION_CAPACITY_EXHAUSTED`, `retryable = false`, and no retry delay. Do not
retry indefinitely or change keys to bypass it. For an unknown publication
outcome, retain the original key and identical intent: exact retries add no
ledger record. An exact retry of a retired operation remains the selected-node
`ExpiredOrRetired` cause (Connect `NotFound` / `MISSING_DURABLE_OBJECT`);
changed intent remains a conflict, and retirement never permits key reuse.

Do not delete or replace the state directory to recover same-mission capacity;
that invalidates durability and restart claims. Preserve it for inspection and
follow the audit procedure below after unclean recovery.

Do not raise limits during a candidate run. A changed limit changes the tested
profile.

## After unclean redb recovery

After any unclean redb storage recovery, stop the service and confirm that no
node process owns the state directory. Before resuming publication, run the
complete offline operation-ledger audit on the recovered v3 store:

```sh
aster inspect --state DIR --audit-event-operations
```

Require a successful command and retain its `EVENT_OPERATION_AUDIT` receipt
with `state=complete` and equal `scanned`/`total` counts. Counts include both
ledger and active reverse-index rows. This complete audit is also required for
release qualification; startup readiness and a background audit still in
progress do not replace it. The inspection command does not repair or migrate
the store. On failure, keep publication stopped and escalate with the sanitized
receipt.

## Reload the application bearer token

Atomically replace the owner-only configured token file, then send `SIGHUP` to
the exact agent process. Verify that the new token succeeds and the old token
fails. A failed reload keeps the old token and Ready state. Mission material,
peers, limits, and emission mode require restart.

## D06 protected-provider lifecycle

The D06 implementation defines these root-operated, stopped-service commands:

```text
aster-credential-admin install --operation HEX64 --load-operation HEX64
aster-credential-admin rotate --operation HEX64 --load-operation HEX64
aster-credential-admin backup --operation HEX64
aster-credential-admin recover --operation HEX64
aster-credential-admin destroy --operation HEX64 --reference HEX
```

The provider code is integrated; use the
[D06 operations procedure](raspberry-pi-provider-v2-operations.md)
for its engineering lifecycle boundary. These command shapes are not yet a
qualified customer package procedure. The final package must define stopping
and termination confirmation, protected input descriptors, reference handoff,
output custody, backup acceptance, readiness checks, and recovery/escalation.
E01 approval and E09 packaged lifecycle qualification remain open. Every semantic
operation uses a fresh retained operation ID; an uncertain result is retried
with the identical ID and identical input.

## Validate a completed candidate bundle

After the owners assemble a canonical candidate body, receipt index, detached
role approvals, and one release decision, validate only those local immutable
bytes:

```sh
python3 tools/check-linux-event-mvp-qualification.py \
  --bundle-root /controlled/candidate-bundle \
  --artifact-root /controlled/candidate-artifacts \
  --body candidate-body.json \
  --index receipt-index.json \
  --approval approvals/profile-product.json \
  --approval approvals/security.json \
  --decision release-decision.json
```

Supply every detached candidate approval with another `--approval`. Omit
`--artifact-root` only when the receipt index has no artifact-root entry. The
validator reads no devices or credentials, makes no network calls, and emits
one sanitized canonical JSON report. Exit 0 means the supplied bundle is
structurally conformant only; it is not a qualification or signature-
verification result. Exit 2 means nonconformant, exit 3 means required local
bytes are unavailable, and exit 70 means the validator itself failed.

## Stop and escalate

Keep the process stopped and preserve sanitized receipts when any of these
occurs:

- provider, credential, executable, package, or configuration identity drift;
- ambiguous or interrupted D06 staging;
- a nonzero administration result whose commit outcome is unknown;
- failed readiness after rotation or recovery;
- unexpected outbound initiation in ReceiveOnly;
- corrupt, incompatible, unreadable, or multiply owned durable state; or
- a capacity stop that cannot be relieved without changing the profile.

For API details, error handling, and shutdown semantics, use the
[Event agent quickstart](../quickstart/connect-agent.md). For the exact evaluation boundary
and acceptance gates, use the
[Linux Event MVP profile](../validation/linux-event-mvp-evaluation-profile-v0.1.md)
and its [candidate annex](../validation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md).
