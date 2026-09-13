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
The customer ARM64 package, hardened systemd unit, package-owned credential
handoff, and final device qualification remain separate deliverables. Source
integration does not close Security/Deployment approval or packaged acceptance.
Until those artifacts are frozen, use the local development path below or the
OS engineer's explicitly identified candidate package. Do not invent service
names, installed paths, or credential handoff steps.

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
| Publish-operation rows reach 512 | Plan intervention; this is the profile warning level. |
| Publish-operation rows reach 1,024 | Stop new publication and preserve existing operation keys. |
| Pending deliveries reach 256 | Stop increasing workload and drain or repair consumers. |
| `OPERATION_CAPACITY_EXHAUSTED` | Do not retry with new keys; escalate for controlled recovery. |
| Unacknowledged Event returns after restart | Commit idempotently, then acknowledge the stable Event identity. |

The 1,024-key boundary is an operator/harness stop, not an enforced store
admission limit. Actual operation-mapping ceilings are 4,096 rows / 512 KiB;
aggregate quotas can reject work earlier. The
[register records the unresolved release-planning request for hard rejection at 1,024](../implementation/linux-event-mvp-evaluation-profile-v0.1-register.md#unresolved-release-planning-capacity-conflict).
Do not treat that request as implemented behavior or change the accepted
profile without its owners' decision.

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
[D06 operations procedure](../implementation/raspberry-pi-provider-v2-operations.md)
for its engineering lifecycle boundary. These command shapes are not yet a
qualified customer package procedure. The final package must define stopping
and termination confirmation, protected input descriptors, reference handoff,
output custody, backup acceptance, readiness checks, and recovery/escalation.
E01 approval and E09 packaged lifecycle qualification remain open. Every semantic
operation uses a fresh retained operation ID; an uncertain result is retried
with the identical ID and identical input.

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
[Event agent quickstart](connect-agent.md). For the exact evaluation boundary
and acceptance gates, use the
[Linux Event MVP profile](../implementation/linux-event-mvp-evaluation-profile-v0.1.md)
and its [candidate annex](../implementation/linux-event-mvp-evaluation-profile-v0.1-annex-template.md).
