# Linux Event MVP operator runbook

> ****

This is the shortest operator path through the currently implemented portions
of the Linux Event evaluation profile. It is for engineering evaluation; open
qualification gates still prevent a profile or release claim.

For a task-oriented packaged installation, authentication, `asterctl`, Event,
and Blob walkthrough written for operators rather than developers, start with
the [human operator guide](../operator-guide.md). This runbook remains the
evidence-bounded Linux Event evaluation procedure.

The 2026-09-15 through 2026-09-16 two-node activity is recorded in the
[direct CI-package record](../validation/evidence/2026-09-15-cm4-ci-package-mvp-validation.md).
Use that record for the exact pass, failure, and unavailable-check boundary;
do not infer additional device results from this runbook.

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
   then the generated Go client. Preserve the numbered publication journal across
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
| Publication capacity is exhausted | Retain the journal and original sequence; drain acknowledged results and inspect configured client limits. |
| Unacknowledged Event returns after restart | Commit idempotently, then acknowledge the stable Event identity. |

Use the [numbered client lifecycle guide](../quickstart/event-client-lifecycle.md)
for capacity inspection, journal recovery, admission tuning and permanent
client retirement. Publication uses a stable client, fenced session and
contiguous sequence, not an unbounded collection of caller-chosen keys.

After an unclean shutdown, preserve the state directory and publication
journals. Let the supported store open and SDK recovery validate retained
state before publishing again. Unsupported historical Event ledgers fail open
without mutation, migration or reset. Do not delete state to bypass a refusal.

The frozen [v0.1 evaluation profile](../validation/linux-event-mvp-evaluation-profile-v0.1.md)
retains its original operation-ledger capacity and qualification requirements;
those results do not qualify numbered publication or the v9 network.

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
Decision 0043 accepts E01's team-internal approval for this bounded MVP
increment; no additional approval is required. E09 packaged lifecycle
qualification remains open. Every semantic operation uses a fresh retained
operation ID; an uncertain result is retried with the identical ID and
identical input.

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
