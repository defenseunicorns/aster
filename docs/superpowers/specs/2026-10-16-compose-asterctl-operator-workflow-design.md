# Compose `asterctl` Operator Workflow Design

## Status and scope

This design extends the evaluation-stage Docker Compose deployment so an
operator can exercise the shipped Aster API without a source checkout, Rust
toolchain, or locally built client image. It advances the adopter surface and
representative DDIL integration tracks. It does not broaden production,
platform, scale, or network-performance claims.

The long-running agent image remains unchanged. The existing
`aster-compose-admin` image gains the statically linked `asterctl` binary, and
the canonical Compose file gains a hardened, one-shot `asterctl` service that
uses that image.

## Artifact and trust boundary

CI builds `asterctl` from the same locked source revision as the agent and
admin helpers. The existing admin OCI and Docker archives contain exactly:

- `aster-compose-credential-admin`;
- `aster-compose-verify`;
- `asterctl`;
- the Aster license and third-party notices.

The OCI inspector, delivery-policy checks, release manifest, checksum set,
credential-canary scan, and binary-level CycloneDX set all enumerate
`asterctl`. No third image or locally built artifact is introduced.

## Compose client service

The canonical `compose.yaml` adds an `asterctl` service with the same runtime
hardening as `verify`: non-root UID/GID, read-only root filesystem, all
capabilities dropped, `no-new-privileges`, bounded PIDs, bounded no-exec
temporary storage, bounded logs, no restart, and `pull_policy: never`.

The service:

- uses `${ASTER_ADMIN_IMAGE_DIGEST:?required}`;
- joins `network_mode: service:aster-agent` so the local agent remains bound
  only inside its existing network namespace;
- depends on the agent health check;
- mounts only the owner-only plaintext token at
  `${ASTER_TOKEN_INPUT:?required}` through a distinct
  `aster-operator-client-token` Compose secret; the generation-bound
  `aster-client-token` remains reserved for the provider-aware agent and
  verifier because it is a protected binary envelope, not CLI input;
- mounts `${ASTER_TRANSFER_DIR:?required}` at `/transfer` for operator Blob
  input and output;
- uses an entrypoint equivalent to
  `asterctl --token-file /run/secrets/aster-client-token` and defaults to
  `status`.

Operators run commands as, for example,
`docker compose run --rm asterctl --json status`. The CLI container receives
neither the provisioning bundle, mission activation, agent configuration, nor
agent state.

## Remote mesh exposure

The default Compose profile continues to expose no host port. A separately
shipped, opt-in override publishes container UDP port 8183 only on an explicit
`${ASTER_MESH_BIND_ADDRESS:?required}` and
`${ASTER_MESH_PUBLISHED_PORT:-8183}`. This allows a local Docker node to peer
with a test device over the host's ZeroTier address without silently widening
the default deployment boundary.

The runbook makes the distinction explicit: `compose.yaml` is local-only;
adding the override deliberately enables inbound mesh traffic on the selected
host interface. The operator must put the published host endpoint in the peer
configuration and permit the UDP port in applicable host policy.

## Operator examples and acceptance

The concise operator runbook covers loading the CI-produced architecture
bundle, setting all required environment variables, creating the transfer
directory, starting and verifying the node, and invoking `asterctl` for:

- status;
- Event publication and query;
- durable Blob publication and read;
- finite-TTL Blob publication and read;
- expected authorization and missing-file failures.

Acceptance uses only the downloaded Compose deployment artifacts. One node is
the local Docker deployment and one is a packaged test device. The retained
test record identifies exact revisions, image and package digests, sanitized
endpoints, commands, and results. It verifies:

1. mutual authenticated contact over the opt-in ZeroTier-bound UDP port;
2. Event movement in both directions;
3. durable Blob movement and byte-for-byte read verification in both
   directions;
4. finite-TTL Blob availability followed by expiry behavior;
5. local Docker agent replacement followed by durable Event and Blob access;
6. bounded transfer measurements for at least one representative Blob, with
   size, elapsed time, throughput, and peak RSS reported without turning the
   observation into a supported-performance claim.

Secrets, mission data, raw private endpoints, and generated binaries are not
committed. If the physical path is unavailable, automated/local validation may
pass but the physical acceptance item remains explicitly pending.

## Compatibility and exclusions

This is additive packaging, Compose, and documentation work. It changes no
wire protocol or public RPC. Existing digest-pinned deployment remains
compatible after adding the required `ASTER_TRANSFER_DIR` variable for the
new service. No production authorization, generalized ZeroTier dependency,
NAT traversal claim, large-Blob threshold, or supported throughput is claimed.
