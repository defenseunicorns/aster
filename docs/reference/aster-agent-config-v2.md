# Aster agent configuration schema v2

Schema v2 is accepted only by the Docker `aster-agent` binary built from
`aster-compose-credentials`. That binary has the dedicated Compose credential
provider statically selected and has no runtime provider selector or systemd
credential dependency. The Debian/package `aster-agent` retains schema v1 and
the statically selected systemd provider; it rejects schema v2.

The canonical example is
[`docker/compose-agent/agent.example.json`](../../docker/compose-agent/agent.example.json).
The deployment records the reviewed file digest in
`ASTER_AGENT_CONFIG_SHA256`. Both no-network preflight and runtime hash the
exact bytes they parse and reject a missing, malformed, or mismatched digest,
so replacing the selected file after plan validation cannot silently change
the activated configuration.
One schema-v2 configuration belongs to exactly one agent deployment, credential
generation, and user-owned state directory. Replicating one Compose service would clone that
ownership and is unsupported. Explicit peers may connect separately deployed
agents only through site-designed networking outside this bounded profile.
The top-level object rejects unknown fields and contains:

| Field | Required behavior |
| --- | --- |
| `schema_version` | Integer `2`. |
| `state.directory` | Fixed deployment value `/var/lib/aster` in the Compose profile. |
| `application.listen` | Loopback application endpoint; the example uses `127.0.0.1:8181`. |
| `health.listen` | Separate loopback lifecycle endpoint; the example uses `127.0.0.1:8182`. |
| `mesh` | Mesh bind address, bounded synchronization interval, emission policy, optional exact `blob_interests`, and explicit peers. |
| `credentials.client_token_file` | Exactly `/run/secrets/aster-client-token`. |
| `credentials.mission_activation_file` | Exactly `/run/secrets/aster-mission-activation`. |
| `storage` | Bounded item, payload, operation-record, logical-byte, reserve, and optional Blob-depot limits. |

Schema v2 uses the same Blob receive and depot rules as
[schema v1](aster-agent-config-v1.md): absent or empty
`mesh.blob_interests` receives no Blob network work; a nonempty list accepts at
most 256 unique canonical exact `TOPIC@SCOPE` selectors and requires explicit
nonzero `storage.blob_depot.max_bytes`, `max_chunks`, and `max_variants`.
Malformed, descendant/wildcard, duplicate canonical, and oversized selector
sets fail validation. Supplying depot limits with empty interests is valid and
bounds local Blob publication.

Selectors are restart-only receive policy, not mission authority or application
subscriptions. Mission route/content authorization remains authoritative, and
authenticated peers can observe the exact configured topic/scope interest
metadata under the current policy. `receive_only` retains the validated
configuration for a later normal-mode restart but performs zero Blob network
work. Public Blob API access, mesh receive interests, and the separate Rust
application-subscription surface are independent.

The canonical example deliberately uses an empty interest list and explicit
depot limits. To opt in, replace that array with values such as
`"imagery.maps@mission/team/alpha"` only after reviewing mission authorization
and metadata exposure. Older Compose agents reject both new fields as unknown;
rollback must restore the prior configuration bytes and update the reviewed
`ASTER_AGENT_CONFIG_SHA256` together with the executable rollback.

The provisioning envelope path is fixed by the Compose provider at
`/run/secrets/aster-provisioning-bundle`; it is not configurable. All three
files must belong to one generated credential generation. The token,
activation, and envelope carry matching generation bindings and fail closed if
mixed.

Schema v2 changes only the credential composition needed for the container
profile. It does not make Compose a custody service, permit inline secrets,
enable file watching or live credential replacement, or alter mission/network
authorization. Rotation selects a complete new generation and uses `docker
compose up -d --force-recreate` followed by authenticated generation
verification. See the [operator procedure](../release/docker-compose.md).
