# Aster ordinary Docker Compose profile

This directory defines the first bounded Linux Docker Engine profile for the
Compose credential provider. It uses ordinary file-backed Compose secrets, not
Docker Swarm. The runtime image is `scratch`, runs as numeric UID/GID 10001 by
default, has no shell or administration command, and receives exactly three
fixed credential mounts. Application and health listeners stay on container
loopback; only the separate mesh listener is exposed to the Compose network.

`compose.yaml` is intentionally canonical JSON-form YAML: JSON is a YAML subset
accepted by Docker Compose. The daemon-free validator validates only the exact
checked-in canonical JSON encoding and its strict object model. General YAML,
aliases, merge keys, duplicate keys, and semantically equivalent rewrites are
outside that validation boundary.

The host generation files must already be owned by the invoking user's nonzero
runtime UID/GID and mode `0400` or `0600`. Compose does not enforce `uid`, `gid`,
or `mode` for file-backed secrets. The generation directory and exact
user-owned `ASTER_STATE_DIR` remain in the site's custody boundary. Use a unique
Compose project name for each isolated deployment; the validator requires and
records that name but does not create persistent host paths.
One project deploys exactly one agent; it is not valid to scale the service or
share its credential generation and state directory with another agent. Multiple
agents require separate deployment projects and separately designed site
networking, which this profile does not qualify. The validator does not execute
Compose, inspect a Docker host, validate project cleanup, or qualify lifecycle
behavior.

No Docker host profile is qualified. Rootless Docker, Docker Desktop, remote
contexts, user namespace remapping, and other host variants are unqualified;
there is no runtime harness that automatically accepts or rejects them. Docker
Swarm is excluded. See the complete [manual operator procedure](../../docs/release/docker-compose.md).

## Example image build commands

Run these commands from the repository root. Dependency download by the pinned
Rust builder requires build-network access and the host's managed CA bundle.
BuildKit presents that bundle as a build secret only for the Cargo step; it is
not retained in a layer, and no network tooling enters either final image.

```sh
docker build --pull=false --network=default --progress=plain --secret id=aster_build_ca,src=/etc/ssl/certs/ca-certificates.crt --file docker/compose-agent/Dockerfile.agent --tag aster-compose-agent:local .
docker build --pull=false --network=default --progress=plain --secret id=aster_build_ca,src=/etc/ssl/certs/ca-certificates.crt --file docker/compose-agent/Dockerfile.admin --tag aster-compose-admin:local .
```

## Example static image inspection commands

```sh
docker image inspect aster-compose-agent:local --format '{{json .Config}}'
docker image inspect aster-compose-admin:local --format '{{json .Config}}'
docker history --no-trunc aster-compose-agent:local
docker history --no-trunc aster-compose-admin:local

agent_container=$(docker create aster-compose-agent:local)
docker export "$agent_container" --output /tmp/aster-compose-agent-local.tar
docker rm "$agent_container"
tar -tf /tmp/aster-compose-agent-local.tar

admin_container=$(docker create aster-compose-admin:local /usr/local/bin/aster-compose-verify)
docker export "$admin_container" --output /tmp/aster-compose-admin-local.tar
docker rm "$admin_container"
tar -tf /tmp/aster-compose-admin-local.tar
```

The agent configuration must report user `10001:10001`. The exported runtime
filesystem must contain only `aster-agent`, `aster-compose-healthcheck`, the
license, and notices. It must not contain `/bin/sh`, a package database,
systemd units or libraries, `aster-compose-credential-admin`, a compiler, a
Cargo cache, or credential fixtures. The admin image contains only its two
commands plus the same notices; neither image may contain generation files or
secret fixtures.

## Render and operate

Copy `agent.example.json` to a deployment-owned absolute path and set
`ASTER_AGENT_CONFIG_FILE` to it. Record its SHA-256 and set the exact reviewed
value as `ASTER_AGENT_CONFIG_SHA256`; preflight and the agent both fail closed
if the mounted bytes differ. Also set `ASTER_UID`, `ASTER_GID`, `ASTER_STATE_DIR`,
`ASTER_AGENT_IMAGE_DIGEST`, `ASTER_ADMIN_IMAGE_DIGEST`,
`ASTER_CREDENTIAL_GENERATION_DIR`, and a unique
`COMPOSE_PROJECT_NAME`. The image
variables must contain immutable digest references such as
`registry.example/aster-agent@sha256:<64-hex>`. The daemon-free validator
rejects mutable tags before it emits a redacted plan.
Render and inspect before activation:

```sh
docker compose -f docker/compose-agent/compose.yaml config --format json
docker compose -f docker/compose-agent/compose.yaml run --rm preflight
docker compose -f docker/compose-agent/compose.yaml up -d --force-recreate aster-agent
docker compose -f docker/compose-agent/compose.yaml run --rm verify
```

Credential rotation always uses `up -d --force-recreate`. `docker compose
restart` is not a supported rotation operation because it does not apply a new
Compose configuration. Preflight has no network and no state mount. Verification
shares only the agent network namespace, receives the generation-bound client
token and selected non-secret manifest, and has no state-directory access.

All services run as the invoking user's numeric UID/GID with every capability
dropped. The operator creates `ASTER_STATE_DIR` with mode `0700`; the validator
rejects missing, relative, symlinked, differently owned, or differently moded
paths. No host root or `sudo` access is part of this profile.
