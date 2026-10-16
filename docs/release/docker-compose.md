# Docker Compose container delivery

This is the operator procedure for Aster's ordinary Docker Compose delivery.
It uses a dedicated, statically composed Compose credential provider. Debian
packages retain the statically composed systemd credential provider and schema
v1 behavior. Docker Swarm and Swarm secrets are excluded.

One invocation of the checked-in Compose model deploys exactly one Aster agent:
one explicit project name, one credential generation, one configuration, and
one user-owned state directory. It is not a scaling template. Do not use
`--scale`, replicas, or a shared project for multiple agents because that would
clone credential and durable-state ownership. A prior two-container local run
was a disposable verification spike, not supported deployment evidence.
Separate Aster deployments may be connected through site-designed networking
and explicit authenticated peer configuration, but that topology is outside
this bounded Compose delivery profile.

No Docker host profile is qualified by this increment. In particular,
rootless Docker, Docker Desktop, remote context deployments, user namespace
remapping, alternate filesystems, and mandatory-access-control combinations
are unqualified. The repository does not automatically reject or approve
those environments: operators must evaluate them before deployment.

## Custody boundary

Compose file-backed secrets are bind mounts. For these sources Compose `uid`,
`gid`, and `mode` controls are ignored, so the host files must already have the
required UID, GID, and exact mode `0400` or `0600`. Compose does not add
encryption at rest or inherit the Debian profile's systemd-managed host key.

Aster validates and consumes one immutable, generation-bound set of three
files. The operator or an external credential service owns encrypted
persistent storage, access protection, rotation, backup, recovery, retention,
rollback authorization, and destruction/cleanup of host copies, snapshots,
backups, swap, and media. Removing a generation is logical cleanup; it is not
a claim of physical erasure.

## Download and verify a release bundle

The normal deployment path does not build Aster locally. A release operator
manually starts the `Build: Compose images` workflow (`workflow_dispatch`) at
the reviewed source revision. Its two native jobs retain separate artifacts:

- `aster-compose-images-amd64-<40-hex-source-revision>` for Linux `amd64`;
- `aster-compose-images-arm64-<40-hex-source-revision>` for Linux `arm64`.

Select the host architecture explicitly. Do not use an artifact built for a
different architecture and do not use QEMU output as release evidence.

```sh
case "$(uname -m)" in
  x86_64) export ASTER_RELEASE_ARCH=amd64 ;;
  aarch64|arm64) export ASTER_RELEASE_ARCH=arm64 ;;
  *) printf 'unsupported release architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
export ASTER_SOURCE_REVISION='<reviewed-40-lowercase-hex>'
export ASTER_WORKFLOW_RUN='<successful-workflow-run-id>'
export ASTER_ARTIFACT_DIR="$(pwd -P)/aster-compose-images-$ASTER_RELEASE_ARCH-$ASTER_SOURCE_REVISION"
mkdir "$ASTER_ARTIFACT_DIR"
gh run download "$ASTER_WORKFLOW_RUN" \
  --repo defenseunicorns/aster \
  --name "aster-compose-images-$ASTER_RELEASE_ARCH-$ASTER_SOURCE_REVISION" \
  --dir "$ASTER_ARTIFACT_DIR"
cd "$ASTER_ARTIFACT_DIR"
sha256sum --check SHA256SUMS
test "$(jq -er '.source_revision' release-manifest.json)" = "$ASTER_SOURCE_REVISION"
test "$(jq -er '.architecture' release-manifest.json)" = "linux/$ASTER_RELEASE_ARCH"
```

For a disconnected deployment host, download on an approved connected staging
system, transfer the complete directory under site policy, and begin on the
deployment host with `sha256sum --check SHA256SUMS`. Checksum verification and
review of the source revision and architecture occur before either Docker
archive is imported. A checksum is not a signature or authorization decision.

The OCI archives retain provenance and static-inspection evidence. The
`.docker.tar` files are the Docker-loadable offline transport. Import both,
then compare Docker's immutable local image ID with the config and selected
manifest digests authenticated in `release-manifest.json`. Docker image-store
implementations may expose either digest as `.Id`:

```sh
docker image load --input "aster-compose-agent-$ASTER_RELEASE_ARCH.docker.tar"
docker image load --input "aster-compose-admin-$ASTER_RELEASE_ARCH.docker.tar"
agent_tag=$(jq -er '.images.agent.transport_tag' release-manifest.json)
admin_tag=$(jq -er '.images.admin.transport_tag' release-manifest.json)
agent_image_id=$(docker image inspect --format '{{.Id}}' "$agent_tag")
admin_image_id=$(docker image inspect --format '{{.Id}}' "$admin_tag")
agent_config_digest=$(jq -er '.images.agent.config_digest' release-manifest.json)
agent_manifest_digest=$(jq -er '.images.agent.manifest_digest' release-manifest.json)
admin_config_digest=$(jq -er '.images.admin.config_digest' release-manifest.json)
admin_manifest_digest=$(jq -er '.images.admin.manifest_digest' release-manifest.json)
case "$agent_image_id" in
  "$agent_config_digest"|"$agent_manifest_digest") ;;
  *) exit 1 ;;
esac
case "$admin_image_id" in
  "$admin_config_digest"|"$admin_manifest_digest") ;;
  *) exit 1 ;;
esac
export ASTER_AGENT_IMAGE_DIGEST="$agent_image_id"
export ASTER_ADMIN_IMAGE_DIGEST="$admin_image_id"
```

These `sha256:<64-lowercase-hex>` values are local image IDs, not mutable
transport tags. `compose.yaml` sets `pull_policy: never` on every service, so a
missing imported image fails locally rather than contacting a registry. Keep
these exports for generation administration, static validation, preflight,
activation, and verification below.

## Developer-only local image builds

Run from a clean committed checkout. The pinned Rust base image is declared in
each Dockerfile. Build secrets supply only the builder CA bundle; never pass
credentials as build arguments, environment variables, or image content.

```sh
docker build --pull=false --progress=plain \
  --secret id=aster_build_ca,src=/etc/ssl/certs/ca-certificates.crt \
  --file docker/compose-agent/Dockerfile.agent \
  --tag aster-compose-agent:local .
docker build --pull=false --progress=plain \
  --secret id=aster_build_ca,src=/etc/ssl/certs/ca-certificates.crt \
  --file docker/compose-agent/Dockerfile.admin \
  --tag aster-compose-admin:local .
```

Registry-based sites may publish or import the images through the site's
registry and record immutable references such as
`registry.example/aster-agent@sha256:<64-lowercase-hex>`. Do not deploy the
local tags above. Both registry digests and verified local image IDs are
immutable deployment inputs; mutable tags remain invalid. The manually
triggered `build-compose-images.yml` workflow is packaging automation, not
runtime qualification. It retains architecture-specific Docker-loadable
archives, digest-pinned OCI archives, and five binary-rooted CycloneDX SBOMs
grouped as the two-binary agent image set and three-binary administration image
set, which includes `asterctl`. Each
SBOM retains its binary component identity, carries the corresponding OCI
digest as an explicit property, passes schema and root/dependency license
checks, and is listed in the release manifest. The bundle also retains
`LICENSE`, notices, `compose.yaml`, the opt-in `compose.remote-mesh.yaml`, the
`agent.example.json` configuration template, and
`aster_compose_delivery.py` validator, their digests, architecture, source
revision, builder versions,
checksums, and build provenance. A repository-owned bounded static
inspector selects the requested Linux `amd64` or Linux `arm64` image manifest
instead of provenance attestations, checks the config and exact scratch
filesystem, and scans
decompressed content plus retained metadata for fixed credential canaries. It
authenticates the OCI layout wrapper's sole inner-index descriptor against the
Buildx `containerimage.digest`; the wrapper `index.json` hash is not substituted
for that digest. It does not run or create a container. Generated
evidence is not included until produced by a successful workflow run and
reviewed. Put plainly: generated evidence is not included until produced; this
document does not fabricate artifact digests or provenance.

## Prepare user-owned deployment paths

Use the invoking user's nonzero numeric identity. All persistent paths remain
owned by that user; this profile requires Docker and Compose access but no host
root or `sudo`; in short, no root is assumed and no sudo is required. Use the
same values for generation creation, preflight, validation, and runtime.

```sh
export ASTER_UID="$(id -u)" ASTER_GID="$(id -g)"
test "$ASTER_UID" -ne 0 && test "$ASTER_GID" -ne 0
export ASTER_DEPLOYMENT_ROOT="$(pwd -P)/aster-site-a"
export ASTER_GENERATION_PARENT="$ASTER_DEPLOYMENT_ROOT/credential-generations"
export ASTER_STATE_DIR="$ASTER_DEPLOYMENT_ROOT/state"
export ASTER_TRANSFER_DIR="$ASTER_DEPLOYMENT_ROOT/transfer"
export ASTER_TOKEN_INPUT="$ASTER_DEPLOYMENT_ROOT/input/client-token"
export ASTER_BUNDLE_INPUT="$ASTER_DEPLOYMENT_ROOT/input/mission.astpb03"
install -d -m 0700 "$ASTER_DEPLOYMENT_ROOT" "$ASTER_GENERATION_PARENT" \
  "$ASTER_STATE_DIR" "$ASTER_TRANSFER_DIR" "$ASTER_DEPLOYMENT_ROOT/input"
chmod 0600 "$ASTER_TOKEN_INPUT" "$ASTER_BUNDLE_INPUT"
```

Protect both inputs under site policy. The generation creator wraps the token
for the provider-aware agent, while Compose mounts the owner-only plaintext
`ASTER_TOKEN_INPUT` only into the one-shot `asterctl` service. The validator
requires this input to be an absolute, singly linked, owner-matched regular
file with mode `0400` or `0600` and valid token contents. Confirm that both
inputs belong to the intended issuance and authorization transaction before
creation.

## Create an immutable generation

Use the verified local admin image ID imported above, or a reviewed registry
digest for a registry-based site. Standard input carries the canonical
`ASTRPB03` bundle; no secret bytes are placed in argv or environment variables.

```sh
: "${ASTER_ADMIN_IMAGE_DIGEST:?set verified local image ID or registry digest}"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$ASTER_UID:$ASTER_GID" \
  --mount "type=bind,src=$ASTER_GENERATION_PARENT,dst=/host/generations" \
  --mount "type=bind,src=$ASTER_TOKEN_INPUT,dst=/host/input/client-token,readonly" \
  --interactive "$ASTER_ADMIN_IMAGE_DIGEST" \
  /usr/local/bin/aster-compose-credential-admin create \
  --output-parent /host/generations \
  --token-file /host/input/client-token < "$ASTER_BUNDLE_INPUT"
```

The sole success line is
`CREATE disposition=created generation=<64-lowercase-hex>`. Select the matching
`generation-<hex>` directory, inspect its non-secret `manifest.json`, and
verify the directory and four files are owned by `$ASTER_UID:$ASTER_GID`.
Credential files must be exactly `0400` or `0600`, singly linked, and unchanged.

```sh
export ASTER_CREDENTIAL_GENERATION_DIR="$ASTER_GENERATION_PARENT/generation-<64-hex>"
chmod 0500 "$ASTER_CREDENTIAL_GENERATION_DIR"
find "$ASTER_CREDENTIAL_GENERATION_DIR" -maxdepth 1 -printf '%u:%g %m %f\n'
```

The host-side `chmod` is idempotent and closes the directory if a desktop
bind-mount implementation did not preserve the creator container's final
`0500` mode. Stop if ownership, file modes, or the validator still disagree.

## Configure and validate without a daemon lifecycle test

Copy the packaged `agent.example.json` to a deployment-owned absolute path,
edit only documented schema v2 values, and select that exact file. Retain the
verified local image IDs imported above, or set reviewed registry digests for
a registry-based site, and choose a unique project name.

```sh
install -m 0644 agent.example.json "$ASTER_DEPLOYMENT_ROOT/agent.json"
export ASTER_AGENT_CONFIG_FILE="$ASTER_DEPLOYMENT_ROOT/agent.json"
sha256sum "$ASTER_AGENT_CONFIG_FILE"
export ASTER_AGENT_CONFIG_SHA256='<reviewed-64-lowercase-hex>'
: "${ASTER_AGENT_IMAGE_DIGEST:?set verified local image ID or registry digest}"
: "${ASTER_ADMIN_IMAGE_DIGEST:?set verified local image ID or registry digest}"
export COMPOSE_PROJECT_NAME=aster-site-a
python3 ./aster_compose_delivery.py ./compose.yaml
docker compose -f ./compose.yaml config --format json \
  > /tmp/aster-compose.rendered.json
```

The validator rejects a missing, relative, unreadable, non-regular, oversized,
or non-schema-v2 configuration file and requires its SHA-256 to equal
`ASTER_AGENT_CONFIG_SHA256`; it records that digest, but not the path, in the
redacted plan. Preflight and the agent hash the exact bytes they parse and fail
closed if Compose later mounts different bytes. The validator also rejects a missing or malformed project name
and records the name. The render command is `docker compose config --format json`;
the explicit file option above selects the checked-in model. Confirm
that the rendered state mount binds the exact reviewed `ASTER_STATE_DIR` to
`/var/lib/aster`, the CLI transfer mount binds the exact reviewed
`ASTER_TRANSFER_DIR` to `/transfer`, and the rendered service and network names
carry the same project prefix. These remain project-qualified Compose resources. Reusing a
project name means intentionally addressing that existing deployment; it never
creates a second agent.

Inspect the render for the two image digests, numeric identity, the exact state
and transfer bind mounts, and exactly three sources below the selected generation. It must not
contain credential bytes, a Docker socket, host namespaces, extra capabilities,
or Swarm `deploy` configuration.

## Run preflight

The validator requires `ASTER_STATE_DIR` and `ASTER_TRANSFER_DIR` to be
absolute, non-symlinked directories owned by `ASTER_UID:ASTER_GID` with exact
mode `0700`. No service runs as container root and no service receives an added
capability.

```sh
docker compose -f ./compose.yaml run --rm preflight
```

The preflight has `network_mode: none`, no state mount, a read-only root
filesystem, the runtime UID/GID, and the same three secret mounts as the agent.
Do not proceed after any preflight failure.

## Activate and verify

```sh
docker compose -f ./compose.yaml up -d --force-recreate aster-agent
docker compose -f ./compose.yaml run --rm verify
docker compose -f ./compose.yaml run --rm asterctl --json status
```

The verify helper makes an authenticated status request and compares the
returned `credential_generation` with the selected manifest. `VERIFY
status=pass` confirms that comparison; it does not authorize rollback or
qualify the host. Never use plain `docker compose restart` for rotation because
restart does not apply changed Compose configuration.

The `asterctl` service uses the same admin image, shares the agent network
namespace, and receives only the selected client token plus the operator-owned
transfer directory. Arguments after the service name replace its default
`status` command while retaining the fixed token-file entrypoint.
See the [operator runbook](../operator-guide.md#3-docker-compose-runbook) for
copyable Event, durable and finite-TTL Blob, and agent-replacement checks using
only these downloaded artifacts.

## Opt in to remote mesh traffic

The default Compose file publishes no host port. For a reviewed physical-peer
test, bind UDP 8183 only to the intended host IPv4 interface and add the shipped
override to all lifecycle commands:

```sh
export ASTER_MESH_BIND_ADDRESS='<reviewed-host-ipv4>'
export ASTER_MESH_PUBLISHED_PORT=8183
docker compose -f compose.yaml -f compose.remote-mesh.yaml config --format json
docker compose -f compose.yaml -f compose.remote-mesh.yaml run --rm preflight
docker compose -f compose.yaml -f compose.remote-mesh.yaml \
  up -d --force-recreate aster-agent
docker compose -f compose.yaml -f compose.remote-mesh.yaml run --rm verify
```

The bind address is required and the published port must be in `1..65535`.
Configure the other Aster node with the host address and published UDP port,
and permit that UDP port in applicable host firewall policy. The override does
not make ZeroTier or any other carrier trusted; Aster authentication remains
required.

## Rotate, roll back, and retain

Create a new immutable generation, rerun static validation, render inspection,
and preflight, then select it and repeat the exact force-recreate and
authenticated verify commands. The state directory remains in place.

Retain the prior generation only for the site's bounded rollback window. An
explicit rollback is allowed only when the authority confirms that the prior
generation is still authorized, unexpired, present, and intact. Select that
directory, rerun preflight, recreate, and verify. Never roll back a revoked,
expired, destroyed, or otherwise unauthorized generation; successful startup
alone is not authorization.

After the reviewed window, stop using the old generation, remove it according
to site retention and cleanup policy, and separately handle backups, snapshots,
logs, and media under the site's destruction procedure. Never delete the state
directory as part of credential rotation.

## Backup, recovery, and incidents

Back up the state directory and credential generations only into the site's
encrypted persistent storage with access controls, audit, restore testing, and
retention appropriate to their classification. Never copy a live database.
Quiesce the one agent, verify that it stopped, and archive only the exact
user-owned paths:

```sh
export ASTER_BACKUP_DIR="$ASTER_DEPLOYMENT_ROOT/encrypted-backups/aster-site-a-20261008"
install -d -m 0700 "$ASTER_BACKUP_DIR"
docker compose -f ./compose.yaml stop -t 40 aster-agent
test -z "$(docker compose -f ./compose.yaml ps --status running -q aster-agent)"
umask 077
tar --acls --xattrs -cpf "$ASTER_BACKUP_DIR/state.tar" -C "$ASTER_STATE_DIR" .
tar --acls --xattrs -cpf "$ASTER_BACKUP_DIR/credential-generation.tar" \
  -C "$ASTER_GENERATION_PARENT" "$(basename "$ASTER_CREDENTIAL_GENERATION_DIR")"
(cd "$ASTER_BACKUP_DIR" && \
  sha256sum state.tar credential-generation.tar > SHA256SUMS)
docker compose -f ./compose.yaml up -d --force-recreate aster-agent
docker compose -f ./compose.yaml run --rm verify
```

Record the project name, image digests, configuration digest, selected
generation name, and `SHA256SUMS` with the backup. The archive is a
logical copy containing classified state or credentials; encryption and media
custody remain site responsibilities.

For a tested restore, first verify both checksums and restore one complete
generation into its private parent. Never merge files from generations. Then
replace only the exact state directory. Preserve the old directory until the
application-level recovery check succeeds:

```sh
(cd "$ASTER_BACKUP_DIR" && sha256sum -c SHA256SUMS)
test ! -e "$ASTER_CREDENTIAL_GENERATION_DIR"
tar --acls --xattrs --same-permissions -xpf \
  "$ASTER_BACKUP_DIR/credential-generation.tar" -C "$ASTER_GENERATION_PARENT"
docker compose -f ./compose.yaml down
test "$(dirname "$ASTER_STATE_DIR")" = "$ASTER_DEPLOYMENT_ROOT"
export ASTER_PRE_RESTORE_STATE="$ASTER_STATE_DIR.before-restore"
test ! -e "$ASTER_PRE_RESTORE_STATE"
mv -- "$ASTER_STATE_DIR" "$ASTER_PRE_RESTORE_STATE"
install -d -m 0700 "$ASTER_STATE_DIR"
tar --acls --xattrs --same-permissions -xpf "$ASTER_BACKUP_DIR/state.tar" \
  -C "$ASTER_STATE_DIR"
docker compose -f ./compose.yaml run --rm preflight
docker compose -f ./compose.yaml up -d --force-recreate aster-agent
docker compose -f ./compose.yaml run --rm verify
```

Successful preflight and generation verification do not replace an
application-level state recovery check. Remove `ASTER_PRE_RESTORE_STATE` only
after that check and the site's recovery policy authorize its cleanup.

For suspected credential disclosure, stop the affected service if policy
requires it, preserve approved forensic evidence without copying secrets into
tickets or logs, revoke the generation through the external authority, issue a
fresh generation, recreate, and verify. Do not use rollback to a revoked
generation. For partial `.staging-` directories, keep them inactive and remove
them only under the site's incident and cleanup procedure.

## Stop, cleanup, and logical destruction

`docker compose down` removes this project's containers and default network but
preserves `ASTER_STATE_DIR`; use it for ordinary service cleanup. Final
decommissioning is a separate authorized action. Stop the exact project,
inspect the exact user-owned path, and only then remove it:

```sh
docker compose -f ./compose.yaml down
test "$(dirname "$ASTER_STATE_DIR")" = "$ASTER_DEPLOYMENT_ROOT"
find "$ASTER_STATE_DIR" -maxdepth 1 -printf '%u:%g %m %f\n'
rm --one-file-system -r -- "$ASTER_STATE_DIR"
```

After the authority confirms that rollback and recovery are no longer allowed,
inspect the exact selected generation path and logically remove only that
directory:

```sh
test "$(dirname "$ASTER_CREDENTIAL_GENERATION_DIR")" = "$ASTER_GENERATION_PARENT"
find "$ASTER_CREDENTIAL_GENERATION_DIR" -maxdepth 1 -printf '%u:%g %m %f\n'
chmod 0700 "$ASTER_CREDENTIAL_GENERATION_DIR"
rm --one-file-system -r -- "$ASTER_CREDENTIAL_GENERATION_DIR"
```

Repeat only for explicitly authorized retained generations. These commands do
not erase encrypted backups, snapshots, logs, swap, storage-controller copies,
or physical media; those remain under the site's destruction procedure.
