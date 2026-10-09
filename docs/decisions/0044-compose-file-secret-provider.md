# Decision 0044: add a statically composed file-secret provider for Compose

- Status: accepted
- Date: 2026-10-08
- Contract: `aster-compose-secret-store/v1`

## Decision

Aster provides a separate Docker runtime binary with a dedicated Compose
credential provider selected at build time. It accepts configuration schema v2
and reads exactly three fixed, read-only file-backed Compose secret mounts.
The Debian package binary remains unchanged in composition: it uses the
systemd provider and schema v1. There is no runtime provider selector,
raw-bundle fallback, Docker socket access, or Docker Swarm deployment.

Credential administration creates immutable, generation-bound files. Manual
activation runs a no-network/no-state preflight, inspects the rendered model,
uses `docker compose up -d --force-recreate`, and verifies the public generation
through the authenticated status API. Rollback is explicit and valid only
while an external authority says the retained prior generation is still
authorized.

The daemon-free plan validator binds the selected schema-v2 configuration to
`ASTER_AGENT_CONFIG_SHA256`. Preflight and runtime independently hash the exact
mounted bytes they parse and fail closed on mismatch, closing replacement
between plan validation and activation.

The selected deployment unit is one Compose project containing one Aster agent,
one credential generation, one configuration, and one project-scoped state
directory owned by the invoking non-root user. No service runs as container
root or receives added capabilities. Scaling that service is unsupported. Multi-agent site topology and
network qualification are separate from this delivery profile; local
multi-container experiments do not widen its deployment claim.

Release delivery uses a manual-only `workflow_dispatch` matrix on native Linux
`amd64` and `arm64` runners. Each architecture artifact contains both an OCI
archive for provenance and inspection and a Docker-loadable archive for
offline import. Deployment accepts either a registry digest reference or a
verified local `sha256:<content-digest>` image ID. Every service sets
`pull_policy: never`; mutable tags and registry fallback are not part of the
selected profile.

## Why

Some target systems accept only OCI containers and cannot use Aster's selected
systemd credential profile. Ordinary Compose offers a portable file-delivery
mechanism, while static provider composition keeps the deployment boundary
small and avoids weakening the Debian profile.

## Consequences and limits

File-backed Compose secrets are bind mounts, and Compose ignores `uid`, `gid`,
and `mode` controls for them. The host must supply correct ownership, exact
`0400` or `0600` modes, access protection, and encryption where required.
Compose does not inherit systemd host-key encryption or Aster-managed host
custody. The operator or an external credential service owns encrypted
persistent storage, rotation, backup, recovery, retention, rollback
authorization, and destruction/cleanup.

The remaining capability differences from the systemd provider and the
required site-owned lifecycle mechanisms are tracked in
[issue 55](https://github.com/defenseunicorns/aster/issues/55). This delivery
increment documents operator procedures but does not claim to close that gap.

No Docker host profile is qualified. Rootless Docker, Docker Desktop, remote
contexts, user namespace remapping, filesystem/mount variants, and mandatory
access controls are unqualified rather than automatically accepted or rejected
by a runtime harness. Docker-host lifecycle qualification may be added later
as a separately approved effort.
