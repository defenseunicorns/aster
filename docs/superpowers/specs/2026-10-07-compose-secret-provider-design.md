# Docker Compose secret provider design

- Status: approved design, pending implementation plan
- Date: 2026-10-07
- Initial deployment profile: Linux Docker Engine with ordinary `docker compose up`
- Provider contract: `aster-compose-secret-store/v1`

## Intent

Aster must be deliverable as OCI container images to sites that accept Docker
containers but cannot adopt the selected systemd credential provider. The
first container profile uses ordinary Docker Compose file-backed secrets. It
does not require systemd in the image or on the host, Docker Swarm, Kubernetes,
or a site-specific secret service.

Success means that a non-root `aster-agent` starts from an immutable image,
loads a versioned mission credential and client bearer token from explicitly
granted Compose secrets, retains durable Aster state across container
recreation, and fails closed before opening any listener when the credential
boundary is invalid. Secret rotation recreates the container with a complete
new immutable generation. The profile makes no stronger claim about Compose
secret custody than Docker's implementation supports.

## Scope

This increment provides:

- a Docker-only `aster-agent` runtime image;
- a Compose-specific implementation of Aster's existing
  `ProvisioningSecretLoader` boundary;
- a strict activation format that binds one mission reference, load operation,
  generation, and provisioning bundle;
- an administration image that creates immutable host-side credential
  generations without passing secret bytes in arguments or environment
  variables;
- an ordinary Compose deployment and a no-state, no-network credential
  preflight;
- recreate-based activation, explicit rollback, and bounded cleanup
  procedures; and
- retained tests and delivery metadata for the exact evaluated Docker Engine,
  Docker Compose, image, and host profile.

The following are out of scope:

- Docker Swarm and Swarm secrets;
- Kubernetes, OpenShift, Vault, HSM, TPM, or cloud secret-store integration;
- live mission-credential replacement;
- in-place mutation or file watching of a mounted Compose secret;
- zero-downtime rotation or concurrent agents sharing one durable state;
- encrypted-at-rest host storage supplied by Aster;
- automatic rollback or rollback to a revoked generation;
- Windows containers, Docker Desktop, remote Docker contexts, and a production
  claim beyond the exact evaluated Linux profile; and
- replacement or relaxation of the existing systemd provider for package
  deployments.

## Selected approach

The provider is selected at build time, not at runtime. The package build keeps
the systemd provider. The Docker build contains the Compose provider and omits
the systemd credential dependency and administration executable. The build
fails if the `aster-agent` binary selects both providers or neither provider.
There is no runtime provider name, provider search path, fallback, or
unprotected customer mode in the Docker image.

The default source build may continue to select the systemd feature to avoid
changing the package contract. The Dockerfile disables default features and
selects only the Compose provider. Provider-neutral runtime and mesh code
continue to depend on `ProvisioningSecretLoader`; the Docker integration does
not introduce provider bytes into mesh messages or the canonical `ASTRPB03`
bundle.

The Compose profile uses agent configuration schema version 2. Schema version
2 replaces version 1's separate `mission_secret_ref_file` and inline
`mission_load_id` fields with one fixed `mission_activation_file`. The
activation secret carries both values, so rotating a credential does not
require editing mission or network configuration. The Docker build accepts
schema version 2 and rejects version 1. The systemd package build continues to
accept version 1 and rejects version 2. This is build-bound schema admission,
not runtime provider selection.

The operator records the reviewed schema-v2 file digest in
`ASTER_AGENT_CONFIG_SHA256`. The daemon-free plan validator requires it to
match the selected file, and both Compose preflight and runtime hash the exact
bytes they parse before credential loading. A replaced or changed config fails
closed instead of activating bytes different from the reviewed plan.

## Components

### Compose credential crate

A new isolated crate implements `ProvisioningSecretLoader` for the Compose
profile. It owns:

- fixed-path secret opening and metadata validation;
- canonical activation and provider-envelope parsing;
- cross-file generation, reference, and load-operation binding;
- bounded bundle recovery into Aster-owned zeroizing storage; and
- fixed sanitized error mapping.

The crate has no Docker socket access and does not invoke the Docker CLI. It
does not create, rotate, destroy, or search for secrets at runtime.

### Runtime image

The runtime image contains the Compose-built `aster-agent`, its required
licenses and notices, and the smallest health/readiness helper justified by the
accepted runtime contract. It does not contain a package manager, shell,
systemd executable, systemd unit, systemd credential crate, credential
administration command, compiler, or build cache.

The service runs as a nonzero numeric UID and GID selected by the deployment.
Its root filesystem is read-only. All Linux capabilities are dropped,
`no-new-privileges` is set, no Docker socket is mounted, and only the declared
application, health, mesh, state, temporary, configuration, and secret paths
exist. Persistent Aster state is one absolute bind-mounted directory owned by
the invoking non-root user with exact mode `0700`. Temporary storage is bounded
`tmpfs`. Logs use a bounded Docker logging policy. No service runs as container
root or receives an added capability; the operator creates and removes the
state directory using ordinary-user filesystem access.

### Administration image

A separate administration image creates one new generation in an
operator-mounted output parent. It reads the canonical mission bundle from
standard input and reads the client token from an explicitly named,
owner-protected input file. Secret bytes never appear in command arguments,
environment variables, stdout, stderr, or the generation manifest.

The command creates a private staging directory on the same filesystem as the
generation parent, writes each file with restrictive creation flags, syncs the
files, atomically renames the completed staging directory to its final unique
generation name, and syncs the parent directory. It refuses an existing final
name and never edits an existing generation. Partial staging directories are
reported with a fixed recovery category and are never activated.

### Compose deployment

The Compose deployment grants exactly three secrets to the runtime service and
maps them to fixed targets:

| Secret | Container target |
| --- | --- |
| Client bearer token | `/run/secrets/aster-client-token` |
| Mission activation | `/run/secrets/aster-mission-activation` |
| Provisioning bundle envelope | `/run/secrets/aster-provisioning-bundle` |

One required `ASTER_CREDENTIAL_GENERATION_DIR` interpolation variable selects
the host directory supplying all three files. The variable contains a path,
not secret bytes. Compose configuration validation must reject an unset or
empty value. A generation-specific env file may carry this path for operator
convenience, but it contains no credential material.

Compose's `uid`, `gid`, and `mode` fields are not treated as security controls
for this profile because Docker Compose silently ignores them for file-backed
secrets. The host files must already be owned by the runtime's numeric UID and
must be mode `0400` or `0600`. The preflight and runtime enforce those facts.

## Credential formats and binding

Every administration operation generates a fresh random generation ID,
reference ID, and load-operation ID. The mission activation and provisioning
envelope are separate canonical binary formats under the
`aster-compose-secret-store/v1` contract. Both carry the provider version,
generation ID, reference ID, and load-operation ID. The provisioning envelope
also carries the exact bounded canonical `ASTRPB03` bundle.

The activation parser constructs the existing Aster
`ProvisioningSecretRef` and `ProvisioningLoadId`. The provider accepts the
provisioning envelope only when every duplicated field is an exact match for
the activation. It rejects unknown versions, reserved-field changes,
noncanonical lengths, trailing data, an invalid inner bundle, or any mixed
generation. There is no raw-bundle fallback.

The envelope is a binding and framing format, not encryption or a signature.
Its checks prevent accidental cross-wiring, truncation, and substitution by an
untrusted container process that cannot modify the read-only mounts. They do
not protect against a compromised host root user or Docker daemon. The host
custody policy is responsible for integrity and confidentiality before Docker
mounts the files.

The non-secret generation manifest records the provider version, generation
identifier, creation time, bounded file sizes, and cryptographic digests used
for operator comparison and retained evidence. The manifest is not accepted as
runtime authorization and is never a substitute for checking the mounted
files. Sites that classify credential commitments as sensitive must protect
the manifest with the generation directory.

## Startup data flow

1. Compose resolves all three secret sources from one generation directory and
   creates the non-root runtime container.
2. The agent parses and validates schema version 2 without opening state or a
   listener.
3. The startup credential layer opens the token and activation at their fixed
   paths and validates their file boundaries.
4. The Compose provider opens the provisioning envelope at its fixed path and
   performs the same boundary validation.
5. The activation and envelope are parsed and cross-checked. The provider
   returns one `ProvisioningLoadReceipt` containing Aster-owned zeroizing
   plaintext only after the exact reference and load operation match.
6. Existing node bootstrap consumes the canonical bundle. Only after complete
   credential and node bootstrap does Aster bind health, application, and mesh
   listeners.
7. Ready status exposes the public generation identifier through
   the authenticated status surface and fixed lifecycle output. It exposes no
   path, reference, operation ID, token, envelope, digest of plaintext, or
   bundle content.

Client-token and mission rotation are intentionally one recreate operation in
this profile. The existing SIGHUP token reload is not part of the Compose
contract because an atomically replaced host source can leave a file bind
mount attached to the old inode, while in-place writes undermine immutable
generation handling.

## File and mount validation

Every secret is opened by descriptor with close-on-exec, no final-symlink
following, and nonblocking behavior. Before and after each bounded read, the
implementation verifies:

- the object is a regular file with exactly one link;
- its owner is the agent's effective nonzero UID;
- its mode is exactly owner-read-only `0400` or owner-read/write `0600`, with
  no group, other, or execute bit;
- the containing secret mount is read-only;
- the file size is within the format-specific public bound; and
- device, inode, owner, mode, link count, size, and modification identity did
  not change during the read.

The provider validates the fixed `/run/secrets` parent and refuses relative
paths, alternate roots, symlinked final entries, FIFOs, devices, directories,
hard links, writable mounts, and unsupported platforms. It does not infer
security from a filename or from Compose labels. Validation failures map to
fixed public categories and never include OS error text.

This increment does not qualify a Docker host profile or retain a Docker
acceptance receipt. Operators must verify the documented ownership, mode, and
read-only mount requirements on their target systems. Automated host
qualification may be added later as a separate, explicitly scoped effort.

## Activation and rotation

The supported activation procedure is:

1. Create a fresh generation with the administration image.
2. Run the Compose credential preflight against that generation with no
   network, no durable state mount, a read-only root filesystem, and the same
   runtime UID/GID and security options as the service.
3. Render and inspect the Compose model. Confirm that all three sources resolve
   beneath the selected generation directory and no secret bytes appear in the
   rendered model.
4. Run `docker compose up -d --force-recreate` for the Aster service. A plain
   `docker compose restart` is prohibited because it does not apply changed
   Compose configuration.
5. Wait for readiness, call the authenticated status surface, and compare the
   observed public generation identifier with the selected manifest.
6. Retain the prior generation only for the site's reviewed rollback window,
   then remove it according to host policy.

The runtime state directory remains mounted across recreation. The agent's
existing exclusive state ownership prevents two generations from running
against one state simultaneously. Ordinary Compose provides no rolling
handoff; the accepted first profile therefore has a bounded interruption
between old-container shutdown and new-container readiness.

## Failure and rollback

A failed generation creation never changes an existing generation. A failed
preflight never contacts the running service or its state. Missing files,
invalid host permissions, writable mounts, mixed generation data, malformed
formats, and provider-binding mismatches fail before activation.

If the recreated service fails startup, it remains unready and reports only a
fixed lifecycle category. Compose may apply a bounded restart policy for
transient runtime failures, but credential-validation failures must not form an
unbounded retry loop. The operator either corrects the new generation or
explicitly selects a still-authorized prior generation and recreates the
service again.

Rollback is prohibited when the previous credential was revoked, destroyed,
expired, or otherwise no longer authorized. Aster never automatically chooses
an older generation and never searches sibling directories. Removing a host
generation is a site custody action; Aster does not claim physical erasure,
snapshot removal, backup removal, or Docker-daemon sanitization.

The Compose provider cannot independently discover a revocation decision held
outside its mounted generation. The site procedure and generation-retention
policy enforce that prohibition. Existing Aster mission/state bindings may
reject an incompatible old credential, but a successful startup is not proof
that rollback was authorized.

## Error contract and logging

The provider maps all failures to Aster's existing bounded secret-store and
startup categories, adding only fixed distinctions needed for operator action
such as invalid mount boundary, invalid activation, generation mismatch, and
unsupported platform. Public errors contain no backend string or dynamic
filesystem value.

Debug representations redact every credential-bearing type. Tests inspect
stdout, stderr, lifecycle output, health output, Docker logs, and generated
manifests for known fixture values. Crash and forced-stop paths receive the
same inspection. The runtime never logs secret source paths because all three
container targets are fixed by contract.

## Verification

### Unit and component checks

- canonical round trips and rejection of every noncanonical field, bound, and
  trailing byte;
- exact operation, reference, provider-version, and generation binding;
- wrong-provider, wrong-generation, and mixed-file rejection;
- symlink, FIFO, device, directory, hard-link, owner, mode, writable-mount,
  oversized-file, truncation, and changed-during-read rejection;
- zeroization of Aster-owned plaintext and partial buffers on success and every
  failure path;
- fixed redacted errors and debug output; and
- compile checks proving the Docker binary cannot include both providers,
  neither provider, or an unprotected customer provider.

### Docker-host qualification deferred

No real-Docker lifecycle or host-qualification harness is part of this
increment. The repository provides daemon-free semantic validation and clear
manual build, deployment, preflight, rotation, rollback, and cleanup
instructions. A future qualification effort may automate those instructions
against an explicitly selected Linux Docker profile.

### Delivery evidence

The deliverable retains image digests, OCI archives, architecture identity,
SBOMs, dependency graphs, license notices, build provenance, the Compose file
digest, and the administration-image digest. Images are referenced by digest
in the release Compose example. No Docker Engine, Compose implementation,
filesystem, mount, user-namespace, or mandatory-access-control profile is
qualified by this increment.

## Relationship to current work

The Event query-prefilter work reviewed as PR 44 does not alter deployment or
credential custody. The `asterctl` work reviewed as PR 45 consumes the client
bearer token but does not provide mission provisioning or remove the agent's
systemd loader. Neither PR satisfies this design. The Compose provider should
remain a focused capability increment and should not be coupled to either PR's
merge.

## Security claims and residuals

This profile claims bounded, fail-closed ingestion of explicitly granted,
host-protected Compose secret files into a non-root Aster container. It claims
that secret bytes are absent from the image, Compose YAML, command arguments,
environment variables, and normal logs. It claims exact cross-file generation
binding and no systemd dependency in the Docker runtime artifact.

It does not claim that ordinary Compose encrypts secrets, stores them in
memory-only filesystems, remaps their ownership, rotates them dynamically, or
protects them from host administrators. Host root, the Docker daemon, source
files, filesystem encryption, swap, snapshots, backups, audit collection, and
media sanitization remain in the site trust boundary. A container compromise
can read the secrets granted to that container. The agent retains provisioning
plaintext in its process for the lifetime required by the selected node, under
the existing Aster memory and zeroization limits.

## Public sources

Accessed 2026-10-07:

- [Docker Compose service secrets](https://docs.docker.com/reference/compose-file/services/#secrets)
  documents fixed `/run/secrets` targets and that `uid`, `gid`, and `mode` are
  silently ignored for file-backed secrets because Compose uses bind mounts.
- [Docker Compose top-level secrets](https://docs.docker.com/reference/compose-file/secrets/)
  documents file and environment sources; this design uses only file sources.
- [`docker compose restart`](https://docs.docker.com/reference/cli/docker/compose/restart/)
  documents that configuration changes are not applied by restart, which is
  why activation uses recreation.

These public Docker sources define the replaceable deployment boundary only.
