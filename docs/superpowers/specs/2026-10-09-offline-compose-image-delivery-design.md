# Offline multi-architecture Compose image delivery design

- Status: approved design, pending implementation plan
- Date: 2026-10-09
- Architectures: Linux `amd64` and Linux `arm64`
- Trigger: manual `workflow_dispatch` only

## Intent

Aster's Compose delivery must be consumable on a disconnected Docker host
without compiling Aster or depending on a container registry. An operator
downloads the artifact for the host architecture, verifies the retained
checksums, imports the agent and administration images into Docker, and runs
the existing one-agent Compose deployment.

Success means that one manually triggered workflow produces independently
downloadable `amd64` and `arm64` bundles. Each bundle is architecture-bound,
contains Docker-loadable images and the existing OCI inspection evidence, and
supports an immutable local image reference accepted by the daemon-free
deployment validator. The workflow remains packaging automation rather than
Docker-host qualification.

## Scope

This increment provides:

- native Linux `amd64` and Linux `arm64` builds on the same GitHub-hosted
  runner classes used by Aster's architecture-specific package workflows;
- one separately named, retained artifact per architecture and source commit;
- Docker-loadable agent and administration image archives for offline use;
- OCI archives retaining BuildKit provenance and static-inspection inputs;
- architecture-bound release manifests, SBOM bindings, checksums, and build
  records;
- immutable local Docker image-ID references in addition to registry digest
  references; and
- an explicit download, checksum, import, configuration, preflight,
  activation, and verification procedure.

The following remain out of scope:

- publishing images to GHCR or another registry;
- a bundled or temporary registry service;
- Docker Swarm, Kubernetes, or multi-agent Compose scaling;
- cross-architecture emulation as release evidence;
- macOS or Docker Desktop deployment qualification;
- automatic host architecture selection or artifact download; and
- expansion of the qualified Docker-host claims.

## Selected approach

The manual Compose packaging workflow uses a two-entry matrix. Linux `amd64`
runs on `ubuntu-24.04`; Linux `arm64` runs on `ubuntu-24.04-arm`. Each matrix
entry performs a native Buildx build for one exact `linux/<architecture>`
platform and uploads one artifact named
`aster-compose-images-<architecture>-<source-revision>`.

Each image uses two cache-sharing native Buildx invocations because the Docker
exporter cannot represent the provenance attestation manifest list emitted by
the OCI build:

1. a provenance-enabled OCI-layout archive used for provenance retention,
   static filesystem and configuration inspection, and manifest-digest
   binding; and
2. a provenance-disabled Docker-loadable archive carrying a deterministic
   release tag for import with `docker image load`.

The workflow binds the Docker archive's config blob to the OCI build's
authenticated config digest. After load, it requires the local image ID to
equal that config digest or the authenticated selected-manifest digest because
Docker image stores expose one of those content identities. These gates prove
that the two transports contain the same runnable image before upload.

The bundle retains both because a Docker archive is the operator-facing
offline transport while the OCI archive is the stronger release-inspection
surface. Operators do not need Buildx, Rust, Skopeo, a registry, or network
access on the deployment host.

## Immutable image references

Registry deployments continue to use
`registry.example/name@sha256:<manifest-digest>`. Offline deployments use the
Docker image content ID reported after import, written as
`sha256:<64-lowercase-hex>`. Both forms are content-addressed and immutable.
Mutable tags remain forbidden as Compose deployment inputs.

The release manifest records, for each image, the OCI index digest, selected
image-manifest digest, config digest, CI-observed Docker image ID, OCI archive
filename, Docker archive filename, and deterministic transport tag. The
documented import procedure verifies that `docker image inspect` resolves the
authenticated config or selected-manifest digest after loading each archive.
The transport tag is only an import aid and is never the deployed reference.

All Compose services declare `pull_policy: never`. A deployment using a local
image ID therefore fails locally when the image is absent and never falls
back to a registry. The daemon-free validator accepts only the existing
registry-digest syntax or exact local-image-ID syntax.

## Bundle contract

Each architecture artifact contains:

- `aster-compose-agent-<architecture>.oci`;
- `aster-compose-admin-<architecture>.oci`;
- `aster-compose-agent-<architecture>.docker.tar`;
- `aster-compose-admin-<architecture>.docker.tar`;
- four binary-rooted CycloneDX SBOMs bound to the corresponding image and
  architecture;
- `compose.yaml` and `agent.example.json`;
- `release-manifest.json` and the two Buildx metadata records;
- `BUILD-PROVENANCE.txt`, `LICENSE`, and `THIRD_PARTY_NOTICES.md`; and
- `SHA256SUMS` covering every other retained file.

Artifact names, inner filenames, manifest architecture values, image config
architecture, selected OCI descriptor platforms, and runner architecture must
agree. A mismatch fails before upload. Each artifact has the existing 14-day
retention period.

## Operator data flow

1. Manually download exactly one artifact matching the Docker host's
   architecture.
2. Verify all retained files with `sha256sum --check SHA256SUMS`.
3. Confirm the manifest's architecture and source revision against the
   intended release.
4. Import both Docker archives with `docker image load`.
5. Inspect both imported images and compare their IDs with the authenticated
   config or selected-manifest digests in the release manifest.
6. Set `ASTER_AGENT_IMAGE_DIGEST` and `ASTER_ADMIN_IMAGE_DIGEST` to those
   `sha256:<content-digest>` values.
7. Run the existing static validator, rendered-Compose review, preflight,
   force-recreate activation, and authenticated verification sequence.

The import operation does not create or modify credential generations, Aster
state, or configuration. Those remain under the existing Compose custody and
lifecycle procedures.

## Validation and failure behavior

The static OCI inspector receives an explicit allowed architecture and
requires it in both the selected platform descriptor and image configuration.
It continues to inspect exact scratch filesystem contents, image configuration,
provenance association, descriptor closure, and fixed credential canaries.
Unexpected but benign BuildKit tar metadata may be accepted only when its
meaning is understood, represented in a regression fixture, and constrained
to the exact safe value. The current `layer-entry-invalid` workflow failure is
resolved under that rule rather than by broadly ignoring metadata.

The delivery-policy suite checks the exact two-entry native runner matrix,
manual-only trigger, architecture-specific outputs and artifact names, both
archive forms, manifest fields, checksum coverage, `pull_policy: never`, and
the two accepted immutable-reference syntaxes. It rejects mutable tags,
unsupported architectures, QEMU release builds, registry publication, hidden
lifecycle execution, and omitted static inspection.

The manually triggered workflow is the end-to-end release test. For each
architecture it builds both images, validates all SBOMs, inspects both OCI
archives, imports both Docker archives into the runner's Docker daemon,
compares imported image IDs with the release manifest, and only then uploads
the bundle. It does not start Aster or claim that the runner qualifies a
production Docker host.

## Security and operational boundaries

Docker-loadable archives are executable release artifacts. Checksum
verification and source-revision review happen before import. OCI provenance,
SBOMs, and static inspection remain retained evidence; a checksum alone is not
a signature or an authorization decision.

Local image IDs eliminate mutable-tag substitution after import, but the
Docker daemon and host remain inside the site's trusted computing boundary.
This design does not add image signing, encrypted artifact transport,
revocation, host qualification, or physical media controls. Existing
credential custody, backup, recovery, rotation, and logical-destruction
responsibilities are unchanged.
