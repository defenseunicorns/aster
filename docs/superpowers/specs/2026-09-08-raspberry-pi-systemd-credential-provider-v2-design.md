#

# Raspberry Pi systemd credential provider v2 design

- Design date: 2026-09-08
- Status: Approved for the amended Linux Event MVP profile
- Profile: `aster-linux-event-mvp-evaluation-v0.1`
- Register row: `P0-1-D06`
- Provider contract: `aster-systemd-credential-store/v2`
- Evidence effect: none

This design expands the D06 boundary incorporated into the
[current Linux Event MVP profile](../../implementation/linux-event-mvp-evaluation-profile-v0.1.md).
It resolves D06 for the amended profile definition; it does not approve an
implementation or qualify an artifact. Security and Deployment E01 approval of
the exact design digest remains required; profile approval does not replace
it. G3/G4 later bind and qualify the implemented provider in the exact package.

The earlier Ubuntu v1 design remains unchanged historical material and does
not qualify v2. This design supersedes
its platform, provider-contract, architecture-package, target-acceptance, and
artifact-binding selections for the amended profile. The runtime loader,
administration binary, provider ledger, seven-operation lifecycle,
backup/recovery, rotation, revoke/rekey, logical destruction, atomicity,
failure-path, and nondisclosure rules below retain their v1 semantics.

## Outcome and exact platform boundary

The Linux Event service will start from one provider-managed encrypted
credential without placing node or mission plaintext in arguments, environment
values, package layers, logs, ordinary configuration, or persistent plaintext
files.

| Dimension | Required value |
|---|---|
| Image | Raspberry Pi reference 2026-06-18 |
| Distribution | Debian GNU/Linux 13 (trixie) |
| Hardware/architecture | Raspberry Pi Compute Module 4 Rev 1.1 / aarch64 |
| Kernel | `6.18.39+rpt-rpi-v8` |
| systemd | `257.13-1~deb13u1` |
| Credential executable | `/usr/bin/systemd-creds` |
| Filesystem | ext4 |
| Package | Native `arm64` `.deb` |
| TPM2 | excluded |

v2 supports only this exact amended profile, not generic Debian or Raspberry
Pi OS. Other hardware models, image/kernel revisions, architectures, VMs,
containers, and cross-distribution portability require a later profile
revision with separate artifacts and evidence. The candidate annex must
revalidate and freeze the environment on every participating device; the
observations recorded in the approved amendment are design inputs, not G4/G5
qualification receipts.

The selected provider is:

- provider contract: `aster-systemd-credential-store/v2`;
- operating-system provider: the exact systemd package and executable above;
- mandatory encrypted service integration: `LoadCredentialEncrypted=`;
- mandatory host-key-backed protection mode: explicit `--with-key=host`;
- credential name: exactly `aster-provisioning.bundle`;
- runtime integration: one statically composed Aster
  `ProvisioningSecretLoader` reading one named systemd service credential; and
- administration artifact: one root-operated `aster-credential-admin` binary.

G3 freezes the exact systemd package, `/usr/bin/systemd-creds` executable,
hardened unit, provider/admin binaries, Aster source commit, and native `arm64`
package identities and digests. These are candidate facts recorded in the
G2/G3 records and candidate annex, never floating versions.

TPM2 is deliberately outside this evaluation design. The provider must never
use `auto`, `tpm2`, `host+tpm2`, `auto-initrd`, or unauthenticated
`tpm2-absent` selection. No hardware-TPM, software-TPM, secure-element, or
production protected-provisioning claim follows from this selection.

## Existing mechanisms and reuse

The current `aster-provisioning-age` crate remains an engineering artifact
protector/unprotector. It does not own persistent key custody, install/load/
destroy operations, unattended startup, backup/recovery, or an operational
administration path. It is not a fallback for this provider.

The `aster-core` provider-neutral types and contracts are retained:

- `ProvisioningSecretRef`;
- `ProvisioningInstallId`, `ProvisioningLoadId`, and
  `ProvisioningDestroyId`;
- `ProvisioningSecretInstaller`, `ProvisioningSecretLoader`, and
  `ProvisioningSecretDestroyer`;
- checked install/load/destroy receipt validation;
- zeroizing plaintext ownership; and
- the fixed sanitized error taxonomy.

The in-memory `PersistentTestSecretStore` remains a contract fixture. It is not
packaged or adapted into the operational provider.

## Components and ownership

### Runtime loader

`aster-systemd-credentials` is a small first-party crate statically composed
into the profile's `aster-agent` executable. It implements only the runtime
capability needed by the agent: `ProvisioningSecretLoader`.

The loader:

1. receives the expected opaque reference and load-operation identifier from
   validated, owner-controlled non-secret configuration;
2. opens the fixed named credential relative to `CREDENTIALS_DIRECTORY` using
   descriptor-relative, no-follow operations;
3. verifies the runtime file is regular, single-link, mode `0400`, owned by the
   service identity, and backed by the secure systemd credential filesystem;
4. reads at most the Aster plaintext limit exactly once;
5. verifies the provider envelope's version, reference, operation identifier,
   generation, and inner length;
6. returns an Aster-owned zeroizing `ProvisioningLoadReceipt`; and
7. maps every failure to a fixed Aster category without logging paths,
   references, identifiers, systemd output, or plaintext.

The runtime does not invoke `systemd-creds`, search credential stores, select a
provider, or try another path. PID 1 authenticates and decrypts the named
credential before process startup.

### Administration binary

`aster-credential-admin` is installed by the native `arm64` package and remains
the root-operated administration boundary. It is the only supported tool for
install, rotation, backup, recovery, and logical destruction.

Secret input is accepted through an already-open input descriptor or standard
input. Secret bytes are never accepted as command arguments, environment
values, or an ordinary plaintext input path. The tool passes the bounded
provider envelope directly to `/usr/bin/systemd-creds encrypt` through a pipe
and requires explicit `--with-key=host` and the fixed credential name.

The administration tool emits only sanitized outcome, opaque reference,
operation disposition, generation, and ciphertext/record digests. It never
prints recovered provisioning plaintext or invokes `systemd-creds decrypt`.
Secret bytes never enter local APIs, logs, status, or retained receipts.

### Provider operation ledger

A root-owned provider ledger at
`/var/lib/aster/provisioning-systemd/ledger` stores:

- schema and provider version;
- install, load, and destroy operation bindings;
- opaque reference and generation;
- active/retired/destroyed state;
- credential-name and ciphertext digest;
- a root-only SHA-256 commitment to the canonical provider envelope for exact
  install-retry comparison;
- backup identity and restore disposition; and
- durable destruction tombstones.

It contains no provisioning plaintext, age identity, bearer token, or host
credential key. The provider-envelope commitment is treated as sensitive
root-only metadata and never enters logs, public receipts, or application
status. Because the canonical bundle contains high-entropy mission key
material, this exact commitment does not expose a reusable credential, but it
is not treated as public. Root ownership, exact file type/mode checks,
single-filesystem atomic rename, file synchronization, and parent-directory
synchronization form the v0.1 ledger trust boundary.

An unknown reference remains indeterminate `NotFound`. Only a committed exact
tombstone returns `Destroyed`. A tombstone is a trusted backend assertion of
logical destruction, not proof of flash sanitization or physical erasure.

## Provider data flow

### Persistent state

- The systemd host credential key remains at its system-managed location under
  `/var/lib/systemd/credential.secret`.
- One root-owned `/etc/aster/provisioning/active` generation directory contains
  `credential.cred`, `reference`, and `manifest` regular files. The credential
  file contains only authenticated ciphertext. The reference and manifest
  contain only the opaque reference, generation, fixed load-operation
  identifier, provider/schema identity, and file digests.
- The provider ledger contains only the bounded operation metadata described
  above at `/var/lib/aster/provisioning-systemd/ledger`; its
  provider-envelope commitment remains sensitive root-only metadata.

The hardened unit always uses `LoadCredentialEncrypted=` to name
`/etc/aster/provisioning/active/credential.cred` as the encrypted source for
credential `aster-provisioning.bundle`. The strict agent configuration always
names `/etc/aster/provisioning/active/reference`. Neither path contains or
names plaintext. A staged generation is a sibling directory on the same local
`ext4` filesystem. Initial install renames a fully synchronized staged
directory to `active`; rotation atomically exchanges the complete staged and
active directories with Linux `renameat2(RENAME_EXCHANGE)` after all contained
files and the parent directory are synchronized.

### Service activation

PID 1 reads and authenticates the encrypted credential with the host key. It
places the plaintext credential in the service-specific systemd credential
directory and starts the unprivileged Aster service. The Aster loader validates
and reads the credential once before state, listeners, or readiness exist.

The credential directory is an accepted provider-managed ephemeral runtime
surface, even though it has a regular-file interface. It is not an ordinary
persistent or configuration file. Qualification requires systemd to classify
the credential storage as `secure`; `weak` or `insecure` storage refuses the
candidate.

Systemd releases the service credential on deactivation. Aster separately
zeroizes allocations that it owns; it does not claim complete systemd, kernel,
allocator, or process-memory erasure.

## Seven-operation lifecycle

### 1. Install a protected reference

The administrator supplies one bounded `ASTRPB03` bundle through a protected
input descriptor and one caller-selected install operation ID. The tool:

1. validates the input before durable mutation;
2. creates a new opaque reference and generation;
3. produces the versioned provider envelope in zeroizing memory;
4. invokes `systemd-creds encrypt --with-key=host
   --name=aster-provisioning.bundle`;
5. writes ciphertext to a same-directory temporary file;
6. synchronizes and atomically installs the ciphertext, reference metadata,
   and operation record; and
7. returns a sanitized install receipt.

An exact retry compares the root-only provider-envelope commitment and returns
the existing reference. Reusing the operation ID with different input returns
`OperationConflict`. No plaintext temporary file is created.

### 2. Load at startup

Systemd must decrypt/authenticate the exact credential before launching the
service. The loader verifies the expected reference, operation, generation,
runtime-file security, provider-envelope bounds, and canonical inner bundle.
It is invoked exactly once after configuration prechecks and before durable
state or listeners are opened.

Missing, corrupted, insecure, mismatched, retired, or destroyed material fails
closed. There is no raw-bundle, age, old-generation, or second-provider
fallback.

### 3. Rotate the application bearer token

The application bearer token remains separate from mission provisioning. The
administrator atomically replaces its owner-only token file and sends
`SIGHUP`. The running Event agent reloads only that token. Failed validation
keeps the prior token active and exposes only a sanitized error.

No service credential, provider reference, mission generation, or process
restart changes during bearer rotation.

### 4. Rotate the mission/provider reference

The administrator builds a complete new generation directory containing the
encrypted credential, opaque reference, and manifest, atomically exchanges it
with `active`, then performs a controlled restart. Startup must prove the new
generation before readiness. Only after the new service is ready may the old
reference be retired and logically destroyed.

An interrupted preparation leaves the old complete generation active. Once the
new generation is committed, startup never silently falls back to the old
generation.

### 5. Back up and recover

v0.1 supports same-host recovery only. Backup copies the authenticated
ciphertext plus its non-secret manifest and digest. It does not export
plaintext, the systemd host key, or the provider ledger.

Recovery restores an exact previously recorded active ciphertext only on the
same host with the unchanged systemd host key and an intact provider ledger.
The tool rejects a digest mismatch, an absent operation record, a retired or
destroyed reference, a generation rollback, or a missing/different host key.

Complete host loss, OS reinstallation, host-key backup, cross-device restore,
ledger restore, and snapshot rollback are outside v0.1. The optional spare CM4
does not widen this same-host recovery contract.

### 6. Revoke and rekey

The administrator stops the affected nodes, uses the profile's authority
workflow to create a new roster/key generation without the removed node,
installs the new protected reference on every remaining node, and restarts
them. The removed node's local reference is logically destroyed when the node
is under administrator control.

Qualification proves the removed credential fails subsequent mission
authentication. This is a stopped-node operational sequence, not live
membership mutation, automatic revoke-plus-rekey, or proof that a captured
host erased every copy.

### 7. Logically destroy

The administrator stops and confirms termination of the service, prepares and
synchronizes a destroyed-generation directory containing the exact reference's
durable tombstone but no credential, atomically exchanges it with `active`,
synchronizes the parent directory, and verifies a subsequent startup fails
before the agent process reaches readiness.

An exact retry returns `AlreadyDestroyed`. An unknown reference remains
`NotFound` and cannot be promoted to a destruction receipt. The operation makes
no physical-media, copy-on-write, backup, swap, or snapshot-erasure claim.

## Atomicity and failure contract

Every administration mutation uses a staged same-filesystem generation. The
active credential, reference, and manifest switch together through one atomic
directory install or exchange. The ledger uses intent and completion records
to reconcile a crash before or after that switch. A crash or injected failure
at any boundary must leave either the complete prior active generation or the
complete new active generation. Partial ciphertext, reference, operation, or
tombstone state is never treated as active.

The following conditions fail closed:

- unavailable or changed `/usr/bin/systemd-creds` identity;
- missing host credential key or encrypted credential;
- plaintext fallback, absence of `LoadCredentialEncrypted=`, or use of a
  protection mode other than `host`;
- decrypt failure, authentication failure, wrong credential name, or embedded
  name, envelope, reference, operation, generation, length, or canonical-bundle
  mismatch;
- reused operation ID with different input;
- retired or destroyed reference;
- wrong owner/mode, unsafe type, link count, mount classification, symlink, or
  path traversal;
- ledger/ciphertext disagreement or unsynchronized state;
- package/interface drift or unsupported systemd/Aster provider version; or
- any provider output that would require echoing sensitive detail.

Runtime failure occurs before readiness, listener creation, database creation,
or Blob-store creation. Administrative failure returns a sanitized typed
result and preserves the last committed state.

## Trust boundary and explicit non-claims

The trusted computing base is the exact reference-image kernel, PID 1/systemd,
the root administrator, `/usr/bin/systemd-creds`, the systemd host credential
key, the protected host filesystem, the provider/admin binaries, and the
running Aster service process.

The design protects against unprivileged local access, accidental plaintext in
packages/configuration/logs, and offline ciphertext access without the host
credential key. It does not protect against:

- root, PID 1, kernel, or running-service compromise;
- live process-memory or service-credential inspection by the trusted root;
- theft of both the host filesystem and host credential key;
- TPM, Secure Boot, measured boot, attestation, or hardware non-exportability;
- FIPS 140-3 validation;
- complete host or provider-ledger loss;
- filesystem/snapshot rollback resistance;
- physical erasure or recovery from copied media; or
- a production or general-platform secret-store claim.

The profile is already non-FIPS and evaluation-only. These residuals are
declared limitations, not implied production acceptance.

## Acceptance and retained evidence

G4 repeats the complete lifecycle and negative acceptance below on both
mandatory physical CM4 nodes, using the unchanged G3 `arm64` package and exact
amended environment:

1. install success, exact idempotent retry, and changed-input conflict;
2. unattended activation, secure credential classification, exactly one load,
   and readiness only after successful bundle validation;
3. missing host key/ciphertext, decrypt failure, corrupt authentication, wrong
   embedded name, wrong reference/operation/generation, unsafe filesystem
   state including wrong owner/mode, tombstone, plaintext fallback, absent
   encrypted unit integration, package/interface drift, and every forbidden
   protection-mode rejection;
4. bearer-token replacement and atomic `SIGHUP` reload without provisioning
   or process restart;
5. controlled mission-reference rotation, restart, new-generation readiness,
   and refusal of the destroyed prior reference;
6. same-host ciphertext backup/recovery with the unchanged host key, plus
   rejection of rollback, wrong-host-key, missing-ledger, retired, and
   destroyed cases;
7. stopped-node revoke/rekey with subsequent rejection of the removed
   credential;
8. logical destroy, idempotent destroy retry, indeterminate unknown reference,
   reboot-persistent tombstone, and fail-closed subsequent startup;
9. crash injection at every ciphertext, reference, ledger, and tombstone
   commit boundary, proving old-or-new atomicity;
10. canary inspection proving no provisioning plaintext in process arguments,
    environment values, local APIs, status, logs, packages, images, ordinary
    configuration, ciphertext, or retained receipts;
11. removal of the systemd runtime credential after service deactivation;
12. exact provider/admin/systemd/source/package/SBOM/notices/provenance
    identity and digest binding; and
13. the complete seven-operation procedure executed through the packaged
    administration binary and hardened systemd unit.

Same-host unit or namespace tests may prepare and regress the mechanism. They
do not qualify the physical targets. The optional third CM4 is a spare or
declared support participant; its role must be recorded if used, and its
results cannot substitute for either mandatory node's complete acceptance.
Replacing a mandatory node changes the inventory and reruns affected cases.
Missing or failed evidence records a failed or not-run gate, never a pass.

## Version and artifact binding

D06 selects the systemd `257.13-1~deb13u1` credential interface on the exact
Raspberry Pi reference 2026-06-18 environment and
`aster-systemd-credential-store/v2`. The profile record binds this design's
SHA-256. Candidate gate E01 separately binds Security and Deployment approvals
of that exact digest, trust boundary, and accepted upstream/provider identity.
It does not treat security updates as implicitly qualified.

One candidate annex records:

- exact image, distribution, hardware, architecture, kernel, and local `ext4`
  filesystem identity revalidated from every participating device;
- exact `systemd` binary package name, version `257.13-1~deb13u1`, `arm64`
  architecture, and package digest;
- `/usr/bin/systemd-creds` digest and reported version;
- Aster source commit and provider/admin source paths;
- native `arm64` `.deb`, executable, unit, configuration, ledger-schema, SBOM,
  notice, and provenance digests; and
- the exact commands and receipts for every lifecycle and negative test.

G3 freezes these exact package, executable, unit, and provider identities;
G4 accepts them unchanged on both mandatory physical nodes. Package or provider
drift creates a new G3 candidate and invalidates dependent G4/G5 evidence.
Image, distribution release, hardware model, architecture, systemd interface,
filesystem, or kernel drift requires candidate review before qualification
continues. A future provider-contract change or broader platform requirement
requires a redesigned and versioned D06 decision rather than silent
compatibility.

## Ownership and sequencing

- Security and Deployment owners approve the exact candidate design digest,
  provider identity, trust boundary, administration artifact, recovery scope,
  limitations, and acceptance plan at E01.
- The provisioning implementation owner builds the loader, administration
  binary, ledger, and tests behind the accepted core contracts.
- The OS/artifact owner composes the exact provider and unit into the one G3
  native `arm64` package and records provenance.
- The integration/device owner runs G4 lifecycle and negative acceptance on
  both mandatory physical CM4 nodes.
- The release owner verifies all immutable identities, receipts, and
  limitations before G6.

This approved design resolves D06 for the amended profile definition. The
provider implementation may proceed only in its separate delivery lane. This
record does not by itself close E01, E09, G3, G4, or any production requirement,
and no candidate may qualify without the required Security and Deployment
approvals.

## Alternatives not selected

### Existing age adapter plus a host identity file

This would reuse an existing encrypted format but leave the decrypting identity
in an ordinary host file and still omit the persistent SecretStore lifecycle.
It conflicts with the accepted v0.1 exclusion and moves rather than resolves
the custody problem.

### TPM2-backed systemd credentials

TPM2 remains excluded by the approved amendment. No hardware-TPM, software-TPM,
or secure-element assurance is included in this exact CM4 evaluation boundary.

### Root-only plaintext file on an encrypted filesystem

This is operationally simple but requires persistent plaintext outside the
provider-managed runtime surface and cannot satisfy the profile.

### Kernel keyring or desktop secret service

These add boot-persistence, headless-service, recovery, or administrative
workflow work without improving the accepted exact reference-image evaluation
boundary. They may be reconsidered for a later platform profile.

## Source and historical binding

This record uses repository design inputs and the user-authorized device facts
recorded in the approved amendment. It adds no external provider-validation or
hardware-qualification evidence.

- Historical Ubuntu v1 design SHA-256:
  `078c35f0046c62a7415d4e8c843f198f97da898da8b8b17eebeaa98de3e2a781`.
- Approved Raspberry Pi amendment SHA-256:
  `9a39c4179e437ea8174aa4bc190e70875dbb36df2e13962ce436d9c8b545064e`.

The historical Ubuntu v1 public-source review is not systemd 257 package or
interface qualification for this v2 design. E01 and G3/G4 must establish the
exact amended provider's identity, behavior, and evidence as specified above.
