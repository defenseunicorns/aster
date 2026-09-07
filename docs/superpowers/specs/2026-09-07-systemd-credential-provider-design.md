#

# Ubuntu systemd credential provider design

- Design date: 2026-09-07
- Design status: approved in working session; pending written review
- Profile: `aster-linux-event-mvp-evaluation-v0.1`
- Register row: `P0-1-D06`
- Evidence effect: none

This design selects an Ubuntu-native protected provisioning boundary for the
Linux Event MVP evaluation. It does not close D06, approve an implementation,
or qualify an artifact. D06 remains Open until security and deployment owners
accept the exact provider and administration record. G3 and G4 later bind and
qualify the implemented provider in the exact packages.

## Outcome

The Linux Event service will start from one provider-managed encrypted
credential without placing node or mission plaintext in arguments, environment
values, package layers, logs, ordinary configuration, or persistent plaintext
files.

The selected provider is:

- provider contract: `aster-systemd-credential-store/v1`;
- operating-system provider: Ubuntu 24.04 `systemd-creds` and
  `LoadCredentialEncrypted=` from the systemd 255.4 line;
- protection mode: explicit `--with-key=host`;
- credential name: exactly `aster-provisioning.bundle`;
- runtime integration: one statically composed Aster
  `ProvisioningSecretLoader` reading one named systemd service credential; and
- administration artifact: one root-operated `aster-credential-admin` binary.

The exact Ubuntu package revision, `/usr/bin/systemd-creds` identity, Aster
source commit, provider/admin executable digests, and architecture package
digests are candidate facts. They are frozen in the G2/G3 records and candidate
annex rather than represented as floating `latest` versions.

TPM2 is deliberately outside this evaluation design. The provider must never
use `auto`, `tpm2`, `host+tpm2`, `auto-initrd`, or unauthenticated
`tpm2-absent` selection.

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

`aster-credential-admin` is installed by both architecture packages and is
operated as root. It is the only supported tool for install, rotation, backup,
recovery, and logical destruction.

Secret input is accepted through an already-open input descriptor or standard
input. Secret bytes are never accepted as command arguments, environment
values, or an ordinary plaintext input path. The tool passes the bounded
provider envelope directly to `/usr/bin/systemd-creds encrypt` through a pipe
and requires explicit `--with-key=host` and the fixed credential name.

The administration tool emits only sanitized outcome, opaque reference,
operation disposition, generation, and ciphertext/record digests. It never
prints recovered provisioning plaintext or invokes `systemd-creds decrypt`.

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

The hardened unit always names
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
ledger restore, and snapshot rollback are outside v0.1.

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
- missing host key or encrypted credential;
- use of a protection mode other than `host`;
- authentication, embedded-name, envelope, reference, operation, generation,
  length, or canonical-bundle mismatch;
- reused operation ID with different input;
- retired or destroyed reference;
- unsafe ownership, mode, type, link count, mount classification, symlink, or
  path traversal;
- ledger/ciphertext disagreement or unsynchronized state;
- unsupported systemd/Aster provider version; or
- any provider output that would require echoing sensitive detail.

Runtime failure occurs before readiness, listener creation, database creation,
or Blob-store creation. Administrative failure returns a sanitized typed
result and preserves the last committed state.

## Trust boundary and explicit non-claims

The trusted computing base is the Ubuntu kernel, PID 1/systemd, the root
administrator, `/usr/bin/systemd-creds`, the systemd host credential key, the
protected host filesystem, the provider/admin binaries, and the running Aster
service process.

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

The exact packaged provider must retain all of the following on each required
architecture where applicable:

1. install success, exact idempotent retry, and changed-input conflict;
2. unattended activation, secure credential classification, exactly one load,
   and readiness only after successful bundle validation;
3. missing host key/ciphertext, corrupt authentication, wrong embedded name,
   wrong reference/operation/generation, unsafe filesystem state, tombstone,
   and every forbidden protection-mode rejection;
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
    environment values, logs, packages, images, ordinary configuration,
    ciphertext, or retained receipts;
11. removal of the systemd runtime credential after service deactivation;
12. exact provider/admin/systemd/source/package/SBOM/notices/provenance
    identity and digest binding; and
13. the complete seven-operation procedure executed through the packaged
    administration binary and hardened systemd unit.

Same-host unit or namespace tests may prepare and regress the mechanism. G4
qualification requires the unchanged G3 artifacts on the declared physical
Ubuntu `x86_64` and `aarch64` targets. Evidence must distinguish those classes.

## Version and artifact binding

D06 selects the systemd 255.4 credential interface on Ubuntu 24.04 and Aster
provider contract v1. The D06 approval record binds this design digest and the
accepted upstream/provider identity. It does not treat Ubuntu security updates
as implicitly qualified.

One candidate annex records:

- exact Ubuntu `systemd` binary package name, version, architecture, and
  package digest;
- `/usr/bin/systemd-creds` digest and reported version;
- Aster source commit and provider/admin source paths;
- `.deb`, executable, unit, configuration, ledger-schema, SBOM, notice, and
  provenance digests; and
- the exact commands and receipts for every lifecycle and negative test.

Package or provider drift creates a new G3 candidate and invalidates dependent
G4/G5 evidence. A future provider-contract change requires a new versioned D06
decision rather than silent compatibility.

## Ownership and sequencing

- Security and deployment owners approve the D06 provider identity, trust
  boundary, administration artifact, recovery scope, limitations, and
  acceptance plan.
- The provisioning implementation owner builds the loader, administration
  binary, ledger, and tests behind the accepted core contracts.
- The OS/artifact owner composes the exact provider and unit into both G3
  packages and records provenance.
- The integration/device owner runs G4 lifecycle and negative acceptance on
  the declared targets.
- The release owner verifies all immutable identities, receipts, and
  limitations before G6.

The provider implementation may proceed after the D06 design is accepted, but
D06 closes only through the reviewed security/deployment decision record. The
implementation does not by itself close D06, E09, G3, G4, or any production
requirement.

## Alternatives not selected

### Existing age adapter plus a host identity file

This would reuse an existing encrypted format but leave the decrypting identity
in an ordinary host file and still omit the persistent SecretStore lifecycle.
It conflicts with the accepted v0.1 exclusion and moves rather than resolves
the custody problem.

### TPM2-backed systemd credentials

This provides a stronger hardware binding but is excluded because the current
CM5 evaluation devices expose only a software module and TPM setup would add
schedule and operational risk without representative hardware assurance.

### Root-only plaintext file on an encrypted filesystem

This is operationally simple but requires persistent plaintext outside the
provider-managed runtime surface and cannot satisfy the profile.

### Kernel keyring or desktop secret service

These add boot-persistence, headless-service, recovery, or administrative
workflow work without improving the accepted Ubuntu evaluation boundary. They
may be reconsidered for a later platform profile.

## Public primary sources

Accessed 2026-09-07:

- [systemd system and service credentials](https://systemd.io/CREDENTIALS/)
- [Ubuntu 24.04 `systemd-creds` manual](https://manpages.ubuntu.com/manpages/noble/man1/systemd-creds.1.html)

These sources describe the public operating-system provider only. The Aster
provider envelope, operation ledger, procedures, acceptance, and limitations
in this design are independently authored project work.
