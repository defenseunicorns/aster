#

# Raspberry Pi systemd credential provider v2 operations

- Profile: `aster-linux-event-mvp-evaluation-v0.1`
- Provider: `aster-systemd-credential-store/v2`
- Status: code-level operator procedure; package and target qualification open

This procedure coordinates the seven provider and Event-agent operations that
exist in the current source tree. The five `aster-credential-admin` command
forms below are exact and executable. The repository does not yet contain the
hardened systemd unit or native package, so the package-owned unit name,
installed executable paths, configuration path, and readiness address are not
invented here. The G3 candidate annex must supply those values and the exact
stop, start, termination-confirmation, and readiness commands before this can
be used as a packaged qualification procedure.

This is an evaluation-only procedure for the exact Raspberry Pi reference
2026-06-18 / Debian 13 / CM4 Rev 1.1 / `aarch64` / kernel
`6.18.39+rpt-rpi-v8` / systemd `257.13-1~deb13u1` / local ext4 profile. It is
not a general Debian, Raspberry Pi, or systemd procedure.

## Rules shared by every operation

`aster-credential-admin` is a root-operated, stopped-service administration
tool. Except for bearer-token reload, stop the Event agent and use the
deployment procedure to confirm that its process has terminated before an
administration command. Keep it stopped after any nonzero result until the
result has been reconciled or escalated. Never run two administration commands
concurrently.

The package must have created these fixed root-owned mode-`0700` directories on
local ext4 before the first operation:

```text
/etc/aster/provisioning
/var/lib/aster/provisioning-systemd
```

The service integration must use `LoadCredentialEncrypted=` for
`/etc/aster/provisioning/active/credential.cred`, name the runtime credential
exactly `aster-provisioning.bundle`, and configure the agent's
`mission_secret_ref_file` as
`/etc/aster/provisioning/active/reference`. The configured
`mission_load_id` must equal the load-operation ID used for the Active
generation. These are package-integration requirements, not artifacts shipped
by the current crate.

For every new semantic provider operation, the authorized operator system
allocates a fresh 32-byte operation ID, renders it as exactly 64 lowercase hex
characters, and retains it with the operation type and authorized input. Do
not print IDs, references, bearer tokens, or input bytes into tickets, logs, or
this procedure. If an invocation is interrupted, times out, or loses its
output, retry with the exact same operation ID and exact same input. Never
guess whether it committed, and never reuse that ID for changed input or a
different operation. The provider retains operation bindings; changed-input
reuse fails with `OperationConflict`.

Install and rotate also bind their exact load-operation ID. Retain it with the
operation and keep the Active generation's agent configuration equal to it.
An exact install/rotate retry returns `existing` while its generation is Active
or Previous; after its exact reference is destroyed, that retry returns the
sanitized Destroyed error rather than recreating it.

Install and rotation accept one canonical `ASTRPB03` bundle only on standard
input. Supply it from an already-open authorized descriptor; do not place
plaintext in an argument, environment value, command transcript, package,
ordinary file, or log. In the examples, descriptor 3 is already open on the
exact authorized bundle. No example credential bytes, IDs, or references are
provided.

The exact command grammar is:

```text
aster-credential-admin install --operation HEX64 --load-operation HEX64 < ASTRPB03
aster-credential-admin rotate --operation HEX64 --load-operation HEX64 < ASTRPB03
aster-credential-admin backup --operation HEX64 > protected-backup.bin
aster-credential-admin recover --operation HEX64 < protected-backup.bin
aster-credential-admin destroy --operation HEX64 --reference HEX
```

Install, rotate, recover, and destroy write their one success line to stdout.
Backup writes artifact bytes only to stdout, flushes them, and writes its one
status line to stderr. Parser, input, provider-open, and provider-operation
failures write no stdout and write only `ERROR ` plus a fixed sanitized error
to stderr. Output transports are not transactional: a later write, flush,
broken-pipe, or backup-status error can leave partial or complete stdout even
though the command exits nonzero. Treat *all* stdout from every nonzero
invocation as invalid and discard it. A nonzero result can follow a committed
operation, so retain the operation ID and retry exactly rather than issuing a
new request.

The complete fixed error lines are:

```text
ERROR provisioning secret store is unavailable
ERROR provisioning secret store rejected the request
ERROR provisioning secret reference is invalid
ERROR provisioning secret value exceeds its size limit
ERROR provisioning secret operation conflicts with its durable record
ERROR provisioning secret reference was not found
ERROR provisioning secret store reports the secret destroyed
```

## 1. Install a protected reference

1. Stop the service and confirm termination through the deployment-owned
   supervisor procedure. Enter the authorized root maintenance context with
   descriptor 3 supplying the canonical bundle.
2. Run the exact command:

   ```sh
   aster-credential-admin install \
     --operation "$INSTALL_OPERATION" \
     --load-operation "$LOAD_OPERATION" <&3
   ```

3. On first success stdout is exactly:

   ```text
   INSTALL disposition=installed generation=1 reference=HEX
   ```

   An exact retry instead reports `disposition=existing` with the same
   generation and reference. Retain the returned opaque reference in the
   authorized root-only operation record: it is the exact future rotation or
   destruction input. Do not copy it into general logs.
4. Confirm that the package configuration points to the fixed Active reference
   path and contains this generation's exact load-operation ID. The repository
   configuration checker is side-effect-free:

   ```sh
   aster-agent --check-config "$ASTER_AGENT_CONFIG"
   ```

   Success is silent with exit code zero. This check validates configuration
   and credential-file form; it does not open the provider or prove startup.

## 2. Load the Active reference at startup

1. Use the deployment-owned start procedure. PID 1 must authenticate and
   decrypt the encrypted credential before launching the unprivileged agent.
   The loader checks the exact reference, load operation, generation, runtime
   file security, provider envelope, and canonical inner bundle once, before
   state or listeners open.
2. Use the deployment-owned readiness check and proceed only after `/readyz`
   reports HTTP 200. Missing, corrupt, insecure, mismatched, retired, or
   destroyed material must prevent readiness; there is no raw-bundle, age,
   old-generation, or alternate-provider fallback.

## 3. Rotate only the Event-agent bearer token

This is the only operation performed while the Event agent remains running.
Use the configured bearer-token path and the atomic owner-only replacement
procedure in the [Event agent quickstart](../quickstart/connect-agent.md#reload-and-stop)
and [configuration reference](../reference/aster-agent-config-v1.md#credential-files).
Create the replacement in the same protected directory, preserve the service
owner and mode `0600` or stricter, and atomically rename the completely written
regular file over the configured path. Never put token bytes in arguments,
environment values, logs, or command output.

Send `SIGHUP` to the exact running agent process:

```sh
kill -HUP "$ASTER_AGENT_PID"
```

A completely validated replacement becomes active atomically. Verify through
an authorized application request that the replacement authorizes and the old
token does not; do not log either authorization header. A failed reload keeps
the prior token and Ready state. This operation changes no provider
credential, opaque reference, load operation, mission generation, peer or
relay configuration, emission policy, or process identity, and it requires no
restart.

## 4. Rotate the mission and provider reference

Before starting, retain the current Active reference from its earlier
successful INSTALL or ROTATE output. Prepare a complete authorized replacement
`ASTRPB03` bundle and the matching agent configuration/load-operation value.
The repository does not issue that mission material.

1. Stop the service and confirm termination. With descriptor 3 supplying the
   replacement bundle, run:

   ```sh
   aster-credential-admin rotate \
     --operation "$ROTATE_OPERATION" \
     --load-operation "$NEW_LOAD_OPERATION" <&3
   ```

2. First success stdout is exactly:

   ```text
   ROTATE disposition=installed generation=N reference=HEX
   ```

   An exact retry reports `disposition=existing`. The provider has atomically
   made the new generation Active and parked the exact prior generation as
   Previous; it has not restarted the service or destroyed Previous. A second
   rotation is rejected while Previous remains.
3. Atomically install the already prepared deployment configuration with
   `mission_load_id` equal to `NEW_LOAD_OPERATION`, retaining the fixed Active
   reference path. Run the side-effect-free `--check-config` command shown in
   operation 1. Configuration replacement is deployment-owned until the
   hardened package exists.
4. Start the service and require the deployment readiness check to pass on the
   new generation. Never fall back to Previous after the new generation has
   committed.
5. Only after readiness, stop and confirm termination again. Allocate a fresh
   destroy operation ID and destroy the retained old reference:

   ```sh
   aster-credential-admin destroy \
     --operation "$DESTROY_PREVIOUS_OPERATION" \
     --reference "$OLD_REFERENCE_HEX"
   ```

   First success stdout is exactly
   `DESTROY disposition=destroyed`; an exact retry is
   `DESTROY disposition=already-destroyed`.
6. Start again and require readiness. This final restart proves operationally
   that the ready generation is independent of the removed Previous slot. It
   is not G4 qualification until run on the frozen package and both mandatory
   physical nodes.

## 5. Back up and recover the exact current generation

Backup and recovery are same-host, current-generation operations. A backup
contains authenticated ciphertext and bounded metadata. It contains neither
provisioning plaintext nor the host key, but it remains owner-only operational
material. It does not include the provider ledger.

Stop the service and confirm termination before backup. Never redirect backup
stdout directly over the sole accepted artifact. Create an owner-only
temporary file in the destination directory, accept it only after a zero exit,
then rename it within that directory:

```sh
(
  set -eu
  umask 077
  test ! -e "$BACKUP_DESTINATION"
  BACKUP_TEMP="$(mktemp --tmpdir="$BACKUP_DIRECTORY" .aster-backup.XXXXXX)"
  trap 'rm -f -- "$BACKUP_TEMP"' EXIT HUP INT TERM
  if aster-credential-admin backup \
    --operation "$BACKUP_OPERATION" >"$BACKUP_TEMP"
  then
    chmod 0600 "$BACKUP_TEMP"
    mv -- "$BACKUP_TEMP" "$BACKUP_DESTINATION"
    trap - EXIT HUP INT TERM
  else
    BACKUP_STATUS=$?
    exit "$BACKUP_STATUS"
  fi
)
```

`BACKUP_DESTINATION` must be a fresh, versioned path in the same protected
directory as the temporary file, not the only previously accepted backup. On
success the binary artifact is stdout and stderr is exactly:

```text
BACKUP disposition=available generation=N
```

The neutral `available` disposition covers first success and exact retry. An
exact retry emits identical bytes while its generation remains Active or
Previous. After the bound generation is destroyed, backup returns a sanitized
nonzero Destroyed result. If the command is nonzero for any reason, the
temporary stdout is invalid and the example removes it; filesystem deletion
is not physical erasure.

Restart and require readiness after a successful backup if the node is to
return to service.

Recovery repairs only the exact generation still recorded Active by the
intact ledger, on the same host with the unchanged systemd host key. Stop and
confirm termination, then run:

```sh
aster-credential-admin recover \
  --operation "$RECOVERY_OPERATION" <"$BACKUP_DESTINATION"
```

The CLI validates the bounded artifact before opening the provider and routes
this command through the narrow `open_for_recovery` path. Operators do not use
a separate open mode or weaken ordinary administration. First repair success
is exactly:

```text
RECOVER disposition=restored generation=N
```

If Active already matches exactly, including on an exact retry, the disposition
is `existing`. A wrong host key, absent or mismatched ledger binding, altered
artifact, Previous or Destroyed reference, another Active generation, or
generation rollback fails closed without choosing a fallback. Keep the service
stopped after failure. After success, start and require readiness.

Complete host loss, OS reinstall, host-key backup or handling, ledger restore,
cross-host/device restore, and snapshot rollback are not supported recovery
procedures.

## 6. Revoke and rekey by composing existing authorities

The provider does not implement membership policy or issue credentials.
Follow the repository's existing [stopped-authority control
workflow](../quickstart/mesh-cli.md#publish-a-control-from-a-stopped-authority-state)
to publish the separately authorized revocation and recipient-filtered scope
rekey. That workflow requires pre-existing authority and signed-registry
artifacts; the repository does not yet ship their protected production
issuance, custody, or recovery procedure. Do not substitute an invented
provider command for that missing authority step.

The coordinated operation is:

1. Stop every affected node and confirm termination.
2. Through the authorized mission issuance workflow, produce the new roster,
   signed registry, key generation, and one complete replacement bundle for
   each retained node, all omitting the removed node. This issuance workflow
   remains external to the repository.
3. Use the linked stopped-authority workflow to commit the revocation and
   recipient-filtered scope rekey, then on each still-stopped retained node
   perform operation 4 with that node's fresh provider operation IDs and exact
   replacement bundle. Revocation and rekey remain separate, idempotent
   authority operations; this is not an automatic or atomic
   revoke-plus-rekey mechanism.
4. If the removed node is under administrator control, keep it stopped and
   use operation 7 to destroy each known live local provider reference, using
   a fresh destroy operation ID per exact reference. If it is not under
   control, make no local-erasure claim.
5. Restart retained nodes only after their authority and provider changes are
   complete. Require readiness on the new generation, then complete each
   retained node's post-readiness Previous destruction from operation 4.
6. Through the authority workflow's authenticated acceptance path, verify that
   retained nodes accept the new generation and subsequent authentication with
   the removed credential is rejected. Provider destruction is not a
   substitute for this mission-authentication check.

The current source-tree authority mechanisms and provider lifecycle make this
composition executable with authorized inputs. Protected issuance, packaged
coordination, physical-node execution, and the exact rejection receipt remain
E09/G4 work.

## Adjacent Event-agent ReceiveOnly behavior

ReceiveOnly belongs to the selected Event-agent/profile behavior, not to the
credential provider. Set `mesh.emission_policy` to `receive_only` in the
complete validated configuration and restart; it is not a SIGHUP-reloadable
field. The node initiates no contacts and discloses no local Event or control
inventory or objects, while accepting authenticated inbound work. Mandatory
link, authentication, acknowledgement, and response traffic can still be
emitted. Do not describe this mode as physical radio silence or literal zero
transfer. Changing this mode neither rotates nor reloads provider material.

Final naming and literal-RF-silence behavior remain the external stakeholder
procedure recorded in [Decision 0004](../decisions/0004-radio-silence-semantics.md).

## 7. Logically destroy a provider reference

Retain the exact Active reference from the successful INSTALL or ROTATE output.
Stop the service and confirm termination, allocate a fresh destroy operation
ID, then run:

```sh
aster-credential-admin destroy \
  --operation "$DESTROY_OPERATION" \
  --reference "$REFERENCE_HEX"
```

First success stdout is exactly:

```text
DESTROY disposition=destroyed
```

The provider durably binds the operation and replaces an Active credential
with a tombstone containing no credential bytes. An exact retry returns
`DESTROY disposition=already-destroyed`. Reusing the operation ID with another
reference conflicts. An unknown reference returns the sanitized nonzero
NotFound error and permanently binds that indeterminate result; it is not a
destruction receipt. When destroying Previous, the provider removes its slot
after committing the tombstone to the ledger and thereby permits a later
rotation.

For Active destruction, use the deployment procedure to attempt the required
negative startup check: the agent must fail before readiness. Do not route
around the tombstone, restore an earlier generation, or substitute another
provider. Keep the service stopped after the expected failure according to the
deployment runbook.

This is logical provider destruction only. It proves neither physical media
erasure nor removal from copied filesystems, snapshots, swap, backups, kernel
or process memory, or an uncontrolled host.

## Interrupted pre-intent staging: preserve and escalate

A failure after rotate, recover, or destroy has staged files but before its
durable intent exists leaves an unbound `staged` directory as evidence. Fresh
ordinary administration and recovery both reject that ambiguous namespace
without promoting or deleting it. Rotation and destruction preparation
preserve the committed Active runtime generation; if service policy allowed a
restart, the loader would still select that old Active generation. Recovery
may have begun because Active was already missing or corrupt, so no
working-startup claim is made for that case. Operationally, keep the service
stopped for all such incidents.

Do not rename `staged` to `active`, decrypt it, copy it into a bundle, reuse it
as command input, edit the ledger, or recursively delete provider state. Record
only the operation type, time, exit status, and exact sanitized `ERROR` line.
Use the deployment's authorized root diagnostic/runbook to verify the
committed Active generation and ledger and to inventory only the fixed
`active`, `previous`, `staged`, `cleanup`, `ledger`, `ledger.next`, and `lock`
state without reading or printing credential, reference, operation, host-key,
or ledger bytes.

There is no implemented `aster-credential-admin` cleanup or inspection command
for this state. Manual cleanup requires an authorized root runbook or escalation
that is external to this repository. Until that procedure verifies and
remediates the exact state, do not run another provider mutation and do not
claim automatic convergence. This is a current operability limitation and a
remaining package/runbook action.

## Qualification and non-claims

Completing the code and this procedure makes the five provider commands and
seven-operation composition executable at source level. It does not qualify a
candidate. All of the following remain open:

- Security and Deployment approval at E01;
- packaged lifecycle qualification at E09;
- a hardened systemd unit and native package integration;
- G3 package, executable, unit, source, SBOM, notice, and provenance freeze;
- G4 lifecycle and negative acceptance on both mandatory physical CM4 nodes;
- protected mission/registry issuance and operator authorization;
- cross-host recovery, complete host loss, and host-key recovery;
- snapshot rollback resistance and rollback recovery;
- physical erasure or sanitization;
- root, PID 1, kernel, running-process, and copied-media compromise; and
- production authorization or general-platform support.

Component tests and successful local commands are implementation evidence, not
E01/E09/G3/G4 or physical-target receipts. The exact candidate must still bind
and qualify the package, hardened unit, provider executable, runtime loader,
administration binary, platform, filesystem, and complete procedure unchanged.
