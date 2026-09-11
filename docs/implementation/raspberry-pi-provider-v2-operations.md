#

# Raspberry Pi systemd credential provider v2 operations

- Profile: `aster-linux-event-mvp-evaluation-v0.1`
- Provider: `aster-systemd-credential-store/v2`
- Status: code-level integration manually validated; packaged qualification blocked

This procedure describes the intended seven provider and Event-agent
operations. The five `aster-credential-admin` command forms and statically
composed runtime loader are exact and executable. A 2026-09-09 engineering
spike exercised the code-level integration on the selected physical hardware.
The original Raspberry Pi packaged qualification remains open. The
[Ubuntu 24.04 amd64 candidate annex](#ubuntu-2404-amd64-package-annex) below
supplies concrete package paths, service identity, reference handoff and
supervisor commands for that separate evaluation target.

This is an evaluation-only procedure for the exact Raspberry Pi reference
2026-06-18 / Debian 13 / CM4 Rev 1.1 / `aarch64` / kernel
`6.18.39+rpt-rpi-v8` / systemd `257.13-1~deb13u1` / local ext4 profile. It is
not a general Debian, Raspberry Pi, or systemd procedure. The Ubuntu annex
reuses the lifecycle rules below; it does not extend Raspberry Pi qualification.

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

The service integration must use `LoadCredentialEncrypted=` for the provider-
internal `/etc/aster/provisioning/active/credential.cred` and name the runtime
credential exactly `aster-provisioning.bundle`. The sibling provider-internal
`/etc/aster/provisioning/active/reference` remains root-only state and **must
not** be configured as the unprivileged Event agent's
`mission_secret_ref_file`.

Instead, the deployment/package owns a separate service-readable reference
handoff file. After a successful INSTALL or ROTATE, the deployment procedure must
parse the exact complete `reference=HEX` success field, decode that canonical
hex to the serialized `ProvisioningSecretRef` bytes expected by the agent, and
atomically replace the handoff file. The file must be owned exactly by the
final service UID with mode `0600`. The Ubuntu candidate annex specifies its
path and manual handoff; the original Raspberry Pi package annex remains open. The
agent's `mission_secret_ref_file` must name that handoff file, and its
configured `mission_load_id` must equal the load-operation ID used for the
Active generation.

The runtime presentation must satisfy either the original service-owned
mode-`0400` `ramfs` form or every predicate of the exact
[systemd 257 credential-presentation amendment](../superpowers/specs/2026-09-09-systemd-257-credential-presentation-amendment.md).
The latter is not a generic `tmpfs` fallback and remains subject to Security
and Deployment approval at E01.

Run the root administration CLI only as root. Run `aster-agent --check-config`
and the agent runtime as the final service UID, not root: agent credential-file
validation requires the bearer-token and reference handoff files to be owned
by its own effective UID. The bearer-token file is likewise owned exactly by
the final service UID with mode `0600`.

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
4. Through the deployment-owned handoff, atomically populate the separate
   service-readable reference file from the exact successful `reference=HEX`
   field. Its owner must be the final service UID and its mode must be `0600`;
   do not expose or directly configure the root-only provider reference file.
   Confirm that the package configuration points to the handoff file and
   contains this generation's exact load-operation ID.
5. As the final service UID, not root, run the side-effect-free repository
   configuration checker:

   ```sh
   aster-agent --check-config "$ASTER_AGENT_CONFIG"
   ```

   Success is silent with exit code zero. This check validates configuration
   and credential-file form; it does not open the provider or prove startup.

## 2. Load the Active reference at startup

1. Use the deployment-owned start procedure. The runtime must execute as the
   same final service UID that owns the reference handoff and bearer-token
   files. PID 1 must authenticate and
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
Create the replacement in the same protected directory, set its owner exactly
to the final service UID and its mode exactly to `0600`, and atomically rename
the completely written regular file over the configured path. Never put token
bytes in arguments, environment values, logs, or command output.

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
3. Through the package-owned trusted handoff, atomically replace the separate
   service-readable reference file from the exact successful `reference=HEX`
   field, owned by the final service UID at mode `0600`. Atomically install the
   already prepared configuration with `mission_load_id` equal to
   `NEW_LOAD_OPERATION` and `mission_secret_ref_file` naming that handoff, not
   the root-only provider-internal Active reference. Run the `--check-config`
   command from operation 1 as the final service UID. Handoff and configuration
   replacement remain blocked on the hardened package annex.
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
   perform **only operation 4 steps 1–3** with that node's fresh provider
   operation IDs and exact replacement bundle. Every retained node remains
   stopped at this coordinated checkpoint. Revocation and rekey remain
   separate, idempotent authority operations; this is not an automatic or
   atomic revoke-plus-rekey mechanism.
4. If the removed node is under administrator control, keep it stopped and
   use operation 7 to destroy each known live local provider reference, using
   a fresh destroy operation ID per exact reference. If it is not under
   control, make no local-erasure claim.
5. Only after every retained node has reached that stopped checkpoint and the
   removed controlled node has completed step 4, perform **operation 4 steps
   4–6 exactly once** on each retained node: start and require new-generation
   readiness, stop and destroy Previous, then start and require readiness
   again.
6. Through the authority workflow's authenticated acceptance path, verify that
   retained nodes accept the new generation and subsequent authentication with
   the removed credential is rejected. Provider destruction is not a
   substitute for this mission-authentication check.

The authority mechanisms and provider CLI pieces are executable with
authorized inputs. Their end-to-end Event-agent composition remains blocked on
the package handoff, identity, service-control, readiness, and protected-
issuance gaps above. Physical-node execution and the exact rejection receipt
remain E09/G4 work.

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

The five provider CLI commands are executable at source level. The complete
seven-operation Event-agent composition is not yet executable end to end and
does not qualify a candidate. All of the following remain open:

- Security and Deployment approval at E01;
- packaged lifecycle qualification at E09;
- a hardened systemd unit and native package integration, including the exact
  service UID, service-readable reference handoff path/ownership setup, unit
  and control values, and readiness check;
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


## Ubuntu 24.04 amd64 package annex

This annex supplies installation details for the existing operations 1 and 2,
using the Ubuntu `.deb` candidate. Follow the shared rules and existing
operations above for retries, rotation, backup/recovery and destruction.
Arm64 qualification is deferred. Build instructions and the scope of existing
runtime evidence are in the [package candidate document](../release/ubuntu-24.04-deb.md).

### Package paths and identity

| Purpose | Installed value |
| --- | --- |
| Service / account | `aster-agent.service` / `aster:aster` (system-assigned UID/GID) |
| Agent / administration CLI | `/usr/bin/aster-agent` / `/usr/sbin/aster-credential-admin` |
| Configuration | `/etc/aster/agent.json`, `root:aster`, `0640` |
| Bearer token | `/etc/aster/agent-credentials/client-token`, `aster:aster`, `0600` |
| Service reference | `/etc/aster/agent-credentials/mission-reference`, `aster:aster`, `0600` |
| Agent state | `/var/lib/aster-agent`, `aster:aster`, `0700` |
| Provider / ledger directories | `/etc/aster/provisioning`, `/var/lib/aster/provisioning-systemd`, `root:root`, `0700` |

The example configuration comes from the
[configuration reference](../reference/aster-agent-config-v1.md), with these
package credential paths. The package installs it only as documentation.

### Prepare a first installation

Use Ubuntu 24.04 amd64 and local ext4 for provider storage. On Ubuntu Minimal,
check dpkg documentation exclusions before installing: retain
`/usr/share/doc/aster` and `/usr/share/doc/aster/*` with `path-include` rules
if `/usr/share/doc/*` is excluded.

```sh
sudo apt install ./aster_VERSION_amd64.deb
sudo install -o root -g aster -m 0640 \
  /usr/share/doc/aster/examples/agent.example.json /etc/aster/agent.json
sudo systemd-creds setup
```

These are first-install commands: do not overwrite an existing configuration
or replace a lost host key on an existing deployment. Existing-key loss uses
operation 5's recovery requirements. The package leaves the service disabled
and stopped; provisioning is an explicit operator step.

Configure approved peers and limits. Supply the bearer-token file through the
existing owner-only credential procedure, using the path and permissions in
the table. Do not use the repository test bundle for deployment.

### Operation 1: install and hand off the reference

Use a root Bash maintenance session with `set -euo pipefail`. As required by
operation 1, descriptor 3 must already supply the authorized bundle, and
`INSTALL_OPERATION` and `LOAD_OPERATION` must contain the retained operation
IDs. Keep the service stopped and prevent concurrent administration or starts.

```sh
set -euo pipefail
systemctl stop aster-agent.service
systemctl show aster-agent.service \
  --property=ActiveState,SubState,MainPID,ControlPID
```

Proceed only with `ActiveState=inactive`, `SubState=dead`, `MainPID=0` and
`ControlPID=0`. The unit uses `KillMode=control-group` and a 40-second stop
timeout; the configured agent shutdown grace is at most 30 seconds.

Capture the existing install command's success output privately. A failed
command ends the sequence; use the shared retry procedure, not a new ID.

```sh
umask 077
admin_result=$(mktemp /etc/aster/.install-result.XXXXXX)
/usr/sbin/aster-credential-admin install \
  --operation "$INSTALL_OPERATION" --load-operation "$LOAD_OPERATION" \
  <&3 > "$admin_result"
test "$(wc -l < "$admin_result")" -eq 1
grep -Eq '^INSTALL disposition=(installed|existing) generation=[1-9][0-9]* reference=([0-9a-f]{2})+$' "$admin_result"
```

Decode only that successful result, set ownership before publishing it, and
atomically rename within the protected destination directory. `basenc`,
`mktemp`, `sync`, `mv`, and the other commands are standard system utilities;
no additional administration wrapper is installed.

```sh
reference_stage=$(mktemp /etc/aster/agent-credentials/.mission-reference.XXXXXX)
sed -n 's/^.* reference=//p' "$admin_result" | tr 'a-f' 'A-F' | \
  basenc --base16 --decode > "$reference_stage"
chown aster:aster "$reference_stage"
chmod 0600 "$reference_stage"
sync -f "$reference_stage"
mv -T "$reference_stage" /etc/aster/agent-credentials/mission-reference
sync -f /etc/aster/agent-credentials
rm -- "$admin_result"
```

Prepare a configuration copy in `/etc/aster`, preserving ownership and mode:

```sh
config_stage=$(mktemp /etc/aster/.agent.json.XXXXXX)
cp --preserve=mode,ownership /etc/aster/agent.json "$config_stage"
```

Edit that copy with your editor: set `credentials.mission_load_id` to the
retained `LOAD_OPERATION`, and confirm the credential paths in the table.
Then validate and atomically publish it:

```sh
runuser -u aster -- /usr/bin/aster-agent --check-config "$config_stage"
sync -f "$config_stage"
mv -T "$config_stage" /etc/aster/agent.json
sync -f /etc/aster
```

The two file replacements are individually atomic, not a transaction; keep
the service stopped if either fails. This is the handoff required by
operation 1, not an additional provider operation. For operation 4's rotation,
use its existing `rotate` command and exact `ROTATE` success format, then
apply the same file ownership and atomic replacement requirements.

### Operation 2: start and check readiness

```sh
sudo -u aster /usr/bin/aster-agent --check-config /etc/aster/agent.json
sudo systemctl start aster-agent.service
curl --fail --silent --output /dev/null http://127.0.0.1:8182/livez
curl --fail --silent --output /dev/null http://127.0.0.1:8182/readyz
```

Readiness may take time after `systemctl start`; require HTTP 200 before
application traffic. Continue with the authenticated `GetStatus` and Event
checks in the [operator runbook](../quickstart/linux-event-mvp-runbook.md#operate-a-provider-composed-candidate).
Enable boot startup only after those checks succeed:
`sudo systemctl enable aster-agent.service`.

For operation 3's bearer-token reload, the package command is
`sudo systemctl reload aster-agent.service`; it sends SIGHUP and does not
reload mesh configuration. Package upgrade/removal behavior is documented
[separately](../release/ubuntu-24.04-deb.md#upgrade-removal-and-remaining-qualification).
