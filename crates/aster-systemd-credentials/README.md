# Aster Raspberry Pi systemd credential provider

This first-party crate implements the Raspberry Pi runtime loader and the root
administration lane for provider contract
`aster-systemd-credential-store/v2`. The loader is statically composed into
the single `aster-agent` customer executable; the administration binary is a
separate stopped-host tool, not a service, plugin, or runtime-selectable
backend.

The exact v2 profile is:

```text
provider = aster-systemd-credential-store/v2
image = Raspberry Pi reference 2026-06-18
distribution = Debian GNU/Linux 13 (trixie)
hardware = Raspberry Pi Compute Module 4 Rev 1.1
architecture = aarch64
kernel = 6.18.39+rpt-rpi-v8
systemd = 257.13-1~deb13u1
credential executable = /usr/bin/systemd-creds
filesystem = ext4
TPM2 = excluded
```

The loader consumes exactly one systemd service credential named
`aster-provisioning.bundle`. PID 1 supplies the absolute credential directory
through `CREDENTIALS_DIRECTORY` after authenticating and decrypting the
`LoadCredentialEncrypted=` source. The loader never invokes `systemd-creds`
and never searches another directory or provider.

Before returning provisioning plaintext, the loader accepts either the
original systemd presentation or the exact systemd 257 profile presentation.
It:

- opens the credential directory without relative components or symlink
  traversal;
- opens the fixed credential name relative to that directory descriptor with
  no-follow semantics;
- accepts the original regular, single-link, effective-service-owned mode
  `0400` file only on Linux `ramfs`;
- on the exact non-root systemd 257 profile, accepts only the root-owned mode
  `0440` file and root-owned mode `0550` per-service directory with exact
  service-UID ACLs, on a read-only `nosuid,nodev,noexec,nosymfollow` `tmpfs`
  mount whose superblock is `noswap`;
- rejects every other path shape, owner, group, mode, ACL, filesystem, mount
  option, or swappable `tmpfs` presentation;
- reads at most the exact v2 provider-envelope bound once and rechecks file
  metadata after the read;
- verifies the provider version, reserved fields, generation, canonical Aster
  reference, load-operation ID, exact lengths, and canonical `ASTRPB03` inner
  bundle; and
- releases plaintext only as an Aster-owned zeroizing
  `ProvisioningLoadReceipt`.

All failures use Aster's fixed `ProvisioningSecretStoreError` categories. The
provider does not log or retain the credential path, reference, operation ID,
envelope, parser detail, or plaintext.

The systemd 257 ACL/tmpfs boundary is defined by the
[profile amendment](../../docs/validation/inputs/systemd-257-credential-presentation-amendment.md).
It does not claim systemd's `secure` label, generic `tmpfs` safety, generic
Debian support, or production qualification. Security and Deployment approval
of the immutable amendment remains required at candidate gate E01.

## Current implementation boundary

The administration lane now supplies the complete code-level
`aster-credential-admin` lifecycle. The package-owned directories
`/etc/aster/provisioning` and `/var/lib/aster/provisioning-systemd` must already
exist as root-owned mode-`0700` directories on local `ext4`. The command:

```text
aster-credential-admin install --operation HEX64 --load-operation HEX64 < ASTRPB03
aster-credential-admin rotate --operation HEX64 --load-operation HEX64 < ASTRPB03
aster-credential-admin backup --operation HEX64 > protected-backup.bin
aster-credential-admin recover --operation HEX64 < protected-backup.bin
aster-credential-admin destroy --operation HEX64 --reference HEX
```

Install and rotate accept a canonical bundle only on standard input and invoke
exactly `/usr/bin/systemd-creds encrypt --with-key=host
--name=aster-provisioning.bundle - -`. Rotation atomically makes one new
generation Active and retains one exact Previous generation until the operator
proves new-generation readiness and destroys it. Backup emits a host-bound
protected binary artifact; recovery can repair only the intact ledger's exact
current generation on the same host with the unchanged systemd host key.
Destroy commits a durable logical tombstone and never claims physical erasure.
All operations bind to the versioned lifecycle ledger; generation mutations
use intent-driven reconciliation, and ambiguous state is rejected without
fallback.

Install and rotate stdout is exactly
`{INSTALL|ROTATE} disposition={installed|existing} generation=N reference=HEX`.
Recover stdout is exactly
`RECOVER disposition={restored|existing} generation=N`; destroy stdout is
exactly `DESTROY disposition={destroyed|already-destroyed}`. Backup writes only
artifact bytes to stdout and writes
`BACKUP disposition=available generation=N` to stderr. A nonzero exit
invalidates all stdout, including a partial or complete prefix left by an
output-transport failure. Operation IDs are permanent bindings: retain the
exact ID and authorized input for retry, and never reuse an ID with changed
input.

The complete human-first sequence, including required stopped-service state,
safe backup redirection, bearer-token SIGHUP composition, mission/provider
rotation, same-host recovery, revoke/rekey composition, destruction, and
pre-intent staged-evidence escalation, is the
[Raspberry Pi provider v2 operations procedure](../../docs/mvp/raspberry-pi-provider-v2-operations.md).

The five provider lifecycle CLI commands and the code-level Event-agent
integration are executable; a three-device engineering spike has exercised
startup and the lifecycle, while final qualification remains open. The Ubuntu amd64 candidate now has
[package installation details](../../docs/mvp/raspberry-pi-provider-v2-operations.md#ubuntu-2404-amd64-package-annex);
this does not qualify the original Raspberry Pi target. The provider's
`active/reference` stays root-only; the deployment procedure must atomically populate
a separate mode-`0600`, final-service-UID-owned reference handoff from
successful INSTALL/ROTATE output. Agent configuration checks and runtime must
run as that final service UID, while the administration CLI remains root-only.
E01, packaged E09 qualification, the exact handoff path and ownership setup,
service UID, hardened unit/control values, readiness check, native package
integration, G3/G4, protected authority issuance, cross-host recovery,
snapshot rollback, physical erasure, production, and general-platform support
remain open. There is no age, plaintext-file, TPM2, or alternate-provider
fallback.

The [approved v2 design](../../docs/validation/inputs/raspberry-pi-systemd-credential-provider-v2-design.md)
on `main` defines this exact evaluation profile. Persistent v1 state is
deliberately rejected rather than migrated; the historical v1 design does not
qualify this v2 provider.

Run the focused provider checks with:

```text
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials
```

The exact design is the approved v2 design on `main` linked above.
