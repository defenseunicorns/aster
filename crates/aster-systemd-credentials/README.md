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

Before returning provisioning plaintext, the loader:

- opens the credential directory without relative components or symlink
  traversal;
- opens the fixed credential name relative to that directory descriptor with
  no-follow semantics;
- requires a regular, single-link, effective-service-owned file with exact
  mode `0400`;
- requires Linux `ramfs`, matching systemd's `secure` classification, and
  rejects `tmpfs` or another filesystem as `weak`;
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

## Current implementation boundary

The administration lane now supplies the initial-install subset of
`aster-credential-admin`. The package-owned directories
`/etc/aster/provisioning` and `/var/lib/aster/provisioning-systemd` must already
exist as root-owned mode-`0700` directories on local `ext4`. The command:

```text
aster-credential-admin install \
  --operation <64-lowercase-hex> \
  --load-operation <64-lowercase-hex> < provisioning.bundle
```

accepts the canonical bundle only on standard input, invokes exactly
`/usr/bin/systemd-creds encrypt --with-key=host
--name=aster-provisioning.bundle - -`, and installs generation one through a
synchronized staging directory and a versioned intent/completion ledger. An
exact retry returns `existing` without invoking the provider again. A changed
load operation or plaintext commitment conflicts. On restart, an exact staged
intent is promoted and an exact active intent is completed; mismatched state
is retained and rejected. The command prints only the sanitized `installed` or
`existing` disposition. The opaque reference is retained in the owner-only
active generation for the agent configuration lane.

The current code implements runtime load and crash-recoverable generation-one
install only. Rotation, backup/recovery, revoke/rekey, logical destruction, a
hardened unit, package/executable freeze, and two-node G4 qualification remain
open. There is no age, plaintext-file, TPM2, or alternate-provider fallback.
This increment does not close E01 or E09 and does not claim G3, G4, or
production completion.

The [approved v2 design](../../docs/superpowers/specs/2026-09-08-raspberry-pi-systemd-credential-provider-v2-design.md)
on `main` defines this exact evaluation profile. Persistent v1 state is
deliberately rejected rather than migrated; the historical v1 design does not
qualify this v2 provider.

Run the focused provider checks with:

```text
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials
```

The exact design is the approved v2 design on `main` linked above.
