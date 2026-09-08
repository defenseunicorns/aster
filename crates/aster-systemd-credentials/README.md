# Aster systemd credential provider

This first-party crate implements the Ubuntu-specific runtime loader and the
root administration lane for provider contract
`aster-systemd-credential-store/v1`. The loader is statically composed into
the single `aster-agent` customer executable; the administration binary is a
separate stopped-host tool, not a service, plugin, or runtime-selectable
backend.

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
- reads at most the exact v1 provider-envelope bound once and rechecks file
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

This increment does not yet supply mission/reference rotation, same-host
backup/recovery, logical destruction, revoke/rekey orchestration, a hardened
systemd unit, Ubuntu packages, frozen `systemd-creds` executable identity, or
qualifying physical-device evidence. There is no age, plaintext-file, TPM2, or
alternate-provider fallback.

The selected profile is Ubuntu 24.04 with the systemd 255.4 credential
interface and explicit host-key protection in the later administration lane.
Debian or generic Debian-family support requires reopening and versioning the
D06 design; this crate makes no such compatibility claim. Runs on CM4/Debian
13 development nodes may be used only as explicitly non-qualifying
compatibility checks.

Run the focused provider checks with:

```text
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials
```

The exact design is
`docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md` on
the `feature/p0-1-linux-event-mvp-profile` branch.
