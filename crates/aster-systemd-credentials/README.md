# Aster systemd credential provider

This first-party crate is the Ubuntu-specific runtime half of provider
contract `aster-systemd-credential-store/v1`. It is statically composed into
the single `aster-agent` customer executable; it is not a service, plugin, or
runtime-selectable backend.

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

This increment supplies only the runtime codec and loader. It does not yet
supply `aster-credential-admin`, the persistent operation ledger, encrypted
install or rotation, same-host backup/recovery, logical destruction,
crash-reconciliation, a hardened systemd unit, Ubuntu packages, or physical
device evidence. There is no age, plaintext-file, TPM2, or alternate-provider
fallback.

The selected profile is Ubuntu 24.04 with the systemd 255.4 credential
interface and explicit host-key protection in the later administration lane.
Debian or generic Debian-family support requires reopening and versioning the
D06 design; this crate makes no such compatibility claim.

Run the focused provider checks with:

```text
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 cargo test -p aster-systemd-credentials
```

The exact design is
`docs/superpowers/specs/2026-09-07-systemd-credential-provider-design.md` on
the `feature/p0-1-linux-event-mvp-profile` branch.

