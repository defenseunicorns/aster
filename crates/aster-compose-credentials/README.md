# Aster Compose credentials

This crate implements the Linux Docker Compose provisioning provider contract
`aster-compose-secret-store/v1`. It owns the canonical activation, provider
reference, and provisioning-envelope formats and implements Aster's existing
`ProvisioningSecretLoader` boundary.

Runtime credential reads use only these fixed mounts:

- `/run/secrets/aster-client-token`
- `/run/secrets/aster-mission-activation`
- `/run/secrets/aster-provisioning-bundle`

Each file is opened by descriptor without following symlinks, is bounded and
checked before and after reading, and must be a singly linked regular file
owned by the effective non-root UID with mode exactly `0400` or `0600`. The
corresponding fixed target must occur exactly once as read-only in
`/proc/self/mountinfo`. Unsupported or ambiguous presentations fail closed
with fixed public error categories.

The client-token mount contains a canonical `ASTRCSTK` envelope binding the
zeroizing token bytes to the same nonzero generation carried by the activation
and provisioning envelope. The provisioning envelope contains a canonical
unprotected `ASTRPB03` bundle. Framing and binding reject malformed or mixed
token/activation/envelope generations; they do not encrypt the credentials or
protect them from a compromised host root user or Docker daemon. There is no
raw-token or raw-bundle fallback, alternate production secret root, runtime
provider selector, Docker CLI/socket integration, or Swarm support.

## Immutable generation administration

`aster-compose-credential-admin` creates one host-side generation at a time.
It must run as the same selected nonzero numeric UID/GID as the runtime, with
an output parent already writable by that identity. It rejects effective UID
0 and never accepts UID/GID/chown options or requires `CAP_CHOWN`.

The canonical `ASTRPB03` mission bundle is accepted only on standard input.
The client token is accepted only through an absolute, owner-protected regular
file named by `--token-file`; it must be owned by the effective UID, singly
linked, and mode exactly `0400` or `0600`. Credential bytes are never accepted
in arguments or environment variables and are never written to status output
or the manifest.

```text
aster-compose-credential-admin create \
  --output-parent /host/protected/aster-generations \
  --token-file /host/protected/client-token < mission.bundle
```

Creation uses a private `.staging-<64-lowercase-hex>` directory under the
output parent. It normalizes only trailing CR/LF from the protected token input,
then writes the fixed generation-bound `aster-client-token`,
`aster-mission-activation`, `aster-provisioning-bundle`, and `manifest.json`
files with exclusive no-follow opens; validates ownership and modes; syncs
each file and the completed directory; changes the generation to read/execute
only; atomically renames it once to `generation-<64-lowercase-hex>` without
replacement; and then syncs the parent. A failure before rename leaves only a
staging directory for operator recovery. An existing final generation is
never replaced or edited.

Success stdout is exactly:

```text
CREATE disposition=created generation=<64-lowercase-hex>
```

The non-secret `aster-compose-secret-generation/v1` manifest contains only
the provider contract, public generation, UTC and Unix creation times, and the
bounded encoded-file sizes and SHA-256 digests (including the token envelope,
never token plaintext). It is comparison evidence, not runtime authorization.
Protect it with the generation directory where credential commitments are
classified as sensitive.

Licensed under Apache-2.0.
