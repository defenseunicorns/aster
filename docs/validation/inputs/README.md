# Immutable validation inputs

These files are exact approval inputs for the Linux Event MVP evaluation
profile. Consumers bind their recorded SHA-256 digests, so update the profile
through a new reviewed input instead of editing a file in place.

The provider design deliberately retains two historical relative links as part
of its approved bytes. Small compatibility pointers resolve those links; their
archived destinations are the
[Raspberry Pi profile amendment](../../../archive/design-history/specs/2026-09-08-raspberry-pi-linux-event-mvp-profile-amendment-design.md)
and the
[Ubuntu v1 provider design](../../../archive/design-history/specs/2026-09-07-systemd-credential-provider-design.md).

The profile links to the canonical inputs in this directory:
[provider design](raspberry-pi-systemd-credential-provider-v2-design.md) and
[credential-presentation amendment](systemd-257-credential-presentation-amendment.md).
Their current bytes do not match the approval digests recorded in the profile.
Preserve both the files and the recorded digests; qualification requires a
separate review of that mismatch.
