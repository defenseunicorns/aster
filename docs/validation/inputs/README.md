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

Hash-identical copies of the two active inputs remain at the original
`docs/superpowers/specs` paths so the immutable profile's literal path-and-digest
bindings continue to verify.
