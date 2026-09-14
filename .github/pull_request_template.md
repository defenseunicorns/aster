## Summary

Describe the behavior changed and why.

## Capability outcome, priority, and claim boundary

- Roadmap alignment — priority/action, profile, outcome, and measurable exit
  criterion advanced (or one bounded-maintenance rationale):
- Profile decision or external gate changed or depended on, if any, including
  owner/status:
- Demonstrated/implemented behavior after this PR:
- Important exclusions and remaining gaps:
- Exact requirement IDs whose evidence boundary changes, if any:

- [ ] For roadmap work, the PR names its profile, priority action, outcome, and
  exit criterion; otherwise it gives one bounded-maintenance rationale.
- [ ] The PR is a coherent increment toward the named outcome; it does not need
  to close every associated atomic requirement.
- [ ] Claims are no broader than the code, tests, environment, and retained
  evidence.
- [ ] Cross-track dependencies and unresolved stakeholder, physical,
  independent, or other external gates remain explicit and owned.
- [ ] `docs/validation/requirements-status.md` and its generated trace were
  updated when requirement evidence changed, or no evidence boundary changed.
- [ ] The capability roadmap was updated only when the planning boundary
  changed; planning changes alone did not move requirement evidence status.

## Security and compatibility

- [ ] Wire/API compatibility is unchanged or explicitly versioned.
- [ ] Applicable causality/lifecycle, scope/bridge, conformance,
  security-profile, carrier, and resource effects are addressed, shown
  unaffected, or recorded as inapplicable by a reviewed profile/decision.
- [ ] Resource limits and failure behavior were considered.
- [ ] No credentials, mission data, local artifacts, or generated binaries are included.
- [ ] Dependency and tool changes are exact-pinned and justified.

## Verification

- [ ] `mise run check`
- [ ] Relevant regression tests
- [ ] `python3 tools/check-implementation-requirements.py` when requirements
  evidence or traceability changed
- [ ] `mise run fuzz-smoke` when parser, framing, envelope, fragmentation, or
  related hostile-input behavior changed
