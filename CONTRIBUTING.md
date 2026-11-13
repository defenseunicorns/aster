# Contributing to Aster

Thank you for helping improve Aster.

Repository: [Aster](https://github.com/defenseunicorns/aster).

Open pull requests against `main`.

Follow the product requirements in [DESIGN.md](DESIGN.md) and read the
[documentation](docs/README.md) relevant to your change.

## Setup

Install the tools listed in `mise.toml`:

```sh
mise install
```

## Testing

After changing code, run:

```sh
mise run check
```

Also run fuzz tests after changing parsers, framing, envelopes, fragmentation,
or their input limits:

```sh
mise run fuzz-smoke
```

## Reporting issues

Check existing issues before opening a new one. For bug reports, explain how
to reproduce the problem, what you expected, what happened, and the environment
you used. Discuss larger changes before starting work.

## Pull requests

Keep each pull request focused on one change. Explain the problem, describe
your solution, and summarize your testing. Link related issues and address
review feedback.

## Versioning and changelog

Use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for releases and
[Keep a Changelog](https://keepachangelog.com/en/2.0.0/) for changelog entries.

## Other ways to contribute

You can also help by improving documentation, reproducing reported bugs,
suggesting clearer text, or helping other users get started.
