#!/usr/bin/env bash
# Apply owner-only creation defaults to CI run steps and their child processes.
# Invoked by ci.yml after checkout; uses: actions do not inherit this mask.
umask 077
exec bash --noprofile --norc -eo pipefail "$@"
