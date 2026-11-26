#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
# Validate each graph independently; do not regenerate or compare lockfile bytes.
set -eu
cd "$(dirname "$0")/.."
result=0
for manifest in Cargo.toml fuzz/Cargo.toml
do
    printf 'Checking committed Cargo lockfile: %s\n' "$manifest"
    if ! cargo fetch --locked --manifest-path "$manifest"; then
        printf 'Lockfile validation failed for %s; regenerate its Cargo.lock after manifest changes.\n' "$manifest" >&2
        result=1
    fi
done
exit "$result"
