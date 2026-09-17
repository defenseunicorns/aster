#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cargo_command=${CARGO:-cargo}

lock_hickory_packages=$(
  awk '
    /^\[\[package\]\]$/ { package = ""; version = "" }
    /^name = "hickory-(proto|resolver)"$/ {
      package = $3
      gsub(/"/, "", package)
    }
    /^version = / && package != "" {
      version = $3
      gsub(/"/, "", version)
      print package " " version
      package = ""
    }
  ' "$repository_root/Cargo.lock"
)
expected_lock_hickory_packages='hickory-proto 0.25.2
hickory-proto 0.26.1
hickory-resolver 0.25.2
hickory-resolver 0.26.1'

if [ "$lock_hickory_packages" != "$expected_lock_hickory_packages" ]; then
  printf '%s\n' 'dependency-exception scope failed: unexpected lock-only Hickory package set' >&2
  printf '%s\n' 'expected:' "$expected_lock_hickory_packages" 'actual:' "$lock_hickory_packages" >&2
  exit 1
fi

if awk '
  /^\[\[package\]\]$/ { package = "" }
  /^name = "paste"$/ { package = "paste" }
  /^version = / && package == "paste" { found = 1 }
  END { exit !found }
' "$repository_root/Cargo.lock"; then
  printf '%s\n' 'dependency-exception scope failed: unmaintained paste remains in Cargo.lock' >&2
  exit 1
fi

tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --workspace \
    --invert proc-macro-error2@2.0.1 \
    --edges normal,build,dev \
    --target all \
    --prefix none \
    --format '{p}'
)
packages=$(printf '%s\n' "$tree" | awk '{ print $1 " " $2 }')
expected='proc-macro-error2 v2.0.1
i18n-embed-fl v0.9.4
age v0.11.5
aster-provisioning-age v0.1.0-alpha.1'

if [ "$packages" != "$expected" ]; then
  printf '%s\n' 'dependency-exception scope failed: unexpected reverse dependency graph' >&2
  printf '%s\n' 'expected:' "$expected" 'actual:' "$packages" >&2
  exit 1
fi

active_tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --workspace \
    --all-features \
    --edges normal,build,dev \
    --target all \
    --prefix none \
    --format '{p}'
)
active_packages=$(printf '%s\n' "$active_tree" | awk '{ print $1 " " $2 }')
active_paste_packages=$(
  printf '%s\n' "$active_packages" |
    awk '$1 == "paste" { print $1 " " $2 }' |
    LC_ALL=C sort -u
)
if [ -n "$active_paste_packages" ]; then
  printf '%s\n' 'dependency-exception scope failed: unmaintained paste is active in the workspace graph' >&2
  printf '%s\n' 'actual:' "$active_paste_packages" >&2
  exit 1
fi

if printf '%s\n' "$active_packages" | awk '
  ($1 == "hickory-proto" || $1 == "hickory-resolver") && $2 == "v0.25.2" { found = 1 }
  END { exit !found }
'; then
  printf '%s\n' 'dependency-exception scope failed: ignored Hickory 0.25.2 package is active in the workspace graph' >&2
  exit 1
fi

fuzz_tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/fuzz/Cargo.toml" \
    --all-features \
    --edges normal,build,dev \
    --target all \
    --prefix none \
    --format '{p}'
)
fuzz_packages=$(printf '%s\n' "$fuzz_tree" | awk '{ print $1 " " $2 }')
if printf '%s\n' "$fuzz_packages" | awk '$1 == "proc-macro-error2" { found = 1 } END { exit !found }'; then
  printf '%s\n' 'dependency-exception scope failed: ignored proc-macro-error2 is present in the excluded fuzz graph' >&2
  exit 1
fi

if printf '%s\n' "$fuzz_packages" | awk '$1 == "paste" { found = 1 } END { exit !found }'; then
  printf '%s\n' 'dependency-exception scope failed: ignored paste is present in the fuzz graph' >&2
  exit 1
fi

if printf '%s\n' "$fuzz_packages" | awk '
  ($1 == "hickory-proto" || $1 == "hickory-resolver") && $2 == "v0.25.2" { found = 1 }
  END { exit !found }
'; then
  printf '%s\n' 'dependency-exception scope failed: ignored Hickory 0.25.2 package is present in the fuzz graph' >&2
  exit 1
fi

printf '%s\n' 'dependency-exception scope passed: RUSTSEC-2026-0173 is isolated to aster-provisioning-age; unmaintained paste is absent from the lock and active graphs; Hickory 0.25.2 remains lock-only/inactive while safe 0.26.1 is permitted; ignored packages are absent from fuzz'
