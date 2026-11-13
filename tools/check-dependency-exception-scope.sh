#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cargo_command=${CARGO:-cargo}
root_lockfile=${ASTER_TEST_ROOT_LOCKFILE:-"$repository_root/Cargo.lock"}

locked_package_records() {
  wanted_name=$1

  awk -v wanted_name="$wanted_name" '
    function unquote(line) {
      sub(/^[^=]*= *"/, "", line)
      sub(/"$/, "", line)
      return line
    }

    function emit_package() {
      if (in_package && package_name == wanted_name) {
        print package_name "|" package_version "|" package_source "|" package_checksum
      }
    }

    /^\[\[package\]\]$/ {
      emit_package()
      in_package = 1
      package_name = ""
      package_version = ""
      package_source = ""
      package_checksum = ""
      next
    }

    in_package && /^name = / { package_name = unquote($0); next }
    in_package && /^version = / { package_version = unquote($0); next }
    in_package && /^source = / { package_source = unquote($0); next }
    in_package && /^checksum = / { package_checksum = unquote($0); next }

    END { emit_package() }
  ' "$root_lockfile"
}

check_exact_locked_package() {
  package_name=$1
  expected_version=$2
  expected_source=$3
  expected_checksum=$4
  expected_record="$package_name|$expected_version|$expected_source|$expected_checksum"
  actual_records=$(locked_package_records "$package_name")

  if [ "$actual_records" != "$expected_record" ]; then
    printf 'dependency-exception scope failed: unexpected locked provenance for %s\n' \
      "$package_name" >&2
    printf '%s\n' 'expected:' "$expected_record" 'actual:' "$actual_records" >&2
    exit 1
  fi
}

crates_io_source='registry+https://github.com/rust-lang/crates.io-index'
check_exact_locked_package \
  proc-macro-error2 \
  2.0.1 \
  "$crates_io_source" \
  11ec05c52be0a07b08061f7dd003e7d7092e0472bc731b4af7bb1ef876109802
check_exact_locked_package \
  basic-toml \
  0.1.10 \
  "$crates_io_source" \
  ba62675e8242a4c4e806d12f11d136e626e6c8361d6b829310732241652a178a

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
  ' "$root_lockfile"
)
expected_lock_hickory_packages='hickory-proto 0.26.2'

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
' "$root_lockfile"; then
  printf '%s\n' 'dependency-exception scope failed: unmaintained paste remains in Cargo.lock' >&2
  exit 1
fi

check_exact_reverse_graph() {
  package=$1
  expected=$2
  tree=$(
    "$cargo_command" tree \
      --locked \
      --manifest-path "$repository_root/Cargo.toml" \
      --workspace \
      --invert "$package" \
      --edges normal,build,dev \
      --target all \
      --prefix none \
      --format '{p}'
  )
  packages=$(printf '%s\n' "$tree" | awk '{ print $1 " " $2 }')

  if [ "$packages" != "$expected" ]; then
    printf 'dependency-exception scope failed: unexpected reverse dependency graph for %s\n' "$package" >&2
    printf '%s\n' 'expected:' "$expected" 'actual:' "$packages" >&2
    exit 1
  fi
}

expected_proc_macro_error2='proc-macro-error2 v2.0.1
i18n-embed-fl v0.9.4
age v0.11.5
aster-provisioning-age v0.1.0-alpha.1'
check_exact_reverse_graph proc-macro-error2@2.0.1 "$expected_proc_macro_error2"

expected_basic_toml='basic-toml v0.1.10
i18n-config v0.4.8
i18n-embed-fl v0.9.4
age v0.11.5
aster-provisioning-age v0.1.0-alpha.1
i18n-embed-impl v0.8.4
i18n-embed v0.15.4
i18n-embed-fl v0.9.4
i18n-embed v0.15.4
age v0.11.5'
check_exact_reverse_graph basic-toml@0.1.10 "$expected_basic_toml"

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

if printf '%s\n' "$fuzz_packages" | awk '$1 == "basic-toml" { found = 1 } END { exit !found }'; then
  printf '%s\n' 'dependency-exception scope failed: ignored basic-toml is present in the excluded fuzz graph' >&2
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

printf '%s\n' 'dependency-exception scope passed: RUSTSEC-2026-0173 and RUSTSEC-2026-0374 are pinned to reviewed lockfile provenance and isolated to aster-provisioning-age; unmaintained paste is absent from the lock and active graphs; Hickory 0.25.2 is absent while fixed 0.26.2 is permitted; ignored packages are absent from fuzz'
