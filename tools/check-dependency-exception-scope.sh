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

# Check the advisory boundary, not Cargo's printed ordering, duplicate markers,
# or parent versions. Include optional features and every target.
check_reverse_boundary() {
  package=$1
  allowed=$2
  tree=$(
    "$cargo_command" tree \
      --locked \
      --manifest-path "$repository_root/Cargo.toml" \
      --workspace \
      --all-features \
      --invert "$package" \
      --edges normal,build,dev \
      --target all \
      --prefix none \
      --format '{p}'
  )
  if ! printf '%s\n' "$tree" | awk -v allowed="$allowed" '
    BEGIN {
      count = split(allowed, names, " ")
      for (i = 1; i <= count; i++) permitted[names[i]] = 1
    }
    NF {
      if (!($1 in permitted)) invalid = 1
      if ($1 == "aster-provisioning-age") pilot = 1
    }
    END { exit (invalid || !pilot) }
  '; then
    printf 'dependency-exception scope failed: %s escaped the age pilot localization boundary or has no pilot consumer\n' "$package" >&2
    printf '%s\n' "$tree" >&2
    exit 1
  fi
}

check_reverse_boundary proc-macro-error2@2.0.1 \
  'proc-macro-error2 i18n-embed-fl age aster-provisioning-age'
check_reverse_boundary basic-toml@0.1.10 \
  'basic-toml i18n-config i18n-embed-fl i18n-embed-impl i18n-embed age aster-provisioning-age'

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
for package in proc-macro-error2 basic-toml; do
  if printf '%s\n' "$fuzz_tree" | awk -v package="$package" '
    $1 == package { found = 1 }
    END { exit !found }
  '; then
    printf 'dependency-exception scope failed: ignored %s is present in the excluded fuzz graph\n' "$package" >&2
    exit 1
  fi
done

printf '%s\n' 'dependency-exception scope passed: RUSTSEC-2026-0173 and RUSTSEC-2026-0374 retain reviewed lockfile provenance, are confined to the age pilot localization boundary, and are absent from fuzz'
