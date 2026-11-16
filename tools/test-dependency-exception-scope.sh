#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
checker="$repository_root/tools/check-dependency-exception-scope.sh"
failing_cargo="$repository_root/tools/testdata/fail-fuzz-cargo.sh"
scope_cargo="$repository_root/tools/testdata/dependency-scope-cargo.sh"
real_cargo=$(command -v "${CARGO:-cargo}")
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

check_rejected_root_lock() {
  description=$1
  lockfile=$2

  if ASTER_TEST_ROOT_LOCKFILE="$lockfile" CARGO="$real_cargo" \
    sh "$checker" >/dev/null 2>&1; then
    printf 'dependency-exception regression failed: %s passed\n' "$description" >&2
    exit 1
  else
    status=$?
  fi

  if [ "$status" -ne 1 ]; then
    printf 'dependency-exception regression failed: expected %s status 1, got %s\n' \
      "$description" "$status" >&2
    exit 1
  fi
}

rewrite_locked_field() {
  package=$1
  field=$2
  replacement=$3
  input=$4
  output=$5

  awk -v package="$package" -v field="$field" -v replacement="$replacement" '
    /^\[\[package\]\]$/ { in_target = 0 }
    $0 == "name = \"" package "\"" { in_target = 1 }
    in_target && index($0, field " = ") == 1 { $0 = replacement }
    { print }
  ' "$input" >"$output"
}

if ASTER_TEST_REAL_CARGO="$real_cargo" CARGO="$failing_cargo" \
  sh "$checker" >/dev/null 2>&1; then
  printf '%s\n' 'dependency-exception regression failed: fuzz cargo-tree failure passed' >&2
  exit 1
else
  status=$?
fi

if [ "$status" -ne 97 ]; then
  printf 'dependency-exception regression failed: expected status 97, got %s\n' "$status" >&2
  exit 1
fi

# Accept equivalent reverse graphs without freezing Cargo's rendering or versions.
ASTER_TEST_REAL_CARGO="$real_cargo" ASTER_TEST_SCOPE_MODE=reorder \
  ASTER_TEST_SCOPE_PACKAGE=basic-toml CARGO="$scope_cargo" sh "$checker"

for package in basic-toml proc-macro-error2; do
  for mode in escape fuzz empty reverse-failure; do
    expected_status=1
    if [ "$mode" = reverse-failure ]; then expected_status=97; fi
    if ASTER_TEST_REAL_CARGO="$real_cargo" ASTER_TEST_SCOPE_MODE="$mode" \
      ASTER_TEST_SCOPE_PACKAGE="$package" CARGO="$scope_cargo" \
      sh "$checker" >"$temporary_directory/output" 2>&1; then
      status=0
    else
      status=$?
    fi
    if [ "$status" -ne "$expected_status" ]; then
      printf 'dependency-exception regression failed: %s %s returned %s, expected %s\n' \
        "$package" "$mode" "$status" "$expected_status" >&2
      exit 1
    fi
  done
done

second_basic_toml_lock="$temporary_directory/second-basic-toml.lock"
cp "$repository_root/Cargo.lock" "$second_basic_toml_lock"
printf '%s\n' \
  '' \
  '[[package]]' \
  'name = "basic-toml"' \
  'version = "0.2.0"' \
  'source = "registry+https://github.com/rust-lang/crates.io-index"' \
  'checksum = "0000000000000000000000000000000000000000000000000000000000000000"' \
  >>"$second_basic_toml_lock"
check_rejected_root_lock 'second locked basic-toml version' "$second_basic_toml_lock"

alternate_proc_macro_source_lock="$temporary_directory/alternate-proc-macro-error2-source.lock"
rewrite_locked_field \
  proc-macro-error2 \
  source \
  'source = "git+https://example.invalid/proc-macro-error2#0000000000000000000000000000000000000000"' \
  "$repository_root/Cargo.lock" \
  "$alternate_proc_macro_source_lock"
check_rejected_root_lock \
  'same-version proc-macro-error2 from an alternate source' \
  "$alternate_proc_macro_source_lock"

changed_basic_toml_checksum_lock="$temporary_directory/changed-basic-toml-checksum.lock"
rewrite_locked_field \
  basic-toml \
  checksum \
  'checksum = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$repository_root/Cargo.lock" \
  "$changed_basic_toml_checksum_lock"
check_rejected_root_lock \
  'same-version basic-toml with a changed checksum' \
  "$changed_basic_toml_checksum_lock"

printf '%s\n' 'dependency-exception regression passed: equivalent reverse graphs pass; both advisory boundaries, graph failures, and unreviewed lockfile provenance fail closed'
