#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
set -eu

manifest_path=
inverted_package=
previous_argument=
for argument do
  case "$previous_argument" in
    --manifest-path) manifest_path=$argument ;;
    --invert) inverted_package=$argument ;;
  esac
  previous_argument=$argument
done

case "${ASTER_TEST_SCOPE_MODE:?}:$manifest_path:$inverted_package" in
  reorder:*:*@*)
    tree=$("${ASTER_TEST_REAL_CARGO:?}" "$@")
    # Order, duplicate rendering, and unrelated parent versions are not policy.
    printf '%s\n' "$tree" "$tree" | awk '{ if ($1 == "age") $2 = "v99.0.0"; print }' | LC_ALL=C sort -r
    ;;
  escape:*:"${ASTER_TEST_SCOPE_PACKAGE:?}"@*)
    "${ASTER_TEST_REAL_CARGO:?}" "$@"
    printf '%s\n' 'unexpected-consumer v1.0.0'
    ;;
  fuzz:*/fuzz/Cargo.toml:)
    "${ASTER_TEST_REAL_CARGO:?}" "$@"
    printf '%s v1.0.0\n' "${ASTER_TEST_SCOPE_PACKAGE:?}"
    ;;
  reverse-failure:*:"${ASTER_TEST_SCOPE_PACKAGE:?}"@*) exit 97 ;;
  empty:*:"${ASTER_TEST_SCOPE_PACKAGE:?}"@*) exit 0 ;;
  *) exec "${ASTER_TEST_REAL_CARGO:?}" "$@" ;;
esac
