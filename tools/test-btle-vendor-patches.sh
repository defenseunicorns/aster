#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/aster-btle-vendor.XXXXXX")
mkdir -p "$repository_root/target"
build_root=$(mktemp -d "$repository_root/target/aster-btle-vendor.XXXXXX")
trap 'rm -rf "$test_root" "$build_root"' EXIT HUP INT TERM

positive_target="$build_root/positive"
hmac_target="$build_root/hmac-negative"
advertisement_target="$build_root/advertisement-negative"
discovery_target="$build_root/discovery-negative"
discovery_absence_target="$build_root/discovery-absence-negative"
capacity_target="$build_root/capacity-negative"

export CARGO_INCREMENTAL=0

expect_test_failure() {
  label=$1
  target=$2
  manifest=$3
  features=$4
  test_filter=$5
  log=$6

  if ! CARGO_TARGET_DIR="$target" cargo test --quiet --offline --locked \
    --manifest-path "$manifest" --no-default-features --features "$features" \
    --lib --no-run >"$log.compile" 2>&1; then
    echo "$label did not compile" >&2
    exit 1
  fi
  if CARGO_TARGET_DIR="$target" RUST_BACKTRACE=0 cargo test --quiet --offline --locked \
    --manifest-path "$manifest" --no-default-features --features "$features" \
    --lib "$test_filter" >"$log" 2>&1; then
    echo "$label unexpectedly passed" >&2
    exit 1
  fi
  if ! grep -F "$test_filter" "$log" >/dev/null || \
    ! grep -F "test result: FAILED" "$log" >/dev/null; then
    echo "$label failed outside its intended test" >&2
    exit 1
  fi
  echo "$label was rejected"
}

python3 "$repository_root/tools/check-btle-vendor-patches.py"

CARGO_TARGET_DIR="$positive_target" \
  cargo test --offline --locked \
    --manifest-path "$repository_root/third-party/hmac-0.13.0-aster/Cargo.toml" \
    --no-default-features --features zeroize
CARGO_TARGET_DIR="$positive_target" \
  cargo test --offline --locked \
    --manifest-path "$repository_root/third-party/bluer-0.17.4-aster/Cargo.toml" \
    --no-default-features --features bluetoothd,l2cap --lib
CARGO_TARGET_DIR="$positive_target" \
  cargo test --offline --locked --manifest-path "$repository_root/Cargo.toml" \
    -p aster-ble-linux --lib discovery_record_rfc_4231_hmac_sanity_vector

hmac_mutant="$test_root/hmac-mutant"
advertisement_mutant="$test_root/advertisement-mutant"
discovery_mutant="$test_root/discovery-mutant"
discovery_absence_mutant="$test_root/discovery-absence-mutant"
capacity_mutant="$test_root/capacity-mutant"
cp -R "$repository_root/third-party/hmac-0.13.0-aster" "$hmac_mutant"
cp -R "$repository_root/third-party/bluer-0.17.4-aster" "$advertisement_mutant"
cp -R "$repository_root/third-party/bluer-0.17.4-aster" "$discovery_mutant"
cp -R "$repository_root/third-party/bluer-0.17.4-aster" "$discovery_absence_mutant"
cp -R "$repository_root/third-party/bluer-0.17.4-aster" "$capacity_mutant"

python3 - \
  "$hmac_mutant/src/block_api.rs" \
  "$advertisement_mutant/src/adv.rs" \
  "$discovery_mutant/src/adapter.rs" \
  "$discovery_absence_mutant/src/adapter.rs" \
  "$capacity_mutant/src/session.rs" <<'PY'
from pathlib import Path
import sys


def replace_once(path: str, old: str, new: str) -> None:
    source = Path(path).read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise SystemExit(f"mutation target count changed in {path}: {source.count(old)}")
    Path(path).write_text(source.replace(old, new), encoding="utf-8")


replace_once(
    sys.argv[1],
    "type ProtectedDerivedKey<D> = Zeroizing<DerivedKeyBlock<D>>;",
    "type ProtectedDerivedKey<D> = DerivedKeyBlock<D>;",
)
replace_once(
    sys.argv[1],
    "Zeroizing::new(DerivedKeyBlock(get_der_key::<D>(key)))",
    "DerivedKeyBlock(get_der_key::<D>(key))",
)
replace_once(
    sys.argv[2],
    "if confirms_advertisement_absent(&unregister().await) {",
    "if true {",
)
replace_once(
    sys.argv[3],
    """DiscoveryOperationOutcome::Completed(Err(error)) => {
            cleanup_unconfirmed_discovery(&mut events, &mut session, &mut stop).await;
            return DiscoveryOwnerExit::RegistrationFailed(registration_reply, error);
        }""",
    """DiscoveryOperationOutcome::Completed(Err(error)) => {
            return DiscoveryOwnerExit::RegistrationFailed(registration_reply, error);
        }""",
)
replace_once(
    sys.argv[4],
    "            | ErrorKind::NotReady\n",
    "",
)
replace_once(
    sys.argv[5],
    "const DBUS_INGRESS_CAPACITY: usize = 256;",
    "const DBUS_INGRESS_CAPACITY: usize = 257;",
)
PY

expect_test_failure \
  "HMAC Zeroizing negative control" \
  "$hmac_target" "$hmac_mutant/Cargo.toml" zeroize \
  block_api::aster_tests "$test_root/hmac-negative.log"
expect_test_failure \
  "BlueR advertisement cleanup negative control" \
  "$advertisement_target" "$advertisement_mutant/Cargo.toml" bluetoothd,l2cap \
  adv::aster_tests::failed_registration_attempts_cleanup_before_returning_error \
  "$test_root/advertisement-negative.log"
expect_test_failure \
  "BlueR discovery cleanup negative control" \
  "$discovery_target" "$discovery_mutant/Cargo.toml" bluetoothd,l2cap \
  adapter::aster_tests::ambiguous_start_failure_is_stopped_before_error_is_returned \
  "$test_root/discovery-negative.log"
expect_test_failure \
  "BlueR discovery absence negative control" \
  "$discovery_absence_target" "$discovery_absence_mutant/Cargo.toml" bluetoothd,l2cap \
  adapter::aster_tests::cleanup_accepts_not_ready_as_proof_discovery_is_absent \
  "$test_root/discovery-absence-negative.log"
expect_test_failure \
  "BlueR ingress capacity negative control" \
  "$capacity_target" "$capacity_mutant/Cargo.toml" bluetoothd,l2cap \
  session::aster_tests::bounded_ingress_fails_the_session_on_item_257 \
  "$test_root/capacity-negative.log"
