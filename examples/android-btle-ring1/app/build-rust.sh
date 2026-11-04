#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build-rust.sh OUTPUT_JNI_LIBS_DIR" >&2
  exit 2
fi

readonly expected_ndk="28.2.13676358"
readonly output_root="$1"
readonly crate_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${crate_dir}/../../.." && pwd)"
readonly android_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
readonly ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${android_sdk:+${android_sdk}/ndk/${expected_ndk}}}}"

if [[ -z "${ndk_root}" || ! -f "${ndk_root}/source.properties" ]]; then
  echo "ANDROID_NDK_HOME must identify Android NDK ${expected_ndk}" >&2
  exit 1
fi
if ! grep -Eq "^Pkg.Revision[[:space:]]*=[[:space:]]*${expected_ndk}$" "${ndk_root}/source.properties"; then
  echo "Android NDK ${expected_ndk} is required" >&2
  exit 1
fi
if ! command -v cargo >/dev/null; then
  echo "cargo is required" >&2
  exit 1
fi
if ! command -v rustup >/dev/null; then
  echo "rustup is required" >&2
  exit 1
fi
if ! rustup target list --installed | grep -Fxq "aarch64-linux-android"; then
  echo "rustup target aarch64-linux-android is required" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) readonly host_tag="linux-x86_64" ;;
  Darwin) readonly host_tag="darwin-x86_64" ;;
  *) echo "unsupported Android NDK host" >&2; exit 1 ;;
esac

readonly clang="${ndk_root}/toolchains/llvm/prebuilt/${host_tag}/bin/aarch64-linux-android29-clang"
if [[ ! -x "${clang}" ]]; then
  echo "NDK API-29 arm64 clang was not found" >&2
  exit 1
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${clang}"
export CC_aarch64_linux_android="${clang}"
cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --locked \
  --package aster-ble-android \
  --target aarch64-linux-android

readonly abi_dir="${output_root}/arm64-v8a"
mkdir -p "${abi_dir}"
cp "${repo_root}/target/aarch64-linux-android/debug/libaster_ble_android.so" "${abi_dir}/"
