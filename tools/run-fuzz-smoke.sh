#!/bin/sh
# Run bounded fuzz campaigns without mutating the retained seed corpus.
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fuzz_smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/aster-fuzz-smoke.XXXXXX")

cleanup_fuzz_smoke() {
    if [ -n "${fuzz_smoke_dir:-}" ] && [ -d "$fuzz_smoke_dir" ]; then
        rm -rf -- "$fuzz_smoke_dir"
    fi
}
trap cleanup_fuzz_smoke 0 1 2 3 15

wire_corpus="$fuzz_smoke_dir/wire-corpus"
fragment_corpus="$fuzz_smoke_dir/fragment-corpus"
envelope_corpus="$fuzz_smoke_dir/envelope-corpus"
selected_frame_corpus="$fuzz_smoke_dir/selected-frame-corpus"
selected_negentropy_corpus="$fuzz_smoke_dir/selected-negentropy-corpus"
classical_profile_corpus="$fuzz_smoke_dir/classical-profile-corpus"
systemd_credential_corpus="$fuzz_smoke_dir/systemd-credential-corpus"
systemd_admin_record_corpus="$fuzz_smoke_dir/systemd-admin-record-corpus"
systemd_backup_corpus="$fuzz_smoke_dir/systemd-backup-corpus"
wire_artifacts="$fuzz_smoke_dir/wire-artifacts"
fragment_artifacts="$fuzz_smoke_dir/fragment-artifacts"
envelope_artifacts="$fuzz_smoke_dir/envelope-artifacts"
selected_frame_artifacts="$fuzz_smoke_dir/selected-frame-artifacts"
selected_negentropy_artifacts="$fuzz_smoke_dir/selected-negentropy-artifacts"
classical_profile_artifacts="$fuzz_smoke_dir/classical-profile-artifacts"
systemd_credential_artifacts="$fuzz_smoke_dir/systemd-credential-artifacts"
systemd_admin_record_artifacts="$fuzz_smoke_dir/systemd-admin-record-artifacts"
systemd_backup_artifacts="$fuzz_smoke_dir/systemd-backup-artifacts"
mkdir -p "$wire_corpus" "$fragment_corpus" "$envelope_corpus" \
    "$selected_frame_corpus" "$selected_negentropy_corpus" "$classical_profile_corpus" \
    "$systemd_credential_corpus" "$systemd_admin_record_corpus" \
    "$wire_artifacts" "$fragment_artifacts" "$envelope_artifacts" \
    "$selected_frame_artifacts" "$selected_negentropy_artifacts" \
    "$classical_profile_artifacts" "$systemd_credential_artifacts" \
    "$systemd_admin_record_artifacts" "$systemd_backup_corpus" "$systemd_backup_artifacts"
cp -R "$project_dir/fuzz/corpus/wire_decode/." "$wire_corpus/"
cp -R "$project_dir/fuzz/corpus/fragment_decode/." "$fragment_corpus/"
cp -R "$project_dir/fuzz/corpus/envelope_inspect/." "$envelope_corpus/"
cp -R "$project_dir/fuzz/corpus/classical_profile_decode/." "$classical_profile_corpus/"
cp -R "$project_dir/fuzz/corpus/systemd_credential_decode/." "$systemd_credential_corpus/"

cd "$project_dir"
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz wire_decode "$wire_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026081901 \
    -artifact_prefix="$wire_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz fragment_decode "$fragment_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026081902 \
    -artifact_prefix="$fragment_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz envelope_inspect "$envelope_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026081903 \
    -artifact_prefix="$envelope_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz selected_frame_decode "$selected_frame_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026082301 \
    -artifact_prefix="$selected_frame_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz selected_negentropy "$selected_negentropy_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026082302 \
    -artifact_prefix="$selected_negentropy_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz classical_profile_decode "$classical_profile_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026082801 \
    -artifact_prefix="$classical_profile_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz systemd_credential_decode "$systemd_credential_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026090801 \
    -artifact_prefix="$systemd_credential_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz systemd_admin_record_decode "$systemd_admin_record_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026090802 \
    -artifact_prefix="$systemd_admin_record_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz systemd_backup_decode "$systemd_backup_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026090803 \
    -artifact_prefix="$systemd_backup_artifacts/" -print_final_stats=1
