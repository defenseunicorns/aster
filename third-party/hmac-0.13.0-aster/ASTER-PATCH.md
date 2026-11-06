# Aster patch provenance

- Upstream package: `hmac` 0.13.0 from crates.io.
- Crate archive SHA-256: `6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f`.
- Upstream VCS revision: `0236c8eb50098dd7f277a71ab89caaeb1e7314df`.
- License: `MIT OR Apache-2.0`; retained notices are `LICENSE-MIT`
  (`9e0dfd2dd4173a530e238cb6adb37aa78c34c6bc7444e0e10c1ab5d8881f63ba`)
  and `LICENSE-APACHE`
  (`a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`).
- Per-file upstream receipt: `ASTER-UPSTREAM.sha256`.
- Canonical patch: `ASTER-PATCH.diff`, SHA-256
  `c9962ca0b2c271f1bd3876567ab99571252e9bff4500fcdf7d09cee135c6e4c7`.

The only upstream-code delta is in `src/block_api.rs`. With the existing
`zeroize` feature enabled, both HMAC constructor paths wrap the derived-key
block in `Zeroizing` so the IPAD/OPAD construction temporary is cleared on all
returns and unwinds. Builds without `zeroize` retain upstream behavior and do
not acquire a new feature requirement. The patch does not change HMAC output,
public API, wire behavior, or Aster protocol policy.

Remove the patch when an upstream release provides equivalent constructor
temporary zeroization and Aster can qualify that exact release. Run
`python3 tools/check-btle-vendor-patches.py` for source equivalence and
`sh tools/test-btle-vendor-patches.sh` for both upstream feature surfaces and
the frozen Aster RFC 4231 vector. The latter also mutates away `Zeroizing` and
requires the normal-return and unwind drop-observation tests to fail.
