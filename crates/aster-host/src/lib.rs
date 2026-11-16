//! Process-owned discovery credential authority for Aster Mesh.

#![forbid(unsafe_code)]

mod discovery_credentials;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use discovery_credentials::fuzz_parse_discovery_credential_artifact;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use discovery_credentials::prepare_discovery_credential_for_test;
pub use discovery_credentials::{
    ActiveDiscoveryCredentialAuthority, BTLE_AUTHORITY_LOCK_PATH,
    BoundedDiscoveryCredentialArtifact, DiscoveryCredentialAdapterParts,
    DiscoveryCredentialArtifactProvider, DiscoveryCredentialError,
    DiscoveryCredentialMaterialParts, PreparedDiscoveryCredential, TrustedClock,
    TrustedClockLeaseGuard, TrustedClockSample, prepare_discovery_credential,
};
#[cfg(target_os = "linux")]
pub use discovery_credentials::{
    UnprotectedReferenceAuthorityGuard, load_unprotected_reference_discovery_credentials,
};
