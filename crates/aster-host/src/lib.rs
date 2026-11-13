//! Process-owned, offline-first composition host for Aster Mesh.
//!
//! [`SharedNodeContactSupervisor`] is the candidate multi-contact ownership
//! boundary evaluated by Gate H.

#![forbid(unsafe_code)]

mod discovery_credentials;
mod mesh_host;
mod node_admission;
mod node_budget;
mod shared_node;

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
pub use mesh_host::{
    CandidateId, CandidateLocator, CandidateProvenance, CandidateStatus, CarrierIdentity,
    ContactCloseReason, ContactDirection, ContactId, ContactPath, HostAction, HostConfig,
    HostEvent, HostSnapshot, MeshHost, MeshHostError,
};
pub use node_admission::AdmissionTransactionError;
pub use node_budget::{
    NodeResourceBudget, NodeResourceClaim, NodeResourceLease, NodeResourceLimits,
    NodeResourceSnapshot, ResourceBudgetError,
};
pub use shared_node::{
    AdmissionAbortReason, ContactDriveReport, ContactOpenReport, ContactOpening, ContactPlan,
    ContactResourceClaims, ContactSessionRole, ContactSupervisorConfig, ContactSupervisorError,
    NodeProviderResourceLease, SharedContactStatus, SharedNodeAuthorizationMutation,
    SharedNodeContactSupervisor, SharedNodeEvidenceCounters, SharedNodeEvidenceTransition,
    SharedNodeMutation,
};
