//! Transport-neutral reference implementation of the Aster Mesh Protocol.
//!
//! The public surface intentionally contains only application-level concepts.
//! Cryptography, link selection, fragmentation, and reconciliation remain
//! internal implementation details or adapter contracts.
//!
//! The default feature set retains the historical SQLite-backed API through
//! `sqlite-store`. The `adapter-sdk` feature also selects `sqlite-store`, so
//! adapter consumers retain that exact composition. Minimal consumers must
//! select `reference-session` with default features disabled. Selecting neither
//! composition is unsupported because Cargo features are additive: an
//! all-features-off build cannot both retain the historical SQLite API and keep
//! the reference-session composition free of SQLite.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "adapter-sdk"), allow(dead_code, unused_imports))]

#[cfg(not(any(feature = "reference-session", feature = "sqlite-store")))]
compile_error!(
    "aster-core requires a runtime composition: use default features for the SQLite-backed API, or use `--no-default-features --features reference-session` for the SQLite-free session surface"
);

#[cfg(feature = "sqlite-store")]
pub mod api;
#[cfg(feature = "sqlite-store")]
pub(crate) mod bridge;
#[cfg(all(feature = "reference-session", not(feature = "sqlite-store")))]
pub(crate) mod bridge;
#[cfg(feature = "reference-session")]
pub mod bridge_adapter;
#[cfg(feature = "sqlite-store")]
pub(crate) mod bridge_service;

#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
// Temporary: the pure profile is exposed first to conformance; provider/store
// adapters consume the remaining construction helpers in the next integration layer.
#[allow(dead_code)]
pub mod batch;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod batch;
#[cfg(all(feature = "reference-session", not(feature = "sqlite-store")))]
mod batch;

#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod blob;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod blob;
#[cfg(all(feature = "reference-session", not(feature = "sqlite-store")))]
mod blob;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod blob_custody;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod blob_custody_v2;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod blob_stream;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod causal;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod causal;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod crypto;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod custody;
#[cfg(all(
    feature = "sqlite-store",
    any(feature = "adapter-sdk", feature = "reference-session")
))]
pub mod engine;
#[cfg(all(
    feature = "sqlite-store",
    not(any(feature = "adapter-sdk", feature = "reference-session"))
))]
mod engine;
#[cfg(all(feature = "reference-session", not(feature = "sqlite-store")))]
#[path = "session_engine.rs"]
pub mod engine;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod envelope;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod fragment;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod fragment;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod inventory;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod inventory;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod link;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod link;
#[cfg(feature = "adapter-sdk")]
pub mod model;
#[cfg(not(feature = "adapter-sdk"))]
mod model;
pub mod provisioning;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod runtime;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod runtime;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod scheduler;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod scheduler;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod source_blob;
#[cfg(feature = "reference-session")]
mod source_control;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod source_event;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod source_record;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod source_state;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod store;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod store;
#[cfg(all(feature = "reference-session", not(feature = "sqlite-store")))]
#[path = "session_store.rs"]
mod store;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod sync;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod sync;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
mod transfer_profile;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub mod wire;
#[cfg(all(feature = "sqlite-store", not(feature = "adapter-sdk")))]
mod wire;
#[cfg(all(feature = "reference-session", not(feature = "sqlite-store")))]
mod wire;

#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub use api::ApplicationNodeRef;
#[cfg(feature = "sqlite-store")]
pub use api::{
    ApplicationMergePolicy, ApplicationNode, ApplicationNodeOptions, BatchPublicationPolicy,
    BatchPublishRequest, BatchPublishResult, BridgeAuthorizationId, BridgeAuthorizationPolicy,
    BridgeAuthorizationResult, BridgeAuthorizationStatus, BridgeCommitStatus, BridgeEdge,
    BridgeEnrollment, BridgeNarrowingPolicy, BridgeRouteHandle, BridgeRouteResult,
    BridgeRouteStatus, Delivery, FinishedBlobBatchItem, FinishedBlobBatchRequest, Item,
    MergeVersion, PublishResult, Query, RekeyRecipient, RekeyRecipientAccess, ScopeRekeyResult,
};
#[cfg(feature = "sqlite-store")]
pub use blob::ReferenceBlobReader;
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use blob::{
    BlobCarrierId, BlobChunkRecord, BlobError, BlobId, BlobManifest, BlobMetadata,
    BlobPhysicalLineage, BlobRangeReadStats, BlobReadStats, BlobReader, BlobRouteCommitment,
    BlobStore, BlobStoreConfig, BlobWriteProgress, BuiltBlobTransferObject, FinishedBlob,
    MAX_BLOB_CHUNK_SIZE, MAX_BLOB_CHUNKS, MAX_BLOB_MANIFEST_BYTES, MAX_BLOB_MEDIA_TYPE_BYTES,
    MAX_BLOB_SCHEMA_ID_BYTES, MAX_BLOB_TRANSFER_OBJECT_BYTES, MIN_BLOB_CHUNK_SIZE, PreparedBlob,
    ReferenceBlobService, SELECTED_BLOB_CHUNK_SIZE, VerifiedBlobContentCompletion,
    VerifiedBlobTransferObject, VerifiedBlobTransferPlan, prepare_blob,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use blob_custody::{
    AuthenticatedBlobCustodyContactV1, AuthenticatedBlobCustodySendContextV1,
    BLOB_CUSTODY_CLAIM_V1_BYTES, BlobCustodyClaimV1, BlobCustodyDirectionV1, BlobCustodyError,
    BlobCustodyTransferId, OpenedBlobSourceFrameV1, VerifiedBlobCustodyClaimV1,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use blob_custody_v2::{
    ApplicationRecordContext, AuthenticatedBlobCustodyContactV2,
    AuthenticatedBlobCustodySendContextV2, BLOB_CUSTODY_CLAIM_V2_BYTES, BlobCustodyClaimV2,
    VerifiedBlobCustodyClaimV2,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use blob_stream::{
    BLOB_STREAM_SEGMENT_BYTES, BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES, BlobPublicationStreamId,
    BlobStreamCheckpoint, BlobStreamFinalCommitment, BlobStreamFrontier, BlobStreamOpen,
    BlobStreamPlainPartition, BlobStreamPlaintextFrontier, BlobStreamPublication,
    BlobStreamPublicationSource, BlobStreamSegmentLeaves, BlobStreamSegmentOpener,
    BlobStreamSegmentSealer, BlobStreamSubtree, BlobUploadDescriptor, BlobUploadPlainPartition,
    BlobUploadSegmentOpener, BlobUploadSegmentSealer, EncryptedBlobStreamSegment,
    EncryptedBlobStreamSegmentHeader, MAX_BLOB_STREAM_BYTES,
    MAX_BLOB_STREAM_PUBLICATION_SOURCE_BYTES, VerifiedBlobStreamFinalCommitment,
    VerifiedBlobStreamOpen, VerifiedBlobStreamPublication, VerifiedBlobStreamPublicationSource,
    local_blob_publication_stream_id,
};
#[cfg(feature = "reference-session")]
pub use bridge_adapter::{
    BridgeAuthorizationLink, MAX_SELECTED_BRIDGE_WRAPPER_BYTES, SelectedBridgeAuthorizationPolicy,
    SelectedBridgeEnrollment, SelectedBridgeError, SelectedBridgeNarrowingPolicy,
    SelectedEventBridgeAdapter, VerifiedSelectedBridgeAuthorization,
    VerifiedSelectedBridgeEnrollment, VerifiedSelectedBridgeEventRoute,
};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use crypto::fuzz_reference_v9_session_pair;
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub use crypto::{
    ApplicationProtection, AuthenticatedChannelBinding, CLASSICAL_SECURITY_PROFILE_ID,
    CLASSICAL_SUITE_ID, ClassicalAuthenticatedSession, ClassicalEnvelopeSealer,
    ClassicalProvisioner, ClassicalProvisioningAccess, ClassicalProvisioningBundle,
    ClassicalSessionAwaitingFinished, ClassicalSessionInitiator, ClassicalSessionResponder,
    ClassicalSessionResponderPending, HYBRID_SECURITY_PROFILE_ID, ProfileEnvelopeSealer,
    ProfileProvisioningBundle, ProvisioningAccess, ProvisioningBundle,
    REFERENCE_SESSION_FRAME_OVERHEAD_BYTES, ReferenceAuthenticatedSession, ReferenceEnvelopeSealer,
    ReferenceNode, ReferenceProvisioner, ReferenceSessionAwaitingFinished,
    ReferenceSessionInitiator, ReferenceSessionResponder, ReferenceSessionResponderPending,
    ScopeRekeyPlan, ScopeRekeyRecipient, SecurityProfile, SecurityProfileId,
    VerifiedSecurityProfile, open_reference_node,
};
#[cfg(all(feature = "reference-session", not(feature = "adapter-sdk")))]
pub use crypto::{
    ApplicationProtection, AuthenticatedChannelBinding, CLASSICAL_SECURITY_PROFILE_ID,
    CLASSICAL_SUITE_ID, ClassicalAuthenticatedSession, ClassicalEnvelopeSealer,
    ClassicalProvisioner, ClassicalProvisioningAccess, ClassicalProvisioningBundle,
    ClassicalSessionAwaitingFinished, ClassicalSessionInitiator, ClassicalSessionResponder,
    ClassicalSessionResponderPending, HYBRID_SECURITY_PROFILE_ID, ProfileEnvelopeSealer,
    ProfileProvisioningBundle, ProvisioningAccess, ProvisioningBundle,
    REFERENCE_SESSION_FRAME_OVERHEAD_BYTES, ReferenceAuthenticatedSession, ReferenceEnvelopeSealer,
    ReferenceProvisioner, ReferenceSessionAwaitingFinished, ReferenceSessionInitiator,
    ReferenceSessionResponder, ReferenceSessionResponderPending, ScopeRekeyRecipient,
    SecurityProfile, SecurityProfileId, VerifiedSecurityProfile,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use custody::{
    CUSTODY_CLAIMS_ENCODED_LEN, CustodyAge, CustodyClaims, CustodyContinuity, CustodyDisposition,
    CustodyError, CustodyExpectation, CustodyHop, CustodySample, CustodyTransferClaims,
    CustodyTransferId, MAX_CUSTODY_WRAPPER_BYTES, MIN_CUSTODY_SEMANTIC_VERSION,
    TransmissionOrderKey, VerifiedCustodyClaims, checked_forwarding_age, evaluate_custody,
    retry_delay_ms,
};
#[cfg(all(feature = "sqlite-store", feature = "adapter-sdk"))]
pub use engine::{
    ApplicationItem, Delivery as EngineDelivery, PublishReceipt, RecordMergePolicy, RecordVersion,
};
#[cfg(feature = "sqlite-store")]
pub use engine::{EmissionPolicy, EngineError, PublishRequest, ResolveRequest};
pub use model::{
    CausalStamp, ConflictAnnotation, DataClass, Dot, ItemId, MAX_CAUSAL_CONTEXT_ENTRIES, NodeId,
    PeerStatus, Priority, Scope, SyncStatus, Topic, VersionVector,
};
pub use provisioning::{
    MAX_PROTECTED_PROVISIONING_BYTES, MAX_PROVISIONING_SECRET_REF_BYTES,
    MAX_UNPROTECTED_PROVISIONING_BYTES, PROVISIONING_SECRET_OPERATION_ID_BYTES,
    ProtectedProvisioningError, ProvisioningDestroyDisposition, ProvisioningDestroyId,
    ProvisioningDestroyReceipt, ProvisioningInstallDisposition, ProvisioningInstallId,
    ProvisioningInstallReceipt, ProvisioningLoadId, ProvisioningLoadReceipt,
    ProvisioningProtectionError, ProvisioningProtector, ProvisioningSecretDestroyer,
    ProvisioningSecretInstaller, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, ProvisioningUnprotector, UnprotectedProvisioning,
    destroy_provisioning_secret, install_provisioning_secret, load_provisioning_secret,
    protect_provisioning_artifact, unprotect_provisioning_artifact,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use source_blob::{
    BlobContentVerification, BlobPeerContentProof, BlobStreamLineage, ContentVerifiedBlobEnvelope,
    CurrentBlobLineage, RouteVerifiedBlobEnvelope,
};
#[cfg(feature = "reference-session")]
pub use source_control::{
    ActivationReadyControlEnvelope, RegistryAuthenticatedScopeRekeyPlan,
    ScopeRekeyPublicationCapability, VerifiedControlEnvelope, VerifiedControlKind,
    VerifiedControlPrincipal,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use source_event::{
    ContentVerifiedEventEnvelope, EventContentVerification, EventRouteLineage,
    RouteVerifiedEventEnvelope, SourceRouteLineage,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use source_record::{
    ContentVerifiedRecordEnvelope, RecordContentVerification, RouteVerifiedRecordEnvelope,
};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use source_state::{
    ContentVerifiedStateEnvelope, RouteVerifiedStateEnvelope, StateContentVerification,
};
#[cfg(feature = "sqlite-store")]
pub use store::{BridgeFilter, EventGap, PeerSnapshot, QuotaUsage, SubscriptionId};
#[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
pub use transfer_profile::{
    NegotiatedTransferProfiles, TransferLaneId, TransferProfileError, TransferProfileId,
    TransferProfileOfferV1, blob_profile_for_canonical_shape, negotiate_transfer_profiles,
    negotiate_transfer_profiles_for_semantic_version, transfer_profile_digest,
};

/// Stable replication-wire, credential, and cryptographic-profile version.
pub const REPLICATION_WIRE_VERSION: u16 = 1;

/// Legacy alias for [`REPLICATION_WIRE_VERSION`].
///
/// This value does not report the semantic version selected by an authenticated
/// session. It remains available so existing callers keep their source and
/// binary expectations while migrating to the unambiguous version surfaces.
pub const PROTOCOL_VERSION: u16 = REPLICATION_WIRE_VERSION;

/// Semantic replication version offered first by a default initiator.
pub const DEFAULT_SEMANTIC_VERSION: u16 = 9;

/// Highest semantic replication version implemented by this build.
pub const HIGHEST_SUPPORTED_SEMANTIC_VERSION: u16 = 9;

#[cfg(feature = "sqlite-store")]
const _: () = assert!(batch::DATA_CLASS_EVENT == model::DataClass::Event as u8);

#[cfg(test)]
mod version_surface_tests {
    use super::*;

    #[test]
    fn public_versions_match_the_authenticated_session_defaults() {
        assert_eq!(PROTOCOL_VERSION, REPLICATION_WIRE_VERSION);
        #[cfg(any(feature = "reference-session", feature = "sqlite-store"))]
        assert_eq!(
            crypto::SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
            &[9, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(DEFAULT_SEMANTIC_VERSION, 9);
        assert_eq!(HIGHEST_SUPPORTED_SEMANTIC_VERSION, DEFAULT_SEMANTIC_VERSION);
        #[cfg(feature = "sqlite-store")]
        assert_eq!(batch::DATA_CLASS_EVENT, DataClass::Event as u8);
    }
}

#[cfg(all(test, feature = "reference-session", not(feature = "sqlite-store")))]
mod reference_session_feature_tests {
    use super::*;

    fn access() -> ProvisioningAccess {
        ProvisioningAccess::member(
            Scope::new("test/reference-session").expect("scope"),
            vec![1],
            vec![Topic::new("mesh").expect("topic")],
        )
        .expect("access")
    }

    fn encoded_bundle(provisioner: &mut ReferenceProvisioner, serial: u64) -> (Vec<u8>, NodeId) {
        let bundle = provisioner
            .issue_node(serial, &[access()])
            .expect("issue bundle");
        let encoded = bundle.to_bytes().expect("encode bundle");
        let identity = ReferenceEnvelopeSealer::open(
            ProvisioningBundle::from_bytes(&encoded).expect("parse identity bundle"),
        )
        .expect("open reference identity")
        .identity();
        (encoded, identity)
    }

    #[test]
    fn minimal_feature_runs_proven_handshake_and_replay_protection() {
        let mut provisioner = ReferenceProvisioner::from_seed([0xa5; 32]).expect("provisioner");
        let (initiator_bundle, initiator_id) = encoded_bundle(&mut provisioner, 1);
        let (responder_bundle, responder_id) = encoded_bundle(&mut provisioner, 2);

        let (initiator, first) = ReferenceSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bundle).expect("initiator bundle"),
        )
        .expect("start initiator");
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bundle).expect("responder bundle"),
        )
        .expect("open responder");
        let (responder, second) = responder.receive_client(&first).expect("receive client");
        let (initiator, third) = initiator.receive_server(&second).expect("receive server");
        let (mut responder, fourth) = responder
            .receive_client_auth(&third)
            .expect("receive client authentication");
        let mut initiator = initiator
            .receive_finished(&fourth)
            .expect("receive finished");

        assert_eq!(initiator.peer_identity(), responder_id);
        assert_eq!(responder.peer_identity(), initiator_id);
        assert_eq!(initiator.semantic_version(), DEFAULT_SEMANTIC_VERSION);
        assert_eq!(responder.semantic_version(), DEFAULT_SEMANTIC_VERSION);
        let frame = initiator.seal_frame(b"mesh-ping").expect("seal frame");
        assert_eq!(
            responder.open_frame(&frame).expect("open frame"),
            b"mesh-ping"
        );
        assert!(responder.open_frame(&frame).is_err());

        let transfer = CustodyTransferClaims::new(
            CustodyTransferId::from_exact_hash([0x51; 32]),
            4_096,
            Some(1_000),
            Priority::Immediate,
        )
        .expect("nonempty transfer");
        let claims = CustodyClaims::new(
            transfer,
            7,
            3,
            CustodyHop::new(
                100,
                CustodySample {
                    clock_id: [0x61; 16],
                    tick_ms: 500,
                },
                20,
            )
            .expect("custody hop"),
        )
        .expect("nonzero policy revision");
        let expected = CustodyExpectation::new(transfer, 7);
        let wrapper = initiator
            .seal_custody_wrapper(&claims)
            .expect("seal custody wrapper");
        assert!(wrapper.len() <= MAX_CUSTODY_WRAPPER_BYTES);
        let outer = initiator.seal_frame(&wrapper).expect("seal outer frame");
        let opened_wrapper = responder.open_frame(&outer).expect("open outer frame");
        let verified = responder
            .open_custody_wrapper(&opened_wrapper, expected)
            .expect("open custody wrapper");
        assert_eq!(verified.transfer_id(), transfer.transfer_id());
        assert_eq!(verified.exact_len(), transfer.exact_len());
        assert_eq!(verified.forwarding_age_ms(), 120);
        assert!(
            responder
                .open_custody_wrapper(&opened_wrapper, expected)
                .is_err()
        );
        let later = initiator.seal_frame(b"after-custody").expect("later seal");
        assert_eq!(
            responder.open_frame(&later).expect("later open"),
            b"after-custody"
        );
    }

    #[test]
    fn minimal_feature_rejects_cross_mission_handshake() {
        let mut mission_a = ReferenceProvisioner::from_seed([0xa6; 32]).expect("mission A");
        let mut mission_b = ReferenceProvisioner::from_seed([0xa7; 32]).expect("mission B");
        let initiator = mission_a.issue_node(1, &[access()]).expect("initiator");
        let responder = mission_b.issue_node(1, &[access()]).expect("responder");
        let (_initiator, first) =
            ReferenceSessionInitiator::start(initiator).expect("start initiator");
        let responder = ReferenceSessionResponder::open(responder).expect("open responder");
        assert!(responder.receive_client(&first).is_err());
    }
}
