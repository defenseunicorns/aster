//! Shared protocol, provisioning, and cryptographic services for Aster nodes.
//!
//! Persistence and application runtime composition belong to `aster-node`.
//! `adapter-sdk` exposes transport and conformance contracts.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "adapter-sdk"), allow(dead_code, unused_imports))]

#[cfg(feature = "adapter-sdk")]
pub mod batch;
#[cfg(not(feature = "adapter-sdk"))]
mod batch;
#[cfg(feature = "adapter-sdk")]
pub mod blob;
#[cfg(not(feature = "adapter-sdk"))]
mod blob;
mod blob_custody;
mod blob_custody_v2;
mod blob_stream;
pub(crate) mod bridge;
#[cfg(feature = "reference-session")]
pub mod bridge_adapter;
#[cfg(feature = "adapter-sdk")]
pub mod causal;
#[cfg(not(feature = "adapter-sdk"))]
mod causal;
mod crypto;
mod custody;
#[path = "session_engine.rs"]
pub mod engine;
mod envelope;
#[cfg(feature = "adapter-sdk")]
pub mod fragment;
#[cfg(not(feature = "adapter-sdk"))]
mod fragment;
#[cfg(feature = "adapter-sdk")]
pub mod inventory;
#[cfg(not(feature = "adapter-sdk"))]
mod inventory;
#[cfg(feature = "adapter-sdk")]
pub mod link;
#[cfg(not(feature = "adapter-sdk"))]
mod link;
#[cfg(feature = "adapter-sdk")]
pub mod model;
#[cfg(not(feature = "adapter-sdk"))]
mod model;
pub mod provisioning;
mod source_blob;
#[cfg(feature = "reference-session")]
mod source_control;
mod source_event;
mod source_record;
mod source_state;
#[path = "session_store.rs"]
mod store;
mod transfer_profile;
#[cfg(feature = "adapter-sdk")]
pub mod wire;
#[cfg(not(feature = "adapter-sdk"))]
mod wire;

pub use blob::ReferenceBlobReader;
pub use blob::{
    BlobCarrierId, BlobChunkRecord, BlobError, BlobId, BlobManifest, BlobMetadata,
    BlobPhysicalLineage, BlobRangeReadStats, BlobReadStats, BlobReader, BlobRouteCommitment,
    BlobStore, BlobStoreConfig, BlobWriteProgress, BuiltBlobTransferObject, FinishedBlob,
    MAX_BLOB_CHUNK_SIZE, MAX_BLOB_CHUNKS, MAX_BLOB_MANIFEST_BYTES, MAX_BLOB_MEDIA_TYPE_BYTES,
    MAX_BLOB_SCHEMA_ID_BYTES, MAX_BLOB_TRANSFER_OBJECT_BYTES, MIN_BLOB_CHUNK_SIZE, PreparedBlob,
    ReferenceBlobService, SELECTED_BLOB_CHUNK_SIZE, VerifiedBlobContentCompletion,
    VerifiedBlobTransferObject, VerifiedBlobTransferPlan, prepare_blob,
};
pub use blob_custody::{
    AuthenticatedBlobCustodyContactV1, AuthenticatedBlobCustodySendContextV1,
    BLOB_CUSTODY_CLAIM_V1_BYTES, BlobCustodyClaimV1, BlobCustodyDirectionV1, BlobCustodyError,
    BlobCustodyTransferId, OpenedBlobSourceFrameV1, VerifiedBlobCustodyClaimV1,
};
pub use blob_custody_v2::{
    ApplicationRecordContext, AuthenticatedBlobCustodyContactV2,
    AuthenticatedBlobCustodySendContextV2, BLOB_CUSTODY_CLAIM_V2_BYTES, BlobCustodyClaimV2,
    VerifiedBlobCustodyClaimV2,
};
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
pub use crypto::{
    ApplicationProtection, AuthenticatedChannelBinding, CLASSICAL_SECURITY_PROFILE_ID,
    CLASSICAL_SUITE_ID, ClassicalAuthenticatedSession, ClassicalEnvelopeSealer,
    ClassicalProvisioner, ClassicalProvisioningAccess, ClassicalProvisioningBundle,
    ClassicalSessionAwaitingFinished, ClassicalSessionInitiator, ClassicalSessionResponder,
    ClassicalSessionResponderPending, HYBRID_SECURITY_PROFILE_ID, ProfileEnvelopeSealer,
    ProfileProvisioningBundle, ProvisioningAccess, ProvisioningBundle,
    REFERENCE_SESSION_FRAME_OVERHEAD_BYTES, ReferenceAuthenticatedSession, ReferenceEnvelopeSealer,
    ReferenceProvisioner, ReferenceSessionAwaitingFinished, ReferenceSessionInitiator,
    ReferenceSessionResponder, ReferenceSessionResponderPending, ScopeRekeyPlan,
    ScopeRekeyRecipient, SecurityProfile, SecurityProfileId, VerifiedSecurityProfile,
};
pub use custody::{
    CUSTODY_CLAIMS_ENCODED_LEN, CustodyAge, CustodyClaims, CustodyContinuity, CustodyDisposition,
    CustodyError, CustodyExpectation, CustodyHop, CustodySample, CustodyTransferClaims,
    CustodyTransferId, MAX_CUSTODY_WRAPPER_BYTES, MIN_CUSTODY_SEMANTIC_VERSION,
    TransmissionOrderKey, VerifiedCustodyClaims, checked_forwarding_age, evaluate_custody,
    retry_delay_ms,
};
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
pub use source_event::{
    ContentVerifiedEventEnvelope, EventContentVerification, EventRouteLineage,
    RouteVerifiedEventEnvelope, SourceRouteLineage,
};
pub use source_record::{
    ContentVerifiedRecordEnvelope, RecordContentVerification, RouteVerifiedRecordEnvelope,
};
pub use source_state::{
    ContentVerifiedStateEnvelope, RouteVerifiedStateEnvelope, StateContentVerification,
};
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

const _: () = assert!(batch::DATA_CLASS_EVENT == model::DataClass::Event as u8);

#[cfg(test)]
mod version_surface_tests {
    use super::*;

    #[test]
    fn public_versions_match_the_authenticated_session_defaults() {
        assert_eq!(PROTOCOL_VERSION, REPLICATION_WIRE_VERSION);
        assert_eq!(crypto::SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS, &[9]);
        assert_eq!(DEFAULT_SEMANTIC_VERSION, 9);
        assert_eq!(HIGHEST_SUPPORTED_SEMANTIC_VERSION, DEFAULT_SEMANTIC_VERSION);
        assert_eq!(batch::DATA_CLASS_EVENT, DataClass::Event as u8);
    }
}

#[cfg(all(test, feature = "reference-session"))]
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
