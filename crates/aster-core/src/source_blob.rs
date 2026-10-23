//! Source-authenticated selected Blob manifest seam for store/runtime compositions.
//!
//! The protected envelope payload is the exact bounded canonical Blob manifest.
//! Route-only nodes can authenticate its `(BlobId, chunk_count, route_root)`
//! commitment, while only a provider with the exact topic content grant can
//! mint a capability that authorizes manifest installation and plaintext reads.

use crate::{
    blob::{
        AuthenticatedBlobRoute, BlobError, BlobId, BlobManifest, BlobPhysicalLineage,
        BlobRangeReadStats, BlobReader, BlobRouteCommitment, BlobStore, InspectedBlobManifest,
        MAX_BLOB_MANIFEST_BYTES, ReferenceBlobService, VerifiedBlobContentCompletion,
        VerifiedBlobManifest, VerifiedBlobTransferPlan, content_group_id,
        inspect_selected_blob_manifest, verify_source_authenticated_store_completion,
    },
    blob_stream::{
        BlobStreamFinalCommitment, BlobStreamOpen, BlobStreamPublication,
        BlobStreamPublicationSource, BlobStreamSegmentOpener, BlobStreamSegmentSealer,
        BlobUploadDescriptor, BlobUploadSegmentOpener, BlobUploadSegmentSealer,
        VerifiedBlobStreamFinalCommitment, VerifiedBlobStreamOpen, VerifiedBlobStreamPublication,
        VerifiedBlobStreamPublicationSource,
    },
    crypto::ReferenceEnvelopeSealer,
    envelope::{EnvelopeError, EnvelopeHeader, EnvelopeSealer, SealRequest, SealedEnvelope},
    model::{DataClass, Dot, ItemId, NodeId, Priority, Scope, Topic, VersionVector},
    source_event::SourceRouteLineage,
    wire::EnvelopeId,
};
use sha2::{Digest, Sha256};
use std::io;

/// Unforgeable module-private witness for provider-authenticated stream capabilities.
pub(crate) struct BlobStreamProviderSeal(pub(crate) ());

/// Provider-authenticated route and physical lineage for one exact Profile-5
/// stream open. These opaque bindings carry no key material and let durable
/// lifecycle state reject same-epoch grant replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamLineage {
    route: SourceRouteLineage,
    physical: BlobPhysicalLineage,
}

impl BlobStreamLineage {
    pub const fn route(self) -> SourceRouteLineage {
        self.route
    }

    pub const fn physical(self) -> BlobPhysicalLineage {
        self.physical
    }
}

const BLOB_STREAM_OPEN_SIGNATURE_DOMAIN: &[u8] = b"ASTER/blob-stream/signed-open/v2\0";
const BLOB_STREAM_COMMITMENT_SIGNATURE_DOMAIN: &[u8] = b"ASTER/blob-stream/signed-commitment/v2\0";
const BLOB_STREAM_PUBLICATION_SIGNATURE_DOMAIN: &[u8] =
    b"ASTER/blob-stream/signed-publication/v2\0";
const MAX_BLOB_STREAM_OPEN_BODY_BYTES: usize = crate::blob_stream::MAX_BLOB_STREAM_OPEN_BYTES;
const MAX_BLOB_STREAM_COMMITMENT_BODY_BYTES: usize =
    crate::blob_stream::MAX_BLOB_STREAM_COMMITMENT_BODY_BYTES;
const MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES: usize =
    crate::blob_stream::MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES;

/// Route- and source-authenticated metadata for one exact selected Blob envelope.
///
/// Fields and construction are deliberately private. This capability permits
/// opaque custody decisions, but it cannot authorize manifest installation or
/// plaintext reads. Use [`ReferenceEnvelopeSealer::verify_blob_content`] to
/// obtain a [`ContentVerifiedBlobEnvelope`] when content access is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteVerifiedBlobEnvelope {
    envelope: crate::envelope::VerifiedEnvelope,
    envelope_id: [u8; 32],
    mission_authority_id: NodeId,
    route_lineage: SourceRouteLineage,
}

impl RouteVerifiedBlobEnvelope {
    fn from_verified(
        envelope: crate::envelope::VerifiedEnvelope,
        sealed: &[u8],
        mission_authority_id: NodeId,
        route_lineage: SourceRouteLineage,
    ) -> Result<Self, EnvelopeError> {
        validate_selected_blob_header(&envelope.header)?;
        Ok(Self {
            envelope,
            envelope_id: Sha256::digest(sealed).into(),
            mission_authority_id,
            route_lineage,
        })
    }

    /// Semantic identifier derived by the existing source-envelope profile.
    pub const fn item_id(&self) -> ItemId {
        self.envelope.id
    }

    /// SHA-256 transfer identity of the exact stable source-sealed bytes.
    pub const fn envelope_id(&self) -> [u8; 32] {
        self.envelope_id
    }

    /// Stable mission authority that authenticated the source credential.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    /// Alias for [`Self::mission_authority_id`].
    pub const fn authority_id(&self) -> NodeId {
        self.mission_authority_id()
    }

    /// Opaque identity of the exact provider route grant which authenticated
    /// this source envelope.
    pub const fn route_lineage(&self) -> SourceRouteLineage {
        self.route_lineage
    }

    /// Complete provider-authenticated selected Blob metadata.
    pub const fn header(&self) -> &EnvelopeHeader {
        &self.envelope.header
    }

    /// Authority-provisioned source identity authenticated by the envelope.
    pub const fn publisher(&self) -> NodeId {
        self.envelope.header.stamp.dot.publisher
    }

    /// Exact source-authenticated causal dot.
    pub const fn dot(&self) -> Dot {
        self.envelope.header.stamp.dot
    }

    /// Source-authenticated causal context preceding this Blob publication.
    pub const fn causal_context(&self) -> &VersionVector {
        &self.envelope.header.stamp.context
    }

    /// Source-authenticated content channel.
    pub const fn topic(&self) -> &Topic {
        &self.envelope.header.topic
    }

    /// Source-authenticated administrative propagation scope.
    pub const fn scope(&self) -> &Scope {
        &self.envelope.header.scope
    }

    /// Source-authenticated scheduling priority.
    pub const fn priority(&self) -> Priority {
        self.envelope.header.priority
    }

    /// Source-authenticated finite TTL, or `None` for durable Blob data.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.envelope.header.ttl_ms
    }

    /// Exact 32-byte Blob identifier used as the logical key.
    pub fn logical_key(&self) -> &[u8] {
        &self.envelope.header.logical_key
    }

    /// Exact authenticated canonical manifest byte length.
    pub const fn content_len(&self) -> u64 {
        self.envelope.header.content_len
    }

    /// Selected Blobs can never be tombstones.
    pub const fn tombstone(&self) -> bool {
        self.envelope.header.tombstone
    }

    /// Source-authenticated route/content key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.envelope.header.key_epoch
    }

    /// Blob identity committed by the protected route descriptor.
    pub fn blob_id(&self) -> BlobId {
        self.route_commitment().blob_id()
    }

    /// Exact `(BlobId, chunk_count, route_root)` route commitment.
    pub fn route_commitment(&self) -> BlobRouteCommitment {
        self.envelope
            .header
            .blob_route
            .expect("RouteVerifiedBlobEnvelope requires a Blob route commitment")
    }

    /// Checks that later bytes equal the exact source-sealed representation.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        if <[u8; 32]>::from(Sha256::digest(sealed)) != self.envelope_id {
            return Err(EnvelopeError(
                "source Blob capability does not match sealed bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Source metadata and exact canonical manifest verified by an authorized provider.
///
/// Its private constructor is reachable only after the provider authenticates
/// and opens the exact envelope bytes held by a route capability.
#[derive(Clone, Eq, PartialEq)]
pub struct ContentVerifiedBlobEnvelope {
    route: RouteVerifiedBlobEnvelope,
    inspected: InspectedBlobManifest,
    manifest_sha256: [u8; 32],
    physical_lineage: BlobPhysicalLineage,
}

impl std::fmt::Debug for ContentVerifiedBlobEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentVerifiedBlobEnvelope")
            .field("blob_id", &self.blob_id())
            .field("envelope_id", &self.envelope_id())
            .field("mission_authority_id", &self.mission_authority_id())
            .field("publisher", &self.publisher())
            .field("manifest_len", &self.content_len())
            .field("manifest_digest", &"[REDACTED]")
            .field("physical_lineage", &self.physical_lineage)
            .finish()
    }
}

impl ContentVerifiedBlobEnvelope {
    fn from_opened(
        route: RouteVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
        physical_lineage: BlobPhysicalLineage,
    ) -> Result<Self, EnvelopeError> {
        let (inspected, computed_route) = inspect_selected_blob_manifest(manifest_bytes)
            .map_err(|_| invalid_selected_blob_manifest())?;
        if computed_route != route.route_commitment()
            || inspected.manifest().id() != route.blob_id()
            || inspected.manifest().chunk_count() != route.route_commitment().chunk_count()
            || *inspected.manifest().content_group()
                != content_group_id(route.scope(), route.topic())
            || inspected.manifest().content_epoch() != route.key_epoch()
        {
            return Err(EnvelopeError(
                "source Blob manifest differs from authenticated routing metadata".into(),
            ));
        }
        Ok(Self {
            route,
            inspected,
            manifest_sha256: Sha256::digest(manifest_bytes).into(),
            physical_lineage,
        })
    }

    /// Semantic identifier derived by the existing source-envelope profile.
    pub const fn item_id(&self) -> ItemId {
        self.route.item_id()
    }

    /// SHA-256 transfer identity of the exact source-sealed bytes that opened.
    pub const fn envelope_id(&self) -> [u8; 32] {
        self.route.envelope_id()
    }

    /// Stable mission authority that authenticated source and content access.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.route.mission_authority_id()
    }

    /// Alias for [`Self::mission_authority_id`].
    pub const fn authority_id(&self) -> NodeId {
        self.mission_authority_id()
    }

    /// Opaque identity of the exact route grant which authenticated the source.
    pub const fn route_lineage(&self) -> SourceRouteLineage {
        self.route.route_lineage()
    }

    /// Provider-owned one-way identity of the exact content grant which opened
    /// this physical encrypted variant.
    pub const fn physical_lineage(&self) -> BlobPhysicalLineage {
        self.physical_lineage
    }

    /// Complete source- and content-authenticated Blob metadata.
    pub const fn header(&self) -> &EnvelopeHeader {
        self.route.header()
    }

    /// Authority-provisioned source identity authenticated by the envelope.
    pub const fn publisher(&self) -> NodeId {
        self.route.publisher()
    }

    /// Exact source-authenticated causal dot.
    pub const fn dot(&self) -> Dot {
        self.route.dot()
    }

    /// Source-authenticated causal context preceding this Blob publication.
    pub const fn causal_context(&self) -> &VersionVector {
        self.route.causal_context()
    }

    /// Source-authenticated content channel.
    pub const fn topic(&self) -> &Topic {
        self.route.topic()
    }

    /// Source-authenticated administrative propagation scope.
    pub const fn scope(&self) -> &Scope {
        self.route.scope()
    }

    /// Source-authenticated scheduling priority.
    pub const fn priority(&self) -> Priority {
        self.route.priority()
    }

    /// Source-authenticated finite TTL, or `None` for durable Blob data.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.route.ttl_ms()
    }

    /// Exact 32-byte Blob identifier used as the logical key.
    pub fn logical_key(&self) -> &[u8] {
        self.route.logical_key()
    }

    /// Exact authenticated canonical manifest byte length.
    pub const fn content_len(&self) -> u64 {
        self.route.content_len()
    }

    /// Selected Blobs can never be tombstones.
    pub const fn tombstone(&self) -> bool {
        self.route.tombstone()
    }

    /// Source-authenticated route/content key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.route.key_epoch()
    }

    /// Blob identity committed by both route descriptor and exact manifest.
    pub fn blob_id(&self) -> BlobId {
        self.route.blob_id()
    }

    /// Exact `(BlobId, chunk_count, route_root)` route commitment.
    pub fn route_commitment(&self) -> BlobRouteCommitment {
        self.route.route_commitment()
    }

    /// Canonically decoded manifest authenticated from the exact payload bytes.
    pub fn manifest(&self) -> &BlobManifest {
        self.inspected.manifest()
    }

    /// Domain-separated digest of the exact canonical manifest encoding.
    pub fn manifest_digest(&self) -> &[u8; 32] {
        self.inspected.manifest_digest()
    }

    /// Checks that later bytes equal the exact content-verified envelope.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        self.route.verify_exact_sealed(sealed)
    }

    /// Checks that later bytes equal the exact authenticated canonical manifest.
    pub fn verify_exact_manifest(&self, manifest_bytes: &[u8]) -> Result<(), EnvelopeError> {
        if <[u8; 32]>::from(Sha256::digest(manifest_bytes)) != self.manifest_sha256 {
            return Err(EnvelopeError(
                "source Blob capability does not match manifest bytes".into(),
            ));
        }
        Ok(())
    }

    /// Alias for [`Self::verify_exact_manifest`] at generic payload boundaries.
    pub fn verify_exact_payload(&self, payload: &[u8]) -> Result<(), EnvelopeError> {
        self.verify_exact_manifest(payload)
    }

    /// Derives the complete nonconstructible carrier plan from the exact
    /// source-authenticated canonical manifest bytes.
    pub fn transfer_plan(
        &self,
        manifest_bytes: &[u8],
    ) -> Result<VerifiedBlobTransferPlan, BlobError> {
        self.verify_exact_manifest(manifest_bytes)
            .map_err(|_| BlobError::AuthenticationFailed)?;
        VerifiedBlobTransferPlan::from_authenticated_manifest(
            AuthenticatedBlobRoute::new(
                EnvelopeId::from_bytes(self.envelope_id()),
                self.route_commitment(),
            ),
            self.physical_lineage,
            manifest_bytes,
            &self.inspected,
        )
    }

    /// Proves that a durable adapter completed the exact authenticated manifest.
    ///
    /// Every expected and committed chunk record, plus the finalization digest,
    /// is compared without exposing content keys or creating source authority.
    /// Raw [`BlobStore::finalize_blob`] calls therefore remain storage mechanics,
    /// not sufficient evidence for publication or delivery.
    pub fn verify_store_completion<S: BlobStore + ?Sized>(
        &self,
        manifest_bytes: &[u8],
        store: &mut S,
    ) -> Result<(), BlobError> {
        self.verify_exact_manifest(manifest_bytes)
            .map_err(|_| BlobError::AuthenticationFailed)?;
        verify_source_authenticated_store_completion(
            manifest_bytes,
            self.inspected_manifest(),
            store,
        )
    }

    pub(crate) const fn inspected_manifest(&self) -> &InspectedBlobManifest {
        &self.inspected
    }
}

/// Provider-minted evidence that both route and physical content lineages are
/// still current for one exact content-verified Blob source.
///
/// Durable promotion should compare this proof with the pending source in the
/// same transaction. Construction remains private so a persisted binding or a
/// coordinate-only check cannot mint currentness.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CurrentBlobLineage {
    mission_authority_id: NodeId,
    source_envelope: EnvelopeId,
    route_lineage: SourceRouteLineage,
    physical_lineage: BlobPhysicalLineage,
    blob_id: BlobId,
    manifest_digest: [u8; 32],
}

/// Fixed provider-owned proof that one authenticated peer possesses the exact
/// current content grant for a Blob selector.
///
/// The bytes carry no content key. They are bound to mission authority,
/// scope/topic/epoch, and claimant NodeID, so another authenticated identity
/// cannot replay a copied proof. Same-epoch key replacement invalidates it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlobPeerContentProof([u8; 32]);

impl BlobPeerContentProof {
    pub const WIRE_LEN: usize = 32;

    /// Fixed proof bytes for a semantic-v5 Blob request.
    pub const fn wire_bytes(self) -> [u8; Self::WIRE_LEN] {
        self.0
    }

    pub const fn as_wire_bytes(&self) -> &[u8; Self::WIRE_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for BlobPeerContentProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BlobPeerContentProof([PROVIDER-OWNED])")
    }
}

impl std::fmt::Debug for CurrentBlobLineage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CurrentBlobLineage")
            .field("mission_authority_id", &self.mission_authority_id)
            .field("source_envelope", &self.source_envelope)
            .field("route_lineage", &self.route_lineage)
            .field("physical_lineage", &self.physical_lineage)
            .field("blob_id", &self.blob_id)
            .field("manifest_digest", &"[REDACTED]")
            .finish()
    }
}

impl CurrentBlobLineage {
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    pub const fn source_envelope(&self) -> EnvelopeId {
        self.source_envelope
    }

    pub const fn route_lineage(&self) -> SourceRouteLineage {
        self.route_lineage
    }

    pub const fn physical_lineage(&self) -> BlobPhysicalLineage {
        self.physical_lineage
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }
}

/// Result of attempting selected Blob content verification through the provider.
#[derive(Clone, Eq, PartialEq)]
// Keep parity with Event/Record verification by returning the strong capability
// directly. Exact manifest bytes remain out-of-line in `Vec` storage.
#[allow(clippy::large_enum_variant)]
pub enum BlobContentVerification {
    /// Source/route metadata is valid, but this provider has no content grant.
    RouteOnly(RouteVerifiedBlobEnvelope),
    /// Source metadata and the exact canonical manifest both authenticated.
    ContentVerified {
        blob: ContentVerifiedBlobEnvelope,
        manifest_bytes: Vec<u8>,
    },
}

impl std::fmt::Debug for BlobContentVerification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteOnly(blob) => formatter
                .debug_struct("BlobContentVerification::RouteOnly")
                .field("blob_id", &blob.blob_id())
                .field("envelope_id", &blob.envelope_id())
                .finish(),
            Self::ContentVerified {
                blob,
                manifest_bytes,
            } => formatter
                .debug_struct("BlobContentVerification::ContentVerified")
                .field("blob_id", &blob.blob_id())
                .field("envelope_id", &blob.envelope_id())
                .field("manifest_len", &manifest_bytes.len())
                .field("manifest_bytes", &"[REDACTED]")
                .finish(),
        }
    }
}

impl ReferenceEnvelopeSealer {
    /// Mints the node-protected provisional-upload codec for one immutable
    /// reservation without creating signed source or causal authority.
    pub fn blob_upload_segment_sealer(
        &self,
        scope: &Scope,
        topic: &Topic,
        upload: &BlobUploadDescriptor,
    ) -> Result<BlobUploadSegmentSealer, EnvelopeError> {
        let seed = self
            .blob_stream_content_grant_seed(scope, topic, upload.content_epoch())
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        BlobStreamSegmentSealer::from_upload_provider(upload, seed, BlobStreamProviderSeal(()))
            .map_err(blob_stream_authentication_error)
    }

    /// Opens only records bound to the exact provisional upload reservation.
    pub fn blob_upload_segment_opener(
        &self,
        scope: &Scope,
        topic: &Topic,
        upload: &BlobUploadDescriptor,
    ) -> Result<BlobUploadSegmentOpener, EnvelopeError> {
        let seed = self
            .blob_stream_content_grant_seed(scope, topic, upload.content_epoch())
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        BlobStreamSegmentOpener::from_upload_provider(upload, seed, BlobStreamProviderSeal(()))
            .map_err(blob_stream_authentication_error)
    }

    pub fn blob_stream_authorization_digest(
        &self,
        scope: &Scope,
        content_epoch: u64,
    ) -> Option<[u8; 32]> {
        self.current_source_route_grant_commitment(scope, content_epoch)
    }

    /// Mints opaque lifecycle lineage only for an open which is still bound to
    /// this provider's exact current route and content grants.
    pub fn blob_stream_lineage(
        &self,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<BlobStreamLineage, EnvelopeError> {
        if open.mission_authority_id() != self.mission_authority_id()
            || self.current_source_route_grant_commitment(
                open.open().scope(),
                open.open().content_epoch(),
            ) != Some(*open.open().authorization_digest())
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        let physical = self
            .current_blob_physical_lineage(
                open.open().scope(),
                open.open().topic(),
                open.open().content_epoch(),
            )
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        Ok(BlobStreamLineage {
            route: SourceRouteLineage::from_commitment(*open.open().authorization_digest()),
            physical,
        })
    }

    pub fn seal_blob_stream_open(&self, open: &BlobStreamOpen) -> Result<Vec<u8>, EnvelopeError> {
        if open.publisher() != self.identity()
            || open.mission_id() != &self.mission_authority_id()
            || self.current_source_route_grant_commitment(open.scope(), open.content_epoch())
                != Some(*open.authorization_digest())
        {
            return Err(EnvelopeError(
                "Blob stream open is outside the current source authority".into(),
            ));
        }
        self.seal_source_protocol_object(
            BLOB_STREAM_OPEN_SIGNATURE_DOMAIN,
            &open.encode(),
            MAX_BLOB_STREAM_OPEN_BODY_BYTES,
        )
    }

    pub fn verify_blob_stream_open(
        &self,
        signed_open: &[u8],
    ) -> Result<VerifiedBlobStreamOpen, EnvelopeError> {
        let (publisher, encoded) = self.verify_source_protocol_object(
            BLOB_STREAM_OPEN_SIGNATURE_DOMAIN,
            signed_open,
            MAX_BLOB_STREAM_OPEN_BODY_BYTES,
        )?;
        let open = BlobStreamOpen::decode(&encoded).map_err(blob_stream_authentication_error)?;
        if open.publisher() != publisher
            || open.mission_id() != &self.mission_authority_id()
            || self.current_source_route_grant_commitment(open.scope(), open.content_epoch())
                != Some(*open.authorization_digest())
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        Ok(VerifiedBlobStreamOpen::from_provider(
            open,
            self.mission_authority_id(),
            signed_open.to_vec(),
            BlobStreamProviderSeal(()),
        ))
    }

    pub fn seal_blob_stream_commitment(
        &self,
        commitment: &BlobStreamFinalCommitment,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_source_protocol_object(
            BLOB_STREAM_COMMITMENT_SIGNATURE_DOMAIN,
            &commitment.encode(),
            MAX_BLOB_STREAM_COMMITMENT_BODY_BYTES,
        )
    }

    pub fn verify_blob_stream_commitment(
        &self,
        open: &VerifiedBlobStreamOpen,
        signed_commitment: &[u8],
    ) -> Result<VerifiedBlobStreamFinalCommitment, EnvelopeError> {
        let (publisher, encoded) = self.verify_source_protocol_object(
            BLOB_STREAM_COMMITMENT_SIGNATURE_DOMAIN,
            signed_commitment,
            MAX_BLOB_STREAM_COMMITMENT_BODY_BYTES,
        )?;
        let commitment = BlobStreamFinalCommitment::decode(&encoded)
            .map_err(blob_stream_authentication_error)?;
        if publisher != open.open().publisher()
            || commitment.open_digest() != &open.open().digest()
            || commitment.stream_id() != open.open().stream_id()
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        Ok(VerifiedBlobStreamFinalCommitment::from_provider(
            commitment,
            signed_commitment.to_vec(),
            BlobStreamProviderSeal(()),
        ))
    }

    pub fn seal_blob_stream_publication(
        &self,
        publication: &BlobStreamPublication,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let open = publication.open();
        let lineage = self
            .current_blob_physical_lineage(open.scope(), open.topic(), open.content_epoch())
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        if open.publisher() != self.identity()
            || open.mission_id() != &self.mission_authority_id()
            || self.current_source_route_grant_commitment(open.scope(), open.content_epoch())
                != Some(*open.authorization_digest())
            || publication.physical_lineage() != lineage.binding()
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        self.seal_source_protocol_object(
            BLOB_STREAM_PUBLICATION_SIGNATURE_DOMAIN,
            &publication.encode(),
            MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES,
        )
    }

    pub fn verify_blob_stream_publication(
        &self,
        authenticated: &[u8],
    ) -> Result<VerifiedBlobStreamPublication, EnvelopeError> {
        let (publisher, encoded) = self.verify_source_protocol_object(
            BLOB_STREAM_PUBLICATION_SIGNATURE_DOMAIN,
            authenticated,
            MAX_BLOB_STREAM_PUBLICATION_BODY_BYTES,
        )?;
        let publication =
            BlobStreamPublication::decode(&encoded).map_err(blob_stream_authentication_error)?;
        let open = publication.open();
        let lineage = self
            .current_blob_physical_lineage(open.scope(), open.topic(), open.content_epoch())
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        if open.publisher() != publisher
            || open.mission_id() != &self.mission_authority_id()
            || self.current_source_route_grant_commitment(open.scope(), open.content_epoch())
                != Some(*open.authorization_digest())
            || publication.physical_lineage() != lineage.binding()
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        Ok(VerifiedBlobStreamPublication::from_provider(
            publication,
            authenticated.to_vec(),
            BlobStreamProviderSeal(()),
        ))
    }

    pub fn verify_blob_stream_publication_source(
        &self,
        encoded: &[u8],
    ) -> Result<VerifiedBlobStreamPublicationSource, EnvelopeError> {
        let source = BlobStreamPublicationSource::decode(encoded)
            .map_err(blob_stream_authentication_error)?;
        let publication =
            self.verify_blob_stream_publication(source.authenticated_publication())?;
        let physical_open = self.verify_blob_stream_open(source.authenticated_open())?;
        let physical_commitment =
            self.verify_blob_stream_commitment(&physical_open, source.authenticated_commitment())?;
        let semantic = publication.publication();
        let open = semantic.open();
        let physical = physical_open.open();
        let lineage = self.blob_stream_lineage(&physical_open)?;
        if semantic.blob_id() != physical_commitment.commitment().blob_id()
            || semantic.physical_lineage() != lineage.physical().binding()
            || open.total_len() != physical.total_len()
            || open.content_epoch() != physical.content_epoch()
            || open.metadata() != physical.metadata()
            || open.content_group() != physical.content_group()
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        Ok(VerifiedBlobStreamPublicationSource::from_provider(
            source,
            publication,
            physical_open,
            physical_commitment,
            BlobStreamProviderSeal(()),
        ))
    }

    pub fn blob_stream_segment_sealer(
        &self,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<BlobStreamSegmentSealer, EnvelopeError> {
        if open.open().publisher() != self.identity()
            || open.mission_authority_id() != self.mission_authority_id()
        {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        let seed = self
            .blob_stream_content_grant_seed(
                open.open().scope(),
                open.open().topic(),
                open.open().content_epoch(),
            )
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        BlobStreamSegmentSealer::from_provider(open, seed, BlobStreamProviderSeal(()))
            .map_err(blob_stream_authentication_error)
    }

    pub fn blob_stream_segment_opener(
        &self,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<BlobStreamSegmentOpener, EnvelopeError> {
        if open.mission_authority_id() != self.mission_authority_id() {
            return Err(blob_stream_authentication_error(
                BlobError::AuthenticationFailed,
            ));
        }
        let seed = self
            .blob_stream_content_grant_seed(
                open.open().scope(),
                open.open().topic(),
                open.open().content_epoch(),
            )
            .ok_or_else(|| blob_stream_authentication_error(BlobError::AuthenticationFailed))?;
        BlobStreamSegmentOpener::from_provider(open, seed, BlobStreamProviderSeal(()))
            .map_err(blob_stream_authentication_error)
    }

    /// Reports whether this node owns the exact route capability for a Blob scope epoch.
    pub fn can_route_blob(&self, scope: &Scope, epoch: u64) -> bool {
        self.can_route_event(scope, epoch)
    }

    /// Reports whether this node can open Blob content for an exact topic and epoch.
    pub fn can_open_blob_content(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.can_open_event_content(scope, topic, epoch)
    }

    /// Tests whether an exact provider-minted physical Blob lineage remains
    /// current at its scope/topic/epoch coordinates.
    pub fn is_current_blob_physical_lineage(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        lineage: BlobPhysicalLineage,
    ) -> bool {
        self.current_blob_physical_lineage(scope, topic, epoch) == Some(lineage)
    }

    /// Tests a persisted one-way physical-lineage binding without exposing a
    /// provider-minted capability or any content-key material.
    pub fn is_current_blob_physical_lineage_binding(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        binding: &[u8; 32],
    ) -> bool {
        self.current_blob_physical_lineage(scope, topic, epoch)
            .is_some_and(|lineage| lineage.binding() == binding)
    }

    /// Mints the semantic-v5 request proof for this node's exact current Blob
    /// content grant. Content-only nodes can mint a proof, but a serving peer's
    /// verification also requires exact route authorization.
    pub fn mint_blob_peer_content_proof(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
    ) -> Result<BlobPeerContentProof, EnvelopeError> {
        self.blob_peer_content_proof_bytes(self.identity(), scope, topic, epoch)
            .map(BlobPeerContentProof)
            .ok_or_else(|| {
                EnvelopeError("no current Blob content grant for requested selector".into())
            })
    }

    /// Authenticates a semantic-v5 peer's exact Blob-content entitlement.
    ///
    /// `peer` and `peer_route_commitments` must come from the same completed
    /// authenticated session. Callers must separately enforce current control
    /// revocation policy. This predicate always requires both exact route
    /// authorization and content-key possession and never infers content access
    /// from a route commitment alone.
    pub fn peer_can_open_blob_content(
        &self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        proof: &[u8; BlobPeerContentProof::WIRE_LEN],
    ) -> bool {
        if !self.peer_can_route(peer, peer_route_commitments, scope, epoch) {
            return false;
        }
        let Some(expected) = self.blob_peer_content_proof_bytes(peer, scope, topic, epoch) else {
            return false;
        };
        expected
            .iter()
            .zip(proof.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    /// Seals an exact canonical selected Blob manifest through the source provider.
    pub fn seal_blob_manifest(
        &mut self,
        header: &EnvelopeHeader,
        manifest_bytes: &[u8],
    ) -> Result<SealedEnvelope, EnvelopeError> {
        validate_selected_blob_header(header)?;
        if u64::try_from(manifest_bytes.len()).ok() != Some(header.content_len) {
            return Err(EnvelopeError(
                "source Blob manifest length differs from authenticated metadata".into(),
            ));
        }
        let (inspected, route) = inspect_selected_blob_manifest(manifest_bytes)
            .map_err(|_| invalid_selected_blob_manifest())?;
        validate_manifest_binding(header, &inspected, route)?;
        <Self as EnvelopeSealer>::seal(
            self,
            SealRequest {
                header,
                payload: manifest_bytes,
            },
        )
    }

    /// Authenticates source identity and protected Blob routing metadata.
    pub fn verify_blob(
        &mut self,
        sealed: &[u8],
    ) -> Result<RouteVerifiedBlobEnvelope, EnvelopeError> {
        let (verified, route_lineage) = self.inspect_source_route_with_lineage(sealed)?;
        RouteVerifiedBlobEnvelope::from_verified(
            verified,
            sealed,
            self.mission_authority_id(),
            SourceRouteLineage::from_commitment(route_lineage),
        )
    }

    /// Authenticates a Blob and requires its source to equal `expected`.
    pub fn verify_blob_from(
        &mut self,
        expected: NodeId,
        sealed: &[u8],
    ) -> Result<RouteVerifiedBlobEnvelope, EnvelopeError> {
        let blob = self.verify_blob(sealed)?;
        if blob.publisher() != expected {
            return Err(EnvelopeError(
                "source Blob publisher differs from expected identity".into(),
            ));
        }
        Ok(blob)
    }

    /// Attempts to authenticate and open the exact manifest for a route capability.
    pub fn verify_blob_content(
        &mut self,
        blob: RouteVerifiedBlobEnvelope,
        sealed: &[u8],
    ) -> Result<BlobContentVerification, EnvelopeError> {
        blob.verify_exact_sealed(sealed)?;
        if blob.mission_authority_id() != self.mission_authority_id() {
            return Err(EnvelopeError(
                "source Blob capability belongs to another mission authority".into(),
            ));
        }
        match <Self as EnvelopeSealer>::open_payload_if_authorized(self, &blob.envelope, sealed)? {
            None => Ok(BlobContentVerification::RouteOnly(blob)),
            Some(manifest_bytes) => {
                if u64::try_from(manifest_bytes.len()).ok() != Some(blob.content_len()) {
                    return Err(EnvelopeError(
                        "source Blob manifest length differs from authenticated metadata".into(),
                    ));
                }
                let physical_lineage = self
                    .current_blob_physical_lineage(blob.scope(), blob.topic(), blob.key_epoch())
                    .ok_or_else(|| {
                        EnvelopeError(
                            "source Blob content grant is not current for authenticated metadata"
                                .into(),
                        )
                    })?;
                let verified = ContentVerifiedBlobEnvelope::from_opened(
                    blob,
                    &manifest_bytes,
                    physical_lineage,
                )?;
                Ok(BlobContentVerification::ContentVerified {
                    blob: verified,
                    manifest_bytes,
                })
            }
        }
    }

    /// Mints currentness evidence only while both exact provider-owned
    /// lineages remain installed at the source-authenticated coordinates.
    pub fn verify_current_blob_lineage(
        &self,
        blob: &ContentVerifiedBlobEnvelope,
    ) -> Result<CurrentBlobLineage, EnvelopeError> {
        if blob.mission_authority_id() != self.mission_authority_id()
            || !self.is_current_source_route_lineage(
                blob.scope(),
                blob.key_epoch(),
                blob.route_lineage(),
            )
            || self.current_blob_physical_lineage(blob.scope(), blob.topic(), blob.key_epoch())
                != Some(blob.physical_lineage())
        {
            return Err(EnvelopeError(
                "source Blob route or content lineage is no longer current".into(),
            ));
        }
        Ok(CurrentBlobLineage {
            mission_authority_id: blob.mission_authority_id(),
            source_envelope: EnvelopeId::from_bytes(blob.envelope_id()),
            route_lineage: blob.route_lineage(),
            physical_lineage: blob.physical_lineage(),
            blob_id: blob.blob_id(),
            manifest_digest: *blob.manifest_digest(),
        })
    }
}

fn blob_stream_authentication_error(_error: BlobError) -> EnvelopeError {
    EnvelopeError("Blob stream authentication failed".into())
}

impl<S: BlobStore> ReferenceBlobService<S> {
    /// Installs the exact provider-verified canonical manifest into the durable adapter.
    pub fn install_verified_manifest(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
    ) -> Result<(), BlobError> {
        blob.verify_exact_manifest(manifest_bytes)
            .map_err(|_| BlobError::AuthenticationFailed)?;
        self.validate_verified_blob_binding(blob)?;
        let mut input = io::Cursor::new(manifest_bytes);
        self.install_authenticated_manifest(&mut input, blob.inspected_manifest())?;
        Ok(())
    }

    /// Opens a selected reader that remains borrowed from this service/store.
    pub fn reader_for_verified(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
    ) -> Result<BlobReader<&'_ mut S>, BlobError> {
        self.validate_verified_blob_binding(blob)?;
        self.reader(VerifiedBlobManifest::new(blob.manifest().clone()))
    }

    /// Reads one exact source-authenticated range without walking its plaintext prefix.
    ///
    /// Only chunks intersecting `offset..offset + output.len()` are decrypted,
    /// and every disclosed chunk is independently checked against the exact
    /// authenticated manifest. The caller must separately preserve any
    /// higher-level authorization and freshness checks around this bounded
    /// content operation.
    pub fn read_range_for_verified(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
        offset: u64,
        output: &mut [u8],
    ) -> Result<BlobRangeReadStats, BlobError> {
        self.validate_verified_blob_binding(blob)?;
        self.read_range(
            VerifiedBlobManifest::new(blob.manifest().clone()),
            offset,
            output,
        )
    }

    /// Freshly streams and authenticates every exact manifest chunk, including
    /// ciphertext digests, AEAD tags, plaintext digests, total length, and the
    /// whole-Blob digest, before minting a publication-grade content proof.
    pub fn verify_blob_content_completion(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
    ) -> Result<VerifiedBlobContentCompletion, BlobError> {
        blob.verify_exact_manifest(manifest_bytes)
            .map_err(|_| BlobError::AuthenticationFailed)?;
        self.validate_verified_blob_binding(blob)?;
        blob.verify_store_completion(manifest_bytes, self.store_mut())?;
        let stats = {
            let mut reader = self.reader_for_verified(blob)?;
            reader.stream_into(&mut io::sink())?
        };
        if stats.verified_chunks != blob.manifest().chunk_count()
            || stats.plaintext_bytes != blob.manifest().total_len()
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let mission_authority_id = self
            .bound_mission_authority_id()
            .ok_or(BlobError::AuthenticationFailed)?;
        Ok(VerifiedBlobContentCompletion::new(
            mission_authority_id,
            EnvelopeId::from_bytes(blob.envelope_id()),
            blob.blob_id(),
            *blob.manifest_digest(),
            blob.physical_lineage(),
            stats.verified_chunks,
            stats.plaintext_bytes,
        ))
    }

    fn validate_verified_blob_binding(
        &self,
        blob: &ContentVerifiedBlobEnvelope,
    ) -> Result<(), BlobError> {
        if self
            .bound_mission_authority_id()
            .is_some_and(|authority| authority != blob.mission_authority_id())
            || self.bound_content_group() != blob.manifest().content_group()
            || self.bound_epoch() != blob.manifest().content_epoch()
            || self.physical_lineage() != blob.physical_lineage()
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(())
    }
}

fn validate_selected_blob_header(header: &EnvelopeHeader) -> Result<(), EnvelopeError> {
    let route = header
        .blob_route
        .ok_or_else(|| EnvelopeError("selected source Blob requires a route commitment".into()))?;
    if header.class != DataClass::Blob
        || header.event_sequence.is_some()
        || header.tombstone
        || header.ttl_ms == Some(0)
        || header.content_len == 0
        || header.content_len > MAX_BLOB_MANIFEST_BYTES
        || header.logical_key.as_slice() != route.blob_id().as_bytes()
    {
        return Err(EnvelopeError(
            "authenticated envelope is not a valid selected Blob".into(),
        ));
    }
    Ok(())
}

fn validate_manifest_binding(
    header: &EnvelopeHeader,
    inspected: &InspectedBlobManifest,
    route: BlobRouteCommitment,
) -> Result<(), EnvelopeError> {
    if header.blob_route != Some(route)
        || inspected.manifest().id() != route.blob_id()
        || inspected.manifest().chunk_count() != route.chunk_count()
        || *inspected.manifest().content_group() != content_group_id(&header.scope, &header.topic)
        || inspected.manifest().content_epoch() != header.key_epoch
    {
        return Err(EnvelopeError(
            "source Blob manifest differs from authenticated routing metadata".into(),
        ));
    }
    Ok(())
}

fn invalid_selected_blob_manifest() -> EnvelopeError {
    EnvelopeError("invalid selected source Blob manifest".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlobChunkRecord, BlobMetadata, BlobStore, CausalStamp, SELECTED_BLOB_CHUNK_SIZE,
        crypto::{ProvisioningAccess, ReferenceProvisioner, ScopeRekeyRecipient},
        prepare_blob,
    };
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    #[derive(Default)]
    struct TestBlobStore {
        manifest: Option<BlobManifest>,
        plaintext: Vec<Option<[u8; 32]>>,
        records: Vec<Option<BlobChunkRecord>>,
        expected: Vec<Option<BlobChunkRecord>>,
        chunks: Vec<Option<Vec<u8>>>,
        finalized: Option<[u8; 32]>,
    }

    impl TestBlobStore {
        fn slot(&self, id: BlobId, index: u64) -> io::Result<usize> {
            let manifest = self
                .manifest
                .as_ref()
                .ok_or_else(|| io::Error::other("manifest absent"))?;
            if manifest.id() != id || index >= manifest.chunk_count() {
                return Err(io::Error::other("Blob key outside manifest"));
            }
            usize::try_from(index).map_err(io::Error::other)
        }
    }

    impl BlobStore for TestBlobStore {
        type StoreError = io::Error;

        fn begin_blob(&mut self, manifest: &BlobManifest) -> io::Result<()> {
            if let Some(existing) = &self.manifest {
                if existing != manifest {
                    return Err(io::Error::other("manifest conflict"));
                }
                return Ok(());
            }
            let count = usize::try_from(manifest.chunk_count()).map_err(io::Error::other)?;
            self.plaintext.resize(count, None);
            self.records.resize(count, None);
            self.expected.resize(count, None);
            self.chunks.resize(count, None);
            self.manifest = Some(manifest.clone());
            Ok(())
        }

        fn put_plaintext_digest(
            &mut self,
            id: BlobId,
            index: u64,
            digest: [u8; 32],
        ) -> io::Result<()> {
            let index = self.slot(id, index)?;
            if self.plaintext[index].is_some_and(|existing| existing != digest) {
                return Err(io::Error::other("plaintext digest conflict"));
            }
            self.plaintext[index] = Some(digest);
            Ok(())
        }

        fn plaintext_digest(&mut self, id: BlobId, index: u64) -> io::Result<Option<[u8; 32]>> {
            let index = self.slot(id, index)?;
            Ok(self.plaintext[index])
        }

        fn chunk_record(&mut self, id: BlobId, index: u64) -> io::Result<Option<BlobChunkRecord>> {
            let index = self.slot(id, index)?;
            Ok(self.records[index])
        }

        fn put_expected_chunk_record(
            &mut self,
            id: BlobId,
            index: u64,
            record: BlobChunkRecord,
        ) -> io::Result<()> {
            let index = self.slot(id, index)?;
            if self.expected[index].is_some_and(|existing| existing != record) {
                return Err(io::Error::other("expected record conflict"));
            }
            self.expected[index] = Some(record);
            Ok(())
        }

        fn expected_chunk_record(
            &mut self,
            id: BlobId,
            index: u64,
        ) -> io::Result<Option<BlobChunkRecord>> {
            let index = self.slot(id, index)?;
            Ok(self.expected[index])
        }

        fn commit_verified_chunk(
            &mut self,
            id: BlobId,
            index: u64,
            record: BlobChunkRecord,
            ciphertext: &[u8],
        ) -> io::Result<()> {
            let index = self.slot(id, index)?;
            if self.expected[index].is_some_and(|expected| expected != record)
                || self.records[index].is_some_and(|existing| existing != record)
                || self.chunks[index]
                    .as_ref()
                    .is_some_and(|existing| existing.as_slice() != ciphertext)
            {
                return Err(io::Error::other("chunk conflict"));
            }
            self.records[index] = Some(record);
            self.chunks[index] = Some(ciphertext.to_vec());
            Ok(())
        }

        fn read_verified_chunk(
            &mut self,
            id: BlobId,
            index: u64,
            output: &mut Vec<u8>,
        ) -> io::Result<bool> {
            let index = self.slot(id, index)?;
            output.clear();
            if let Some(chunk) = &self.chunks[index] {
                output.extend_from_slice(chunk);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn finalize_blob(&mut self, id: BlobId, manifest_digest: [u8; 32]) -> io::Result<()> {
            if self.manifest.as_ref().map(BlobManifest::id) != Some(id) {
                return Err(io::Error::other("Blob key outside manifest"));
            }
            if self
                .finalized
                .is_some_and(|existing| existing != manifest_digest)
            {
                return Err(io::Error::other("finalized digest conflict"));
            }
            self.finalized = Some(manifest_digest);
            Ok(())
        }

        fn finalized_manifest_digest(&mut self, id: BlobId) -> io::Result<Option<[u8; 32]>> {
            let _ = self.slot(id, 0)?;
            Ok(self.finalized)
        }
    }

    fn scope() -> Scope {
        Scope::new("test/source-blob").expect("scope")
    }

    fn topic() -> Topic {
        Topic::new("mesh-blob").expect("topic")
    }

    fn other_topic() -> Topic {
        Topic::new("other-blob").expect("other topic")
    }

    fn full_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1, 2], vec![topic(), other_topic()])
            .expect("member access")
    }

    fn relay_access() -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(), vec![1, 2]).expect("relay access")
    }

    fn wrong_topic_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1, 2], vec![other_topic()])
            .expect("wrong topic access")
    }

    struct Services {
        publisher: ReferenceEnvelopeSealer,
        other: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        relay: ReferenceEnvelopeSealer,
        wrong_topic: ReferenceEnvelopeSealer,
    }

    fn services() -> Services {
        let mut provisioner = ReferenceProvisioner::from_seed([0x41; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_node(1, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let other = provisioner
            .issue_node(2, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("other publisher");
        let reader = provisioner
            .issue_node(3, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("reader");
        let relay = provisioner
            .issue_node(4, &[relay_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("relay");
        let wrong_topic = provisioner
            .issue_node(5, &[wrong_topic_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong topic reader");
        Services {
            publisher,
            other,
            reader,
            relay,
            wrong_topic,
        }
    }

    fn wrong_mission_reader() -> ReferenceEnvelopeSealer {
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x92; 32]).expect("wrong mission provisioner");
        provisioner
            .issue_node(1, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong mission reader")
    }

    #[test]
    fn blob_stream_provider_authenticates_open_segments_and_finish() {
        let Services {
            publisher,
            reader,
            relay,
            other,
            ..
        } = services();
        let authorization = publisher
            .blob_stream_authorization_digest(&scope(), 1)
            .expect("authorization");
        let open = BlobStreamOpen::new(
            crate::blob_stream::BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream ID"),
            publisher.identity(),
            b"provider-test".to_vec(),
            publisher.mission_authority_id(),
            1,
            VersionVector::default(),
            topic(),
            scope(),
            BlobMetadata::new(Some("application/octet-stream".into()), b"schema".to_vec())
                .expect("metadata"),
            Priority::Immediate,
            None,
            None,
            7,
            1,
            1,
            authorization,
            [0x66; 32],
        )
        .expect("open");
        let signed_open = publisher.seal_blob_stream_open(&open).expect("sign open");
        let verified = reader
            .verify_blob_stream_open(&signed_open)
            .expect("verify open");
        let publisher_lineage = publisher
            .blob_stream_lineage(&verified)
            .expect("publisher stream lineage");
        assert_eq!(
            reader
                .blob_stream_lineage(&verified)
                .expect("reader stream lineage"),
            publisher_lineage
        );
        assert!(relay.blob_stream_lineage(&verified).is_err());
        let sealer = publisher
            .blob_stream_segment_sealer(&verified)
            .expect("segment sealer");
        let opener = reader
            .blob_stream_segment_opener(&verified)
            .expect("segment opener");
        assert!(relay.blob_stream_segment_opener(&verified).is_err());
        let partition = crate::blob_stream::BlobStreamPlainPartition::new(
            [0x11; 32],
            open.digest(),
            1,
            0,
            0,
            7,
            b"payload".to_vec(),
        )
        .expect("partition");
        let (encrypted, _) = sealer.seal(partition).expect("seal segment");
        assert_eq!(
            opener.open(&encrypted).expect("open segment").0.as_slice(),
            b"payload"
        );
        let commitment = BlobStreamFinalCommitment::new(&verified, [0x71; 32], [0x72; 32], 1, None)
            .expect("commitment");
        let signed_finish = publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("sign finish");
        reader
            .verify_blob_stream_commitment(&verified, &signed_finish)
            .expect("verify finish");
        let publication = BlobStreamPublication::new(
            open.clone(),
            commitment.blob_id(),
            commitment.final_custody(),
            *publisher_lineage.physical().binding(),
        )
        .expect("publication binding");
        let signed_publication = publisher
            .seal_blob_stream_publication(&publication)
            .expect("sign publication binding");
        let verified_publication = reader
            .verify_blob_stream_publication(&signed_publication)
            .expect("verify publication binding");
        assert_eq!(verified_publication.publication(), &publication);
        assert_eq!(
            verified_publication.authenticated_bytes(),
            signed_publication
        );
        let source = BlobStreamPublicationSource::new(
            signed_publication.clone(),
            signed_open.clone(),
            signed_finish.clone(),
        )
        .and_then(|source| source.encode())
        .expect("encode publication source");
        let verified_source = reader
            .verify_blob_stream_publication_source(&source)
            .expect("verify publication source");
        assert_eq!(
            verified_source.publication().authenticated_bytes(),
            signed_publication
        );
        assert_eq!(
            verified_source.physical_commitment().authenticated_bytes(),
            signed_finish
        );

        // The semantic publication may be paired with an independently
        // encoded equivalent physical pack from another authorized publisher.
        let other_authorization = other
            .blob_stream_authorization_digest(&scope(), 1)
            .expect("other authorization");
        let other_open = BlobStreamOpen::new(
            crate::blob_stream::BlobPublicationStreamId::from_bytes([0x12; 32])
                .expect("other stream ID"),
            other.identity(),
            b"provider-equivalent-pack".to_vec(),
            other.mission_authority_id(),
            1,
            VersionVector::default(),
            topic(),
            scope(),
            open.metadata().clone(),
            Priority::Immediate,
            None,
            None,
            7,
            1,
            1,
            other_authorization,
            [0x67; 32],
        )
        .expect("equivalent physical open");
        let other_signed_open = other
            .seal_blob_stream_open(&other_open)
            .expect("sign equivalent physical open");
        let other_verified_open = reader
            .verify_blob_stream_open(&other_signed_open)
            .expect("verify equivalent physical open");
        let other_commitment =
            BlobStreamFinalCommitment::new(&other_verified_open, [0x71; 32], [0x73; 32], 1, None)
                .expect("equivalent physical commitment");
        assert_eq!(other_commitment.blob_id(), commitment.blob_id());
        let other_signed_finish = other
            .seal_blob_stream_commitment(&other_commitment)
            .expect("sign equivalent physical commitment");
        let equivalent_source = BlobStreamPublicationSource::new(
            signed_publication.clone(),
            other_signed_open,
            other_signed_finish,
        )
        .and_then(|source| source.encode())
        .expect("encode equivalent publication source");
        reader
            .verify_blob_stream_publication_source(&equivalent_source)
            .expect("semantic publication accepts equivalent physical pack");

        let mut tampered_source = source;
        *tampered_source.last_mut().expect("source byte") ^= 1;
        assert!(
            reader
                .verify_blob_stream_publication_source(&tampered_source)
                .is_err()
        );
        let mut tampered = signed_finish;
        *tampered.last_mut().expect("signed byte") ^= 1;
        assert!(
            reader
                .verify_blob_stream_commitment(&verified, &tampered)
                .is_err()
        );
        let mut tampered = signed_publication;
        *tampered.last_mut().expect("signed byte") ^= 1;
        assert!(reader.verify_blob_stream_publication(&tampered).is_err());
    }

    struct Fixture {
        service: ReferenceBlobService<TestBlobStore>,
        manifest: BlobManifest,
        finished: crate::FinishedBlob,
        plaintext: Vec<u8>,
    }

    fn fixture(
        provider: &ReferenceEnvelopeSealer,
        channel: &Topic,
        epoch: u64,
        plaintext: Vec<u8>,
        metadata: BlobMetadata,
    ) -> Fixture {
        let mut source = Cursor::new(plaintext.clone());
        let prepared = prepare_blob(&mut source, SELECTED_BLOB_CHUNK_SIZE, metadata)
            .expect("prepare selected Blob");
        let mut service = provider
            .blob_service_with_store(&scope(), channel, epoch, TestBlobStore::default())
            .expect("provider-owned store service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install preparation");
        let progress = service
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .expect("encrypt chunks");
        assert!(progress.complete);
        let finished = service.finish_manifest(&manifest).expect("finish manifest");
        Fixture {
            service,
            manifest,
            finished,
            plaintext,
        }
    }

    fn header(
        publisher: NodeId,
        finished: &crate::FinishedBlob,
        channel: Topic,
        epoch: u64,
        counter: u64,
    ) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Blob,
            topic: channel,
            scope: scope(),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot { publisher, counter },
                context: VersionVector::default(),
            },
            event_sequence: None,
            logical_key: finished.id().as_bytes().to_vec(),
            blob_route: Some(finished.route_commitment()),
            ttl_ms: None,
            content_len: finished.manifest_bytes().len() as u64,
            tombstone: false,
            key_epoch: epoch,
        }
    }

    fn content_verified(
        reader: &mut ReferenceEnvelopeSealer,
        sealed: &[u8],
    ) -> (ContentVerifiedBlobEnvelope, Vec<u8>) {
        let route = reader.verify_blob(sealed).expect("verify Blob route");
        match reader
            .verify_blob_content(route, sealed)
            .expect("verify Blob content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        }
    }

    #[test]
    fn selected_blob_identity_capabilities_and_borrowed_reader_bind_exact_bytes() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let plaintext = (0..SELECTED_BLOB_CHUNK_SIZE as usize + 37)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let metadata = BlobMetadata::new(Some("application/octet-stream".into()), vec![7, 9])
            .expect("metadata");

        let mut positioned = Cursor::new(plaintext.clone());
        positioned.set_position(17);
        let same_first = prepare_blob(&mut positioned, SELECTED_BLOB_CHUNK_SIZE, metadata.clone())
            .expect("first preparation");
        assert_eq!(positioned.position(), 17);
        let same_second = prepare_blob(
            &mut Cursor::new(plaintext.clone()),
            SELECTED_BLOB_CHUNK_SIZE,
            metadata.clone(),
        )
        .expect("repeat preparation");
        assert_eq!(same_first.id(), same_second.id());
        let changed_metadata = prepare_blob(
            &mut Cursor::new(plaintext.clone()),
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(Some("application/example".into()), vec![7, 9])
                .expect("different metadata"),
        )
        .expect("metadata preparation");
        assert_ne!(same_first.id(), changed_metadata.id());
        let mut changed_plaintext = plaintext.clone();
        changed_plaintext[0] ^= 1;
        let changed_content = prepare_blob(
            &mut Cursor::new(changed_plaintext),
            SELECTED_BLOB_CHUNK_SIZE,
            metadata.clone(),
        )
        .expect("changed content preparation");
        assert_ne!(same_first.id(), changed_content.id());

        let mut fixture = fixture(&publisher, &topic(), 1, plaintext, metadata);
        let finished_debug = format!("{:?}", fixture.finished);
        assert!(finished_debug.contains("manifest_bytes: \"[REDACTED]\""));
        assert!(finished_debug.contains("manifest_digest: \"[REDACTED]\""));
        assert_eq!(fixture.manifest.id(), same_first.id());
        assert_eq!(fixture.manifest.chunk_size(), SELECTED_BLOB_CHUNK_SIZE);
        assert_eq!(fixture.manifest.chunk_count(), 2);
        let source_header = header(publisher.identity(), &fixture.finished, topic(), 1, 1);
        let sealed = publisher
            .seal_blob_manifest(&source_header, fixture.finished.manifest_bytes())
            .expect("seal selected Blob");
        let resealed = publisher
            .seal_blob_manifest(&source_header, fixture.finished.manifest_bytes())
            .expect("reseal selected Blob");
        assert_ne!(sealed.bytes, resealed.bytes);

        let route = reader.verify_blob(&sealed.bytes).expect("route capability");
        assert_eq!(route.item_id(), sealed.id);
        assert_eq!(route.blob_id(), fixture.finished.id());
        assert_eq!(
            route.route_commitment(),
            fixture.finished.route_commitment()
        );
        assert_eq!(route.logical_key(), fixture.finished.id().as_bytes());
        assert_eq!(route.ttl_ms(), None);
        assert!(!route.tombstone());
        assert_eq!(route.key_epoch(), 1);
        assert_eq!(route.header(), &source_header);
        assert!(route.verify_exact_sealed(&resealed.bytes).is_err());

        let verification = reader
            .verify_blob_content(route, &sealed.bytes)
            .expect("content verification");
        let debug = format!("{verification:?}");
        assert!(debug.contains("[REDACTED]"));
        let (blob, manifest_bytes) = match verification {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        assert_eq!(blob.blob_id(), fixture.finished.id());
        assert_eq!(blob.route_commitment(), fixture.finished.route_commitment());
        assert_eq!(blob.manifest(), &fixture.manifest);
        assert_eq!(blob.manifest_digest(), fixture.finished.manifest_digest());
        assert!(format!("{blob:?}").contains("manifest_digest: \"[REDACTED]\""));
        blob.verify_exact_sealed(&sealed.bytes)
            .expect("exact sealed bytes");
        blob.verify_exact_manifest(&manifest_bytes)
            .expect("exact manifest bytes");
        blob.verify_exact_payload(&manifest_bytes)
            .expect("exact payload alias");
        let mut stale = manifest_bytes.clone();
        stale[0] ^= 1;
        assert!(blob.verify_exact_manifest(&stale).is_err());

        fixture
            .service
            .install_verified_manifest(&blob, &manifest_bytes)
            .expect("install verified manifest");
        let current_lineage = reader
            .verify_current_blob_lineage(&blob)
            .expect("current Blob lineage");
        assert_eq!(
            current_lineage.mission_authority_id(),
            blob.mission_authority_id()
        );
        assert_eq!(
            current_lineage.source_envelope().as_bytes(),
            &blob.envelope_id()
        );
        assert_eq!(current_lineage.route_lineage(), blob.route_lineage());
        assert_eq!(current_lineage.physical_lineage(), blob.physical_lineage());
        assert_eq!(current_lineage.blob_id(), blob.blob_id());
        assert_eq!(current_lineage.manifest_digest(), blob.manifest_digest());

        let plan = blob
            .transfer_plan(&manifest_bytes)
            .expect("verified transfer plan");
        assert_eq!(plan.manifest(), blob.manifest());
        assert_eq!(plan.manifest_bytes(), manifest_bytes);
        assert_eq!(plan.manifest_digest(), blob.manifest_digest());
        assert_eq!(plan.physical_lineage(), blob.physical_lineage());
        assert_eq!(
            plan.chunk_records().len(),
            usize::try_from(blob.manifest().chunk_count()).expect("chunk count")
        );
        let first_id = plan.carrier_id(0).expect("first carrier ID");
        assert_eq!(first_id.wire_bytes()[0], 2);
        assert_eq!(
            plan.carrier_index(&first_id.wire_bytes())
                .expect("carrier index"),
            0
        );
        let built = plan
            .build_carrier(fixture.service.store_mut(), 0)
            .expect("canonical first carrier");
        assert_eq!(built.object_id(), first_id);
        assert!(built.bytes().len() <= crate::MAX_BLOB_TRANSFER_OBJECT_BYTES);
        assert_eq!(
            plan.carrier_total_len(&first_id.wire_bytes())
                .expect("carrier total length"),
            built.bytes().len() as u64
        );
        let (total, first_range) = plan
            .read_carrier_range(fixture.service.store_mut(), &first_id.wire_bytes(), 0, 137)
            .expect("bounded carrier range");
        assert_eq!(total, built.bytes().len() as u64);
        assert_eq!(first_range, built.bytes()[..137]);
        let verified_carrier = plan
            .verify_carrier(&first_id.wire_bytes(), built.bytes())
            .expect("verify canonical carrier");
        assert_eq!(verified_carrier.object_id(), first_id);
        assert_eq!(verified_carrier.index(), 0);
        assert_eq!(verified_carrier.record(), plan.chunk_records()[0]);
        let mut tampered_carrier = built.bytes().to_vec();
        *tampered_carrier.last_mut().expect("carrier byte") ^= 1;
        assert!(
            plan.verify_carrier(&first_id.wire_bytes(), &tampered_carrier)
                .is_err()
        );
        let mut imported = TestBlobStore::default();
        imported
            .begin_blob_with_lineage(plan.manifest(), plan.physical_lineage())
            .expect("begin imported physical variant");
        plan.install_verified_carrier(&mut imported, &verified_carrier)
            .expect("install verified carrier");
        assert_eq!(imported.records[0], Some(plan.chunk_records()[0]));

        let completion = fixture
            .service
            .verify_blob_content_completion(&blob, &manifest_bytes)
            .expect("fresh full-content completion");
        assert_eq!(
            completion.mission_authority_id(),
            blob.mission_authority_id()
        );
        assert_eq!(completion.source_envelope().as_bytes(), &blob.envelope_id());
        assert_eq!(completion.blob_id(), blob.blob_id());
        assert_eq!(completion.manifest_digest(), blob.manifest_digest());
        assert_eq!(completion.physical_lineage(), blob.physical_lineage());
        assert_eq!(completion.chunk_count(), blob.manifest().chunk_count());
        assert_eq!(completion.plaintext_bytes(), blob.manifest().total_len());
        let mut output = Vec::new();
        let stats = fixture
            .service
            .reader_for_verified(&blob)
            .and_then(|mut blob_reader| blob_reader.stream_into(&mut output))
            .expect("borrowed verified reader");
        assert_eq!(output, fixture.plaintext);
        assert_eq!(stats.plaintext_bytes, fixture.plaintext.len() as u64);
        assert_eq!(stats.verified_chunks, fixture.manifest.chunk_count());
    }

    #[test]
    fn store_completion_requires_every_exact_authenticated_record_and_digest() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let plaintext = (0..SELECTED_BLOB_CHUNK_SIZE as usize + 19)
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();
        let mut source = Cursor::new(plaintext);
        let prepared = prepare_blob(
            &mut source,
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(Some("application/octet-stream".into()), vec![4, 2])
                .expect("metadata"),
        )
        .expect("prepare selected Blob");
        let mut store = TestBlobStore::default();
        let mut service = publisher
            .blob_service_with_store(&scope(), &topic(), 1, &mut store)
            .expect("borrowed provider-owned store service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install preparation");
        assert!(
            service
                .encrypt_some(&mut source, &manifest, u64::MAX)
                .expect("encrypt chunks")
                .complete
        );
        let finished = service.finish_manifest(&manifest).expect("finish manifest");
        drop(service);
        // The selected redb adapter binds locally derived records as expected
        // records during commit. Model that stronger completion invariant here.
        store.expected.clone_from(&store.records);

        let selected = header(publisher.identity(), &finished, topic(), 1, 33);
        let sealed = publisher
            .seal_blob_manifest(&selected, finished.manifest_bytes())
            .expect("seal manifest");
        let (blob, manifest_bytes) = content_verified(&mut reader, &sealed.bytes);
        blob.verify_store_completion(&manifest_bytes, &mut store)
            .expect("exact durable completion");

        let authentic = store.records[0].expect("committed record");
        let mut wrong_ciphertext_digest = *authentic.ciphertext_sha256();
        wrong_ciphertext_digest[0] ^= 1;
        let wrong = BlobChunkRecord::from_parts(
            *authentic.plaintext_sha256(),
            wrong_ciphertext_digest,
            authentic.plaintext_len(),
            authentic.ciphertext_len(),
        )
        .expect("structurally valid wrong record");

        // A caller-controlled adapter cannot turn mutually consistent wrong
        // records plus the authentic final digest into completion authority.
        store.expected[0] = Some(wrong);
        store.records[0] = Some(wrong);
        store.finalized = Some(*blob.manifest_digest());
        assert!(
            blob.verify_store_completion(&manifest_bytes, &mut store)
                .is_err()
        );

        store.expected[0] = Some(authentic);
        store.records[0] = Some(authentic);
        store.finalized = Some([0x55; 32]);
        assert!(
            blob.verify_store_completion(&manifest_bytes, &mut store)
                .is_err()
        );

        store.finalized = Some(*blob.manifest_digest());
        store.expected[0] = None;
        assert!(
            blob.verify_store_completion(&manifest_bytes, &mut store)
                .is_err()
        );

        store.expected[0] = Some(authentic);
        let mut tampered_manifest = manifest_bytes;
        tampered_manifest[0] ^= 1;
        assert!(
            blob.verify_store_completion(&tampered_manifest, &mut store)
                .is_err()
        );
    }

    #[test]
    fn class_ttl_empty_noncanonical_chunking_and_tamper_fail_closed() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let fixture = fixture(
            &publisher,
            &topic(),
            1,
            b"nonempty selected Blob".to_vec(),
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        );
        let selected = header(publisher.identity(), &fixture.finished, topic(), 1, 1);

        let mut wrong_class = selected.clone();
        wrong_class.class = DataClass::State;
        wrong_class.blob_route = None;
        assert!(
            publisher
                .seal_blob_manifest(&wrong_class, fixture.finished.manifest_bytes())
                .is_err()
        );
        let generic_state = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_class,
                payload: fixture.finished.manifest_bytes(),
            },
        )
        .expect("seal class-confused payload through generic boundary");
        assert!(reader.verify_blob(&generic_state.bytes).is_err());

        let mut zero_ttl = selected.clone();
        zero_ttl.ttl_ms = Some(0);
        assert!(
            publisher
                .seal_blob_manifest(&zero_ttl, fixture.finished.manifest_bytes())
                .is_err()
        );
        let generic = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &zero_ttl,
                payload: fixture.finished.manifest_bytes(),
            },
        )
        .expect("generic provider permits zero TTL syntax");
        assert!(reader.verify_blob(&generic.bytes).is_err());

        let empty = prepare_blob(
            &mut Cursor::new(Vec::<u8>::new()),
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(None, Vec::new()).expect("empty metadata"),
        )
        .expect("bounded empty preparation");
        let mut selected_service = publisher
            .blob_service_with_store(&scope(), &topic(), 1, TestBlobStore::default())
            .expect("selected service");
        let empty_manifest = selected_service
            .install_prepared(&empty)
            .expect("selected empty manifest");
        let empty_finished = selected_service
            .finish_manifest(&empty_manifest)
            .expect("finish selected empty manifest");
        assert_eq!(empty_manifest.total_len(), 0);
        assert_eq!(empty_manifest.chunk_count(), 0);
        assert!(!empty_finished.manifest_bytes().is_empty());

        let noncanonical = prepare_blob(
            &mut Cursor::new(vec![1_u8; 4097]),
            4 * 1024,
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        )
        .expect("generic preparation");
        assert!(selected_service.install_prepared(&noncanonical).is_err());

        let sealed = publisher
            .seal_blob_manifest(&selected, fixture.finished.manifest_bytes())
            .expect("seal Blob");
        let mut route_tamper = sealed.bytes.clone();
        route_tamper[0] ^= 1;
        assert!(reader.verify_blob(&route_tamper).is_err());

        let mut content_tamper = sealed.bytes.clone();
        let last = content_tamper.len() - 1;
        content_tamper[last] ^= 1;
        let route = reader
            .verify_blob(&content_tamper)
            .expect("route metadata remains authenticated");
        assert!(reader.verify_blob_content(route, &content_tamper).is_err());

        let mut manifest_tamper = fixture.finished.manifest_bytes().to_vec();
        manifest_tamper[0] ^= 1;
        assert!(
            publisher
                .seal_blob_manifest(&selected, &manifest_tamper)
                .is_err()
        );
    }

    #[test]
    fn positive_blob_ttl_preserves_authenticated_route_and_manifest_bindings() {
        // Mutation caught: continuing to reject every finite Blob, or bypassing
        // the existing route/manifest/header checks when TTL becomes positive.
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let fixture = fixture(
            &publisher,
            &topic(),
            1,
            b"finite selected Blob".to_vec(),
            BlobMetadata::new(None, vec![8]).expect("metadata"),
        );
        let mut finite = header(publisher.identity(), &fixture.finished, topic(), 1, 9);
        finite.ttl_ms = Some(50);
        let sealed = publisher
            .seal_blob_manifest(&finite, fixture.finished.manifest_bytes())
            .expect("seal positive finite Blob");
        let route = reader
            .verify_blob(&sealed.bytes)
            .expect("verify finite route");
        assert_eq!(route.ttl_ms(), Some(50));
        assert_eq!(route.priority(), Priority::Immediate);
        assert_eq!(route.publisher(), publisher.identity());
        assert_eq!(route.blob_id(), fixture.finished.id());
        match reader
            .verify_blob_content(route, &sealed.bytes)
            .expect("verify finite content")
        {
            BlobContentVerification::ContentVerified { blob, .. } => {
                assert_eq!(blob.ttl_ms(), Some(50));
                assert_eq!(blob.blob_id(), fixture.finished.id());
                assert_eq!(blob.manifest(), &fixture.manifest);
            }
            BlobContentVerification::RouteOnly(_) => panic!("reader lost finite content grant"),
        }
    }

    #[test]
    fn blob_custody_capability_binds_every_authenticated_source_and_contact_field() {
        // Mutations caught: omitting the exact opened-claim digest from the
        // contact authority, or omitting any exchange, source, source-header,
        // sample, hop, age, session, or direction comparison at verification.
        use crate::CustodySample;
        use crate::blob_custody::{
            AuthenticatedBlobCustodyContactV1, BlobCustodyClaimV1, BlobCustodyDirectionV1,
            BlobCustodyError, BlobCustodyTransferId,
        };

        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let fixture = fixture(
            &publisher,
            &topic(),
            1,
            b"claim-bound selected Blob".to_vec(),
            BlobMetadata::new(None, vec![3, 8]).expect("metadata"),
        );
        let mut finite = header(publisher.identity(), &fixture.finished, topic(), 1, 17);
        finite.priority = Priority::Priority;
        finite.ttl_ms = Some(9_000);
        let sealed = publisher
            .seal_blob_manifest(&finite, fixture.finished.manifest_bytes())
            .expect("seal finite Blob");
        let (blob, _) = content_verified(&mut reader, &sealed.bytes);
        let transfer_id = BlobCustodyTransferId::from_exact_hash(blob.envelope_id());
        let sample = CustodySample {
            clock_id: [0x71; 16],
            tick_ms: 1_500,
        };
        let claim = BlobCustodyClaimV1::from_authenticated_source(
            [0x61; 32],
            41,
            BlobCustodyDirectionV1::ToSessionResponder,
            transfer_id,
            &blob,
            &sealed.bytes,
            700,
            sample,
            25,
        )
        .expect("build authenticated finite claim");
        let decoded = BlobCustodyClaimV1::decode(&claim.encode()).expect("decode raw frame claim");
        let contact = || {
            AuthenticatedBlobCustodyContactV1::from_opened_record(
                [0x61; 32],
                [0x62; 32],
                BlobCustodyDirectionV1::ToSessionResponder,
                9,
                claim.digest(),
            )
        };
        let authenticated_contact = contact();
        let contact_identity = authenticated_contact.contact_identity();
        let verified = decoded
            .verify_authenticated_source(
                authenticated_contact,
                41,
                transfer_id,
                &blob,
                &sealed.bytes,
                700,
                sample,
                25,
            )
            .expect("verify exact authenticated context");
        assert_eq!(verified.digest(), claim.digest());
        assert_eq!(verified.source_transfer_id(), transfer_id);
        assert_eq!(verified.publication_id(), blob.item_id());
        assert_eq!(verified.blob_id(), blob.blob_id());
        assert_eq!(verified.priority(), Priority::Priority);
        assert_eq!(verified.ttl_ms(), 9_000);
        assert_eq!(verified.forwarding_age_ms(), 725);
        assert_eq!(verified.contact_identity(), contact_identity);

        let other_contact = AuthenticatedBlobCustodyContactV1::from_opened_record(
            [0x63; 32],
            [0x62; 32],
            BlobCustodyDirectionV1::ToSessionResponder,
            9,
            claim.digest(),
        );
        assert_eq!(
            decoded.verify_authenticated_source(
                other_contact,
                41,
                transfer_id,
                &blob,
                &sealed.bytes,
                700,
                sample,
                25,
            ),
            Err(BlobCustodyError::ContextMismatch),
            "a capability from another authenticated session must not authorize the claim"
        );

        for (exchange_id, prior_age, changed_sample, hop_delta) in [
            (42, 700, sample, 25),
            (41, 701, sample, 25),
            (
                41,
                700,
                CustodySample {
                    clock_id: [0x72; 16],
                    tick_ms: 1_500,
                },
                25,
            ),
            (41, 700, sample, 26),
        ] {
            assert_eq!(
                decoded.verify_authenticated_source(
                    contact(),
                    exchange_id,
                    transfer_id,
                    &blob,
                    &sealed.bytes,
                    prior_age,
                    changed_sample,
                    hop_delta,
                ),
                Err(BlobCustodyError::ContextMismatch),
                "one exact opened claim must not authorize different caller context"
            );
        }
        assert_eq!(
            decoded.verify_authenticated_source(
                contact(),
                41,
                BlobCustodyTransferId::from_exact_hash([0x99; 32]),
                &blob,
                &sealed.bytes,
                700,
                sample,
                25,
            ),
            Err(BlobCustodyError::ContextMismatch),
            "one exact opened claim must not authorize another source"
        );

        for offset in [
            14usize, 46, 54, 55, 87, 95, 127, 159, 160, 168, 176, 192, 200,
        ] {
            let mut substituted = claim.encode();
            if offset == 54 {
                substituted[offset] = 1;
            } else {
                substituted[offset] ^= 1;
            }
            let substituted = BlobCustodyClaimV1::decode(&substituted)
                .expect("substitution remains structurally canonical");
            assert_eq!(
                substituted.verify_authenticated_source(
                    contact(),
                    41,
                    transfer_id,
                    &blob,
                    &sealed.bytes,
                    700,
                    sample,
                    25,
                ),
                Err(BlobCustodyError::ContextMismatch),
                "bound-field byte offset {offset}"
            );
        }

        let mut durable = finite;
        durable.ttl_ms = None;
        let durable_sealed = publisher
            .seal_blob_manifest(&durable, fixture.finished.manifest_bytes())
            .expect("seal durable Blob");
        let (durable_blob, _) = content_verified(&mut reader, &durable_sealed.bytes);
        assert_eq!(
            BlobCustodyClaimV1::from_authenticated_source(
                [0x61; 32],
                41,
                BlobCustodyDirectionV1::ToSessionResponder,
                BlobCustodyTransferId::from_exact_hash(durable_blob.envelope_id()),
                &durable_blob,
                &durable_sealed.bytes,
                0,
                sample,
                0,
            ),
            Err(BlobCustodyError::InvalidClaim)
        );
    }

    #[test]
    fn route_root_group_epoch_source_and_mission_bindings_are_exact() {
        let Services {
            mut publisher,
            other,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let base = fixture(
            &publisher,
            &topic(),
            1,
            vec![0x35; SELECTED_BLOB_CHUNK_SIZE as usize + 1],
            BlobMetadata::new(Some("application/base".into()), vec![1]).expect("base metadata"),
        );
        let base_header = header(publisher.identity(), &base.finished, topic(), 1, 1);
        let sealed = publisher
            .seal_blob_manifest(&base_header, base.finished.manifest_bytes())
            .expect("seal base Blob");
        assert!(
            reader
                .verify_blob_from(other.identity(), &sealed.bytes)
                .is_err()
        );
        reader
            .verify_blob_from(publisher.identity(), &sealed.bytes)
            .expect("expected source");

        let mut wrong_root_header = base_header.clone();
        let route = base.finished.route_commitment();
        let mut wrong_root = *route.root();
        wrong_root[0] ^= 1;
        wrong_root_header.blob_route = Some(
            BlobRouteCommitment::from_parts(route.blob_id(), route.chunk_count(), wrong_root)
                .expect("structurally valid wrong root"),
        );
        assert!(
            publisher
                .seal_blob_manifest(&wrong_root_header, base.finished.manifest_bytes())
                .is_err()
        );
        let wrong_root_sealed = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_root_header,
                payload: base.finished.manifest_bytes(),
            },
        )
        .expect("generic provider seals authenticated wrong root");
        let wrong_root_route = reader
            .verify_blob(&wrong_root_sealed.bytes)
            .expect("route-only verification authenticates committed root");
        assert!(
            reader
                .verify_blob_content(wrong_root_route, &wrong_root_sealed.bytes)
                .is_err()
        );

        let wrong_group = fixture(
            &publisher,
            &other_topic(),
            1,
            b"wrong group".to_vec(),
            BlobMetadata::new(None, vec![2]).expect("group metadata"),
        );
        let wrong_group_header = header(publisher.identity(), &wrong_group.finished, topic(), 1, 2);
        assert!(
            publisher
                .seal_blob_manifest(&wrong_group_header, wrong_group.finished.manifest_bytes())
                .is_err()
        );
        let generic_wrong_group = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_group_header,
                payload: wrong_group.finished.manifest_bytes(),
            },
        )
        .expect("generic group mismatch");
        let group_route = reader
            .verify_blob(&generic_wrong_group.bytes)
            .expect("verify group route");
        assert!(
            reader
                .verify_blob_content(group_route, &generic_wrong_group.bytes)
                .is_err()
        );

        let wrong_epoch = fixture(
            &publisher,
            &topic(),
            2,
            b"wrong epoch".to_vec(),
            BlobMetadata::new(None, vec![3]).expect("epoch metadata"),
        );
        let wrong_epoch_header = header(publisher.identity(), &wrong_epoch.finished, topic(), 1, 3);
        assert!(
            publisher
                .seal_blob_manifest(&wrong_epoch_header, wrong_epoch.finished.manifest_bytes())
                .is_err()
        );
        let generic_wrong_epoch = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_epoch_header,
                payload: wrong_epoch.finished.manifest_bytes(),
            },
        )
        .expect("generic epoch mismatch");
        let epoch_route = reader
            .verify_blob(&generic_wrong_epoch.bytes)
            .expect("verify epoch route");
        assert!(
            reader
                .verify_blob_content(epoch_route, &generic_wrong_epoch.bytes)
                .is_err()
        );

        let mut outsider = wrong_mission_reader();
        assert!(outsider.verify_blob(&sealed.bytes).is_err());
        let right_route = reader
            .verify_blob(&sealed.bytes)
            .expect("right mission route");
        assert!(
            outsider
                .verify_blob_content(right_route, &sealed.bytes)
                .is_err()
        );
    }

    #[test]
    fn route_only_and_wrong_topic_grants_cannot_mint_blob_content() {
        let Services {
            mut publisher,
            other: _,
            reader: _,
            mut relay,
            mut wrong_topic,
        } = services();
        let fixture = fixture(
            &publisher,
            &topic(),
            1,
            b"opaque to relays".to_vec(),
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        );
        let source_header = header(publisher.identity(), &fixture.finished, topic(), 1, 1);
        let sealed = publisher
            .seal_blob_manifest(&source_header, fixture.finished.manifest_bytes())
            .expect("seal Blob");

        assert!(relay.can_route_blob(&scope(), 1));
        assert!(!relay.can_open_blob_content(&scope(), &topic(), 1));
        assert!(
            relay
                .blob_service_with_store(&scope(), &topic(), 1, TestBlobStore::default())
                .is_err()
        );
        for provider in [&mut relay, &mut wrong_topic] {
            let route = provider
                .verify_blob(&sealed.bytes)
                .expect("route-only verification");
            match provider
                .verify_blob_content(route, &sealed.bytes)
                .expect("route-only decision")
            {
                BlobContentVerification::RouteOnly(route) => {
                    assert_eq!(route.blob_id(), fixture.finished.id());
                }
                BlobContentVerification::ContentVerified { .. } => {
                    panic!("route-only provider minted Blob content capability")
                }
            }
        }
    }

    #[test]
    fn blob_peer_content_proof_is_exact_current_and_identity_bound() {
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x6d; 32]).expect("proof provisioner");
        let authority_bundle = provisioner
            .issue_control_authority(1, &[full_access()])
            .expect("proof authority bundle");
        let reader_bundle = provisioner
            .issue_node(2, &[full_access()])
            .expect("proof reader bundle");
        let relay_bundle = provisioner
            .issue_node(3, &[relay_access()])
            .expect("proof relay bundle");
        let mut authority =
            ReferenceEnvelopeSealer::open(authority_bundle).expect("proof authority");
        let mut reader = ReferenceEnvelopeSealer::open(reader_bundle).expect("proof reader");
        let mut relay = ReferenceEnvelopeSealer::open(relay_bundle).expect("proof relay");
        let authority_id = authority.identity();
        let reader_id = reader.identity();
        let relay_id = relay.identity();

        let old_fixture = fixture(
            &authority,
            &topic(),
            1,
            b"same logical Blob across a same-epoch rekey".to_vec(),
            BlobMetadata::new(Some("application/octet-stream".into()), vec![6, 1])
                .expect("old lineage metadata"),
        );
        let old_header = header(authority_id, &old_fixture.finished, topic(), 1, 1);
        let old_sealed = authority
            .seal_blob_manifest(&old_header, old_fixture.finished.manifest_bytes())
            .expect("old lineage source");
        let (old_blob, _) = content_verified(&mut reader, &old_sealed.bytes);
        assert!(reader.verify_current_blob_lineage(&old_blob).is_ok());

        let stale = reader
            .mint_blob_peer_content_proof(&scope(), &topic(), 1)
            .expect("pre-rekey proof");
        let plan = provisioner
            .plan_scope_rekey(
                scope(),
                1,
                vec![
                    ScopeRekeyRecipient::member(authority_id, vec![topic()])
                        .expect("authority proof recipient"),
                    ScopeRekeyRecipient::member(reader_id, vec![topic()])
                        .expect("reader proof recipient"),
                    ScopeRekeyRecipient::route_only(relay_id),
                ],
            )
            .expect("proof rekey plan");
        let control = authority
            .seal_scope_rekey_chained(&plan, 1, None)
            .expect("proof rekey control");
        for provider in [&mut authority, &mut reader, &mut relay] {
            <ReferenceEnvelopeSealer as EnvelopeSealer>::inspect_control(provider, &control)
                .expect("verify proof rekey");
            <ReferenceEnvelopeSealer as EnvelopeSealer>::activate_control(
                provider, &control, false,
            )
            .expect("activate proof rekey");
        }

        let current = reader
            .mint_blob_peer_content_proof(&scope(), &topic(), 1)
            .expect("current reader proof");
        assert_ne!(stale.wire_bytes(), current.wire_bytes());
        assert_eq!(
            format!("{current:?}"),
            "BlobPeerContentProof([PROVIDER-OWNED])"
        );
        assert!(authority.peer_can_open_blob_content(
            reader_id,
            &[],
            &scope(),
            &topic(),
            1,
            current.as_wire_bytes(),
        ));

        assert!(reader.verify_current_blob_lineage(&old_blob).is_err());
        assert!(!reader.is_current_source_route_lineage(
            old_blob.scope(),
            old_blob.key_epoch(),
            old_blob.route_lineage(),
        ));
        assert!(!reader.is_current_blob_physical_lineage(
            old_blob.scope(),
            old_blob.topic(),
            old_blob.key_epoch(),
            old_blob.physical_lineage(),
        ));
        assert!(reader.verify_blob(&old_sealed.bytes).is_err());

        let new_fixture = fixture(
            &authority,
            &topic(),
            1,
            b"same logical Blob across a same-epoch rekey".to_vec(),
            BlobMetadata::new(Some("application/octet-stream".into()), vec![6, 1])
                .expect("new lineage metadata"),
        );
        assert_eq!(new_fixture.finished.id(), old_fixture.finished.id());
        let new_header = header(authority_id, &new_fixture.finished, topic(), 1, 2);
        let new_sealed = authority
            .seal_blob_manifest(&new_header, new_fixture.finished.manifest_bytes())
            .expect("new lineage source");
        let (new_blob, _) = content_verified(&mut reader, &new_sealed.bytes);
        assert_ne!(new_blob.route_lineage(), old_blob.route_lineage());
        assert_ne!(new_blob.physical_lineage(), old_blob.physical_lineage());
        assert_ne!(
            new_blob.route_lineage().binding(),
            old_blob.route_lineage().binding()
        );
        assert_ne!(
            new_blob.physical_lineage().binding(),
            old_blob.physical_lineage().binding()
        );
        reader
            .verify_current_blob_lineage(&new_blob)
            .expect("replacement lineage is current");

        // A same-epoch key replacement invalidates the superseded proof even
        // though the numeric route coordinate remains authorized.
        assert!(!authority.peer_can_open_blob_content(
            reader_id,
            &[],
            &scope(),
            &topic(),
            1,
            stale.as_wire_bytes(),
        ));
        assert!(
            relay
                .mint_blob_peer_content_proof(&scope(), &topic(), 1)
                .is_err()
        );
        assert!(!authority.peer_can_open_blob_content(
            relay_id,
            &[],
            &scope(),
            &topic(),
            1,
            current.as_wire_bytes(),
        ));

        assert!(!authority.peer_can_open_blob_content(
            authority_id,
            &[],
            &scope(),
            &topic(),
            1,
            current.as_wire_bytes(),
        ));
        assert!(!authority.peer_can_open_blob_content(
            reader_id,
            &[],
            &Scope::new("test/other-scope").expect("other scope"),
            &topic(),
            1,
            current.as_wire_bytes(),
        ));
        assert!(!authority.peer_can_open_blob_content(
            reader_id,
            &[],
            &scope(),
            &other_topic(),
            1,
            current.as_wire_bytes(),
        ));
        assert!(!authority.peer_can_open_blob_content(
            reader_id,
            &[],
            &scope(),
            &topic(),
            2,
            current.as_wire_bytes(),
        ));
        let foreign = wrong_mission_reader();
        assert!(!foreign.peer_can_open_blob_content(
            reader_id,
            &[],
            &scope(),
            &topic(),
            1,
            current.as_wire_bytes(),
        ));
        let mut tampered = current.wire_bytes();
        tampered[17] ^= 0x80;
        assert!(!authority.peer_can_open_blob_content(
            reader_id,
            &[],
            &scope(),
            &topic(),
            1,
            &tampered,
        ));
    }

    struct FailingSource {
        inner: Cursor<Vec<u8>>,
        yielded_partial_plaintext: bool,
    }

    impl Read for FailingSource {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.yielded_partial_plaintext {
                return Err(io::Error::other("injected read failure"));
            }
            self.yielded_partial_plaintext = true;
            let count = output.len().min(5);
            self.inner.read(&mut output[..count])
        }
    }

    impl Seek for FailingSource {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn preparation_restores_source_position_after_io_error_and_redacts_digests() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();

        let mut source = FailingSource {
            inner: Cursor::new(vec![0x77; 10]),
            yielded_partial_plaintext: false,
        };
        source.seek(SeekFrom::Start(4)).expect("initial seek");
        let result = prepare_blob(
            &mut source,
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        );
        assert!(result.is_err());
        assert_eq!(source.stream_position().expect("restored position"), 4);

        let prepared = prepare_blob(
            &mut Cursor::new(b"debug-safe".to_vec()),
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        )
        .expect("preparation");
        let debug = format!("{prepared:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("plaintext_sha256"));
    }
}
