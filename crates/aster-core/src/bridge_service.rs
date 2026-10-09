//! High-level creation and administration for semantic-v2 bridge objects.
//!
//! This module is deliberately the only layer which combines canonical bridge
//! values, provider-owned verification capabilities, and crash-atomic store
//! promotion. Requests carry identifiers, policy, and opaque route-grant
//! commitments; no route seed, content seed, derived key, or payload plaintext
//! crosses this boundary.

use crate::bridge::{
    self, BridgeAuthorization, BridgeCodecError, BridgeHop, BridgeNarrowing, BridgeRoute,
    EnabledAuthorization,
};
use crate::crypto::{
    BridgeCryptoProvider, BridgeEdgeEnrollment, ReferenceEnvelopeSealer,
    VerifiedBridgeAuthorization as ProviderVerifiedAuthorization,
    VerifiedBridgeSourceRoute as ProviderVerifiedSource,
};
use crate::custody::{CustodyAge, CustodyContinuity, CustodySample};
use crate::engine::{EmissionPolicy, EnvelopeError, EnvelopeHeader, EnvelopeSealer};
use crate::model::{NodeId, Priority, Scope, Topic};
use crate::store::{
    BridgeAuthorizationCursor, BridgeControlOutcome, BridgeRouteOutcome, BridgeRouteReadiness,
    EnvelopeId, RecordStore, SqliteStore, StoreError, StoredBridgeRoute, StoredItem,
    VerifiedBlobRouteMetadata, VerifiedBridgeAuthorization as StoreVerifiedAuthorization,
    VerifiedBridgeRoute as StoreVerifiedRoute, VerifiedBridgeSource as StoreVerifiedSource,
    VerifiedBridgeSourceMetadata,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const AUTHORIZATION_SCAN_PAGE: usize = 1_024;

/// High-level authority request to enable or replace one exact bridge edge.
pub(crate) struct EnableBridgeAuthorizationRequest {
    enrollment: BridgeEdgeEnrollment,
    topics: BTreeSet<Topic>,
    allowed_priorities: BTreeSet<Priority>,
    max_total_hops: u8,
}

impl fmt::Debug for EnableBridgeAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnableBridgeAuthorizationRequest")
            .field("enrollment", &self.enrollment)
            .field("topics", &self.topics)
            .field("allowed_priorities", &self.allowed_priorities)
            .field("max_total_hops", &self.max_total_hops)
            .finish()
    }
}

impl EnableBridgeAuthorizationRequest {
    pub(crate) fn new(
        enrollment: BridgeEdgeEnrollment,
        topics: Vec<Topic>,
        allowed_priorities: Vec<Priority>,
        max_total_hops: u8,
    ) -> Result<Self, BridgeServiceError> {
        let topic_count = topics.len();
        let topics = topics.into_iter().collect::<BTreeSet<_>>();
        let priority_count = allowed_priorities.len();
        let allowed_priorities = allowed_priorities.into_iter().collect::<BTreeSet<_>>();
        if topics.is_empty()
            || topics.len() != topic_count
            || topics.len() > bridge::MAX_TOPICS
            || allowed_priorities.is_empty()
            || allowed_priorities.len() != priority_count
            || max_total_hops == 0
            || usize::from(max_total_hops) > bridge::MAX_HOPS
        {
            return Err(BridgeServiceError::Invalid(
                "enabled bridge authorization has invalid topics, priorities, or path bound",
            ));
        }
        Ok(Self {
            enrollment,
            topics,
            allowed_priorities,
            max_total_hops,
        })
    }
}

/// High-level authority request to disable an existing exact bridge edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DisableBridgeAuthorizationRequest {
    bridge_node_id: NodeId,
    source_scope: Scope,
    target_scope: Scope,
}

impl DisableBridgeAuthorizationRequest {
    pub(crate) fn new(
        bridge_node_id: NodeId,
        source_scope: Scope,
        target_scope: Scope,
    ) -> Result<Self, BridgeServiceError> {
        if source_scope == target_scope {
            return Err(BridgeServiceError::Invalid(
                "bridge disable request must name a directed edge",
            ));
        }
        Ok(Self {
            bridge_node_id,
            source_scope,
            target_scope,
        })
    }
}

/// Local policy intersection for one newly-created hop.
///
/// An empty topic set means all topics still allowed by the authority object.
/// The priority set is always explicit and nonempty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalBridgeNarrowing {
    topics: BTreeSet<Topic>,
    allowed_priorities: BTreeSet<Priority>,
}

impl LocalBridgeNarrowing {
    pub(crate) fn new(
        topics: Vec<Topic>,
        allowed_priorities: Vec<Priority>,
    ) -> Result<Self, BridgeServiceError> {
        let topic_count = topics.len();
        let topics = topics.into_iter().collect::<BTreeSet<_>>();
        let priority_count = allowed_priorities.len();
        let allowed_priorities = allowed_priorities.into_iter().collect::<BTreeSet<_>>();
        if topics.len() != topic_count
            || topics.len() > bridge::MAX_TOPICS
            || allowed_priorities.is_empty()
            || allowed_priorities.len() != priority_count
        {
            return Err(BridgeServiceError::Invalid(
                "local bridge narrowing is noncanonical or empty",
            ));
        }
        Ok(Self {
            topics,
            allowed_priorities,
        })
    }

    fn canonical(&self) -> BridgeNarrowing {
        BridgeNarrowing {
            topics: self.topics.clone(),
            allowed_priority_mask: priority_mask(&self.allowed_priorities),
        }
    }
}

/// Request to create the first wrapper around one already-durable format-2 source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirstBridgeHopRequest {
    pub(crate) source_envelope_id: EnvelopeId,
    pub(crate) authorization_envelope_id: EnvelopeId,
    pub(crate) local_narrowing: LocalBridgeNarrowing,
    pub(crate) custody_sample: Option<CustodySample>,
}

/// Request to extend one already-durable, active wrapper by exactly one hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NestedBridgeHopRequest {
    pub(crate) current_wrapper_envelope_id: EnvelopeId,
    pub(crate) authorization_envelope_id: EnvelopeId,
    pub(crate) local_narrowing: LocalBridgeNarrowing,
    pub(crate) custody_sample: Option<CustodySample>,
}

/// Durable result of one authority update.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IssuedBridgeAuthorization {
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) authorization_key: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) control_sequence: u64,
    pub(crate) enabled: bool,
    pub(crate) exact_bytes: Vec<u8>,
}

impl fmt::Debug for IssuedBridgeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedBridgeAuthorization")
            .field("envelope_id", &self.envelope_id)
            .field("authorization_key", &self.authorization_key)
            .field("generation", &self.generation)
            .field("control_sequence", &self.control_sequence)
            .field("enabled", &self.enabled)
            .field("sealed_len", &self.exact_bytes.len())
            .field("credential", &"[PROVIDER-OWNED]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Deterministic store disposition after atomic wrapper promotion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BridgeCommitDisposition {
    Active,
    RetainedAlternate,
    DuplicateActive,
    DuplicateInactive,
}

/// Durable result of one locally-created bridge wrapper.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CreatedBridgeRoute {
    pub(crate) wrapper_envelope_id: EnvelopeId,
    pub(crate) bridge_route_id: [u8; 32],
    pub(crate) origin_envelope_id: EnvelopeId,
    pub(crate) source_item_id: crate::model::ItemId,
    pub(crate) current_scope: Scope,
    pub(crate) current_route_epoch: u64,
    pub(crate) hop_count: u8,
    pub(crate) disposition: BridgeCommitDisposition,
    pub(crate) exact_wrapper_bytes: Vec<u8>,
}

impl fmt::Debug for CreatedBridgeRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedBridgeRoute")
            .field("wrapper_envelope_id", &self.wrapper_envelope_id)
            .field("bridge_route_id", &self.bridge_route_id)
            .field("origin_envelope_id", &self.origin_envelope_id)
            .field("source_item_id", &self.source_item_id)
            .field("current_scope", &self.current_scope)
            .field("current_route_epoch", &self.current_route_epoch)
            .field("hop_count", &self.hop_count)
            .field("disposition", &self.disposition)
            .field("sealed_len", &self.exact_wrapper_bytes.len())
            .field("source_route", &"[PROVIDER-VERIFIED-OPAQUE]")
            .field("payload", &"[NONE]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Fail-closed bridge service error.
#[derive(Debug)]
pub(crate) enum BridgeServiceError {
    Invalid(&'static str),
    Provider(EnvelopeError),
    Store(StoreError),
    Codec(BridgeCodecError),
}

impl fmt::Display for BridgeServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "bridge service rejected: {message}"),
            Self::Provider(error) => {
                write!(formatter, "bridge provider rejected operation: {error}")
            }
            Self::Store(error) => write!(formatter, "bridge durable operation failed: {error}"),
            Self::Codec(error) => write!(formatter, "bridge canonical value rejected: {error}"),
        }
    }
}

impl Error for BridgeServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<EnvelopeError> for BridgeServiceError {
    fn from(value: EnvelopeError) -> Self {
        Self::Provider(value)
    }
}

impl From<StoreError> for BridgeServiceError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<BridgeCodecError> for BridgeServiceError {
    fn from(value: BridgeCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Reference coordinator for authority updates and local wrapper creation.
///
/// The service borrows one live provider and one durable store so all checks
/// and the final promotion occur in one serialized high-level operation.
pub(crate) struct ReferenceBridgeService<'a> {
    mission_id: [u8; 32],
    provider: &'a mut ReferenceEnvelopeSealer,
    store: &'a mut SqliteStore,
    emission: EmissionPolicy,
}

impl<'a> ReferenceBridgeService<'a> {
    pub(crate) fn new(
        provider: &'a mut ReferenceEnvelopeSealer,
        store: &'a mut SqliteStore,
        emission: EmissionPolicy,
    ) -> Self {
        let mission_id = provider.bridge_mission_id();
        Self {
            mission_id,
            provider,
            store,
            emission,
        }
    }

    /// Reauthenticates durable controls and committed routes for a standalone
    /// application node after restart. Durable bytes never become live merely
    /// because SQLite reopened; every admitted record is reopened through the
    /// provider and every route is checked against current authorization,
    /// revocation, epoch, and custody state before promotion.
    pub(crate) fn reauthenticate_durable_application_state(
        &mut self,
        sample: Option<CustodySample>,
    ) -> Result<(), BridgeServiceError> {
        let mut authorization_cursor = None;
        loop {
            let page = self.store.stored_bridge_authorizations_after(
                authorization_cursor,
                AUTHORIZATION_SCAN_PAGE,
            )?;
            if page.is_empty() {
                break;
            }
            for stored in &page {
                authorization_cursor = Some(BridgeAuthorizationCursor {
                    authority_id: stored.authorization.authority_id,
                    sequence: stored.authorization.control_sequence,
                });
                match self.authenticate_and_ingest_authorization(&stored.exact_bytes) {
                    Ok(_) => {}
                    // A provider-rejected recovery record remains durable but
                    // cannot populate the process-local verified set.
                    Err(BridgeServiceError::Provider(_)) => continue,
                    Err(error) => return Err(error),
                }
            }
            if page.len() < AUTHORIZATION_SCAN_PAGE {
                break;
            }
        }

        let mut route_cursor = None;
        loop {
            let page = self
                .store
                .stored_bridge_routes_after(route_cursor, AUTHORIZATION_SCAN_PAGE)?;
            if page.is_empty() {
                break;
            }
            for stored in &page {
                let verified = match self.reverify_stored_route(stored) {
                    Ok(verified) => verified,
                    Err(BridgeServiceError::Provider(_))
                    | Err(BridgeServiceError::Codec(_))
                    | Err(BridgeServiceError::Invalid(_)) => continue,
                    Err(error) => return Err(error),
                };
                match self.store.verified_bridge_route_readiness(&verified)? {
                    BridgeRouteReadiness::Eligible => {}
                    BridgeRouteReadiness::MissingDependency | BridgeRouteReadiness::Ineligible => {
                        continue;
                    }
                }
                match self
                    .store
                    .promote_verified_bridge_route_at(&verified, sample)
                {
                    Ok(_) | Err(StoreError::BridgeRouteIneligible) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            route_cursor = page.last().map(|route| route.inserted_order);
            if page.len() < AUTHORIZATION_SCAN_PAGE {
                break;
            }
        }
        Ok(())
    }

    /// Creates, provider-verifies, and durably activates one enabled update.
    pub(crate) fn issue_enabled_authorization(
        &mut self,
        request: EnableBridgeAuthorizationRequest,
    ) -> Result<IssuedBridgeAuthorization, BridgeServiceError> {
        self.require_live_store()?;
        let principal = self
            .provider
            .control_principal()
            .ok_or(BridgeServiceError::Invalid(
                "provider is not the mission control authority",
            ))?;
        let authority_id = principal.authority;
        let enrollment = self
            .provider
            .open_bridge_edge_enrollment(&request.enrollment)?;
        let claims = ReferenceEnvelopeSealer::bridge_edge_enrollment_claims(&enrollment);
        if claims.mission_id != self.mission_id
            || self.store.is_revoked(&authority_id)?
            || self.store.is_revoked(&principal.signer)?
            || self.store.is_revoked(&claims.bridge_node_id)?
            || self.store.scope_epoch(&claims.source_scope)? != claims.source_route_epoch
            || self.store.scope_epoch(&claims.target_scope)? != claims.target_route_epoch
        {
            return Err(BridgeServiceError::Invalid(
                "bridge enrollment, revocation state, or route epoch is not current",
            ));
        }
        let (control_sequence, previous_control_id) = self.bridge_chain_head(authority_id)?;
        let authorization_key = bridge::bridge_authorization_key(
            &self.mission_id,
            &claims.bridge_node_id,
            &claims.source_scope,
            &claims.target_scope,
        )?;
        let generation = self.next_generation(
            &authorization_key,
            claims.bridge_node_id,
            &claims.source_scope,
            &claims.target_scope,
        )?;
        let mut authorization = BridgeAuthorization {
            mission_id: self.mission_id,
            authority_id,
            control_sequence,
            previous_control_id,
            authorization_key,
            generation,
            bridge_node_id: claims.bridge_node_id,
            source_scope: claims.source_scope,
            target_scope: claims.target_scope,
            enabled: Some(EnabledAuthorization {
                source_route_epoch: claims.source_route_epoch,
                target_route_epoch: claims.target_route_epoch,
                source_route_commitment: [0; 32],
                target_route_commitment: [0; 32],
                allowed_priority_mask: priority_mask(&request.allowed_priorities),
                max_total_hops: request.max_total_hops,
                topics: request.topics.into_iter().collect(),
                bridge_credential: Vec::new(),
                authority_credential_signature: Vec::new(),
            }),
            authority_control_signature: Vec::new(),
        };
        self.provider
            .bind_bridge_edge_enrollment(&enrollment, &mut authorization)?;
        let exact_bytes = self.provider.seal_bridge_authorization(authorization)?;
        self.persist_issued_authorization(exact_bytes)
    }

    /// Creates, provider-verifies, and durably activates a higher-generation disable.
    pub(crate) fn issue_disabled_authorization(
        &mut self,
        request: DisableBridgeAuthorizationRequest,
    ) -> Result<IssuedBridgeAuthorization, BridgeServiceError> {
        self.require_live_store()?;
        let principal = self
            .provider
            .control_principal()
            .ok_or(BridgeServiceError::Invalid(
                "provider is not the mission control authority",
            ))?;
        let authority_id = principal.authority;
        if self.store.is_revoked(&authority_id)? || self.store.is_revoked(&principal.signer)? {
            return Err(BridgeServiceError::Invalid(
                "revoked authority cannot issue bridge controls",
            ));
        }
        let (control_sequence, previous_control_id) = self.bridge_chain_head(authority_id)?;
        let authorization_key = bridge::bridge_authorization_key(
            &self.mission_id,
            &request.bridge_node_id,
            &request.source_scope,
            &request.target_scope,
        )?;
        let current = self
            .store
            .active_bridge_authorization(&authorization_key)?
            .ok_or(BridgeServiceError::Invalid(
                "cannot disable an unknown bridge authorization",
            ))?;
        if current.authorization.enabled.is_none()
            || current.authorization.mission_id != self.mission_id
            || current.authorization.authority_id != authority_id
            || current.authorization.bridge_node_id != request.bridge_node_id
            || current.authorization.source_scope != request.source_scope
            || current.authorization.target_scope != request.target_scope
        {
            return Err(BridgeServiceError::Invalid(
                "bridge disable does not match the active enabled authorization",
            ));
        }
        let generation =
            current
                .authorization
                .generation
                .checked_add(1)
                .ok_or(BridgeServiceError::Invalid(
                    "bridge authorization generation is exhausted",
                ))?;
        let authorization = BridgeAuthorization {
            mission_id: self.mission_id,
            authority_id,
            control_sequence,
            previous_control_id,
            authorization_key,
            generation,
            bridge_node_id: request.bridge_node_id,
            source_scope: request.source_scope,
            target_scope: request.target_scope,
            enabled: None,
            authority_control_signature: Vec::new(),
        };
        let exact_bytes = self.provider.seal_bridge_authorization(authorization)?;
        self.persist_issued_authorization(exact_bytes)
    }

    /// Creates the first authorized target wrapper for one ordinary source.
    pub(crate) fn create_first_hop(
        &mut self,
        request: FirstBridgeHopRequest,
    ) -> Result<CreatedBridgeRoute, BridgeServiceError> {
        self.require_live_store()?;
        let item = self
            .store
            .get_by_envelope(&request.source_envelope_id)?
            .ok_or(BridgeServiceError::Invalid(
                "first-hop source is not an ordinary durable envelope",
            ))?;
        if item.envelope_id != request.source_envelope_id
            || bridge::exact_object_id(&item.sealed) != request.source_envelope_id
        {
            return Err(BridgeServiceError::Invalid(
                "ordinary source bytes do not match the requested envelope identity",
            ));
        }
        let source = self.provider.open_source_route_for_bridge(&item.sealed)?;
        self.require_source_matches_item(&source, &item)?;
        self.require_live_source(&source, request.custody_sample)?;
        let authorization = self.load_live_authorization(&request.authorization_envelope_id)?;
        let enabled = self.authorize_new_edge(
            &authorization,
            source.header(),
            &source.header().scope,
            source.header().key_epoch,
            1,
            &request.local_narrowing,
        )?;
        let (cumulative_custody_age_ms, age_continuity_unknown) =
            effective_item_custody(&item, request.custody_sample);
        require_unexpired(
            source.header(),
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )?;
        let mut route = BridgeRoute {
            mission_id: self.mission_id,
            origin_envelope_id: source.origin_envelope_id(),
            source_item_id: source.source_item_id(),
            origin_scope: source.header().scope.clone(),
            origin_route_epoch: source.header().key_epoch,
            current_scope: authorization.envelope().authorization.target_scope.clone(),
            current_route_epoch: enabled.target_route_epoch,
            source_route_descriptor: source.copy_exact_route_descriptor(),
            hops: vec![BridgeHop {
                authorization_envelope_id: authorization.envelope().envelope_id,
                bridge_node_id: self.provider.identity(),
                from_scope: source.header().scope.clone(),
                from_route_epoch: source.header().key_epoch,
                to_scope: authorization.envelope().authorization.target_scope.clone(),
                to_route_epoch: enabled.target_route_epoch,
                cumulative_custody_age_ms,
                age_continuity_unknown,
                previous_hop_digest: [0; 32],
                bridge_hybrid_signature: Vec::new(),
            }],
            bridge_route_id: [0; 32],
        };
        self.provider.sign_bridge_hop(&mut route, 0)?;
        let target_scope = route.current_scope.clone();
        let target_epoch = route.current_route_epoch;
        let exact_wrapper_bytes =
            self.provider
                .seal_bridge_wrapper(&route, &source, &target_scope, target_epoch)?;
        self.verify_and_promote_created_route(
            route,
            exact_wrapper_bytes,
            item.sealed,
            0,
            request.custody_sample,
            Some((0, &request.local_narrowing)),
        )
    }

    /// Revalidates one active route and appends exactly one narrower hop.
    pub(crate) fn create_nested_hop(
        &mut self,
        request: NestedBridgeHopRequest,
    ) -> Result<CreatedBridgeRoute, BridgeServiceError> {
        self.require_live_store()?;
        let (mut route, source, source_bytes, source_forwarding_age_ms, stored) = self
            .rehydrate_existing_route(
                &request.current_wrapper_envelope_id,
                request.custody_sample,
            )?;
        if route.hops.len() >= bridge::MAX_HOPS {
            return Err(BridgeServiceError::Invalid(
                "bridge path already has the maximum eight hops",
            ));
        }
        self.require_live_source(&source, request.custody_sample)?;
        let authorization = self.load_live_authorization(&request.authorization_envelope_id)?;
        let next_hop_count = route
            .hops
            .len()
            .checked_add(1)
            .ok_or(BridgeServiceError::Invalid("bridge hop count overflow"))?;
        let enabled = self.authorize_new_edge(
            &authorization,
            source.header(),
            &route.current_scope,
            route.current_route_epoch,
            next_hop_count,
            &request.local_narrowing,
        )?;
        let (cumulative_custody_age_ms, age_continuity_unknown) =
            effective_route_custody(&stored, request.custody_sample);
        require_unexpired(
            source.header(),
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )?;
        let prior_index = u8::try_from(route.hops.len())
            .map_err(|_| BridgeServiceError::Invalid("bridge hop count exceeds byte range"))?;
        let previous_hop_digest = route
            .hops
            .last()
            .ok_or(BridgeServiceError::Invalid(
                "nested bridge route has no prior hop",
            ))?
            .digest(prior_index)?;
        let from_scope = route.current_scope.clone();
        let from_epoch = route.current_route_epoch;
        let to_scope = authorization.envelope().authorization.target_scope.clone();
        route.current_scope = to_scope.clone();
        route.current_route_epoch = enabled.target_route_epoch;
        route.hops.push(BridgeHop {
            authorization_envelope_id: authorization.envelope().envelope_id,
            bridge_node_id: self.provider.identity(),
            from_scope,
            from_route_epoch: from_epoch,
            to_scope,
            to_route_epoch: enabled.target_route_epoch,
            cumulative_custody_age_ms,
            age_continuity_unknown,
            previous_hop_digest,
            bridge_hybrid_signature: Vec::new(),
        });
        let new_hop_index = route
            .hops
            .len()
            .checked_sub(1)
            .ok_or(BridgeServiceError::Invalid("nested bridge hop is missing"))?;
        self.provider.sign_bridge_hop(&mut route, new_hop_index)?;
        let target_scope = route.current_scope.clone();
        let target_epoch = route.current_route_epoch;
        let exact_wrapper_bytes =
            self.provider
                .seal_bridge_wrapper(&route, &source, &target_scope, target_epoch)?;
        self.verify_and_promote_created_route(
            route,
            exact_wrapper_bytes,
            source_bytes,
            source_forwarding_age_ms,
            request.custody_sample,
            Some((new_hop_index, &request.local_narrowing)),
        )
    }

    fn require_live_store(&mut self) -> Result<(), BridgeServiceError> {
        if self.store.is_zeroized()? {
            return Err(BridgeServiceError::Invalid(
                "zeroized store cannot create bridge objects",
            ));
        }
        Ok(())
    }

    fn bridge_chain_head(
        &mut self,
        authority_id: NodeId,
    ) -> Result<(u64, Option<EnvelopeId>), BridgeServiceError> {
        let mut cursor = None;
        let mut expected_sequence = 1u64;
        let mut previous = None;
        loop {
            let records = self
                .store
                .stored_bridge_authorizations_after(cursor, AUTHORIZATION_SCAN_PAGE)?;
            if records.is_empty() {
                break;
            }
            for stored in &records {
                cursor = Some(BridgeAuthorizationCursor {
                    authority_id: stored.authorization.authority_id,
                    sequence: stored.authorization.control_sequence,
                });
                if stored.authorization.authority_id != authority_id {
                    continue;
                }
                let verified = self.authenticate_and_ingest_authorization(&stored.exact_bytes)?;
                let envelope = verified.envelope();
                let refreshed = self
                    .store
                    .stored_bridge_authorization(&stored.envelope_id)?
                    .ok_or(BridgeServiceError::Invalid(
                        "bridge authorization disappeared during chain scan",
                    ))?;
                if envelope.envelope_id != stored.envelope_id
                    || envelope.authorization != stored.authorization
                    || !refreshed.applied
                    || stored.authorization.control_sequence != expected_sequence
                    || stored.authorization.previous_control_id != previous
                {
                    return Err(BridgeServiceError::Invalid(
                        "bridge control chain is not a contiguous verified prefix",
                    ));
                }
                previous = Some(stored.envelope_id);
                expected_sequence =
                    expected_sequence
                        .checked_add(1)
                        .ok_or(BridgeServiceError::Invalid(
                            "bridge control sequence is exhausted",
                        ))?;
            }
            if records.len() < AUTHORIZATION_SCAN_PAGE {
                break;
            }
        }
        Ok((expected_sequence, previous))
    }

    fn next_generation(
        &self,
        authorization_key: &[u8; 32],
        bridge_node_id: NodeId,
        source_scope: &Scope,
        target_scope: &Scope,
    ) -> Result<u64, BridgeServiceError> {
        let Some(current) = self.store.active_bridge_authorization(authorization_key)? else {
            return Ok(1);
        };
        if !current.applied
            || current.authorization.mission_id != self.mission_id
            || current.authorization.bridge_node_id != bridge_node_id
            || &current.authorization.source_scope != source_scope
            || &current.authorization.target_scope != target_scope
        {
            return Err(BridgeServiceError::Invalid(
                "bridge generation high-water does not match the requested edge",
            ));
        }
        current
            .authorization
            .generation
            .checked_add(1)
            .ok_or(BridgeServiceError::Invalid(
                "bridge authorization generation is exhausted",
            ))
    }

    fn persist_issued_authorization(
        &mut self,
        exact_bytes: Vec<u8>,
    ) -> Result<IssuedBridgeAuthorization, BridgeServiceError> {
        let verified = self.authenticate_and_ingest_authorization(&exact_bytes)?;
        let envelope = verified.envelope();
        let active = self
            .store
            .active_bridge_authorization(&envelope.authorization.authorization_key)?
            .ok_or(BridgeServiceError::Invalid(
                "issued bridge authorization did not become active",
            ))?;
        if active.envelope_id != envelope.envelope_id || !active.applied {
            return Err(BridgeServiceError::Invalid(
                "issued bridge authorization remained pending or was superseded",
            ));
        }
        Ok(IssuedBridgeAuthorization {
            envelope_id: envelope.envelope_id,
            authorization_key: envelope.authorization.authorization_key,
            generation: envelope.authorization.generation,
            control_sequence: envelope.authorization.control_sequence,
            enabled: envelope.authorization.enabled.is_some(),
            exact_bytes,
        })
    }

    fn authenticate_and_ingest_authorization(
        &mut self,
        exact_bytes: &[u8],
    ) -> Result<ProviderVerifiedAuthorization, BridgeServiceError> {
        let verified = self.provider.open_bridge_authorization(exact_bytes)?;
        let envelope = verified.envelope();
        if envelope.authorization.mission_id != self.mission_id {
            return Err(BridgeServiceError::Invalid(
                "bridge authorization belongs to another mission",
            ));
        }
        let store_verified = StoreVerifiedAuthorization::from_provider(
            envelope.envelope_id,
            envelope.authorization.clone(),
            verified.control_signer(),
            exact_bytes.to_vec(),
        )?;
        let outcome = self.store.ingest_bridge_authorization(&store_verified)?;
        if outcome.rejected_input().is_some() {
            let message = if self
                .store
                .is_revoked(&envelope.authorization.authority_id)?
            {
                "bridge control authority was revoked by the mission chain"
            } else {
                "bridge control signer was revoked by the mission chain"
            };
            return Err(BridgeServiceError::Invalid(message));
        }
        match outcome {
            BridgeControlOutcome::Applied { .. }
            | BridgeControlOutcome::Duplicate { .. }
            | BridgeControlOutcome::Pending { .. } => {}
            BridgeControlOutcome::Rejected { .. } => {
                return Err(BridgeServiceError::Invalid(
                    "bridge control signer was revoked by the mission chain",
                ));
            }
        }
        Ok(verified)
    }

    fn load_live_authorization(
        &mut self,
        envelope_id: &EnvelopeId,
    ) -> Result<ProviderVerifiedAuthorization, BridgeServiceError> {
        let stored = self.store.stored_bridge_authorization(envelope_id)?.ok_or(
            BridgeServiceError::Invalid("bridge authorization dependency is missing"),
        )?;
        let verified = self.authenticate_and_ingest_authorization(&stored.exact_bytes)?;
        if verified.envelope().envelope_id != stored.envelope_id
            || verified.envelope().authorization != stored.authorization
            || verified.control_signer() != stored.control_signer
        {
            return Err(BridgeServiceError::Invalid(
                "stored bridge authorization differs from provider verification",
            ));
        }
        let active = self
            .store
            .active_bridge_authorization(&stored.authorization.authorization_key)?
            .ok_or(BridgeServiceError::Invalid(
                "bridge authorization is not active",
            ))?;
        let authorization = &stored.authorization;
        let enabled = authorization
            .enabled
            .as_ref()
            .ok_or(BridgeServiceError::Invalid(
                "bridge authorization is disabled",
            ))?;
        if !active.applied
            || active.envelope_id != stored.envelope_id
            || authorization.mission_id != self.mission_id
            || self.store.is_revoked(&authorization.authority_id)?
            || self.store.is_revoked(&stored.control_signer)?
            || self.store.is_revoked(&authorization.bridge_node_id)?
            || self.store.scope_epoch(&authorization.source_scope)? != enabled.source_route_epoch
            || self.store.scope_epoch(&authorization.target_scope)? != enabled.target_route_epoch
        {
            return Err(BridgeServiceError::Invalid(
                "bridge authorization is superseded, revoked, or stale-epoch",
            ));
        }
        Ok(verified)
    }

    fn authorize_new_edge<'b>(
        &mut self,
        authorization: &'b ProviderVerifiedAuthorization,
        header: &EnvelopeHeader,
        from_scope: &Scope,
        from_route_epoch: u64,
        resulting_hop_count: usize,
        local: &LocalBridgeNarrowing,
    ) -> Result<&'b EnabledAuthorization, BridgeServiceError> {
        let record = authorization.envelope();
        let control = &record.authorization;
        let enabled = control.enabled.as_ref().ok_or(BridgeServiceError::Invalid(
            "disabled authorization cannot create a bridge hop",
        ))?;
        let local = local.canonical();
        local.validate_subset(enabled)?;
        if control.bridge_node_id != self.provider.identity()
            || &control.source_scope != from_scope
            || enabled.source_route_epoch != from_route_epoch
            || resulting_hop_count > usize::from(enabled.max_total_hops)
            || enabled.topics.binary_search(&header.topic).is_err()
            || !bridge::priority_allowed(enabled.allowed_priority_mask, header.priority)
            || (!local.topics.is_empty() && !local.topics.contains(&header.topic))
            || !bridge::priority_allowed(local.allowed_priority_mask, header.priority)
            || !self.store.bridge_allows(
                from_scope,
                &control.target_scope,
                &header.topic,
                header.priority,
            )?
            || !self.emission.allows(header.priority)
        {
            return Err(BridgeServiceError::Invalid(
                "source metadata is outside the exact authority/local/emission intersection",
            ));
        }
        Ok(enabled)
    }

    fn require_source_matches_item(
        &self,
        source: &ProviderVerifiedSource,
        item: &StoredItem,
    ) -> Result<(), BridgeServiceError> {
        let header = source.header();
        if source.mission_id() != self.mission_id
            || source.origin_envelope_id() != item.envelope_id
            || source.source_item_id() != item.id
            || header.class != item.class
            || header.topic != item.topic
            || header.scope != item.scope
            || header.priority != item.priority
            || header.stamp != item.stamp
            || header.event_sequence != item.event_sequence
            || header.logical_key != item.logical_key
            || header.ttl_ms != item.ttl_ms
            || header.content_len != item.content_len
            || header.tombstone != item.tombstone
            || header.key_epoch != item.key_epoch
        {
            return Err(BridgeServiceError::Invalid(
                "provider-verified source metadata differs from the durable ordinary item",
            ));
        }
        Ok(())
    }

    fn require_live_source(
        &mut self,
        source: &ProviderVerifiedSource,
        sample: Option<CustodySample>,
    ) -> Result<(), BridgeServiceError> {
        if source.mission_id() != self.mission_id
            || self
                .store
                .is_revoked(&source.header().stamp.dot.publisher)?
            || self.store.scope_epoch(&source.header().scope)? != source.header().key_epoch
        {
            return Err(BridgeServiceError::Invalid(
                "source publisher is revoked or its origin epoch is stale",
            ));
        }
        if let Some(item) = self.store.get_by_envelope(&source.origin_envelope_id())? {
            let (age, unknown) = effective_item_custody(&item, sample);
            require_unexpired(source.header(), age, unknown)?;
        }
        Ok(())
    }

    fn verify_route_authorizations(
        &mut self,
        route: &BridgeRoute,
        header: &EnvelopeHeader,
        local_new_hop: Option<(usize, &LocalBridgeNarrowing)>,
    ) -> Result<(), BridgeServiceError> {
        let mut records = BTreeMap::new();
        let mut active = BTreeMap::new();
        for (index, hop) in route.hops.iter().enumerate() {
            let authorization = self.load_live_authorization(&hop.authorization_envelope_id)?;
            self.provider
                .verify_bridge_hop(route, index, &authorization)?;
            let envelope = authorization.envelope().clone();
            active.insert(
                envelope.authorization.authorization_key,
                envelope.envelope_id,
            );
            records.insert(envelope.envelope_id, envelope);
        }
        route.validate_authority_path(&header.topic, header.priority, &records, &active)?;
        if let Some((index, local)) = local_new_hop {
            route.validate_local_new_hop(
                index,
                &header.topic,
                header.priority,
                &records,
                &active,
                &local.canonical(),
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_and_promote_created_route(
        &mut self,
        expected_route: BridgeRoute,
        exact_wrapper_bytes: Vec<u8>,
        source_bytes: Vec<u8>,
        source_forwarding_age_ms: u64,
        sample: Option<CustodySample>,
        local_new_hop: Option<(usize, &LocalBridgeNarrowing)>,
    ) -> Result<CreatedBridgeRoute, BridgeServiceError> {
        let wrapper = self.provider.open_bridge_wrapper(
            &exact_wrapper_bytes,
            &expected_route.current_scope,
            expected_route.current_route_epoch,
        )?;
        if wrapper.route() != &expected_route {
            return Err(BridgeServiceError::Invalid(
                "newly sealed wrapper did not reopen to the exact route",
            ));
        }
        let source = self
            .provider
            .verify_bridge_wrapper_source(&wrapper, &source_bytes)?;
        self.verify_route_authorizations(wrapper.route(), source.header(), local_new_hop)?;
        let store_source = store_verified_source(&source, source_bytes, source_forwarding_age_ms)?;
        let store_route = StoreVerifiedRoute::from_provider(
            wrapper.wrapper_envelope_id(),
            wrapper.route().clone(),
            exact_wrapper_bytes.clone(),
            0,
            store_source,
        )?;
        let outcome = self
            .store
            .promote_verified_bridge_route_at(&store_route, sample)?;
        let disposition = match outcome {
            BridgeRouteOutcome::Active { .. } => BridgeCommitDisposition::Active,
            BridgeRouteOutcome::RetainedAlternate { .. } => {
                BridgeCommitDisposition::RetainedAlternate
            }
            BridgeRouteOutcome::Duplicate { active: true, .. } => {
                BridgeCommitDisposition::DuplicateActive
            }
            BridgeRouteOutcome::Duplicate { active: false, .. } => {
                BridgeCommitDisposition::DuplicateInactive
            }
        };
        let route = wrapper.route();
        Ok(CreatedBridgeRoute {
            wrapper_envelope_id: wrapper.wrapper_envelope_id(),
            bridge_route_id: route.bridge_route_id,
            origin_envelope_id: route.origin_envelope_id,
            source_item_id: route.source_item_id,
            current_scope: route.current_scope.clone(),
            current_route_epoch: route.current_route_epoch,
            hop_count: u8::try_from(route.hops.len())
                .map_err(|_| BridgeServiceError::Invalid("bridge hop count exceeds byte range"))?,
            disposition,
            exact_wrapper_bytes,
        })
    }

    fn reverify_stored_route(
        &mut self,
        stored: &StoredBridgeRoute,
    ) -> Result<StoreVerifiedRoute, BridgeServiceError> {
        let wrapper = self
            .provider
            .open_bridge_wrapper_for_any_local_route(&stored.exact_wrapper_bytes)?;
        if wrapper.wrapper_envelope_id() != stored.wrapper_envelope_id
            || wrapper.route().bridge_route_id != stored.bridge_route_id
            || wrapper.route().origin_envelope_id != stored.origin_envelope_id
            || wrapper.route().source_item_id != stored.source_item_id
            || wrapper.route().origin_scope != stored.origin_scope
            || wrapper.route().origin_route_epoch != stored.origin_route_epoch
            || wrapper.route().current_scope != stored.current_scope
            || wrapper.route().current_route_epoch != stored.current_route_epoch
            || wrapper.route().hops.len() != usize::from(stored.hop_count)
        {
            return Err(BridgeServiceError::Invalid(
                "stored bridge route differs from provider verification",
            ));
        }
        let source = self
            .provider
            .verify_bridge_wrapper_source(&wrapper, &stored.exact_source_bytes)?;
        self.verify_route_authorizations(wrapper.route(), source.header(), None)?;
        let source = store_verified_source(
            &source,
            stored.exact_source_bytes.clone(),
            stored.authenticated_forwarding_age_ms,
        )?;
        StoreVerifiedRoute::from_provider(
            wrapper.wrapper_envelope_id(),
            wrapper.route().clone(),
            stored.exact_wrapper_bytes.clone(),
            stored.authenticated_forwarding_age_ms,
            source,
        )
        .map_err(Into::into)
    }

    fn rehydrate_existing_route(
        &mut self,
        wrapper_envelope_id: &EnvelopeId,
        sample: Option<CustodySample>,
    ) -> Result<
        (
            BridgeRoute,
            ProviderVerifiedSource,
            Vec<u8>,
            u64,
            StoredBridgeRoute,
        ),
        BridgeServiceError,
    > {
        let stored = self.store.stored_bridge_route(wrapper_envelope_id)?.ok_or(
            BridgeServiceError::Invalid("nested bridge wrapper is not durably committed"),
        )?;
        if !stored.active
            || bridge::exact_object_id(&stored.exact_wrapper_bytes) != *wrapper_envelope_id
            || bridge::exact_object_id(&stored.exact_source_bytes) != stored.origin_envelope_id
        {
            return Err(BridgeServiceError::Invalid(
                "nested bridge route is inactive or has invalid exact identities",
            ));
        }
        let wrapper = self.provider.open_bridge_wrapper(
            &stored.exact_wrapper_bytes,
            &stored.current_scope,
            stored.current_route_epoch,
        )?;
        if wrapper.wrapper_envelope_id() != stored.wrapper_envelope_id
            || wrapper.route().bridge_route_id != stored.bridge_route_id
        {
            return Err(BridgeServiceError::Invalid(
                "stored wrapper differs from provider verification",
            ));
        }
        let source = self
            .provider
            .verify_bridge_wrapper_source(&wrapper, &stored.exact_source_bytes)?;
        self.verify_route_authorizations(wrapper.route(), source.header(), None)?;
        let stored_source = self
            .store
            .stored_bridge_source(&stored.origin_envelope_id)?
            .ok_or(BridgeServiceError::Invalid(
                "nested bridge source dependency is missing",
            ))?;
        let store_source = store_verified_source(
            &source,
            stored.exact_source_bytes.clone(),
            stored_source.authenticated_forwarding_age_ms,
        )?;
        let store_route = StoreVerifiedRoute::from_provider(
            wrapper.wrapper_envelope_id(),
            wrapper.route().clone(),
            stored.exact_wrapper_bytes.clone(),
            stored.authenticated_forwarding_age_ms,
            store_source,
        )?;
        self.store
            .promote_verified_bridge_route_at(&store_route, sample)?;
        if !self
            .store
            .bridge_route_is_live_at(wrapper_envelope_id, sample)?
        {
            return Err(BridgeServiceError::Invalid(
                "nested bridge route did not become process-live after revalidation",
            ));
        }
        let refreshed = self.store.stored_bridge_route(wrapper_envelope_id)?.ok_or(
            BridgeServiceError::Invalid("nested bridge route disappeared after revalidation"),
        )?;
        Ok((
            wrapper.route().clone(),
            source,
            stored.exact_source_bytes,
            stored_source.authenticated_forwarding_age_ms,
            refreshed,
        ))
    }
}

fn priority_mask(priorities: &BTreeSet<Priority>) -> u8 {
    priorities
        .iter()
        .fold(0u8, |mask, priority| mask | (1 << *priority as u8))
}

fn require_unexpired(
    header: &EnvelopeHeader,
    cumulative_age_ms: u64,
    continuity_unknown: bool,
) -> Result<(), BridgeServiceError> {
    if !header.tombstone
        && header
            .ttl_ms
            .is_some_and(|ttl| continuity_unknown || cumulative_age_ms >= ttl)
    {
        return Err(BridgeServiceError::Invalid(
            "finite-TTL source has expired or unknown custody continuity",
        ));
    }
    Ok(())
}

fn effective_custody(
    persisted_age_ms: u64,
    persisted_unknown: bool,
    clock_id: Option<[u8; 16]>,
    tick_ms: Option<u64>,
    elapsed_available: bool,
    sample: Option<CustodySample>,
) -> (u64, bool) {
    let checkpoint = clock_id
        .zip(tick_ms)
        .map(|(clock_id, tick_ms)| CustodySample { clock_id, tick_ms });
    let continuity = if !persisted_unknown && elapsed_available {
        CustodyContinuity::Continuous
    } else {
        CustodyContinuity::Lost
    };
    let Ok(mut age) = CustodyAge::from_parts(persisted_age_ms, checkpoint, continuity) else {
        return (persisted_age_ms, true);
    };
    match age.effective_age(sample) {
        Ok(age_ms) => (age_ms, false),
        Err(_) => (age.cumulative_age_ms(), true),
    }
}

fn effective_item_custody(item: &StoredItem, sample: Option<CustodySample>) -> (u64, bool) {
    effective_custody(
        item.custody_age_ms,
        false,
        item.custody_clock_id,
        item.custody_tick_ms,
        item.custody_elapsed_available,
        sample,
    )
}

fn effective_route_custody(
    route: &StoredBridgeRoute,
    sample: Option<CustodySample>,
) -> (u64, bool) {
    effective_custody(
        route.cumulative_custody_age_ms,
        route.age_continuity_unknown,
        route.custody_clock_id,
        route.custody_tick_ms,
        route.custody_elapsed_available,
        sample,
    )
}

fn store_verified_source(
    source: &ProviderVerifiedSource,
    exact_bytes: Vec<u8>,
    authenticated_forwarding_age_ms: u64,
) -> Result<StoreVerifiedSource, BridgeServiceError> {
    let header = source.header();
    let blob_route = header.blob_route.map(|blob| VerifiedBlobRouteMetadata {
        blob_id: *blob.blob_id().as_bytes(),
        chunk_count: blob.chunk_count(),
        merkle_root: *blob.root(),
    });
    Ok(StoreVerifiedSource::from_provider(
        source.origin_envelope_id(),
        VerifiedBridgeSourceMetadata {
            source_item_id: source.source_item_id(),
            class: header.class,
            topic: header.topic.clone(),
            priority: header.priority,
            stamp: header.stamp.clone(),
            event_sequence: header.event_sequence,
            logical_key: header.logical_key.clone(),
            ttl_ms: header.ttl_ms,
            blob_route,
            content_len: header.content_len,
            tombstone: header.tombstone,
            origin_scope: header.scope.clone(),
            origin_route_epoch: header.key_epoch,
        },
        exact_bytes,
        authenticated_forwarding_age_ms,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ProvisioningAccess, ReferenceProvisioner};
    use crate::engine::SealRequest;
    use crate::model::{CausalStamp, DataClass, Dot, VersionVector};
    use crate::store::{ApplyOutcome, BridgeFilter, ScopeEpoch, StoreConfig, VersionStatus};

    #[test]
    fn effective_custody_overflow_loses_continuity_instead_of_saturating_live() {
        assert_eq!(
            effective_custody(
                u64::MAX,
                false,
                Some([0x91; 16]),
                Some(1),
                true,
                Some(CustodySample {
                    clock_id: [0x91; 16],
                    tick_ms: 2,
                }),
            ),
            (u64::MAX, true)
        );
    }

    #[test]
    fn lower_bound_bridge_age_advances_without_becoming_forwardable() {
        let clock = [0x92; 16];
        let header = EnvelopeHeader {
            class: DataClass::State,
            topic: topic("ops"),
            scope: scope("alpha"),
            priority: Priority::Routine,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: [0x93; 32],
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: None,
            logical_key: b"lower-bound".to_vec(),
            blob_route: None,
            ttl_ms: Some(30),
            content_len: 1,
            tombstone: false,
            key_epoch: 1,
        };

        let below_ttl = effective_custody(
            10,
            true,
            Some(clock),
            Some(1_000),
            true,
            Some(CustodySample {
                clock_id: clock,
                tick_ms: 1_019,
            }),
        );
        assert_eq!(below_ttl, (29, true));
        assert!(require_unexpired(&header, below_ttl.0, below_ttl.1).is_err());

        let at_ttl = effective_custody(
            29,
            true,
            Some(clock),
            Some(1_019),
            true,
            Some(CustodySample {
                clock_id: clock,
                tick_ms: 1_020,
            }),
        );
        assert_eq!(at_ttl, (30, true));
        assert!(require_unexpired(&header, at_ttl.0, at_ttl.1).is_err());
    }

    struct Fixture {
        authority: ReferenceEnvelopeSealer,
        bridge: ReferenceEnvelopeSealer,
        store: SqliteStore,
        source: StoredItem,
        sample: CustodySample,
    }

    fn scope(value: &str) -> Scope {
        Scope::new(value).unwrap_or_else(|error| panic!("scope failed: {error}"))
    }

    fn topic(value: &str) -> Topic {
        Topic::new(value).unwrap_or_else(|error| panic!("topic failed: {error}"))
    }

    fn relay(scope_name: &str, epoch: u64) -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(scope_name), vec![epoch])
            .unwrap_or_else(|error| panic!("relay access failed: {error}"))
    }

    fn configure_epoch(store: &mut SqliteStore, authority: NodeId, scope_name: &str, epoch: u64) {
        store
            .set_scope_epoch(&ScopeEpoch {
                authority,
                signer: authority,
                scope: scope(scope_name),
                epoch,
                control_sequence: epoch,
                previous_control: None,
                sealed_notice: [scope_name.as_bytes(), &epoch.to_be_bytes()].concat(),
            })
            .unwrap_or_else(|error| panic!("scope epoch setup failed: {error}"));
    }

    fn fixture() -> Fixture {
        let mut provisioner = ReferenceProvisioner::from_seed([0xe1; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let grants = [relay("alpha", 7), relay("bravo", 9), relay("charlie", 11)];
        let authority_bundle = provisioner
            .issue_control_authority(1, &grants)
            .unwrap_or_else(|error| panic!("authority issue failed: {error}"));
        let bridge_bundle = provisioner
            .issue_node(2, &grants)
            .unwrap_or_else(|error| panic!("bridge issue failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(
                3,
                &[
                    ProvisioningAccess::member(scope("alpha"), vec![7], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("publisher access failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let authority = ReferenceEnvelopeSealer::open(authority_bundle)
            .unwrap_or_else(|error| panic!("authority open failed: {error}"));
        let control_authority_id = authority
            .control_authority()
            .unwrap_or_else(|| panic!("control authority identity missing"));
        let bridge = ReferenceEnvelopeSealer::open(bridge_bundle)
            .unwrap_or_else(|error| panic!("bridge open failed: {error}"));
        let mut publisher = ReferenceEnvelopeSealer::open(publisher_bundle)
            .unwrap_or_else(|error| panic!("publisher open failed: {error}"));
        let alpha = scope("alpha");
        let sample = CustodySample {
            clock_id: [0x71; 16],
            tick_ms: 1_000,
        };
        let header = EnvelopeHeader {
            class: DataClass::State,
            topic: topic("ops"),
            scope: alpha,
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: publisher.identity(),
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: None,
            logical_key: b"bridge-state".to_vec(),
            blob_route: None,
            ttl_ms: Some(60_000),
            content_len: 14,
            tombstone: false,
            key_epoch: 7,
        };
        let payload = b"secret-payload";
        let sealed = publisher
            .seal(SealRequest {
                header: &header,
                payload,
            })
            .unwrap_or_else(|error| panic!("source seal failed: {error}"));
        let source = StoredItem {
            id: sealed.id,
            envelope_id: bridge::exact_object_id(&sealed.bytes),
            class: header.class,
            topic: header.topic.clone(),
            scope: header.scope.clone(),
            priority: header.priority,
            stamp: header.stamp.clone(),
            event_sequence: header.event_sequence,
            logical_key: header.logical_key.clone(),
            ttl_ms: header.ttl_ms,
            observed_at_ms: None,
            sealed: sealed.bytes,
            content_len: header.content_len,
            tombstone: header.tombstone,
            key_epoch: header.key_epoch,
            custody_age_ms: 250,
            custody_clock_id: Some(sample.clock_id),
            custody_tick_ms: Some(sample.tick_ms),
            custody_elapsed_available: true,
            status: VersionStatus::Current,
            inserted_order: 0,
        };
        let mut store = SqliteStore::open_in_memory(StoreConfig::default())
            .unwrap_or_else(|error| panic!("store open failed: {error}"));
        configure_epoch(&mut store, control_authority_id, "alpha", 7);
        configure_epoch(&mut store, control_authority_id, "bravo", 9);
        configure_epoch(&mut store, control_authority_id, "charlie", 11);
        store
            .replace_bridge_filters(&[
                BridgeFilter {
                    from_scope: scope("alpha"),
                    to_scope: scope("bravo"),
                    topics: BTreeSet::from([topic("ops")]),
                    minimum_priority: Priority::Priority,
                },
                BridgeFilter {
                    from_scope: scope("bravo"),
                    to_scope: scope("charlie"),
                    topics: BTreeSet::from([topic("ops")]),
                    minimum_priority: Priority::Priority,
                },
            ])
            .unwrap_or_else(|error| panic!("bridge filters failed: {error}"));
        match store
            .ingest(source.clone())
            .unwrap_or_else(|error| panic!("source ingest failed: {error}"))
        {
            ApplyOutcome::Inserted { .. } => {}
            ApplyOutcome::Duplicate { .. } => panic!("fresh source was duplicate"),
        }
        Fixture {
            authority,
            bridge,
            store,
            source,
            sample,
        }
    }

    fn enrollment(
        bridge: &ReferenceEnvelopeSealer,
        source_scope: &str,
        source_epoch: u64,
        target_scope: &str,
        target_epoch: u64,
    ) -> BridgeEdgeEnrollment {
        bridge
            .create_bridge_edge_enrollment(
                &scope(source_scope),
                source_epoch,
                &scope(target_scope),
                target_epoch,
            )
            .unwrap_or_else(|error| panic!("edge enrollment failed: {error}"))
    }

    fn enable_request(enrollment: BridgeEdgeEnrollment) -> EnableBridgeAuthorizationRequest {
        EnableBridgeAuthorizationRequest::new(
            enrollment,
            vec![topic("intel"), topic("ops")],
            vec![Priority::Priority, Priority::Immediate, Priority::Flash],
            8,
        )
        .unwrap_or_else(|error| panic!("enable request failed: {error}"))
    }

    fn local_ops() -> LocalBridgeNarrowing {
        LocalBridgeNarrowing::new(
            vec![topic("ops")],
            vec![Priority::Immediate, Priority::Flash],
        )
        .unwrap_or_else(|error| panic!("local rule failed: {error}"))
    }

    #[test]
    fn authority_enable_first_hop_and_nested_hop_commit_atomically() {
        let mut fixture = fixture();
        let alpha_bravo = enrollment(&fixture.bridge, "alpha", 7, "bravo", 9);
        let first_authorization = {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.authority,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            service
                .issue_enabled_authorization(enable_request(alpha_bravo))
                .unwrap_or_else(|error| panic!("first authorization failed: {error}"))
        };
        let bravo_charlie = enrollment(&fixture.bridge, "bravo", 9, "charlie", 11);
        let second_authorization = {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.authority,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            service
                .issue_enabled_authorization(enable_request(bravo_charlie))
                .unwrap_or_else(|error| panic!("second authorization failed: {error}"))
        };
        assert_eq!(first_authorization.control_sequence, 1);
        assert_eq!(second_authorization.control_sequence, 2);
        assert_eq!(first_authorization.generation, 1);
        assert_eq!(second_authorization.generation, 1);
        assert!(!format!("{first_authorization:?}").contains("route_grant"));

        let first = {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.bridge,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            service
                .create_first_hop(FirstBridgeHopRequest {
                    source_envelope_id: fixture.source.envelope_id,
                    authorization_envelope_id: first_authorization.envelope_id,
                    local_narrowing: local_ops(),
                    custody_sample: Some(fixture.sample),
                })
                .unwrap_or_else(|error| panic!("first hop failed: {error}"))
        };
        assert_eq!(first.hop_count, 1);
        assert_eq!(first.current_scope, scope("bravo"));
        assert_eq!(first.current_route_epoch, 9);
        assert_eq!(first.disposition, BridgeCommitDisposition::Active);
        assert!(
            !first
                .exact_wrapper_bytes
                .windows(b"secret-payload".len())
                .any(|window| window == b"secret-payload")
        );
        assert!(!format!("{first:?}").contains("secret-payload"));

        let nested = {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.bridge,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            service
                .create_nested_hop(NestedBridgeHopRequest {
                    current_wrapper_envelope_id: first.wrapper_envelope_id,
                    authorization_envelope_id: second_authorization.envelope_id,
                    local_narrowing: local_ops(),
                    custody_sample: Some(fixture.sample),
                })
                .unwrap_or_else(|error| panic!("nested hop failed: {error}"))
        };
        assert_eq!(nested.hop_count, 2);
        assert_eq!(nested.origin_envelope_id, fixture.source.envelope_id);
        assert_eq!(nested.current_scope, scope("charlie"));
        assert_eq!(nested.current_route_epoch, 11);
        assert_eq!(nested.disposition, BridgeCommitDisposition::Active);
        let stored = fixture
            .store
            .stored_bridge_route(&nested.wrapper_envelope_id)
            .unwrap_or_else(|error| panic!("stored nested route failed: {error}"))
            .unwrap_or_else(|| panic!("nested route was not atomically committed"));
        assert!(stored.active);
        assert_eq!(stored.hop_count, 2);
        assert_eq!(stored.exact_source_bytes, fixture.source.sealed);
        assert_eq!(
            fixture
                .store
                .active_bridge_route_at(
                    &fixture.source.envelope_id,
                    &scope("charlie"),
                    11,
                    Some(fixture.sample),
                )
                .unwrap_or_else(|error| panic!("active nested route failed: {error}"))
                .map(|route| route.wrapper_envelope_id),
            Some(nested.wrapper_envelope_id)
        );
    }

    #[test]
    fn disable_narrowing_epoch_revocation_and_emission_fail_closed() {
        let mut fixture = fixture();
        let alpha_bravo = enrollment(&fixture.bridge, "alpha", 7, "bravo", 9);
        let authorization = {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.authority,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            service
                .issue_enabled_authorization(enable_request(alpha_bravo))
                .unwrap_or_else(|error| panic!("authorization failed: {error}"))
        };
        let widened =
            LocalBridgeNarrowing::new(vec![topic("not-authorized")], vec![Priority::Immediate])
                .unwrap_or_else(|error| panic!("widened local rule setup failed: {error}"));
        {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.bridge,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            assert!(
                service
                    .create_first_hop(FirstBridgeHopRequest {
                        source_envelope_id: fixture.source.envelope_id,
                        authorization_envelope_id: authorization.envelope_id,
                        local_narrowing: widened,
                        custody_sample: Some(fixture.sample),
                    })
                    .is_err()
            );
        }
        {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.bridge,
                &mut fixture.store,
                EmissionPolicy::receive_only(),
            );
            assert!(
                service
                    .create_first_hop(FirstBridgeHopRequest {
                        source_envelope_id: fixture.source.envelope_id,
                        authorization_envelope_id: authorization.envelope_id,
                        local_narrowing: local_ops(),
                        custody_sample: Some(fixture.sample),
                    })
                    .is_err()
            );
        }
        let disabled = {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.authority,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            service
                .issue_disabled_authorization(
                    DisableBridgeAuthorizationRequest::new(
                        fixture.bridge.identity(),
                        scope("alpha"),
                        scope("bravo"),
                    )
                    .unwrap_or_else(|error| panic!("disable request failed: {error}")),
                )
                .unwrap_or_else(|error| panic!("disable failed: {error}"))
        };
        assert!(!disabled.enabled);
        assert_eq!(disabled.generation, 2);
        assert_eq!(disabled.control_sequence, 2);
        {
            let mut service = ReferenceBridgeService::new(
                &mut fixture.bridge,
                &mut fixture.store,
                EmissionPolicy::default(),
            );
            assert!(
                service
                    .create_first_hop(FirstBridgeHopRequest {
                        source_envelope_id: fixture.source.envelope_id,
                        authorization_envelope_id: authorization.envelope_id,
                        local_narrowing: local_ops(),
                        custody_sample: Some(fixture.sample),
                    })
                    .is_err()
            );
        }

        let revoked_enrollment = enrollment(&fixture.bridge, "alpha", 7, "bravo", 9);
        fixture
            .store
            .apply_revocation(&crate::store::Revocation {
                subject: fixture.bridge.identity(),
                authority: fixture.authority.control_authority().unwrap_or([0; 32]),
                signer: fixture.authority.identity(),
                generation: 1,
                control_sequence: 99,
                previous_control: None,
                sealed_notice: b"test-revocation".to_vec(),
                observed_at_ms: None,
            })
            .unwrap_or_else(|error| panic!("revocation setup failed: {error}"));
        let mut service = ReferenceBridgeService::new(
            &mut fixture.authority,
            &mut fixture.store,
            EmissionPolicy::default(),
        );
        assert!(
            service
                .issue_enabled_authorization(enable_request(revoked_enrollment))
                .is_err()
        );

        let mut stale_fixture = self::fixture();
        let stale_enrollment = enrollment(&stale_fixture.bridge, "alpha", 7, "bravo", 9);
        let authority_id = stale_fixture
            .authority
            .control_authority()
            .unwrap_or_else(|| panic!("stale fixture authority missing"));
        configure_epoch(&mut stale_fixture.store, authority_id, "alpha", 8);
        let mut service = ReferenceBridgeService::new(
            &mut stale_fixture.authority,
            &mut stale_fixture.store,
            EmissionPolicy::default(),
        );
        assert!(
            service
                .issue_enabled_authorization(enable_request(stale_enrollment))
                .is_err()
        );
    }
}
