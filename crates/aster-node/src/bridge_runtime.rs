//! Bounded static composition for the selected Event bridge foundation.
//!
//! This module deliberately stops below contact scheduling and wire framing. It
//! authenticates one complete operator-supplied bridge-control chain, commits
//! it to the mission-bound store, installs exact Carry selectors for local
//! outgoing edges, re-verifies retained routes after restart, and exposes
//! payload-redacting materialization and receive operations.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use aster_mesh::{
    NodeId, Priority, ReferenceEnvelopeSealer, Scope, SelectedBridgeNarrowingPolicy,
    SelectedEventBridgeAdapter, Topic, VerifiedSelectedBridgeAuthorization,
    VerifiedSelectedBridgeEventRoute,
};
use aster_profile::ItemId;
use aster_redb_store::{
    ControlPolicySnapshot, EventSubscriptionKey, EventSubscriptionMode, EventSubscriptionSpec,
    SelectedBridgeAuthorizationCommitOutcome, SelectedBridgeEventRouteCommitOutcome, Store,
    StoredEventTransfer, StoredSelectedBridgeEventRouteCandidate,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::mission::UnprotectedReferenceMission;
use crate::runtime::open_replayed_verifier;

/// Maximum complete bridge-control records accepted by the static MVP.
pub const MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATIONS: usize = 64;
/// Maximum exact authorization bytes retained by the static MVP config.
pub const MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATION_BYTES: usize = 65_536;
/// Maximum aggregate exact authorization bytes retained by one config.
pub const MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATION_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum locally operated directed edges in one static node config.
pub const MAX_SELECTED_EVENT_BRIDGE_EDGES: usize = 8;
/// Maximum deterministic Carry selectors derived from local edges.
pub const MAX_SELECTED_EVENT_BRIDGE_CARRY_SELECTORS: usize = 256;
/// Maximum durable routes re-verified during one bounded restart.
pub const MAX_SELECTED_EVENT_BRIDGE_RESTART_ROUTES: usize = 256;
/// Maximum ordinary and bridge candidates inspected for one outbound batch.
pub const MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_SCAN: usize = 256;
/// Maximum opaque wrappers returned by one outbound batch.
pub const MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_BATCH: usize = 32;
/// Maximum authenticated peer route-grant commitments accepted per contact.
pub const MAX_SELECTED_EVENT_BRIDGE_PEER_ROUTE_COMMITMENTS: usize = 256;
/// Maximum process-local peer progress cursors retained by one bridge runtime.
pub const MAX_SELECTED_EVENT_BRIDGE_PEER_CURSORS: usize = 256;

const AUTHORIZATION_CANDIDATE_PAGE: usize = 64;
const ROUTE_CANDIDATE_PAGE: usize = 16;
const BRIDGE_CARRY_OPERATION_PREFIX: &[u8] = b"aster/selected-event-bridge/v1/carry/";

/// Stable public category for a selected Event bridge runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedEventBridgeRuntimeErrorKind {
    /// Static input is empty, duplicate, inconsistent, or outside MVP bounds.
    InvalidConfiguration,
    /// Exact bytes failed cryptographic or canonical authentication.
    Authentication,
    /// Static local intent would widen or does not select an authenticated route.
    PolicyMismatch,
    /// Durable state is unavailable, conflicting, or cannot be advanced safely.
    StateUnavailable,
    /// A bounded startup or selector limit was exceeded.
    CapacityExceeded,
}

/// Sanitized failure from the static selected Event bridge composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEventBridgeRuntimeError {
    operation: &'static str,
    kind: SelectedEventBridgeRuntimeErrorKind,
}

impl SelectedEventBridgeRuntimeError {
    fn new(operation: &'static str, kind: SelectedEventBridgeRuntimeErrorKind) -> Self {
        Self { operation, kind }
    }

    fn invalid(operation: &'static str) -> Self {
        Self::new(
            operation,
            SelectedEventBridgeRuntimeErrorKind::InvalidConfiguration,
        )
    }

    fn authentication(operation: &'static str) -> Self {
        Self::new(
            operation,
            SelectedEventBridgeRuntimeErrorKind::Authentication,
        )
    }

    fn policy(operation: &'static str) -> Self {
        Self::new(
            operation,
            SelectedEventBridgeRuntimeErrorKind::PolicyMismatch,
        )
    }

    fn state(operation: &'static str) -> Self {
        Self::new(
            operation,
            SelectedEventBridgeRuntimeErrorKind::StateUnavailable,
        )
    }

    fn capacity(operation: &'static str) -> Self {
        Self::new(
            operation,
            SelectedEventBridgeRuntimeErrorKind::CapacityExceeded,
        )
    }

    /// Stable failing operation without paths, bytes, or provider detail.
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Stable public failure category.
    pub const fn kind(&self) -> SelectedEventBridgeRuntimeErrorKind {
        self.kind
    }
}

impl fmt::Display for SelectedEventBridgeRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "selected Event bridge {} failed ({:?})",
            self.operation, self.kind
        )
    }
}

impl Error for SelectedEventBridgeRuntimeError {}

/// One exact locally operated edge within the complete authority chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEventBridgeEdge {
    authorization_envelope_id: [u8; 32],
    narrowing: SelectedBridgeNarrowingPolicy,
}

impl SelectedEventBridgeEdge {
    /// Selects one exact authorization and a bridge-local narrowing policy.
    pub const fn new(
        authorization_envelope_id: [u8; 32],
        narrowing: SelectedBridgeNarrowingPolicy,
    ) -> Self {
        Self {
            authorization_envelope_id,
            narrowing,
        }
    }

    /// Exact authority-envelope identity for this edge.
    pub const fn authorization_envelope_id(&self) -> [u8; 32] {
        self.authorization_envelope_id
    }

    /// Bridge-local topic and priority narrowing.
    pub const fn narrowing(&self) -> &SelectedBridgeNarrowingPolicy {
        &self.narrowing
    }
}

/// Complete bounded static configuration for one selected Event bridge node.
#[derive(Clone, Eq, PartialEq)]
pub struct SelectedEventBridgeConfig {
    authorization_chain: Vec<Vec<u8>>,
    edges: Vec<SelectedEventBridgeEdge>,
    delivery_enabled: bool,
}

impl SelectedEventBridgeConfig {
    /// Validates and retains one exact complete authority chain and local role.
    pub fn new(
        authorization_chain: Vec<Vec<u8>>,
        edges: Vec<SelectedEventBridgeEdge>,
        delivery_enabled: bool,
    ) -> Result<Self, SelectedEventBridgeRuntimeError> {
        let config = Self {
            authorization_chain,
            edges,
            delivery_enabled,
        };
        config.validate()?;
        Ok(config)
    }

    /// Number of exact records in the complete configured chain.
    pub fn authorization_count(&self) -> usize {
        self.authorization_chain.len()
    }

    /// Locally operated outgoing edges.
    pub fn edges(&self) -> &[SelectedEventBridgeEdge] {
        &self.edges
    }

    /// Whether authenticated target payloads may be opened for safe receipts.
    pub const fn delivery_enabled(&self) -> bool {
        self.delivery_enabled
    }

    fn validate(&self) -> Result<(), SelectedEventBridgeRuntimeError> {
        if self.authorization_chain.is_empty()
            || self.authorization_chain.len() > MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATIONS
            || self.edges.len() > MAX_SELECTED_EVENT_BRIDGE_EDGES
            || (self.edges.is_empty() && !self.delivery_enabled)
        {
            return Err(SelectedEventBridgeRuntimeError::invalid(
                "configuration validation",
            ));
        }
        let mut total = 0usize;
        let mut exact_ids = BTreeSet::new();
        for exact in &self.authorization_chain {
            if exact.is_empty() || exact.len() > MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATION_BYTES {
                return Err(SelectedEventBridgeRuntimeError::invalid(
                    "configuration validation",
                ));
            }
            total = total
                .checked_add(exact.len())
                .ok_or_else(|| SelectedEventBridgeRuntimeError::capacity("configuration"))?;
            if !exact_ids.insert(exact_digest(exact)) {
                return Err(SelectedEventBridgeRuntimeError::invalid(
                    "configuration validation",
                ));
            }
        }
        if total > MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATION_TOTAL_BYTES
            || self
                .edges
                .iter()
                .map(SelectedEventBridgeEdge::authorization_envelope_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.edges.len()
        {
            return Err(SelectedEventBridgeRuntimeError::invalid(
                "configuration validation",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for SelectedEventBridgeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact_lengths = self
            .authorization_chain
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("SelectedEventBridgeConfig")
            .field("authorization_exact_lengths", &exact_lengths)
            .field("edges", &self.edges)
            .field("delivery_enabled", &self.delivery_enabled)
            .finish()
    }
}

/// Safe metadata proving one target payload was freshly opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEventBridgeDeliveryReceipt {
    /// Exact received wrapper identity.
    pub wrapper_envelope_id: [u8; 32],
    /// Canonical complete bridge-route identity.
    pub bridge_route_id: [u8; 32],
    /// Exact source envelope identity.
    pub origin_envelope_id: [u8; 32],
    /// Source-authenticated item identity.
    pub source_item_id: ItemId,
    /// Source-authenticated publisher.
    pub publisher: NodeId,
    /// Source-authenticated origin scope before bridging.
    pub origin_scope: Scope,
    /// Source-authenticated origin route epoch before bridging.
    pub origin_route_epoch: u64,
    /// Final locally authenticated scope.
    pub current_scope: Scope,
    /// Final locally authenticated route epoch.
    pub current_route_epoch: u64,
    /// Source-authenticated topic.
    pub topic: Topic,
    /// Source-authenticated priority.
    pub priority: Priority,
    /// Source-authenticated Event sequence.
    pub event_sequence: u64,
    /// Authenticated bridge hop count.
    pub hop_count: u8,
    /// Exact opened payload length, with no plaintext retained.
    pub payload_len: usize,
    /// SHA-256 of the freshly opened payload, with no plaintext retained.
    pub payload_sha256: [u8; 32],
}

/// Bounded result of static bridge initialization and restart promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEventBridgeInitializationReceipt {
    /// Freshly authenticated complete authorization records.
    pub authorizations_verified: usize,
    /// Newly appended authorization records.
    pub authorizations_applied: usize,
    /// Exact already-durable authorization records.
    pub authorizations_existing: usize,
    /// Locally enabled outgoing edges.
    pub local_edges: usize,
    /// Newly inserted deterministic Carry subscriptions.
    pub carry_subscriptions_inserted: usize,
    /// Exact already-present deterministic Carry subscriptions.
    pub carry_subscriptions_existing: usize,
    /// Durable route candidates inspected during restart.
    pub route_candidates: usize,
    /// Route candidates freshly authenticated and recommitted.
    pub routes_reverified: usize,
    /// Retained candidates which did not freshly authenticate for this runtime.
    pub routes_inactive: usize,
    /// Final active process-live route count.
    pub active_routes: u64,
    /// Active target deliveries freshly opened during restart, without plaintext.
    pub deliveries: Vec<SelectedEventBridgeDeliveryReceipt>,
}

/// Whether materialization created a wrapper or reused the existing active route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedEventBridgeMaterializationDisposition {
    /// This call created and activated the returned wrapper.
    Created,
    /// An already-active route was freshly reverified and returned.
    Existing,
}

/// Safe metadata for one locally selected outbound wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEventBridgeMaterializationReceipt {
    /// Whether the wrapper was newly created or reused.
    pub disposition: SelectedEventBridgeMaterializationDisposition,
    /// Exact wrapper identity.
    pub wrapper_envelope_id: [u8; 32],
    /// Canonical bridge-route identity.
    pub bridge_route_id: [u8; 32],
    /// Exact source envelope identity.
    pub origin_envelope_id: [u8; 32],
    /// Source-authenticated item identity.
    pub source_item_id: ItemId,
    /// Source-authenticated origin scope before bridging.
    pub origin_scope: Scope,
    /// Source-authenticated origin route epoch before bridging.
    pub origin_route_epoch: u64,
    /// Current target scope.
    pub current_scope: Scope,
    /// Current target route epoch.
    pub current_route_epoch: u64,
    /// Total authenticated bridge hops.
    pub hop_count: u8,
}

/// Exact outbound bridge object. Debug output reports lengths but never bytes.
pub struct SelectedEventBridgeOutbound {
    receipt: SelectedEventBridgeMaterializationReceipt,
    exact_wrapper_bytes: Vec<u8>,
    exact_source_bytes: Vec<u8>,
}

/// One bounded deterministic outbound preparation result.
#[derive(Debug)]
pub struct SelectedEventBridgeOutboundBatch {
    /// Freshly materialized or reverified opaque routes, in deterministic scan order.
    pub routes: Vec<SelectedEventBridgeOutbound>,
    /// Additional locally prefiltered candidates inside the bounded scan.
    ///
    /// This is structural backpressure, not an authenticated claim that every
    /// deferred candidate will survive fresh materialization on a later call.
    pub remaining: usize,
    /// Ordinary accepted Event positions examined.
    pub ordinary_scanned: usize,
    /// Durable bridge candidates examined.
    pub bridge_scanned: usize,
    /// Finite-TTL candidates skipped because this static seam has no live
    /// authenticated custody-age continuity input.
    pub finite_ttl_skipped: usize,
    /// Prefiltered candidates which failed fresh materialization.
    pub inactive: usize,
    /// True when more durable ordinary or bridge rows exist beyond the scan bound.
    pub scan_truncated: bool,
}

impl SelectedEventBridgeOutbound {
    /// Safe materialization metadata.
    pub const fn receipt(&self) -> &SelectedEventBridgeMaterializationReceipt {
        &self.receipt
    }

    /// Exact opaque wrapper bytes for the selected bridge wire carrier.
    pub fn exact_wrapper_bytes(&self) -> &[u8] {
        &self.exact_wrapper_bytes
    }

    /// Exact opaque ordinary source envelope bytes paired with the wrapper.
    pub fn exact_source_bytes(&self) -> &[u8] {
        &self.exact_source_bytes
    }
}

impl fmt::Debug for SelectedEventBridgeOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedEventBridgeOutbound")
            .field("receipt", &self.receipt)
            .field("exact_wrapper_len", &self.exact_wrapper_bytes.len())
            .field("exact_source_len", &self.exact_source_bytes.len())
            .finish()
    }
}

/// Sanitized durable disposition for a freshly authenticated received route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedEventBridgeApplyDisposition {
    /// The route became the active deterministic route.
    Active,
    /// The route was retained but a better active route already exists.
    RetainedAlternate,
    /// Exact bytes were already durable and active.
    DuplicateActive,
    /// Exact bytes were already durable but inactive.
    DuplicateInactive,
    /// Authenticated route was outside local forwarding and delivery intent.
    NotSelected,
}

/// Safe result of authenticating and applying one received bridge route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedEventBridgeApplyReceipt {
    /// Durable route disposition.
    pub disposition: SelectedEventBridgeApplyDisposition,
    /// Exact wrapper identity.
    pub wrapper_envelope_id: [u8; 32],
    /// Canonical bridge-route identity.
    pub bridge_route_id: [u8; 32],
    /// Exact source identity.
    pub origin_envelope_id: [u8; 32],
    /// Authenticated total bridge hops.
    pub hop_count: u8,
    /// Target delivery proof when explicitly enabled and content-authorized.
    pub delivery: Option<SelectedEventBridgeDeliveryReceipt>,
}

#[derive(Clone)]
struct RuntimeEdge {
    authorization_index: usize,
    authorization_envelope_id: [u8; 32],
    narrowing: SelectedBridgeNarrowingPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PeerOutboundCursor {
    next_eligible_ordinal: usize,
}

/// Process-local static selected Event bridge state.
pub struct SelectedEventBridgeRuntime {
    store: Arc<Store>,
    provider: ReferenceEnvelopeSealer,
    control_policy: ControlPolicySnapshot,
    authorizations: Vec<VerifiedSelectedBridgeAuthorization>,
    edges: Vec<RuntimeEdge>,
    delivery_enabled: bool,
    outbound_peer_cursors: BTreeMap<NodeId, PeerOutboundCursor>,
}

impl fmt::Debug for SelectedEventBridgeRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedEventBridgeRuntime")
            .field("identity", &self.provider.identity())
            .field("authorization_count", &self.authorizations.len())
            .field("local_edge_count", &self.edges.len())
            .field("delivery_enabled", &self.delivery_enabled)
            .field(
                "outbound_peer_cursor_count",
                &self.outbound_peer_cursors.len(),
            )
            .finish()
    }
}

impl SelectedEventBridgeRuntime {
    /// Initializes a bounded static bridge against one live mission-bound store.
    pub fn initialize(
        store: Arc<Store>,
        mission: &UnprotectedReferenceMission,
        config: SelectedEventBridgeConfig,
    ) -> Result<(Self, SelectedEventBridgeInitializationReceipt), SelectedEventBridgeRuntimeError>
    {
        config.validate()?;
        if store.mission_authority() != Some(mission.mission_authority_id()) {
            return Err(SelectedEventBridgeRuntimeError::state("mission binding"));
        }
        let provider_head = store
            .control_head()
            .map_err(|_| SelectedEventBridgeRuntimeError::state("provider control head"))?;
        let provider = open_replayed_verifier(&store, mission)
            .map_err(|_| SelectedEventBridgeRuntimeError::state("provider initialization"))?;
        let policy = store
            .control_policy_snapshot()
            .map_err(|_| SelectedEventBridgeRuntimeError::state("provider control policy"))?;
        if store
            .control_head()
            .map_err(|_| SelectedEventBridgeRuntimeError::state("provider control head"))?
            != provider_head
        {
            return Err(SelectedEventBridgeRuntimeError::state(
                "provider control changed",
            ));
        }
        let mut authorizations = Vec::with_capacity(config.authorization_chain.len());
        for exact in &config.authorization_chain {
            authorizations.push(
                SelectedEventBridgeAdapter::verify_authorization(&provider, exact).map_err(
                    |_| SelectedEventBridgeRuntimeError::authentication("authorization verify"),
                )?,
            );
        }
        let active = validate_authorization_chain(&authorizations, mission.mission_authority_id())?;
        preflight_durable_authorizations(&store, &config.authorization_chain)?;

        let mut authorizations_applied = 0usize;
        let mut authorizations_existing = 0usize;
        for authorization in &authorizations {
            match store
                .commit_verified_selected_bridge_authorization(authorization)
                .map_err(|_| SelectedEventBridgeRuntimeError::state("authorization commit"))?
            {
                SelectedBridgeAuthorizationCommitOutcome::Applied { .. } => {
                    authorizations_applied += 1;
                }
                SelectedBridgeAuthorizationCommitOutcome::Duplicate { .. } => {
                    authorizations_existing += 1;
                }
            }
        }

        let by_id = authorizations
            .iter()
            .enumerate()
            .map(|(index, authorization)| (authorization.envelope_id(), index))
            .collect::<BTreeMap<_, _>>();
        let mut edges = Vec::with_capacity(config.edges.len());
        let mut carry_plans = Vec::new();
        let mut carry_keys = BTreeSet::new();
        for configured in &config.edges {
            let index = by_id
                .get(&configured.authorization_envelope_id)
                .copied()
                .ok_or_else(|| SelectedEventBridgeRuntimeError::policy("edge authorization"))?;
            let authorization = &authorizations[index];
            if authorization.bridge_node_id() != mission.identity()
                || !authorization.is_enabled()
                || active.get(&authorization.authorization_key())
                    != Some(&authorization.envelope_id())
                || authorization.source_route_epoch().is_none()
                || authorization.target_route_epoch().is_none()
            {
                return Err(SelectedEventBridgeRuntimeError::policy(
                    "edge authorization",
                ));
            }
            authorization
                .validate_narrowing(&configured.narrowing)
                .map_err(|_| SelectedEventBridgeRuntimeError::policy("edge narrowing"))?;
            let topics = if configured.narrowing.topics().len() == 0 {
                authorization
                    .allowed_topics()
                    .ok_or_else(|| SelectedEventBridgeRuntimeError::policy("edge topics"))?
                    .to_vec()
            } else {
                configured.narrowing.topics().cloned().collect()
            };
            for topic in topics {
                let key = bridge_carry_key(configured.authorization_envelope_id, &topic)?;
                if !carry_keys.insert(key.as_bytes().to_vec()) {
                    return Err(SelectedEventBridgeRuntimeError::invalid(
                        "Carry subscription derivation",
                    ));
                }
                carry_plans.push((
                    key,
                    EventSubscriptionSpec {
                        mode: EventSubscriptionMode::Carry,
                        topic,
                        scope: authorization.source_scope().clone(),
                        include_descendant_scopes: false,
                    },
                ));
            }
            edges.push(RuntimeEdge {
                authorization_index: index,
                authorization_envelope_id: configured.authorization_envelope_id,
                narrowing: configured.narrowing.clone(),
            });
        }
        edges.sort_by_key(|edge| edge.authorization_envelope_id);
        carry_plans.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        if carry_plans.len() > MAX_SELECTED_EVENT_BRIDGE_CARRY_SELECTORS {
            return Err(SelectedEventBridgeRuntimeError::capacity(
                "Carry subscription derivation",
            ));
        }
        let mut carry_subscriptions_inserted = 0usize;
        let mut carry_subscriptions_existing = 0usize;
        let client = if carry_plans.is_empty() {
            None
        } else {
            let journal = crate::demo_publication::Journal::open(
                &store,
                aster_redb_store::EventClientId::new(
                    b"aster.native.bridge-subscriptions.v1".to_vec(),
                )
                .map_err(|_| SelectedEventBridgeRuntimeError::state("Carry client"))?,
            )
            .map_err(|_| SelectedEventBridgeRuntimeError::state("Carry client recovery"))?;
            Some(aster_redb_store::EventClientContext {
                client_id: journal.client.clone(),
                session: journal
                    .session()
                    .map_err(|_| SelectedEventBridgeRuntimeError::state("Carry client session"))?,
            })
        };
        for (key, spec) in carry_plans {
            let outcome = store
                .create_event_subscription_with_policy(
                    client
                        .as_ref()
                        .ok_or_else(|| SelectedEventBridgeRuntimeError::state("Carry client"))?,
                    &policy,
                    &key,
                    spec,
                )
                .map_err(|_| SelectedEventBridgeRuntimeError::state("Carry subscription"))?;
            if outcome.inserted {
                carry_subscriptions_inserted += 1;
            } else {
                carry_subscriptions_existing += 1;
            }
        }

        let mut runtime = Self {
            store,
            provider,
            control_policy: policy,
            authorizations,
            edges,
            delivery_enabled: config.delivery_enabled,
            outbound_peer_cursors: BTreeMap::new(),
        };
        let restart = runtime.reverify_persisted_routes()?;
        let receipt = SelectedEventBridgeInitializationReceipt {
            authorizations_verified: runtime.authorizations.len(),
            authorizations_applied,
            authorizations_existing,
            local_edges: runtime.edges.len(),
            carry_subscriptions_inserted,
            carry_subscriptions_existing,
            route_candidates: restart.candidates,
            routes_reverified: restart.reverified,
            routes_inactive: restart.inactive,
            active_routes: restart.active_routes,
            deliveries: restart.deliveries,
        };
        Ok((runtime, receipt))
    }

    /// Mission identity whose route capabilities back this runtime.
    pub fn identity(&self) -> NodeId {
        self.provider.identity()
    }

    /// Whether target payload opening was explicitly enabled.
    pub const fn delivery_enabled(&self) -> bool {
        self.delivery_enabled
    }

    /// Exact locally operated authorization IDs in deterministic order.
    pub fn local_edge_authorization_ids(&self) -> impl ExactSizeIterator<Item = [u8; 32]> + '_ {
        self.edges.iter().map(|edge| edge.authorization_envelope_id)
    }

    /// Deterministically prepares a bounded contact batch from retained
    /// ordinary Events and already-durable bridge candidates for one
    /// authority-authenticated peer.
    ///
    /// This static MVP has no authenticated live custody clock, so every
    /// finite-TTL candidate is skipped. Unmatched or freshly stale candidates
    /// and routes whose exact target scope/epoch is absent from the peer's
    /// authenticated credential commitments are ordinary non-selections rather
    /// than contact-fatal errors.
    ///
    /// Eligible candidates advance through a bounded process-local per-peer
    /// round-robin cursor. Cursors deliberately are not durable in this MVP, so
    /// restart can repeat the first batch; exact route identities and durable
    /// commit idempotency make that repeat safe.
    pub fn prepare_outbound_routes(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_grant_commitments: &[[u8; 32]],
        limit: usize,
    ) -> Result<SelectedEventBridgeOutboundBatch, SelectedEventBridgeRuntimeError> {
        if limit == 0 || limit > MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_BATCH {
            return Err(SelectedEventBridgeRuntimeError::capacity(
                "outbound batch limit",
            ));
        }
        if peer_route_grant_commitments.len() > MAX_SELECTED_EVENT_BRIDGE_PEER_ROUTE_COMMITMENTS
            || peer_route_grant_commitments
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(SelectedEventBridgeRuntimeError::authentication(
                "peer route commitments",
            ));
        }
        self.require_current_policy("outbound preparation")?;
        let cursor_start = self
            .outbound_peer_cursors
            .get(&authenticated_peer)
            .copied()
            .unwrap_or_default()
            .next_eligible_ordinal;
        let mut plan_window = OutboundPlanWindow::new(cursor_start, limit);
        let mut finite_ttl_skipped = 0usize;
        let inventory = self
            .store
            .transfer_inventory_with_policy(&self.control_policy)
            .map_err(|_| SelectedEventBridgeRuntimeError::state("ordinary outbound inventory"))?;
        let ordinary_scanned = inventory.len().min(MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_SCAN);
        for transfer_id in inventory.iter().take(ordinary_scanned).copied() {
            let transfer = self
                .store
                .get_transfer_with_policy(&self.control_policy, transfer_id)
                .map_err(|_| SelectedEventBridgeRuntimeError::state("ordinary outbound load"))?
                .ok_or_else(|| SelectedEventBridgeRuntimeError::state("ordinary outbound load"))?;
            let (header, exact_source_bytes) = match &transfer {
                StoredEventTransfer::Accepted(event) => (&event.header, event.sealed.as_slice()),
                StoredEventTransfer::RouteCached(event) => {
                    (&event.header_claim, event.sealed.as_slice())
                }
            };
            for edge in &self.edges {
                let authorization = &self.authorizations[edge.authorization_index];
                if !edge_selects_metadata(
                    authorization,
                    &edge.narrowing,
                    &header.scope,
                    header.key_epoch,
                    &header.topic,
                    header.priority,
                ) {
                    continue;
                }
                let Some(target_epoch) = authorization.target_route_epoch() else {
                    continue;
                };
                if !self.provider.peer_can_route(
                    authenticated_peer,
                    peer_route_grant_commitments,
                    authorization.target_scope(),
                    target_epoch,
                ) {
                    continue;
                }
                if header.ttl_ms.is_some() {
                    finite_ttl_skipped = finite_ttl_skipped.checked_add(1).ok_or_else(|| {
                        SelectedEventBridgeRuntimeError::capacity("outbound TTL count")
                    })?;
                } else {
                    plan_window.consider(|| OutboundPlan::First {
                        exact_source_bytes: exact_source_bytes.to_vec(),
                        authorization_envelope_id: edge.authorization_envelope_id,
                    })?;
                }
            }
        }

        let bridge_stats = self
            .store
            .selected_bridge_stats()
            .map_err(|_| SelectedEventBridgeRuntimeError::state("bridge outbound stats"))?;
        let durable_bridge_count = usize::try_from(bridge_stats.event_routes)
            .map_err(|_| SelectedEventBridgeRuntimeError::capacity("bridge outbound scan"))?;
        let bridge_scan_target = durable_bridge_count.min(MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_SCAN);
        let mut bridge_scanned = 0usize;
        let mut after = None;
        while bridge_scanned < bridge_scan_target {
            let scan_limit = ROUTE_CANDIDATE_PAGE.min(bridge_scan_target - bridge_scanned);
            let page = self
                .store
                .selected_bridge_event_route_candidates_after(after, scan_limit)
                .map_err(|_| SelectedEventBridgeRuntimeError::state("bridge outbound scan"))?;
            if page.is_empty() {
                return Err(SelectedEventBridgeRuntimeError::state(
                    "bridge outbound accounting",
                ));
            }
            for candidate in page {
                bridge_scanned += 1;
                after = Some(candidate.wrapper_envelope_id());
                for edge in &self.edges {
                    let authorization = &self.authorizations[edge.authorization_index];
                    if !edge_selects_metadata(
                        authorization,
                        &edge.narrowing,
                        candidate.current_scope(),
                        candidate.current_route_epoch(),
                        candidate.topic(),
                        candidate.priority(),
                    ) {
                        continue;
                    }
                    let Some(target_epoch) = authorization.target_route_epoch() else {
                        continue;
                    };
                    if !self.provider.peer_can_route(
                        authenticated_peer,
                        peer_route_grant_commitments,
                        authorization.target_scope(),
                        target_epoch,
                    ) {
                        continue;
                    }
                    if candidate.ttl_ms().is_some() {
                        finite_ttl_skipped =
                            finite_ttl_skipped.checked_add(1).ok_or_else(|| {
                                SelectedEventBridgeRuntimeError::capacity("outbound TTL count")
                            })?;
                    } else {
                        plan_window.consider(|| OutboundPlan::Nested {
                            exact_wrapper_bytes: candidate.exact_wrapper_bytes().to_vec(),
                            exact_source_bytes: candidate.exact_source_bytes().to_vec(),
                            authorization_envelope_id: edge.authorization_envelope_id,
                        })?;
                    }
                }
            }
        }

        let eligible = plan_window.eligible();
        if eligible > 0
            && !self.outbound_peer_cursors.contains_key(&authenticated_peer)
            && self.outbound_peer_cursors.len() >= MAX_SELECTED_EVENT_BRIDGE_PEER_CURSORS
        {
            return Err(SelectedEventBridgeRuntimeError::capacity(
                "outbound peer cursors",
            ));
        }
        let plans = plan_window.finish();
        let remaining = eligible
            .checked_sub(plans.len())
            .ok_or_else(|| SelectedEventBridgeRuntimeError::capacity("outbound remaining count"))?;
        let next_eligible_ordinal = plans
            .last()
            .map(|numbered| {
                numbered
                    .ordinal
                    .checked_add(1)
                    .ok_or_else(|| {
                        SelectedEventBridgeRuntimeError::capacity("outbound peer cursor")
                    })
                    .map(|next| next % eligible)
            })
            .transpose()?;
        let mut routes = Vec::with_capacity(plans.len());
        let mut inactive = 0usize;
        for numbered in plans {
            let result = match numbered.plan {
                OutboundPlan::First {
                    exact_source_bytes,
                    authorization_envelope_id,
                } => self.materialize_first_hop(
                    &exact_source_bytes,
                    authorization_envelope_id,
                    0,
                    false,
                ),
                OutboundPlan::Nested {
                    exact_wrapper_bytes,
                    exact_source_bytes,
                    authorization_envelope_id,
                } => self.materialize_nested_hop(
                    &exact_wrapper_bytes,
                    &exact_source_bytes,
                    authorization_envelope_id,
                    0,
                    false,
                ),
            };
            match result {
                Ok(route) => routes.push(route),
                Err(error)
                    if matches!(
                        error.kind(),
                        SelectedEventBridgeRuntimeErrorKind::Authentication
                            | SelectedEventBridgeRuntimeErrorKind::PolicyMismatch
                    ) =>
                {
                    inactive += 1;
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(next_eligible_ordinal) = next_eligible_ordinal {
            self.outbound_peer_cursors.insert(
                authenticated_peer,
                PeerOutboundCursor {
                    next_eligible_ordinal,
                },
            );
        }
        Ok(SelectedEventBridgeOutboundBatch {
            routes,
            remaining,
            ordinary_scanned,
            bridge_scanned,
            finite_ttl_skipped,
            inactive,
            scan_truncated: inventory.len() > MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_SCAN
                || durable_bridge_count > MAX_SELECTED_EVENT_BRIDGE_OUTBOUND_SCAN,
        })
    }

    /// Creates or reuses the active first wrapper for one exact source Event.
    pub fn materialize_first_hop(
        &mut self,
        exact_source_bytes: &[u8],
        authorization_envelope_id: [u8; 32],
        cumulative_custody_age_ms: u64,
        age_continuity_unknown: bool,
    ) -> Result<SelectedEventBridgeOutbound, SelectedEventBridgeRuntimeError> {
        self.require_current_policy("first-hop materialize")?;
        let (authorization_index, narrowing) = self.local_edge(authorization_envelope_id)?;
        let authorization = &self.authorizations[authorization_index];
        let target_scope = authorization.target_scope().clone();
        let target_epoch = authorization
            .target_route_epoch()
            .ok_or_else(|| SelectedEventBridgeRuntimeError::policy("first-hop edge"))?;
        let origin = exact_digest(exact_source_bytes);
        if let Some(existing) = self.active_outbound(
            origin,
            &target_scope,
            target_epoch,
            exact_source_bytes,
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )? {
            return Ok(existing);
        }
        let chain = self.authorizations.iter().collect::<Vec<_>>();
        let verified = SelectedEventBridgeAdapter::create_first_hop(
            &mut self.provider,
            exact_source_bytes,
            authorization_envelope_id,
            &chain,
            &narrowing,
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )
        .map_err(|_| SelectedEventBridgeRuntimeError::authentication("first-hop materialize"))?;
        let created_id = verified.wrapper_envelope_id();
        self.store
            .commit_verified_selected_bridge_event_route(&verified)
            .map_err(|_| SelectedEventBridgeRuntimeError::state("first-hop commit"))?;
        self.selected_active_outbound(
            verified.origin_envelope_id(),
            &target_scope,
            target_epoch,
            verified.exact_source_bytes(),
            created_id,
        )
    }

    /// Appends or reuses the active nested wrapper for one authenticated route.
    pub fn materialize_nested_hop(
        &mut self,
        exact_wrapper_bytes: &[u8],
        exact_source_bytes: &[u8],
        authorization_envelope_id: [u8; 32],
        cumulative_custody_age_ms: u64,
        age_continuity_unknown: bool,
    ) -> Result<SelectedEventBridgeOutbound, SelectedEventBridgeRuntimeError> {
        self.require_current_policy("nested-hop materialize")?;
        let (authorization_index, narrowing) = self.local_edge(authorization_envelope_id)?;
        let chain = self.authorizations.iter().collect::<Vec<_>>();
        let current = SelectedEventBridgeAdapter::verify_event_route(
            &self.provider,
            exact_wrapper_bytes,
            exact_source_bytes,
            &chain,
        )
        .map_err(|_| SelectedEventBridgeRuntimeError::authentication("nested source verify"))?;
        let authorization = &self.authorizations[authorization_index];
        if !edge_selects(authorization, &narrowing, &current) {
            return Err(SelectedEventBridgeRuntimeError::policy("nested-hop edge"));
        }
        let target_scope = authorization.target_scope().clone();
        let target_epoch = authorization
            .target_route_epoch()
            .ok_or_else(|| SelectedEventBridgeRuntimeError::policy("nested-hop edge"))?;
        if let Some(existing) = self.active_outbound(
            current.origin_envelope_id(),
            &target_scope,
            target_epoch,
            current.exact_source_bytes(),
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )? {
            return Ok(existing);
        }
        let verified = SelectedEventBridgeAdapter::create_nested_hop(
            &mut self.provider,
            &current,
            authorization_envelope_id,
            &chain,
            &narrowing,
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )
        .map_err(|_| SelectedEventBridgeRuntimeError::authentication("nested-hop materialize"))?;
        let created_id = verified.wrapper_envelope_id();
        self.store
            .commit_verified_selected_bridge_event_route(&verified)
            .map_err(|_| SelectedEventBridgeRuntimeError::state("nested-hop commit"))?;
        self.selected_active_outbound(
            verified.origin_envelope_id(),
            &target_scope,
            target_epoch,
            verified.exact_source_bytes(),
            created_id,
        )
    }

    /// Freshly authenticates and durably applies one received wrapper/source pair.
    pub fn apply_received_route(
        &mut self,
        exact_wrapper_bytes: &[u8],
        exact_source_bytes: &[u8],
    ) -> Result<SelectedEventBridgeApplyReceipt, SelectedEventBridgeRuntimeError> {
        self.require_current_policy("received route apply")?;
        let chain = self.authorizations.iter().collect::<Vec<_>>();
        let verified = SelectedEventBridgeAdapter::verify_event_route(
            &self.provider,
            exact_wrapper_bytes,
            exact_source_bytes,
            &chain,
        )
        .map_err(|_| SelectedEventBridgeRuntimeError::authentication("received route verify"))?;
        if !verified.is_tombstone() && verified.ttl_ms().is_some() {
            return Ok(SelectedEventBridgeApplyReceipt {
                disposition: SelectedEventBridgeApplyDisposition::NotSelected,
                wrapper_envelope_id: verified.wrapper_envelope_id(),
                bridge_route_id: verified.bridge_route_id(),
                origin_envelope_id: verified.origin_envelope_id(),
                hop_count: verified.hop_count(),
                delivery: None,
            });
        }
        let forwardable = self.edges.iter().any(|edge| {
            edge_selects(
                &self.authorizations[edge.authorization_index],
                &edge.narrowing,
                &verified,
            )
        });
        let deliverable = self.delivery_enabled
            && self.provider.can_open_event_content(
                verified.origin_scope(),
                verified.topic(),
                verified.origin_route_epoch(),
            );
        if !forwardable && !deliverable {
            return Ok(SelectedEventBridgeApplyReceipt {
                disposition: SelectedEventBridgeApplyDisposition::NotSelected,
                wrapper_envelope_id: verified.wrapper_envelope_id(),
                bridge_route_id: verified.bridge_route_id(),
                origin_envelope_id: verified.origin_envelope_id(),
                hop_count: verified.hop_count(),
                delivery: None,
            });
        }
        let outcome = self
            .store
            .commit_verified_selected_bridge_event_route(&verified)
            .map_err(|_| SelectedEventBridgeRuntimeError::state("received route commit"))?;
        let delivery = deliverable
            .then(|| delivery_receipt(&self.provider, &verified))
            .transpose()?;
        Ok(SelectedEventBridgeApplyReceipt {
            disposition: apply_disposition(outcome),
            wrapper_envelope_id: verified.wrapper_envelope_id(),
            bridge_route_id: verified.bridge_route_id(),
            origin_envelope_id: verified.origin_envelope_id(),
            hop_count: verified.hop_count(),
            delivery,
        })
    }

    fn local_edge(
        &self,
        authorization_envelope_id: [u8; 32],
    ) -> Result<(usize, SelectedBridgeNarrowingPolicy), SelectedEventBridgeRuntimeError> {
        self.edges
            .iter()
            .find(|edge| edge.authorization_envelope_id == authorization_envelope_id)
            .map(|edge| (edge.authorization_index, edge.narrowing.clone()))
            .ok_or_else(|| SelectedEventBridgeRuntimeError::policy("local edge selection"))
    }

    fn require_current_policy(
        &self,
        operation: &'static str,
    ) -> Result<(), SelectedEventBridgeRuntimeError> {
        let current = self
            .store
            .control_policy_snapshot()
            .map_err(|_| SelectedEventBridgeRuntimeError::state(operation))?;
        if current != self.control_policy {
            return Err(SelectedEventBridgeRuntimeError::state(operation));
        }
        Ok(())
    }

    fn active_outbound(
        &self,
        origin_envelope_id: [u8; 32],
        current_scope: &Scope,
        current_route_epoch: u64,
        expected_source_bytes: &[u8],
        cumulative_custody_age_ms: u64,
        age_continuity_unknown: bool,
    ) -> Result<Option<SelectedEventBridgeOutbound>, SelectedEventBridgeRuntimeError> {
        let Some(candidate) = self
            .store
            .active_selected_bridge_event_route_candidate(
                origin_envelope_id,
                current_scope,
                current_route_epoch,
            )
            .map_err(|_| SelectedEventBridgeRuntimeError::state("active route lookup"))?
        else {
            return Ok(None);
        };
        if candidate.exact_source_bytes() != expected_source_bytes {
            return Err(SelectedEventBridgeRuntimeError::authentication(
                "active route source",
            ));
        }
        let verified = self.verify_candidate(&candidate)?;
        if !verified.is_tombstone()
            && verified
                .ttl_ms()
                .is_some_and(|ttl_ms| age_continuity_unknown || cumulative_custody_age_ms >= ttl_ms)
        {
            return Err(SelectedEventBridgeRuntimeError::authentication(
                "active route custody age",
            ));
        }
        Ok(Some(outbound(
            &verified,
            SelectedEventBridgeMaterializationDisposition::Existing,
        )))
    }

    fn selected_active_outbound(
        &self,
        origin_envelope_id: [u8; 32],
        current_scope: &Scope,
        current_route_epoch: u64,
        expected_source_bytes: &[u8],
        created_id: [u8; 32],
    ) -> Result<SelectedEventBridgeOutbound, SelectedEventBridgeRuntimeError> {
        let candidate = self
            .store
            .active_selected_bridge_event_route_candidate(
                origin_envelope_id,
                current_scope,
                current_route_epoch,
            )
            .map_err(|_| SelectedEventBridgeRuntimeError::state("active route selection"))?
            .ok_or_else(|| SelectedEventBridgeRuntimeError::state("active route selection"))?;
        if candidate.exact_source_bytes() != expected_source_bytes {
            return Err(SelectedEventBridgeRuntimeError::authentication(
                "active route source",
            ));
        }
        let disposition = if candidate.wrapper_envelope_id() == created_id {
            SelectedEventBridgeMaterializationDisposition::Created
        } else {
            SelectedEventBridgeMaterializationDisposition::Existing
        };
        let verified = self.verify_candidate(&candidate)?;
        Ok(outbound(&verified, disposition))
    }

    fn verify_candidate(
        &self,
        candidate: &StoredSelectedBridgeEventRouteCandidate,
    ) -> Result<VerifiedSelectedBridgeEventRoute, SelectedEventBridgeRuntimeError> {
        let chain = self.authorizations.iter().collect::<Vec<_>>();
        SelectedEventBridgeAdapter::verify_event_route(
            &self.provider,
            candidate.exact_wrapper_bytes(),
            candidate.exact_source_bytes(),
            &chain,
        )
        .map_err(|_| SelectedEventBridgeRuntimeError::authentication("active route verify"))
    }

    fn reverify_persisted_routes(
        &mut self,
    ) -> Result<RestartReceipt, SelectedEventBridgeRuntimeError> {
        self.require_current_policy("route restart verification")?;
        let initial = self
            .store
            .selected_bridge_stats()
            .map_err(|_| SelectedEventBridgeRuntimeError::state("route restart stats"))?;
        let candidate_count = usize::try_from(initial.event_routes)
            .map_err(|_| SelectedEventBridgeRuntimeError::capacity("route restart scan"))?;
        if candidate_count > MAX_SELECTED_EVENT_BRIDGE_RESTART_ROUTES {
            return Err(SelectedEventBridgeRuntimeError::capacity(
                "route restart scan",
            ));
        }
        let mut after = None;
        let mut candidates = 0usize;
        let mut reverified = 0usize;
        let mut inactive = 0usize;
        let mut deliveries =
            BTreeMap::<([u8; 32], Scope, u64), SelectedEventBridgeDeliveryReceipt>::new();
        loop {
            let page = self
                .store
                .selected_bridge_event_route_candidates_after(after, ROUTE_CANDIDATE_PAGE)
                .map_err(|_| SelectedEventBridgeRuntimeError::state("route restart scan"))?;
            if page.is_empty() {
                break;
            }
            for candidate in &page {
                candidates += 1;
                after = Some(candidate.wrapper_envelope_id());
                let chain = self.authorizations.iter().collect::<Vec<_>>();
                let Ok(verified) = SelectedEventBridgeAdapter::verify_event_route(
                    &self.provider,
                    candidate.exact_wrapper_bytes(),
                    candidate.exact_source_bytes(),
                    &chain,
                ) else {
                    inactive += 1;
                    continue;
                };
                if !verified.is_tombstone() && verified.ttl_ms().is_some() {
                    inactive += 1;
                    continue;
                }
                let deliverable = self.delivery_enabled
                    && self.provider.can_open_event_content(
                        verified.origin_scope(),
                        verified.topic(),
                        verified.origin_route_epoch(),
                    );
                let key = (
                    verified.origin_envelope_id(),
                    verified.current_scope().clone(),
                    verified.current_route_epoch(),
                );
                let outcome = self
                    .store
                    .commit_verified_selected_bridge_event_route(&verified)
                    .map_err(|_| {
                        SelectedEventBridgeRuntimeError::state("route restart promotion")
                    })?;
                reverified += 1;
                if route_outcome_is_active(outcome) {
                    if deliverable {
                        let delivery = delivery_receipt(&self.provider, &verified)?;
                        deliveries.insert(key, delivery);
                    } else {
                        deliveries.remove(&key);
                    }
                }
            }
            if page.len() < ROUTE_CANDIDATE_PAGE {
                break;
            }
        }
        if candidates != candidate_count {
            return Err(SelectedEventBridgeRuntimeError::state(
                "route restart accounting",
            ));
        }
        let final_stats = self
            .store
            .selected_bridge_stats()
            .map_err(|_| SelectedEventBridgeRuntimeError::state("route restart stats"))?;
        self.require_current_policy("route restart verification")?;
        Ok(RestartReceipt {
            candidates,
            reverified,
            inactive,
            active_routes: final_stats.active_routes,
            deliveries: deliveries.into_values().collect(),
        })
    }
}

struct RestartReceipt {
    candidates: usize,
    reverified: usize,
    inactive: usize,
    active_routes: u64,
    deliveries: Vec<SelectedEventBridgeDeliveryReceipt>,
}

enum OutboundPlan {
    First {
        exact_source_bytes: Vec<u8>,
        authorization_envelope_id: [u8; 32],
    },
    Nested {
        exact_wrapper_bytes: Vec<u8>,
        exact_source_bytes: Vec<u8>,
        authorization_envelope_id: [u8; 32],
    },
}

struct NumberedOutboundPlan {
    ordinal: usize,
    plan: OutboundPlan,
}

struct OutboundPlanWindow {
    start: usize,
    limit: usize,
    eligible: usize,
    after_start: Vec<NumberedOutboundPlan>,
    wraparound: Vec<NumberedOutboundPlan>,
}

impl OutboundPlanWindow {
    fn new(start: usize, limit: usize) -> Self {
        Self {
            start,
            limit,
            eligible: 0,
            after_start: Vec::with_capacity(limit),
            wraparound: Vec::with_capacity(limit),
        }
    }

    fn consider(
        &mut self,
        build: impl FnOnce() -> OutboundPlan,
    ) -> Result<(), SelectedEventBridgeRuntimeError> {
        let ordinal = self.eligible;
        self.eligible = self
            .eligible
            .checked_add(1)
            .ok_or_else(|| SelectedEventBridgeRuntimeError::capacity("outbound candidates"))?;
        let selected = if ordinal >= self.start && self.after_start.len() < self.limit {
            Some(&mut self.after_start)
        } else if ordinal < self.start && self.wraparound.len() < self.limit {
            Some(&mut self.wraparound)
        } else {
            None
        };
        if let Some(selected) = selected {
            selected.push(NumberedOutboundPlan {
                ordinal,
                plan: build(),
            });
        }
        Ok(())
    }

    const fn eligible(&self) -> usize {
        self.eligible
    }

    fn finish(mut self) -> Vec<NumberedOutboundPlan> {
        let remaining_capacity = self.limit.saturating_sub(self.after_start.len());
        let wraparound_count = remaining_capacity.min(self.wraparound.len());
        self.after_start
            .extend(self.wraparound.drain(..wraparound_count));
        self.after_start
    }
}

fn validate_authorization_chain(
    authorizations: &[VerifiedSelectedBridgeAuthorization],
    mission_authority: NodeId,
) -> Result<BTreeMap<[u8; 32], [u8; 32]>, SelectedEventBridgeRuntimeError> {
    let mut expected_sequence = 1u64;
    let mut previous = None;
    let mut generations = BTreeMap::<[u8; 32], u64>::new();
    let mut active = BTreeMap::new();
    for authorization in authorizations {
        if authorization.authority_id() != mission_authority
            || authorization.control_sequence() != expected_sequence
            || authorization.previous_control_id() != previous
            || generations
                .get(&authorization.authorization_key())
                .is_some_and(|generation| *generation >= authorization.generation())
        {
            return Err(SelectedEventBridgeRuntimeError::authentication(
                "authorization chain",
            ));
        }
        generations.insert(
            authorization.authorization_key(),
            authorization.generation(),
        );
        active.insert(
            authorization.authorization_key(),
            authorization.envelope_id(),
        );
        previous = Some(authorization.envelope_id());
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| SelectedEventBridgeRuntimeError::capacity("authorization chain"))?;
    }
    Ok(active)
}

fn preflight_durable_authorizations(
    store: &Store,
    configured: &[Vec<u8>],
) -> Result<(), SelectedEventBridgeRuntimeError> {
    let stats = store
        .selected_bridge_stats()
        .map_err(|_| SelectedEventBridgeRuntimeError::state("authorization preflight"))?;
    let durable_count = usize::try_from(stats.authorizations)
        .map_err(|_| SelectedEventBridgeRuntimeError::capacity("authorization preflight"))?;
    if durable_count > configured.len()
        || durable_count > MAX_SELECTED_EVENT_BRIDGE_AUTHORIZATIONS
        || stats.authorization_head_sequence != stats.authorizations
    {
        return Err(SelectedEventBridgeRuntimeError::state(
            "authorization preflight",
        ));
    }
    let mut after = None;
    let mut seen = 0usize;
    loop {
        let page = store
            .selected_bridge_authorization_candidates_after(after, AUTHORIZATION_CANDIDATE_PAGE)
            .map_err(|_| SelectedEventBridgeRuntimeError::state("authorization preflight"))?;
        if page.is_empty() {
            break;
        }
        for candidate in &page {
            if configured.get(seen).map(Vec::as_slice) != Some(candidate.exact_bytes()) {
                return Err(SelectedEventBridgeRuntimeError::state(
                    "authorization preflight",
                ));
            }
            seen += 1;
            after = Some(candidate.control_sequence());
        }
        if page.len() < AUTHORIZATION_CANDIDATE_PAGE {
            break;
        }
    }
    if seen != durable_count {
        return Err(SelectedEventBridgeRuntimeError::state(
            "authorization preflight",
        ));
    }
    Ok(())
}

fn bridge_carry_key(
    authorization_envelope_id: [u8; 32],
    topic: &Topic,
) -> Result<EventSubscriptionKey, SelectedEventBridgeRuntimeError> {
    let topic_len = u16::try_from(topic.as_str().len())
        .map_err(|_| SelectedEventBridgeRuntimeError::capacity("Carry operation key"))?;
    let mut bytes =
        Vec::with_capacity(BRIDGE_CARRY_OPERATION_PREFIX.len() + 32 + 2 + usize::from(topic_len));
    bytes.extend_from_slice(BRIDGE_CARRY_OPERATION_PREFIX);
    bytes.extend_from_slice(&authorization_envelope_id);
    bytes.extend_from_slice(&topic_len.to_be_bytes());
    bytes.extend_from_slice(topic.as_str().as_bytes());
    EventSubscriptionKey::new(bytes)
        .map_err(|_| SelectedEventBridgeRuntimeError::capacity("Carry operation key"))
}

fn edge_selects(
    authorization: &VerifiedSelectedBridgeAuthorization,
    narrowing: &SelectedBridgeNarrowingPolicy,
    route: &VerifiedSelectedBridgeEventRoute,
) -> bool {
    edge_selects_metadata(
        authorization,
        narrowing,
        route.current_scope(),
        route.current_route_epoch(),
        route.topic(),
        route.priority(),
    )
}

fn edge_selects_metadata(
    authorization: &VerifiedSelectedBridgeAuthorization,
    narrowing: &SelectedBridgeNarrowingPolicy,
    scope: &Scope,
    route_epoch: u64,
    topic: &Topic,
    priority: Priority,
) -> bool {
    authorization.is_enabled()
        && authorization.source_scope() == scope
        && authorization.source_route_epoch() == Some(route_epoch)
        && narrowing.priorities().any(|selected| *selected == priority)
        && if narrowing.topics().len() == 0 {
            authorization
                .allowed_topics()
                .is_some_and(|topics| topics.contains(topic))
        } else {
            narrowing.topics().any(|selected| selected == topic)
        }
}

fn outbound(
    route: &VerifiedSelectedBridgeEventRoute,
    disposition: SelectedEventBridgeMaterializationDisposition,
) -> SelectedEventBridgeOutbound {
    SelectedEventBridgeOutbound {
        receipt: SelectedEventBridgeMaterializationReceipt {
            disposition,
            wrapper_envelope_id: route.wrapper_envelope_id(),
            bridge_route_id: route.bridge_route_id(),
            origin_envelope_id: route.origin_envelope_id(),
            source_item_id: route.source_item_id().into(),
            origin_scope: route.origin_scope().clone(),
            origin_route_epoch: route.origin_route_epoch(),
            current_scope: route.current_scope().clone(),
            current_route_epoch: route.current_route_epoch(),
            hop_count: route.hop_count(),
        },
        exact_wrapper_bytes: route.exact_wrapper_bytes().to_vec(),
        exact_source_bytes: route.exact_source_bytes().to_vec(),
    }
}

fn delivery_receipt(
    provider: &ReferenceEnvelopeSealer,
    route: &VerifiedSelectedBridgeEventRoute,
) -> Result<SelectedEventBridgeDeliveryReceipt, SelectedEventBridgeRuntimeError> {
    let mut payload = SelectedEventBridgeAdapter::open_event_payload(provider, route)
        .map_err(|_| SelectedEventBridgeRuntimeError::authentication("target delivery"))?;
    let payload_len = payload.len();
    let payload_sha256 = Sha256::digest(&payload).into();
    payload.zeroize();
    Ok(SelectedEventBridgeDeliveryReceipt {
        wrapper_envelope_id: route.wrapper_envelope_id(),
        bridge_route_id: route.bridge_route_id(),
        origin_envelope_id: route.origin_envelope_id(),
        source_item_id: route.source_item_id().into(),
        publisher: route.publisher(),
        origin_scope: route.origin_scope().clone(),
        origin_route_epoch: route.origin_route_epoch(),
        current_scope: route.current_scope().clone(),
        current_route_epoch: route.current_route_epoch(),
        topic: route.topic().clone(),
        priority: route.priority(),
        event_sequence: route.event_sequence(),
        hop_count: route.hop_count(),
        payload_len,
        payload_sha256,
    })
}

fn apply_disposition(
    outcome: SelectedBridgeEventRouteCommitOutcome,
) -> SelectedEventBridgeApplyDisposition {
    match outcome {
        SelectedBridgeEventRouteCommitOutcome::Active { .. } => {
            SelectedEventBridgeApplyDisposition::Active
        }
        SelectedBridgeEventRouteCommitOutcome::RetainedAlternate { .. } => {
            SelectedEventBridgeApplyDisposition::RetainedAlternate
        }
        SelectedBridgeEventRouteCommitOutcome::Duplicate { active: true, .. } => {
            SelectedEventBridgeApplyDisposition::DuplicateActive
        }
        SelectedBridgeEventRouteCommitOutcome::Duplicate { active: false, .. } => {
            SelectedEventBridgeApplyDisposition::DuplicateInactive
        }
    }
}

fn route_outcome_is_active(outcome: SelectedBridgeEventRouteCommitOutcome) -> bool {
    matches!(
        outcome,
        SelectedBridgeEventRouteCommitOutcome::Active { .. }
            | SelectedBridgeEventRouteCommitOutcome::Duplicate { active: true, .. }
    )
}

fn exact_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use aster_mesh::{
        BridgeAuthorizationLink, CausalStamp, DataClass, Dot, ProvisioningAccess,
        ReferenceProvisioner, ReferenceSessionInitiator, ReferenceSessionResponder,
        SelectedBridgeAuthorizationPolicy, VersionVector, engine::EnvelopeHeader,
    };

    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-selected-bridge-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create bridge test root");
            Self(path)
        }

        fn store(&self, name: &str, authority: NodeId) -> Arc<Store> {
            Arc::new(
                Store::open_for_mission(self.0.join(format!("{name}.redb")), authority)
                    .expect("open bridge test store"),
            )
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Services {
        authority: ReferenceEnvelopeSealer,
        publisher: ReferenceEnvelopeSealer,
        first: UnprotectedReferenceMission,
        second: UnprotectedReferenceMission,
        target: UnprotectedReferenceMission,
    }

    struct Authorizations {
        chain: Vec<Vec<u8>>,
        first: [u8; 32],
        second: [u8; 32],
    }

    fn scope(value: &str) -> Scope {
        Scope::new(value).expect("test scope")
    }

    fn topic(value: &str) -> Topic {
        Topic::new(value).expect("test topic")
    }

    fn relay(value: &str, epoch: u64) -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(value), vec![epoch]).expect("relay access")
    }

    fn member(value: &str, epoch: u64) -> ProvisioningAccess {
        ProvisioningAccess::member(
            scope(value),
            vec![epoch],
            vec![topic("ops"), topic("other")],
        )
        .expect("member access")
    }

    fn services(seed: u8) -> Services {
        let mut provisioner =
            ReferenceProvisioner::from_seed([seed; 32]).expect("test provisioner");
        let alpha = relay("demo/alpha", 1);
        let parent = relay("demo/parent", 2);
        let bravo = relay("demo/bravo", 3);
        let authority = provisioner
            .issue_control_authority(1, &[alpha.clone(), parent.clone(), bravo.clone()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("authority provider");
        let publisher = provisioner
            .issue_node(2, &[member("demo/alpha", 1)])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher provider");
        let first = provisioner
            .issue_node(3, &[alpha.clone(), parent.clone()])
            .and_then(|bundle| bundle.to_bytes())
            .map(UnprotectedReferenceMission::from_bytes)
            .expect("encode first bridge")
            .expect("first bridge mission");
        let second = provisioner
            .issue_node(4, &[alpha, parent, bravo])
            .and_then(|bundle| bundle.to_bytes())
            .map(UnprotectedReferenceMission::from_bytes)
            .expect("encode second bridge")
            .expect("second bridge mission");
        let target_access = ProvisioningAccess::content_only(
            scope("demo/alpha"),
            vec![1],
            vec![topic("ops"), topic("other")],
        )
        .expect("target content access");
        let target = provisioner
            .issue_node(5, &[member("demo/bravo", 3), target_access])
            .and_then(|bundle| bundle.to_bytes())
            .map(UnprotectedReferenceMission::from_bytes)
            .expect("encode target")
            .expect("target mission");
        Services {
            authority,
            publisher,
            first,
            second,
            target,
        }
    }

    fn authenticated_peer_route_view(
        local: &UnprotectedReferenceMission,
        peer: &UnprotectedReferenceMission,
    ) -> (NodeId, Vec<[u8; 32]>) {
        let (initiator, client_hello) =
            ReferenceSessionInitiator::start(peer.fresh_bundle().expect("peer session bundle"))
                .expect("start peer session");
        let responder =
            ReferenceSessionResponder::open(local.fresh_bundle().expect("local session bundle"))
                .expect("open local session");
        let (responder, server_hello) = responder
            .receive_client(&client_hello)
            .expect("local authenticates peer hello");
        let (initiator, client_auth) = initiator
            .receive_server(&server_hello)
            .expect("peer authenticates local hello");
        let (local_session, server_finished) = responder
            .receive_client_auth(&client_auth)
            .expect("local authenticates peer session");
        let _peer_session = initiator
            .receive_finished(&server_finished)
            .expect("peer authenticates local finish");
        assert_eq!(local_session.peer_identity(), peer.identity());
        (
            local_session.peer_identity(),
            local_session.peer_route_grant_commitments().to_vec(),
        )
    }

    fn authorizations(services: &mut Services) -> Authorizations {
        let first_provider = ReferenceEnvelopeSealer::open(
            services.first.fresh_bundle().expect("first fresh bundle"),
        )
        .expect("first enrollment provider");
        let second_provider = ReferenceEnvelopeSealer::open(
            services.second.fresh_bundle().expect("second fresh bundle"),
        )
        .expect("second enrollment provider");
        let first_enrollment = SelectedEventBridgeAdapter::create_enrollment(
            &first_provider,
            &scope("demo/alpha"),
            1,
            &scope("demo/parent"),
            2,
        )
        .expect("first enrollment");
        let first_enrollment =
            SelectedEventBridgeAdapter::verify_enrollment(&services.authority, &first_enrollment)
                .expect("verify first enrollment");
        let policy = SelectedBridgeAuthorizationPolicy::new(
            vec![topic("ops"), topic("other")],
            vec![Priority::Immediate, Priority::Flash],
            2,
        )
        .expect("bridge authorization policy");
        let first = SelectedEventBridgeAdapter::issue_authorization(
            &mut services.authority,
            &first_enrollment,
            BridgeAuthorizationLink::new(1, None, 1).expect("first auth link"),
            &policy,
        )
        .expect("first authorization");
        let second_enrollment = SelectedEventBridgeAdapter::create_enrollment(
            &second_provider,
            &scope("demo/parent"),
            2,
            &scope("demo/bravo"),
            3,
        )
        .expect("second enrollment");
        let second_enrollment =
            SelectedEventBridgeAdapter::verify_enrollment(&services.authority, &second_enrollment)
                .expect("verify second enrollment");
        let second = SelectedEventBridgeAdapter::issue_authorization(
            &mut services.authority,
            &second_enrollment,
            BridgeAuthorizationLink::new(2, Some(first.envelope_id()), 1)
                .expect("second auth link"),
            &policy,
        )
        .expect("second authorization");
        Authorizations {
            chain: vec![first.exact_bytes().to_vec(), second.exact_bytes().to_vec()],
            first: first.envelope_id(),
            second: second.envelope_id(),
        }
    }

    fn edge(id: [u8; 32]) -> SelectedEventBridgeEdge {
        SelectedEventBridgeEdge::new(
            id,
            SelectedBridgeNarrowingPolicy::new(vec![topic("ops")], vec![Priority::Immediate])
                .expect("test narrowing"),
        )
    }

    fn source_header(
        publisher: NodeId,
        selected_topic: &str,
        priority: Priority,
        sequence: u64,
        payload_len: usize,
    ) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Event,
            topic: topic(selected_topic),
            scope: scope("demo/alpha"),
            priority,
            stamp: CausalStamp {
                dot: Dot {
                    publisher,
                    counter: sequence,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(sequence),
            logical_key: format!("bridge-event-{sequence}").into_bytes(),
            blob_route: None,
            ttl_ms: None,
            content_len: payload_len as u64,
            tombstone: false,
            key_epoch: 1,
        }
    }

    #[test]
    fn two_hop_runtime_is_filtered_payload_blind_idempotent_and_restart_promoted() {
        let root = TestRoot::new("two-hop-runtime");
        let mut services = services(0xe1);
        let authorizations = authorizations(&mut services);
        let authority = services.first.mission_authority_id();
        let first_path = root.0.join("first.redb");
        let first_store = root.store("first", authority);
        let second_store = root.store("second", authority);
        let target_path = root.0.join("target.redb");
        let target_store = root.store("target", authority);
        let first_config = SelectedEventBridgeConfig::new(
            authorizations.chain.clone(),
            vec![edge(authorizations.first)],
            false,
        )
        .expect("first bridge config");
        let second_config = SelectedEventBridgeConfig::new(
            authorizations.chain.clone(),
            vec![edge(authorizations.second)],
            false,
        )
        .expect("second bridge config");
        let target_config =
            SelectedEventBridgeConfig::new(authorizations.chain.clone(), Vec::new(), true)
                .expect("target config");
        let collision_store = root.store("Carry-key-collision", authority);
        let collision_policy = collision_store
            .control_policy_snapshot()
            .expect("collision policy");
        let collision_key =
            bridge_carry_key(authorizations.first, &topic("ops")).expect("reserved Carry key");
        let collision_journal = crate::demo_publication::Journal::open(
            &collision_store,
            aster_redb_store::EventClientId::new(b"aster.native.bridge-subscriptions.v1".to_vec())
                .unwrap(),
        )
        .unwrap();
        let collision_client = aster_redb_store::EventClientContext {
            client_id: collision_journal.client.clone(),
            session: collision_journal.session().unwrap(),
        };
        collision_store
            .create_event_subscription_with_policy(
                &collision_client,
                &collision_policy,
                &collision_key,
                EventSubscriptionSpec {
                    mode: EventSubscriptionMode::Consume,
                    topic: topic("ops"),
                    scope: scope("demo/alpha"),
                    include_descendant_scopes: false,
                },
            )
            .expect("seed conflicting reserved key");
        let collision_error = SelectedEventBridgeRuntime::initialize(
            Arc::clone(&collision_store),
            &services.first,
            first_config.clone(),
        )
        .expect_err("reserved Carry key collision must fail closed");
        assert_eq!(
            collision_error.kind(),
            SelectedEventBridgeRuntimeErrorKind::StateUnavailable
        );
        assert_eq!(
            collision_store
                .event_subscription_stats()
                .expect("collision subscription stats")
                .subscriptions,
            1
        );
        let (mut first, first_init) = SelectedEventBridgeRuntime::initialize(
            Arc::clone(&first_store),
            &services.first,
            first_config.clone(),
        )
        .expect("initialize first bridge");
        let (mut second, second_init) = SelectedEventBridgeRuntime::initialize(
            Arc::clone(&second_store),
            &services.second,
            second_config,
        )
        .expect("initialize second bridge");
        let (mut target, target_init) = SelectedEventBridgeRuntime::initialize(
            Arc::clone(&target_store),
            &services.target,
            target_config.clone(),
        )
        .expect("initialize target");
        assert_eq!(first_init.carry_subscriptions_inserted, 1);
        assert_eq!(second_init.carry_subscriptions_inserted, 1);
        assert_eq!(target_init.carry_subscriptions_inserted, 0);
        assert_eq!(
            first_store
                .event_subscription_stats()
                .unwrap()
                .subscriptions,
            1
        );

        let payload = b"runtime target payload canary";
        let source = services
            .publisher
            .seal_event(
                &source_header(
                    services.publisher.identity(),
                    "ops",
                    Priority::Immediate,
                    1,
                    payload.len(),
                ),
                payload,
            )
            .expect("seal source Event");
        let replication = first_store
            .event_replication_policy_snapshot()
            .expect("first bridge replication policy");
        let route_verified_source = first
            .provider
            .verify_event(&source.bytes)
            .expect("first bridge source-route verification");
        first_store
            .cache_route_verified_event_with_replication_policy(
                &replication,
                &route_verified_source,
                &source.bytes,
            )
            .expect("Carry-cache source Event");
        assert!(matches!(
            first_store
                .get_transfer(aster_redb_store::EventTransferId::new(
                    route_verified_source.envelope_id(),
                ))
                .expect("load Carry transfer"),
            Some(StoredEventTransfer::RouteCached(_))
        ));
        let (second_peer, second_commitments) =
            authenticated_peer_route_view(&services.first, &services.second);
        let mut prepared = first
            .prepare_outbound_routes(second_peer, &second_commitments, 4)
            .expect("prepare Carry source bridge route");
        assert_eq!(prepared.ordinary_scanned, 1);
        assert_eq!(prepared.routes.len(), 1);
        let first_outbound = prepared.routes.pop().expect("prepared first hop");
        assert_eq!(
            first_outbound.receipt().disposition,
            SelectedEventBridgeMaterializationDisposition::Created
        );
        let first_again = first
            .materialize_first_hop(&source.bytes, authorizations.first, 2, false)
            .expect("reuse first hop");
        assert_eq!(
            first_again.receipt().disposition,
            SelectedEventBridgeMaterializationDisposition::Existing
        );
        assert_eq!(
            first_again.exact_wrapper_bytes(),
            first_outbound.exact_wrapper_bytes()
        );
        let parent_apply = second
            .apply_received_route(
                first_outbound.exact_wrapper_bytes(),
                first_outbound.exact_source_bytes(),
            )
            .expect("apply parent route");
        assert!(parent_apply.delivery.is_none());
        assert!(!format!("{parent_apply:?}").contains("runtime target payload canary"));
        let (wrong_peer, wrong_commitments) =
            authenticated_peer_route_view(&services.second, &services.first);
        let wrong_target = second
            .prepare_outbound_routes(wrong_peer, &wrong_commitments, 4)
            .expect("wrong-target peer is an ordinary empty selection");
        assert!(wrong_target.routes.is_empty());
        assert_eq!(wrong_target.remaining, 0);
        assert_eq!(wrong_target.bridge_scanned, 1);
        assert_eq!(
            second_store
                .selected_bridge_stats()
                .expect("wrong-target bridge stats")
                .event_routes,
            1
        );
        let (target_peer, target_commitments) =
            authenticated_peer_route_view(&services.second, &services.target);
        let mut prepared_second = second
            .prepare_outbound_routes(target_peer, &target_commitments, 4)
            .expect("target-authorized peer selects nested hop");
        assert_eq!(prepared_second.routes.len(), 1);
        let second_outbound = prepared_second.routes.pop().expect("prepared nested hop");
        let observer_store = root.store("route-only-observer", authority);
        let observer_config =
            SelectedEventBridgeConfig::new(authorizations.chain.clone(), Vec::new(), true)
                .expect("observer config");
        let (mut observer, _) = SelectedEventBridgeRuntime::initialize(
            Arc::clone(&observer_store),
            &services.second,
            observer_config,
        )
        .expect("initialize route-only observer");
        let not_selected = observer
            .apply_received_route(
                second_outbound.exact_wrapper_bytes(),
                second_outbound.exact_source_bytes(),
            )
            .expect("unselected valid route is nonfatal");
        assert_eq!(
            not_selected.disposition,
            SelectedEventBridgeApplyDisposition::NotSelected
        );
        assert_eq!(
            observer_store
                .selected_bridge_stats()
                .expect("observer bridge stats")
                .event_routes,
            0
        );
        let target_apply = target
            .apply_received_route(
                second_outbound.exact_wrapper_bytes(),
                second_outbound.exact_source_bytes(),
            )
            .expect("apply target route");
        let delivery = target_apply
            .delivery
            .as_ref()
            .expect("target delivery receipt");
        assert_eq!(delivery.payload_len, payload.len());
        assert_eq!(delivery.payload_sha256, exact_digest(payload));
        assert!(!format!("{target_apply:?}").contains("runtime target payload canary"));

        let wrong_topic = services
            .publisher
            .seal_event(
                &source_header(
                    services.publisher.identity(),
                    "other",
                    Priority::Immediate,
                    2,
                    payload.len(),
                ),
                payload,
            )
            .expect("seal wrong-topic Event");
        assert!(
            first
                .materialize_first_hop(&wrong_topic.bytes, authorizations.first, 0, false)
                .is_err()
        );
        let wrong_priority = services
            .publisher
            .seal_event(
                &source_header(
                    services.publisher.identity(),
                    "ops",
                    Priority::Flash,
                    3,
                    payload.len(),
                ),
                payload,
            )
            .expect("seal wrong-priority Event");
        assert!(
            first
                .materialize_first_hop(&wrong_priority.bytes, authorizations.first, 0, false)
                .is_err()
        );

        drop(target);
        drop(target_store);
        let reopened_target_store = Arc::new(
            Store::open_for_mission(&target_path, authority).expect("reopen target store"),
        );
        let (_reopened_target, restart) = SelectedEventBridgeRuntime::initialize(
            reopened_target_store,
            &services.target,
            target_config,
        )
        .expect("restart target runtime");
        assert_eq!(restart.routes_reverified, 1);
        assert_eq!(restart.active_routes, 1);
        assert_eq!(restart.deliveries.len(), 1);
        assert_eq!(restart.deliveries[0].payload_sha256, exact_digest(payload));

        drop(first);
        drop(first_store);
        let reopened_first_store = Arc::new(
            Store::open_for_mission(&first_path, authority).expect("reopen first bridge store"),
        );
        let (_reopened_first, retry) = SelectedEventBridgeRuntime::initialize(
            Arc::clone(&reopened_first_store),
            &services.first,
            first_config,
        )
        .expect("restart first bridge runtime");
        assert_eq!(retry.carry_subscriptions_inserted, 0);
        assert_eq!(retry.carry_subscriptions_existing, 1);
        assert_eq!(
            reopened_first_store
                .event_subscription_stats()
                .unwrap()
                .subscriptions,
            1
        );
    }

    #[test]
    fn outbound_peer_cursor_progresses_past_one_contact_batch() {
        let root = TestRoot::new("outbound-peer-progress");
        let mut services = services(0xe2);
        let authorizations = authorizations(&mut services);
        let authority = services.first.mission_authority_id();
        let store = root.store("first", authority);
        let config = SelectedEventBridgeConfig::new(
            authorizations.chain,
            vec![edge(authorizations.first)],
            false,
        )
        .expect("first bridge config");
        let (mut runtime, _) =
            SelectedEventBridgeRuntime::initialize(Arc::clone(&store), &services.first, config)
                .expect("initialize first bridge");
        let replication = store
            .event_replication_policy_snapshot()
            .expect("first bridge replication policy");
        for sequence in 1..=10 {
            let payload = format!("round-robin-payload-{sequence}");
            let source = services
                .publisher
                .seal_event(
                    &source_header(
                        services.publisher.identity(),
                        "ops",
                        Priority::Immediate,
                        sequence,
                        payload.len(),
                    ),
                    payload.as_bytes(),
                )
                .expect("seal round-robin Event");
            let route_verified = runtime
                .provider
                .verify_event(&source.bytes)
                .expect("route-verify round-robin Event");
            store
                .cache_route_verified_event_with_replication_policy(
                    &replication,
                    &route_verified,
                    &source.bytes,
                )
                .expect("Carry-cache round-robin Event");
        }

        let (peer, commitments) = authenticated_peer_route_view(&services.first, &services.second);
        let first = runtime
            .prepare_outbound_routes(peer, &commitments, 8)
            .expect("prepare first round-robin batch");
        assert_eq!(first.routes.len(), 8);
        assert_eq!(first.remaining, 2);
        let first_origins = first
            .routes
            .iter()
            .map(|route| route.receipt().origin_envelope_id)
            .collect::<BTreeSet<_>>();

        let second = runtime
            .prepare_outbound_routes(peer, &commitments, 8)
            .expect("prepare second round-robin batch");
        assert_eq!(second.routes.len(), 8);
        assert_eq!(second.remaining, 2);
        let second_origins = second
            .routes
            .iter()
            .map(|route| route.receipt().origin_envelope_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(second_origins.difference(&first_origins).count(), 2);
        assert_eq!(first_origins.union(&second_origins).count(), 10);
        assert_eq!(runtime.outbound_peer_cursors.len(), 1);
    }

    #[test]
    fn config_debug_redacts_exact_authorization_bytes_and_rejects_duplicate_edges() {
        let canary = b"exact-authorization-secret-canary".to_vec();
        let narrowing =
            SelectedBridgeNarrowingPolicy::new(vec![topic("ops")], vec![Priority::Immediate])
                .expect("narrowing");
        let id = [7; 32];
        let config = SelectedEventBridgeConfig::new(
            vec![canary],
            vec![SelectedEventBridgeEdge::new(id, narrowing.clone())],
            false,
        )
        .expect("structurally bounded config");
        assert!(!format!("{config:?}").contains("exact-authorization-secret-canary"));
        assert!(
            SelectedEventBridgeConfig::new(
                vec![vec![1]],
                vec![
                    SelectedEventBridgeEdge::new(id, narrowing.clone()),
                    SelectedEventBridgeEdge::new(id, narrowing),
                ],
                false,
            )
            .is_err()
        );
    }
}
