//! High-level live and stopped-state surfaces for source-authenticated State projections.
//!
//! The cloneable live handle reaches the running node's sole application
//! authority through its bounded actor. Both surfaces publish and query State,
//! and expose a durable at-least-once positive-current-version queue. The queue
//! is not a materialized projection feed and emits no synthetic withdrawal when
//! authorization leaves an exact key without a visible current version. The
//! stopped/exclusive facade shares the mission-bound store,
//! control policy, source-envelope provider, and causal ledger with the selected
//! Event surface. A running node reconciles durable State objects through the
//! class-specific State lane when its configured receive policy declares a
//! matching source interest; application subscriptions do not replace that
//! network policy in this slice.

use std::{
    fmt, fs,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use aster_mesh::{
    CausalStamp, NodeId, Priority, ReferenceEnvelopeSealer, RouteVerifiedStateEnvelope, Scope,
    StateContentVerification, Topic,
};
use aster_redb_store::{
    ControlPolicySnapshot, ControlTransferId, MAX_STATE_POLL_DELIVERIES,
    MAX_STATE_SUBSCRIPTION_SCAN, StateDeliveryAck as StoreStateDeliveryAck,
    StateDeliveryToken as StoreStateDeliveryToken, StateOperationKey, StateOperationRequest,
    StateProjectionPlan, StatePublicationIntent, StateSemanticId, StateSenderProjection,
    StateSubscriptionId as StoreStateSubscriptionId, StateSubscriptionKey,
    StateSubscriptionPollSelection, StateSubscriptionRemoveOutcome, StateSubscriptionSpec,
    StateVersionDisposition as StoreStateDisposition, Store, StoreError, StoredState,
};
use tokio::sync::{mpsc, oneshot};

use super::{
    ApplicationError, ApplicationErrorKind, SelectedApplicationCommand, actor_unavailable,
    application_error,
};
use crate::{
    frame::MAX_OBJECT_BYTES,
    mission::UnprotectedReferenceMission,
    runtime::{
        AuthenticatedEventRouteCache, STORE_FILE, StartupEventVerification,
        cache_authenticated_state_route_claim, ensure_principal_active,
        ensure_state_accepts_normal_operation, open_startup_event_verifier_and_cache,
        refresh_application_policy,
    },
};

/// Maximum number of projected State heads returned by one poll.
pub const MAX_SELECTED_STATE_DELIVERIES: usize = MAX_STATE_POLL_DELIVERIES;

/// Maximum retained State candidates freshly authenticated by one poll.
pub const MAX_SELECTED_STATE_SUBSCRIPTION_SCAN: usize = MAX_STATE_SUBSCRIPTION_SCAN;

/// Canonical byte length of an opaque [`StateDeliveryToken`].
pub const STATE_DELIVERY_TOKEN_BYTES: usize = aster_redb_store::STATE_DELIVERY_TOKEN_BYTES;

const MAX_SELECTED_STATE_PLAN_RETRIES: usize = 4;

/// Source-authenticated semantic identity of one State version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateId([u8; 32]);

impl StateId {
    /// Constructs an identity from its complete semantic bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete semantic identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: StateSemanticId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> StateSemanticId {
        StateSemanticId::new(self.0)
    }
}

impl fmt::Display for StateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One durable, operation-key-idempotent State publication request.
///
/// A tombstone is an authenticated State version and therefore requires an
/// empty payload. Finite TTL is absent until the selected forwarding path
/// carries authenticated cumulative age.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatePublishRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Causal disposition computed for one retained State version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateVersionDisposition {
    /// Deterministic application-visible causal maximum.
    Current,
    /// Another causal maximum retained for recovery.
    Concurrent,
    /// A retained version observed by a later version.
    Superseded,
}

/// Successful durable State publication without sealed-byte/provider details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatePublishResult {
    pub id: StateId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    pub acceptance_marker: u64,
    pub inserted: bool,
}

/// Exact logical-key query for one selected State projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateQuery {
    pub topic: Topic,
    pub scope: Scope,
    pub logical_key: Vec<u8>,
    /// Include all currently active retained concurrent and superseded versions.
    ///
    /// Versions made inactive by revocation, a later scope epoch, or a
    /// same-epoch route-key replacement remain durable but are not exposed as
    /// application results. Their exact source proof is retained in the
    /// bounded startup cache; current-lineage results are freshly opened.
    pub include_recoverable_versions: bool,
}

/// One freshly source/content-verified retained State version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateItem {
    pub id: StateId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
    pub acceptance_marker: u64,
    pub disposition: StateVersionDisposition,
}

/// Deterministic latest-value State projection plus optional recovery history.
///
/// A current tombstone remains visible as `Some(StateItem { tombstone: true,
/// .. })`; deletion is never collapsed into an unauthenticated absence.
/// The Store's numeric policy reduction is verified independently from the
/// stricter current-lineage application reduction. Revoked, stale-epoch, and
/// cache-proven superseded-lineage versions are never exposed as plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProjection {
    pub current: Option<StateItem>,
    pub recoverable: Vec<StateItem>,
}

/// Stable mission-local identity of one durable State subscription.
///
/// This local ledger identity grants no route or content authority. The
/// selected node intersects its receive intent with current mission policy and
/// freshly authenticates every State candidate before delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateSubscriptionId([u8; 32]);

impl StateSubscriptionId {
    /// Constructs an identifier from its complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: StoreStateSubscriptionId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> StoreStateSubscriptionId {
        StoreStateSubscriptionId::from_bytes(self.0)
    }
}

impl fmt::Display for StateSubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Idempotent creation request for one durable positive-current-version subscription.
///
/// The selector covers every logical key in the selected topic and scope.
/// Descendant scopes remain distinct projection groups. Subscription intent
/// cannot expand current route or content authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSubscriptionRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub include_descendant_scopes: bool,
}

/// Result of creating or replaying one durable State subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSubscription {
    pub id: StateSubscriptionId,
    pub inserted: bool,
}

/// One bounded at-least-once positive-current-version delivery poll.
///
/// `scan_limit` bounds the complete matching retained candidate set freshly
/// authenticated by one poll. Poll fails closed when that full projection
/// snapshot exceeds the bound; it never advances through a partial candidate
/// set. `has_more` reports additional verified, unacknowledged current heads
/// beyond `delivery_limit`. An empty result is not a Current-to-None withdrawal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatePollRequest {
    pub subscription: StateSubscriptionId,
    pub delivery_limit: usize,
    pub scan_limit: usize,
}

impl StatePollRequest {
    fn validate(self) -> Result<Self, ApplicationError> {
        if self.delivery_limit == 0
            || self.delivery_limit > MAX_SELECTED_STATE_DELIVERIES
            || self.scan_limit == 0
            || self.scan_limit > MAX_SELECTED_STATE_SUBSCRIPTION_SCAN
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "state poll",
            ));
        }
        Ok(self)
    }
}

/// Opaque acknowledgement identity for one exact State delivery tenure and retry.
///
/// Tokens originate in [`StateDelivery`] and may be restored from their
/// canonical bytes. They bind the subscription incarnation, State identity,
/// current tenure, and issued retry so a delayed acknowledgement cannot consume
/// later work.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateDeliveryToken(StoreStateDeliveryToken);

impl StateDeliveryToken {
    /// Restores a canonical opaque token previously obtained from [`Self::as_bytes`].
    ///
    /// A structurally valid token is still accepted only when acknowledgement
    /// verifies its exact subscription and State binding.
    pub fn from_bytes(bytes: [u8; STATE_DELIVERY_TOKEN_BYTES]) -> Result<Self, ApplicationError> {
        StoreStateDeliveryToken::from_bytes(bytes)
            .map(Self::from_store)
            .map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::InvalidRequest, "state delivery token")
            })
    }

    /// Returns the canonical opaque bytes for durable application transport.
    pub fn as_bytes(&self) -> &[u8; STATE_DELIVERY_TOKEN_BYTES] {
        self.0.as_bytes()
    }

    fn from_store(token: StoreStateDeliveryToken) -> Self {
        Self(token)
    }

    fn into_store(self) -> StoreStateDeliveryToken {
        self.0
    }

    #[cfg(test)]
    fn inert_for_command_rejection() -> Self {
        let mut bytes = [0_u8; STATE_DELIVERY_TOKEN_BYTES];
        bytes[0] = 1;
        bytes[8] = 1;
        bytes[16] = 1;
        bytes[24] = 1;
        Self::from_bytes(bytes).expect("canonical inert delivery token")
    }
}

/// One positive current State version whose retry was committed before return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateDelivery {
    /// Freshly authenticated deterministic current head for one exact key.
    pub state: StateItem,
    /// Nonzero durable at-least-once attempt number.
    pub attempt: u64,
    /// Exact opaque token required to acknowledge this delivery.
    pub token: StateDeliveryToken,
}

/// Bounded positive-current-version delivery result.
///
/// An empty page means there is no unacknowledged positive Current version. It
/// is not a complete projection snapshot and does not signal that a previously
/// authorized current value was withdrawn.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateDeliveryPage {
    pub deliveries: Vec<StateDelivery>,
    pub has_more: bool,
}

/// Idempotent acknowledgement disposition for one projected State head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

/// Idempotent disposition from withdrawing one durable State selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateUnsubscribe {
    /// This call removed the selector and its delivery ledger.
    Removed,
    /// The exact selector was already absent.
    AlreadyAbsent,
}

/// Structurally audited local State delivery-ledger status.
///
/// This reports only durable application selectors and at-least-once delivery
/// bookkeeping. It is not network synchronization or convergence status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateDeliveryStatus {
    pub subscriptions: u64,
    pub pending_deliveries: u64,
    pub acknowledged_deliveries: u64,
    pub delivery_cursors: u64,
    pub selector_generation: u64,
}

struct VerifiedStateCandidate {
    id: StateId,
    item: Option<StateItem>,
    stamp: CausalStamp,
    store_disposition: Option<StoreStateDisposition>,
    policy_active: bool,
    active: bool,
}

struct VerifiedStateSubscriptionCandidate {
    id: StateId,
    stored: StoredState,
    item: Option<StateItem>,
    stamp: CausalStamp,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StateSubscriptionCandidateDisposition {
    Current,
    Noncurrent,
    Inactive,
}

struct StatePublicationRouteContext<'a> {
    store: &'a Store,
    policy: &'a ControlPolicySnapshot,
    source_route_cache: &'a AuthenticatedEventRouteCache,
    verifier: &'a mut ReferenceEnvelopeSealer,
}

/// Cloneable live State handle backed by the running node's sole authority.
#[derive(Clone)]
pub struct SelectedStateHandle {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    admission: Arc<AtomicBool>,
    identity: NodeId,
    mission_authority: NodeId,
}

impl SelectedStateHandle {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        admission: Arc<AtomicBool>,
        identity: NodeId,
        mission_authority: NodeId,
    ) -> Self {
        Self {
            commands,
            admission,
            identity,
            mission_authority,
        }
    }

    /// Authenticated local State publisher identity.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable mission authority bound to the live store.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission_authority
    }

    /// Durably publishes one State version through the running node actor.
    pub async fn publish(
        &self,
        request: StatePublishRequest,
    ) -> Result<StatePublishResult, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::Publish { request, response },
            received,
            "state publish",
        )
        .await
    }

    /// Queries one freshly verified State projection through the running node actor.
    pub async fn query(&self, query: StateQuery) -> Result<StateProjection, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::Query { query, response },
            received,
            "state query",
        )
        .await
    }

    /// Idempotently creates one durable projected-State delivery subscription.
    pub async fn subscribe(
        &self,
        request: StateSubscriptionRequest,
    ) -> Result<StateSubscription, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::Subscribe { request, response },
            received,
            "state subscribe",
        )
        .await
    }

    /// Polls freshly authenticated positive Current versions with at-least-once delivery.
    pub async fn poll(
        &self,
        request: StatePollRequest,
    ) -> Result<StateDeliveryPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::Poll { request, response },
            received,
            "state poll",
        )
        .await
    }

    /// Idempotently acknowledges one exact token-bound State delivery.
    pub async fn acknowledge(
        &self,
        subscription: StateSubscriptionId,
        state: StateId,
        token: StateDeliveryToken,
    ) -> Result<StateAcknowledgement, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::Acknowledge {
                subscription,
                state,
                token,
                response,
            },
            received,
            "state acknowledge",
        )
        .await
    }

    /// Idempotently removes one State selector and its delivery ledger.
    pub async fn unsubscribe(
        &self,
        subscription: StateSubscriptionId,
    ) -> Result<StateUnsubscribe, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::Unsubscribe {
                subscription,
                response,
            },
            received,
            "state unsubscribe",
        )
        .await
    }

    /// Returns audited local State selector and delivery-ledger counts.
    pub async fn delivery_status(&self) -> Result<StateDeliveryStatus, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedStateCommand::DeliveryStatus { response },
            received,
            "state delivery status",
        )
        .await
    }

    async fn send<T>(
        &self,
        command: SelectedStateCommand,
        received: oneshot::Receiver<Result<T, ApplicationError>>,
        operation: &'static str,
    ) -> Result<T, ApplicationError> {
        if !self.admission.load(Ordering::Acquire) {
            return Err(actor_unavailable(operation));
        }
        self.commands
            .send(SelectedApplicationCommand::State(command))
            .await
            .map_err(|_| actor_unavailable(operation))?;
        received.await.map_err(|_| actor_unavailable(operation))?
    }
}

pub(crate) enum SelectedStateCommand {
    Publish {
        request: StatePublishRequest,
        response: oneshot::Sender<Result<StatePublishResult, ApplicationError>>,
    },
    Query {
        query: StateQuery,
        response: oneshot::Sender<Result<StateProjection, ApplicationError>>,
    },
    Subscribe {
        request: StateSubscriptionRequest,
        response: oneshot::Sender<Result<StateSubscription, ApplicationError>>,
    },
    Poll {
        request: StatePollRequest,
        response: oneshot::Sender<Result<StateDeliveryPage, ApplicationError>>,
    },
    Acknowledge {
        subscription: StateSubscriptionId,
        state: StateId,
        token: StateDeliveryToken,
        response: oneshot::Sender<Result<StateAcknowledgement, ApplicationError>>,
    },
    Unsubscribe {
        subscription: StateSubscriptionId,
        response: oneshot::Sender<Result<StateUnsubscribe, ApplicationError>>,
    },
    DeliveryStatus {
        response: oneshot::Sender<Result<StateDeliveryStatus, ApplicationError>>,
    },
}

impl SelectedStateCommand {
    pub(crate) const fn mutates_selectors(&self) -> bool {
        matches!(self, Self::Subscribe { .. } | Self::Unsubscribe { .. })
    }

    pub(crate) fn reject(self) {
        match self {
            Self::Publish { response, .. } => {
                _ = response.send(Err(actor_unavailable("state publish")));
            }
            Self::Query { response, .. } => {
                _ = response.send(Err(actor_unavailable("state query")));
            }
            Self::Subscribe { response, .. } => {
                _ = response.send(Err(actor_unavailable("state subscribe")));
            }
            Self::Poll { response, .. } => {
                _ = response.send(Err(actor_unavailable("state poll")));
            }
            Self::Acknowledge { response, .. } => {
                _ = response.send(Err(actor_unavailable("state acknowledge")));
            }
            Self::Unsubscribe { response, .. } => {
                _ = response.send(Err(actor_unavailable("state unsubscribe")));
            }
            Self::DeliveryStatus { response } => {
                _ = response.send(Err(actor_unavailable("state delivery status")));
            }
        }
    }
}

/// Exclusive stopped-state handle over the selected State projection.
///
/// The handle takes the same process-exclusive mission-bound redb writer as
/// the Event facade and live runtime. It therefore cannot observe or mutate
/// around their policy snapshots. Stop this handle before running the network
/// actor; [`SelectedStateHandle`] then reaches the same composition through
/// that actor.
pub struct SelectedStateNode {
    mission: UnprotectedReferenceMission,
    store: Arc<Store>,
    verifier: ReferenceEnvelopeSealer,
    historical_verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
    source_route_cache: Arc<AuthenticatedEventRouteCache>,
}

impl SelectedStateNode {
    /// Opens the explicitly unprotected reference provisioning path.
    ///
    /// Terminal state is rejected before mission bytes are loaded. The exact
    /// store is mission-bound and process-locked, every retained exact source
    /// is proved across ordered control replay, then the current verifier and
    /// bounded route-lineage cache become available to State operations.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        let state = state.as_ref();
        ensure_state_accepts_normal_operation(state)
            .map_err(|error| application_error("state open", error))?;
        let mission = UnprotectedReferenceMission::load(mission_bundle)
            .map_err(|error| application_error("state open", error.into()))?;
        fs::create_dir_all(state).map_err(|error| application_error("state open", error.into()))?;
        let store = Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())
            .map_err(|error| application_error("state open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("state open", error.into()))?;
        let StartupEventVerification {
            verifier,
            historical_verifier,
            cache: source_route_cache,
            policy: _,
        } = open_startup_event_verifier_and_cache(&store, &mission)
            .map_err(|error| application_error("state open", error))?;
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("state open", error))?;
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("state open", error.into()))?;
        let mut selected = Self {
            mission,
            store: Arc::new(store),
            verifier,
            historical_verifier,
            verifier_head,
            source_route_cache,
        };
        selected.current_policy("state open")?;
        Ok(selected)
    }

    pub(crate) fn from_runtime(
        mission: UnprotectedReferenceMission,
        store: Arc<Store>,
        verifier: ReferenceEnvelopeSealer,
        historical_verifier: ReferenceEnvelopeSealer,
        verifier_head: Option<(u64, ControlTransferId)>,
        source_route_cache: Arc<AuthenticatedEventRouteCache>,
    ) -> Self {
        Self {
            mission,
            store,
            verifier,
            historical_verifier,
            verifier_head,
            source_route_cache,
        }
    }

    /// Authenticated local State publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to provisioning and the durable store.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Durably publishes one State version exactly once per operation key.
    pub fn publish(
        &mut self,
        request: StatePublishRequest,
    ) -> Result<StatePublishResult, ApplicationError> {
        let StatePublishRequest {
            operation_key,
            topic,
            scope,
            priority,
            logical_key,
            payload,
            tombstone,
        } = request;
        if payload.len() > MAX_OBJECT_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "state publish",
            ));
        }
        let operation = StateOperationKey::new(operation_key)
            .map_err(|error| application_error("state publish", error.into()))?;
        let intent = StatePublicationIntent::new(
            self.identity(),
            topic.clone(),
            scope.clone(),
            priority,
            logical_key.clone(),
            &payload,
            tombstone,
        )
        .map_err(|error| application_error("state publish", error.into()))?;
        let operation_request = StateOperationRequest::new(&operation, &intent, &payload)
            .map_err(|error| application_error("state publish", error.into()))?;
        let policy = self.current_policy("state publish")?;
        let epoch = self
            .store
            .active_scope_epoch(&scope)
            .map_err(|error| application_error("state publish", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_state(&scope, epoch)
            || !self.verifier.can_open_state_content(&scope, &topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "state publish",
            ));
        }
        let reservation = self
            .store
            .reserve_state_with_policy(&policy, self.identity(), &topic, &scope)
            .map_err(|error| application_error("state publish", error.into()))?;
        let content_len = u64::try_from(payload.len()).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "state publish")
        })?;
        let header = reservation
            .header(priority, logical_key, content_len, tombstone, epoch)
            .map_err(|error| application_error("state publish", error.into()))?;
        let sealed = self
            .verifier
            .seal_state(&header, &payload)
            .map_err(|error| application_error("state publish", error.into()))?;
        if sealed.bytes.len() > MAX_OBJECT_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "state publish",
            ));
        }
        let route = self
            .verifier
            .verify_state(&sealed.bytes)
            .map_err(|error| application_error("state publish", error.into()))?;
        let verified = match self
            .verifier
            .verify_state_content(route, &sealed.bytes)
            .map_err(|error| application_error("state publish", error.into()))?
        {
            StateContentVerification::ContentVerified {
                state,
                payload: opened,
            } => {
                if opened != payload {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state publish",
                    ));
                }
                state
            }
            StateContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::RequestRejected,
                    "state publish",
                ));
            }
        };
        verified
            .ensure_live_for_local_publication()
            .map_err(|error| application_error("state publish", error.into()))?;
        let outcome = self
            .store
            .commit_reserved_state_once_with_policy(
                &policy,
                &operation_request,
                &reservation,
                &verified,
                &sealed.bytes,
            )
            .map_err(|error| application_error("state publish", error.into()))?;
        let state = outcome.state();
        self.verify_publication_result(&policy, &intent, &payload, state, outcome.inserted())?;
        Ok(StatePublishResult {
            id: StateId::from_store(state.semantic_id),
            publisher: state.header.stamp.dot.publisher,
            publisher_counter: state.header.stamp.dot.counter,
            priority: state.header.priority,
            acceptance_marker: state.acceptance_marker,
            inserted: outcome.inserted(),
        })
    }

    fn verify_publication_result(
        &mut self,
        policy: &ControlPolicySnapshot,
        intent: &StatePublicationIntent,
        payload: &[u8],
        stored: &StoredState,
        inserted: bool,
    ) -> Result<(), ApplicationError> {
        let route = match self.verifier.verify_state(&stored.sealed) {
            Ok(route) => route,
            Err(error) if inserted => {
                return Err(application_error("state publish", error.into()));
            }
            Err(_) => {
                return self.verify_historical_publication_result(policy, intent, payload, stored);
            }
        };
        Self::verify_publication_route(
            StatePublicationRouteContext {
                store: &self.store,
                policy,
                source_route_cache: &self.source_route_cache,
                verifier: &mut self.verifier,
            },
            intent,
            payload,
            stored,
            route,
        )
    }

    fn verify_historical_publication_result(
        &mut self,
        policy: &ControlPolicySnapshot,
        intent: &StatePublicationIntent,
        payload: &[u8],
        stored: &StoredState,
    ) -> Result<(), ApplicationError> {
        let projection = self
            .store
            .retained_state_sender_inventory_with_policy(policy)
            .map_err(|error| application_error("state publish", error.into()))?
            .into_iter()
            .find(|projection| projection.transfer_id() == stored.transfer_id)
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "state publish")
            })?;
        if projection.semantic_id() != stored.semantic_id
            || projection.publisher() != stored.header.stamp.dot.publisher
            || projection.topic() != &stored.header.topic
            || projection.scope() != &stored.header.scope
            || projection.key_epoch() != stored.header.key_epoch
            || projection.exact_len()
                != u64::try_from(stored.sealed.len()).map_err(|_| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "state publish")
                })?
            || projection.acceptance_marker() != stored.acceptance_marker
            || self
                .source_route_cache
                .is_current_state_sender_projection(&self.verifier, &projection)
                .map_err(|error| application_error("state publish", error))?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        let route = self
            .historical_verifier
            .verify_state(&stored.sealed)
            .map_err(|error| application_error("state publish", error.into()))?;
        if self.verifier.is_current_source_route_lineage(
            route.scope(),
            route.key_epoch(),
            route.route_lineage(),
        ) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        Self::verify_publication_route(
            StatePublicationRouteContext {
                store: &self.store,
                policy,
                source_route_cache: &self.source_route_cache,
                verifier: &mut self.historical_verifier,
            },
            intent,
            payload,
            stored,
            route,
        )
    }

    fn verify_publication_route(
        context: StatePublicationRouteContext<'_>,
        intent: &StatePublicationIntent,
        payload: &[u8],
        stored: &StoredState,
        route: RouteVerifiedStateEnvelope,
    ) -> Result<(), ApplicationError> {
        let StatePublicationRouteContext {
            store,
            policy,
            source_route_cache,
            verifier,
        } = context;
        if route.envelope_id() != *stored.transfer_id.as_bytes()
            || route.item_id() != *stored.semantic_id.as_bytes()
            || route.header() != &stored.header
            || route.publisher() != intent.publisher()
            || route.topic() != intent.topic()
            || route.scope() != intent.scope()
            || route.priority() != intent.priority()
            || route.logical_key() != intent.logical_key()
            || route.content_len() != intent.content_len()
            || route.tombstone() != intent.tombstone()
            || route.ttl_ms().is_some()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        if store
            .is_control_principal_revoked(route.publisher())
            .map_err(|error| application_error("state publish", error.into()))?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "state publish",
            ));
        }
        let current_epoch = store
            .active_scope_epoch(route.scope())
            .map_err(|error| application_error("state publish", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if route.key_epoch() > current_epoch {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        if !verifier.can_route_state(route.scope(), route.key_epoch())
            || !verifier.can_open_state_content(route.scope(), route.topic(), route.key_epoch())
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        match verifier
            .verify_state_content(route.clone(), &stored.sealed)
            .map_err(|error| application_error("state publish", error.into()))?
        {
            StateContentVerification::ContentVerified {
                state,
                payload: opened,
            } if opened == payload => {
                state
                    .verify_exact_payload(payload)
                    .map_err(|error| application_error("state publish", error.into()))?;
                cache_authenticated_state_route_claim(
                    store,
                    policy,
                    source_route_cache,
                    verifier,
                    &route,
                )
                .map_err(|error| application_error("state publish", error))
            }
            StateContentVerification::ContentVerified { .. }
            | StateContentVerification::RouteOnly(_) => Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            )),
        }
    }

    /// Idempotently creates one durable projected-State delivery subscription.
    ///
    /// The selector covers all logical keys in the selected topic/scope. It is
    /// local application-delivery intent only; configured mutable interests
    /// remain the network receive policy in this slice.
    pub fn subscribe(
        &mut self,
        request: StateSubscriptionRequest,
    ) -> Result<StateSubscription, ApplicationError> {
        let StateSubscriptionRequest {
            operation_key,
            topic,
            scope,
            include_descendant_scopes,
        } = request;
        let key = StateSubscriptionKey::new(operation_key)
            .map_err(|error| application_error("state subscribe", error.into()))?;
        let policy = self.current_policy("state subscribe")?;
        let epoch = self
            .store
            .active_scope_epoch(&scope)
            .map_err(|error| application_error("state subscribe", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_state(&scope, epoch)
            || !self.verifier.can_open_state_content(&scope, &topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "state subscribe",
            ));
        }
        let outcome = self
            .store
            .create_state_subscription_with_policy(
                &policy,
                &key,
                StateSubscriptionSpec {
                    topic,
                    scope,
                    include_descendant_scopes,
                },
            )
            .map_err(|error| application_error("state subscribe", error.into()))?;
        Ok(StateSubscription {
            id: StateSubscriptionId::from_store(outcome.id),
            inserted: outcome.inserted,
        })
    }

    /// Polls deterministic positive Current versions with durable at-least-once attempts.
    ///
    /// Preparation returns the complete matching retained snapshot, including
    /// acknowledged candidates. Every exact source is freshly authenticated;
    /// current/noncurrent/inactive reduction is then supplied to the privileged
    /// store commit, which atomically rechecks the complete plan before attempts
    /// advance. A committed noncurrent/inactive classification retires an
    /// acknowledgement's suppression tenure, so the same semantic version can
    /// be delivered with a new token if a later poll selects it as Current again.
    /// No delivery is synthesized for a Current-to-None authorization change.
    pub fn poll(
        &mut self,
        request: StatePollRequest,
    ) -> Result<StateDeliveryPage, ApplicationError> {
        let request = request.validate()?;
        for _ in 0..MAX_SELECTED_STATE_PLAN_RETRIES {
            let policy = self.current_policy("state poll")?;
            let plan = self
                .store
                .prepare_state_subscription_poll_with_policy(
                    &policy,
                    request.subscription.into_store(),
                    request.delivery_limit,
                    request.scan_limit,
                )
                .map_err(|error| application_error("state poll", error.into()))?;
            if plan.subscription() != request.subscription.into_store() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state poll",
                ));
            }
            let spec = plan.spec();
            let retained_projections = self
                .store
                .retained_state_sender_inventory_with_policy(&policy)
                .map_err(|error| application_error("state poll", error.into()))?;
            let mut verified = Vec::with_capacity(plan.candidates().len());
            let mut groups =
                std::collections::BTreeMap::<(Topic, Scope, Vec<u8>), Vec<usize>>::new();
            let mut seen = std::collections::BTreeSet::new();

            for candidate in plan.candidates() {
                if candidate
                    .pending_attempt()
                    .is_some_and(|attempt| attempt == 0)
                    || candidate
                        .acknowledged_attempt()
                        .is_some_and(|attempt| attempt == 0)
                    || (candidate.pending_attempt().is_some()
                        && candidate.acknowledged_attempt().is_some())
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state poll",
                    ));
                }
                let stored = candidate.state();
                let id = StateId::from_store(stored.semantic_id);
                if !seen.insert(id) {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state poll",
                    ));
                }
                let scope_matches = if spec.include_descendant_scopes {
                    spec.scope.contains(&stored.header.scope)
                } else {
                    spec.scope == stored.header.scope
                };
                if spec.topic != stored.header.topic || !scope_matches {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state poll",
                    ));
                }
                let sender_projection = retained_projections
                    .iter()
                    .find(|projection| projection.transfer_id() == stored.transfer_id)
                    .ok_or_else(|| {
                        ApplicationError::new(ApplicationErrorKind::Integrity, "state poll")
                    })?;
                let query = StateQuery {
                    topic: stored.header.topic.clone(),
                    scope: stored.header.scope.clone(),
                    logical_key: stored.header.logical_key.clone(),
                    include_recoverable_versions: true,
                };
                let (item, _policy_active, active) = self
                    .open_state_candidate(&query, stored, sender_projection)
                    .map_err(|error| ApplicationError::new(error.kind(), "state poll"))?;
                if active && item.is_none() {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state poll",
                    ));
                }
                let index = verified.len();
                groups
                    .entry((
                        stored.header.topic.clone(),
                        stored.header.scope.clone(),
                        stored.header.logical_key.clone(),
                    ))
                    .or_default()
                    .push(index);
                verified.push(VerifiedStateSubscriptionCandidate {
                    id,
                    stored: stored.clone(),
                    item,
                    stamp: stored.header.stamp.clone(),
                    active,
                });
            }

            let mut dispositions =
                vec![StateSubscriptionCandidateDisposition::Inactive; verified.len()];
            for indexes in groups.values() {
                let candidates = indexes
                    .iter()
                    .map(|index| {
                        let candidate = &verified[*index];
                        (candidate.id, &candidate.stamp, candidate.active)
                    })
                    .collect::<Vec<_>>();
                let (current, reduced) = recompute_state_dispositions(&candidates);
                for (group_index, disposition) in reduced.into_iter().enumerate() {
                    let index = indexes[group_index];
                    dispositions[index] = match disposition {
                        Some(StateVersionDisposition::Current) => {
                            if Some(group_index) != current {
                                return Err(ApplicationError::new(
                                    ApplicationErrorKind::Integrity,
                                    "state poll",
                                ));
                            }
                            StateSubscriptionCandidateDisposition::Current
                        }
                        Some(
                            StateVersionDisposition::Concurrent
                            | StateVersionDisposition::Superseded,
                        ) => StateSubscriptionCandidateDisposition::Noncurrent,
                        None => StateSubscriptionCandidateDisposition::Inactive,
                    };
                    if let Some(item) = verified[index].item.as_mut() {
                        if let Some(disposition) = disposition {
                            item.disposition = disposition;
                        }
                    } else if disposition.is_some() {
                        return Err(ApplicationError::new(
                            ApplicationErrorKind::Integrity,
                            "state poll",
                        ));
                    }
                }
            }

            let mut selection = StateSubscriptionPollSelection::default();
            let mut opened_current = std::collections::BTreeMap::new();
            for (candidate, disposition) in verified.into_iter().zip(dispositions) {
                match disposition {
                    StateSubscriptionCandidateDisposition::Current => {
                        selection.current.push(candidate.id.into_store());
                        let item = candidate.item.ok_or_else(|| {
                            ApplicationError::new(ApplicationErrorKind::Integrity, "state poll")
                        })?;
                        if item.disposition != StateVersionDisposition::Current
                            || opened_current
                                .insert(candidate.id, (candidate.stored, item))
                                .is_some()
                        {
                            return Err(ApplicationError::new(
                                ApplicationErrorKind::Integrity,
                                "state poll",
                            ));
                        }
                    }
                    StateSubscriptionCandidateDisposition::Noncurrent => {
                        selection.noncurrent.push(candidate.id.into_store());
                    }
                    StateSubscriptionCandidateDisposition::Inactive => {
                        selection.inactive.push(candidate.id.into_store());
                    }
                }
            }

            let committed = match self
                .store
                .commit_state_subscription_poll_with_policy(&policy, &plan, &selection)
            {
                Ok(committed) => committed,
                Err(
                    StoreError::StateSubscriptionPlanChanged
                    | StoreError::StateSelectorGenerationChanged
                    | StoreError::ControlPolicyChanged,
                ) => continue,
                Err(error) => return Err(application_error("state poll", error.into())),
            };
            let mut deliveries = Vec::with_capacity(committed.deliveries.len());
            for delivery in committed.deliveries {
                let id = StateId::from_store(delivery.state.semantic_id);
                let (verified_state, item) = opened_current.remove(&id).ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "state poll")
                })?;
                if delivery.state != verified_state || delivery.attempt == 0 {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state poll",
                    ));
                }
                deliveries.push(StateDelivery {
                    state: item,
                    attempt: delivery.attempt,
                    token: StateDeliveryToken::from_store(delivery.token),
                });
            }
            return Ok(StateDeliveryPage {
                deliveries,
                has_more: committed.has_more,
            });
        }
        Err(ApplicationError::new(
            ApplicationErrorKind::PolicyUnsettled,
            "state poll",
        ))
    }

    /// Idempotently acknowledges one exact token-bound State delivery.
    pub fn acknowledge(
        &mut self,
        subscription: StateSubscriptionId,
        state: StateId,
        token: StateDeliveryToken,
    ) -> Result<StateAcknowledgement, ApplicationError> {
        let policy = self.current_policy("state acknowledge")?;
        match self
            .store
            .acknowledge_state_delivery_with_policy(
                &policy,
                subscription.into_store(),
                state.into_store(),
                token.into_store(),
            )
            .map_err(|error| application_error("state acknowledge", error.into()))?
        {
            StoreStateDeliveryAck::Acknowledged => Ok(StateAcknowledgement::Acknowledged),
            StoreStateDeliveryAck::AlreadyAcknowledged => {
                Ok(StateAcknowledgement::AlreadyAcknowledged)
            }
        }
    }

    /// Idempotently removes one durable State selector and its delivery ledger.
    pub fn unsubscribe(
        &mut self,
        subscription: StateSubscriptionId,
    ) -> Result<StateUnsubscribe, ApplicationError> {
        let policy = self.current_policy("state unsubscribe")?;
        let StateSubscriptionRemoveOutcome { removed, .. } = self
            .store
            .remove_state_subscription_with_policy(&policy, subscription.into_store())
            .map_err(|error| application_error("state unsubscribe", error.into()))?;
        Ok(if removed {
            StateUnsubscribe::Removed
        } else {
            StateUnsubscribe::AlreadyAbsent
        })
    }

    /// Returns audited local State selector and delivery-ledger counts.
    pub fn delivery_status(&mut self) -> Result<StateDeliveryStatus, ApplicationError> {
        let _policy = self.current_policy("state delivery status")?;
        let stats = self
            .store
            .state_subscription_stats()
            .map_err(|error| application_error("state delivery status", error.into()))?;
        Ok(StateDeliveryStatus {
            subscriptions: stats.subscriptions,
            pending_deliveries: stats.pending_deliveries,
            acknowledged_deliveries: stats.acknowledged_deliveries,
            delivery_cursors: stats.delivery_cursors,
            selector_generation: stats.selector_generation,
        })
    }

    /// Returns the deterministic, freshly verified projection for one exact key.
    pub fn query(&mut self, query: StateQuery) -> Result<StateProjection, ApplicationError> {
        let policy = self.current_policy("state query")?;
        let epoch = self
            .store
            .active_scope_epoch(&query.scope)
            .map_err(|error| application_error("state query", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_state(&query.scope, epoch)
            || !self
                .verifier
                .can_open_state_content(&query.scope, &query.topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "state query",
            ));
        }
        let plan = self
            .store
            .prepare_state_projection_with_policy(
                &policy,
                &query.topic,
                &query.scope,
                &query.logical_key,
            )
            .map_err(|error| application_error("state query", error.into()))?;
        let projection = self.verify_projection(&query, &plan)?;
        self.store
            .require_state_projection_plan_with_policy(&policy, &plan)
            .map_err(|error| application_error("state query", error.into()))?;
        Ok(projection)
    }

    fn verify_projection(
        &mut self,
        query: &StateQuery,
        plan: &StateProjectionPlan,
    ) -> Result<StateProjection, ApplicationError> {
        if plan.topic() != &query.topic
            || plan.scope() != &query.scope
            || plan.logical_key() != query.logical_key
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }

        let mut candidates = Vec::with_capacity(plan.candidates().len());
        let retained_projections = self
            .store
            .retained_state_sender_inventory_with_policy(plan.control_policy())
            .map_err(|error| application_error("state query", error.into()))?;
        let mut previous = None;
        for candidate in plan.candidates() {
            let state = candidate.state();
            let id = StateId::from_store(state.semantic_id);
            if previous.is_some_and(|previous| previous >= id) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state query",
                ));
            }
            previous = Some(id);
            let sender_projection = retained_projections
                .iter()
                .find(|projection| projection.transfer_id() == state.transfer_id)
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "state query")
                })?;
            let (item, policy_active, active) =
                self.open_state_candidate(query, state, sender_projection)?;
            candidates.push(VerifiedStateCandidate {
                id,
                stamp: state.header.stamp.clone(),
                item,
                store_disposition: candidate.disposition(),
                policy_active,
                active,
            });
        }

        let policy_candidates = candidates
            .iter()
            .map(|candidate| (candidate.id, &candidate.stamp, candidate.policy_active))
            .collect::<Vec<_>>();
        let (policy_current_index, policy_dispositions) =
            recompute_state_dispositions(&policy_candidates);
        let plan_current = plan
            .current()
            .map(|candidate| StateId::from_store(candidate.state().semantic_id));
        let verified_policy_current = policy_current_index.map(|index| candidates[index].id);
        if plan_current != verified_policy_current {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }

        for (candidate, disposition) in candidates.iter().zip(policy_dispositions) {
            if candidate.store_disposition != disposition.map(StateVersionDisposition::into_store) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state query",
                ));
            }
        }

        let current_candidates = candidates
            .iter()
            .map(|candidate| (candidate.id, &candidate.stamp, candidate.active))
            .collect::<Vec<_>>();
        let (current_index, dispositions) = recompute_state_dispositions(&current_candidates);
        for (candidate, disposition) in candidates.iter_mut().zip(dispositions) {
            if let Some(disposition) = disposition {
                candidate
                    .item
                    .as_mut()
                    .ok_or_else(|| {
                        ApplicationError::new(ApplicationErrorKind::Integrity, "state query")
                    })?
                    .disposition = disposition;
            }
        }

        let current = current_index
            .map(|index| {
                candidates[index].item.clone().ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "state query")
                })
            })
            .transpose()?;
        let recoverable = if query.include_recoverable_versions {
            candidates
                .into_iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    (candidate.active && Some(index) != current_index)
                        .then_some(candidate.item)
                        .flatten()
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(StateProjection {
            current,
            recoverable,
        })
    }

    fn open_state_candidate(
        &mut self,
        query: &StateQuery,
        stored: &StoredState,
        projection: &StateSenderProjection,
    ) -> Result<(Option<StateItem>, bool, bool), ApplicationError> {
        let route = match self.verifier.verify_state(&stored.sealed) {
            Ok(route) => route,
            Err(_) => {
                if stored.header.topic != query.topic
                    || stored.header.scope != query.scope
                    || stored.header.logical_key != query.logical_key
                    || stored.header.ttl_ms.is_some()
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state query",
                    ));
                }
                if projection.semantic_id() != stored.semantic_id
                    || projection.publisher() != stored.header.stamp.dot.publisher
                    || projection.topic() != &stored.header.topic
                    || projection.scope() != &stored.header.scope
                    || projection.key_epoch() != stored.header.key_epoch
                    || projection.exact_len()
                        != u64::try_from(stored.sealed.len()).map_err(|_| {
                            ApplicationError::new(ApplicationErrorKind::Integrity, "state query")
                        })?
                    || projection.acceptance_marker() != stored.acceptance_marker
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state query",
                    ));
                }
                let revoked = self
                    .store
                    .is_control_principal_revoked(projection.publisher())
                    .map_err(|error| application_error("state query", error.into()))?;
                let current_epoch = self
                    .store
                    .active_scope_epoch(projection.scope())
                    .map_err(|error| application_error("state query", error.into()))?
                    .map_or(1, |(epoch, _)| epoch);
                if projection.key_epoch() > current_epoch {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state query",
                    ));
                }
                let policy_active = !revoked && projection.key_epoch() == current_epoch;
                let current = self
                    .source_route_cache
                    .is_current_state_sender_projection(&self.verifier, projection)
                    .map_err(|error| application_error("state query", error))?;
                if current {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state query",
                    ));
                }
                return Ok((None, policy_active, false));
            }
        };
        if route.envelope_id() != *stored.transfer_id.as_bytes()
            || route.item_id() != *stored.semantic_id.as_bytes()
            || route.header() != &stored.header
            || route.topic() != &query.topic
            || route.scope() != &query.scope
            || route.logical_key() != query.logical_key
            || route.ttl_ms().is_some()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }
        let revoked = self
            .store
            .is_control_principal_revoked(route.publisher())
            .map_err(|error| application_error("state query", error.into()))?;
        let current_epoch = self
            .store
            .active_scope_epoch(route.scope())
            .map_err(|error| application_error("state query", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if route.key_epoch() > current_epoch {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }
        let policy_active = !revoked && route.key_epoch() == current_epoch;
        let active = policy_active
            && self.verifier.is_current_source_route_lineage(
                route.scope(),
                route.key_epoch(),
                route.route_lineage(),
            );
        if !self
            .verifier
            .can_route_state(route.scope(), route.key_epoch())
            || !self.verifier.can_open_state_content(
                route.scope(),
                route.topic(),
                route.key_epoch(),
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }
        let payload = match self
            .verifier
            .verify_state_content(route, &stored.sealed)
            .map_err(|error| application_error("state query", error.into()))?
        {
            StateContentVerification::ContentVerified { state, payload } => {
                state
                    .verify_exact_payload(&payload)
                    .map_err(|error| application_error("state query", error.into()))?;
                payload
            }
            StateContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state query",
                ));
            }
        };
        Ok((
            Some(StateItem {
                id: StateId::from_store(stored.semantic_id),
                publisher: stored.header.stamp.dot.publisher,
                publisher_counter: stored.header.stamp.dot.counter,
                topic: stored.header.topic.clone(),
                scope: stored.header.scope.clone(),
                priority: stored.header.priority,
                logical_key: stored.header.logical_key.clone(),
                payload,
                tombstone: stored.header.tombstone,
                acceptance_marker: stored.acceptance_marker,
                disposition: StateVersionDisposition::Superseded,
            }),
            policy_active,
            active,
        ))
    }

    fn current_policy(
        &mut self,
        operation: &'static str,
    ) -> Result<ControlPolicySnapshot, ApplicationError> {
        match refresh_application_policy(
            &self.store,
            &self.mission,
            &mut self.verifier,
            &mut self.verifier_head,
        ) {
            Ok(Some(policy)) => Ok(policy),
            Ok(None) => Err(ApplicationError::new(
                ApplicationErrorKind::PolicyUnsettled,
                operation,
            )),
            Err(error) => Err(application_error(operation, error)),
        }
    }
}

impl StateVersionDisposition {
    const fn into_store(self) -> StoreStateDisposition {
        match self {
            Self::Current => StoreStateDisposition::Current,
            Self::Concurrent => StoreStateDisposition::Concurrent,
            Self::Superseded => StoreStateDisposition::Superseded,
        }
    }
}

fn recompute_state_dispositions(
    candidates: &[(StateId, &CausalStamp, bool)],
) -> (Option<usize>, Vec<Option<StateVersionDisposition>>) {
    let mut maximal = candidates
        .iter()
        .map(|(_, _, active)| *active)
        .collect::<Vec<_>>();
    for index in 0..candidates.len() {
        if !candidates[index].2 {
            continue;
        }
        for other in 0..candidates.len() {
            if index != other
                && candidates[other].2
                && candidates[other]
                    .1
                    .context
                    .observes(candidates[index].1.dot)
            {
                maximal[index] = false;
                break;
            }
        }
    }
    let current = maximal
        .iter()
        .enumerate()
        .filter(|(_, maximal)| **maximal)
        .max_by_key(|(index, _)| candidates[*index].0)
        .map(|(index, _)| index);
    let dispositions = candidates
        .iter()
        .enumerate()
        .map(|(index, (_, _, active))| {
            if !active {
                None
            } else if Some(index) == current {
                Some(StateVersionDisposition::Current)
            } else if maximal[index] {
                Some(StateVersionDisposition::Concurrent)
            } else {
                Some(StateVersionDisposition::Superseded)
            }
        })
        .collect();
    (current, dispositions)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
    };

    use aster_mesh::{
        Dot, ProvisioningAccess, ReferenceProvisioner, ScopeRekeyRecipient, VersionVector,
    };

    use super::*;
    use crate::application::{EventQuery, SelectedEventNode};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn live_handle_and_actor_rejection_fail_closed() {
        let (commands, _receiver) = mpsc::channel(1);
        let identity = [0x31; 32];
        let mission_authority = [0x32; 32];
        let handle = SelectedStateHandle::new(
            commands,
            Arc::new(AtomicBool::new(false)),
            identity,
            mission_authority,
        );
        let cloned = handle.clone();
        assert_eq!(cloned.identity(), identity);
        assert_eq!(cloned.mission_authority(), mission_authority);

        let query = StateQuery {
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            logical_key: b"closed".to_vec(),
            include_recoverable_versions: false,
        };
        let closed = handle.query(query.clone()).await.expect_err("closed actor");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state query");

        let publish = StatePublishRequest {
            operation_key: b"closed-publish".to_vec(),
            topic: query.topic.clone(),
            scope: query.scope.clone(),
            priority: Priority::Priority,
            logical_key: query.logical_key.clone(),
            payload: b"closed payload".to_vec(),
            tombstone: false,
        };
        let closed = handle
            .publish(publish.clone())
            .await
            .expect_err("closed actor publication");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state publish");

        let subscription_request = StateSubscriptionRequest {
            operation_key: b"closed-subscription".to_vec(),
            topic: query.topic.clone(),
            scope: query.scope.clone(),
            include_descendant_scopes: false,
        };
        let closed = handle
            .subscribe(subscription_request.clone())
            .await
            .expect_err("closed actor subscription");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state subscribe");
        let subscription = StateSubscriptionId::from_bytes([0x33; 32]);
        let closed = handle
            .poll(StatePollRequest {
                subscription,
                delivery_limit: 1,
                scan_limit: 1,
            })
            .await
            .expect_err("closed actor poll");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state poll");
        let closed = handle
            .acknowledge(
                subscription,
                StateId::from_bytes([0x34; 32]),
                StateDeliveryToken::inert_for_command_rejection(),
            )
            .await
            .expect_err("closed actor acknowledgement");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state acknowledge");
        let closed = handle
            .unsubscribe(subscription)
            .await
            .expect_err("closed actor unsubscribe");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state unsubscribe");
        let closed = handle
            .delivery_status()
            .await
            .expect_err("closed actor delivery status");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "state delivery status");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::Publish {
            request: publish,
            response,
        }
        .reject();
        let rejected = received
            .await
            .expect("actor publication rejection response")
            .expect_err("rejected publication command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state publish");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::Query { query, response }.reject();
        let rejected = received
            .await
            .expect("actor rejection response")
            .expect_err("rejected command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state query");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::Subscribe {
            request: subscription_request,
            response,
        }
        .reject();
        let rejected = received
            .await
            .expect("actor subscription rejection response")
            .expect_err("rejected subscription command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state subscribe");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::Poll {
            request: StatePollRequest {
                subscription,
                delivery_limit: 1,
                scan_limit: 1,
            },
            response,
        }
        .reject();
        let rejected = received
            .await
            .expect("actor poll rejection response")
            .expect_err("rejected poll command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state poll");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::Acknowledge {
            subscription,
            state: StateId::from_bytes([0x35; 32]),
            token: StateDeliveryToken::inert_for_command_rejection(),
            response,
        }
        .reject();
        let rejected = received
            .await
            .expect("actor acknowledgement rejection response")
            .expect_err("rejected acknowledgement command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state acknowledge");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::Unsubscribe {
            subscription,
            response,
        }
        .reject();
        let rejected = received
            .await
            .expect("actor unsubscribe rejection response")
            .expect_err("rejected unsubscribe command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state unsubscribe");

        let (response, received) = oneshot::channel();
        SelectedStateCommand::DeliveryStatus { response }.reject();
        let rejected = received
            .await
            .expect("actor delivery-status rejection response")
            .expect_err("rejected delivery-status command");
        assert_eq!(rejected.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(rejected.operation(), "state delivery status");
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-state-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn mission_path(&self) -> PathBuf {
            self.path().join("mission.unprotected-reference.bundle")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn persist_mission(root: &TestRoot) {
        let scope = Scope::new("mission/apps").expect("scope");
        let state = Topic::new("ops.state").expect("topic");
        let events = Topic::new("ops.events").expect("topic");
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![state, events]).expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x73; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue node")
            .to_bytes()
            .expect("encode mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist mission"),
        );
    }

    struct StateRekeyServices {
        control_authority: ReferenceEnvelopeSealer,
        registry: Vec<u8>,
        authority: NodeId,
        selected_identity: NodeId,
    }

    fn persist_rekeyable_mission(root: &TestRoot) -> StateRekeyServices {
        let scope = Scope::new("mission/apps").expect("scope");
        let state = Topic::new("ops.state").expect("topic");
        let events = Topic::new("ops.events").expect("topic");
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![state, events]).expect("member access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x74; 32]).expect("rekey provisioner");
        let control_authority = provisioner
            .issue_control_authority(60, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control authority");
        let selected_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .expect("issue selected node")
            .to_bytes()
            .expect("encode selected mission");
        let selected_mission = UnprotectedReferenceMission::from_bytes(selected_bytes.clone())
            .expect("parse selected mission");
        let selected_identity = ReferenceEnvelopeSealer::open(
            selected_mission
                .fresh_bundle()
                .expect("fresh selected bundle"),
        )
        .expect("inspect selected identity")
        .identity();
        let registry = provisioner.export_rekey_registry().expect("rekey registry");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), selected_bytes)
                .expect("persist rekeyable mission"),
        );
        StateRekeyServices {
            authority: control_authority.mission_authority_id(),
            control_authority,
            registry,
            selected_identity,
        }
    }

    fn apply_same_epoch_rekey(root: &TestRoot, services: &mut StateRekeyServices) {
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.control_authority.identity(),
                vec![Topic::new("ops.state").expect("State topic")],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(
                services.selected_identity,
                vec![Topic::new("ops.state").expect("State topic")],
            )
            .expect("selected recipient"),
        ];
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                Scope::new("mission/apps").expect("scope"),
                1,
                recipients,
                1,
                None,
            )
            .expect("seal same-epoch rekey");
        let verified = services
            .control_authority
            .verify_control(&sealed)
            .expect("verify same-epoch rekey");
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("open store for rekey");
        let outcome = store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit same-epoch rekey");
        assert_eq!(outcome.activated().len(), 1);
        assert_eq!(
            store
                .active_scope_epoch(&Scope::new("mission/apps").expect("scope"))
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(1)
        );
    }

    fn selected_node(root: &TestRoot) -> SelectedStateNode {
        if !root.mission_path().exists() {
            persist_mission(root);
        }
        SelectedStateNode::open_unprotected_reference(root.path(), root.mission_path())
            .expect("open selected State node")
    }

    fn request(operation: &[u8], payload: &[u8]) -> StatePublishRequest {
        StatePublishRequest {
            operation_key: operation.to_vec(),
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            priority: Priority::Priority,
            logical_key: b"asset-7".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn query(recoverable: bool) -> StateQuery {
        StateQuery {
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            logical_key: b"asset-7".to_vec(),
            include_recoverable_versions: recoverable,
        }
    }

    fn payload_for_exact_sealed_size(node: &mut SelectedStateNode, target: usize) -> Vec<u8> {
        let template = request(b"state/size-probe", b"");
        let policy = node.current_policy("state size probe").expect("policy");
        let epoch = node
            .store
            .active_scope_epoch(&template.scope)
            .expect("active epoch")
            .map_or(1, |(epoch, _)| epoch);
        let reservation = node
            .store
            .reserve_state_with_policy(&policy, node.identity(), &template.topic, &template.scope)
            .expect("State size-probe reservation");
        let probe_header = reservation
            .header(
                template.priority,
                template.logical_key.clone(),
                0,
                false,
                epoch,
            )
            .expect("State size-probe header");
        let probe = node
            .verifier
            .seal_state(&probe_header, b"")
            .expect("seal State size probe");
        let payload_len = target
            .checked_sub(probe.bytes.len())
            .expect("target exceeds State envelope overhead");
        let payload = vec![0x5a; payload_len];
        let header = reservation
            .header(
                template.priority,
                template.logical_key,
                u64::try_from(payload.len()).expect("payload length"),
                false,
                epoch,
            )
            .expect("State boundary header");
        let sealed = node
            .verifier
            .seal_state(&header, &payload)
            .expect("seal State boundary payload");
        assert_eq!(sealed.bytes.len(), target);
        payload
    }

    #[test]
    fn state_reducer_uses_explicit_observation_and_id_tie_without_delete_wins() {
        let first_dot = Dot {
            publisher: [0x11; 32],
            counter: 1,
        };
        let concurrent_dot = Dot {
            publisher: [0x22; 32],
            counter: 1,
        };
        let first = CausalStamp {
            dot: first_dot,
            context: VersionVector::default(),
        };
        let concurrent = CausalStamp {
            dot: concurrent_dot,
            context: VersionVector::default(),
        };
        let low = StateId::from_bytes([0x10; 32]);
        let high = StateId::from_bytes([0x20; 32]);

        // Tombstone is intentionally not an input to this reducer: concurrent
        // edit/delete heads use the same complete semantic-ID tie break.
        let (current, dispositions) =
            recompute_state_dispositions(&[(low, &first, true), (high, &concurrent, true)]);
        assert_eq!(current, Some(1));
        assert_eq!(
            dispositions,
            vec![
                Some(StateVersionDisposition::Concurrent),
                Some(StateVersionDisposition::Current),
            ]
        );
        let (current, dispositions) =
            recompute_state_dispositions(&[(high, &concurrent, true), (low, &first, true)]);
        assert_eq!(current, Some(0));
        assert_eq!(
            dispositions,
            vec![
                Some(StateVersionDisposition::Current),
                Some(StateVersionDisposition::Concurrent),
            ]
        );

        let mut successor_context = VersionVector::default();
        successor_context.observe(first_dot);
        let successor = CausalStamp {
            dot: Dot {
                publisher: first_dot.publisher,
                counter: 2,
            },
            context: successor_context,
        };
        let (current, dispositions) =
            recompute_state_dispositions(&[(high, &first, true), (low, &successor, true)]);
        assert_eq!(current, Some(1));
        assert_eq!(
            dispositions,
            vec![
                Some(StateVersionDisposition::Superseded),
                Some(StateVersionDisposition::Current),
            ]
        );

        let (current, dispositions) =
            recompute_state_dispositions(&[(high, &concurrent, false), (low, &first, true)]);
        assert_eq!(current, Some(1));
        assert_eq!(
            dispositions,
            vec![None, Some(StateVersionDisposition::Current)]
        );

        // A later branch can supersede the deterministic concurrent winner
        // without observing the other maximum. The earlier semantic version
        // then becomes Current again even though the retained history grows
        // monotonically: A -> B -> A is a valid projection sequence.
        let a_id = StateId::from_bytes([0x20; 32]);
        let b_id = StateId::from_bytes([0x30; 32]);
        let c_id = StateId::from_bytes([0x10; 32]);
        let a = CausalStamp {
            dot: Dot {
                publisher: [0x41; 32],
                counter: 1,
            },
            context: VersionVector::default(),
        };
        let b = CausalStamp {
            dot: Dot {
                publisher: [0x42; 32],
                counter: 1,
            },
            context: VersionVector::default(),
        };
        let mut c_context = VersionVector::default();
        c_context.observe(b.dot);
        let c = CausalStamp {
            dot: Dot {
                publisher: b.dot.publisher,
                counter: 2,
            },
            context: c_context,
        };
        let (winner, before_branch) =
            recompute_state_dispositions(&[(a_id, &a, true), (b_id, &b, true)]);
        assert_eq!(winner, Some(1));
        assert_eq!(
            before_branch,
            vec![
                Some(StateVersionDisposition::Concurrent),
                Some(StateVersionDisposition::Current),
            ]
        );
        let (returned, after_branch) =
            recompute_state_dispositions(&[(a_id, &a, true), (b_id, &b, true), (c_id, &c, true)]);
        assert_eq!(returned, Some(0));
        assert_eq!(
            after_branch,
            vec![
                Some(StateVersionDisposition::Current),
                Some(StateVersionDisposition::Superseded),
                Some(StateVersionDisposition::Concurrent),
            ]
        );
    }

    #[test]
    fn state_projection_is_causal_idempotent_and_restart_stable() {
        let root = TestRoot::new("projection");
        let (first, second) = {
            let mut node = selected_node(&root);
            let first_request = request(b"state/first", b"ready");
            let first = node.publish(first_request.clone()).expect("first State");
            assert!(first.inserted);
            assert_eq!(first.publisher_counter, 1);
            let first_projection = node.query(query(true)).expect("first projection");
            assert_eq!(
                first_projection.current.as_ref().map(|item| item.id),
                Some(first.id)
            );
            assert!(first_projection.recoverable.is_empty());

            let second = node
                .publish(request(b"state/second", b"moving"))
                .expect("second State");
            assert!(second.inserted);
            assert_eq!(second.publisher_counter, 2);
            let projection = node.query(query(true)).expect("causal projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(second.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(b"moving".as_slice())
            );
            assert_eq!(projection.recoverable.len(), 1);
            assert_eq!(projection.recoverable[0].id, first.id);
            assert_eq!(
                projection.recoverable[0].disposition,
                StateVersionDisposition::Superseded
            );

            let replay = node.publish(first_request).expect("idempotent replay");
            assert!(!replay.inserted);
            assert_eq!(replay.id, first.id);
            assert_eq!(replay.publisher_counter, first.publisher_counter);
            assert_eq!(replay.acceptance_marker, first.acceptance_marker);
            let conflict = node
                .publish(request(b"state/first", b"different"))
                .expect_err("changed operation intent");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            (first, second)
        };

        let mut reopened = selected_node(&root);
        let projection = reopened.query(query(true)).expect("reopen projection");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(second.id)
        );
        assert_eq!(projection.recoverable.len(), 1);
        assert_eq!(projection.recoverable[0].id, first.id);
    }

    #[test]
    fn state_delivery_status_tracks_durable_ledger_across_reopen() {
        let root = TestRoot::new("delivery-status");
        let subscription_request = StateSubscriptionRequest {
            operation_key: b"subscriptions/state/status".to_vec(),
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            include_descendant_scopes: false,
        };

        let (subscription, state, token) = {
            let mut node = selected_node(&root);
            assert_eq!(
                node.delivery_status().expect("empty State delivery status"),
                StateDeliveryStatus::default()
            );
            let state = node
                .publish(request(b"state/status", b"ready"))
                .expect("publish State");
            let subscription = node
                .subscribe(subscription_request.clone())
                .expect("create State subscription");
            let replay = node
                .subscribe(subscription_request)
                .expect("replay State subscription");
            assert_eq!(replay.id, subscription.id);
            assert!(!replay.inserted);
            assert_eq!(
                node.delivery_status().expect("subscribed State status"),
                StateDeliveryStatus {
                    subscriptions: 1,
                    pending_deliveries: 0,
                    acknowledged_deliveries: 0,
                    delivery_cursors: 0,
                    selector_generation: 1,
                }
            );
            let page = node
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: 1,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("poll State");
            let delivery = page.deliveries.into_iter().next().expect("delivery");
            assert_eq!(delivery.state.id, state.id);
            assert_eq!(
                node.delivery_status().expect("pending State status"),
                StateDeliveryStatus {
                    subscriptions: 1,
                    pending_deliveries: 1,
                    acknowledged_deliveries: 0,
                    delivery_cursors: 1,
                    selector_generation: 1,
                }
            );
            (subscription, state, delivery.token)
        };

        let mut reopened = selected_node(&root);
        assert_eq!(
            reopened.delivery_status().expect("reopened State status"),
            StateDeliveryStatus {
                subscriptions: 1,
                pending_deliveries: 1,
                acknowledged_deliveries: 0,
                delivery_cursors: 1,
                selector_generation: 1,
            }
        );
        assert_eq!(
            reopened
                .acknowledge(subscription.id, state.id, token)
                .expect("acknowledge State"),
            StateAcknowledgement::Acknowledged
        );
        assert_eq!(
            reopened
                .delivery_status()
                .expect("acknowledged State status"),
            StateDeliveryStatus {
                subscriptions: 1,
                pending_deliveries: 0,
                acknowledged_deliveries: 1,
                delivery_cursors: 1,
                selector_generation: 1,
            }
        );
    }

    #[test]
    fn state_subscription_reduces_redelivers_acknowledges_and_reopens() {
        let root = TestRoot::new("subscription");
        let subscription_request = StateSubscriptionRequest {
            operation_key: b"subscriptions/state/asset".to_vec(),
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            include_descendant_scopes: false,
        };
        let (subscription, current, first_current_token) = {
            let mut node = selected_node(&root);
            let first = node
                .publish(request(b"state/subscription/first", b"ready"))
                .expect("first State");
            let subscription = node
                .subscribe(subscription_request.clone())
                .expect("create State subscription");
            assert!(subscription.inserted);
            let replay = node
                .subscribe(subscription_request.clone())
                .expect("replay State subscription");
            assert_eq!(replay.id, subscription.id);
            assert!(!replay.inserted);

            let first_page = node
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("first State poll");
            assert_eq!(first_page.deliveries.len(), 1);
            assert_eq!(first_page.deliveries[0].state.id, first.id);
            assert_eq!(first_page.deliveries[0].attempt, 1);
            assert_eq!(
                first_page.deliveries[0].state.disposition,
                StateVersionDisposition::Current
            );
            let first_token = first_page.deliveries[0].token;

            let current = node
                .publish(request(b"state/subscription/current", b"moving"))
                .expect("superseding State");
            let replacement = node
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("replacement State poll");
            assert_eq!(replacement.deliveries.len(), 1);
            assert_eq!(replacement.deliveries[0].state.id, current.id);
            assert_eq!(replacement.deliveries[0].attempt, 1);
            assert_ne!(replacement.deliveries[0].state.id, first.id);
            let swapped = node
                .acknowledge(subscription.id, current.id, first_token)
                .expect_err("a token cannot acknowledge a different State");
            assert_eq!(swapped.kind(), ApplicationErrorKind::InvalidRequest);
            assert_eq!(swapped.operation(), "state acknowledge");
            let stale = node
                .acknowledge(subscription.id, first.id, first_token)
                .expect_err("an unacknowledged retired tenure token is stale");
            assert_eq!(stale.kind(), ApplicationErrorKind::InvalidRequest);
            assert_eq!(stale.operation(), "state acknowledge");
            (subscription, current, replacement.deliveries[0].token)
        };

        let mut reopened = selected_node(&root);
        let repeated = reopened
            .poll(StatePollRequest {
                subscription: subscription.id,
                delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
            })
            .expect("repeat unacknowledged current State");
        assert_eq!(repeated.deliveries.len(), 1);
        assert_eq!(repeated.deliveries[0].state.id, current.id);
        assert_eq!(repeated.deliveries[0].attempt, 2);
        assert_ne!(repeated.deliveries[0].token, first_current_token);
        let repeated_token = repeated.deliveries[0].token;
        assert_eq!(
            StateDeliveryToken::from_bytes(*repeated_token.as_bytes())
                .expect("restore opaque State delivery token"),
            repeated_token
        );
        let malformed = StateDeliveryToken::from_bytes([0_u8; STATE_DELIVERY_TOKEN_BYTES])
            .expect_err("reject malformed State delivery token");
        assert_eq!(malformed.kind(), ApplicationErrorKind::InvalidRequest);
        assert_eq!(malformed.operation(), "state delivery token");
        assert_eq!(
            reopened
                .acknowledge(subscription.id, current.id, repeated_token)
                .expect("acknowledge current State"),
            StateAcknowledgement::Acknowledged
        );
        assert_eq!(
            reopened
                .acknowledge(subscription.id, current.id, repeated_token)
                .expect("idempotent State acknowledgement"),
            StateAcknowledgement::AlreadyAcknowledged
        );
        assert!(
            reopened
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("empty after State acknowledgement")
                .deliveries
                .is_empty()
        );

        let mut deletion = request(b"state/subscription/delete", b"");
        deletion.tombstone = true;
        let tombstone = reopened.publish(deletion).expect("State tombstone");
        let deletion = reopened
            .poll(StatePollRequest {
                subscription: subscription.id,
                delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
            })
            .expect("tombstone delivery");
        assert_eq!(deletion.deliveries.len(), 1);
        assert_eq!(deletion.deliveries[0].state.id, tombstone.id);
        assert!(deletion.deliveries[0].state.tombstone);
        assert!(deletion.deliveries[0].state.payload.is_empty());
        assert_eq!(deletion.deliveries[0].attempt, 1);
        let removed_incarnation_token = deletion.deliveries[0].token;

        assert_eq!(
            reopened
                .unsubscribe(subscription.id)
                .expect("remove State subscription"),
            StateUnsubscribe::Removed
        );
        assert_eq!(
            reopened
                .unsubscribe(subscription.id)
                .expect("idempotent remove State subscription"),
            StateUnsubscribe::AlreadyAbsent
        );
        let recreated = reopened
            .subscribe(subscription_request)
            .expect("recreate removed State subscription");
        assert!(recreated.inserted);
        assert_eq!(recreated.id, subscription.id);
        let redelivered = reopened
            .poll(StatePollRequest {
                subscription: recreated.id,
                delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
            })
            .expect("recreated subscription starts a fresh ledger");
        assert_eq!(redelivered.deliveries.len(), 1);
        assert_eq!(redelivered.deliveries[0].state.id, tombstone.id);
        assert_eq!(redelivered.deliveries[0].attempt, 1);
        assert_ne!(redelivered.deliveries[0].token, removed_incarnation_token);
        let recreated_token = redelivered.deliveries[0].token;
        let stale = reopened
            .acknowledge(recreated.id, tombstone.id, removed_incarnation_token)
            .expect_err("removed subscription incarnation token is stale");
        assert_eq!(stale.kind(), ApplicationErrorKind::InvalidRequest);
        assert_eq!(stale.operation(), "state acknowledge");
        let retried = reopened
            .poll(StatePollRequest {
                subscription: recreated.id,
                delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
            })
            .expect("stale token leaves recreated delivery pending");
        assert_eq!(retried.deliveries.len(), 1);
        assert_eq!(retried.deliveries[0].state.id, tombstone.id);
        assert_eq!(retried.deliveries[0].attempt, 2);
        assert_ne!(retried.deliveries[0].token, recreated_token);
        assert_eq!(
            reopened
                .acknowledge(recreated.id, tombstone.id, recreated_token)
                .expect("an earlier retry token in the current tenure remains valid"),
            StateAcknowledgement::Acknowledged
        );
        assert_eq!(
            reopened
                .acknowledge(recreated.id, tombstone.id, recreated_token)
                .expect("recreated delivery acknowledgement is idempotent"),
            StateAcknowledgement::AlreadyAcknowledged
        );
    }

    #[test]
    fn state_subscription_rejects_conflicts_bounds_and_unauthorized_intent() {
        let root = TestRoot::new("subscription-errors");
        let mut node = selected_node(&root);
        let request = StateSubscriptionRequest {
            operation_key: b"subscriptions/state/errors".to_vec(),
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            include_descendant_scopes: false,
        };
        let subscription = node.subscribe(request.clone()).expect("subscription");

        let mut conflict = request;
        conflict.include_descendant_scopes = true;
        let error = node
            .subscribe(conflict)
            .expect_err("changed State selector operation");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert_eq!(error.operation(), "state subscribe");

        for invalid in [
            StatePollRequest {
                subscription: subscription.id,
                delivery_limit: 0,
                scan_limit: 1,
            },
            StatePollRequest {
                subscription: subscription.id,
                delivery_limit: MAX_SELECTED_STATE_DELIVERIES + 1,
                scan_limit: 1,
            },
            StatePollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 0,
            },
            StatePollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN + 1,
            },
        ] {
            let error = node.poll(invalid).expect_err("invalid State poll bound");
            assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
            assert_eq!(error.operation(), "state poll");
        }

        let unauthorized = node
            .subscribe(StateSubscriptionRequest {
                operation_key: b"subscriptions/state/unauthorized".to_vec(),
                topic: Topic::new("private.state").expect("topic"),
                scope: Scope::new("mission/apps").expect("scope"),
                include_descendant_scopes: false,
            })
            .expect_err("unauthorized State subscription");
        assert_eq!(unauthorized.kind(), ApplicationErrorKind::RequestRejected);
        assert_eq!(unauthorized.operation(), "state subscribe");
    }

    #[test]
    fn same_epoch_rekey_withholds_old_state_and_replacement_is_restart_stable() {
        let root = TestRoot::new("same-epoch-lineage");
        let mut services = persist_rekeyable_mission(&root);
        let old_request = request(b"state/pre-rekey", b"old route");
        let (old, subscription, old_token) = {
            let mut node = selected_node(&root);
            let old = node
                .publish(old_request.clone())
                .expect("publish pre-rekey State");
            let subscription = node
                .subscribe(StateSubscriptionRequest {
                    operation_key: b"state/rekey/subscription".to_vec(),
                    topic: old_request.topic.clone(),
                    scope: old_request.scope.clone(),
                    include_descendant_scopes: false,
                })
                .expect("subscribe before same-epoch rekey");
            let page = node
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("deliver pre-rekey State");
            assert_eq!(page.deliveries.len(), 1);
            assert_eq!(page.deliveries[0].state.id, old.id);
            let token = page.deliveries[0].token;
            assert_eq!(
                node.acknowledge(subscription.id, old.id, token)
                    .expect("acknowledge pre-rekey State"),
                StateAcknowledgement::Acknowledged
            );
            (old, subscription, token)
        };

        apply_same_epoch_rekey(&root, &mut services);
        let replacement = {
            let mut reopened = selected_node(&root);
            let hidden = reopened
                .query(query(true))
                .expect("cache-proven old State is safely withheld");
            assert!(hidden.current.is_none());
            assert!(hidden.recoverable.is_empty());
            let empty = reopened
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("authorization loss has no synthetic withdrawal delivery");
            assert!(empty.deliveries.is_empty());
            assert!(!empty.has_more);
            assert_eq!(
                reopened
                    .acknowledge(subscription.id, old.id, old_token)
                    .expect("retired acknowledged tenure remains idempotent"),
                StateAcknowledgement::AlreadyAcknowledged
            );

            let replay = reopened
                .publish(old_request)
                .expect("exact State retry survives same-epoch rekey");
            assert!(!replay.inserted);
            assert_eq!(replay.id, old.id);
            assert_eq!(replay.publisher_counter, old.publisher_counter);
            assert_eq!(replay.acceptance_marker, old.acceptance_marker);

            let replacement = reopened
                .publish(request(b"state/post-rekey", b"current route"))
                .expect("publish post-rekey State");
            assert_ne!(replacement.id, old.id);
            let projection = reopened.query(query(true)).expect("current projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(replacement.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(b"current route".as_slice())
            );
            assert!(projection.recoverable.is_empty());
            let replacement_page = reopened
                .poll(StatePollRequest {
                    subscription: subscription.id,
                    delivery_limit: MAX_SELECTED_STATE_DELIVERIES,
                    scan_limit: MAX_SELECTED_STATE_SUBSCRIPTION_SCAN,
                })
                .expect("deliver authorized post-rekey State");
            assert_eq!(replacement_page.deliveries.len(), 1);
            assert_eq!(replacement_page.deliveries[0].state.id, replacement.id);
            assert_ne!(replacement_page.deliveries[0].token, old_token);
            assert_eq!(
                reopened
                    .acknowledge(
                        subscription.id,
                        replacement.id,
                        replacement_page.deliveries[0].token,
                    )
                    .expect("acknowledge post-rekey State"),
                StateAcknowledgement::Acknowledged
            );
            replacement
        };

        let mut restarted = selected_node(&root);
        let projection = restarted
            .query(query(true))
            .expect("restart-stable lineage filtering");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(replacement.id)
        );
        assert!(projection.recoverable.is_empty());
    }

    #[test]
    fn state_sealed_wire_boundary_is_inclusive_and_oversize_is_restart_atomic() {
        let root = TestRoot::new("sealed-wire-boundary");
        let exact;
        let exact_payload;
        {
            let mut node = selected_node(&root);
            let payload_over_wire = vec![0x41; MAX_OBJECT_BYTES + 1];
            let error = node
                .publish(request(
                    b"state/payload-over-wire-limit",
                    &payload_over_wire,
                ))
                .expect_err("payload larger than the wire object bound");
            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);

            exact_payload = payload_for_exact_sealed_size(&mut node, MAX_OBJECT_BYTES);
            exact = node
                .publish(request(b"state/exact-wire-limit", &exact_payload))
                .expect("exact-bound State");
            assert!(exact.inserted);
            assert_eq!(exact.publisher_counter, 1);

            let oversized = payload_for_exact_sealed_size(&mut node, MAX_OBJECT_BYTES + 1);
            let error = node
                .publish(request(b"state/oversized-wire-limit", &oversized))
                .expect_err("oversized sealed State");
            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
            assert_eq!(error.operation(), "state publish");
            assert_eq!(
                error.to_string(),
                "selected application state publish failed: selected data resource limit reached"
            );

            let projection = node.query(query(true)).expect("unchanged projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(exact.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(exact_payload.as_slice())
            );
            assert!(projection.recoverable.is_empty());
        }

        let mut reopened = selected_node(&root);
        let projection = reopened.query(query(true)).expect("reopened projection");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(exact.id)
        );
        assert_eq!(
            projection
                .current
                .as_ref()
                .map(|item| item.payload.as_slice()),
            Some(exact_payload.as_slice())
        );
        assert!(projection.recoverable.is_empty());

        let replacement = reopened
            .publish(request(b"state/oversized-wire-limit", b"small replacement"))
            .expect("rejected operation key remains unbound");
        assert!(replacement.inserted);
        assert_eq!(replacement.publisher_counter, 2);
        let preflight_replacement = reopened
            .publish(request(
                b"state/payload-over-wire-limit",
                b"small preflight replacement",
            ))
            .expect("preflight-rejected operation key remains unbound");
        assert!(preflight_replacement.inserted);
        assert_eq!(preflight_replacement.publisher_counter, 3);
    }

    #[test]
    fn authenticated_tombstone_remains_visible_as_the_current_state() {
        let root = TestRoot::new("tombstone");
        let mut node = selected_node(&root);
        let live = node
            .publish(request(b"state/live", b"ready"))
            .expect("live State");
        let mut deletion = request(b"state/delete", b"");
        deletion.tombstone = true;
        let tombstone = node.publish(deletion).expect("State tombstone");
        let projection = node.query(query(true)).expect("tombstone projection");
        let current = projection.current.expect("visible current tombstone");
        assert_eq!(current.id, tombstone.id);
        assert!(current.tombstone);
        assert!(current.payload.is_empty());
        assert_eq!(projection.recoverable.len(), 1);
        assert_eq!(projection.recoverable[0].id, live.id);

        let mut invalid = request(b"state/invalid-delete", b"not-empty");
        invalid.tombstone = true;
        let error = node.publish(invalid).expect_err("nonempty tombstone");
        assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
    }

    #[test]
    fn event_and_state_share_publisher_counters_but_not_event_positions() {
        let root = TestRoot::new("shared-ledger");
        persist_mission(&root);
        use crate::publication_journal::{Intent, Journal};
        let path = root.path().join("event-publication.redb");
        Journal::initialize(&path, b"interleaved-event-fixture").unwrap();
        let event_request = |payload: &[u8]| Intent {
            predecessor: None,
            topic: "ops.events".to_owned(),
            scope: "mission/apps".to_owned(),
            priority: Priority::Routine as u8,
            logical_key: b"asset-7".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
            ttl_ms: None,
        };
        let first_event = {
            let mut events =
                SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open Event node");
            let mut journal = Journal::open(&path, b"interleaved-event-fixture").unwrap();
            journal.recover_stopped(&mut events).unwrap();
            let result = journal
                .publish_metadata_stopped(&mut events, event_request(b"first"))
                .unwrap();
            journal.acknowledge_stopped(&mut events).unwrap();
            result
        };
        assert_eq!(first_event.publisher_counter, 1);
        assert_eq!(first_event.event_sequence, 1);

        let state = {
            let mut state = selected_node(&root);
            state
                .publish(request(b"state/interleaved", b"state"))
                .expect("interleaved State")
        };
        assert_eq!(state.publisher_counter, 2);

        let mut events =
            SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("reopen Event node");
        let mut journal = Journal::open(&path, b"interleaved-event-fixture").unwrap();
        journal.recover_stopped(&mut events).unwrap();
        let second_event = journal
            .publish_metadata_stopped(&mut events, event_request(b"second"))
            .unwrap();
        assert_eq!(second_event.publisher_counter, 3);
        assert_eq!(second_event.event_sequence, 2);
        let page = events.query(EventQuery::default()).expect("Event page");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.scanned_through, 2);
    }

    #[test]
    fn state_and_event_facades_share_the_exact_writer_exclusion() {
        let root = TestRoot::new("writer-exclusion");
        persist_mission(&root);
        let events =
            SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("open Event owner");
        let error =
            match SelectedStateNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("second writer must fail"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        drop(events);
        drop(selected_node(&root));
    }
}
