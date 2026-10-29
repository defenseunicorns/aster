//! Provider-neutral ownership of concurrent contacts over one durable node.
//!
//! Connectivity providers contribute bounded, nonblocking [`Link`] objects and
//! carrier metadata. They never receive provisioning bytes, durable paths, the
//! semantic authority, or a session factory. This owner creates every
//! [`ReferenceSemanticRuntimeSession`], keeps its [`RuntimeDriver`] beside the
//! corresponding node-resource lease, and completes host policy, resource, and
//! durable admission synchronously at the runtime's external-admission barrier.

use crate::node_admission::{AdmissionTransaction, transact_authenticated};
use crate::{
    AdmissionTransactionError, CandidateId, CandidateLocator, CandidateProvenance, CarrierIdentity,
    ContactDirection, ContactId, ContactPath, HostAction, HostEvent, HostSnapshot, MeshHost,
    MeshHostError, NodeResourceBudget, NodeResourceClaim, NodeResourceLease, NodeResourceSnapshot,
    ResourceBudgetError,
};
use aster_mesh::inventory::SparseInventory;
use aster_mesh::link::Link;
use aster_mesh::runtime::{
    AppliedAuthorizationControl, BlobRuntimeError, ReferenceSemanticRuntimeAuthority,
    ReferenceSemanticRuntimeSession, RuntimeAuthorizationGenerationCheck,
    RuntimeAuthorizationGenerationCounters, RuntimeDriver, RuntimeError, RuntimeLimits,
    SignedAuthorizationControl, StartRequest,
};
use aster_mesh::sync::{SyncConfig, SyncState};
use aster_mesh::{ItemId, NodeId, ProvisioningBundle, UnprotectedProvisioning};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

type SharedContactDriver = RuntimeDriver<ReferenceSemanticRuntimeSession>;

/// Fixed aggregate claims charged for each supervisor-owned lifecycle object.
///
/// Claims are base values. A connectivity-relay contact is additionally
/// charged one `relay_reservations` unit while it is pre-authenticated or
/// admitted. Candidate and pending-connection claims remain separate because
/// they can exist without a runtime session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactResourceClaims {
    candidate: NodeResourceClaim,
    pending_connection: NodeResourceClaim,
    pre_authentication: NodeResourceClaim,
    admitted: NodeResourceClaim,
}

impl ContactResourceClaims {
    pub fn new(
        candidate: NodeResourceClaim,
        pending_connection: NodeResourceClaim,
        pre_authentication: NodeResourceClaim,
        admitted: NodeResourceClaim,
    ) -> Result<Self, ContactSupervisorError> {
        require_lifecycle_claim(candidate, ClaimKind::Candidate)?;
        require_lifecycle_claim(pending_connection, ClaimKind::PendingConnection)?;
        require_lifecycle_claim(pre_authentication, ClaimKind::PreAuthentication)?;
        require_lifecycle_claim(admitted, ClaimKind::Admitted)?;
        Ok(Self {
            candidate,
            pending_connection,
            pre_authentication,
            admitted,
        })
    }

    pub fn candidate(self) -> NodeResourceClaim {
        self.candidate
    }

    pub fn pending_connection(self) -> NodeResourceClaim {
        self.pending_connection
    }

    pub fn pre_authentication(self) -> NodeResourceClaim {
        self.pre_authentication
    }

    pub fn admitted(self) -> NodeResourceClaim {
        self.admitted
    }

    fn validate_runtime_floors(
        self,
        runtime_limits: RuntimeLimits,
    ) -> Result<(), ContactSupervisorError> {
        let frame_metadata_floor = runtime_frame_metadata_floor(runtime_limits)?;
        validate_runtime_claim_floor(
            self.pre_authentication,
            runtime_limits,
            frame_metadata_floor,
            "pre-authentication frame claim is below the runtime metadata floor",
            "pre-authentication inbound-byte claim is below the runtime retention floor",
            "pre-authentication outbound-byte claim is below the runtime retention floor",
        )?;
        validate_runtime_claim_floor(
            self.admitted,
            runtime_limits,
            frame_metadata_floor,
            "admitted frame claim is below the runtime metadata floor",
            "admitted inbound-byte claim is below the runtime retention floor",
            "admitted outbound-byte claim is below the runtime retention floor",
        )?;
        Ok(())
    }

    fn pre_authentication_for(
        self,
        path: ContactPath,
    ) -> Result<NodeResourceClaim, ContactSupervisorError> {
        claim_for_path(self.pre_authentication, path)
    }

    fn admitted_for(self, path: ContactPath) -> Result<NodeResourceClaim, ContactSupervisorError> {
        claim_for_path(self.admitted, path)
    }
}

fn validate_runtime_claim_floor(
    claim: NodeResourceClaim,
    runtime_limits: RuntimeLimits,
    frame_metadata_floor: usize,
    frame_error: &'static str,
    inbound_error: &'static str,
    outbound_error: &'static str,
) -> Result<(), ContactSupervisorError> {
    if claim.frames < frame_metadata_floor {
        return Err(ContactSupervisorError::InvalidConfig(frame_error));
    }
    if claim.inbound_bytes < runtime_limits.retained_inbound_payload_bytes() {
        return Err(ContactSupervisorError::InvalidConfig(inbound_error));
    }
    if claim.outbound_bytes < runtime_limits.retained_outbound_payload_bytes() {
        return Err(ContactSupervisorError::InvalidConfig(outbound_error));
    }
    Ok(())
}

/// Retained frame-bearing metadata owned by one admitted runtime.
///
/// Reassembly and its authenticated carrier-route binding each retain one
/// entry per in-flight logical frame. Successful and failed transfer replay
/// caches each retain `max_completed_transfers` entries. Outbox, retry, and
/// handshake-retry entries are separate from the payload-byte reservations.
fn runtime_frame_metadata_floor(
    runtime_limits: RuntimeLimits,
) -> Result<usize, ContactSupervisorError> {
    runtime_limits
        .max_in_flight_logical_frames
        .checked_mul(2)
        .and_then(|floor| floor.checked_add(runtime_limits.max_pending_outbox))
        .and_then(|floor| floor.checked_add(runtime_limits.max_pending_retries))
        .and_then(|floor| {
            runtime_limits
                .max_completed_transfers
                .checked_mul(2)
                .and_then(|completed| floor.checked_add(completed))
        })
        .and_then(|floor| floor.checked_add(1))
        .ok_or(ContactSupervisorError::InvalidConfig(
            "runtime frame metadata reservation overflow",
        ))
}

#[derive(Clone, Copy)]
enum ClaimKind {
    Candidate,
    PendingConnection,
    PreAuthentication,
    Admitted,
}

fn require_lifecycle_claim(
    claim: NodeResourceClaim,
    kind: ClaimKind,
) -> Result<(), ContactSupervisorError> {
    let expected = match kind {
        ClaimKind::Candidate => (1, 0, 0, 0),
        ClaimKind::PendingConnection => (0, 1, 0, 0),
        ClaimKind::PreAuthentication => (0, 0, 1, 0),
        ClaimKind::Admitted => (0, 0, 0, 1),
    };
    if (
        claim.candidates,
        claim.pending_connections,
        claim.pre_authentication_contacts,
        claim.admitted_contacts,
    ) != expected
        || claim.relay_reservations != 0
    {
        return Err(ContactSupervisorError::InvalidConfig(
            "resource claim has incompatible lifecycle counters",
        ));
    }
    if matches!(kind, ClaimKind::PreAuthentication | ClaimKind::Admitted)
        && (claim.streams == 0
            || claim.tasks == 0
            || claim.frames == 0
            || claim.inbound_bytes == 0
            || claim.outbound_bytes == 0)
    {
        return Err(ContactSupervisorError::InvalidConfig(
            "contact claim must account stream, task, frame, and byte resources",
        ));
    }
    Ok(())
}

fn claim_for_path(
    mut claim: NodeResourceClaim,
    path: ContactPath,
) -> Result<NodeResourceClaim, ContactSupervisorError> {
    if path == ContactPath::ConnectivityRelay {
        claim.relay_reservations = claim.relay_reservations.checked_add(1).ok_or(
            ContactSupervisorError::InvalidConfig("relay reservation claim overflow"),
        )?;
    }
    Ok(claim)
}

/// Immutable per-contact runtime and admission policy.
#[derive(Clone, Debug)]
pub struct ContactSupervisorConfig {
    sync: SyncConfig,
    runtime_limits: RuntimeLimits,
    start_template: StartRequest,
    pending_connection_timeout: Duration,
    pre_authentication_timeout: Duration,
    resources: ContactResourceClaims,
    allowed_peers: Option<BTreeSet<NodeId>>,
}

impl ContactSupervisorConfig {
    pub fn new(
        sync: SyncConfig,
        runtime_limits: RuntimeLimits,
        start_template: StartRequest,
        pre_authentication_timeout: Duration,
        resources: ContactResourceClaims,
    ) -> Result<Self, ContactSupervisorError> {
        sync.validate()
            .map_err(|_| ContactSupervisorError::InvalidConfig("invalid synchronization limits"))?;
        runtime_limits
            .validate()
            .map_err(|_| ContactSupervisorError::InvalidConfig("invalid contact runtime limits"))?;
        resources.validate_runtime_floors(runtime_limits)?;
        if start_template.topics.is_empty() || start_template.scopes.is_empty() {
            return Err(ContactSupervisorError::InvalidConfig(
                "contact interest requires a topic and scope",
            ));
        }
        if pre_authentication_timeout.is_zero() {
            return Err(ContactSupervisorError::InvalidConfig(
                "pre-authentication timeout must be nonzero",
            ));
        }
        Ok(Self {
            sync,
            runtime_limits,
            start_template,
            pending_connection_timeout: pre_authentication_timeout,
            pre_authentication_timeout,
            resources,
            allowed_peers: None,
        })
    }

    /// Sets the hard lifetime of a reserved outbound dial. A provider must
    /// either open or explicitly settle the connection before this deadline;
    /// otherwise the supervisor releases both Host and aggregate capacity.
    pub fn with_pending_connection_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, ContactSupervisorError> {
        if timeout.is_zero() {
            return Err(ContactSupervisorError::InvalidConfig(
                "pending-connection timeout must be nonzero",
            ));
        }
        self.pending_connection_timeout = timeout;
        Ok(self)
    }

    pub fn pending_connection_timeout(&self) -> Duration {
        self.pending_connection_timeout
    }

    /// Restricts durable admission to these cryptographically authenticated
    /// Aster identities. The check runs before Host preparation, aggregate
    /// lease upgrade, or durable authorization.
    pub fn with_allowed_peers(
        mut self,
        allowed_peers: BTreeSet<NodeId>,
    ) -> Result<Self, ContactSupervisorError> {
        if allowed_peers.is_empty() {
            return Err(ContactSupervisorError::InvalidConfig(
                "an explicit peer allowlist must be nonempty",
            ));
        }
        self.allowed_peers = Some(allowed_peers);
        Ok(self)
    }

    pub fn pre_authentication_timeout(&self) -> Duration {
        self.pre_authentication_timeout
    }

    pub fn resources(&self) -> ContactResourceClaims {
        self.resources
    }

    pub fn runtime_limits(&self) -> RuntimeLimits {
        self.runtime_limits
    }

    pub fn allowed_peers(&self) -> Option<&BTreeSet<NodeId>> {
        self.allowed_peers.as_ref()
    }
}

/// Aster handshake role selected from provider-owned simultaneous-open state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactSessionRole {
    Initiator { peer_hint: Option<NodeId> },
    Responder { peer_hint: Option<NodeId> },
}

/// Provider-supplied metadata for one already-open carrier stream.
///
/// The absence of durable paths, credentials, an authority, and a session
/// factory is intentional. The supervisor owns all four.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactOpening {
    pub contact: ContactId,
    pub candidate: CandidateId,
    pub locator: CandidateLocator,
    pub carrier_identity: Option<CarrierIdentity>,
    pub direction: ContactDirection,
    pub path: ContactPath,
    pub role: ContactSessionRole,
}

/// Result of offering an already-open carrier to the supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactOpenReport {
    pub opened: bool,
    pub actions: Vec<HostAction>,
}

/// Result of one nonblocking drive of one contact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactDriveReport {
    pub contact: ContactId,
    pub authenticated_peer: Option<NodeId>,
    pub admitted: bool,
    pub completed_frames: usize,
    pub outbound_blocked: bool,
    pub inventory_contacts_notified: usize,
    pub actions: Vec<HostAction>,
}

/// Provider work plus aggregate-capacity rejections from one planning pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactPlan {
    pub actions: Vec<HostAction>,
    pub dial_resource_rejections: usize,
}

/// Why a prepared common-host admission did not commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionAbortReason {
    Resource,
    Authorization,
    HostCommit,
    ResourceRollback,
}

/// Provider-neutral lifecycle evidence emitted by the common supervisor.
///
/// Providers serialize these transitions; they do not infer authentication,
/// admission, or authorization state from carrier events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SharedNodeEvidenceTransition {
    AsterAuthenticated {
        contact: ContactId,
        peer: NodeId,
    },
    AdmissionPrepared {
        contact: ContactId,
        peer: NodeId,
    },
    AdmissionCommitted {
        contact: ContactId,
        peer: NodeId,
    },
    AdmissionAborted {
        contact: ContactId,
        peer: NodeId,
        reason: AdmissionAbortReason,
    },
    GenerationChecked {
        contact: ContactId,
        peer: NodeId,
        check: RuntimeAuthorizationGenerationCheck,
    },
    /// A reserved provider dial exceeded its supervisor-owned hard deadline.
    PendingConnectionExpired {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
    /// A provider explicitly cancelled a reserved dial before it opened.
    PendingConnectionCancelled {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
}

/// Cumulative common-supervisor lifecycle evidence counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedNodeEvidenceCounters {
    pub authorization_generation_checks: u64,
    pub authorization_generation_mismatches: u64,
    pub authorization_generation_unavailable: u64,
}

/// Non-upgradeable RAII lease for provider-owned node-lifetime resources.
///
/// This wrapper intentionally does not expose [`NodeResourceLease::replace`]:
/// carrier code cannot turn a base reservation into a candidate, connection,
/// stream, or contact grant outside the supervisor lifecycle.
#[derive(Debug)]
pub struct NodeProviderResourceLease {
    lease: NodeResourceLease,
}

impl NodeProviderResourceLease {
    pub fn claim(&self) -> NodeResourceClaim {
        self.lease.claim()
    }

    pub fn release(self) -> Result<(), ResourceBudgetError> {
        self.lease.release()
    }
}

/// Stable supervisor-owned contact status without backend or credential access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedContactStatus {
    pub contact: ContactId,
    pub authenticated_peer: Option<NodeId>,
    pub admitted: bool,
    pub terminal: bool,
    pub authorization_invalidated: bool,
    pub pending_outbound_frames: usize,
    pub pre_authentication_deadline: Instant,
}

/// Outcome of invalidating the shared durable authority's authorization
/// generation through its narrow typed API.
#[derive(Debug)]
pub struct SharedNodeMutation {
    pub generation: Result<u64, BlobRuntimeError>,
    pub contacts_requiring_reauthentication: Vec<ContactId>,
}

/// Exact coordinator result for one durably applied signed control.
#[derive(Debug)]
pub struct SharedNodeAuthorizationMutation {
    pub control: AppliedAuthorizationControl,
    pub contacts_requiring_reauthentication: Vec<ContactId>,
}

/// Fail-closed supervisor error.
#[derive(Debug)]
pub enum ContactSupervisorError {
    InvalidConfig(&'static str),
    UnobservedCandidate(CandidateId),
    UnauthorizedPeer {
        contact: ContactId,
        peer: NodeId,
    },
    DuplicateContact(ContactId),
    UnknownContact(ContactId),
    PreAuthenticationExpired(ContactId),
    AuthorizationChanged(ContactId),
    Credential,
    ExchangeIdExhausted,
    Host(MeshHostError),
    Resource(ResourceBudgetError),
    Runtime {
        contact: ContactId,
        error: RuntimeError,
    },
    Admission {
        contact: ContactId,
        error: AdmissionTransactionError,
    },
    InventoryFanout {
        contact: ContactId,
        error: RuntimeError,
    },
}

impl fmt::Display for ContactSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid contact supervisor: {reason}")
            }
            Self::UnobservedCandidate(candidate) => write!(
                formatter,
                "candidate {} must be observed and resource-accounted before contact open",
                candidate.as_str()
            ),
            Self::UnauthorizedPeer { contact, peer } => {
                write!(
                    formatter,
                    "contact {} authenticated an Aster peer outside the admission allowlist: ",
                    contact.0
                )?;
                for byte in peer {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::DuplicateContact(contact) => {
                write!(formatter, "contact {} is already supervised", contact.0)
            }
            Self::UnknownContact(contact) => write!(formatter, "unknown contact {}", contact.0),
            Self::PreAuthenticationExpired(contact) => {
                write!(
                    formatter,
                    "contact {} exceeded its authentication deadline",
                    contact.0
                )
            }
            Self::AuthorizationChanged(contact) => write!(
                formatter,
                "contact {} requires fresh authorization before further synchronization",
                contact.0
            ),
            Self::Credential => formatter.write_str("supervisor provisioning is unavailable"),
            Self::ExchangeIdExhausted => formatter.write_str("contact exchange IDs are exhausted"),
            Self::Host(error) => write!(formatter, "mesh host failed: {error}"),
            Self::Resource(error) => write!(formatter, "node resource budget failed: {error}"),
            Self::Runtime { contact, error } => {
                write!(formatter, "contact {} runtime failed: {error}", contact.0)
            }
            Self::Admission { contact, error } => {
                write!(formatter, "contact {} admission failed: {error}", contact.0)
            }
            Self::InventoryFanout { contact, error } => write!(
                formatter,
                "contact {} inventory fanout failed: {error}",
                contact.0
            ),
        }
    }
}

impl Error for ContactSupervisorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::Runtime { error, .. } | Self::InventoryFanout { error, .. } => Some(error),
            Self::Admission { error, .. } => Some(error),
            Self::InvalidConfig(_)
            | Self::UnobservedCandidate(_)
            | Self::UnauthorizedPeer { .. }
            | Self::DuplicateContact(_)
            | Self::UnknownContact(_)
            | Self::PreAuthenticationExpired(_)
            | Self::AuthorizationChanged(_)
            | Self::Credential
            | Self::ExchangeIdExhausted => None,
        }
    }
}

impl ContactSupervisorError {
    fn terminal_contact(&self) -> Option<ContactId> {
        match self {
            Self::UnauthorizedPeer { contact, .. }
            | Self::PreAuthenticationExpired(contact)
            | Self::AuthorizationChanged(contact)
            | Self::Runtime { contact, .. }
            | Self::Admission { contact, .. }
            | Self::InventoryFanout { contact, .. } => Some(*contact),
            Self::InvalidConfig(_)
            | Self::UnobservedCandidate(_)
            | Self::DuplicateContact(_)
            | Self::UnknownContact(_)
            | Self::Credential
            | Self::ExchangeIdExhausted
            | Self::Host(_)
            | Self::Resource(_) => None,
        }
    }
}

impl From<MeshHostError> for ContactSupervisorError {
    fn from(error: MeshHostError) -> Self {
        Self::Host(error)
    }
}

impl From<ResourceBudgetError> for ContactSupervisorError {
    fn from(error: ResourceBudgetError) -> Self {
        Self::Resource(error)
    }
}

struct CandidateLease {
    _lease: NodeResourceLease,
}

struct PendingConnection {
    lease: NodeResourceLease,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedContactState {
    PreAuthentication,
    Admitted(NodeId),
    Terminal,
}

struct ManagedContact {
    driver: SharedContactDriver,
    link: Box<dyn Link>,
    lease: NodeResourceLease,
    admitted_claim: NodeResourceClaim,
    pre_authentication_deadline: Instant,
    state: ManagedContactState,
    authorization_invalidated: bool,
    authentication_evidenced: bool,
    last_generation_evidence: Option<RuntimeAuthorizationGenerationCheck>,
    last_runtime_generation_counters: RuntimeAuthorizationGenerationCounters,
    #[cfg(test)]
    panic_next_durable_admission: bool,
}

/// One non-Tokio owner for all live contacts of a process-owned durable node.
///
/// The type exposes provider actions and accepts provider metadata, but its
/// authority, zeroizing credentials, sessions, drivers, and leases are private.
/// All methods are nonblocking except for the bounded synchronous durable work
/// already performed by `RuntimeDriver`/the reference authority.
pub struct SharedNodeContactSupervisor {
    host: MeshHost,
    resources: NodeResourceBudget,
    authority: ReferenceSemanticRuntimeAuthority,
    credentials: UnprotectedProvisioning,
    config: ContactSupervisorConfig,
    candidate_leases: BTreeMap<CandidateId, CandidateLease>,
    pending_connections: BTreeMap<(CandidateId, CandidateLocator), PendingConnection>,
    contacts: BTreeMap<ContactId, ManagedContact>,
    evidence: VecDeque<SharedNodeEvidenceTransition>,
    evidence_counters: SharedNodeEvidenceCounters,
    next_exchange_id: u64,
}

impl SharedNodeContactSupervisor {
    /// Creates the process owner after durable state has already been opened
    /// exactly once and wrapped in `authority`.
    pub fn new(
        host: MeshHost,
        resources: NodeResourceBudget,
        authority: ReferenceSemanticRuntimeAuthority,
        credentials: UnprotectedProvisioning,
        config: ContactSupervisorConfig,
    ) -> Result<Self, ContactSupervisorError> {
        ProvisioningBundle::from_bytes(credentials.expose())
            .map_err(|_| ContactSupervisorError::Credential)?;
        Ok(Self {
            host,
            resources,
            authority,
            credentials,
            config,
            candidate_leases: BTreeMap::new(),
            pending_connections: BTreeMap::new(),
            contacts: BTreeMap::new(),
            evidence: VecDeque::new(),
            evidence_counters: SharedNodeEvidenceCounters::default(),
            next_exchange_id: 1,
        })
    }

    pub fn host_snapshot(&self) -> HostSnapshot {
        self.host.snapshot()
    }

    pub fn resource_snapshot(&self) -> Result<NodeResourceSnapshot, ContactSupervisorError> {
        self.resources.snapshot().map_err(Into::into)
    }

    /// Returns the current generation of the one process-owned authority.
    pub fn authorization_generation(&self) -> Result<u64, BlobRuntimeError> {
        self.authority.authorization_generation()
    }

    /// Checks one exact durable ItemID through the supervisor-owned authority
    /// without opening another store connection or projecting its payload.
    pub fn durable_item_present(&self, item_id: ItemId) -> Result<bool, BlobRuntimeError> {
        self.authority.durable_item_present(item_id)
    }

    /// Drains exact common-host lifecycle transitions since the previous call.
    pub fn take_evidence(&mut self) -> Vec<SharedNodeEvidenceTransition> {
        self.evidence.drain(..).collect()
    }

    pub const fn evidence_counters(&self) -> SharedNodeEvidenceCounters {
        self.evidence_counters
    }

    /// Reserves provider-owned, node-lifetime capacity from the same aggregate
    /// authority used by candidates and contacts.
    ///
    /// A provider must acquire this lease before it binds descriptors, creates
    /// queues or control maps, allocates receive buffers, or starts tasks, and
    /// retain it for at least as long as those resources. Candidate,
    /// connection, and contact lifecycle counters remain supervisor-owned and
    /// cannot be bypassed through this seam.
    pub fn reserve_provider_resources(
        &self,
        claim: NodeResourceClaim,
    ) -> Result<NodeProviderResourceLease, ContactSupervisorError> {
        if claim.candidates != 0
            || claim.pending_connections != 0
            || claim.pre_authentication_contacts != 0
            || claim.admitted_contacts != 0
            || claim.streams != 0
        {
            return Err(ContactSupervisorError::InvalidConfig(
                "provider base claim cannot reserve supervisor-owned lifecycle resources",
            ));
        }
        self.resources
            .try_reserve(claim)
            .map(|lease| NodeProviderResourceLease { lease })
            .map_err(Into::into)
    }

    pub fn contact_status(&self) -> Vec<SharedContactStatus> {
        self.contacts
            .iter()
            .map(|(contact, managed)| SharedContactStatus {
                contact: *contact,
                authenticated_peer: match managed.state {
                    ManagedContactState::Admitted(peer) => Some(peer),
                    ManagedContactState::PreAuthentication | ManagedContactState::Terminal => {
                        managed.driver.authenticated_peer()
                    }
                },
                admitted: matches!(managed.state, ManagedContactState::Admitted(_)),
                terminal: managed.state == ManagedContactState::Terminal,
                authorization_invalidated: managed.authorization_invalidated,
                pending_outbound_frames: managed.driver.pending_outbound_frame_count(),
                pre_authentication_deadline: managed.pre_authentication_deadline,
            })
            .collect()
    }

    /// Adds or refreshes one provider candidate under both Host policy and the
    /// aggregate candidate budget.
    pub fn observe_candidate(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        provenance: CandidateProvenance,
        path: ContactPath,
        expected_peer: Option<NodeId>,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        let new_lease = if self.candidate_leases.contains_key(&candidate) {
            None
        } else {
            Some(
                self.resources
                    .try_reserve(self.config.resources.candidate())?,
            )
        };
        let actions = self.host.handle_event(
            HostEvent::CandidateObserved {
                candidate: candidate.clone(),
                locator,
                provenance,
                path,
                expected_peer,
            },
            now,
        )?;
        if let Some(lease) = new_lease
            && self.host_has_candidate(&candidate)
        {
            self.candidate_leases
                .insert(candidate, CandidateLease { _lease: lease });
        }
        self.reconcile_candidate_leases();
        Ok(actions)
    }

    pub fn expire_candidate(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        let actions = self
            .host
            .handle_event(HostEvent::CandidateExpired { candidate, locator }, now)?;
        self.reconcile_candidate_leases();
        Ok(actions)
    }

    pub fn refresh_candidate(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        self.host
            .handle_event(HostEvent::CandidateRefreshed { candidate, locator }, now)
            .map_err(Into::into)
    }

    pub fn candidate_carrier_matched(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        carrier_identity: CarrierIdentity,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        self.host
            .handle_event(
                HostEvent::CandidateCarrierMatched {
                    candidate,
                    locator,
                    carrier_identity,
                },
                now,
            )
            .map_err(Into::into)
    }

    /// Plans provider work and reserves every pending dial before returning it.
    /// Dials that cannot obtain aggregate capacity are settled as failed inside
    /// the Host and omitted from the provider action list.
    pub fn plan(&mut self, now: Instant) -> Result<ContactPlan, ContactSupervisorError> {
        self.expire_pending_connections(now)?;
        let planned = self.host.plan(now);
        let mut actions = Vec::with_capacity(planned.len());
        let mut dial_resource_rejections = 0_usize;
        for action in planned {
            let HostAction::Dial { candidate, locator } = &action else {
                actions.push(action);
                continue;
            };
            let key = (candidate.clone(), locator.clone());
            if self.pending_connections.contains_key(&key) {
                actions.push(action);
                continue;
            }
            match self
                .resources
                .try_reserve(self.config.resources.pending_connection())
            {
                Ok(lease) => {
                    let deadline = now
                        .checked_add(self.config.pending_connection_timeout)
                        .unwrap_or(now);
                    self.pending_connections
                        .insert(key, PendingConnection { lease, deadline });
                    actions.push(action);
                }
                Err(ResourceBudgetError::Capacity(_)) => {
                    dial_resource_rejections = dial_resource_rejections.saturating_add(1);
                    self.host.handle_event(
                        HostEvent::DialFailed {
                            candidate: candidate.clone(),
                            locator: locator.clone(),
                        },
                        now,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.reconcile_candidate_leases();
        Ok(ContactPlan {
            actions,
            dial_resource_rejections,
        })
    }

    pub fn dial_failed(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        self.pending_connections
            .remove(&(candidate.clone(), locator.clone()));
        let actions = self
            .host
            .handle_event(HostEvent::DialFailed { candidate, locator }, now)?;
        self.reconcile_candidate_leases();
        Ok(actions)
    }

    /// Explicitly cancels a provider dial and releases both the aggregate
    /// pending-connection lease and the Host's pending-dial slot. Repeated
    /// cancellation after settlement is an idempotent no-op.
    pub fn cancel_pending_connection(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        let key = (candidate.clone(), locator.clone());
        let Some(pending) = self.pending_connections.remove(&key) else {
            return Ok(Vec::new());
        };
        drop(pending);
        let actions = self.host.handle_event(
            HostEvent::DialFailed {
                candidate: candidate.clone(),
                locator: locator.clone(),
            },
            now,
        )?;
        self.evidence
            .push_back(SharedNodeEvidenceTransition::PendingConnectionCancelled {
                candidate,
                locator,
            });
        self.reconcile_candidate_leases();
        Ok(actions)
    }

    fn expire_pending_connections(&mut self, now: Instant) -> Result<(), ContactSupervisorError> {
        let expired = self
            .pending_connections
            .iter()
            .filter_map(|(key, pending)| (now >= pending.deadline).then_some(key.clone()))
            .collect::<Vec<_>>();
        for (candidate, locator) in expired {
            let Some(pending) = self
                .pending_connections
                .remove(&(candidate.clone(), locator.clone()))
            else {
                continue;
            };
            drop(pending);
            self.host.handle_event(
                HostEvent::DialFailed {
                    candidate: candidate.clone(),
                    locator: locator.clone(),
                },
                now,
            )?;
            self.evidence
                .push_back(SharedNodeEvidenceTransition::PendingConnectionExpired {
                    candidate,
                    locator,
                });
        }
        self.reconcile_candidate_leases();
        Ok(())
    }

    /// Reserves the complete pre-authentication claim before constructing the
    /// provider-owned link queues, counters, or other per-contact state.
    ///
    /// The factory is never called when candidate, Host, or aggregate resource
    /// policy rejects the contact. Providers with non-trivial per-contact
    /// allocation must use this entry point so resource rejection happens
    /// before constructing provider state.
    pub fn open_contact_with_factory<L, F>(
        &mut self,
        opening: ContactOpening,
        now: Instant,
        link_factory: F,
    ) -> Result<ContactOpenReport, ContactSupervisorError>
    where
        L: Link + 'static,
        F: FnOnce() -> L,
    {
        self.expire_pending_connections(now)?;
        if self.contacts.contains_key(&opening.contact) {
            return Err(ContactSupervisorError::DuplicateContact(opening.contact));
        }
        if !self.candidate_leases.contains_key(&opening.candidate) {
            return Err(ContactSupervisorError::UnobservedCandidate(
                opening.candidate,
            ));
        }
        let pre_authentication_claim =
            self.config.resources.pre_authentication_for(opening.path)?;
        let key = (opening.candidate.clone(), opening.locator.clone());
        let (lease, settled_pending_dial) = match self.pending_connections.remove(&key) {
            Some(mut pending) => {
                if let Err(error) = pending.lease.replace(pre_authentication_claim) {
                    let _ = self.host.handle_event(
                        HostEvent::DialFailed {
                            candidate: opening.candidate,
                            locator: opening.locator,
                        },
                        now,
                    );
                    self.reconcile_candidate_leases();
                    return Err(error.into());
                }
                (pending.lease, true)
            }
            None => (self.resources.try_reserve(pre_authentication_claim)?, false),
        };
        let actions = match self.host.handle_event(
            HostEvent::ContactOpened {
                contact: opening.contact,
                candidate: opening.candidate.clone(),
                locator: opening.locator.clone(),
                carrier_identity: opening.carrier_identity,
                direction: opening.direction,
                path: opening.path,
            },
            now,
        ) {
            Ok(actions) => actions,
            Err(error) => {
                if settled_pending_dial {
                    let _ = self.host.handle_event(
                        HostEvent::DialFailed {
                            candidate: opening.candidate.clone(),
                            locator: opening.locator.clone(),
                        },
                        now,
                    );
                }
                drop(lease);
                self.reconcile_candidate_leases();
                return Err(error.into());
            }
        };
        if actions.iter().any(|action| {
            matches!(action, HostAction::Close { contact, .. } if *contact == opening.contact)
        }) {
            drop(lease);
            self.reconcile_candidate_leases();
            return Ok(ContactOpenReport {
                opened: false,
                actions,
            });
        }

        let driver = match self.new_driver(opening.contact, opening.role) {
            Ok(driver) => driver,
            Err(error) => {
                self.host.handle_event(
                    HostEvent::ContactClosed {
                        contact: opening.contact,
                        failed: true,
                    },
                    now,
                )?;
                drop(lease);
                self.reconcile_candidate_leases();
                return Err(error);
            }
        };
        let pre_authentication_deadline = now
            .checked_add(self.config.pre_authentication_timeout)
            .unwrap_or(now);
        let admitted_claim = self.config.resources.admitted_for(opening.path)?;
        let link = match catch_unwind(AssertUnwindSafe(link_factory)) {
            Ok(link) => link,
            Err(payload) => {
                // The factory runs only after Host opening and resource/session
                // reservation. Retire those grants before preserving the
                // provider panic so no invisible active contact survives.
                drop(driver);
                drop(lease);
                let _ = self.host.handle_event(
                    HostEvent::ContactClosed {
                        contact: opening.contact,
                        failed: true,
                    },
                    now,
                );
                self.reconcile_candidate_leases();
                resume_unwind(payload);
            }
        };
        self.contacts.insert(
            opening.contact,
            ManagedContact {
                driver,
                link: Box::new(link),
                lease,
                admitted_claim,
                pre_authentication_deadline,
                state: ManagedContactState::PreAuthentication,
                authorization_invalidated: false,
                authentication_evidenced: false,
                last_generation_evidence: None,
                last_runtime_generation_counters: RuntimeAuthorizationGenerationCounters::default(),
                #[cfg(test)]
                panic_next_durable_admission: false,
            },
        );
        Ok(ContactOpenReport {
            opened: true,
            actions,
        })
    }

    fn new_driver(
        &mut self,
        contact: ContactId,
        role: ContactSessionRole,
    ) -> Result<SharedContactDriver, ContactSupervisorError> {
        let exchange_id = self.next_exchange_id;
        self.next_exchange_id = self
            .next_exchange_id
            .checked_add(1)
            .ok_or(ContactSupervisorError::ExchangeIdExhausted)?;
        let mut start = self.config.start_template.clone();
        start.exchange_id = exchange_id;
        let sync = SyncState::new(self.config.sync.clone(), SparseInventory::new())
            .map_err(|_| ContactSupervisorError::InvalidConfig("invalid contact sync state"))?;
        let bundle = ProvisioningBundle::from_bytes(self.credentials.expose())
            .map_err(|_| ContactSupervisorError::Credential)?;
        let session = self.authority.session();
        let mut driver = match role {
            ContactSessionRole::Initiator { peer_hint } => RuntimeDriver::initiator_with_limits(
                bundle,
                sync,
                session,
                start,
                peer_hint,
                self.config.runtime_limits,
            ),
            ContactSessionRole::Responder { peer_hint } => {
                RuntimeDriver::responder_with_start_and_limits(
                    bundle,
                    sync,
                    session,
                    start,
                    peer_hint,
                    self.config.runtime_limits,
                )
            }
        }
        .map_err(|error| ContactSupervisorError::Runtime { contact, error })?;
        driver
            .require_external_admission()
            .map_err(|error| ContactSupervisorError::Runtime { contact, error })?;
        Ok(driver)
    }

    /// Drives one contact once. If Aster authentication completed, host policy,
    /// the aggregate lease transition, durable authorization/hydration, and the
    /// final carrier binding commit execute in one non-yielding transaction.
    pub fn drive_contact(
        &mut self,
        contact: ContactId,
        now: Instant,
    ) -> Result<ContactDriveReport, ContactSupervisorError> {
        let generation_before = self.authority.authorization_generation();
        self.drive_contact_after_generation_snapshot(contact, now, generation_before)
    }

    fn drive_contact_after_generation_snapshot(
        &mut self,
        contact: ContactId,
        now: Instant,
        generation_before: Result<u64, BlobRuntimeError>,
    ) -> Result<ContactDriveReport, ContactSupervisorError> {
        let result = match catch_unwind(AssertUnwindSafe(|| self.drive_contact_inner(contact, now)))
        {
            Ok(result) => result,
            Err(payload) => {
                // `transact_authenticated` first rolls back its Host token and
                // lease upgrade, then resumes an authorization panic. Retire
                // the enclosing supervisor-owned driver/link/contact before
                // preserving that panic for a caller which chooses to recover.
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    self.retire_managed_contact(contact, true, now)
                }));
                resume_unwind(payload);
            }
        };
        let generation_after = self.authority.authorization_generation();
        if authorization_generation_changed(&generation_before, &generation_after) {
            // A pump can durably activate a pending authorization prefix and
            // still return an error for the submitted suffix. Propagate the
            // actual shared-authority mutation to every admitted session
            // before returning either the success or that input error.
            self.mark_admitted_contacts_authorization_invalidated();
        }
        match result {
            Ok(report) => {
                let contacts_to_close = report
                    .actions
                    .iter()
                    .filter_map(|action| match action {
                        HostAction::Close { contact, .. } => Some(*contact),
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                for contact in contacts_to_close {
                    self.retire_managed_contact(contact, false, now)?;
                }
                Ok(report)
            }
            Err(error) => {
                if let Some(failed_contact) = error.terminal_contact() {
                    self.retire_managed_contact(failed_contact, true, now)?;
                }
                Err(error)
            }
        }
    }

    fn drive_contact_inner(
        &mut self,
        contact: ContactId,
        now: Instant,
    ) -> Result<ContactDriveReport, ContactSupervisorError> {
        let Some(managed) = self.contacts.get_mut(&contact) else {
            return Err(ContactSupervisorError::UnknownContact(contact));
        };
        if managed.state == ManagedContactState::Terminal {
            return Err(ContactSupervisorError::AuthorizationChanged(contact));
        }
        if managed.authorization_invalidated {
            let peer = match managed.state {
                ManagedContactState::Admitted(peer) => peer,
                ManagedContactState::PreAuthentication | ManagedContactState::Terminal => {
                    managed.state = ManagedContactState::Terminal;
                    return Err(ContactSupervisorError::AuthorizationChanged(contact));
                }
            };
            let _ = managed.driver.revalidate_authorization_generation();
            if let Some(check) = managed.driver.take_authorization_generation_check() {
                record_generation_evidence(
                    &mut self.evidence,
                    &mut self.evidence_counters,
                    managed,
                    contact,
                    peer,
                    check,
                );
            }
            managed.state = ManagedContactState::Terminal;
            return Err(ContactSupervisorError::AuthorizationChanged(contact));
        }
        if managed.state == ManagedContactState::PreAuthentication
            && now >= managed.pre_authentication_deadline
        {
            managed.state = ManagedContactState::Terminal;
            return Err(ContactSupervisorError::PreAuthenticationExpired(contact));
        }

        let admitted_peer_before_pump = match managed.state {
            ManagedContactState::Admitted(peer) => Some(peer),
            ManagedContactState::PreAuthentication | ManagedContactState::Terminal => None,
        };
        let pump_result = managed.driver.pump(managed.link.as_ref());
        if let (Some(peer), Some(check)) = (
            admitted_peer_before_pump,
            managed.driver.take_authorization_generation_check(),
        ) {
            record_generation_evidence(
                &mut self.evidence,
                &mut self.evidence_counters,
                managed,
                contact,
                peer,
                check,
            );
        }
        let (completed_frames, outbound_blocked) = match pump_result {
            Ok(completed) => (completed, false),
            Err(RuntimeError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => (0, true),
            Err(RuntimeError::AuthorizationGenerationChanged) => {
                managed.state = ManagedContactState::Terminal;
                managed.authorization_invalidated = true;
                return Err(ContactSupervisorError::AuthorizationChanged(contact));
            }
            Err(error) => {
                managed.state = ManagedContactState::Terminal;
                return Err(ContactSupervisorError::Runtime { contact, error });
            }
        };

        let mut actions = Vec::new();
        if managed.driver.awaiting_external_admission()
            && managed.state == ManagedContactState::PreAuthentication
        {
            if now >= managed.pre_authentication_deadline {
                managed.state = ManagedContactState::Terminal;
                return Err(ContactSupervisorError::PreAuthenticationExpired(contact));
            }
            let peer =
                managed
                    .driver
                    .authenticated_peer()
                    .ok_or(ContactSupervisorError::Runtime {
                        contact,
                        error: RuntimeError::FailedState,
                    })?;
            if !managed.authentication_evidenced {
                self.evidence
                    .push_back(SharedNodeEvidenceTransition::AsterAuthenticated { contact, peer });
                managed.authentication_evidenced = true;
            }
            if self
                .config
                .allowed_peers
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&peer))
            {
                managed.state = ManagedContactState::Terminal;
                return Err(ContactSupervisorError::UnauthorizedPeer { contact, peer });
            }
            let transaction = transact_authenticated(
                &mut self.host,
                &mut managed.lease,
                managed.admitted_claim,
                contact,
                peer,
                now,
                || {
                    #[cfg(test)]
                    if std::mem::take(&mut managed.panic_next_durable_admission) {
                        panic!("injected durable-admission panic");
                    }
                    managed
                        .driver
                        .admit_authenticated()
                        .map_err(|error| error.to_string())
                },
            );
            let generation_check = managed.driver.take_authorization_generation_check();
            match transaction {
                Ok(AdmissionTransaction::Rejected {
                    actions: rejected_actions,
                }) => actions = rejected_actions,
                Ok(AdmissionTransaction::Admitted {
                    actions: admitted_actions,
                }) => {
                    self.evidence
                        .push_back(SharedNodeEvidenceTransition::AdmissionPrepared {
                            contact,
                            peer,
                        });
                    if let Some(check) = generation_check {
                        record_generation_evidence(
                            &mut self.evidence,
                            &mut self.evidence_counters,
                            managed,
                            contact,
                            peer,
                            check,
                        );
                    }
                    managed.state = ManagedContactState::Admitted(peer);
                    self.evidence
                        .push_back(SharedNodeEvidenceTransition::AdmissionCommitted {
                            contact,
                            peer,
                        });
                    actions = admitted_actions;
                }
                Err(error) => {
                    let prepared = generation_check.is_some()
                        || matches!(
                            error,
                            AdmissionTransactionError::Resource(_)
                                | AdmissionTransactionError::Authorization(_)
                                | AdmissionTransactionError::ResourceRollback(_)
                        );
                    if prepared {
                        self.evidence
                            .push_back(SharedNodeEvidenceTransition::AdmissionPrepared {
                                contact,
                                peer,
                            });
                    }
                    if let Some(check) = generation_check {
                        record_generation_evidence(
                            &mut self.evidence,
                            &mut self.evidence_counters,
                            managed,
                            contact,
                            peer,
                            check,
                        );
                    }
                    if prepared {
                        let reason = match &error {
                            AdmissionTransactionError::Resource(_) => {
                                AdmissionAbortReason::Resource
                            }
                            AdmissionTransactionError::Authorization(_) => {
                                AdmissionAbortReason::Authorization
                            }
                            AdmissionTransactionError::ResourceRollback(_) => {
                                AdmissionAbortReason::ResourceRollback
                            }
                            AdmissionTransactionError::Host(_) => AdmissionAbortReason::HostCommit,
                        };
                        self.evidence
                            .push_back(SharedNodeEvidenceTransition::AdmissionAborted {
                                contact,
                                peer,
                                reason,
                            });
                    }
                    managed.state = ManagedContactState::Terminal;
                    return Err(ContactSupervisorError::Admission { contact, error });
                }
            }
        }

        let changed = managed.driver.take_local_inventory_changed();
        let peer = match managed.state {
            ManagedContactState::Admitted(peer) => Some(peer),
            ManagedContactState::PreAuthentication | ManagedContactState::Terminal => {
                managed.driver.authenticated_peer()
            }
        };
        let admitted = matches!(managed.state, ManagedContactState::Admitted(_));
        let inventory_contacts_notified = if changed && admitted {
            self.fanout_inventory(contact)?
        } else {
            0
        };
        Ok(ContactDriveReport {
            contact,
            authenticated_peer: peer,
            admitted,
            completed_frames,
            outbound_blocked,
            inventory_contacts_notified,
            actions,
        })
    }

    fn retire_managed_contact(
        &mut self,
        contact: ContactId,
        failed: bool,
        now: Instant,
    ) -> Result<(), ContactSupervisorError> {
        let Some(managed) = self.contacts.remove(&contact) else {
            return Ok(());
        };
        // Drop the driver, its authority session, provider link, and aggregate
        // lease before publishing the corresponding Host closure.
        drop(managed);
        let result = self
            .host
            .handle_event(HostEvent::ContactClosed { contact, failed }, now);
        self.reconcile_candidate_leases();
        result.map(|_| ()).map_err(Into::into)
    }

    fn fanout_inventory(&mut self, source: ContactId) -> Result<usize, ContactSupervisorError> {
        let targets = self
            .contacts
            .iter()
            .filter_map(|(contact, managed)| {
                (*contact != source
                    && matches!(managed.state, ManagedContactState::Admitted(_))
                    && !managed.authorization_invalidated)
                    .then_some(*contact)
            })
            .collect::<Vec<_>>();
        let mut notified = 0_usize;
        for contact in targets {
            let managed = self
                .contacts
                .get_mut(&contact)
                .ok_or(ContactSupervisorError::UnknownContact(contact))?;
            if let Err(error) = managed.driver.local_inventory_changed() {
                managed.state = ManagedContactState::Terminal;
                return Err(ContactSupervisorError::InventoryFanout { contact, error });
            }
            notified = notified.saturating_add(1);
        }
        Ok(notified)
    }

    /// Drops the runtime session and lease before recording provider closure.
    pub fn close_contact(
        &mut self,
        contact: ContactId,
        failed: bool,
        now: Instant,
    ) -> Result<Vec<HostAction>, ContactSupervisorError> {
        let managed = self
            .contacts
            .remove(&contact)
            .ok_or(ContactSupervisorError::UnknownContact(contact))?;
        drop(managed);
        let actions = self
            .host
            .handle_event(HostEvent::ContactClosed { contact, failed }, now)?;
        self.reconcile_candidate_leases();
        Ok(actions)
    }

    /// Invalidates durable authorization and every admitted contact before
    /// another link pump can emit synchronization traffic.
    pub fn invalidate_authorization_generation(&mut self) -> SharedNodeMutation {
        let generation = self.authority.invalidate_authorization_generation();
        let contacts_requiring_reauthentication =
            self.mark_admitted_contacts_authorization_invalidated();
        SharedNodeMutation {
            generation,
            contacts_requiring_reauthentication,
        }
    }

    /// Durably applies an exact authority-signed control and invalidates every
    /// admitted contact as one supervisor transition before another pump.
    pub fn apply_authorization_control(
        &mut self,
        control: &SignedAuthorizationControl,
    ) -> Result<SharedNodeAuthorizationMutation, BlobRuntimeError> {
        let generation_before = self.authority.authorization_generation();
        let applied = self.authority.apply_authorization_control(control);
        self.complete_authorization_control_application(generation_before, applied)
    }

    fn complete_authorization_control_application(
        &mut self,
        generation_before: Result<u64, BlobRuntimeError>,
        applied: Result<AppliedAuthorizationControl, BlobRuntimeError>,
    ) -> Result<SharedNodeAuthorizationMutation, BlobRuntimeError> {
        let generation_after = self.authority.authorization_generation();
        let contacts_requiring_reauthentication = if applied.is_ok()
            || authorization_generation_changed(&generation_before, &generation_after)
        {
            self.mark_admitted_contacts_authorization_invalidated()
        } else {
            Vec::new()
        };
        let applied = applied?;
        Ok(SharedNodeAuthorizationMutation {
            control: applied,
            contacts_requiring_reauthentication,
        })
    }

    fn mark_admitted_contacts_authorization_invalidated(&mut self) -> Vec<ContactId> {
        let mut contacts_requiring_reauthentication = Vec::new();
        for (contact, managed) in &mut self.contacts {
            if matches!(managed.state, ManagedContactState::Admitted(_)) {
                managed.authorization_invalidated = true;
                contacts_requiring_reauthentication.push(*contact);
            }
        }
        contacts_requiring_reauthentication
    }

    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        if self
            .contacts
            .values()
            .any(|managed| managed.authorization_invalidated)
        {
            return Some(now);
        }
        self.contacts
            .values()
            .filter_map(|managed| {
                let runtime = managed.driver.next_wakeup(managed.link.as_ref());
                if managed.state == ManagedContactState::PreAuthentication {
                    Some(
                        runtime.map_or(managed.pre_authentication_deadline, |deadline| {
                            deadline.min(managed.pre_authentication_deadline)
                        }),
                    )
                } else {
                    runtime
                }
            })
            .chain(
                self.pending_connections
                    .values()
                    .map(|pending| pending.deadline),
            )
            .chain(self.host.next_wakeup(now))
            .min()
    }

    fn host_has_candidate(&self, candidate: &CandidateId) -> bool {
        self.host
            .snapshot()
            .candidates
            .iter()
            .any(|status| &status.candidate == candidate)
    }

    fn reconcile_candidate_leases(&mut self) {
        let retained = self
            .host
            .snapshot()
            .candidates
            .into_iter()
            .map(|status| status.candidate)
            .collect::<BTreeSet<_>>();
        self.candidate_leases
            .retain(|candidate, _| retained.contains(candidate));
    }
}

fn record_generation_evidence(
    evidence: &mut VecDeque<SharedNodeEvidenceTransition>,
    counters: &mut SharedNodeEvidenceCounters,
    managed: &mut ManagedContact,
    contact: ContactId,
    peer: NodeId,
    check: RuntimeAuthorizationGenerationCheck,
) {
    let runtime = managed.driver.authorization_generation_counters();
    counters.authorization_generation_checks =
        counters.authorization_generation_checks.saturating_add(
            runtime
                .checks
                .saturating_sub(managed.last_runtime_generation_counters.checks),
        );
    counters.authorization_generation_mismatches =
        counters.authorization_generation_mismatches.saturating_add(
            runtime
                .mismatches
                .saturating_sub(managed.last_runtime_generation_counters.mismatches),
        );
    counters.authorization_generation_unavailable = counters
        .authorization_generation_unavailable
        .saturating_add(
            runtime
                .unavailable
                .saturating_sub(managed.last_runtime_generation_counters.unavailable),
        );
    managed.last_runtime_generation_counters = runtime;
    if managed.last_generation_evidence == Some(check) {
        return;
    }
    managed.last_generation_evidence = Some(check);
    evidence.push_back(SharedNodeEvidenceTransition::GenerationChecked {
        contact,
        peer,
        check,
    });
}

fn authorization_generation_changed(
    before: &Result<u64, BlobRuntimeError>,
    after: &Result<u64, BlobRuntimeError>,
) -> bool {
    match (before, after) {
        (Ok(before), Ok(after)) => before != after,
        // Exhaustion, poisoning, or any other unavailable node-global
        // generation cannot leave an admitted view trusted.
        (Ok(_), Err(_)) | (Err(_), Ok(_)) | (Err(_), Err(_)) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostConfig, NodeResourceLimits};
    use aster_mesh::blob::{BlobStoreConfig, BlobTransferStore};
    use aster_mesh::engine::NodeConfig;
    use aster_mesh::link::{LinkCharacteristics, ReceivedFrame};
    use aster_mesh::runtime::ReferenceSemanticRuntimeBackend;
    use aster_mesh::wire::EnvelopeId;
    use aster_mesh::{
        DataClass, EmissionPolicy, Priority, ProvisioningAccess, PublishRequest,
        ReferenceProvisioner, Scope, Topic, open_reference_node,
    };
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct MemoryLink {
        name: &'static str,
        local: NodeId,
        inbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        outbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        sends: Arc<AtomicU64>,
    }

    impl MemoryLink {
        fn pair(
            name: &'static str,
            left: NodeId,
            right: NodeId,
        ) -> (Self, Self, Arc<AtomicU64>, Arc<AtomicU64>) {
            let left_inbound = Arc::new(Mutex::new(VecDeque::new()));
            let right_inbound = Arc::new(Mutex::new(VecDeque::new()));
            let left_sends = Arc::new(AtomicU64::new(0));
            let right_sends = Arc::new(AtomicU64::new(0));
            (
                Self {
                    name,
                    local: left,
                    inbound: Arc::clone(&left_inbound),
                    outbound: Arc::clone(&right_inbound),
                    sends: Arc::clone(&left_sends),
                },
                Self {
                    name,
                    local: right,
                    inbound: right_inbound,
                    outbound: left_inbound,
                    sends: Arc::clone(&right_sends),
                },
                left_sends,
                right_sends,
            )
        }
    }

    impl Link for MemoryLink {
        fn name(&self) -> &str {
            self.name
        }

        fn characteristics(&self) -> LinkCharacteristics {
            LinkCharacteristics {
                mtu: 1_200,
                bits_per_second: Some(10_000_000),
                cost: 1,
                emission: 1,
                broadcast: false,
            }
        }

        fn send(&self, _peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            self.outbound
                .lock()
                .map_err(|_| io::Error::other("memory link poisoned"))?
                .push_back(ReceivedFrame {
                    peer: Some(self.local),
                    bytes: frame.to_vec(),
                });
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            Ok(self
                .inbound
                .lock()
                .map_err(|_| io::Error::other("memory link poisoned"))?
                .pop_front())
        }

        fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
            Ok(())
        }

        fn next_wakeup(&self) -> Option<Instant> {
            self.inbound
                .lock()
                .ok()
                .and_then(|queue| (!queue.is_empty()).then(Instant::now))
        }

        fn retry_floor(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    struct DropTrackedLink {
        inner: MemoryLink,
        drops: Arc<AtomicU64>,
    }

    impl Drop for DropTrackedLink {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Link for DropTrackedLink {
        fn name(&self) -> &str {
            self.inner.name()
        }

        fn characteristics(&self) -> LinkCharacteristics {
            self.inner.characteristics()
        }

        fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            self.inner.send(peer, frame)
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            self.inner.try_receive()
        }

        fn set_discovery(&self, enabled: bool) -> io::Result<()> {
            self.inner.set_discovery(enabled)
        }

        fn next_wakeup(&self) -> Option<Instant> {
            self.inner.next_wakeup()
        }

        fn retry_floor(&self) -> Duration {
            self.inner.retry_floor()
        }
    }

    struct FactoryDropProbe(Arc<AtomicU64>);

    impl Drop for FactoryDropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct TestNode {
        root: std::path::PathBuf,
        identity: NodeId,
        published_item: Option<ItemId>,
        supervisor: SharedNodeContactSupervisor,
    }

    fn test_root(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "aster-contact-supervisor-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn canonical_durable_digest(root: &std::path::Path) -> [u8; 32] {
        fn collect(
            root: &std::path::Path,
            directory: &std::path::Path,
            files: &mut Vec<(String, Vec<u8>)>,
        ) {
            let mut entries = fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    collect(root, &path, files);
                } else if path.is_file() {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    files.push((relative, fs::read(path).unwrap()));
                }
            }
        }

        let mut files = Vec::new();
        collect(root, root, &mut files);
        files.sort_by(|left, right| left.0.cmp(&right.0));
        let mut canonical = b"aster/test/durable-tree/v1".to_vec();
        for (path, bytes) in files {
            canonical.extend_from_slice(&(path.len() as u64).to_be_bytes());
            canonical.extend_from_slice(path.as_bytes());
            canonical.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            canonical.extend_from_slice(&bytes);
        }
        EnvelopeId::from_sealed_bytes(&canonical).into_bytes()
    }

    fn observed_authorization_generation(
        supervisor: &SharedNodeContactSupervisor,
    ) -> Result<u64, BlobRuntimeError> {
        supervisor.authorization_generation()
    }

    fn resource_claims() -> ContactResourceClaims {
        ContactResourceClaims::new(
            NodeResourceClaim {
                candidates: 1,
                ..NodeResourceClaim::default()
            },
            NodeResourceClaim {
                pending_connections: 1,
                ..NodeResourceClaim::default()
            },
            NodeResourceClaim {
                pre_authentication_contacts: 1,
                streams: 1,
                tasks: 1,
                frames: 32,
                inbound_bytes: 256 * 1_024,
                outbound_bytes: 256 * 1_024,
                descriptors: 1,
                ..NodeResourceClaim::default()
            },
            NodeResourceClaim {
                admitted_contacts: 1,
                streams: 1,
                tasks: 1,
                frames: 32,
                inbound_bytes: 256 * 1_024,
                outbound_bytes: 256 * 1_024,
                descriptors: 1,
                ..NodeResourceClaim::default()
            },
        )
        .unwrap()
    }

    fn runtime_limits() -> RuntimeLimits {
        RuntimeLimits {
            max_in_flight_logical_frames: 4,
            max_reassembly_bytes: 256 * 1_024,
            max_pending_retries: 4,
            max_pending_outbox: 4,
            max_pending_logical_bytes: 256 * 1_024,
            deferred_want_epoch_reserve: 64 * 1_024,
            max_completed_transfers: 4,
            ..RuntimeLimits::default()
        }
    }

    fn limits(active: usize) -> NodeResourceLimits {
        NodeResourceLimits {
            candidates: 8,
            pending_connections: active,
            pre_authentication_contacts: active,
            admitted_contacts: active,
            streams: active * 2,
            tasks: active * 2,
            frames: active * 64,
            inbound_bytes: active * 512 * 1_024,
            outbound_bytes: active * 512 * 1_024,
            descriptors: active * 2,
            relay_reservations: active,
        }
    }

    fn test_node(label: &str, ordinal: u64, active: usize) -> TestNode {
        test_node_with_allowed(label, ordinal, active, None)
    }

    fn test_node_with_allowed(
        label: &str,
        ordinal: u64,
        active: usize,
        allowed_peers: Option<BTreeSet<NodeId>>,
    ) -> TestNode {
        test_node_with_allowed_and_limits(label, ordinal, active, allowed_peers, None, false)
    }

    fn test_node_with_allowed_and_limits(
        label: &str,
        ordinal: u64,
        active: usize,
        allowed_peers: Option<BTreeSet<NodeId>>,
        resource_limits: Option<NodeResourceLimits>,
        publish_item: bool,
    ) -> TestNode {
        let root = test_root(label);
        let topic = Topic::new("supervisor.test").unwrap();
        let scope = Scope::new("mission/supervisor").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xe1; 32]).unwrap();
        let bytes = provisioner
            .issue_node(ordinal, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let bundle = ProvisioningBundle::from_bytes(&bytes).unwrap();
        let mut node =
            open_reference_node(root.join("node.sqlite"), bundle, NodeConfig::default()).unwrap();
        let identity = node.identity();
        let published_item = publish_item.then(|| {
            node.publish(PublishRequest {
                class: DataClass::State,
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                ttl_ms: None,
                logical_key: b"supervisor-durable-item-present".to_vec(),
                payload: b"sealed-payload-must-not-be-materialized".to_vec(),
                tombstone: false,
            })
            .unwrap()
            .id
        });
        let blobs =
            BlobTransferStore::open_with_config(root.join("blobs"), BlobStoreConfig::default())
                .unwrap();
        let backend = ReferenceSemanticRuntimeBackend::new(node, blobs).unwrap();
        let authority = ReferenceSemanticRuntimeAuthority::new(backend);
        let host = MeshHost::new(
            HostConfig {
                max_candidates: 8,
                max_active_contacts: active,
                candidate_ttl: Duration::from_secs(60),
                contact_quantum: Duration::from_secs(60),
                reconnect_initial: Duration::from_millis(10),
                reconnect_max: Duration::from_secs(1),
            },
            EmissionPolicy::default(),
        )
        .unwrap();
        let mut config = ContactSupervisorConfig::new(
            SyncConfig::default(),
            runtime_limits(),
            StartRequest {
                exchange_id: 0,
                topics: vec![topic.as_str().to_owned()],
                scopes: vec![scope.as_str().to_owned()],
                min_priority: Priority::Routine as u8,
            },
            Duration::from_secs(10),
            resource_claims(),
        )
        .unwrap();
        if let Some(allowed_peers) = allowed_peers {
            config = config.with_allowed_peers(allowed_peers).unwrap();
        }
        let supervisor = SharedNodeContactSupervisor::new(
            host,
            NodeResourceBudget::new(resource_limits.unwrap_or_else(|| limits(active))).unwrap(),
            authority,
            UnprotectedProvisioning::new(bytes).unwrap(),
            config,
        )
        .unwrap();
        TestNode {
            root,
            identity,
            published_item,
            supervisor,
        }
    }

    fn candidate(ordinal: u64) -> CandidateId {
        CandidateId::new(format!("candidate-{ordinal:03}")).unwrap()
    }

    fn locator(ordinal: u64) -> CandidateLocator {
        CandidateLocator::new(format!("/ip4/192.0.2.{ordinal}/tcp/4000")).unwrap()
    }

    #[test]
    fn supervisor_checks_exact_item_through_its_existing_authority() {
        let TestNode {
            root,
            published_item,
            supervisor,
            ..
        } = test_node_with_allowed_and_limits("durable-item-present", 1, 1, None, None, true);

        assert!(
            supervisor
                .durable_item_present(published_item.unwrap())
                .unwrap()
        );
        assert!(!supervisor.durable_item_present([0x92; 32]).unwrap());

        drop(supervisor);
        fs::remove_dir_all(root).unwrap();
    }

    fn open<L>(
        supervisor: &mut SharedNodeContactSupervisor,
        contact: ContactId,
        ordinal: u64,
        remote: NodeId,
        role: ContactSessionRole,
        direction: ContactDirection,
        link: L,
    ) where
        L: Link + 'static,
    {
        let now = Instant::now();
        supervisor
            .observe_candidate(
                candidate(ordinal),
                locator(ordinal),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(remote),
                now,
            )
            .unwrap();
        if direction == ContactDirection::Outbound {
            let plan = supervisor.plan(now).unwrap();
            assert!(plan.actions.iter().any(|action| {
                matches!(
                    action,
                    HostAction::Dial {
                        candidate: planned_candidate,
                        locator: planned_locator,
                    } if planned_candidate == &candidate(ordinal)
                        && planned_locator == &locator(ordinal)
                )
            }));
        }
        let report = supervisor
            .open_contact_with_factory(
                ContactOpening {
                    contact,
                    candidate: candidate(ordinal),
                    locator: locator(ordinal),
                    carrier_identity: Some(CarrierIdentity::new(vec![ordinal as u8; 8]).unwrap()),
                    direction,
                    path: ContactPath::Direct,
                    role,
                },
                now,
                || link,
            )
            .unwrap();
        assert!(report.opened);
        assert!(report.actions.is_empty());
    }

    #[test]
    fn regression_shared_supervisor_does_not_negotiate_unimplemented_blob_stream_semantics() {
        let mut initiator = test_node("semantic-ceiling-initiator", 1, 1);
        let mut responder = test_node("semantic-ceiling-responder", 2, 1);
        let (initiator_link, responder_link, _, _) =
            MemoryLink::pair("semantic-ceiling", initiator.identity, responder.identity);
        open(
            &mut initiator.supervisor,
            ContactId(1),
            1,
            responder.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(responder.identity),
            },
            ContactDirection::Outbound,
            initiator_link,
        );
        open(
            &mut responder.supervisor,
            ContactId(1),
            2,
            initiator.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(initiator.identity),
            },
            ContactDirection::Inbound,
            responder_link,
        );

        for _ in 0..256 {
            let now = Instant::now();
            initiator
                .supervisor
                .drive_contact(ContactId(1), now)
                .expect("drive initiator");
            responder
                .supervisor
                .drive_contact(ContactId(1), now)
                .expect("drive responder");
            if initiator.supervisor.contact_status()[0].admitted
                && responder.supervisor.contact_status()[0].admitted
            {
                break;
            }
        }
        assert!(initiator.supervisor.contact_status()[0].admitted);
        assert!(responder.supervisor.contact_status()[0].admitted);

        // ReferenceSemanticRuntimeBackend still moves Blob content with the
        // profile-4 BlobChunk lane, which semantic v9 forbids. Until this host
        // composes profile 5, its authenticated session must stop at v8.
        for node in [&initiator, &responder] {
            let version = node
                .supervisor
                .contacts
                .get(&ContactId(1))
                .expect("managed contact")
                .driver
                .authenticated_semantic_version();
            assert_eq!(
                version,
                Some(8),
                "shared host advertised semantic v9 without a profile-5 Blob implementation"
            );
        }

        drop(initiator.supervisor);
        drop(responder.supervisor);
        fs::remove_dir_all(initiator.root).unwrap();
        fs::remove_dir_all(responder.root).unwrap();
    }

    fn admitted_three_node_line(
        label: &str,
    ) -> (TestNode, TestNode, TestNode, Arc<AtomicU64>, Arc<AtomicU64>) {
        let mut center = test_node(&format!("{label}-center"), 1, 2);
        let mut left = test_node(&format!("{label}-left"), 2, 1);
        let mut right = test_node(&format!("{label}-right"), 3, 1);
        let (center_left, left_center, center_left_sends, _) =
            MemoryLink::pair("generation-center-left", center.identity, left.identity);
        let (center_right, right_center, center_right_sends, _) =
            MemoryLink::pair("generation-center-right", center.identity, right.identity);
        open(
            &mut center.supervisor,
            ContactId(1),
            31,
            left.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(left.identity),
            },
            ContactDirection::Outbound,
            center_left,
        );
        open(
            &mut left.supervisor,
            ContactId(1),
            32,
            center.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(center.identity),
            },
            ContactDirection::Inbound,
            left_center,
        );
        open(
            &mut center.supervisor,
            ContactId(2),
            33,
            right.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(right.identity),
            },
            ContactDirection::Outbound,
            center_right,
        );
        open(
            &mut right.supervisor,
            ContactId(1),
            34,
            center.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(center.identity),
            },
            ContactDirection::Inbound,
            right_center,
        );
        for _ in 0..256 {
            let now = Instant::now();
            center.supervisor.drive_contact(ContactId(1), now).unwrap();
            left.supervisor.drive_contact(ContactId(1), now).unwrap();
            center.supervisor.drive_contact(ContactId(2), now).unwrap();
            right.supervisor.drive_contact(ContactId(1), now).unwrap();
            if center
                .supervisor
                .contact_status()
                .iter()
                .filter(|status| status.admitted)
                .count()
                == 2
                && left.supervisor.contact_status()[0].admitted
                && right.supervisor.contact_status()[0].admitted
            {
                break;
            }
        }
        assert_eq!(
            center
                .supervisor
                .contact_status()
                .iter()
                .filter(|status| status.admitted)
                .count(),
            2
        );
        center.supervisor.take_evidence();
        (center, left, right, center_left_sends, center_right_sends)
    }

    #[test]
    fn aggregate_pre_authentication_capacity_releases_with_the_contact() {
        let mut local = test_node("aggregate", 1, 1);
        let peer_a = [0xa1; 32];
        let peer_b = [0xb2; 32];
        let (first, _, _, _) = MemoryLink::pair("first", local.identity, peer_a);
        let (second, _, _, _) = MemoryLink::pair("second", local.identity, peer_b);
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            peer_a,
            ContactSessionRole::Responder {
                peer_hint: Some(peer_a),
            },
            ContactDirection::Inbound,
            first,
        );
        local
            .supervisor
            .observe_candidate(
                candidate(2),
                locator(2),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer_b),
                Instant::now(),
            )
            .unwrap();
        assert!(matches!(
            local.supervisor.open_contact_with_factory(
                ContactOpening {
                    contact: ContactId(2),
                    candidate: candidate(2),
                    locator: locator(2),
                    carrier_identity: None,
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                    role: ContactSessionRole::Responder {
                        peer_hint: Some(peer_b),
                    },
                },
                Instant::now(),
                || second.clone(),
            ),
            Err(ContactSupervisorError::Resource(
                ResourceBudgetError::Capacity("pre-authentication contacts")
            ))
        ));
        assert_eq!(
            local
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pre_authentication_contacts,
            1
        );
        local
            .supervisor
            .close_contact(ContactId(1), false, Instant::now())
            .unwrap();
        assert_eq!(
            local
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pre_authentication_contacts,
            0
        );
        assert!(
            local
                .supervisor
                .open_contact_with_factory(
                    ContactOpening {
                        contact: ContactId(2),
                        candidate: candidate(2),
                        locator: locator(2),
                        carrier_identity: None,
                        direction: ContactDirection::Inbound,
                        path: ContactPath::Direct,
                        role: ContactSessionRole::Responder {
                            peer_hint: Some(peer_b),
                        },
                    },
                    Instant::now(),
                    || second,
                )
                .unwrap()
                .opened
        );

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn contact_link_factory_runs_only_after_preauthentication_capacity_reservation() {
        let mut local = test_node("factory-after-reservation", 1, 1);
        let peer_a = [0xa1; 32];
        let peer_b = [0xb2; 32];
        let (first, _, _, _) = MemoryLink::pair("factory-first", local.identity, peer_a);
        let (second, _, _, _) = MemoryLink::pair("factory-second", local.identity, peer_b);
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            peer_a,
            ContactSessionRole::Responder {
                peer_hint: Some(peer_a),
            },
            ContactDirection::Inbound,
            first,
        );
        local
            .supervisor
            .observe_candidate(
                candidate(2),
                locator(2),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer_b),
                Instant::now(),
            )
            .unwrap();
        let second_opening = ContactOpening {
            contact: ContactId(2),
            candidate: candidate(2),
            locator: locator(2),
            carrier_identity: None,
            direction: ContactDirection::Inbound,
            path: ContactPath::Direct,
            role: ContactSessionRole::Responder {
                peer_hint: Some(peer_b),
            },
        };
        let factory_called = AtomicBool::new(false);
        assert!(matches!(
            local.supervisor.open_contact_with_factory(
                second_opening.clone(),
                Instant::now(),
                || {
                    factory_called.store(true, Ordering::Relaxed);
                    second.clone()
                },
            ),
            Err(ContactSupervisorError::Resource(
                ResourceBudgetError::Capacity("pre-authentication contacts")
            ))
        ));
        assert!(!factory_called.load(Ordering::Relaxed));
        assert_eq!(
            local
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pre_authentication_contacts,
            1
        );

        local
            .supervisor
            .close_contact(ContactId(1), false, Instant::now())
            .unwrap();
        assert!(
            local
                .supervisor
                .open_contact_with_factory(second_opening, Instant::now(), || {
                    factory_called.store(true, Ordering::Relaxed);
                    second
                })
                .unwrap()
                .opened
        );
        assert!(factory_called.load(Ordering::Relaxed));

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn panicking_contact_link_factory_releases_session_host_and_preauthentication_lease() {
        let mut local = test_node("panicking-link-factory", 1, 1);
        let peer = [0xa1; 32];
        local
            .supervisor
            .observe_candidate(
                candidate(1),
                locator(1),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer),
                Instant::now(),
            )
            .unwrap();
        let opening = ContactOpening {
            contact: ContactId(1),
            candidate: candidate(1),
            locator: locator(1),
            carrier_identity: None,
            direction: ContactDirection::Inbound,
            path: ContactPath::Direct,
            role: ContactSessionRole::Responder {
                peer_hint: Some(peer),
            },
        };
        let factory_entered = AtomicBool::new(false);
        let factory_drops = Arc::new(AtomicU64::new(0));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = local.supervisor.open_contact_with_factory(
                opening.clone(),
                Instant::now(),
                || -> MemoryLink {
                    factory_entered.store(true, Ordering::Relaxed);
                    let _probe = FactoryDropProbe(Arc::clone(&factory_drops));
                    panic!("injected contact-link construction panic");
                },
            );
        }));
        assert!(panic.is_err());
        assert!(factory_entered.load(Ordering::Relaxed));
        assert_eq!(factory_drops.load(Ordering::Relaxed), 1);
        assert!(local.supervisor.contact_status().is_empty());
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            resource_claims().candidate()
        );
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.carrier_binding_count, 0);
        assert_eq!(host.pending_admissions, 0);
        assert_eq!(host.candidate_count, 1);

        let (link, _, _, _) = MemoryLink::pair("factory-recovery", local.identity, peer);
        assert!(
            local
                .supervisor
                .open_contact_with_factory(opening, Instant::now(), || link)
                .unwrap()
                .opened
        );
        local
            .supervisor
            .close_contact(ContactId(1), false, Instant::now())
            .unwrap();

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_preauthentication_close_drops_inflight_session_and_releases_owned_leases() {
        let mut local = test_node("explicit-preauth-close", 1, 1);
        let peer = [0xa1; 32];
        let (link, _peer_link, _, _) =
            MemoryLink::pair("explicit-preauth-close", local.identity, peer);
        let link_drops = Arc::new(AtomicU64::new(0));
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            peer,
            ContactSessionRole::Initiator {
                peer_hint: Some(peer),
            },
            ContactDirection::Outbound,
            DropTrackedLink {
                inner: link,
                drops: Arc::clone(&link_drops),
            },
        );

        let status = local.supervisor.contact_status();
        assert_eq!(status.len(), 1);
        assert!(!status[0].admitted);
        assert!(!status[0].terminal);
        assert!(status[0].pending_outbound_frames > 0);
        assert_eq!(link_drops.load(Ordering::Relaxed), 0);
        let resources = local.supervisor.resource_snapshot().unwrap();
        assert_eq!(resources.current.candidates, 1);
        assert_eq!(resources.current.pre_authentication_contacts, 1);
        assert_eq!(resources.current.streams, 1);
        assert_eq!(resources.current.tasks, 1);
        assert_eq!(resources.current.descriptors, 1);
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 1);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.pending_admissions, 0);

        local
            .supervisor
            .close_contact(ContactId(1), false, Instant::now())
            .unwrap();
        assert_eq!(link_drops.load(Ordering::Relaxed), 1);
        assert!(local.supervisor.contact_status().is_empty());
        assert!(matches!(
            local.supervisor.drive_contact(ContactId(1), Instant::now()),
            Err(ContactSupervisorError::UnknownContact(ContactId(1)))
        ));
        let resources = local.supervisor.resource_snapshot().unwrap();
        assert_eq!(resources.current, resource_claims().candidate());
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.carrier_binding_count, 0);
        assert_eq!(host.pending_admissions, 0);

        local
            .supervisor
            .expire_candidate(candidate(1), locator(1), Instant::now())
            .unwrap();
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            NodeResourceClaim::default()
        );
        assert_eq!(local.supervisor.host_snapshot().candidate_count, 0);

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_connection_deadline_wakes_and_releases_host_and_resource_reservation() {
        let mut local = test_node("pending-connection-deadline", 1, 1);
        local.supervisor.config = local
            .supervisor
            .config
            .clone()
            .with_pending_connection_timeout(Duration::from_millis(50))
            .unwrap();
        let now = Instant::now();
        local
            .supervisor
            .observe_candidate(
                candidate(1),
                locator(1),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some([0xa1; 32]),
                now,
            )
            .unwrap();
        let plan = local.supervisor.plan(now).unwrap();
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            HostAction::Dial { candidate: id, locator: address }
                if id == &candidate(1) && address == &locator(1)
        )));
        assert_eq!(plan.dial_resource_rejections, 0);
        let deadline = now.checked_add(Duration::from_millis(50)).unwrap();
        assert_eq!(local.supervisor.next_wakeup(now), Some(deadline));
        assert_eq!(
            local
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pending_connections,
            1
        );
        assert_eq!(local.supervisor.host_snapshot().pending_dials, 1);

        let before_deadline = deadline.checked_sub(Duration::from_millis(1)).unwrap();
        assert!(
            local
                .supervisor
                .plan(before_deadline)
                .unwrap()
                .actions
                .is_empty()
        );
        assert_eq!(
            local
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .pending_connections,
            1
        );
        assert!(local.supervisor.plan(deadline).unwrap().actions.is_empty());
        assert_eq!(
            local.supervisor.take_evidence(),
            vec![SharedNodeEvidenceTransition::PendingConnectionExpired {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            resource_claims().candidate()
        );
        assert_eq!(local.supervisor.host_snapshot().pending_dials, 0);
        let factory_called = AtomicBool::new(false);
        let local_identity = local.identity;
        assert!(matches!(
            local.supervisor.open_contact_with_factory(
                ContactOpening {
                    contact: ContactId(1),
                    candidate: candidate(1),
                    locator: locator(1),
                    carrier_identity: None,
                    direction: ContactDirection::Outbound,
                    path: ContactPath::Direct,
                    role: ContactSessionRole::Initiator {
                        peer_hint: Some([0xa1; 32]),
                    },
                },
                deadline,
                || {
                    factory_called.store(true, Ordering::Relaxed);
                    MemoryLink::pair("expired-dial", local_identity, [0xa1; 32]).0
                },
            ),
            Err(ContactSupervisorError::Host(
                MeshHostError::UnknownCandidate
            ))
        ));
        assert!(!factory_called.load(Ordering::Relaxed));
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            resource_claims().candidate()
        );

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_pending_connection_cancellation_releases_host_and_resource_reservation() {
        let mut local = test_node("pending-connection-cancellation", 1, 1);
        let now = Instant::now();
        local
            .supervisor
            .observe_candidate(
                candidate(1),
                locator(1),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some([0xa1; 32]),
                now,
            )
            .unwrap();
        assert!(
            local
                .supervisor
                .plan(now)
                .unwrap()
                .actions
                .iter()
                .any(|action| {
                    matches!(action, HostAction::Dial { candidate: id, locator: address }
                if id == &candidate(1) && address == &locator(1))
                })
        );
        assert_eq!(local.supervisor.host_snapshot().pending_dials, 1);
        assert!(
            local
                .supervisor
                .cancel_pending_connection(candidate(1), locator(1), now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            local.supervisor.take_evidence(),
            vec![SharedNodeEvidenceTransition::PendingConnectionCancelled {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            resource_claims().candidate()
        );
        assert_eq!(local.supervisor.host_snapshot().pending_dials, 0);
        assert!(
            local
                .supervisor
                .cancel_pending_connection(candidate(1), locator(1), now)
                .unwrap()
                .is_empty()
        );
        assert!(local.supervisor.take_evidence().is_empty());

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbound_contact_requires_a_resource_accounted_candidate() {
        let mut local = test_node("unobserved", 1, 1);
        let peer = [0xa1; 32];
        let (link, _, _, _) = MemoryLink::pair("unobserved", local.identity, peer);

        assert!(matches!(
            local.supervisor.open_contact_with_factory(
                ContactOpening {
                    contact: ContactId(1),
                    candidate: candidate(1),
                    locator: locator(1),
                    carrier_identity: None,
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                    role: ContactSessionRole::Responder {
                        peer_hint: Some(peer),
                    },
                },
                Instant::now(),
                || link,
            ),
            Err(ContactSupervisorError::UnobservedCandidate(_))
        ));
        let resources = local.supervisor.resource_snapshot().unwrap();
        assert_eq!(resources.current.candidates, 0);
        assert_eq!(resources.current.pre_authentication_contacts, 0);
        assert_eq!(local.supervisor.host_snapshot().candidate_count, 0);

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provider_base_lease_uses_shared_budget_without_bypassing_lifecycle() {
        let local = test_node("provider-base", 1, 1);
        let base = NodeResourceClaim {
            tasks: 1,
            frames: 1,
            inbound_bytes: 65_507,
            descriptors: 1,
            ..NodeResourceClaim::default()
        };
        let lease = local.supervisor.reserve_provider_resources(base).unwrap();
        assert_eq!(lease.claim(), base);
        assert_eq!(local.supervisor.resource_snapshot().unwrap().current, base);
        assert!(matches!(
            local
                .supervisor
                .reserve_provider_resources(NodeResourceClaim {
                    candidates: 1,
                    ..NodeResourceClaim::default()
                }),
            Err(ContactSupervisorError::InvalidConfig(
                "provider base claim cannot reserve supervisor-owned lifecycle resources"
            ))
        ));
        assert_eq!(local.supervisor.resource_snapshot().unwrap().current, base);
        drop(lease);
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            NodeResourceClaim::default()
        );

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pre_authentication_and_admitted_claims_cover_runtime_floors() {
        let claims = resource_claims();
        let shared_descriptor_claims = ContactResourceClaims::new(
            claims.candidate(),
            claims.pending_connection(),
            NodeResourceClaim {
                descriptors: 0,
                ..claims.pre_authentication()
            },
            NodeResourceClaim {
                descriptors: 0,
                ..claims.admitted()
            },
        )
        .unwrap();
        shared_descriptor_claims
            .validate_runtime_floors(runtime_limits())
            .unwrap();
        assert!(matches!(
            ContactResourceClaims::new(
                claims.candidate(),
                claims.pending_connection(),
                NodeResourceClaim {
                    streams: 0,
                    descriptors: 0,
                    ..claims.pre_authentication()
                },
                NodeResourceClaim {
                    descriptors: 0,
                    ..claims.admitted()
                },
            ),
            Err(ContactSupervisorError::InvalidConfig(
                "contact claim must account stream, task, frame, and byte resources"
            ))
        ));
        let under_reserved_pre_authentication = ContactResourceClaims::new(
            claims.candidate(),
            claims.pending_connection(),
            NodeResourceClaim {
                frames: 8,
                ..claims.pre_authentication()
            },
            claims.admitted(),
        )
        .unwrap();
        assert!(matches!(
            under_reserved_pre_authentication.validate_runtime_floors(runtime_limits()),
            Err(ContactSupervisorError::InvalidConfig(
                "pre-authentication frame claim is below the runtime metadata floor"
            ))
        ));

        let excessive_metadata = RuntimeLimits {
            max_completed_transfers: 16,
            ..runtime_limits()
        };
        assert!(matches!(
            claims.validate_runtime_floors(excessive_metadata),
            Err(ContactSupervisorError::InvalidConfig(
                "pre-authentication frame claim is below the runtime metadata floor"
            ))
        ));

        let under_reserved_admitted = ContactResourceClaims::new(
            claims.candidate(),
            claims.pending_connection(),
            claims.pre_authentication(),
            NodeResourceClaim {
                inbound_bytes: 64 * 1_024,
                ..claims.admitted()
            },
        )
        .unwrap();
        assert!(matches!(
            under_reserved_admitted.validate_runtime_floors(runtime_limits()),
            Err(ContactSupervisorError::InvalidConfig(
                "admitted inbound-byte claim is below the runtime retention floor"
            ))
        ));
    }

    #[test]
    fn authentication_timeout_retires_session_lease_and_host_contact_before_error() {
        let mut local = test_node("timeout-retirement", 1, 1);
        let peer = [0xa1; 32];
        let (link, _, _, _) = MemoryLink::pair("timeout", local.identity, peer);
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            peer,
            ContactSessionRole::Responder {
                peer_hint: Some(peer),
            },
            ContactDirection::Inbound,
            link,
        );

        let expired = Instant::now().checked_add(Duration::from_secs(11)).unwrap();
        assert!(matches!(
            local.supervisor.drive_contact(ContactId(1), expired),
            Err(ContactSupervisorError::PreAuthenticationExpired(ContactId(
                1
            )))
        ));
        assert!(local.supervisor.contact_status().is_empty());
        let resources = local.supervisor.resource_snapshot().unwrap();
        assert_eq!(resources.current.pre_authentication_contacts, 0);
        assert_eq!(resources.current.admitted_contacts, 0);
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.carrier_binding_count, 0);
        assert_eq!(host.pending_admissions, 0);

        let root = local.root.clone();
        drop(local);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn peer_allowlist_rejects_before_host_resource_or_durable_admission() {
        let mut local =
            test_node_with_allowed("allowlist-local", 1, 1, Some(BTreeSet::from([[0xee; 32]])));
        let mut remote = test_node("allowlist-remote", 2, 1);
        let (local_link, remote_link, local_sends, _) =
            MemoryLink::pair("allowlist", local.identity, remote.identity);
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            remote.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(remote.identity),
            },
            ContactDirection::Outbound,
            local_link,
        );
        open(
            &mut remote.supervisor,
            ContactId(1),
            2,
            local.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(local.identity),
            },
            ContactDirection::Inbound,
            remote_link,
        );

        let mut rejected = false;
        for _ in 0..64 {
            let now = Instant::now();
            match local.supervisor.drive_contact(ContactId(1), now) {
                Ok(_) => {}
                Err(ContactSupervisorError::UnauthorizedPeer { contact, peer }) => {
                    assert_eq!(contact, ContactId(1));
                    assert_eq!(peer, remote.identity);
                    rejected = true;
                    break;
                }
                Err(error) => panic!("unexpected allowlist drive failure: {error}"),
            }
            remote.supervisor.drive_contact(ContactId(1), now).unwrap();
        }
        assert!(rejected);
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.carrier_binding_count, 0);
        assert_eq!(host.pending_admissions, 0);
        assert!(local.supervisor.contact_status().is_empty());
        let resources = local.supervisor.resource_snapshot().unwrap();
        assert_eq!(resources.current.admitted_contacts, 0);
        assert_eq!(resources.current.pre_authentication_contacts, 0);

        let sends_at_barrier = local_sends.load(Ordering::Relaxed);
        assert!(matches!(
            local.supervisor.drive_contact(ContactId(1), Instant::now()),
            Err(ContactSupervisorError::UnknownContact(ContactId(1)))
        ));
        assert_eq!(local_sends.load(Ordering::Relaxed), sends_at_barrier);

        let roots = [local.root.clone(), remote.root.clone()];
        drop(local);
        drop(remote);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn second_authenticated_contact_capacity_failure_retires_every_partial_grant() {
        let mut constrained = limits(2);
        constrained.admitted_contacts = 1;
        let mut center = test_node_with_allowed_and_limits(
            "admission-capacity-center",
            1,
            2,
            None,
            Some(constrained),
            false,
        );
        let mut left = test_node("admission-capacity-left", 2, 1);
        let mut right = test_node("admission-capacity-right", 3, 1);
        let (center_left, left_center, _, _) =
            MemoryLink::pair("capacity-left", center.identity, left.identity);
        let (center_right, right_center, center_right_sends, _) =
            MemoryLink::pair("capacity-right", center.identity, right.identity);

        open(
            &mut center.supervisor,
            ContactId(1),
            11,
            left.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(left.identity),
            },
            ContactDirection::Outbound,
            center_left,
        );
        open(
            &mut left.supervisor,
            ContactId(1),
            12,
            center.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(center.identity),
            },
            ContactDirection::Inbound,
            left_center,
        );
        open(
            &mut center.supervisor,
            ContactId(2),
            21,
            right.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(right.identity),
            },
            ContactDirection::Outbound,
            center_right,
        );
        open(
            &mut right.supervisor,
            ContactId(1),
            22,
            center.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(center.identity),
            },
            ContactDirection::Inbound,
            right_center,
        );

        for _ in 0..64 {
            let now = Instant::now();
            center.supervisor.drive_contact(ContactId(1), now).unwrap();
            left.supervisor.drive_contact(ContactId(1), now).unwrap();
            if center.supervisor.contact_status()[0].admitted
                && left.supervisor.contact_status()[0].admitted
            {
                break;
            }
        }
        assert!(
            center
                .supervisor
                .contact_status()
                .iter()
                .any(|status| status.contact == ContactId(1) && status.admitted)
        );
        assert!(!center.supervisor.take_evidence().is_empty());

        let resources_before_failure = center.supervisor.resource_snapshot().unwrap();
        let generation_before_failure =
            observed_authorization_generation(&center.supervisor).unwrap();
        let blob_quota_before_failure = center.supervisor.authority.blob_quota_snapshot().unwrap();
        let durable_digest_before_failure = canonical_durable_digest(&center.root);

        let mut capacity_failed_after_authentication = false;
        for _ in 0..64 {
            let now = Instant::now();
            match center.supervisor.drive_contact(ContactId(2), now) {
                Ok(_) => {}
                Err(ContactSupervisorError::Admission {
                    contact: ContactId(2),
                    error:
                        AdmissionTransactionError::Resource(ResourceBudgetError::Capacity(
                            "admitted contacts",
                        )),
                }) => {
                    capacity_failed_after_authentication = true;
                    break;
                }
                Err(error) => panic!("unexpected second-contact drive failure: {error}"),
            }
            right.supervisor.drive_contact(ContactId(1), now).unwrap();
        }
        assert!(capacity_failed_after_authentication);
        assert_eq!(
            center.supervisor.take_evidence(),
            vec![
                SharedNodeEvidenceTransition::AsterAuthenticated {
                    contact: ContactId(2),
                    peer: right.identity,
                },
                SharedNodeEvidenceTransition::AdmissionPrepared {
                    contact: ContactId(2),
                    peer: right.identity,
                },
                SharedNodeEvidenceTransition::AdmissionAborted {
                    contact: ContactId(2),
                    peer: right.identity,
                    reason: AdmissionAbortReason::Resource,
                },
            ]
        );
        let statuses = center.supervisor.contact_status();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].contact, ContactId(1));
        assert!(statuses[0].admitted);
        let resources = center.supervisor.resource_snapshot().unwrap();
        let expected_current = NodeResourceClaim {
            candidates: 2,
            admitted_contacts: 1,
            streams: 1,
            tasks: 1,
            frames: 32,
            inbound_bytes: 256 * 1_024,
            outbound_bytes: 256 * 1_024,
            descriptors: 1,
            ..NodeResourceClaim::default()
        };
        assert_eq!(resources.current, expected_current);
        assert_eq!(
            resources_before_failure.current,
            NodeResourceClaim {
                pre_authentication_contacts: 1,
                streams: 2,
                tasks: 2,
                frames: 64,
                inbound_bytes: 512 * 1_024,
                outbound_bytes: 512 * 1_024,
                descriptors: 2,
                ..expected_current
            }
        );
        assert_eq!(resources.rejections.admitted_contacts, 1);
        assert_eq!(resources.rejected_claims, 1);
        assert_eq!(
            observed_authorization_generation(&center.supervisor).unwrap(),
            generation_before_failure
        );
        assert_eq!(
            center.supervisor.authority.blob_quota_snapshot().unwrap(),
            blob_quota_before_failure
        );
        assert_eq!(
            canonical_durable_digest(&center.root),
            durable_digest_before_failure
        );
        let host = center.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 1);
        assert_eq!(host.authenticated_contacts, 1);
        assert_eq!(host.carrier_binding_count, 1);
        assert_eq!(host.pending_admissions, 0);

        let sends_at_failure = center_right_sends.load(Ordering::Relaxed);
        assert!(matches!(
            center
                .supervisor
                .drive_contact(ContactId(2), Instant::now()),
            Err(ContactSupervisorError::UnknownContact(ContactId(2)))
        ));
        assert_eq!(center_right_sends.load(Ordering::Relaxed), sends_at_failure);

        let roots = [center.root.clone(), left.root.clone(), right.root.clone()];
        drop(center);
        drop(left);
        drop(right);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn late_host_commit_failure_after_durable_admission_releases_every_partial_grant() {
        let mut local = test_node("late-host-commit-local", 1, 1);
        let mut remote = test_node("late-host-commit-remote", 2, 1);
        let (local_link, remote_link, local_sends, _) =
            MemoryLink::pair("late-host-commit", local.identity, remote.identity);
        let local_link_drops = Arc::new(AtomicU64::new(0));
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            remote.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(remote.identity),
            },
            ContactDirection::Outbound,
            DropTrackedLink {
                inner: local_link,
                drops: Arc::clone(&local_link_drops),
            },
        );
        open(
            &mut remote.supervisor,
            ContactId(1),
            2,
            local.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(local.identity),
            },
            ContactDirection::Inbound,
            remote_link,
        );

        let generation_before = local.supervisor.authorization_generation().unwrap();
        let blob_quota_before = local.supervisor.authority.blob_quota_snapshot().unwrap();
        let durable_digest_before = canonical_durable_digest(&local.root);
        local
            .supervisor
            .host
            .fail_next_authenticated_commit_for_test();

        let mut failed_after_durable_admission = false;
        for _ in 0..64 {
            let now = Instant::now();
            match local.supervisor.drive_contact(ContactId(1), now) {
                Ok(_) => {}
                Err(ContactSupervisorError::Admission {
                    contact: ContactId(1),
                    error: AdmissionTransactionError::Host(MeshHostError::StaleAdmission),
                }) => {
                    failed_after_durable_admission = true;
                    break;
                }
                Err(error) => panic!("unexpected late host-commit failure: {error}"),
            }
            remote.supervisor.drive_contact(ContactId(1), now).unwrap();
        }
        assert!(failed_after_durable_admission);
        assert_eq!(
            local.supervisor.take_evidence(),
            vec![
                SharedNodeEvidenceTransition::AsterAuthenticated {
                    contact: ContactId(1),
                    peer: remote.identity,
                },
                SharedNodeEvidenceTransition::AdmissionPrepared {
                    contact: ContactId(1),
                    peer: remote.identity,
                },
                SharedNodeEvidenceTransition::GenerationChecked {
                    contact: ContactId(1),
                    peer: remote.identity,
                    check: RuntimeAuthorizationGenerationCheck::Current {
                        generation: generation_before,
                    },
                },
                SharedNodeEvidenceTransition::AdmissionAborted {
                    contact: ContactId(1),
                    peer: remote.identity,
                    reason: AdmissionAbortReason::HostCommit,
                },
            ]
        );
        assert_eq!(local_link_drops.load(Ordering::Relaxed), 1);
        assert!(local.supervisor.contact_status().is_empty());
        assert_eq!(
            local.supervisor.authorization_generation().unwrap(),
            generation_before
        );
        assert_eq!(
            local.supervisor.authority.blob_quota_snapshot().unwrap(),
            blob_quota_before
        );
        assert_eq!(canonical_durable_digest(&local.root), durable_digest_before);
        let resources = local.supervisor.resource_snapshot().unwrap();
        assert_eq!(resources.current, resource_claims().candidate());
        assert_eq!(resources.high_water.pre_authentication_contacts, 1);
        assert_eq!(resources.high_water.admitted_contacts, 1);
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.carrier_binding_count, 0);
        assert_eq!(host.pending_admissions, 0);

        let sends_at_failure = local_sends.load(Ordering::Relaxed);
        assert!(matches!(
            local.supervisor.drive_contact(ContactId(1), Instant::now()),
            Err(ContactSupervisorError::UnknownContact(ContactId(1)))
        ));
        assert_eq!(local_sends.load(Ordering::Relaxed), sends_at_failure);
        local
            .supervisor
            .expire_candidate(candidate(1), locator(1), Instant::now())
            .unwrap();
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            NodeResourceClaim::default()
        );

        let roots = [local.root.clone(), remote.root.clone()];
        drop(local);
        drop(remote);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn panicking_durable_admission_retires_driver_link_host_and_all_contact_leases() {
        let mut local = test_node("panicking-durable-admission-local", 1, 1);
        let mut remote = test_node("panicking-durable-admission-remote", 2, 1);
        let (local_link, remote_link, local_sends, _) = MemoryLink::pair(
            "panicking-durable-admission",
            local.identity,
            remote.identity,
        );
        let local_link_drops = Arc::new(AtomicU64::new(0));
        open(
            &mut local.supervisor,
            ContactId(1),
            1,
            remote.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(remote.identity),
            },
            ContactDirection::Outbound,
            DropTrackedLink {
                inner: local_link,
                drops: Arc::clone(&local_link_drops),
            },
        );
        open(
            &mut remote.supervisor,
            ContactId(1),
            2,
            local.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(local.identity),
            },
            ContactDirection::Inbound,
            remote_link,
        );
        local
            .supervisor
            .contacts
            .get_mut(&ContactId(1))
            .unwrap()
            .panic_next_durable_admission = true;

        let mut observed_panic = false;
        for _ in 0..64 {
            let now = Instant::now();
            let result = catch_unwind(AssertUnwindSafe(|| {
                local.supervisor.drive_contact(ContactId(1), now)
            }));
            match result {
                Err(_) => {
                    observed_panic = true;
                    break;
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!("unexpected local drive failure: {error}"),
            }
            remote.supervisor.drive_contact(ContactId(1), now).unwrap();
        }
        assert!(observed_panic);
        assert_eq!(local_link_drops.load(Ordering::Relaxed), 1);
        assert!(local.supervisor.contact_status().is_empty());
        assert_eq!(
            local.supervisor.resource_snapshot().unwrap().current,
            resource_claims().candidate()
        );
        let host = local.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.pending_admissions, 0);
        assert_eq!(host.pending_dials, 0);
        assert_eq!(host.carrier_binding_count, 0);

        let sends_after_cleanup = local_sends.load(Ordering::Relaxed);
        assert!(matches!(
            local.supervisor.drive_contact(ContactId(1), Instant::now()),
            Err(ContactSupervisorError::UnknownContact(ContactId(1)))
        ));
        assert_eq!(local_sends.load(Ordering::Relaxed), sends_after_cleanup);

        let roots = [local.root.clone(), remote.root.clone()];
        drop(local);
        drop(remote);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn two_contacts_share_one_authority_and_mutation_stops_outbound_before_pump() {
        let mut center = test_node("center", 1, 2);
        let mut left = test_node("left", 2, 1);
        let mut right = test_node("right", 3, 1);
        let (center_left, left_center, center_left_sends, _) =
            MemoryLink::pair("center-left", center.identity, left.identity);
        let (center_right, right_center, _, _) =
            MemoryLink::pair("center-right", center.identity, right.identity);

        open(
            &mut center.supervisor,
            ContactId(1),
            11,
            left.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(left.identity),
            },
            ContactDirection::Outbound,
            center_left,
        );
        open(
            &mut left.supervisor,
            ContactId(1),
            12,
            center.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(center.identity),
            },
            ContactDirection::Inbound,
            left_center,
        );
        open(
            &mut center.supervisor,
            ContactId(2),
            21,
            right.identity,
            ContactSessionRole::Initiator {
                peer_hint: Some(right.identity),
            },
            ContactDirection::Outbound,
            center_right,
        );
        open(
            &mut right.supervisor,
            ContactId(1),
            22,
            center.identity,
            ContactSessionRole::Responder {
                peer_hint: Some(center.identity),
            },
            ContactDirection::Inbound,
            right_center,
        );

        for _ in 0..128 {
            let now = Instant::now();
            center.supervisor.drive_contact(ContactId(1), now).unwrap();
            left.supervisor.drive_contact(ContactId(1), now).unwrap();
            center.supervisor.drive_contact(ContactId(2), now).unwrap();
            right.supervisor.drive_contact(ContactId(1), now).unwrap();
            if center
                .supervisor
                .contact_status()
                .iter()
                .filter(|status| status.admitted)
                .count()
                == 2
                && left.supervisor.contact_status()[0].admitted
                && right.supervisor.contact_status()[0].admitted
            {
                break;
            }
        }
        assert_eq!(
            center
                .supervisor
                .contact_status()
                .iter()
                .filter(|status| status.admitted)
                .count(),
            2
        );
        assert_eq!(
            center
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .admitted_contacts,
            2
        );
        assert!(!center.supervisor.take_evidence().is_empty());
        assert_eq!(center.supervisor.fanout_inventory(ContactId(1)).unwrap(), 1);

        let mutation = center.supervisor.invalidate_authorization_generation();
        assert!(mutation.generation.is_ok());
        assert_eq!(
            mutation.contacts_requiring_reauthentication,
            vec![ContactId(1), ContactId(2)]
        );
        let sends_before = center_left_sends.load(Ordering::Relaxed);
        let evidence_counters_before = center.supervisor.evidence_counters();
        assert!(matches!(
            center
                .supervisor
                .drive_contact(ContactId(1), Instant::now()),
            Err(ContactSupervisorError::AuthorizationChanged(ContactId(1)))
        ));
        assert_eq!(
            center.supervisor.take_evidence(),
            vec![SharedNodeEvidenceTransition::GenerationChecked {
                contact: ContactId(1),
                peer: left.identity,
                check: RuntimeAuthorizationGenerationCheck::Changed {
                    expected_generation: 0,
                    observed_generation: 1,
                },
            }]
        );
        assert_eq!(
            center.supervisor.evidence_counters(),
            SharedNodeEvidenceCounters {
                authorization_generation_checks: evidence_counters_before
                    .authorization_generation_checks
                    + 1,
                authorization_generation_mismatches: evidence_counters_before
                    .authorization_generation_mismatches
                    + 1,
                authorization_generation_unavailable: evidence_counters_before
                    .authorization_generation_unavailable,
            }
        );
        assert_eq!(center_left_sends.load(Ordering::Relaxed), sends_before);
        assert_eq!(
            center
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .admitted_contacts,
            1
        );
        assert!(matches!(
            center
                .supervisor
                .drive_contact(ContactId(2), Instant::now()),
            Err(ContactSupervisorError::AuthorizationChanged(ContactId(2)))
        ));
        assert!(center.supervisor.contact_status().is_empty());
        assert_eq!(
            center
                .supervisor
                .resource_snapshot()
                .unwrap()
                .current
                .admitted_contacts,
            0
        );
        let host = center.supervisor.host_snapshot();
        assert_eq!(host.active_contacts, 0);
        assert_eq!(host.authenticated_contacts, 0);
        assert_eq!(host.pending_admissions, 0);
        // Carrier bindings are bounded locator provenance caches, not live
        // sessions or authorization grants; a new contact must still perform
        // a fresh Aster handshake and durable admission.
        assert_eq!(host.carrier_binding_count, 2);

        let roots = [center.root.clone(), left.root.clone(), right.root.clone()];
        drop(center);
        drop(left);
        drop(right);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn pump_generation_change_invalidates_and_wakes_every_admitted_contact() {
        let (mut center, left, right, center_left_sends, center_right_sends) =
            admitted_three_node_line("pump-generation-cascade");
        let generation_before = center.supervisor.authority.authorization_generation();
        assert_eq!(generation_before.as_ref().copied().unwrap(), 0);
        center
            .supervisor
            .authority
            .invalidate_authorization_generation()
            .unwrap();
        let left_sends_before = center_left_sends.load(Ordering::Relaxed);
        let right_sends_before = center_right_sends.load(Ordering::Relaxed);
        let now = Instant::now();
        assert!(matches!(
            center.supervisor.drive_contact_after_generation_snapshot(
                ContactId(1),
                now,
                generation_before,
            ),
            Err(ContactSupervisorError::AuthorizationChanged(ContactId(1)))
        ));
        assert_eq!(center_left_sends.load(Ordering::Relaxed), left_sends_before);
        assert_eq!(
            center_right_sends.load(Ordering::Relaxed),
            right_sends_before
        );
        assert_eq!(center.supervisor.next_wakeup(now), Some(now));
        let statuses = center.supervisor.contact_status();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].contact, ContactId(2));
        assert_eq!(statuses[0].authenticated_peer, Some(right.identity));
        assert!(statuses[0].admitted);
        assert!(!statuses[0].terminal);
        assert!(statuses[0].authorization_invalidated);
        assert!(matches!(
            center
                .supervisor
                .drive_contact(ContactId(2), Instant::now()),
            Err(ContactSupervisorError::AuthorizationChanged(ContactId(2)))
        ));
        assert_eq!(
            center_right_sends.load(Ordering::Relaxed),
            right_sends_before
        );
        assert!(center.supervisor.contact_status().is_empty());

        let roots = [center.root.clone(), left.root.clone(), right.root.clone()];
        drop(center);
        drop(left);
        drop(right);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn rejected_admin_result_after_generation_change_invalidates_all_but_duplicate_does_not() {
        let (mut center, left, right, center_left_sends, center_right_sends) =
            admitted_three_node_line("admin-generation-cascade");
        let generation_before = center.supervisor.authority.authorization_generation();
        center
            .supervisor
            .authority
            .invalidate_authorization_generation()
            .unwrap();
        let left_sends_before = center_left_sends.load(Ordering::Relaxed);
        let right_sends_before = center_right_sends.load(Ordering::Relaxed);
        assert!(
            center
                .supervisor
                .complete_authorization_control_application(
                    generation_before,
                    Err(BlobRuntimeError::Invalid("rejected mixed signed control")),
                )
                .is_err()
        );
        let statuses = center.supervisor.contact_status();
        assert_eq!(statuses.len(), 2);
        assert!(
            statuses.iter().all(|status| status.admitted
                && status.authorization_invalidated
                && !status.terminal)
        );
        let now = Instant::now();
        assert_eq!(center.supervisor.next_wakeup(now), Some(now));
        for contact in [ContactId(1), ContactId(2)] {
            assert!(matches!(
                center.supervisor.drive_contact(contact, Instant::now()),
                Err(ContactSupervisorError::AuthorizationChanged(changed)) if changed == contact
            ));
        }
        assert_eq!(center_left_sends.load(Ordering::Relaxed), left_sends_before);
        assert_eq!(
            center_right_sends.load(Ordering::Relaxed),
            right_sends_before
        );

        let roots = [center.root.clone(), left.root.clone(), right.root.clone()];
        drop(center);
        drop(left);
        drop(right);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }

        let (mut duplicate, duplicate_left, duplicate_right, _, _) =
            admitted_three_node_line("admin-duplicate-no-cascade");
        let generation = duplicate.supervisor.authority.authorization_generation();
        assert!(
            duplicate
                .supervisor
                .complete_authorization_control_application(
                    generation,
                    Err(BlobRuntimeError::Invalid("duplicate signed control")),
                )
                .is_err()
        );
        assert!(
            duplicate
                .supervisor
                .contact_status()
                .iter()
                .all(|status| status.admitted && !status.authorization_invalidated)
        );
        let roots = [
            duplicate.root.clone(),
            duplicate_left.root.clone(),
            duplicate_right.root.clone(),
        ];
        drop(duplicate);
        drop(duplicate_left);
        drop(duplicate_right);
        for root in roots {
            fs::remove_dir_all(root).unwrap();
        }
    }
}
