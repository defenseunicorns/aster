use crate::{
    ControllerAdmissionPolicy, ControllerProbeLimits, DriverError, LeasedDiscoveryCredentialSet,
    configuration, policy::LifecycleCancellationObserver,
};
use aster_contact::TransientLocator;
use aster_mesh::NodeId;
use bluer::{
    Address, AddressType,
    l2cap::{PSM_LE_DYN_START, PSM_LE_MAX, SocketAddr},
};
use std::{cmp::Ordering, fmt, sync::Arc, time::Duration};

/// Largest protected carrier frame admitted by the Ring-1 evaluation profile.
pub const RING1_MAXIMUM_FRAME_BYTES: usize = 2 * 1024 * 1024;
/// Largest complete contact exchange admitted by the Ring-1 evaluation profile.
pub const RING1_MAXIMUM_EXCHANGE_BYTES: usize = 64 * 1024 * 1024;
/// Longest platform or authenticated-progress operation in the Ring-1 profile.
pub const RING1_MAXIMUM_DEADLINE: Duration = Duration::from_secs(30);
/// Initial unavailable epoch used when registering the automatic BTLE adapter.
pub const AUTOMATIC_BTLE_INITIAL_AVAILABILITY_EPOCH: u64 = 0;
/// Smallest kernel-reported MTU accepted in either direction for an Event contact.
///
/// LE Credit-Based L2CAP implementations must support 23-byte MTUs. Aster's
/// ordered-contact stream fragments larger records, so this baseline rejects
/// invalid links without imposing a larger hardware-specific policy.
pub const BTLE_EVENT_MINIMUM_DIRECTIONAL_MTU_BYTES: usize = 23;

const SUPERVISOR_MAXIMUM_CONTACT_CADENCE: Duration = Duration::from_secs(24 * 60 * 60);

/// Provisioned direction of one contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedRole {
    /// Opens one connection to the provisioned listener.
    Initiator,
    /// Advertises, listens, and accepts only the provisioned peer.
    Listener,
}

/// Role-independent Linux link configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkConfig {
    /// Exact BlueZ controller name, such as `hci0`.
    pub adapter_name: String,
    /// Exact provisioned local controller address.
    pub local_address: Address,
    /// Public or random type of the local address.
    pub local_address_type: AddressType,
    /// Exact provisioned peer address.
    pub peer_address: Address,
    /// Public or random type of the peer address.
    pub peer_address_type: AddressType,
    /// Provisioned unprivileged LE PSM.
    pub psm: u16,
    /// Maximum protected carrier frame.
    pub maximum_frame_bytes: usize,
    /// Maximum complete contact accounting.
    pub maximum_exchange_bytes: usize,
    /// Deadline for controller verification and socket establishment.
    pub open_timeout: Duration,
    /// Deadline for one ordered-contact operation.
    pub operation_timeout: Duration,
}

impl LinkConfig {
    /// Validates the shared local link configuration before BlueZ is contacted.
    pub fn validate(self) -> Result<ValidatedLinkConfig, DriverError> {
        validate_local_controller(
            &self.adapter_name,
            self.local_address,
            self.local_address_type,
        )?;
        if self.peer_address == Address::any() {
            return Err(configuration("Bluetooth addresses must be explicit"));
        }
        if self.local_address == self.peer_address {
            return Err(configuration(
                "local and peer Bluetooth addresses must differ",
            ));
        }
        if !is_le(self.peer_address_type) {
            return Err(configuration(
                "Bluetooth address types must be LE public or random",
            ));
        }
        if !(PSM_LE_DYN_START..=PSM_LE_MAX).contains(&self.psm) {
            return Err(configuration(
                "LE PSM is outside the unprivileged dynamic range",
            ));
        }
        validate_contact_bounds(
            self.maximum_frame_bytes,
            self.maximum_exchange_bytes,
            self.open_timeout,
            self.operation_timeout,
        )?;
        Ok(ValidatedLinkConfig(self))
    }
}

fn validate_local_controller(
    adapter_name: &str,
    local_address: Address,
    local_address_type: AddressType,
) -> Result<(), DriverError> {
    let adapter_index = adapter_name.strip_prefix("hci").unwrap_or_default();
    if adapter_index.is_empty() || !adapter_index.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(configuration(
            "Bluetooth adapter name must be hci followed by digits",
        ));
    }
    if local_address == Address::any() {
        return Err(configuration("Bluetooth addresses must be explicit"));
    }
    if !is_le(local_address_type) {
        return Err(configuration(
            "Bluetooth address types must be LE public or random",
        ));
    }
    Ok(())
}

fn validate_contact_bounds(
    maximum_frame_bytes: usize,
    maximum_exchange_bytes: usize,
    open_timeout: Duration,
    operation_timeout: Duration,
) -> Result<(), DriverError> {
    if maximum_frame_bytes == 0
        || maximum_frame_bytes > RING1_MAXIMUM_FRAME_BYTES
        || maximum_frame_bytes > u32::MAX as usize
    {
        return Err(configuration(
            "carrier frame bound is outside the Ring-1 profile",
        ));
    }
    if maximum_exchange_bytes != RING1_MAXIMUM_EXCHANGE_BYTES {
        return Err(configuration(
            "exchange bound must equal the fixed Ring-1 ceiling",
        ));
    }
    if open_timeout.is_zero() || open_timeout > RING1_MAXIMUM_DEADLINE {
        return Err(configuration(
            "platform open deadline is outside the Ring-1 profile",
        ));
    }
    if operation_timeout.is_zero() || operation_timeout > RING1_MAXIMUM_DEADLINE {
        return Err(configuration(
            "contact deadline is outside the Ring-1 profile",
        ));
    }
    Ok(())
}

fn is_le(address_type: AddressType) -> bool {
    matches!(address_type, AddressType::LePublic | AddressType::LeRandom)
}

/// Shared link configuration that passed all local Ring-1 checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLinkConfig(LinkConfig);

impl ValidatedLinkConfig {
    pub(crate) fn adapter_name(&self) -> &str {
        &self.0.adapter_name
    }

    pub(crate) const fn peer_address(&self) -> Address {
        self.0.peer_address
    }

    /// Applies a fixed role to an already-validated link configuration.
    pub fn for_role(&self, role: FixedRole) -> ValidatedConfig {
        ValidatedConfig {
            link: self.clone(),
            role,
        }
    }

    fn open_request(&self, role: FixedRole) -> OpenRequest {
        match role {
            FixedRole::Initiator => OpenRequest::Initiator {
                adapter_name: self.0.adapter_name.clone(),
                local: SocketAddr::new(self.0.local_address, self.0.local_address_type, 0),
                peer: SocketAddr::new(self.0.peer_address, self.0.peer_address_type, self.0.psm),
            },
            FixedRole::Listener => OpenRequest::Listener {
                adapter_name: self.0.adapter_name.clone(),
                local: SocketAddr::new(self.0.local_address, self.0.local_address_type, self.0.psm),
                expected_peer_address: self.0.peer_address,
                expected_peer_address_type: self.0.peer_address_type,
            },
        }
    }

    fn peer_locator(&self) -> Result<TransientLocator, DriverError> {
        let locator = format!("btle:{}:{}", self.0.peer_address, self.0.peer_address_type);
        TransientLocator::new(locator.into_bytes())
            .map_err(|_| configuration("peer locator is outside its carrier bound"))
    }

    pub(crate) const fn maximum_frame_bytes(&self) -> usize {
        self.0.maximum_frame_bytes
    }

    pub(crate) const fn maximum_exchange_bytes(&self) -> usize {
        self.0.maximum_exchange_bytes
    }

    pub(crate) const fn open_timeout(&self) -> Duration {
        self.0.open_timeout
    }

    pub(crate) const fn operation_timeout(&self) -> Duration {
        self.0.operation_timeout
    }
}

/// Complete fixed-role Linux driver configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverConfig {
    /// Shared provisioned Linux link.
    pub link: LinkConfig,
    /// Fixed direction for this process.
    pub role: FixedRole,
}

impl DriverConfig {
    /// Validates the shared link and applies the fixed role.
    pub fn validate(self) -> Result<ValidatedConfig, DriverError> {
        Ok(self.link.validate()?.for_role(self.role))
    }
}

/// Fixed-role configuration derived from a validated shared link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    link: ValidatedLinkConfig,
    role: FixedRole,
}

impl ValidatedConfig {
    /// Constructs the exact operation passed to the platform socket factory.
    pub fn open_request(&self) -> OpenRequest {
        self.link.open_request(self.role)
    }

    /// Fixed role of this process.
    pub const fn role(&self) -> FixedRole {
        self.role
    }

    /// Maximum complete exchange byte count.
    pub const fn maximum_exchange_bytes(&self) -> usize {
        self.link.maximum_exchange_bytes()
    }

    pub(crate) fn peer_locator(&self) -> Result<TransientLocator, DriverError> {
        self.link.peer_locator()
    }

    pub(crate) const fn maximum_frame_bytes(&self) -> usize {
        self.link.maximum_frame_bytes()
    }

    pub(crate) const fn open_timeout(&self) -> Duration {
        self.link.open_timeout()
    }

    pub(crate) const fn operation_timeout(&self) -> Duration {
        self.link.operation_timeout()
    }
}

/// Role-independent configuration for the unattended Linux supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisorConfig {
    /// Shared provisioned Linux link.
    pub link: LinkConfig,
    /// Local authenticated mission identity.
    pub local_mission_id: NodeId,
    /// Exact authenticated mission peer identity.
    pub peer_mission_id: NodeId,
    /// Delay between successful initiator contacts.
    pub contact_cadence: Duration,
}

impl SupervisorConfig {
    /// Validates the supervisor configuration and derives the deterministic role.
    pub fn validate(self) -> Result<ValidatedSupervisorConfig, DriverError> {
        let role = derive_role(self.local_mission_id, self.peer_mission_id)?;
        validate_contact_cadence(self.contact_cadence)?;
        Ok(ValidatedSupervisorConfig {
            link: self.link.validate()?,
            role,
            peer_mission_id: self.peer_mission_id,
            contact_cadence: self.contact_cadence,
        })
    }
}

fn derive_role(local: NodeId, peer: NodeId) -> Result<FixedRole, DriverError> {
    match local.cmp(&peer) {
        Ordering::Less => Ok(FixedRole::Initiator),
        Ordering::Greater => Ok(FixedRole::Listener),
        Ordering::Equal => Err(configuration(
            "local and peer mission identities must differ",
        )),
    }
}

fn validate_contact_cadence(contact_cadence: Duration) -> Result<(), DriverError> {
    if contact_cadence.is_zero() || contact_cadence > SUPERVISOR_MAXIMUM_CONTACT_CADENCE {
        return Err(configuration(
            "contact cadence must be nonzero and at most 24 hours",
        ));
    }
    Ok(())
}

/// Supervisor configuration with a validated shared link and derived role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSupervisorConfig {
    link: ValidatedLinkConfig,
    role: FixedRole,
    peer_mission_id: NodeId,
    contact_cadence: Duration,
}

impl ValidatedSupervisorConfig {
    /// Validated role-independent Linux link.
    pub const fn link(&self) -> &ValidatedLinkConfig {
        &self.link
    }

    /// Deterministic fixed role derived from full mission node IDs.
    pub const fn role(&self) -> FixedRole {
        self.role
    }

    /// Exact mission identity required from the authenticated peer.
    pub const fn peer_mission_id(&self) -> NodeId {
        self.peer_mission_id
    }

    /// Delay between successful initiator contacts.
    pub const fn contact_cadence(&self) -> Duration {
        self.contact_cadence
    }
}

/// Process-level rostered adapter mode.
pub enum RosteredAdapterConfig {
    /// No BTLE rostered listener, advertisement, scan, or supervisor exists.
    Off,
    /// Validate and own one rostered Linux supervisor configuration.
    Enabled(Box<RosteredSupervisorConfig>),
}

impl RosteredAdapterConfig {
    /// Validates configuration without constructing or contacting a platform.
    pub fn validate(self) -> Result<Option<ValidatedRosteredSupervisorConfig>, DriverError> {
        match self {
            Self::Off => Ok(None),
            Self::Enabled(config) => (*config).validate().map(Some),
        }
    }
}

impl fmt::Debug for RosteredAdapterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => formatter.write_str("RosteredAdapterConfig::Off"),
            Self::Enabled(config) => formatter
                .debug_tuple("RosteredAdapterConfig::Enabled")
                .field(config)
                .finish(),
        }
    }
}

/// Exact local controller selection for rostered discovery and contacts.
pub struct ControllerConfig {
    /// Exact BlueZ controller name, such as `hci0`.
    pub adapter_name: String,
    /// Exact provisioned local controller address.
    pub local_address: Address,
    /// Public or random type of the local controller address.
    pub local_address_type: AddressType,
}

impl ControllerConfig {
    fn validate(self) -> Result<ValidatedControllerConfig, DriverError> {
        validate_local_controller(
            &self.adapter_name,
            self.local_address,
            self.local_address_type,
        )?;
        Ok(ValidatedControllerConfig {
            config: self,
            epoch: None,
        })
    }
}

impl fmt::Debug for ControllerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerConfig")
            .field("adapter_name", &self.adapter_name)
            .field("local_identity", &"[REDACTED]")
            .finish()
    }
}

/// Validated exact local controller selection.
pub struct ValidatedControllerConfig {
    config: ControllerConfig,
    epoch: Option<ControllerEpochBinding>,
}

struct ControllerEpochBinding {
    generation: u64,
    cancellation: LifecycleCancellationObserver,
}

#[derive(Clone)]
pub(crate) struct ControllerOperationBinding {
    adapter_name: String,
    local_address: Address,
    local_address_type: AddressType,
    epoch: Option<ControllerEpochBinding>,
}

impl Clone for ControllerEpochBinding {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            cancellation: self.cancellation.clone(),
        }
    }
}

impl ControllerOperationBinding {
    pub(crate) fn ensure_current(&self) -> Result<(), DriverError> {
        ensure_epoch_current(self.epoch.as_ref())
    }

    pub(crate) fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    pub(crate) const fn local_address(&self) -> Address {
        self.local_address
    }

    pub(crate) const fn local_address_type(&self) -> AddressType {
        self.local_address_type
    }
}

fn ensure_epoch_current(epoch: Option<&ControllerEpochBinding>) -> Result<(), DriverError> {
    if epoch.is_some_and(|epoch| epoch.generation == 0 || epoch.cancellation.is_cancelled()) {
        return Err(DriverError::new(
            crate::DriverErrorKind::Cancelled,
            "controller epoch is stale",
        ));
    }
    Ok(())
}

impl ValidatedControllerConfig {
    pub(crate) fn for_epoch(
        adapter_name: String,
        local_address: Address,
        local_address_type: AddressType,
        generation: u64,
        cancellation: LifecycleCancellationObserver,
    ) -> Result<Self, DriverError> {
        let config = ControllerConfig {
            adapter_name,
            local_address,
            local_address_type,
        }
        .validate()?;
        Ok(Self {
            config: config.config,
            epoch: Some(ControllerEpochBinding {
                generation,
                cancellation,
            }),
        })
    }

    pub(crate) fn ensure_current(&self) -> Result<(), DriverError> {
        ensure_epoch_current(self.epoch.as_ref())
    }

    pub(crate) fn operation_binding(&self) -> ControllerOperationBinding {
        ControllerOperationBinding {
            adapter_name: self.config.adapter_name.clone(),
            local_address: self.config.local_address,
            local_address_type: self.config.local_address_type,
            epoch: self.epoch.clone(),
        }
    }

    /// Exact BlueZ controller name.
    pub fn adapter_name(&self) -> &str {
        &self.config.adapter_name
    }

    /// Exact local controller address.
    pub const fn local_address(&self) -> Address {
        self.config.local_address
    }

    /// Exact local controller LE address type.
    pub const fn local_address_type(&self) -> AddressType {
        self.config.local_address_type
    }
}

impl fmt::Debug for ValidatedControllerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.config.fmt(formatter)
    }
}

/// Fixed rostered-discovery profile and its host-authorized credentials.
pub struct RosteredDiscoveryConfig {
    /// Host-authorized short-lived discovery credentials.
    pub credentials: LeasedDiscoveryCredentialSet,
}

impl RosteredDiscoveryConfig {
    fn validate(self) -> ValidatedRosteredDiscoveryConfig {
        ValidatedRosteredDiscoveryConfig(self)
    }
}

impl fmt::Debug for RosteredDiscoveryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosteredDiscoveryConfig([REDACTED])")
    }
}

/// Validated fixed discovery profile and its leased credentials.
pub struct ValidatedRosteredDiscoveryConfig(RosteredDiscoveryConfig);

impl ValidatedRosteredDiscoveryConfig {
    /// Host-authorized credentials owned by this adapter epoch.
    pub const fn credentials(&self) -> &LeasedDiscoveryCredentialSet {
        &self.0.credentials
    }
}

impl fmt::Debug for ValidatedRosteredDiscoveryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Existing protected-contact bounds reused by the rostered adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactLimits {
    /// Maximum protected carrier frame.
    pub maximum_frame_bytes: usize,
    /// Maximum complete contact accounting.
    pub maximum_exchange_bytes: usize,
    /// Deadline for controller and socket establishment.
    pub open_timeout: Duration,
    /// Deadline for one ordered-contact operation.
    pub operation_timeout: Duration,
}

impl ContactLimits {
    fn validate(self) -> Result<ValidatedContactLimits, DriverError> {
        validate_contact_bounds(
            self.maximum_frame_bytes,
            self.maximum_exchange_bytes,
            self.open_timeout,
            self.operation_timeout,
        )?;
        Ok(ValidatedContactLimits(self))
    }
}

/// Validated protected-contact bounds for rostered socket operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedContactLimits(ContactLimits);

impl ValidatedContactLimits {
    /// Maximum protected carrier frame.
    pub const fn maximum_frame_bytes(self) -> usize {
        self.0.maximum_frame_bytes
    }

    /// Maximum complete contact accounting.
    pub const fn maximum_exchange_bytes(self) -> usize {
        self.0.maximum_exchange_bytes
    }

    /// Controller and socket establishment deadline.
    pub const fn open_timeout(self) -> Duration {
        self.0.open_timeout
    }

    /// Ordered-contact operation deadline.
    pub const fn operation_timeout(self) -> Duration {
        self.0.operation_timeout
    }
}

/// Rostered Linux configuration with no remote locator, PSM, or discovery knobs.
pub struct RosteredSupervisorConfig {
    /// Exact local controller selection.
    pub controller: ControllerConfig,
    /// Fixed discovery policy and leased credentials.
    pub discovery: RosteredDiscoveryConfig,
    /// Local authenticated mission identity.
    pub local_mission_id: NodeId,
    /// Exact authenticated mission peer identity.
    pub peer_mission_id: NodeId,
    /// Delay between successful preferred-direction contacts.
    pub contact_cadence: Duration,
    /// Existing protected-contact limits.
    pub contact_limits: ContactLimits,
}

/// Automatic rostered Linux policy with no detected controller identity.
pub struct AutomaticRosteredSupervisorConfig {
    /// Immutable controller admission and support policy.
    pub controller_policy: ControllerAdmissionPolicy,
    /// Bounds for one serialized compatibility-probe sweep.
    pub controller_probe_limits: ControllerProbeLimits,
    /// Fixed discovery policy and leased credentials.
    pub discovery: RosteredDiscoveryConfig,
    /// Local authenticated mission identity.
    pub local_mission_id: NodeId,
    /// Stable local mission authority that scopes automatic coordinator tickets.
    pub local_mission_authority_id: NodeId,
    /// Exact authenticated mission peer identity.
    pub peer_mission_id: NodeId,
    /// Delay between successful preferred-direction contacts.
    pub contact_cadence: Duration,
    /// Existing protected-contact limits.
    pub contact_limits: ContactLimits,
}

impl AutomaticRosteredSupervisorConfig {
    /// Validates immutable policy without requiring present Bluetooth hardware.
    pub fn validate(self) -> Result<ValidatedAutomaticRosteredSupervisorConfig, DriverError> {
        let Self {
            controller_policy,
            controller_probe_limits,
            discovery,
            local_mission_id,
            local_mission_authority_id,
            peer_mission_id,
            contact_cadence,
            contact_limits,
        } = self;
        validate_probe_limits(controller_probe_limits)?;
        validate_contact_cadence(contact_cadence)?;
        let role = derive_role(local_mission_id, peer_mission_id)?;
        Ok(ValidatedAutomaticRosteredSupervisorConfig {
            controller_policy,
            controller_probe_limits,
            discovery: Arc::new(discovery.validate()),
            local_mission_id,
            local_mission_authority_id,
            peer_mission_id,
            role,
            contact_cadence,
            contact_limits: contact_limits.validate()?,
        })
    }
}

impl fmt::Debug for AutomaticRosteredSupervisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutomaticRosteredSupervisorConfig")
            .field("controller_policy", &self.controller_policy)
            .field("controller_probe_limits", &self.controller_probe_limits)
            .field("discovery", &self.discovery)
            .field("local_mission_authority_id", &"[REDACTED]")
            .field("role", &"derived after validation")
            .field("contact_cadence", &self.contact_cadence)
            .field("contact_limits", &self.contact_limits)
            .field("transient_and_mission_material", &"[REDACTED]")
            .finish()
    }
}

fn validate_probe_limits(limits: ControllerProbeLimits) -> Result<(), DriverError> {
    if limits.operation().is_zero()
        || limits.candidate().is_zero()
        || limits.sweep().is_zero()
        || limits.operation() > limits.candidate()
        || limits.candidate() > limits.sweep()
    {
        return Err(configuration(
            "controller probe limits must be nonzero and monotonically bounded",
        ));
    }
    Ok(())
}

impl RosteredSupervisorConfig {
    /// Validates only local controller, mission, and existing contact policy.
    pub fn validate(self) -> Result<ValidatedRosteredSupervisorConfig, DriverError> {
        let Self {
            controller,
            discovery,
            local_mission_id,
            peer_mission_id,
            contact_cadence,
            contact_limits,
        } = self;
        let controller = controller.validate()?;
        let discovery = RosteredDiscoveryStorage::Fixed(discovery.validate());
        let contact_limits = contact_limits.validate()?;
        validate_contact_cadence(contact_cadence)?;
        let role = derive_role(local_mission_id, peer_mission_id)?;
        Ok(ValidatedRosteredSupervisorConfig {
            controller,
            discovery,
            local_mission_id,
            local_mission_authority_id: local_mission_id,
            peer_mission_id,
            role,
            contact_cadence,
            contact_limits,
        })
    }
}

impl fmt::Debug for RosteredSupervisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RosteredSupervisorConfig")
            .field("controller", &self.controller)
            .field("discovery", &self.discovery)
            .field("local_mission_id", &"[REDACTED]")
            .field("peer_mission_id", &"[REDACTED]")
            .field("role", &"derived after validation")
            .field("contact_cadence", &self.contact_cadence)
            .field("contact_limits", &self.contact_limits)
            .finish_non_exhaustive()
    }
}

/// Fully validated rostered Linux supervisor input.
pub struct ValidatedRosteredSupervisorConfig {
    controller: ValidatedControllerConfig,
    discovery: RosteredDiscoveryStorage,
    local_mission_id: NodeId,
    local_mission_authority_id: NodeId,
    peer_mission_id: NodeId,
    role: FixedRole,
    contact_cadence: Duration,
    contact_limits: ValidatedContactLimits,
}

enum RosteredDiscoveryStorage {
    Fixed(ValidatedRosteredDiscoveryConfig),
    Automatic(Arc<ValidatedRosteredDiscoveryConfig>),
}

impl fmt::Debug for RosteredDiscoveryStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(discovery) => discovery.fmt(formatter),
            Self::Automatic(discovery) => discovery.fmt(formatter),
        }
    }
}

/// Validated automatic roster policy containing no detected controller identity.
pub struct ValidatedAutomaticRosteredSupervisorConfig {
    controller_policy: ControllerAdmissionPolicy,
    controller_probe_limits: ControllerProbeLimits,
    discovery: Arc<ValidatedRosteredDiscoveryConfig>,
    local_mission_id: NodeId,
    local_mission_authority_id: NodeId,
    peer_mission_id: NodeId,
    role: FixedRole,
    contact_cadence: Duration,
    contact_limits: ValidatedContactLimits,
}

impl ValidatedAutomaticRosteredSupervisorConfig {
    /// Immutable controller admission policy.
    pub const fn controller_policy(&self) -> &ControllerAdmissionPolicy {
        &self.controller_policy
    }

    /// Serialized compatibility-probe bounds.
    pub const fn controller_probe_limits(&self) -> ControllerProbeLimits {
        self.controller_probe_limits
    }

    /// Local authenticated mission identity.
    pub const fn local_mission_id(&self) -> NodeId {
        self.local_mission_id
    }

    /// Stable local mission authority that scopes automatic coordinator tickets.
    pub const fn local_mission_authority_id(&self) -> NodeId {
        self.local_mission_authority_id
    }

    /// Exact authenticated mission peer identity.
    pub const fn peer_mission_id(&self) -> NodeId {
        self.peer_mission_id
    }

    /// Preferred direction derived solely from full mission identities.
    pub const fn role(&self) -> FixedRole {
        self.role
    }

    pub(crate) fn discovery_credentials_expires_at(&self) -> std::time::Instant {
        self.discovery.credentials().expires_at()
    }

    pub(crate) fn for_controller(
        &self,
        adapter_name: String,
        local_address: Address,
        local_address_type: AddressType,
        generation: u64,
        cancellation: LifecycleCancellationObserver,
    ) -> Result<ValidatedRosteredSupervisorConfig, DriverError> {
        Ok(ValidatedRosteredSupervisorConfig {
            controller: ValidatedControllerConfig::for_epoch(
                adapter_name,
                local_address,
                local_address_type,
                generation,
                cancellation,
            )?,
            discovery: RosteredDiscoveryStorage::Automatic(self.discovery.clone()),
            local_mission_id: self.local_mission_id,
            local_mission_authority_id: self.local_mission_authority_id,
            peer_mission_id: self.peer_mission_id,
            role: self.role,
            contact_cadence: self.contact_cadence,
            contact_limits: self.contact_limits,
        })
    }
}

impl fmt::Debug for ValidatedAutomaticRosteredSupervisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedAutomaticRosteredSupervisorConfig")
            .field("controller_policy", &self.controller_policy)
            .field("controller_probe_limits", &self.controller_probe_limits)
            .field("discovery", &self.discovery)
            .field("role", &self.role)
            .field("contact_cadence", &self.contact_cadence)
            .field("contact_limits", &self.contact_limits)
            .field("transient_and_mission_material", &"[REDACTED]")
            .finish()
    }
}

impl ValidatedRosteredSupervisorConfig {
    /// Exact local BlueZ controller name.
    pub fn adapter_name(&self) -> &str {
        self.controller.adapter_name()
    }

    /// Exact local controller address.
    pub const fn local_address(&self) -> Address {
        self.controller.local_address()
    }

    /// Exact local controller LE address type.
    pub const fn local_address_type(&self) -> AddressType {
        self.controller.local_address_type()
    }

    /// Local authenticated mission identity.
    pub const fn local_mission_id(&self) -> NodeId {
        self.local_mission_id
    }

    pub(crate) const fn local_mission_authority_id(&self) -> NodeId {
        self.local_mission_authority_id
    }

    /// Exact mission peer identity required after carrier discovery.
    pub const fn peer_mission_id(&self) -> NodeId {
        self.peer_mission_id
    }

    /// Preferred direction derived solely from full mission identities.
    pub const fn role(&self) -> FixedRole {
        self.role
    }

    /// Maximum protected carrier frame.
    pub const fn maximum_frame_bytes(&self) -> usize {
        self.contact_limits.maximum_frame_bytes()
    }

    /// Maximum complete contact accounting.
    pub const fn maximum_exchange_bytes(&self) -> usize {
        self.contact_limits.maximum_exchange_bytes()
    }

    /// Controller and socket establishment deadline.
    pub const fn open_timeout(&self) -> Duration {
        self.contact_limits.open_timeout()
    }

    /// Ordered-contact operation deadline.
    pub const fn operation_timeout(&self) -> Duration {
        self.contact_limits.operation_timeout()
    }

    /// Delay between successful preferred-direction contacts.
    pub const fn contact_cadence(&self) -> Duration {
        self.contact_cadence
    }

    /// Host-authorized discovery credentials owned by this adapter epoch.
    pub const fn discovery_credentials(&self) -> &LeasedDiscoveryCredentialSet {
        self.discovery().credentials()
    }

    /// Validated local controller selection passed to Linux platform seams.
    pub const fn controller(&self) -> &ValidatedControllerConfig {
        &self.controller
    }

    /// Fixed discovery profile and leased credential owner.
    pub const fn discovery(&self) -> &ValidatedRosteredDiscoveryConfig {
        match &self.discovery {
            RosteredDiscoveryStorage::Fixed(discovery) => discovery,
            RosteredDiscoveryStorage::Automatic(_) => {
                panic!("automatic epoch discovery is crate-private")
            }
        }
    }

    pub(crate) fn epoch_discovery_credentials(&self) -> &LeasedDiscoveryCredentialSet {
        match &self.discovery {
            RosteredDiscoveryStorage::Fixed(discovery) => discovery.credentials(),
            RosteredDiscoveryStorage::Automatic(discovery) => discovery.credentials(),
        }
    }

    /// Existing validated protected-contact bounds.
    pub const fn contact_limits(&self) -> ValidatedContactLimits {
        self.contact_limits
    }
}

impl fmt::Debug for ValidatedRosteredSupervisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRosteredSupervisorConfig")
            .field("controller", &self.controller)
            .field("discovery", &self.discovery)
            .field("role", &self.role)
            .field("contact_cadence", &self.contact_cadence)
            .field("contact_limits", &self.contact_limits)
            .field("transient_and_mission_material", &"[REDACTED]")
            .finish()
    }
}

/// Exact socket operation selected from validated configuration and role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenRequest {
    /// Bind the configured local controller address and connect to the peer PSM.
    Initiator {
        /// Exact BlueZ adapter name verified before opening the socket.
        adapter_name: String,
        /// Exact local address; its PSM is zero for a client-side ephemeral bind.
        local: SocketAddr,
        /// Exact provisioned remote address and dynamic PSM.
        peer: SocketAddr,
    },
    /// Bind the configured local controller/PSM and accept the provisioned peer.
    Listener {
        /// Exact BlueZ adapter name verified before advertising.
        adapter_name: String,
        /// Exact local address and dynamic PSM.
        local: SocketAddr,
        /// Only accepted remote Bluetooth address.
        expected_peer_address: Address,
        /// Only accepted remote Bluetooth address type.
        expected_peer_address_type: AddressType,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControllerAdmissionPolicy, ControllerProbeLimits, DiscoveryCredential, DiscoveryGeneration,
        DiscoverySecret, DriverErrorKind, LeasedDiscoveryCredentialSet,
    };
    use bluer::{Address, AddressType};
    use std::{
        str::FromStr,
        time::{Duration, Instant},
    };

    fn address(value: &str) -> Address {
        Address::from_str(value).expect("test Bluetooth address")
    }

    fn link() -> LinkConfig {
        LinkConfig {
            adapter_name: "hci7".to_owned(),
            local_address: address("02:00:00:00:00:01"),
            local_address_type: AddressType::LeRandom,
            peer_address: address("02:00:00:00:00:02"),
            peer_address_type: AddressType::LePublic,
            psm: 0x0081,
            maximum_frame_bytes: 2 * 1024 * 1024,
            maximum_exchange_bytes: 64 * 1024 * 1024,
            open_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(30),
        }
    }

    fn driver(role: FixedRole) -> DriverConfig {
        DriverConfig { link: link(), role }
    }

    fn rostered(local_mission_id: NodeId, peer_mission_id: NodeId) -> RosteredAdapterConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        RosteredAdapterConfig::Enabled(Box::new(RosteredSupervisorConfig {
            controller: ControllerConfig {
                adapter_name: "hci7".to_owned(),
                local_address: address("02:00:00:00:00:01"),
                local_address_type: AddressType::LeRandom,
            },
            discovery: RosteredDiscoveryConfig { credentials },
            local_mission_id,
            peer_mission_id,
            contact_cadence: Duration::from_secs(60),
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        }))
    }

    fn automatic_rostered(
        local_mission_id: NodeId,
        local_mission_authority_id: NodeId,
        peer_mission_id: NodeId,
    ) -> AutomaticRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        AutomaticRosteredSupervisorConfig {
            controller_policy: ControllerAdmissionPolicy::default(),
            controller_probe_limits: ControllerProbeLimits::new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(8),
            ),
            discovery: RosteredDiscoveryConfig { credentials },
            local_mission_id,
            local_mission_authority_id,
            peer_mission_id,
            contact_cadence: Duration::from_secs(60),
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        }
    }

    mod automatic_controller {
        use super::*;

        const fn fixed_discovery_accessors_are_const(
            config: &ValidatedRosteredSupervisorConfig,
        ) -> (
            &LeasedDiscoveryCredentialSet,
            &ValidatedRosteredDiscoveryConfig,
        ) {
            (config.discovery_credentials(), config.discovery())
        }

        #[test]
        fn automatic_config_validates_without_present_controller() {
            let validated = automatic_rostered([0x11; 32], [0x33; 32], [0x22; 32])
                .validate()
                .unwrap();

            assert_eq!(validated.role(), FixedRole::Initiator);
            assert_eq!(validated.local_mission_id(), [0x11; 32]);
            assert_eq!(validated.local_mission_authority_id(), [0x33; 32]);
            assert_eq!(validated.peer_mission_id(), [0x22; 32]);
        }

        #[test]
        fn fixed_evaluation_config_remains_exact_controller_bound() {
            let validated = rostered([0x11; 32], [0x22; 32])
                .validate()
                .unwrap()
                .unwrap();

            assert_eq!(validated.adapter_name(), "hci7");
            assert_eq!(validated.local_address(), address("02:00:00:00:00:01"));
            assert_eq!(validated.local_address_type(), AddressType::LeRandom);
            let _ = fixed_discovery_accessors_are_const(&validated);
        }
    }

    #[test]
    fn rostered_off_validates_to_no_runtime_configuration() {
        assert!(RosteredAdapterConfig::Off.validate().unwrap().is_none());
    }

    #[test]
    fn rostered_enabled_owns_only_local_controller_mission_and_contact_bounds() {
        let local = [0x11; 32];
        let peer = [0x22; 32];
        let validated = rostered(local, peer).validate().unwrap().unwrap();

        assert_eq!(validated.adapter_name(), "hci7");
        assert_eq!(validated.local_address(), address("02:00:00:00:00:01"));
        assert_eq!(validated.local_address_type(), AddressType::LeRandom);
        assert_eq!(validated.local_mission_id(), local);
        assert_eq!(validated.peer_mission_id(), peer);
        assert_eq!(validated.role(), FixedRole::Initiator);
        assert_eq!(validated.maximum_frame_bytes(), RING1_MAXIMUM_FRAME_BYTES);
        assert_eq!(
            validated.maximum_exchange_bytes(),
            RING1_MAXIMUM_EXCHANGE_BYTES
        );
        assert_eq!(validated.open_timeout(), Duration::from_secs(5));
        assert_eq!(validated.operation_timeout(), Duration::from_secs(30));
        assert_eq!(validated.contact_cadence(), Duration::from_secs(60));
    }

    #[test]
    fn rostered_roles_are_complementary_and_invalid_config_stays_pure() {
        let lower = [0x11; 32];
        let higher = [0x22; 32];
        assert_eq!(
            rostered(lower, higher).validate().unwrap().unwrap().role(),
            FixedRole::Initiator
        );
        assert_eq!(
            rostered(higher, lower).validate().unwrap().unwrap().role(),
            FixedRole::Listener
        );

        let RosteredAdapterConfig::Enabled(mut invalid) = rostered(lower, higher) else {
            unreachable!()
        };
        invalid.controller.adapter_name = "peer-addresses-are-not-config".to_owned();
        assert_eq!(
            RosteredAdapterConfig::Enabled(invalid)
                .validate()
                .unwrap_err()
                .kind(),
            DriverErrorKind::Configuration
        );
    }

    #[test]
    fn configuration_rejects_invalid_adapter_addresses_psm_bounds_and_deadlines() {
        let mut candidate = link();
        candidate.adapter_name.clear();
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.local_address = Address::any();
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.peer_address_type = AddressType::BrEdr;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.psm = bluer::l2cap::PSM_LE_DYN_START - 1;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.maximum_frame_bytes = 0;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.maximum_exchange_bytes = candidate.maximum_frame_bytes - 1;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.maximum_exchange_bytes = RING1_MAXIMUM_EXCHANGE_BYTES - 1;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.open_timeout = Duration::ZERO;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );

        let mut candidate = link();
        candidate.operation_timeout = Duration::ZERO;
        assert_eq!(
            candidate.validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );
    }

    #[test]
    fn fixed_roles_construct_exact_bound_client_and_listener_requests() {
        let initiator = driver(FixedRole::Initiator).validate().unwrap();
        assert_eq!(
            initiator.open_request(),
            OpenRequest::Initiator {
                adapter_name: "hci7".to_owned(),
                local: bluer::l2cap::SocketAddr::new(
                    address("02:00:00:00:00:01"),
                    AddressType::LeRandom,
                    0,
                ),
                peer: bluer::l2cap::SocketAddr::new(
                    address("02:00:00:00:00:02"),
                    AddressType::LePublic,
                    0x0081,
                ),
            }
        );

        let listener = driver(FixedRole::Listener).validate().unwrap();
        assert_eq!(
            listener.open_request(),
            OpenRequest::Listener {
                adapter_name: "hci7".to_owned(),
                local: bluer::l2cap::SocketAddr::new(
                    address("02:00:00:00:00:01"),
                    AddressType::LeRandom,
                    0x0081,
                ),
                expected_peer_address: address("02:00:00:00:00:02"),
                expected_peer_address_type: AddressType::LePublic,
            }
        );
    }

    #[test]
    fn supervisor_role_is_complementary_and_stable() {
        let local = [0; 32];
        let mut peer = [0; 32];
        peer[31] = 1;

        let lower = SupervisorConfig {
            link: link(),
            local_mission_id: local,
            peer_mission_id: peer,
            contact_cadence: Duration::from_secs(60),
        }
        .validate()
        .unwrap();
        let higher = SupervisorConfig {
            link: link(),
            local_mission_id: peer,
            peer_mission_id: local,
            contact_cadence: Duration::from_secs(60),
        }
        .validate()
        .unwrap();

        assert_eq!(lower.role(), FixedRole::Initiator);
        assert_eq!(higher.role(), FixedRole::Listener);
        assert_eq!(lower.peer_mission_id(), peer);
        assert_eq!(higher.peer_mission_id(), local);
    }

    #[test]
    fn supervisor_rejects_equal_mission_ids() {
        assert_eq!(
            SupervisorConfig {
                link: link(),
                local_mission_id: [7; 32],
                peer_mission_id: [7; 32],
                contact_cadence: Duration::from_secs(60),
            }
            .validate()
            .unwrap_err()
            .kind(),
            DriverErrorKind::Configuration
        );
    }

    #[test]
    fn supervisor_rejects_zero_or_over_24_hour_cadence() {
        let config = |contact_cadence| SupervisorConfig {
            link: link(),
            local_mission_id: [1; 32],
            peer_mission_id: [2; 32],
            contact_cadence,
        };

        assert_eq!(
            config(Duration::ZERO).validate().unwrap_err().kind(),
            DriverErrorKind::Configuration
        );
        assert_eq!(
            config(Duration::from_secs(24 * 60 * 60 + 1))
                .validate()
                .unwrap_err()
                .kind(),
            DriverErrorKind::Configuration
        );
        assert_eq!(
            config(Duration::from_secs(60))
                .validate()
                .unwrap()
                .contact_cadence(),
            Duration::from_secs(60)
        );
        assert_eq!(
            config(Duration::from_secs(24 * 60 * 60))
                .validate()
                .unwrap()
                .contact_cadence(),
            Duration::from_secs(24 * 60 * 60)
        );
    }
}
