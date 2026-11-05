use crate::{DriverError, configuration};
use aster_contact::TransientLocator;
use aster_mesh::NodeId;
use bluer::{
    Address, AddressType,
    l2cap::{PSM_LE_DYN_START, PSM_LE_MAX, SocketAddr},
};
use std::{cmp::Ordering, time::Duration};

/// Largest protected carrier frame admitted by the Ring-1 evaluation profile.
pub const RING1_MAXIMUM_FRAME_BYTES: usize = 2 * 1024 * 1024;
/// Largest complete contact exchange admitted by the Ring-1 evaluation profile.
pub const RING1_MAXIMUM_EXCHANGE_BYTES: usize = 64 * 1024 * 1024;
/// Longest platform or authenticated-progress operation in the Ring-1 profile.
pub const RING1_MAXIMUM_DEADLINE: Duration = Duration::from_secs(30);

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
        let adapter_index = self.adapter_name.strip_prefix("hci").unwrap_or_default();
        if adapter_index.is_empty() || !adapter_index.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(configuration(
                "Bluetooth adapter name must be hci followed by digits",
            ));
        }
        if self.local_address == Address::any() || self.peer_address == Address::any() {
            return Err(configuration("Bluetooth addresses must be explicit"));
        }
        if self.local_address == self.peer_address {
            return Err(configuration(
                "local and peer Bluetooth addresses must differ",
            ));
        }
        if !is_le(self.local_address_type) || !is_le(self.peer_address_type) {
            return Err(configuration(
                "Bluetooth address types must be LE public or random",
            ));
        }
        if !(PSM_LE_DYN_START..=PSM_LE_MAX).contains(&self.psm) {
            return Err(configuration(
                "LE PSM is outside the unprivileged dynamic range",
            ));
        }
        if self.maximum_frame_bytes == 0
            || self.maximum_frame_bytes > RING1_MAXIMUM_FRAME_BYTES
            || self.maximum_frame_bytes > u32::MAX as usize
        {
            return Err(configuration(
                "carrier frame bound is outside the Ring-1 profile",
            ));
        }
        if self.maximum_exchange_bytes != RING1_MAXIMUM_EXCHANGE_BYTES {
            return Err(configuration(
                "exchange bound must equal the fixed Ring-1 ceiling",
            ));
        }
        if self.open_timeout.is_zero() || self.open_timeout > RING1_MAXIMUM_DEADLINE {
            return Err(configuration(
                "platform open deadline is outside the Ring-1 profile",
            ));
        }
        if self.operation_timeout.is_zero() || self.operation_timeout > RING1_MAXIMUM_DEADLINE {
            return Err(configuration(
                "contact deadline is outside the Ring-1 profile",
            ));
        }
        Ok(ValidatedLinkConfig(self))
    }
}

fn is_le(address_type: AddressType) -> bool {
    matches!(address_type, AddressType::LePublic | AddressType::LeRandom)
}

/// Shared link configuration that passed all local Ring-1 checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLinkConfig(LinkConfig);

impl ValidatedLinkConfig {
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
        let role = match self.local_mission_id.cmp(&self.peer_mission_id) {
            Ordering::Less => FixedRole::Initiator,
            Ordering::Greater => FixedRole::Listener,
            Ordering::Equal => {
                return Err(configuration(
                    "local and peer mission identities must differ",
                ));
            }
        };
        if self.contact_cadence.is_zero()
            || self.contact_cadence > SUPERVISOR_MAXIMUM_CONTACT_CADENCE
        {
            return Err(configuration(
                "contact cadence must be nonzero and at most 24 hours",
            ));
        }
        Ok(ValidatedSupervisorConfig {
            link: self.link.validate()?,
            role,
            peer_mission_id: self.peer_mission_id,
            contact_cadence: self.contact_cadence,
        })
    }
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
    use crate::DriverErrorKind;
    use bluer::{Address, AddressType};
    use std::{str::FromStr, time::Duration};

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
