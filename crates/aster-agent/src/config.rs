use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    io::Read as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use aster_iroh::{PinnedRelay, RelayUrl};
use aster_mesh::ProvisioningLoadId;
use aster_node::{
    EventEmissionPolicy, MissionExpectedPeer, NodeConfigOptions, SelectedForwardingConfig,
    StoreLimits,
};
use aster_redb_store::{
    CUSTODY_EMERGENCY_BYTE_RESERVE, CUSTODY_EMERGENCY_ITEM_RESERVE, CustodyQuota,
    EventOperationLimits, MAX_CONTROL_BYTES, MAX_CONTROL_ITEMS,
};
use serde::Deserialize;

use crate::{MAX_AGENT_MESSAGE_BYTES, credentials::load_startup_credentials};

const SYSTEMD_SCHEMA_VERSION: u32 = 1;
const COMPOSE_SCHEMA_VERSION: u32 = 2;
const COMPOSE_CLIENT_TOKEN_PATH: &str = "/run/secrets/aster-client-token";
const COMPOSE_MISSION_ACTIVATION_PATH: &str = "/run/secrets/aster-mission-activation";
const COMPOSE_STATE_PATH: &str = "/var/lib/aster";
const MAX_CONFIGURED_PEERS: usize = 256;
const MAX_SYNC_INTERVAL_MS: u64 = 60_000;
const MAX_APPLICATION_CONNECTIONS: usize = 64;
const MAX_UNAUTHENTICATED_APPLICATION_CONNECTIONS: usize = 8;
const MAX_APPLICATION_HEADER_BYTES: usize = 16 * 1024;
const MAX_FIRST_AUTHENTICATION_TIMEOUT_MS: u64 = 5_000;
const MAX_IN_FLIGHT_APPLICATION_REQUESTS: usize = 64;
const MAX_SHUTDOWN_GRACE_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigReason {
    AbsolutePathRequired,
    DuplicateField,
    DistinctListenersRequired,
    DuplicatePeerCarrier,
    DuplicatePeerMission,
    CredentialBoundary,
    FileAccess,
    InvalidMissionLoadId,
    InvalidEmissionPolicy,
    InvalidPeer,
    InvalidRelay,
    InvalidStorage,
    InvalidOperationStorage,
    LimitOutOfRange,
    LoopbackListenerRequired,
    MissingField,
    StorageTooSmall,
    StateBoundary,
    SyncIntervalOutOfRange,
    Syntax,
    TooManyPeers,
    UnknownField,
    UnsupportedSchemaVersion,
}

impl ConfigReason {
    const fn message(self) -> &'static str {
        match self {
            Self::AbsolutePathRequired => "configuration path must be absolute",
            Self::DuplicateField => "configuration contains a duplicate field",
            Self::DistinctListenersRequired => "configuration listeners must be distinct",
            Self::DuplicatePeerCarrier => "configuration contains a duplicate peer carrier",
            Self::DuplicatePeerMission => "configuration contains a duplicate peer mission",
            Self::CredentialBoundary => "credential file boundary is invalid",
            Self::FileAccess => "configuration file cannot be read",
            Self::InvalidMissionLoadId => "configuration mission load id is invalid",
            Self::InvalidEmissionPolicy => "configuration emission policy is invalid",
            Self::InvalidPeer => "configuration peer is invalid",
            Self::InvalidRelay => "configuration relay is invalid",
            Self::InvalidStorage => "configuration storage limits are invalid",
            Self::InvalidOperationStorage => {
                "configuration storage.operations requires nonzero limits, emergency_reserve < max_records, and max_logical_bytes >= emergency_reserve * 162 without overflow"
            }
            Self::LimitOutOfRange => "configuration limit is out of range",
            Self::LoopbackListenerRequired => "configuration listener must be loopback",
            Self::MissingField => "configuration is missing a required field",
            Self::StorageTooSmall => "configuration storage cannot preserve required reserves",
            Self::StateBoundary => "configuration state boundary is invalid",
            Self::SyncIntervalOutOfRange => {
                "configuration synchronization interval is out of range"
            }
            Self::Syntax => "configuration syntax is invalid",
            Self::TooManyPeers => "configuration has too many peers",
            Self::UnknownField => "configuration contains an unknown field",
            Self::UnsupportedSchemaVersion => "configuration schema version is unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError {
    reason: ConfigReason,
}

impl ConfigError {
    const fn new(reason: ConfigReason) -> Self {
        Self { reason }
    }

    pub const fn reason(&self) -> ConfigReason {
        self.reason
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason.message())
    }
}

impl Error for ConfigError {}

#[derive(Clone)]
pub struct CredentialPaths {
    client_token_file: PathBuf,
    mission_secret_ref_file: PathBuf,
    mission_load_id: ProvisioningLoadId,
}

impl CredentialPaths {
    pub fn client_token_file(&self) -> &Path {
        &self.client_token_file
    }

    pub fn mission_secret_ref_file(&self) -> &Path {
        &self.mission_secret_ref_file
    }

    pub const fn mission_load_id(&self) -> ProvisioningLoadId {
        self.mission_load_id
    }
}

impl fmt::Debug for CredentialPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialPaths([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentLimits {
    max_connections: usize,
    max_unauthenticated_connections: usize,
    max_header_bytes: usize,
    first_authentication_timeout: Duration,
    max_in_flight_requests: usize,
    shutdown_grace: Duration,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_APPLICATION_CONNECTIONS,
            max_unauthenticated_connections: MAX_UNAUTHENTICATED_APPLICATION_CONNECTIONS,
            max_header_bytes: MAX_APPLICATION_HEADER_BYTES,
            first_authentication_timeout: Duration::from_millis(
                MAX_FIRST_AUTHENTICATION_TIMEOUT_MS,
            ),
            max_in_flight_requests: MAX_IN_FLIGHT_APPLICATION_REQUESTS,
            shutdown_grace: Duration::from_millis(MAX_SHUTDOWN_GRACE_MS),
        }
    }
}

impl AgentLimits {
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub const fn max_unauthenticated_connections(&self) -> usize {
        self.max_unauthenticated_connections
    }

    pub const fn max_header_bytes(&self) -> usize {
        self.max_header_bytes
    }

    pub const fn first_authentication_timeout(&self) -> Duration {
        self.first_authentication_timeout
    }

    pub const fn max_in_flight_requests(&self) -> usize {
        self.max_in_flight_requests
    }

    pub const fn shutdown_grace(&self) -> Duration {
        self.shutdown_grace
    }
}

pub struct ValidatedRuntimeConfig {
    state: PathBuf,
    application: SocketAddr,
    health: SocketAddr,
    mesh_bind: SocketAddr,
    peers: Vec<MissionExpectedPeer>,
    forwarding: SelectedForwardingConfig,
    limits: AgentLimits,
    sync_interval: Duration,
}

impl ValidatedRuntimeConfig {
    pub fn node_options(&self) -> NodeConfigOptions {
        NodeConfigOptions::new(self.mesh_bind, self.sync_interval).with_peers(self.peers.clone())
    }

    pub fn forwarding(&self) -> SelectedForwardingConfig {
        self.forwarding.clone()
    }

    pub const fn emission_policy(&self) -> EventEmissionPolicy {
        self.forwarding.emission_policy()
    }

    pub fn limits(&self) -> &AgentLimits {
        &self.limits
    }

    pub fn state(&self) -> &Path {
        &self.state
    }

    pub const fn application(&self) -> SocketAddr {
        self.application
    }

    pub const fn health(&self) -> SocketAddr {
        self.health
    }
}

pub struct ValidatedSystemdAgentConfig {
    runtime: ValidatedRuntimeConfig,
    credentials: CredentialPaths,
}

impl ValidatedSystemdAgentConfig {
    pub const fn runtime(&self) -> &ValidatedRuntimeConfig {
        &self.runtime
    }

    pub const fn credential_paths(&self) -> &CredentialPaths {
        &self.credentials
    }

    pub fn into_parts(self) -> (ValidatedRuntimeConfig, CredentialPaths) {
        (self.runtime, self.credentials)
    }
}

impl std::ops::Deref for ValidatedSystemdAgentConfig {
    type Target = ValidatedRuntimeConfig;

    fn deref(&self) -> &Self::Target {
        &self.runtime
    }
}

pub struct ValidatedComposeAgentConfig {
    runtime: ValidatedRuntimeConfig,
}

impl ValidatedComposeAgentConfig {
    pub const fn runtime(&self) -> &ValidatedRuntimeConfig {
        &self.runtime
    }

    pub fn into_runtime(self) -> ValidatedRuntimeConfig {
        self.runtime
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig<C> {
    schema_version: u32,
    state: RawState,
    application: RawListener,
    health: RawListener,
    mesh: RawMesh,
    credentials: C,
    storage: RawStorage,
    #[serde(default)]
    limits: RawLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
    directory: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    listen: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMesh {
    bind: SocketAddr,
    sync_interval_ms: u64,
    emission_policy: RawEmissionPolicy,
    peers: Vec<String>,
    #[serde(default)]
    relay: Option<RawRelay>,
}

#[derive(Clone, Copy)]
enum RawEmissionPolicy {
    Normal,
    ReceiveOnly,
}

impl<'de> Deserialize<'de> for RawEmissionPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "normal" => Ok(Self::Normal),
            "receive_only" => Ok(Self::ReceiveOnly),
            _ => Err(serde::de::Error::custom("invalid emission policy")),
        }
    }
}

impl From<RawEmissionPolicy> for EventEmissionPolicy {
    fn from(policy: RawEmissionPolicy) -> Self {
        match policy {
            RawEmissionPolicy::Normal => Self::Normal,
            RawEmissionPolicy::ReceiveOnly => Self::ReceiveOnly,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelay {
    url: String,
    trust: RawRelayTrust,
    route_policy: RawRelayRoutePolicy,
    #[serde(default)]
    der_roots: Vec<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawRelayTrust {
    Webpki,
    DerRoots,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawRelayRoutePolicy {
    DirectPreferred,
    RelayOnly,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSystemdCredentials {
    client_token_file: PathBuf,
    mission_secret_ref_file: PathBuf,
    mission_load_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComposeCredentials {
    client_token_file: PathBuf,
    mission_activation_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    max_items: u64,
    max_payload_bytes: u64,
    operations: RawOperationStorage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOperationStorage {
    max_records: u64,
    max_logical_bytes: u64,
    emergency_reserve: u64,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    #[serde(default)]
    max_connections: Option<usize>,
    #[serde(default)]
    max_unauthenticated_connections: Option<usize>,
    #[serde(default)]
    max_header_bytes: Option<usize>,
    #[serde(default)]
    first_authentication_timeout_ms: Option<u64>,
    #[serde(default)]
    max_in_flight_requests: Option<usize>,
    #[serde(default)]
    shutdown_grace_ms: Option<u64>,
}

pub fn load_and_validate_config(path: &Path) -> Result<ValidatedSystemdAgentConfig, ConfigError> {
    let bytes = std::fs::read(path).map_err(|_| ConfigError::new(ConfigReason::FileAccess))?;
    let raw: RawAgentConfig<RawSystemdCredentials> =
        serde_json::from_slice(&bytes).map_err(classify_json_error)?;
    validate_systemd(raw)
}

pub fn load_and_validate_compose_config(
    path: &Path,
) -> Result<ValidatedComposeAgentConfig, ConfigError> {
    let bytes = std::fs::read(path).map_err(|_| ConfigError::new(ConfigReason::FileAccess))?;
    validate_compose_config_bytes(&bytes)
}

pub fn validate_compose_config_bytes(
    bytes: &[u8],
) -> Result<ValidatedComposeAgentConfig, ConfigError> {
    let raw: RawAgentConfig<RawComposeCredentials> =
        serde_json::from_slice(bytes).map_err(classify_json_error)?;
    validate_compose(raw)
}

pub fn check_config(path: &Path) -> Result<(), ConfigError> {
    let config = load_and_validate_config(path)?;
    load_startup_credentials(config.credential_paths())
        .map_err(|_| ConfigError::new(ConfigReason::CredentialBoundary))?;
    Ok(())
}

fn classify_json_error(error: serde_json::Error) -> ConfigError {
    let message = error.to_string();
    let reason = if message.starts_with("invalid emission policy") {
        ConfigReason::InvalidEmissionPolicy
    } else if message.starts_with("unknown field") {
        ConfigReason::UnknownField
    } else if message.starts_with("duplicate field") {
        ConfigReason::DuplicateField
    } else if message.starts_with("missing field") {
        ConfigReason::MissingField
    } else {
        ConfigReason::Syntax
    };
    ConfigError::new(reason)
}

fn validate_systemd(
    raw: RawAgentConfig<RawSystemdCredentials>,
) -> Result<ValidatedSystemdAgentConfig, ConfigError> {
    if raw.schema_version != SYSTEMD_SCHEMA_VERSION {
        return Err(ConfigError::new(ConfigReason::UnsupportedSchemaVersion));
    }
    require_absolute(&raw.credentials.client_token_file)?;
    require_absolute(&raw.credentials.mission_secret_ref_file)?;
    let credentials = CredentialPaths {
        client_token_file: raw.credentials.client_token_file.clone(),
        mission_secret_ref_file: raw.credentials.mission_secret_ref_file.clone(),
        mission_load_id: parse_mission_load_id(&raw.credentials.mission_load_id)?,
    };
    Ok(ValidatedSystemdAgentConfig {
        runtime: validate_runtime(raw)?,
        credentials,
    })
}

fn validate_compose(
    raw: RawAgentConfig<RawComposeCredentials>,
) -> Result<ValidatedComposeAgentConfig, ConfigError> {
    if raw.schema_version != COMPOSE_SCHEMA_VERSION {
        return Err(ConfigError::new(ConfigReason::UnsupportedSchemaVersion));
    }
    if raw.credentials.client_token_file != Path::new(COMPOSE_CLIENT_TOKEN_PATH)
        || raw.credentials.mission_activation_file != Path::new(COMPOSE_MISSION_ACTIVATION_PATH)
    {
        return Err(ConfigError::new(ConfigReason::CredentialBoundary));
    }
    if raw.state.directory != Path::new(COMPOSE_STATE_PATH) {
        return Err(ConfigError::new(ConfigReason::StateBoundary));
    }
    Ok(ValidatedComposeAgentConfig {
        runtime: validate_runtime(raw)?,
    })
}

fn validate_runtime<C>(raw: RawAgentConfig<C>) -> Result<ValidatedRuntimeConfig, ConfigError> {
    require_absolute(&raw.state.directory)?;
    validate_listeners(raw.application.listen, raw.health.listen)?;
    let sync_interval = validate_sync_interval(raw.mesh.sync_interval_ms)?;
    let peers = validate_peers(raw.mesh.peers)?;
    let forwarding =
        validate_forwarding(raw.storage, raw.mesh.emission_policy.into(), raw.mesh.relay)?;
    let limits = validate_limits(raw.limits)?;

    Ok(ValidatedRuntimeConfig {
        state: raw.state.directory,
        application: raw.application.listen,
        health: raw.health.listen,
        mesh_bind: raw.mesh.bind,
        peers,
        forwarding,
        limits,
        sync_interval,
    })
}

fn validate_limits(raw: RawLimits) -> Result<AgentLimits, ConfigError> {
    Ok(AgentLimits {
        max_connections: tighten_usize(raw.max_connections, MAX_APPLICATION_CONNECTIONS)?,
        max_unauthenticated_connections: tighten_usize(
            raw.max_unauthenticated_connections,
            MAX_UNAUTHENTICATED_APPLICATION_CONNECTIONS,
        )?,
        max_header_bytes: tighten_usize(raw.max_header_bytes, MAX_APPLICATION_HEADER_BYTES)?,
        first_authentication_timeout: Duration::from_millis(tighten_u64(
            raw.first_authentication_timeout_ms,
            MAX_FIRST_AUTHENTICATION_TIMEOUT_MS,
        )?),
        max_in_flight_requests: tighten_usize(
            raw.max_in_flight_requests,
            MAX_IN_FLIGHT_APPLICATION_REQUESTS,
        )?,
        shutdown_grace: Duration::from_millis(tighten_u64(
            raw.shutdown_grace_ms,
            MAX_SHUTDOWN_GRACE_MS,
        )?),
    })
}

fn tighten_usize(value: Option<usize>, ceiling: usize) -> Result<usize, ConfigError> {
    let value = value.unwrap_or(ceiling);
    if value == 0 || value > ceiling {
        return Err(ConfigError::new(ConfigReason::LimitOutOfRange));
    }
    Ok(value)
}

fn tighten_u64(value: Option<u64>, ceiling: u64) -> Result<u64, ConfigError> {
    let value = value.unwrap_or(ceiling);
    if value == 0 || value > ceiling {
        return Err(ConfigError::new(ConfigReason::LimitOutOfRange));
    }
    Ok(value)
}

fn require_absolute(path: &Path) -> Result<(), ConfigError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ConfigError::new(ConfigReason::AbsolutePathRequired))
    }
}

fn validate_listeners(application: SocketAddr, health: SocketAddr) -> Result<(), ConfigError> {
    if !application.ip().is_loopback() || !health.ip().is_loopback() {
        return Err(ConfigError::new(ConfigReason::LoopbackListenerRequired));
    }
    if application == health {
        return Err(ConfigError::new(ConfigReason::DistinctListenersRequired));
    }
    Ok(())
}

fn validate_sync_interval(milliseconds: u64) -> Result<Duration, ConfigError> {
    if !(1..=MAX_SYNC_INTERVAL_MS).contains(&milliseconds) {
        return Err(ConfigError::new(ConfigReason::SyncIntervalOutOfRange));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn validate_peers(raw_peers: Vec<String>) -> Result<Vec<MissionExpectedPeer>, ConfigError> {
    if raw_peers.len() > MAX_CONFIGURED_PEERS {
        return Err(ConfigError::new(ConfigReason::TooManyPeers));
    }
    let mut carrier_ids = BTreeSet::new();
    let mut missions = BTreeSet::new();
    let mut peers = Vec::with_capacity(raw_peers.len());
    for raw_peer in raw_peers {
        let peer = MissionExpectedPeer::from_str(&raw_peer)
            .map_err(|_| ConfigError::new(ConfigReason::InvalidPeer))?;
        if !carrier_ids.insert(peer.carrier.id) {
            return Err(ConfigError::new(ConfigReason::DuplicatePeerCarrier));
        }
        if !missions.insert(peer.mission) {
            return Err(ConfigError::new(ConfigReason::DuplicatePeerMission));
        }
        peers.push(peer);
    }
    Ok(peers)
}

fn validate_forwarding(
    raw_storage: RawStorage,
    emission_policy: EventEmissionPolicy,
    raw_relay: Option<RawRelay>,
) -> Result<SelectedForwardingConfig, ConfigError> {
    let limits = StoreLimits::new(raw_storage.max_items, raw_storage.max_payload_bytes)
        .map_err(|_| ConfigError::new(ConfigReason::InvalidStorage))?;
    let minimum_items = MAX_CONTROL_ITEMS + CUSTODY_EMERGENCY_ITEM_RESERVE + 1;
    let minimum_bytes = MAX_CONTROL_BYTES
        + CUSTODY_EMERGENCY_BYTE_RESERVE
        + u64::try_from(MAX_AGENT_MESSAGE_BYTES).expect("agent message limit fits u64");
    if limits.max_items() < minimum_items || limits.max_total_payload_bytes() < minimum_bytes {
        return Err(ConfigError::new(ConfigReason::StorageTooSmall));
    }
    CustodyQuota::for_store_limits(limits)
        .map_err(|_| ConfigError::new(ConfigReason::StorageTooSmall))?;
    let operations = raw_storage.operations;
    let operation_limits = EventOperationLimits::new(
        operations.max_records,
        operations.max_logical_bytes,
        operations.emergency_reserve,
    )
    .map_err(|_| ConfigError::new(ConfigReason::InvalidOperationStorage))?;
    let forwarding = SelectedForwardingConfig::default()
        .with_emission_policy(emission_policy)
        .with_store_limits(limits)
        .with_operation_limits(operation_limits);
    let Some(raw_relay) = raw_relay else {
        return Ok(forwarding);
    };
    let relay = validate_relay(raw_relay)?;
    Ok(match relay.1 {
        RawRelayRoutePolicy::DirectPreferred => forwarding.with_controlled_relay(relay.0),
        RawRelayRoutePolicy::RelayOnly => forwarding.with_controlled_relay_only(relay.0),
    })
}

fn validate_relay(raw: RawRelay) -> Result<(PinnedRelay, RawRelayRoutePolicy), ConfigError> {
    let url =
        RelayUrl::from_str(&raw.url).map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
    let relay = match raw.trust {
        RawRelayTrust::Webpki => {
            if !raw.der_roots.is_empty() {
                return Err(ConfigError::new(ConfigReason::InvalidRelay));
            }
            PinnedRelay::new(url).map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?
        }
        RawRelayTrust::DerRoots => {
            if raw.der_roots.is_empty() {
                return Err(ConfigError::new(ConfigReason::InvalidRelay));
            }
            for root in &raw.der_roots {
                require_absolute(root).map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
            }
            let roots = read_bounded_der_roots(&raw.der_roots)?;
            PinnedRelay::with_ca_roots(url, roots)
                .map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?
        }
    };
    Ok((relay, raw.route_policy))
}

fn read_bounded_der_roots(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, ConfigError> {
    if paths.len() > aster_iroh::MAX_RELAY_CA_ROOTS {
        return Err(ConfigError::new(ConfigReason::InvalidRelay));
    }
    let mut total = 0usize;
    for path in paths {
        let length = der_root_length(path)?;
        total = total
            .checked_add(length)
            .filter(|total| *total <= aster_iroh::MAX_RELAY_CA_ROOT_TOTAL_BYTES)
            .ok_or_else(|| ConfigError::new(ConfigReason::InvalidRelay))?;
    }
    let mut roots = Vec::with_capacity(paths.len());
    let mut actual_total = 0usize;
    for path in paths {
        let root = read_bounded_der_root(path)?;
        actual_total = actual_total
            .checked_add(root.len())
            .filter(|total| *total <= aster_iroh::MAX_RELAY_CA_ROOT_TOTAL_BYTES)
            .ok_or_else(|| ConfigError::new(ConfigReason::InvalidRelay))?;
        roots.push(root);
    }
    Ok(roots)
}

fn read_bounded_der_root(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let length = der_root_length(path)?;
    let file =
        std::fs::File::open(path).map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
    let mut root = Vec::with_capacity(length);
    file.take((aster_iroh::MAX_RELAY_CA_ROOT_BYTES + 1) as u64)
        .read_to_end(&mut root)
        .map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
    if root.len() != length || root.len() > aster_iroh::MAX_RELAY_CA_ROOT_BYTES {
        return Err(ConfigError::new(ConfigReason::InvalidRelay));
    }
    Ok(root)
}

fn der_root_length(path: &Path) -> Result<usize, ConfigError> {
    let metadata =
        std::fs::metadata(path).map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
    if !metadata.is_file() || length == 0 || length > aster_iroh::MAX_RELAY_CA_ROOT_BYTES {
        return Err(ConfigError::new(ConfigReason::InvalidRelay));
    }
    Ok(length)
}

fn parse_mission_load_id(value: &str) -> Result<ProvisioningLoadId, ConfigError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::new(ConfigReason::InvalidMissionLoadId));
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0])
            .ok_or_else(|| ConfigError::new(ConfigReason::InvalidMissionLoadId))?;
        let low = hex_digit(pair[1])
            .ok_or_else(|| ConfigError::new(ConfigReason::InvalidMissionLoadId))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(ProvisioningLoadId::new(bytes))
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use aster_node::EventEmissionPolicy;
    use aster_redb_store::{
        CUSTODY_EMERGENCY_BYTE_RESERVE, CUSTODY_EMERGENCY_ITEM_RESERVE, MAX_CONTROL_BYTES,
        MAX_CONTROL_ITEMS,
    };

    use super::{ConfigReason, load_and_validate_config};
    use crate::MAX_AGENT_MESSAGE_BYTES;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn v1_rejects_unknown_duplicate_and_bridge_fields() {
        assert_reason(json_with("unknown", "true"), ConfigReason::UnknownField);
        assert_reason(
            json_with_duplicate("schema_version", "1"),
            ConfigReason::DuplicateField,
        );
        assert_reason(json_with("event_bridge", "{}"), ConfigReason::UnknownField);
    }

    #[test]
    fn quota_must_leave_reserves_and_one_maximum_event() {
        let minimum_items = MAX_CONTROL_ITEMS + CUSTODY_EMERGENCY_ITEM_RESERVE + 1;
        let minimum_bytes =
            MAX_CONTROL_BYTES + CUSTODY_EMERGENCY_BYTE_RESERVE + MAX_AGENT_MESSAGE_BYTES as u64;
        assert_reason(
            config_with_storage(minimum_items - 1, minimum_bytes),
            ConfigReason::StorageTooSmall,
        );
        assert!(validate_storage(minimum_items, minimum_bytes).is_ok());
    }

    #[test]
    fn v1_accepts_valid_config_and_derives_node_and_forwarding_options() {
        let config = validate_json(config_with_storage(4_161, 17_891_328))
            .expect("hand-checked minimum configuration");
        assert_eq!(config.forwarding().store_limits().max_items(), 4_161);
        assert_eq!(
            config.forwarding().store_limits().max_total_payload_bytes(),
            17_891_328
        );
        let _options = config.node_options();
    }

    #[test]
    fn v2_accepts_only_the_compose_state_mount() {
        let accepted = validate_compose_json(compose_config_with_state("/var/lib/aster"))
            .expect("exact Compose state mount");
        assert_eq!(
            accepted.into_runtime().state(),
            std::path::Path::new("/var/lib/aster")
        );

        for state in [
            "/tmp/aster",
            "/var/lib/aster/../aster",
            "/var/lib/aster-agent",
        ] {
            let error = rejected(
                validate_compose_json(compose_config_with_state(state)),
                "alternate Compose state path must be rejected",
            );
            assert_eq!(error.reason(), ConfigReason::StateBoundary, "state {state}");
        }
    }

    #[test]
    fn v1_operation_storage_accepts_explicit_profile_and_boundary_limits() {
        // Break caught: ignoring or silently replacing the operator's ledger quota.
        for (records, bytes, reserve) in [(1_000_000, 201_326_592, 10_000), (3, 324, 2)] {
            let config = validate_json(config_with_operations(serde_json::json!({
                "max_records": records,
                "max_logical_bytes": bytes,
                "emergency_reserve": reserve,
            })))
            .expect("explicit valid operation limits");
            let limits = config.forwarding().operation_limits();
            assert_eq!(limits.max_records(), records);
            assert_eq!(limits.max_logical_bytes(), bytes);
            assert_eq!(limits.emergency_reserve(), reserve);
        }
    }

    #[test]
    fn v1_operation_storage_requires_exact_object_and_fields() {
        // Break caught: serde defaults or permissive parsing silently change capacity.
        let mut config: serde_json::Value =
            serde_json::from_str(&config_with_storage(4_161, 17_891_328)).unwrap();
        config["storage"]
            .as_object_mut()
            .unwrap()
            .remove("operations");
        assert_reason(config.to_string(), ConfigReason::MissingField);
        for field in ["max_records", "max_logical_bytes", "emergency_reserve"] {
            let mut operations = valid_operations();
            operations.as_object_mut().unwrap().remove(field);
            assert_reason(
                config_with_operations(operations),
                ConfigReason::MissingField,
            );
        }
        for field in ["unknown", "max_aliases_per_event"] {
            let mut operations = valid_operations();
            operations[field] = 64.into();
            assert_reason(
                config_with_operations(operations),
                ConfigReason::UnknownField,
            );
        }
        assert_reason(
            config_with_operations(serde_json::Value::Null),
            ConfigReason::Syntax,
        );
        let duplicate = config_with_operations(valid_operations()).replace(
            "\"max_records\":1000000",
            "\"max_records\":1000000,\"max_records\":1000000",
        );
        assert_reason(duplicate, ConfigReason::DuplicateField);
    }

    #[test]
    fn v1_operation_storage_rejects_invalid_reserves_without_echoing_input() {
        // Break caught: admitting zero/overflowing quotas or consuming emergency bytes.
        for (records, bytes, reserve) in [
            (0, 324, 1),
            (3, 0, 1),
            (3, 324, 0),
            (3, 486, 3),
            (3, 648, 4),
            (3, 323, 2),
            (u64::MAX, u64::MAX, u64::MAX / 162 + 1),
        ] {
            let error = rejected(
                validate_json(config_with_operations(serde_json::json!({
                    "max_records": records,
                    "max_logical_bytes": bytes,
                    "emergency_reserve": reserve,
                }))),
                "invalid operation limits",
            );
            assert_eq!(
                error.to_string(),
                "configuration storage.operations requires nonzero limits, emergency_reserve < max_records, and max_logical_bytes >= emergency_reserve * 162 without overflow"
            );
        }
    }

    #[test]
    fn v1_requires_exact_emission_policy() {
        let normal =
            validate_json(config_with_storage(4_161, 17_891_328)).expect("normal emission policy");
        assert_eq!(normal.emission_policy(), EventEmissionPolicy::Normal);
        assert_eq!(
            normal.forwarding().emission_policy(),
            EventEmissionPolicy::Normal
        );

        let receive_only = validate_json(replace_value(
            config_with_storage(4_161, 17_891_328),
            "\"emission_policy\":\"normal\"",
            "\"emission_policy\":\"receive_only\"",
        ))
        .expect("receive-only emission policy");
        assert_eq!(
            receive_only.emission_policy(),
            EventEmissionPolicy::ReceiveOnly
        );
        assert_eq!(
            receive_only.forwarding().emission_policy(),
            EventEmissionPolicy::ReceiveOnly
        );

        assert_reason(
            replace_value(
                config_with_storage(4_161, 17_891_328),
                "\"emission_policy\":\"normal\"",
                "\"emission_policy\":\"transmit_nothing\"",
            ),
            ConfigReason::InvalidEmissionPolicy,
        );
    }

    #[test]
    fn customer_limits_default_to_compiled_ceilings_and_may_only_tighten() {
        let config = validate_json(json_with_limits(
            config_with_storage(4_161, 17_891_328),
            r#"{"max_connections":32,"max_unauthenticated_connections":4,"max_header_bytes":8192,"first_authentication_timeout_ms":2500,"max_in_flight_requests":32,"shutdown_grace_ms":10000}"#,
        ))
        .expect("tightened customer limits");
        let limits = config.limits();
        assert_eq!(limits.max_connections(), 32);
        assert_eq!(limits.max_unauthenticated_connections(), 4);
        assert_eq!(limits.max_header_bytes(), 8192);
        assert_eq!(
            limits.first_authentication_timeout(),
            Duration::from_millis(2500)
        );
        assert_eq!(limits.max_in_flight_requests(), 32);
        assert_eq!(limits.shutdown_grace(), Duration::from_secs(10));

        assert_reason(
            json_with_limits(
                config_with_storage(4_161, 17_891_328),
                r#"{"max_connections":65}"#,
            ),
            ConfigReason::LimitOutOfRange,
        );
    }

    #[test]
    fn configuration_requires_absolute_paths_distinct_loopback_listeners_and_bounded_sync() {
        let cases = [
            (
                "relative state path",
                replace_value(
                    config_with_storage(4_161, 17_891_328),
                    "\"directory\":\"/var/lib/aster-agent\"",
                    "\"directory\":\"state\"",
                ),
                ConfigReason::AbsolutePathRequired,
            ),
            (
                "non-loopback application listener",
                replace_value(
                    config_with_storage(4_161, 17_891_328),
                    "127.0.0.1:8181",
                    "192.0.2.10:8181",
                ),
                ConfigReason::LoopbackListenerRequired,
            ),
            (
                "same application and health listener",
                replace_value(
                    config_with_storage(4_161, 17_891_328),
                    "127.0.0.1:8182",
                    "127.0.0.1:8181",
                ),
                ConfigReason::DistinctListenersRequired,
            ),
            (
                "zero synchronization interval",
                replace_value(
                    config_with_storage(4_161, 17_891_328),
                    "\"sync_interval_ms\":500",
                    "\"sync_interval_ms\":0",
                ),
                ConfigReason::SyncIntervalOutOfRange,
            ),
            (
                "oversized synchronization interval",
                replace_value(
                    config_with_storage(4_161, 17_891_328),
                    "\"sync_interval_ms\":500",
                    "\"sync_interval_ms\":60001",
                ),
                ConfigReason::SyncIntervalOutOfRange,
            ),
        ];
        for (name, json, expected) in cases {
            let error = rejected(validate_json(json), name);
            assert_eq!(error.reason(), expected, "{name}");
        }
    }

    #[test]
    fn configuration_rejects_invalid_load_ids_and_invalid_or_repeated_peers() {
        assert_reason(
            replace_value(
                config_with_storage(4_161, 17_891_328),
                "1111111111111111111111111111111111111111111111111111111111111111",
                "not-a-load-id",
            ),
            ConfigReason::InvalidMissionLoadId,
        );

        let carrier = aster_iroh::SecretKey::from_bytes(&[7; 32]).public();
        let first = format!("{carrier}@127.0.0.1:9001={}", "22".repeat(32));
        let repeated_carrier = format!("{carrier}@127.0.0.1:9002={}", "33".repeat(32));
        let json = replace_value(
            config_with_storage(4_161, 17_891_328),
            "\"peers\":[]",
            &format!("\"peers\":[\"{first}\",\"{repeated_carrier}\"]"),
        );
        assert_reason(json, ConfigReason::DuplicatePeerCarrier);
    }

    #[test]
    fn peer_socket_addresses_need_not_be_unique_when_identities_are_unique() {
        let first_carrier = aster_iroh::SecretKey::from_bytes(&[8; 32]).public();
        let second_carrier = aster_iroh::SecretKey::from_bytes(&[9; 32]).public();
        let first = format!("{first_carrier}@127.0.0.1:9001={}", "44".repeat(32));
        let second = format!("{second_carrier}@127.0.0.1:9001={}", "55".repeat(32));
        let json = replace_value(
            config_with_storage(4_161, 17_891_328),
            "\"peers\":[]",
            &format!("\"peers\":[\"{first}\",\"{second}\"]"),
        );
        assert!(validate_json(json).is_ok());
    }

    #[test]
    fn oversized_der_root_is_rejected_before_it_is_loaded() {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-agent-oversized-der-root-{}-{sequence}",
            std::process::id()
        ));
        fs::write(&path, vec![0; aster_iroh::MAX_RELAY_CA_ROOT_BYTES + 1])
            .expect("write oversized DER fixture");
        let error = rejected(
            super::read_bounded_der_root(&path),
            "oversized root must be rejected before loading",
        );
        assert_eq!(error.reason(), ConfigReason::InvalidRelay);
        fs::remove_file(path).expect("remove oversized DER fixture");
    }

    #[test]
    fn unreadable_configuration_path_has_a_sanitized_file_access_reason() {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-agent-absent-config-{}-{sequence}.json",
            std::process::id()
        ));
        let error = rejected(
            load_and_validate_config(&path),
            "absent configuration must be rejected",
        );
        assert_eq!(error.reason(), ConfigReason::FileAccess);
        assert!(!error.to_string().contains("aster-agent-absent-config"));
    }

    #[test]
    fn invalid_configuration_does_not_create_state_or_bind_configured_ports() {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let state = std::env::temp_dir().join(format!(
            "aster-agent-config-state-canary-{}-{sequence}",
            std::process::id()
        ));
        let application = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let health = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let mut json = config_with_storage(4_161, 17_891_328);
        json = replace_value(
            json,
            "/var/lib/aster-agent",
            state.to_str().expect("UTF-8 temporary path"),
        );
        if let (Some(application), Some(health)) = (&application, &health) {
            json = replace_value(
                json,
                "127.0.0.1:8181",
                &application
                    .local_addr()
                    .expect("application address")
                    .to_string(),
            );
            json = replace_value(
                json,
                "127.0.0.1:8182",
                &health.local_addr().expect("health address").to_string(),
            );
        }
        assert_reason(
            json_with_field(json, "unknown", "true"),
            ConfigReason::UnknownField,
        );
        assert!(!state.exists(), "invalid validation created state");
        if let (Some(application), Some(health)) = (application, health) {
            let application_address = application.local_addr().expect("application address");
            let health_address = health.local_addr().expect("health address");
            drop(application);
            drop(health);
            let rebound_application = std::net::TcpListener::bind(application_address)
                .expect("invalid validation must not bind application port");
            let rebound_health = std::net::TcpListener::bind(health_address)
                .expect("invalid validation must not bind health port");
            drop(rebound_application);
            drop(rebound_health);
        }
    }

    fn assert_reason(json: String, expected: ConfigReason) {
        let error = rejected(validate_json(json), "configuration must be rejected");
        assert_eq!(error.reason(), expected);
    }

    fn validate_storage(items: u64, bytes: u64) -> Result<(), super::ConfigError> {
        validate_json(config_with_storage(items, bytes)).map(|_| ())
    }

    fn validate_json(
        json: String,
    ) -> Result<super::ValidatedSystemdAgentConfig, super::ConfigError> {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-agent-config-test-{}-{sequence}.json",
            std::process::id()
        ));
        fs::write(&path, json).expect("write configuration fixture");
        let result = load_and_validate_config(&path);
        fs::remove_file(&path).expect("remove configuration fixture");
        result
    }

    fn validate_compose_json(
        json: String,
    ) -> Result<super::ValidatedComposeAgentConfig, super::ConfigError> {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-compose-config-test-{}-{sequence}.json",
            std::process::id()
        ));
        fs::write(&path, json).expect("write Compose configuration fixture");
        let result = super::load_and_validate_compose_config(&path);
        fs::remove_file(&path).expect("remove Compose configuration fixture");
        result
    }

    fn compose_config_with_state(state: &str) -> String {
        format!(
            r#"{{"schema_version":2,"state":{{"directory":"{state}"}},"application":{{"listen":"127.0.0.1:8181"}},"health":{{"listen":"127.0.0.1:8182"}},"mesh":{{"bind":"127.0.0.1:8183","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"/run/secrets/aster-client-token","mission_activation_file":"/run/secrets/aster-mission-activation"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}}}}"#
        )
    }

    fn config_with_storage(max_items: u64, max_payload_bytes: u64) -> String {
        format!(
            r#"{{"schema_version":1,"state":{{"directory":"/var/lib/aster-agent"}},"application":{{"listen":"127.0.0.1:8181"}},"health":{{"listen":"127.0.0.1:8182"}},"mesh":{{"bind":"127.0.0.1:8183","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"/run/aster-agent/client-token","mission_secret_ref_file":"/run/aster-agent/mission-ref","mission_load_id":"1111111111111111111111111111111111111111111111111111111111111111"}},"storage":{{"max_items":{max_items},"max_payload_bytes":{max_payload_bytes},"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}}}}"#
        )
    }

    fn valid_operations() -> serde_json::Value {
        serde_json::json!({"max_records": 1_000_000, "max_logical_bytes": 201_326_592, "emergency_reserve": 10_000})
    }

    fn config_with_operations(operations: serde_json::Value) -> String {
        let mut config: serde_json::Value =
            serde_json::from_str(&config_with_storage(4_161, 17_891_328)).unwrap();
        config["storage"]["operations"] = operations;
        config.to_string()
    }

    fn json_with(field: &str, value: &str) -> String {
        json_with_field(config_with_storage(4_161, 17_891_328), field, value)
    }

    fn json_with_limits(json: String, limits: &str) -> String {
        let mut json = json;
        json.insert_str(json.len() - 1, &format!(",\"limits\":{limits}"));
        json
    }

    fn json_with_duplicate(field: &str, value: &str) -> String {
        let mut json = config_with_storage(4_161, 17_891_328);
        json.insert_str(1, &format!(r#""{field}":{value},"#));
        json
    }

    fn json_with_field(mut json: String, field: &str, value: &str) -> String {
        json.insert_str(1, &format!(r#""{field}":{value},"#));
        json
    }

    fn replace_value(json: String, old: &str, replacement: &str) -> String {
        assert!(json.contains(old), "fixture does not contain {old}");
        json.replacen(old, replacement, 1)
    }

    fn rejected<T>(result: Result<T, super::ConfigError>, message: &str) -> super::ConfigError {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}
