use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use aster_iroh::{PinnedRelay, RelayUrl};
use aster_mesh::ProvisioningLoadId;
use aster_node::{MissionExpectedPeer, NodeConfigOptions, SelectedForwardingConfig, StoreLimits};
use aster_redb_store::{
    CUSTODY_EMERGENCY_BYTE_RESERVE, CUSTODY_EMERGENCY_ITEM_RESERVE, CustodyQuota,
    MAX_CONTROL_BYTES, MAX_CONTROL_ITEMS,
};
use serde::Deserialize;

use crate::MAX_AGENT_MESSAGE_BYTES;

const SUPPORTED_SCHEMA_VERSION: u32 = 1;
const MAX_CONFIGURED_PEERS: usize = 256;
const MAX_SYNC_INTERVAL_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigReason {
    AbsolutePathRequired,
    DuplicateField,
    DistinctListenersRequired,
    DuplicatePeerAddress,
    DuplicatePeerCarrier,
    DuplicatePeerMission,
    InvalidMissionLoadId,
    InvalidPeer,
    InvalidRelay,
    InvalidStorage,
    LoopbackListenerRequired,
    MissingField,
    StorageTooSmall,
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
            Self::DuplicatePeerAddress => "configuration contains a duplicate peer address",
            Self::DuplicatePeerCarrier => "configuration contains a duplicate peer carrier",
            Self::DuplicatePeerMission => "configuration contains a duplicate peer mission",
            Self::InvalidMissionLoadId => "configuration mission load id is invalid",
            Self::InvalidPeer => "configuration peer is invalid",
            Self::InvalidRelay => "configuration relay is invalid",
            Self::InvalidStorage => "configuration storage limits are invalid",
            Self::LoopbackListenerRequired => "configuration listener must be loopback",
            Self::MissingField => "configuration is missing a required field",
            Self::StorageTooSmall => "configuration storage cannot preserve required reserves",
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentLimits {}

pub struct ValidatedAgentConfig {
    state: PathBuf,
    application: SocketAddr,
    health: SocketAddr,
    mesh_bind: SocketAddr,
    peers: Vec<MissionExpectedPeer>,
    forwarding: SelectedForwardingConfig,
    credentials: CredentialPaths,
    limits: AgentLimits,
    sync_interval: Duration,
}

impl ValidatedAgentConfig {
    pub fn node_options(&self) -> NodeConfigOptions {
        NodeConfigOptions::new(self.mesh_bind, self.sync_interval).with_peers(self.peers.clone())
    }

    pub fn forwarding(&self) -> SelectedForwardingConfig {
        self.forwarding.clone()
    }

    pub fn credential_paths(&self) -> &CredentialPaths {
        &self.credentials
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig {
    schema_version: u32,
    state: RawState,
    application: RawListener,
    health: RawListener,
    mesh: RawMesh,
    credentials: RawCredentials,
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
    peers: Vec<String>,
    #[serde(default)]
    relay: Option<RawRelay>,
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
struct RawCredentials {
    client_token_file: PathBuf,
    mission_secret_ref_file: PathBuf,
    mission_load_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    max_items: u64,
    max_payload_bytes: u64,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {}

pub fn load_and_validate_config(path: &Path) -> Result<ValidatedAgentConfig, ConfigError> {
    let bytes = std::fs::read(path).map_err(|_| ConfigError::new(ConfigReason::Syntax))?;
    let raw: RawAgentConfig = serde_json::from_slice(&bytes).map_err(classify_json_error)?;
    validate(raw)
}

pub fn check_config(path: &Path) -> Result<(), ConfigError> {
    load_and_validate_config(path).map(|_| ())
}

fn classify_json_error(error: serde_json::Error) -> ConfigError {
    let message = error.to_string();
    let reason = if message.starts_with("unknown field") {
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

fn validate(raw: RawAgentConfig) -> Result<ValidatedAgentConfig, ConfigError> {
    if raw.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(ConfigError::new(ConfigReason::UnsupportedSchemaVersion));
    }
    require_absolute(&raw.state.directory)?;
    require_absolute(&raw.credentials.client_token_file)?;
    require_absolute(&raw.credentials.mission_secret_ref_file)?;
    validate_listeners(raw.application.listen, raw.health.listen)?;
    let sync_interval = validate_sync_interval(raw.mesh.sync_interval_ms)?;
    let peers = validate_peers(raw.mesh.peers)?;
    let forwarding = validate_forwarding(raw.storage, raw.mesh.relay)?;
    let credentials = CredentialPaths {
        client_token_file: raw.credentials.client_token_file,
        mission_secret_ref_file: raw.credentials.mission_secret_ref_file,
        mission_load_id: parse_mission_load_id(&raw.credentials.mission_load_id)?,
    };
    let _ = raw.limits;

    Ok(ValidatedAgentConfig {
        state: raw.state.directory,
        application: raw.application.listen,
        health: raw.health.listen,
        mesh_bind: raw.mesh.bind,
        peers,
        forwarding,
        credentials,
        limits: AgentLimits::default(),
        sync_interval,
    })
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
    let mut addresses = BTreeSet::new();
    let mut missions = BTreeSet::new();
    let mut peers = Vec::with_capacity(raw_peers.len());
    for raw_peer in raw_peers {
        let peer = MissionExpectedPeer::from_str(&raw_peer)
            .map_err(|_| ConfigError::new(ConfigReason::InvalidPeer))?;
        if !carrier_ids.insert(peer.carrier.id) {
            return Err(ConfigError::new(ConfigReason::DuplicatePeerCarrier));
        }
        if !addresses.insert(peer.carrier.address) {
            return Err(ConfigError::new(ConfigReason::DuplicatePeerAddress));
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
    let forwarding = SelectedForwardingConfig::default().with_store_limits(limits);
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
            let roots = raw
                .der_roots
                .iter()
                .map(std::fs::read)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?;
            PinnedRelay::with_ca_roots(url, roots)
                .map_err(|_| ConfigError::new(ConfigReason::InvalidRelay))?
        }
    };
    Ok((relay, raw.route_policy))
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
    };

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

    fn validate_json(json: String) -> Result<super::ValidatedAgentConfig, super::ConfigError> {
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

    fn config_with_storage(max_items: u64, max_payload_bytes: u64) -> String {
        format!(
            r#"{{"schema_version":1,"state":{{"directory":"/var/lib/aster-agent"}},"application":{{"listen":"127.0.0.1:8181"}},"health":{{"listen":"127.0.0.1:8182"}},"mesh":{{"bind":"127.0.0.1:8183","sync_interval_ms":500,"peers":[]}},"credentials":{{"client_token_file":"/run/aster-agent/client-token","mission_secret_ref_file":"/run/aster-agent/mission-ref","mission_load_id":"1111111111111111111111111111111111111111111111111111111111111111"}},"storage":{{"max_items":{max_items},"max_payload_bytes":{max_payload_bytes}}}}}"#
        )
    }

    fn json_with(field: &str, value: &str) -> String {
        json_with_field(config_with_storage(4_161, 17_891_328), field, value)
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

    fn rejected(
        result: Result<super::ValidatedAgentConfig, super::ConfigError>,
        message: &str,
    ) -> super::ConfigError {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}
