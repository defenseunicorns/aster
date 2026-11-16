use aster_mesh::MAX_UNPROTECTED_PROVISIONING_BYTES;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

const MAX_CONFIG_JSON_BYTES: usize = 16 * 1024;
const MAX_CONFIG_STRING_BYTES: usize = 4 * 1024;
const MAX_EVENT_TEXT_BYTES: usize = 1_024;
const MIN_LE_DYNAMIC_PSM: u16 = 0x0080;
const MAX_LE_DYNAMIC_PSM: u16 = 0x00ff;

/// Maximum accepted unprotected mission bundle size.
pub const MAX_MISSION_BUNDLE_BYTES: usize = MAX_UNPROTECTED_PROVISIONING_BYTES;

/// Stable sanitized validator failure category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorErrorCategory {
    /// Invalid operator input or local configuration.
    Configuration,
    /// A configured or observed value exceeded a fixed bound.
    Bounds,
    /// The platform carrier is unavailable.
    Unavailable,
    /// An operation exceeded its fixed deadline.
    Timeout,
    /// Mission authentication or peer authorization failed.
    Authentication,
    /// Protected protocol validation failed.
    Protocol,
    /// Durable state could not be opened or updated.
    Storage,
    /// An internal adapter failure was contained.
    Internal,
}

impl ValidatorErrorCategory {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Bounds => "bounds",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Authentication => "authentication",
            Self::Protocol => "protocol",
            Self::Storage => "storage",
            Self::Internal => "internal",
        }
    }
}

/// Sanitized validator error that never retains peer-controlled input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidatorError {
    category: ValidatorErrorCategory,
    message: String,
}

impl ValidatorError {
    fn configuration(message: &'static str) -> Self {
        Self::new(ValidatorErrorCategory::Configuration, message)
    }

    fn bounds(message: &'static str) -> Self {
        Self::new(ValidatorErrorCategory::Bounds, message)
    }

    pub(crate) fn new(category: ValidatorErrorCategory, message: &'static str) -> Self {
        Self {
            category,
            message: message.to_owned(),
        }
    }

    /// Returns the stable sanitized category.
    #[must_use]
    pub const fn category(&self) -> ValidatorErrorCategory {
        self.category
    }
}

impl fmt::Display for ValidatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ValidatorError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawValidatorConfig {
    state_path: String,
    mission_bundle_path: String,
    mission_peer: String,
    bluetooth_address: String,
    psm: u16,
    event_text: String,
    send_packet_bytes: usize,
    receive_packet_bytes: usize,
    require_event_larger_than_mtu: bool,
}

/// Immutable, fully validated Android Ring-1 run configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorConfig {
    state_path: PathBuf,
    mission_bundle_path: PathBuf,
    mission_peer: [u8; 32],
    bluetooth_address: String,
    psm: u16,
    event_text: String,
    send_packet_bytes: usize,
    receive_packet_bytes: usize,
    require_event_larger_than_mtu: bool,
}

impl ValidatorConfig {
    /// Parses and completely validates one bounded JSON configuration.
    pub fn from_json(input: &str) -> Result<Self, ValidatorError> {
        if input.is_empty() || input.len() > MAX_CONFIG_JSON_BYTES {
            return Err(ValidatorError::bounds(
                "validator configuration exceeds its bound",
            ));
        }
        let raw: RawValidatorConfig = serde_json::from_str(input)
            .map_err(|_| ValidatorError::configuration("validator configuration is invalid"))?;
        for value in [
            &raw.state_path,
            &raw.mission_bundle_path,
            &raw.mission_peer,
            &raw.bluetooth_address,
        ] {
            if value.is_empty() || value.len() > MAX_CONFIG_STRING_BYTES || value.contains('\0') {
                return Err(ValidatorError::configuration(
                    "validator configuration contains an invalid string",
                ));
            }
        }
        let state_path = PathBuf::from(raw.state_path);
        let mission_bundle_path = PathBuf::from(raw.mission_bundle_path);
        if state_path == mission_bundle_path {
            return Err(ValidatorError::configuration(
                "validator state and mission paths must be distinct",
            ));
        }
        validate_mission_file(&mission_bundle_path)?;
        let mission_peer = aster_node::parse_node_id(&raw.mission_peer).map_err(|_| {
            ValidatorError::configuration("validator mission peer identifier is invalid")
        })?;
        if !is_bluetooth_address(&raw.bluetooth_address) {
            return Err(ValidatorError::configuration(
                "validator Bluetooth address is invalid",
            ));
        }
        if !(MIN_LE_DYNAMIC_PSM..=MAX_LE_DYNAMIC_PSM).contains(&raw.psm) {
            return Err(ValidatorError::configuration(
                "validator LE PSM is outside the Ring-1 range",
            ));
        }
        if raw.event_text.is_empty() || raw.event_text.len() > MAX_EVENT_TEXT_BYTES {
            return Err(ValidatorError::configuration(
                "validator Event text is outside its bound",
            ));
        }
        if raw.send_packet_bytes == 0
            || raw.send_packet_bytes > usize::from(u16::MAX)
            || raw.receive_packet_bytes == 0
            || raw.receive_packet_bytes > usize::from(u16::MAX)
        {
            return Err(ValidatorError::configuration(
                "validator packet size is invalid",
            ));
        }
        if !raw.require_event_larger_than_mtu {
            return Err(ValidatorError::configuration(
                "validator must require an Event larger than the receive packet size",
            ));
        }
        Ok(Self {
            state_path,
            mission_bundle_path,
            mission_peer,
            bluetooth_address: raw.bluetooth_address,
            psm: raw.psm,
            event_text: raw.event_text,
            send_packet_bytes: raw.send_packet_bytes,
            receive_packet_bytes: raw.receive_packet_bytes,
            require_event_larger_than_mtu: raw.require_event_larger_than_mtu,
        })
    }

    /// Returns the private durable state path.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Returns the copied private mission bundle path.
    #[must_use]
    pub fn mission_bundle_path(&self) -> &Path {
        &self.mission_bundle_path
    }

    /// Returns the exact expected mission peer identity.
    #[must_use]
    pub const fn mission_peer(&self) -> [u8; 32] {
        self.mission_peer
    }

    /// Returns the manually selected transient Bluetooth address.
    #[must_use]
    pub fn bluetooth_address(&self) -> &str {
        &self.bluetooth_address
    }

    /// Returns the fixed Ring-1 LE PSM.
    #[must_use]
    pub const fn psm(&self) -> u16 {
        self.psm
    }

    /// Returns the exact bounded UTF-8 Event payload entered by the operator.
    #[must_use]
    pub fn event_text(&self) -> &str {
        &self.event_text
    }

    /// Returns Android's connected-socket maximum transmit packet size.
    #[must_use]
    pub const fn send_packet_bytes(&self) -> usize {
        self.send_packet_bytes
    }

    /// Returns Android's connected-socket maximum receive packet size.
    #[must_use]
    pub const fn receive_packet_bytes(&self) -> usize {
        self.receive_packet_bytes
    }

    /// Returns whether the validator requires a received Event page larger than the packet size.
    #[must_use]
    pub const fn require_event_larger_than_mtu(&self) -> bool {
        self.require_event_larger_than_mtu
    }
}

fn validate_mission_file(path: &Path) -> Result<(), ValidatorError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ValidatorError::configuration("validator mission bundle is unavailable"))?;
    if !metadata.file_type().is_file() {
        return Err(ValidatorError::configuration(
            "validator mission bundle is not a regular file",
        ));
    }
    if metadata.len()
        > u64::try_from(MAX_MISSION_BUNDLE_BYTES).expect("mission bundle bound fits in u64")
    {
        return Err(ValidatorError::bounds(
            "validator mission bundle exceeds its bound",
        ));
    }
    Ok(())
}

fn is_bluetooth_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 17
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 2 | 5 | 8 | 11 | 14) {
                *byte == b':'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

    struct TestPaths {
        root: PathBuf,
        state: PathBuf,
        mission: PathBuf,
    }

    impl TestPaths {
        fn new() -> Self {
            let suffix = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aster-ble-android-config-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create test root");
            let state = root.join("state");
            let mission = root.join("mission.bundle");
            fs::write(&mission, b"mission").expect("write mission fixture");
            Self {
                root,
                state,
                mission,
            }
        }

        fn json(&self) -> String {
            format!(
                concat!(
                    "{{",
                    "\"state_path\":\"{}\",",
                    "\"mission_bundle_path\":\"{}\",",
                    "\"mission_peer\":\"{}\",",
                    "\"bluetooth_address\":\"7C:FA:80:72:3B:7A\",",
                    "\"psm\":128,",
                    "\"event_text\":\"hello from Android\",",
                    "\"send_packet_bytes\":512,",
                    "\"receive_packet_bytes\":256,",
                    "\"require_event_larger_than_mtu\":true",
                    "}}"
                ),
                self.state.display(),
                self.mission.display(),
                "11".repeat(32),
            )
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn accepts_fixed_initiator_configuration() {
        let paths = TestPaths::new();

        let config = ValidatorConfig::from_json(&paths.json()).expect("valid configuration");

        assert_eq!(config.psm(), 0x0080);
        assert_eq!(config.send_packet_bytes(), 512);
        assert_eq!(config.receive_packet_bytes(), 256);
        assert_eq!(config.mission_peer(), [0x11; 32]);
        assert_eq!(config.event_text(), "hello from Android");
        assert_eq!(config.state_path(), paths.state);
        assert_eq!(config.mission_bundle_path(), paths.mission);
        assert!(config.require_event_larger_than_mtu());
    }

    #[test]
    fn preserves_exact_bounded_utf8_event_text() {
        let paths = TestPaths::new();
        let text = "Snowman ☃\n\"quoted\"\0";
        let input = paths.json().replace(
            "\"event_text\":\"hello from Android\"",
            &format!(
                "\"event_text\":{}",
                serde_json::to_string(text).expect("encode event text")
            ),
        );

        let config = ValidatorConfig::from_json(&input).expect("bounded event text");

        assert_eq!(config.event_text().as_bytes(), text.as_bytes());
    }

    #[test]
    fn rejects_empty_or_oversized_utf8_event_text() {
        let paths = TestPaths::new();
        for text in [String::new(), "é".repeat(513)] {
            let input = paths.json().replace(
                "\"event_text\":\"hello from Android\"",
                &format!(
                    "\"event_text\":{}",
                    serde_json::to_string(&text).expect("encode event text")
                ),
            );
            let error = ValidatorConfig::from_json(&input).expect_err("invalid event text");
            assert_eq!(error.category(), ValidatorErrorCategory::Configuration);
            if !text.is_empty() {
                assert!(!error.to_string().contains(&text));
            }
        }

        let boundary = "é".repeat(512);
        let input = paths.json().replace(
            "\"event_text\":\"hello from Android\"",
            &format!(
                "\"event_text\":{}",
                serde_json::to_string(&boundary).expect("encode boundary event text")
            ),
        );
        let config = ValidatorConfig::from_json(&input).expect("1,024-byte event text");
        assert_eq!(config.event_text().len(), 1_024);
    }

    #[test]
    fn rejects_malformed_or_unknown_json_fields() {
        let paths = TestPaths::new();
        let malformed = ValidatorConfig::from_json("{").expect_err("malformed JSON");
        assert_eq!(malformed.category(), ValidatorErrorCategory::Configuration);
        assert!(!malformed.to_string().contains('{'));

        let unknown = paths
            .json()
            .replacen("{", "{\"unexpected_secret\":\"do-not-echo\",", 1);
        let error = ValidatorConfig::from_json(&unknown).expect_err("unknown field");
        assert_eq!(error.category(), ValidatorErrorCategory::Configuration);
        assert!(!error.to_string().contains("do-not-echo"));
    }

    #[test]
    fn rejects_invalid_node_address_psm_packet_sizes_and_paths() {
        let paths = TestPaths::new();
        let cases = [
            paths.json().replace(&"11".repeat(32), "not-a-node-id"),
            paths.json().replace("7C:FA:80:72:3B:7A", "not-an-address"),
            paths.json().replace("\"psm\":128", "\"psm\":127"),
            paths
                .json()
                .replace("\"send_packet_bytes\":512", "\"send_packet_bytes\":0"),
            paths.json().replace(
                &format!("\"state_path\":\"{}\"", paths.state.display()),
                &format!("\"state_path\":\"{}\"", paths.mission.display()),
            ),
        ];

        for input in cases {
            let error = ValidatorConfig::from_json(&input).expect_err("invalid configuration");
            assert_eq!(error.category(), ValidatorErrorCategory::Configuration);
            assert!(!error.to_string().contains("not-a-node-id"));
            assert!(!error.to_string().contains("not-an-address"));
        }
    }

    #[test]
    fn rejects_mission_bundle_above_the_existing_bound() {
        let paths = TestPaths::new();
        File::options()
            .write(true)
            .open(&paths.mission)
            .expect("open mission fixture")
            .set_len(u64::try_from(MAX_MISSION_BUNDLE_BYTES + 1).expect("bound fits"))
            .expect("expand mission fixture");

        let error = ValidatorConfig::from_json(&paths.json()).expect_err("oversized mission");

        assert_eq!(error.category(), ValidatorErrorCategory::Bounds);
        assert!(
            !error
                .to_string()
                .contains(&paths.mission.display().to_string())
        );
    }
}
