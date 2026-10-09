//! Docker Compose credential store provider for Aster provisioning.

#![forbid(unsafe_code)]

mod format;
mod generation;
mod mountinfo;
mod secret_file;

pub use format::{
    ComposeActivation, ComposeClientToken, ComposeCredentialError, ComposeCredentialGeneration,
    ComposeCredentialReason, ComposeProvisioningLoader, MAX_ACTIVATION_BYTES,
    MAX_CLIENT_TOKEN_ENVELOPE_BYTES, MAX_ENVELOPE_BYTES, PROVIDER_CONTRACT, encode_activation,
    encode_client_token, encode_provisioning_envelope, provisioning_secret_ref,
};
pub use generation::{
    GenerationCreateError, GenerationCreateReason, GenerationCreateReceipt, create_generation,
};

/// Fixed Compose mount for the client bearer token.
pub const CLIENT_TOKEN_PATH: &str = "/run/secrets/aster-client-token";
/// Fixed Compose mount for the mission activation.
pub const MISSION_ACTIVATION_PATH: &str = "/run/secrets/aster-mission-activation";
/// Fixed Compose mount for the provisioning envelope.
pub const PROVISIONING_BUNDLE_PATH: &str = "/run/secrets/aster-provisioning-bundle";

/// Reads the fixed client-token mount through the fail-closed boundary.
pub fn read_client_token_file() -> Result<ComposeClientToken, ComposeCredentialError> {
    ComposeClientToken::from_fixed_file()
}

#[cfg(test)]
mod tests {
    #[test]
    fn link_count_normalization_accepts_platform_source_widths() {
        assert_eq!(super::secret_file::normalize_link_count(7_u32), 7_u64);
        assert_eq!(super::secret_file::normalize_link_count(9_u64), 9_u64);
    }
}
