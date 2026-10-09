use aster_mesh::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningBundle, ProvisioningLoadId,
    ProvisioningLoadReceipt, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, UnprotectedProvisioning,
};
use std::{error::Error, fmt};
use zeroize::Zeroizing;

/// Stable identity of the Docker Compose credential provider contract.
pub const PROVIDER_CONTRACT: &str = "aster-compose-secret-store/v1";

const VERSION: u16 = 1;
const PROVIDER_REFERENCE_MAGIC: &[u8; 8] = b"ASTRCSRF";
const PROVIDER_REFERENCE_BYTES: usize = 8 + 2 + 2 + 32 + 32;
const ASTER_REFERENCE_HEADER_BYTES: usize = 8 + 2 + 4;
const CANONICAL_REFERENCE_BYTES: usize = ASTER_REFERENCE_HEADER_BYTES + PROVIDER_REFERENCE_BYTES;
const ACTIVATION_MAGIC: &[u8; 8] = b"ASTRCSAC";
const ACTIVATION_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4;
/// Exact length of one canonical Compose activation.
pub const MAX_ACTIVATION_BYTES: usize = ACTIVATION_HEADER_BYTES + CANONICAL_REFERENCE_BYTES;
const TOKEN_MAGIC: &[u8; 8] = b"ASTRCSTK";
const TOKEN_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4;
const MAX_CLIENT_TOKEN_BYTES: usize = 256;
/// Maximum length of one canonical generation-bound Compose client token.
pub const MAX_CLIENT_TOKEN_ENVELOPE_BYTES: usize = TOKEN_HEADER_BYTES + MAX_CLIENT_TOKEN_BYTES;
const ENVELOPE_MAGIC: &[u8; 8] = b"ASTRCSEN";
const ENVELOPE_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4 + 4;
/// Maximum length of one canonical Compose provisioning envelope.
pub const MAX_ENVELOPE_BYTES: usize =
    ENVELOPE_HEADER_BYTES + CANONICAL_REFERENCE_BYTES + MAX_UNPROTECTED_PROVISIONING_BYTES;

/// Public, non-secret identity of one immutable credential generation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ComposeCredentialGeneration([u8; 32]);

impl ComposeCredentialGeneration {
    /// Constructs a generation identity from exact caller-owned bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact generation identity.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Debug for ComposeCredentialGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComposeCredentialGeneration([REDACTED])")
    }
}

/// Fixed, non-sensitive reason for a Compose credential failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ComposeCredentialReason {
    UnsupportedPlatform,
    FileAccess,
    InvalidMountBoundary,
    Changed,
    NotRegular,
    LinkCount,
    Ownership,
    Permissions,
    TooLarge,
    InvalidToken,
    InvalidActivation,
    InvalidEnvelope,
    InvalidBundle,
    ProviderMismatch,
    GenerationMismatch,
    ReferenceMismatch,
    OperationMismatch,
    AlreadyConsumed,
}

/// Sanitized Compose credential error carrying only a fixed public reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComposeCredentialError {
    reason: ComposeCredentialReason,
}

impl ComposeCredentialError {
    #[doc(hidden)]
    pub const fn new(reason: ComposeCredentialReason) -> Self {
        Self { reason }
    }

    /// Returns the fixed public reason without backend or path detail.
    pub const fn reason(&self) -> ComposeCredentialReason {
        self.reason
    }
}

impl fmt::Display for ComposeCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.reason {
            ComposeCredentialReason::UnsupportedPlatform => "unsupported credential platform",
            ComposeCredentialReason::FileAccess => "credential file access failed",
            ComposeCredentialReason::InvalidMountBoundary => "credential mount boundary is invalid",
            ComposeCredentialReason::Changed => "credential file changed during validation",
            ComposeCredentialReason::NotRegular => "credential is not a regular file",
            ComposeCredentialReason::LinkCount => "credential link count is invalid",
            ComposeCredentialReason::Ownership => "credential ownership is invalid",
            ComposeCredentialReason::Permissions => "credential permissions are invalid",
            ComposeCredentialReason::TooLarge => "credential exceeds its size limit",
            ComposeCredentialReason::InvalidToken => "credential token is invalid",
            ComposeCredentialReason::InvalidActivation => "credential activation is invalid",
            ComposeCredentialReason::InvalidEnvelope => "credential envelope is invalid",
            ComposeCredentialReason::InvalidBundle => "credential bundle is invalid",
            ComposeCredentialReason::ProviderMismatch => "credential provider does not match",
            ComposeCredentialReason::GenerationMismatch => "credential generation does not match",
            ComposeCredentialReason::ReferenceMismatch => "credential reference does not match",
            ComposeCredentialReason::OperationMismatch => "credential operation does not match",
            ComposeCredentialReason::AlreadyConsumed => "credential envelope was already consumed",
        })
    }
}

impl Error for ComposeCredentialError {}

/// Parsed bearer token bound to one immutable Compose credential generation.
pub struct ComposeClientToken {
    generation: ComposeCredentialGeneration,
    token: Zeroizing<Vec<u8>>,
}

impl ComposeClientToken {
    /// Opens and parses the fixed Compose client-token mount.
    pub fn from_fixed_file() -> Result<Self, ComposeCredentialError> {
        let encoded = crate::secret_file::read_fixed_secret(
            crate::CLIENT_TOKEN_PATH,
            MAX_CLIENT_TOKEN_ENVELOPE_BYTES,
        )?;
        Self::from_bytes(&encoded)
    }

    /// Parses one exact canonical generation-bound token envelope.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ComposeCredentialError> {
        if encoded.len() > MAX_CLIENT_TOKEN_ENVELOPE_BYTES {
            return Err(error(ComposeCredentialReason::TooLarge));
        }
        if encoded.len() < TOKEN_HEADER_BYTES
            || &encoded[..8] != TOKEN_MAGIC
            || read_u16(&encoded[8..10]) != Some(VERSION)
            || read_u16(&encoded[10..12]) != Some(0)
        {
            return Err(error(ComposeCredentialReason::InvalidToken));
        }
        let generation = ComposeCredentialGeneration::new(
            encoded[12..44]
                .try_into()
                .map_err(|_| error(ComposeCredentialReason::InvalidToken))?,
        );
        if generation.is_zero() {
            return Err(error(ComposeCredentialReason::GenerationMismatch));
        }
        let token_len = read_u32(&encoded[44..48])
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| error(ComposeCredentialReason::InvalidToken))?;
        if token_len == 0 {
            return Err(error(ComposeCredentialReason::InvalidToken));
        }
        if token_len > MAX_CLIENT_TOKEN_BYTES {
            return Err(error(ComposeCredentialReason::TooLarge));
        }
        let end = TOKEN_HEADER_BYTES
            .checked_add(token_len)
            .ok_or_else(|| error(ComposeCredentialReason::InvalidToken))?;
        if end != encoded.len() {
            return Err(error(ComposeCredentialReason::InvalidToken));
        }
        Ok(Self {
            generation,
            token: Zeroizing::new(encoded[TOKEN_HEADER_BYTES..].to_vec()),
        })
    }

    /// Returns the public generation identity carried by this token.
    pub const fn generation(&self) -> ComposeCredentialGeneration {
        self.generation
    }

    /// Releases token bytes only when the activation names the same generation.
    pub fn into_token_for_activation(
        self,
        activation: &ComposeActivation,
    ) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
        if self.generation != activation.generation {
            return Err(error(ComposeCredentialReason::GenerationMismatch));
        }
        Ok(self.token)
    }

    /// Releases token bytes only when an operator-selected manifest names the
    /// same public generation. This is used for post-start verification; the
    /// manifest does not authorize agent startup or provisioning.
    pub fn into_token_for_generation(
        self,
        generation: ComposeCredentialGeneration,
    ) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
        if self.generation != generation {
            return Err(error(ComposeCredentialReason::GenerationMismatch));
        }
        Ok(self.token)
    }
}

impl fmt::Debug for ComposeClientToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComposeClientToken([REDACTED])")
    }
}

/// Parsed mission activation bound to one provider generation and load.
#[derive(Clone)]
pub struct ComposeActivation {
    generation: ComposeCredentialGeneration,
    operation: ProvisioningLoadId,
    secret_ref: ProvisioningSecretRef,
}

impl ComposeActivation {
    /// Opens and parses the fixed Compose mission-activation mount.
    pub fn from_fixed_file() -> Result<Self, ComposeCredentialError> {
        let encoded = crate::secret_file::read_fixed_secret(
            crate::MISSION_ACTIVATION_PATH,
            MAX_ACTIVATION_BYTES,
        )?;
        Self::from_bytes(&encoded)
    }

    /// Parses one exact canonical activation.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ComposeCredentialError> {
        if encoded.len() != MAX_ACTIVATION_BYTES
            || &encoded[..8] != ACTIVATION_MAGIC
            || read_u16(&encoded[8..10]) != Some(VERSION)
            || read_u16(&encoded[10..12]) != Some(0)
            || read_u32(&encoded[44..48]) != Some(CANONICAL_REFERENCE_BYTES as u32)
        {
            return Err(error(ComposeCredentialReason::InvalidActivation));
        }
        let operation = ProvisioningLoadId::new(
            encoded[12..44]
                .try_into()
                .map_err(|_| error(ComposeCredentialReason::InvalidActivation))?,
        );
        let secret_ref = ProvisioningSecretRef::from_bytes(&encoded[ACTIVATION_HEADER_BYTES..])
            .map_err(|_| error(ComposeCredentialReason::InvalidActivation))?;
        let generation = provider_generation(&secret_ref)?;
        Ok(Self {
            generation,
            operation,
            secret_ref,
        })
    }

    /// Returns the generation named by this activation.
    pub const fn generation(&self) -> ComposeCredentialGeneration {
        self.generation
    }

    /// Returns the load operation named by this activation.
    pub const fn operation(&self) -> ProvisioningLoadId {
        self.operation
    }

    /// Returns the exact Aster provisioning reference.
    pub const fn secret_ref(&self) -> &ProvisioningSecretRef {
        &self.secret_ref
    }
}

impl fmt::Debug for ComposeActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComposeActivation([REDACTED])")
    }
}

/// Constructs the canonical Aster reference for one Compose generation.
pub fn provisioning_secret_ref(
    generation: ComposeCredentialGeneration,
    reference_id: [u8; 32],
) -> Result<ProvisioningSecretRef, ComposeCredentialError> {
    if generation.is_zero() {
        return Err(error(ComposeCredentialReason::GenerationMismatch));
    }
    let mut opaque = Vec::with_capacity(PROVIDER_REFERENCE_BYTES);
    opaque.extend_from_slice(PROVIDER_REFERENCE_MAGIC);
    opaque.extend_from_slice(&VERSION.to_be_bytes());
    opaque.extend_from_slice(&0_u16.to_be_bytes());
    opaque.extend_from_slice(generation.as_bytes());
    opaque.extend_from_slice(&reference_id);
    ProvisioningSecretRef::from_opaque(opaque)
        .map_err(|_| error(ComposeCredentialReason::InvalidActivation))
}

/// Encodes one canonical Compose activation.
pub fn encode_activation(
    generation: ComposeCredentialGeneration,
    operation: ProvisioningLoadId,
    secret_ref: &ProvisioningSecretRef,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    if provider_generation(secret_ref)? != generation {
        return Err(error(ComposeCredentialReason::GenerationMismatch));
    }
    let reference = Zeroizing::new(secret_ref.to_bytes());
    if reference.len() != CANONICAL_REFERENCE_BYTES {
        return Err(error(ComposeCredentialReason::InvalidActivation));
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_ACTIVATION_BYTES));
    encoded.extend_from_slice(ACTIVATION_MAGIC);
    encoded.extend_from_slice(&VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(operation.as_bytes());
    encoded.extend_from_slice(&(CANONICAL_REFERENCE_BYTES as u32).to_be_bytes());
    encoded.extend_from_slice(&reference);
    Ok(encoded)
}

/// Encodes one canonical generation-bound Compose client token.
pub fn encode_client_token(
    generation: ComposeCredentialGeneration,
    token: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    if generation.is_zero() {
        return Err(error(ComposeCredentialReason::GenerationMismatch));
    }
    if token.is_empty() {
        return Err(error(ComposeCredentialReason::InvalidToken));
    }
    if token.len() > MAX_CLIENT_TOKEN_BYTES {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    let token_len =
        u32::try_from(token.len()).map_err(|_| error(ComposeCredentialReason::TooLarge))?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(TOKEN_HEADER_BYTES + token.len()));
    encoded.extend_from_slice(TOKEN_MAGIC);
    encoded.extend_from_slice(&VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(generation.as_bytes());
    encoded.extend_from_slice(&token_len.to_be_bytes());
    encoded.extend_from_slice(token);
    Ok(encoded)
}

/// Encodes one canonical Compose provisioning envelope.
pub fn encode_provisioning_envelope(
    generation: ComposeCredentialGeneration,
    operation: ProvisioningLoadId,
    secret_ref: &ProvisioningSecretRef,
    plaintext: &UnprotectedProvisioning,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    if provider_generation(secret_ref)? != generation {
        return Err(error(ComposeCredentialReason::GenerationMismatch));
    }
    ProvisioningBundle::from_bytes(plaintext.expose())
        .map_err(|_| error(ComposeCredentialReason::InvalidBundle))?;
    let bundle_len =
        u32::try_from(plaintext.len()).map_err(|_| error(ComposeCredentialReason::TooLarge))?;
    let reference = Zeroizing::new(secret_ref.to_bytes());
    if reference.len() != CANONICAL_REFERENCE_BYTES {
        return Err(error(ComposeCredentialReason::InvalidEnvelope));
    }
    let total = ENVELOPE_HEADER_BYTES
        .checked_add(reference.len())
        .and_then(|length| length.checked_add(plaintext.len()))
        .ok_or_else(|| error(ComposeCredentialReason::TooLarge))?;
    if total > MAX_ENVELOPE_BYTES {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(total));
    encoded.extend_from_slice(ENVELOPE_MAGIC);
    encoded.extend_from_slice(&VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(operation.as_bytes());
    encoded.extend_from_slice(&(CANONICAL_REFERENCE_BYTES as u32).to_be_bytes());
    encoded.extend_from_slice(&bundle_len.to_be_bytes());
    encoded.extend_from_slice(&reference);
    encoded.extend_from_slice(plaintext.expose());
    Ok(encoded)
}

/// One-shot loader for one activation-bound Compose envelope.
pub struct ComposeProvisioningLoader {
    receipt: Option<ProvisioningLoadReceipt>,
}

impl ComposeProvisioningLoader {
    /// Opens the fixed provisioning-envelope mount into a one-shot loader.
    pub fn from_fixed_file(activation: ComposeActivation) -> Result<Self, ComposeCredentialError> {
        let envelope = crate::secret_file::read_fixed_secret(
            crate::PROVISIONING_BUNDLE_PATH,
            MAX_ENVELOPE_BYTES,
        )?;
        Self::from_envelope(activation, envelope)
    }

    /// Validates one activation and envelope before constructing a one-shot loader.
    pub fn from_envelope(
        activation: ComposeActivation,
        envelope: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ComposeCredentialError> {
        let operation = activation.operation();
        let secret_ref = activation.secret_ref().clone();
        let receipt = decode_envelope(envelope, &activation, operation, &secret_ref)?;
        Ok(Self {
            receipt: Some(receipt),
        })
    }

    /// Loads the envelope while preserving the provider's fixed reason.
    pub fn load_with_reason(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ComposeCredentialError> {
        let receipt = self
            .receipt
            .take()
            .ok_or_else(|| error(ComposeCredentialReason::AlreadyConsumed))?;
        if receipt.secret_ref() != secret_ref {
            return Err(error(ComposeCredentialReason::ReferenceMismatch));
        }
        if receipt.operation() != operation {
            return Err(error(ComposeCredentialReason::OperationMismatch));
        }
        Ok(receipt)
    }
}

impl fmt::Debug for ComposeProvisioningLoader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComposeProvisioningLoader([REDACTED])")
    }
}

impl ProvisioningSecretLoader for ComposeProvisioningLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.load_with_reason(operation, secret_ref)
            .map_err(map_store_error)
    }
}

fn decode_envelope(
    encoded: Zeroizing<Vec<u8>>,
    activation: &ComposeActivation,
    expected_operation: ProvisioningLoadId,
    expected_ref: &ProvisioningSecretRef,
) -> Result<ProvisioningLoadReceipt, ComposeCredentialError> {
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    if encoded.len() < ENVELOPE_HEADER_BYTES
        || &encoded[..8] != ENVELOPE_MAGIC
        || read_u16(&encoded[8..10]) != Some(VERSION)
        || read_u16(&encoded[10..12]) != Some(0)
    {
        return Err(error(ComposeCredentialReason::InvalidEnvelope));
    }
    let operation = ProvisioningLoadId::new(
        encoded[12..44]
            .try_into()
            .map_err(|_| error(ComposeCredentialReason::InvalidEnvelope))?,
    );
    let reference_len = read_u32(&encoded[44..48])
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| error(ComposeCredentialReason::InvalidEnvelope))?;
    let bundle_len = read_u32(&encoded[48..52])
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| error(ComposeCredentialReason::InvalidEnvelope))?;
    if reference_len != CANONICAL_REFERENCE_BYTES || bundle_len == 0 {
        return Err(error(ComposeCredentialReason::InvalidEnvelope));
    }
    if bundle_len > MAX_UNPROTECTED_PROVISIONING_BYTES {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    let reference_end = ENVELOPE_HEADER_BYTES
        .checked_add(reference_len)
        .ok_or_else(|| error(ComposeCredentialReason::InvalidEnvelope))?;
    let envelope_end = reference_end
        .checked_add(bundle_len)
        .ok_or_else(|| error(ComposeCredentialReason::InvalidEnvelope))?;
    if envelope_end != encoded.len() {
        return Err(error(ComposeCredentialReason::InvalidEnvelope));
    }
    let envelope_ref =
        ProvisioningSecretRef::from_bytes(&encoded[ENVELOPE_HEADER_BYTES..reference_end])
            .map_err(|_| error(ComposeCredentialReason::InvalidEnvelope))?;
    let envelope_generation = provider_generation(&envelope_ref)?;
    if envelope_generation != activation.generation {
        return Err(error(ComposeCredentialReason::GenerationMismatch));
    }
    if envelope_ref != activation.secret_ref || expected_ref != &activation.secret_ref {
        return Err(error(ComposeCredentialReason::ReferenceMismatch));
    }
    if operation != activation.operation || expected_operation != activation.operation {
        return Err(error(ComposeCredentialReason::OperationMismatch));
    }
    let bundle = &encoded[reference_end..];
    ProvisioningBundle::from_bytes(bundle)
        .map_err(|_| error(ComposeCredentialReason::InvalidBundle))?;
    let plaintext = UnprotectedProvisioning::new(bundle.to_vec())
        .map_err(|_| error(ComposeCredentialReason::InvalidBundle))?;
    Ok(ProvisioningLoadReceipt::new(
        expected_operation,
        expected_ref.clone(),
        plaintext,
    ))
}

fn provider_generation(
    secret_ref: &ProvisioningSecretRef,
) -> Result<ComposeCredentialGeneration, ComposeCredentialError> {
    let opaque = secret_ref.expose_opaque();
    if opaque.len() != PROVIDER_REFERENCE_BYTES
        || &opaque[..8] != PROVIDER_REFERENCE_MAGIC
        || read_u16(&opaque[8..10]) != Some(VERSION)
        || read_u16(&opaque[10..12]) != Some(0)
    {
        return Err(error(ComposeCredentialReason::ProviderMismatch));
    }
    let generation = ComposeCredentialGeneration::new(
        opaque[12..44]
            .try_into()
            .map_err(|_| error(ComposeCredentialReason::GenerationMismatch))?,
    );
    if generation.is_zero() {
        return Err(error(ComposeCredentialReason::GenerationMismatch));
    }
    Ok(generation)
}

const fn error(reason: ComposeCredentialReason) -> ComposeCredentialError {
    ComposeCredentialError::new(reason)
}

fn read_u16(bytes: &[u8]) -> Option<u16> {
    bytes.try_into().ok().map(u16::from_be_bytes)
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    bytes.try_into().ok().map(u32::from_be_bytes)
}

const fn map_store_error(error: ComposeCredentialError) -> ProvisioningSecretStoreError {
    match error.reason {
        ComposeCredentialReason::UnsupportedPlatform | ComposeCredentialReason::FileAccess => {
            ProvisioningSecretStoreError::Unavailable
        }
        ComposeCredentialReason::TooLarge => ProvisioningSecretStoreError::TooLarge,
        ComposeCredentialReason::AlreadyConsumed | ComposeCredentialReason::OperationMismatch => {
            ProvisioningSecretStoreError::OperationConflict
        }
        ComposeCredentialReason::ProviderMismatch
        | ComposeCredentialReason::GenerationMismatch
        | ComposeCredentialReason::ReferenceMismatch => {
            ProvisioningSecretStoreError::InvalidReference
        }
        ComposeCredentialReason::InvalidMountBoundary
        | ComposeCredentialReason::Changed
        | ComposeCredentialReason::NotRegular
        | ComposeCredentialReason::LinkCount
        | ComposeCredentialReason::Ownership
        | ComposeCredentialReason::Permissions
        | ComposeCredentialReason::InvalidToken
        | ComposeCredentialReason::InvalidActivation
        | ComposeCredentialReason::InvalidEnvelope
        | ComposeCredentialReason::InvalidBundle => ProvisioningSecretStoreError::Rejected,
    }
}
