//! Cryptographic provider boundary and RustCrypto reference implementation.
//!
//! The provider in this module is deliberately crate-internal: applications interact with
//! high-level publish/sync APIs, never raw cryptographic operations.  The fixed v1 suite is:
//! SHA-256, HKDF-SHA-256, AES-256-GCM, ECDSA P-256 **and** ML-DSA-65 signatures, and
//! P-256 ECDH **and** ML-KEM-768 key establishment.
//!
//! # Assurance boundary
//!
//! [`RustCryptoProvider`] is a portable reference provider. It is **not a FIPS 140-3 validated
//! cryptographic module**. A deployment which requires validated cryptography must provide a
//! different [`CryptoProvider`] backed by a validated module and retain the AND-composition and
//! transcript rules defined here.

mod classical;
mod facade;
mod profile;
mod reference;

pub use classical::{
    AuthenticatedChannelBinding, ClassicalAuthenticatedSession, ClassicalEnvelopeSealer,
    ClassicalProvisioner, ClassicalProvisioningAccess, ClassicalProvisioningBundle,
    ClassicalSessionAwaitingFinished, ClassicalSessionInitiator, ClassicalSessionResponder,
    ClassicalSessionResponderPending,
};
pub use facade::{ProfileEnvelopeSealer, ProfileProvisioningBundle};
pub use profile::{
    ApplicationProtection, CLASSICAL_SECURITY_PROFILE_ID, CLASSICAL_SUITE_ID,
    HYBRID_SECURITY_PROFILE_ID, SecurityProfile, SecurityProfileId, VerifiedSecurityProfile,
};

#[cfg(feature = "fuzzing")]
pub use reference::fuzz_reference_v9_session_pair;
pub(crate) use reference::{
    PendingBatchItem, VerifiedBatchItem, VerifiedBatchProof, VerifiedBridgeAuthorization,
    VerifiedBridgeSourceRoute, VerifiedBridgeWrapper,
};
pub use reference::{
    ProvisioningAccess, ProvisioningBundle, REFERENCE_SESSION_FRAME_OVERHEAD_BYTES,
    ReferenceAuthenticatedSession, ReferenceEnvelopeSealer, ReferenceProvisioner,
    ReferenceSessionAwaitingFinished, ReferenceSessionInitiator, ReferenceSessionResponder,
    ReferenceSessionResponderPending, ScopeRekeyPlan, ScopeRekeyRecipient,
};
#[cfg(feature = "sqlite-store")]
pub use reference::{ReferenceNode, open_reference_node};
#[cfg(test)]
pub(crate) use reference::{SessionPrivacyCanaries, session_privacy_canaries};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use hkdf::Hkdf;
use ml_dsa::{
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, Generate as MlDsaGenerate, Keypair, MlDsa65,
    Signature as MlDsaSignature, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey,
    Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{
    B32 as MlKemRandomness, Ciphertext as MlKemCiphertext, Decapsulate,
    EncapsulationKey768 as MlKemEncapsulationKey, Generate as MlKemGenerate, Key as MlKemKey,
    KeyExport as MlKemKeyExport, MlKem768, ml_kem_768::DecapsulationKey as MlKemDecapsulationKey,
};
use p256::{
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
    ecdh::diffie_hellman,
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
        signature::{Signer as P256Signer, Verifier as P256Verifier},
    },
    elliptic_curve::{Generate as P256Generate, sec1::ToSec1Point},
};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use zeroize::Zeroize;

/// Stable credential, envelope, and cryptographic-profile encoding version.
///
/// This is deliberately independent from the semantic replication version
/// negotiated inside the authenticated handshake.
pub(crate) const PROTOCOL_VERSION: u16 = 1;
pub(crate) const SEMANTIC_PROTOCOL_V1: u16 = 1;
pub(crate) const SEMANTIC_PROTOCOL_V2: u16 = 2;
pub(crate) const SEMANTIC_PROTOCOL_V3: u16 = 3;
pub(crate) const SEMANTIC_PROTOCOL_V4: u16 = 4;
pub(crate) const SEMANTIC_PROTOCOL_V5: u16 = 5;
pub(crate) const SEMANTIC_PROTOCOL_V6: u16 = 6;
pub(crate) const SEMANTIC_PROTOCOL_V7: u16 = 7;
pub(crate) const SEMANTIC_PROTOCOL_V8: u16 = 8;
pub(crate) const SEMANTIC_PROTOCOL_V9: u16 = 9;
pub(crate) const HYBRID_SUITE_ID: u16 = 0x0001;

const NONCE_LEN: usize = 12;
const HASH_LEN: usize = 32;
const MAX_OFFERED_VERSIONS: usize = 16;
const MAX_OFFERED_SUITES: usize = 16;
pub(crate) const SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS: &[u16] = &[
    SEMANTIC_PROTOCOL_V9,
    SEMANTIC_PROTOCOL_V8,
    SEMANTIC_PROTOCOL_V7,
    SEMANTIC_PROTOCOL_V6,
    SEMANTIC_PROTOCOL_V5,
    SEMANTIC_PROTOCOL_V4,
    SEMANTIC_PROTOCOL_V3,
    SEMANTIC_PROTOCOL_V2,
    SEMANTIC_PROTOCOL_V1,
];
// Preference order is policy, never numeric suite-ID order.
const SUPPORTED_HYBRID_SUITES: &[u16] = &[HYBRID_SUITE_ID];
const HYBRID_SUITE_LABEL: &[u8] =
    b"ASTER-v1/P256+ML-KEM-768/ECDSA-P256+ML-DSA-65/AES-256-GCM/HKDF-SHA256";
const KDF_DOMAIN: &[u8] = b"ASTER-KDF-v1";
const RECORD_AAD_DOMAIN: &[u8] = b"ASTER-RECORD-AAD-v1";
const CLIENT_HELLO_DOMAIN: &[u8] = b"ASTER-CLIENT-HELLO-v1";
const SERVER_HELLO_DOMAIN: &[u8] = b"ASTER-SERVER-HELLO-v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"ASTER-HANDSHAKE-TRANSCRIPT-v1";
const SERVER_AUTH_DOMAIN: &[u8] = b"ASTER-SERVER-AUTH-v1";
const CLIENT_AUTH_DOMAIN: &[u8] = b"ASTER-CLIENT-AUTH-v1";
const SERVER_CONFIRM_DOMAIN: &[u8] = b"ASTER-SERVER-CONFIRM-v1";
const CLIENT_CONFIRM_DOMAIN: &[u8] = b"ASTER-CLIENT-CONFIRM-v1";
const FINISHED_DOMAIN: &[u8] = b"ASTER-FINISHED-v1";
const SERVER_AUTH_PROTECTION_DOMAIN: &[u8] = b"ASTER-SERVER-AUTH-PROTECTION-v1";
const CLIENT_AUTH_PROTECTION_DOMAIN: &[u8] = b"ASTER-CLIENT-AUTH-PROTECTION-v1";
const SERVER_FINISHED_DOMAIN: &[u8] = b"ASTER-SERVER-FINISHED-v1";
const MAX_HANDSHAKE_AUTH_CONTEXT: usize = 1024 * 1024;

pub(crate) type Hash32 = [u8; HASH_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoAssurance {
    ReferenceOnlyNotFipsValidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoError {
    RandomnessUnavailable,
    NonceExhausted,
    EncryptionFailed,
    AuthenticationFailed,
    KdfFailed,
    LengthExceeded,
    InvalidClassicalKey,
    InvalidPostQuantumKey,
    InvalidPostQuantumCiphertext,
    MissingClassicalSignature,
    MissingPostQuantumSignature,
    InvalidClassicalSignature,
    InvalidPostQuantumSignature,
    KeyZeroized,
    UnsupportedProtocolVersion,
    InvalidVersionOffer,
    UnsupportedSuite,
    InvalidSuiteOffer,
    InvalidHandshake,
    KeyConfirmationFailed,
    SequenceExhausted,
    ReplayDetected,
    ReplayTooOld,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RandomnessUnavailable => "cryptographic randomness is unavailable",
            Self::NonceExhausted => "AEAD nonce space is exhausted",
            Self::EncryptionFailed => "authenticated encryption failed",
            Self::AuthenticationFailed => "authenticated decryption failed",
            Self::KdfFailed => "key derivation failed",
            Self::LengthExceeded => "cryptographic input exceeds the encoded length limit",
            Self::InvalidClassicalKey => "invalid P-256 key",
            Self::InvalidPostQuantumKey => "invalid post-quantum key",
            Self::InvalidPostQuantumCiphertext => "invalid ML-KEM ciphertext",
            Self::MissingClassicalSignature => "required ECDSA signature is missing",
            Self::MissingPostQuantumSignature => "required ML-DSA signature is missing",
            Self::InvalidClassicalSignature => "ECDSA signature verification failed",
            Self::InvalidPostQuantumSignature => "ML-DSA signature verification failed",
            Self::KeyZeroized => "cryptographic key has been zeroized",
            Self::UnsupportedProtocolVersion => "unsupported cryptographic protocol version",
            Self::InvalidVersionOffer => "invalid cryptographic protocol version offer",
            Self::UnsupportedSuite => "required hybrid cryptographic suite is unavailable",
            Self::InvalidSuiteOffer => "invalid cryptographic suite offer",
            Self::InvalidHandshake => "invalid hybrid handshake message",
            Self::KeyConfirmationFailed => "hybrid handshake key confirmation failed",
            Self::SequenceExhausted => "sender sequence space is exhausted",
            Self::ReplayDetected => "record sequence has already been accepted",
            Self::ReplayTooOld => "record sequence is outside the replay window",
        };
        f.write_str(message)
    }
}

impl Error for CryptoError {}

/// A secret which is explicitly erased on drop. It intentionally does not implement `Clone`.
pub(crate) struct Secret32([u8; HASH_LEN]);

impl Secret32 {
    fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub(crate) fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32([REDACTED])")
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct SecretBuffer(Vec<u8>);

impl SecretBuffer {
    fn with_two(left: &Secret32, right: &Secret32) -> Self {
        let mut bytes = Vec::with_capacity(HASH_LEN * 2);
        bytes.extend_from_slice(left.expose());
        bytes.extend_from_slice(right.expose());
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AeadCiphertext {
    pub(crate) nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 128-bit GCM authentication tag appended.
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HybridVerifyingKey {
    /// Compressed SEC1 P-256 point.
    pub(crate) p256_sec1: Vec<u8>,
    /// FIPS 204 ML-DSA-65 encoded verification key.
    pub(crate) ml_dsa_65: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HybridSignature {
    /// Raw fixed-width `(r || s)` ECDSA P-256 signature.
    pub(crate) ecdsa_p256: Option<Vec<u8>>,
    /// FIPS 204 ML-DSA-65 encoded signature.
    pub(crate) ml_dsa_65: Option<Vec<u8>>,
}

/// Explicit destruction contract for long-term identity keys.
pub(crate) trait ZeroizeKey {
    fn zeroize_key(&mut self);
    fn is_zeroized(&self) -> bool;
}

/// Internal boundary which allows a validated module to replace the reference implementation.
pub(crate) trait CryptoProvider {
    type SigningKey: ZeroizeKey;
    type EcdhSecret;
    type KemDecapsulationKey;

    fn assurance(&self) -> CryptoAssurance;
    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), CryptoError>;
    fn hash_id(&self, input: &[u8]) -> Hash32;
    fn derive_secret(
        &self,
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        label: &[u8],
        context: &[u8],
    ) -> Result<Secret32, CryptoError>;
    fn seal(
        &mut self,
        key: &Secret32,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<AeadCiphertext, CryptoError>;
    fn open(
        &self,
        key: &Secret32,
        sealed: &AeadCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Retained for provider conformance and deterministic internal tests; production identity
    /// keys enter through the opaque provisioning service.
    #[allow(dead_code)]
    fn generate_signing_key(&mut self) -> Result<Self::SigningKey, CryptoError>;
    fn verifying_key(
        &self,
        signing_key: &Self::SigningKey,
    ) -> Result<HybridVerifyingKey, CryptoError>;
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<HybridSignature, CryptoError>;
    fn verify(
        &self,
        verifying_key: &HybridVerifyingKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), CryptoError>;

    fn generate_ecdh_keypair(&mut self) -> Result<(Self::EcdhSecret, Vec<u8>), CryptoError>;
    fn ecdh_agree(
        &self,
        secret: &Self::EcdhSecret,
        peer_public_key: &[u8],
    ) -> Result<Secret32, CryptoError>;
    fn generate_kem_keypair(&mut self)
    -> Result<(Self::KemDecapsulationKey, Vec<u8>), CryptoError>;
    fn kem_encapsulate(
        &mut self,
        peer_encapsulation_key: &[u8],
    ) -> Result<(Vec<u8>, Secret32), CryptoError>;
    fn kem_decapsulate(
        &self,
        decapsulation_key: &Self::KemDecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<Secret32, CryptoError>;
}

/// One exact semantic-v2 compact representation produced by a batch seal.
pub(crate) struct SealedBatchItem {
    pub(crate) item_id: Hash32,
    pub(crate) envelope_id: Hash32,
    pub(crate) bytes: Vec<u8>,
}

impl fmt::Debug for SealedBatchItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedBatchItem")
            .field("item_id", &self.item_id)
            .field("envelope_id", &self.envelope_id)
            .field("sealed_len", &self.bytes.len())
            .field("plaintext", &"[NONE]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Atomic cryptographic output for one source-created semantic-v2 batch.
pub(crate) struct SealedSourceBatch {
    pub(crate) batch_id: Hash32,
    pub(crate) proof_envelope_id: Hash32,
    pub(crate) proof_bytes: Vec<u8>,
    pub(crate) items: Vec<SealedBatchItem>,
}

impl fmt::Debug for SealedSourceBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedSourceBatch")
            .field("batch_id", &self.batch_id)
            .field("proof_envelope_id", &self.proof_envelope_id)
            .field("proof_sealed_len", &self.proof_bytes.len())
            .field("item_count", &self.items.len())
            .field("plaintext", &"[NONE]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Internal semantic-v2 content-committing batch boundary.
///
/// Pending and verified associated values are provider-created capabilities.
/// A compact item can expose its exact proof dependency while remaining
/// unaccepted until the provider receives the matching verified proof.
#[allow(dead_code)]
pub(crate) trait BatchCryptoProvider {
    type Error;
    type PendingItem;
    type VerifiedProof;
    type VerifiedItem;

    fn seal_source_batch(
        &mut self,
        requests: &[crate::engine::SealRequest<'_>],
    ) -> Result<SealedSourceBatch, Self::Error>;

    fn open_batch_proof(
        &self,
        sealed: &[u8],
        selected_semantic_version: u16,
    ) -> Result<Self::VerifiedProof, Self::Error>;

    fn open_compact_batch_item(
        &self,
        sealed: &[u8],
        selected_semantic_version: u16,
    ) -> Result<Self::PendingItem, Self::Error>;

    fn pending_batch_proof_id(&self, pending: &Self::PendingItem) -> Hash32;

    fn verify_compact_batch_item(
        &self,
        pending: &Self::PendingItem,
        proof: Option<&Self::VerifiedProof>,
        sealed: &[u8],
    ) -> Result<Self::VerifiedItem, Self::Error>;

    fn open_compact_batch_payload(
        &self,
        verified: &Self::VerifiedItem,
        sealed: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Internal semantic-v2 bridge boundary.
///
/// The associated verified values are provider-created capabilities. This seam
/// deliberately exposes neither provisioned seeds nor derived keys, and it is
/// separate from the primitive provider so a validated implementation can keep
/// bridge policy and key handles inside its module boundary.
#[allow(dead_code)]
pub(crate) trait BridgeCryptoProvider {
    type Error;
    type EdgeEnrollment;
    type VerifiedEdgeEnrollment;
    type VerifiedAuthorization;
    type VerifiedSourceRoute;
    type VerifiedWrapper;

    /// Stable mission identifier used only for provider/service consistency.
    fn bridge_mission_id(&self) -> [u8; 32];

    /// Creates a bridge-node-signed, authority-verifiable enrollment for one
    /// exact directed scope-epoch edge. The returned value is opaque outside
    /// the provider boundary.
    fn create_bridge_edge_enrollment(
        &self,
        source_scope: &crate::model::Scope,
        source_route_epoch: u64,
        target_scope: &crate::model::Scope,
        target_route_epoch: u64,
    ) -> Result<Self::EdgeEnrollment, Self::Error>;

    /// Authenticates an opaque enrollment against this authority provider.
    fn open_bridge_edge_enrollment(
        &self,
        enrollment: &Self::EdgeEnrollment,
    ) -> Result<Self::VerifiedEdgeEnrollment, Self::Error>;

    /// Returns only non-secret, policy-relevant authenticated claims.
    fn bridge_edge_enrollment_claims(
        enrollment: &Self::VerifiedEdgeEnrollment,
    ) -> BridgeEdgeEnrollmentClaims;

    /// Binds provider-owned credential and route-commitment material into an
    /// authorization whose public claims already match the verified enrollment.
    fn bind_bridge_edge_enrollment(
        &self,
        enrollment: &Self::VerifiedEdgeEnrollment,
        authorization: &mut crate::bridge::BridgeAuthorization,
    ) -> Result<(), Self::Error>;

    fn bind_own_bridge_credential(
        &self,
        authorization: &mut crate::bridge::BridgeAuthorization,
    ) -> Result<(), Self::Error>;

    fn seal_bridge_authorization(
        &mut self,
        authorization: crate::bridge::BridgeAuthorization,
    ) -> Result<Vec<u8>, Self::Error>;

    fn open_bridge_authorization(
        &self,
        sealed: &[u8],
    ) -> Result<Self::VerifiedAuthorization, Self::Error>;

    fn open_source_route_for_bridge(
        &self,
        source_envelope: &[u8],
    ) -> Result<Self::VerifiedSourceRoute, Self::Error>;

    fn verify_copied_source_route_for_bridge(
        &self,
        source_envelope: &[u8],
        exact_route_descriptor: &[u8],
    ) -> Result<Self::VerifiedSourceRoute, Self::Error>;

    fn sign_bridge_hop(
        &self,
        route: &mut crate::bridge::BridgeRoute,
        index: usize,
    ) -> Result<(), Self::Error>;

    fn verify_bridge_hop(
        &self,
        route: &crate::bridge::BridgeRoute,
        index: usize,
        authorization: &Self::VerifiedAuthorization,
    ) -> Result<(), Self::Error>;

    fn seal_bridge_wrapper(
        &mut self,
        route: &crate::bridge::BridgeRoute,
        source: &Self::VerifiedSourceRoute,
        target_scope: &crate::model::Scope,
        target_route_epoch: u64,
    ) -> Result<Vec<u8>, Self::Error>;

    fn open_bridge_wrapper(
        &self,
        sealed: &[u8],
        target_scope: &crate::model::Scope,
        target_route_epoch: u64,
    ) -> Result<Self::VerifiedWrapper, Self::Error>;

    /// Authenticates against only the provider's bounded local route handles,
    /// then requires the protected route to name the handle that succeeded.
    fn open_bridge_wrapper_for_any_local_route(
        &self,
        sealed: &[u8],
    ) -> Result<Self::VerifiedWrapper, Self::Error>;

    fn verify_bridge_wrapper_source(
        &self,
        wrapper: &Self::VerifiedWrapper,
        source_envelope: &[u8],
    ) -> Result<Self::VerifiedSourceRoute, Self::Error>;

    fn open_bridged_payload(
        &self,
        source: &Self::VerifiedSourceRoute,
        source_envelope: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Provider-owned bridge enrollment artifact. Its authenticated bytes are
/// deliberately inaccessible to application, engine, store, and transport APIs.
pub(crate) struct BridgeEdgeEnrollment {
    bytes: Vec<u8>,
}

impl fmt::Debug for BridgeEdgeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeEdgeEnrollment")
            .field("authenticated_artifact", &"[PROVIDER-OWNED]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Non-secret claims authenticated by an opaque bridge enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeEdgeEnrollmentClaims {
    pub(crate) mission_id: [u8; 32],
    pub(crate) bridge_node_id: crate::model::NodeId,
    pub(crate) source_scope: crate::model::Scope,
    pub(crate) source_route_epoch: u64,
    pub(crate) target_scope: crate::model::Scope,
    pub(crate) target_route_epoch: u64,
}

/// Long-term hybrid identity key for the RustCrypto reference provider.
pub(crate) struct RustCryptoSigningKey {
    p256: Option<P256SigningKey>,
    ml_dsa: Option<MlDsaSigningKey<MlDsa65>>,
}

impl fmt::Debug for RustCryptoSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustCryptoSigningKey")
            .field("zeroized", &self.is_zeroized())
            .finish()
    }
}

impl ZeroizeKey for RustCryptoSigningKey {
    fn zeroize_key(&mut self) {
        // Both dependency key types erase their secret representation on drop when the required
        // features listed in the evidence record are enabled.
        self.p256 = None;
        self.ml_dsa = None;
    }

    fn is_zeroized(&self) -> bool {
        self.p256.is_none() || self.ml_dsa.is_none()
    }
}

/// Portable RustCrypto implementation. This type is not FIPS 140-3 validated.
pub(crate) struct RustCryptoProvider<R> {
    rng: R,
    nonce_prefix: [u8; 4],
    nonce_counter: u64,
    nonce_start: u64,
    nonce_exhausted: bool,
}

impl<R: TryCryptoRng> RustCryptoProvider<R> {
    /// Creates a provider and reserves a random 96-bit nonce starting point.
    ///
    /// Nonces are a random 32-bit process domain followed by a random-starting 64-bit monotonic
    /// sequence. They are unique for the provider lifetime; wrapping is rejected. A new provider
    /// must always be constructed with a fresh CSPRNG after process restart.
    pub(crate) fn try_new(mut rng: R) -> Result<Self, CryptoError> {
        let mut nonce_seed = [0u8; NONCE_LEN];
        rng.try_fill_bytes(&mut nonce_seed)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&nonce_seed[..4]);
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&nonce_seed[4..]);
        let counter = u64::from_be_bytes(counter_bytes);
        nonce_seed.zeroize();
        counter_bytes.zeroize();

        Ok(Self {
            rng,
            nonce_prefix: prefix,
            nonce_counter: counter,
            nonce_start: counter,
            nonce_exhausted: false,
        })
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], CryptoError> {
        if self.nonce_exhausted {
            return Err(CryptoError::NonceExhausted);
        }

        let current = self.nonce_counter;
        let next = current.wrapping_add(1);
        if next == self.nonce_start {
            self.nonce_exhausted = true;
        }
        self.nonce_counter = next;

        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&current.to_be_bytes());
        Ok(nonce)
    }

    fn live_keys<'a>(
        &self,
        key: &'a RustCryptoSigningKey,
    ) -> Result<(&'a P256SigningKey, &'a MlDsaSigningKey<MlDsa65>), CryptoError> {
        match (&key.p256, &key.ml_dsa) {
            (Some(classical), Some(post_quantum)) => Ok((classical, post_quantum)),
            _ => Err(CryptoError::KeyZeroized),
        }
    }

    fn open_parts(
        &self,
        key: &Secret32,
        nonce: [u8; NONCE_LEN],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut key_array = Array(*key.expose());
        let cipher = Aes256Gcm::new(&key_array);
        key_array.as_mut_slice().zeroize();
        let nonce_array = Array(nonce);
        cipher
            .decrypt(
                &nonce_array,
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn seal_with_nonce(
        &self,
        key: &Secret32,
        nonce: [u8; NONCE_LEN],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut key_array = Array(*key.expose());
        let cipher = Aes256Gcm::new(&key_array);
        key_array.as_mut_slice().zeroize();
        let nonce_array = Array(nonce);
        cipher
            .encrypt(
                &nonce_array,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }
}

impl<R> Drop for RustCryptoProvider<R> {
    fn drop(&mut self) {
        self.nonce_prefix.zeroize();
        self.nonce_counter.zeroize();
        self.nonce_start.zeroize();
        self.nonce_exhausted = true;
    }
}

impl<R: TryCryptoRng> CryptoProvider for RustCryptoProvider<R> {
    type SigningKey = RustCryptoSigningKey;
    type EcdhSecret = P256SecretKey;
    type KemDecapsulationKey = MlKemDecapsulationKey;

    fn assurance(&self) -> CryptoAssurance {
        CryptoAssurance::ReferenceOnlyNotFipsValidated
    }

    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        self.rng
            .try_fill_bytes(output)
            .map_err(|_| CryptoError::RandomnessUnavailable)
    }

    fn hash_id(&self, input: &[u8]) -> Hash32 {
        let digest = Sha256::digest(input);
        let mut result = [0u8; HASH_LEN];
        result.copy_from_slice(&digest);
        result
    }

    fn derive_secret(
        &self,
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        label: &[u8],
        context: &[u8],
    ) -> Result<Secret32, CryptoError> {
        let label_len = u16::try_from(label.len()).map_err(|_| CryptoError::LengthExceeded)?;
        let context_len = u32::try_from(context.len()).map_err(|_| CryptoError::LengthExceeded)?;
        let mut info = Vec::with_capacity(KDF_DOMAIN.len() + 2 + label.len() + 4 + context.len());
        info.extend_from_slice(KDF_DOMAIN);
        info.extend_from_slice(&label_len.to_be_bytes());
        info.extend_from_slice(label);
        info.extend_from_slice(&context_len.to_be_bytes());
        info.extend_from_slice(context);

        let hkdf = Hkdf::<Sha256>::new(salt, input_key_material);
        let mut output = [0u8; HASH_LEN];
        hkdf.expand(&info, &mut output)
            .map_err(|_| CryptoError::KdfFailed)?;
        Ok(Secret32::new(output))
    }

    fn seal(
        &mut self,
        key: &Secret32,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<AeadCiphertext, CryptoError> {
        let nonce = self.next_nonce()?;
        let mut key_array = Array(*key.expose());
        let cipher = Aes256Gcm::new(&key_array);
        key_array.as_mut_slice().zeroize();
        let nonce_array = Array(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce_array,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(AeadCiphertext { nonce, ciphertext })
    }

    fn open(
        &self,
        key: &Secret32,
        sealed: &AeadCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.open_parts(key, sealed.nonce, &sealed.ciphertext, associated_data)
    }

    fn generate_signing_key(&mut self) -> Result<Self::SigningKey, CryptoError> {
        let p256 = <P256SigningKey as P256Generate>::try_generate_from_rng(&mut self.rng)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        let ml_dsa =
            <MlDsaSigningKey<MlDsa65> as MlDsaGenerate>::try_generate_from_rng(&mut self.rng)
                .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(RustCryptoSigningKey {
            p256: Some(p256),
            ml_dsa: Some(ml_dsa),
        })
    }

    fn verifying_key(
        &self,
        signing_key: &Self::SigningKey,
    ) -> Result<HybridVerifyingKey, CryptoError> {
        let (p256, ml_dsa) = self.live_keys(signing_key)?;
        Ok(HybridVerifyingKey {
            p256_sec1: p256.verifying_key().to_sec1_point(true).as_ref().to_vec(),
            ml_dsa_65: ml_dsa.verifying_key().encode().as_slice().to_vec(),
        })
    }

    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<HybridSignature, CryptoError> {
        let (p256, ml_dsa) = self.live_keys(signing_key)?;
        let classical: P256Signature = P256Signer::try_sign(p256, message)
            .map_err(|_| CryptoError::InvalidClassicalSignature)?;
        let post_quantum: MlDsaSignature<MlDsa65> = MlDsaSigner::try_sign(ml_dsa, message)
            .map_err(|_| CryptoError::InvalidPostQuantumSignature)?;
        Ok(HybridSignature {
            ecdsa_p256: Some(classical.to_bytes().as_slice().to_vec()),
            ml_dsa_65: Some(post_quantum.encode().as_slice().to_vec()),
        })
    }

    fn verify(
        &self,
        verifying_key: &HybridVerifyingKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), CryptoError> {
        let classical_bytes = signature
            .ecdsa_p256
            .as_deref()
            .ok_or(CryptoError::MissingClassicalSignature)?;
        let post_quantum_bytes = signature
            .ml_dsa_65
            .as_deref()
            .ok_or(CryptoError::MissingPostQuantumSignature)?;

        let classical_key = P256VerifyingKey::from_sec1_bytes(&verifying_key.p256_sec1)
            .map_err(|_| CryptoError::InvalidClassicalKey)?;
        let classical_signature = P256Signature::from_slice(classical_bytes)
            .map_err(|_| CryptoError::InvalidClassicalSignature)?;

        let encoded_pq_key =
            MlDsaEncodedVerifyingKey::<MlDsa65>::try_from(verifying_key.ml_dsa_65.as_slice())
                .map_err(|_| CryptoError::InvalidPostQuantumKey)?;
        let post_quantum_key = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded_pq_key);
        let post_quantum_signature = MlDsaSignature::<MlDsa65>::try_from(post_quantum_bytes)
            .map_err(|_| CryptoError::InvalidPostQuantumSignature)?;

        P256Verifier::verify(&classical_key, message, &classical_signature)
            .map_err(|_| CryptoError::InvalidClassicalSignature)?;
        MlDsaVerifier::verify(&post_quantum_key, message, &post_quantum_signature)
            .map_err(|_| CryptoError::InvalidPostQuantumSignature)?;
        Ok(())
    }

    fn generate_ecdh_keypair(&mut self) -> Result<(Self::EcdhSecret, Vec<u8>), CryptoError> {
        let secret = <P256SecretKey as P256Generate>::try_generate_from_rng(&mut self.rng)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        let public = secret.public_key().to_sec1_point(true).as_ref().to_vec();
        Ok((secret, public))
    }

    fn ecdh_agree(
        &self,
        secret: &Self::EcdhSecret,
        peer_public_key: &[u8],
    ) -> Result<Secret32, CryptoError> {
        let peer = P256PublicKey::from_sec1_bytes(peer_public_key)
            .map_err(|_| CryptoError::InvalidClassicalKey)?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        let mut output = [0u8; HASH_LEN];
        output.copy_from_slice(shared.raw_secret_bytes().as_ref());
        Ok(Secret32::new(output))
    }

    fn generate_kem_keypair(
        &mut self,
    ) -> Result<(Self::KemDecapsulationKey, Vec<u8>), CryptoError> {
        let decapsulation_key =
            <MlKemDecapsulationKey as MlKemGenerate>::try_generate_from_rng(&mut self.rng)
                .map_err(|_| CryptoError::RandomnessUnavailable)?;
        let public = decapsulation_key
            .encapsulation_key()
            .to_bytes()
            .as_slice()
            .to_vec();
        Ok((decapsulation_key, public))
    }

    fn kem_encapsulate(
        &mut self,
        peer_encapsulation_key: &[u8],
    ) -> Result<(Vec<u8>, Secret32), CryptoError> {
        let encoded = MlKemKey::<MlKemEncapsulationKey>::try_from(peer_encapsulation_key)
            .map_err(|_| CryptoError::InvalidPostQuantumKey)?;
        let peer =
            MlKemEncapsulationKey::new(&encoded).map_err(|_| CryptoError::InvalidPostQuantumKey)?;

        // The deterministic API is used only after obtaining all 256 bits from the caller-supplied
        // CSPRNG. This preserves fallible RNG handling instead of using an infallible wrapper.
        let mut randomness = MlKemRandomness::default();
        if self.rng.try_fill_bytes(randomness.as_mut_slice()).is_err() {
            randomness.as_mut_slice().zeroize();
            return Err(CryptoError::RandomnessUnavailable);
        }
        let (ciphertext, mut shared) = peer.encapsulate_deterministic(&randomness);
        randomness.as_mut_slice().zeroize();

        let mut output = [0u8; HASH_LEN];
        output.copy_from_slice(shared.as_ref());
        shared.as_mut_slice().zeroize();
        Ok((ciphertext.as_slice().to_vec(), Secret32::new(output)))
    }

    fn kem_decapsulate(
        &self,
        decapsulation_key: &Self::KemDecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<Secret32, CryptoError> {
        let encoded = MlKemCiphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_| CryptoError::InvalidPostQuantumCiphertext)?;
        let mut shared = decapsulation_key.decapsulate(&encoded);
        let mut output = [0u8; HASH_LEN];
        output.copy_from_slice(shared.as_ref());
        shared.as_mut_slice().zeroize();
        Ok(Secret32::new(output))
    }
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CryptoError> {
    let length = u32::try_from(value.len()).map_err(|_| CryptoError::LengthExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_canonical_offer(
    offered: &[u16],
    maximum: usize,
    invalid: CryptoError,
) -> Result<(), CryptoError> {
    if offered.is_empty() || offered.len() > maximum || offered.contains(&0) {
        return Err(invalid);
    }
    // Numeric descending order is the canonical wire order. It is deliberately independent of
    // local preference so the same set has one encoding and duplicate/reordered offers fail
    // before expensive key establishment.
    if offered.windows(2).any(|pair| pair[0] <= pair[1]) {
        return Err(invalid);
    }
    Ok(())
}

fn validate_version_offer(offered: &[u16]) -> Result<(), CryptoError> {
    validate_canonical_offer(
        offered,
        MAX_OFFERED_VERSIONS,
        CryptoError::InvalidVersionOffer,
    )
}

fn validate_suite_offer(offered: &[u16]) -> Result<(), CryptoError> {
    validate_canonical_offer(offered, MAX_OFFERED_SUITES, CryptoError::InvalidSuiteOffer)
}

fn select_highest_common_version(
    offered: &[u16],
    locally_supported: &[u16],
) -> Result<u16, CryptoError> {
    offered
        .iter()
        .copied()
        .filter(|candidate| locally_supported.contains(candidate))
        .max()
        .ok_or(CryptoError::UnsupportedProtocolVersion)
}

fn select_preferred_common_suite(
    offered: &[u16],
    local_preference: &[u16],
) -> Result<u16, CryptoError> {
    // Suite IDs are registry identifiers, not strength rankings. Local order is policy order.
    local_preference
        .iter()
        .copied()
        .find(|candidate| offered.contains(candidate))
        .ok_or(CryptoError::UnsupportedSuite)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClientHello {
    /// Canonical descending offer. Unknown future versions remain transcript-bound.
    pub(crate) supported_versions: Vec<u16>,
    /// Canonical descending complete-suite offer. Suites are indivisible: there is no
    /// component-by-component or classical-only fallback.
    pub(crate) offered_suites: Vec<u16>,
    pub(crate) initiator_nonce: Hash32,
    pub(crate) p256_ephemeral_public: Vec<u8>,
    pub(crate) ml_kem_768_encapsulation_key: Vec<u8>,
}

pub(crate) fn validate_client_hello(hello: &ClientHello) -> Result<(), CryptoError> {
    validate_version_offer(&hello.supported_versions)?;
    validate_suite_offer(&hello.offered_suites)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerHello {
    pub(crate) selected_version: u16,
    pub(crate) selected_suite: u16,
    pub(crate) responder_nonce: Hash32,
    pub(crate) p256_ephemeral_public: Vec<u8>,
    pub(crate) ml_kem_768_ciphertext: Vec<u8>,
    pub(crate) protected_auth: AeadCiphertext,
    pub(crate) confirmation: AeadCiphertext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClientFinish {
    pub(crate) protected_auth: AeadCiphertext,
    pub(crate) confirmation: AeadCiphertext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerFinished {
    pub(crate) protected_finished: AeadCiphertext,
}

fn encode_client_hello(hello: &ClientHello) -> Result<Vec<u8>, CryptoError> {
    validate_client_hello(hello)?;
    let version_count =
        u16::try_from(hello.supported_versions.len()).map_err(|_| CryptoError::LengthExceeded)?;
    let suite_count =
        u16::try_from(hello.offered_suites.len()).map_err(|_| CryptoError::LengthExceeded)?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(CLIENT_HELLO_DOMAIN);
    encoded.extend_from_slice(HYBRID_SUITE_LABEL);
    encoded.extend_from_slice(&version_count.to_be_bytes());
    for version in &hello.supported_versions {
        encoded.extend_from_slice(&version.to_be_bytes());
    }
    encoded.extend_from_slice(&suite_count.to_be_bytes());
    for suite in &hello.offered_suites {
        encoded.extend_from_slice(&suite.to_be_bytes());
    }
    encoded.extend_from_slice(&hello.initiator_nonce);
    append_len_prefixed(&mut encoded, &hello.p256_ephemeral_public)?;
    append_len_prefixed(&mut encoded, &hello.ml_kem_768_encapsulation_key)?;
    Ok(encoded)
}

pub(crate) fn client_hello_hash<P: CryptoProvider>(
    provider: &P,
    hello: &ClientHello,
) -> Result<Hash32, CryptoError> {
    Ok(provider.hash_id(&encode_client_hello(hello)?))
}

fn encode_server_hello_unsigned(hello: &ServerHello) -> Result<Vec<u8>, CryptoError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SERVER_HELLO_DOMAIN);
    encoded.extend_from_slice(HYBRID_SUITE_LABEL);
    encoded.extend_from_slice(&hello.selected_version.to_be_bytes());
    encoded.extend_from_slice(&hello.selected_suite.to_be_bytes());
    encoded.extend_from_slice(&hello.responder_nonce);
    append_len_prefixed(&mut encoded, &hello.p256_ephemeral_public)?;
    append_len_prefixed(&mut encoded, &hello.ml_kem_768_ciphertext)?;
    Ok(encoded)
}

fn transcript_hash<P: CryptoProvider>(
    provider: &P,
    client: &ClientHello,
    server: &ServerHello,
) -> Result<Hash32, CryptoError> {
    let client_bytes = encode_client_hello(client)?;
    let server_bytes = encode_server_hello_unsigned(server)?;
    let mut transcript =
        Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 8 + client_bytes.len() + server_bytes.len());
    transcript.extend_from_slice(TRANSCRIPT_DOMAIN);
    append_len_prefixed(&mut transcript, &client_bytes)?;
    append_len_prefixed(&mut transcript, &server_bytes)?;
    Ok(provider.hash_id(&transcript))
}

fn auth_message(
    domain: &[u8],
    transcript: &Hash32,
    prior_auth: Option<&[u8]>,
    credential_context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if credential_context.len() > MAX_HANDSHAKE_AUTH_CONTEXT {
        return Err(CryptoError::LengthExceeded);
    }
    let mut message = Vec::with_capacity(
        domain.len()
            + HASH_LEN
            + prior_auth.map_or(0, |value| value.len())
            + credential_context.len()
            + 8,
    );
    message.extend_from_slice(domain);
    message.extend_from_slice(transcript);
    append_len_prefixed(&mut message, prior_auth.unwrap_or_default())?;
    append_len_prefixed(&mut message, credential_context)?;
    Ok(message)
}

fn confirmation_aad(domain: &[u8], transcript: &Hash32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + HASH_LEN + HYBRID_SUITE_LABEL.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(HYBRID_SUITE_LABEL);
    aad.extend_from_slice(transcript);
    aad
}

fn final_transcript_hash<P: CryptoProvider>(
    provider: &P,
    transcript: &Hash32,
    server_auth: &[u8],
    client_auth: &[u8],
) -> Result<Hash32, CryptoError> {
    let mut encoded = Vec::with_capacity(
        FINISHED_DOMAIN.len() + HASH_LEN + server_auth.len() + client_auth.len() + 8,
    );
    encoded.extend_from_slice(FINISHED_DOMAIN);
    encoded.extend_from_slice(transcript);
    append_len_prefixed(&mut encoded, server_auth)?;
    append_len_prefixed(&mut encoded, client_auth)?;
    Ok(provider.hash_id(&encoded))
}

fn protection_aad(domain: &[u8], transcript: &Hash32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + HYBRID_SUITE_LABEL.len() + HASH_LEN);
    aad.extend_from_slice(domain);
    aad.extend_from_slice(HYBRID_SUITE_LABEL);
    aad.extend_from_slice(transcript);
    aad
}

fn encode_signature(output: &mut Vec<u8>, signature: &HybridSignature) -> Result<(), CryptoError> {
    let classical = signature
        .ecdsa_p256
        .as_deref()
        .ok_or(CryptoError::MissingClassicalSignature)?;
    let post_quantum = signature
        .ml_dsa_65
        .as_deref()
        .ok_or(CryptoError::MissingPostQuantumSignature)?;
    append_len_prefixed(output, classical)?;
    append_len_prefixed(output, post_quantum)
}

fn read_len_prefixed<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], CryptoError> {
    let length_bytes: [u8; 4] = input
        .get(..4)
        .ok_or(CryptoError::InvalidHandshake)?
        .try_into()
        .map_err(|_| CryptoError::InvalidHandshake)?;
    *input = &input[4..];
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| CryptoError::LengthExceeded)?;
    let value = input.get(..length).ok_or(CryptoError::InvalidHandshake)?;
    *input = &input[length..];
    Ok(value)
}

fn encode_handshake_auth(
    credential_context: &[u8],
    signature: &HybridSignature,
) -> Result<Vec<u8>, CryptoError> {
    if credential_context.len() > MAX_HANDSHAKE_AUTH_CONTEXT {
        return Err(CryptoError::LengthExceeded);
    }
    let mut encoded = Vec::new();
    append_len_prefixed(&mut encoded, credential_context)?;
    encode_signature(&mut encoded, signature)?;
    Ok(encoded)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakeAuthRole {
    Server,
    Client,
}

pub(crate) struct OpenedHandshakeAuth {
    credential_context: Vec<u8>,
    signature: HybridSignature,
    encoded: Vec<u8>,
    role: HandshakeAuthRole,
    public_transcript_hash: Hash32,
}

impl fmt::Debug for OpenedHandshakeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedHandshakeAuth")
            .field("credential_context_len", &self.credential_context.len())
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl Drop for OpenedHandshakeAuth {
    fn drop(&mut self) {
        self.credential_context.zeroize();
        if let Some(signature) = self.signature.ecdsa_p256.as_mut() {
            signature.zeroize();
        }
        if let Some(signature) = self.signature.ml_dsa_65.as_mut() {
            signature.zeroize();
        }
        self.encoded.zeroize();
        self.public_transcript_hash.zeroize();
    }
}

impl OpenedHandshakeAuth {
    pub(crate) fn credential_context(&self) -> &[u8] {
        &self.credential_context
    }

    fn into_encoded(mut self) -> Vec<u8> {
        std::mem::take(&mut self.encoded)
    }
}

fn decode_handshake_auth(
    mut encoded: Vec<u8>,
    role: HandshakeAuthRole,
    mut public_transcript_hash: Hash32,
) -> Result<OpenedHandshakeAuth, CryptoError> {
    let parsed = (|| {
        let mut remaining = encoded.as_slice();
        let credential_context = read_len_prefixed(&mut remaining)?;
        if credential_context.len() > MAX_HANDSHAKE_AUTH_CONTEXT {
            return Err(CryptoError::LengthExceeded);
        }
        let classical = read_len_prefixed(&mut remaining)?;
        let post_quantum = read_len_prefixed(&mut remaining)?;
        if !remaining.is_empty() {
            return Err(CryptoError::InvalidHandshake);
        }
        Ok((
            credential_context.to_vec(),
            HybridSignature {
                ecdsa_p256: Some(classical.to_vec()),
                ml_dsa_65: Some(post_quantum.to_vec()),
            },
        ))
    })();
    let (credential_context, signature) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            encoded.zeroize();
            public_transcript_hash.zeroize();
            return Err(error);
        }
    };
    Ok(OpenedHandshakeAuth {
        credential_context,
        signature,
        encoded,
        role,
        public_transcript_hash,
    })
}

fn make_schedule_context(
    selected_version: u16,
    selected_suite: u16,
    transcript: &Hash32,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(4 + HYBRID_SUITE_LABEL.len() + HASH_LEN);
    context.extend_from_slice(&selected_version.to_be_bytes());
    context.extend_from_slice(&selected_suite.to_be_bytes());
    context.extend_from_slice(HYBRID_SUITE_LABEL);
    context.extend_from_slice(transcript);
    context
}

struct HandshakeSchedule {
    initiator_to_responder: Secret32,
    responder_to_initiator: Secret32,
    server_auth_protection: Secret32,
    client_auth_protection: Secret32,
    server_confirmation: Secret32,
    client_confirmation: Secret32,
    server_finished: Secret32,
    selected_version: u16,
    selected_suite: u16,
}

fn derive_handshake_schedule<P: CryptoProvider>(
    provider: &P,
    classical_shared: Secret32,
    post_quantum_shared: Secret32,
    selected_version: u16,
    selected_suite: u16,
    transcript: &Hash32,
) -> Result<HandshakeSchedule, CryptoError> {
    // AND composition: both independently established secrets are required as HKDF input.
    let combined = SecretBuffer::with_two(&classical_shared, &post_quantum_shared);
    let context = make_schedule_context(selected_version, selected_suite, transcript);
    let initiator_to_responder = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"initiator-to-responder",
        &context,
    )?;
    let responder_to_initiator = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"responder-to-initiator",
        &context,
    )?;
    let server_auth_protection = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"server-handshake-protection",
        &context,
    )?;
    let client_auth_protection = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"client-handshake-protection",
        &context,
    )?;
    let server_confirmation = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"server-key-confirmation",
        &context,
    )?;
    let client_confirmation = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"client-key-confirmation",
        &context,
    )?;
    let server_finished = provider.derive_secret(
        combined.as_slice(),
        Some(transcript),
        b"server-finished-confirmation",
        &context,
    )?;
    Ok(HandshakeSchedule {
        initiator_to_responder,
        responder_to_initiator,
        server_auth_protection,
        client_auth_protection,
        server_confirmation,
        client_confirmation,
        server_finished,
        selected_version,
        selected_suite,
    })
}

fn make_confirmation<P: CryptoProvider>(
    provider: &mut P,
    key: &Secret32,
    domain: &[u8],
    transcript: &Hash32,
) -> Result<AeadCiphertext, CryptoError> {
    let aad = confirmation_aad(domain, transcript);
    provider.seal(key, &[], &aad)
}

fn verify_confirmation<P: CryptoProvider>(
    provider: &P,
    key: &Secret32,
    domain: &[u8],
    transcript: &Hash32,
    confirmation: &AeadCiphertext,
) -> Result<(), CryptoError> {
    let aad = confirmation_aad(domain, transcript);
    let mut plaintext = provider
        .open(key, confirmation, &aad)
        .map_err(|_| CryptoError::KeyConfirmationFailed)?;
    let empty = plaintext.is_empty();
    plaintext.zeroize();
    if empty {
        Ok(())
    } else {
        Err(CryptoError::KeyConfirmationFailed)
    }
}

pub(crate) struct SessionKeys {
    transmit: Secret32,
    receive: Secret32,
    pub(crate) transcript_hash: Hash32,
    selected_version: u16,
    selected_suite: u16,
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("transcript_hash", &self.transcript_hash)
            .field("selected_version", &self.selected_version)
            .field("selected_suite", &self.selected_suite)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl SessionKeys {
    pub(crate) fn selected_version(&self) -> u16 {
        self.selected_version
    }

    pub(crate) fn into_channel(self) -> SecureChannel {
        SecureChannel {
            transmit: self.transmit,
            receive: self.receive,
            send_sequence: SendSequence::default(),
            replay_window: ReplayWindow::default(),
            contextual_replay_window: ReplayWindow::default(),
        }
    }
}

pub(crate) struct InitiatorHandshake<P: CryptoProvider> {
    client_hello: ClientHello,
    ecdh_secret: P::EcdhSecret,
    kem_decapsulation_key: P::KemDecapsulationKey,
}

impl<P: CryptoProvider> InitiatorHandshake<P> {
    pub(crate) fn start(
        provider: &mut P,
        supported_versions: Vec<u16>,
        offered_suites: Vec<u16>,
    ) -> Result<(Self, ClientHello), CryptoError> {
        validate_version_offer(&supported_versions)?;
        validate_suite_offer(&offered_suites)?;
        select_highest_common_version(&supported_versions, SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS)?;
        select_preferred_common_suite(&offered_suites, SUPPORTED_HYBRID_SUITES)?;
        let (ecdh_secret, p256_ephemeral_public) = provider.generate_ecdh_keypair()?;
        let (kem_decapsulation_key, ml_kem_768_encapsulation_key) =
            provider.generate_kem_keypair()?;
        let mut initiator_nonce = [0u8; HASH_LEN];
        provider.fill_random(&mut initiator_nonce)?;

        let hello = ClientHello {
            supported_versions,
            offered_suites,
            initiator_nonce,
            p256_ephemeral_public,
            ml_kem_768_encapsulation_key,
        };
        // Validate all encoded lengths before retaining ephemeral secrets.
        encode_client_hello(&hello)?;
        Ok((
            Self {
                client_hello: hello.clone(),
                ecdh_secret,
                kem_decapsulation_key,
            },
            hello,
        ))
    }

    #[cfg(test)]
    pub(crate) fn open_server_auth(
        self,
        provider: &P,
        server_hello: &ServerHello,
    ) -> Result<(InitiatorHandshakePending, OpenedHandshakeAuth), CryptoError> {
        self.open_server_auth_borrowed(provider, server_hello)
    }

    pub(crate) fn open_server_auth_borrowed(
        &self,
        provider: &P,
        server_hello: &ServerHello,
    ) -> Result<(InitiatorHandshakePending, OpenedHandshakeAuth), CryptoError> {
        if !SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS.contains(&server_hello.selected_version)
            || !self
                .client_hello
                .supported_versions
                .contains(&server_hello.selected_version)
        {
            return Err(CryptoError::UnsupportedProtocolVersion);
        }
        if !SUPPORTED_HYBRID_SUITES.contains(&server_hello.selected_suite)
            || !self
                .client_hello
                .offered_suites
                .contains(&server_hello.selected_suite)
        {
            return Err(CryptoError::UnsupportedSuite);
        }

        let transcript = transcript_hash(provider, &self.client_hello, server_hello)?;
        let classical =
            provider.ecdh_agree(&self.ecdh_secret, &server_hello.p256_ephemeral_public)?;
        let post_quantum = provider.kem_decapsulate(
            &self.kem_decapsulation_key,
            &server_hello.ml_kem_768_ciphertext,
        )?;
        let schedule = derive_handshake_schedule(
            provider,
            classical,
            post_quantum,
            server_hello.selected_version,
            server_hello.selected_suite,
            &transcript,
        )?;
        verify_confirmation(
            provider,
            &schedule.server_confirmation,
            SERVER_CONFIRM_DOMAIN,
            &transcript,
            &server_hello.confirmation,
        )?;
        let aad = protection_aad(SERVER_AUTH_PROTECTION_DOMAIN, &transcript);
        let encoded = provider.open(
            &schedule.server_auth_protection,
            &server_hello.protected_auth,
            &aad,
        )?;
        let opened = decode_handshake_auth(encoded, HandshakeAuthRole::Server, transcript)?;
        Ok((
            InitiatorHandshakePending {
                public_transcript_hash: transcript,
                schedule,
            },
            opened,
        ))
    }
}

pub(crate) struct InitiatorHandshakePending {
    public_transcript_hash: Hash32,
    schedule: HandshakeSchedule,
}

impl InitiatorHandshakePending {
    pub(crate) fn authenticate_server<P: CryptoProvider>(
        self,
        provider: &P,
        opened: OpenedHandshakeAuth,
        expected_responder_key: &HybridVerifyingKey,
    ) -> Result<InitiatorHandshakeAuthenticated, CryptoError> {
        if opened.role != HandshakeAuthRole::Server
            || opened.public_transcript_hash != self.public_transcript_hash
        {
            return Err(CryptoError::InvalidHandshake);
        }
        let message = auth_message(
            SERVER_AUTH_DOMAIN,
            &self.public_transcript_hash,
            None,
            &opened.credential_context,
        )?;
        provider.verify(expected_responder_key, &message, &opened.signature)?;
        Ok(InitiatorHandshakeAuthenticated {
            public_transcript_hash: self.public_transcript_hash,
            server_auth: opened.into_encoded(),
            schedule: self.schedule,
        })
    }
}

pub(crate) struct InitiatorHandshakeAuthenticated {
    public_transcript_hash: Hash32,
    server_auth: Vec<u8>,
    schedule: HandshakeSchedule,
}

impl InitiatorHandshakeAuthenticated {
    pub(crate) fn seal_client_auth<P: CryptoProvider>(
        self,
        provider: &mut P,
        initiator_signing_key: &P::SigningKey,
        credential_context: &[u8],
    ) -> Result<(InitiatorHandshakeAwaitingFinished, ClientFinish), CryptoError> {
        let message = auth_message(
            CLIENT_AUTH_DOMAIN,
            &self.public_transcript_hash,
            Some(&self.server_auth),
            credential_context,
        )?;
        let signature = provider.sign(initiator_signing_key, &message)?;
        let encoded = encode_handshake_auth(credential_context, &signature)?;
        let aad = protection_aad(CLIENT_AUTH_PROTECTION_DOMAIN, &self.public_transcript_hash);
        let protected_auth =
            provider.seal(&self.schedule.client_auth_protection, &encoded, &aad)?;
        let final_hash = final_transcript_hash(
            provider,
            &self.public_transcript_hash,
            &self.server_auth,
            &encoded,
        )?;
        let confirmation = make_confirmation(
            provider,
            &self.schedule.client_confirmation,
            CLIENT_CONFIRM_DOMAIN,
            &final_hash,
        )?;
        Ok((
            InitiatorHandshakeAwaitingFinished {
                final_transcript_hash: final_hash,
                schedule: self.schedule,
            },
            ClientFinish {
                protected_auth,
                confirmation,
            },
        ))
    }
}

pub(crate) struct InitiatorHandshakeAwaitingFinished {
    final_transcript_hash: Hash32,
    schedule: HandshakeSchedule,
}

impl InitiatorHandshakeAwaitingFinished {
    #[cfg(test)]
    pub(crate) fn finish<P: CryptoProvider>(
        self,
        provider: &P,
        finished: &ServerFinished,
    ) -> Result<SessionKeys, CryptoError> {
        self.verify_finished(provider, finished)?;
        Ok(self.into_session_keys())
    }

    pub(crate) fn verify_finished<P: CryptoProvider>(
        &self,
        provider: &P,
        finished: &ServerFinished,
    ) -> Result<(), CryptoError> {
        let aad = protection_aad(SERVER_FINISHED_DOMAIN, &self.final_transcript_hash);
        let mut plaintext = provider
            .open(
                &self.schedule.server_finished,
                &finished.protected_finished,
                &aad,
            )
            .map_err(|_| CryptoError::KeyConfirmationFailed)?;
        let matches = plaintext.as_slice() == self.final_transcript_hash;
        plaintext.zeroize();
        if !matches {
            return Err(CryptoError::KeyConfirmationFailed);
        }
        Ok(())
    }

    pub(crate) fn into_session_keys(self) -> SessionKeys {
        SessionKeys {
            transmit: self.schedule.initiator_to_responder,
            receive: self.schedule.responder_to_initiator,
            transcript_hash: self.final_transcript_hash,
            selected_version: self.schedule.selected_version,
            selected_suite: self.schedule.selected_suite,
        }
    }
}

pub(crate) struct ResponderHandshakePrepared {
    public_hello: ServerHello,
    public_transcript_hash: Hash32,
    schedule: HandshakeSchedule,
}

impl ResponderHandshakePrepared {
    #[cfg(test)]
    pub(crate) fn respond<P: CryptoProvider>(
        provider: &mut P,
        client_hello: &ClientHello,
    ) -> Result<Self, CryptoError> {
        Self::respond_with_supported_versions(
            provider,
            client_hello,
            SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
        )
    }

    pub(crate) fn respond_with_supported_versions<P: CryptoProvider>(
        provider: &mut P,
        client_hello: &ClientHello,
        supported_versions: &[u16],
    ) -> Result<Self, CryptoError> {
        validate_client_hello(client_hello)?;
        let selected_version =
            select_highest_common_version(&client_hello.supported_versions, supported_versions)?;
        let selected_suite =
            select_preferred_common_suite(&client_hello.offered_suites, SUPPORTED_HYBRID_SUITES)?;
        // Parse/validate the classical key before performing expensive post-quantum work.
        let (responder_ecdh_secret, p256_ephemeral_public) = provider.generate_ecdh_keypair()?;
        let classical =
            provider.ecdh_agree(&responder_ecdh_secret, &client_hello.p256_ephemeral_public)?;
        let (ml_kem_768_ciphertext, post_quantum) =
            provider.kem_encapsulate(&client_hello.ml_kem_768_encapsulation_key)?;

        let mut responder_nonce = [0u8; HASH_LEN];
        provider.fill_random(&mut responder_nonce)?;
        let server_hello = ServerHello {
            selected_version,
            selected_suite,
            responder_nonce,
            p256_ephemeral_public,
            ml_kem_768_ciphertext,
            protected_auth: AeadCiphertext {
                nonce: [0u8; NONCE_LEN],
                ciphertext: Vec::new(),
            },
            confirmation: AeadCiphertext {
                nonce: [0u8; NONCE_LEN],
                ciphertext: Vec::new(),
            },
        };

        let transcript = transcript_hash(provider, client_hello, &server_hello)?;
        let schedule = derive_handshake_schedule(
            provider,
            classical,
            post_quantum,
            selected_version,
            selected_suite,
            &transcript,
        )?;

        Ok(Self {
            public_hello: server_hello,
            public_transcript_hash: transcript,
            schedule,
        })
    }

    pub(crate) fn seal_server_auth<P: CryptoProvider>(
        mut self,
        provider: &mut P,
        responder_signing_key: &P::SigningKey,
        credential_context: &[u8],
    ) -> Result<(ResponderHandshake, ServerHello), CryptoError> {
        let message = auth_message(
            SERVER_AUTH_DOMAIN,
            &self.public_transcript_hash,
            None,
            credential_context,
        )?;
        let signature = provider.sign(responder_signing_key, &message)?;
        let encoded = encode_handshake_auth(credential_context, &signature)?;
        let aad = protection_aad(SERVER_AUTH_PROTECTION_DOMAIN, &self.public_transcript_hash);
        self.public_hello.protected_auth =
            provider.seal(&self.schedule.server_auth_protection, &encoded, &aad)?;
        self.public_hello.confirmation = make_confirmation(
            provider,
            &self.schedule.server_confirmation,
            SERVER_CONFIRM_DOMAIN,
            &self.public_transcript_hash,
        )?;

        Ok((
            ResponderHandshake {
                public_transcript_hash: self.public_transcript_hash,
                server_auth: encoded,
                schedule: self.schedule,
            },
            self.public_hello,
        ))
    }
}

pub(crate) struct ResponderHandshake {
    public_transcript_hash: Hash32,
    server_auth: Vec<u8>,
    schedule: HandshakeSchedule,
}

impl ResponderHandshake {
    #[cfg(test)]
    pub(crate) fn open_client_auth<P: CryptoProvider>(
        self,
        provider: &P,
        client_finish: &ClientFinish,
    ) -> Result<(ResponderHandshakePending, OpenedHandshakeAuth), CryptoError> {
        let (final_hash, opened) = self.inspect_client_auth(provider, client_finish)?;
        Ok((
            ResponderHandshakePending {
                public_transcript_hash: self.public_transcript_hash,
                final_transcript_hash: final_hash,
                server_auth: self.server_auth,
                schedule: self.schedule,
            },
            opened,
        ))
    }

    pub(crate) fn inspect_client_auth<P: CryptoProvider>(
        &self,
        provider: &P,
        client_finish: &ClientFinish,
    ) -> Result<(Hash32, OpenedHandshakeAuth), CryptoError> {
        let aad = protection_aad(CLIENT_AUTH_PROTECTION_DOMAIN, &self.public_transcript_hash);
        let encoded = provider.open(
            &self.schedule.client_auth_protection,
            &client_finish.protected_auth,
            &aad,
        )?;
        let opened = decode_handshake_auth(
            encoded,
            HandshakeAuthRole::Client,
            self.public_transcript_hash,
        )?;
        let final_hash = final_transcript_hash(
            provider,
            &self.public_transcript_hash,
            &self.server_auth,
            &opened.encoded,
        )?;
        verify_confirmation(
            provider,
            &self.schedule.client_confirmation,
            CLIENT_CONFIRM_DOMAIN,
            &final_hash,
            &client_finish.confirmation,
        )?;
        Ok((final_hash, opened))
    }

    pub(crate) fn verify_client_auth<P: CryptoProvider>(
        &self,
        provider: &P,
        opened: &OpenedHandshakeAuth,
        expected_initiator_key: &HybridVerifyingKey,
    ) -> Result<(), CryptoError> {
        if opened.role != HandshakeAuthRole::Client
            || opened.public_transcript_hash != self.public_transcript_hash
        {
            return Err(CryptoError::InvalidHandshake);
        }
        let message = auth_message(
            CLIENT_AUTH_DOMAIN,
            &self.public_transcript_hash,
            Some(&self.server_auth),
            &opened.credential_context,
        )?;
        provider.verify(expected_initiator_key, &message, &opened.signature)
    }

    pub(crate) fn seal_server_finished<P: CryptoProvider>(
        &self,
        provider: &mut P,
        final_transcript_hash: &Hash32,
    ) -> Result<ServerFinished, CryptoError> {
        let aad = protection_aad(SERVER_FINISHED_DOMAIN, final_transcript_hash);
        let protected_finished =
            provider.seal(&self.schedule.server_finished, final_transcript_hash, &aad)?;
        Ok(ServerFinished { protected_finished })
    }

    pub(crate) fn into_session_keys(self, final_transcript_hash: Hash32) -> SessionKeys {
        SessionKeys {
            transmit: self.schedule.responder_to_initiator,
            receive: self.schedule.initiator_to_responder,
            transcript_hash: final_transcript_hash,
            selected_version: self.schedule.selected_version,
            selected_suite: self.schedule.selected_suite,
        }
    }
}

#[cfg(test)]
pub(crate) struct ResponderHandshakePending {
    public_transcript_hash: Hash32,
    final_transcript_hash: Hash32,
    server_auth: Vec<u8>,
    schedule: HandshakeSchedule,
}

#[cfg(test)]
impl ResponderHandshakePending {
    pub(crate) fn authenticate_client<P: CryptoProvider>(
        self,
        provider: &mut P,
        opened: OpenedHandshakeAuth,
        expected_initiator_key: &HybridVerifyingKey,
    ) -> Result<(ServerFinished, SessionKeys), CryptoError> {
        if opened.role != HandshakeAuthRole::Client
            || opened.public_transcript_hash != self.public_transcript_hash
        {
            return Err(CryptoError::InvalidHandshake);
        }
        let message = auth_message(
            CLIENT_AUTH_DOMAIN,
            &self.public_transcript_hash,
            Some(&self.server_auth),
            &opened.credential_context,
        )?;
        provider.verify(expected_initiator_key, &message, &opened.signature)?;
        let aad = protection_aad(SERVER_FINISHED_DOMAIN, &self.final_transcript_hash);
        let protected_finished = provider.seal(
            &self.schedule.server_finished,
            &self.final_transcript_hash,
            &aad,
        )?;
        let finished = ServerFinished { protected_finished };
        let session = SessionKeys {
            transmit: self.schedule.responder_to_initiator,
            receive: self.schedule.initiator_to_responder,
            transcript_hash: self.final_transcript_hash,
            selected_version: self.schedule.selected_version,
            selected_suite: self.schedule.selected_suite,
        };
        Ok((finished, session))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SequencedCiphertext {
    pub(crate) sequence: u64,
    pub(crate) sealed: AeadCiphertext,
}

#[derive(Debug, Default)]
pub(crate) struct SendSequence {
    next: u64,
    exhausted: bool,
}

impl SendSequence {
    pub(crate) const fn next_value(&self) -> Option<u64> {
        if self.exhausted {
            None
        } else {
            Some(self.next)
        }
    }

    fn reserve(&mut self) -> Result<u64, CryptoError> {
        if self.exhausted {
            return Err(CryptoError::SequenceExhausted);
        }
        let value = self.next;
        if value == u64::MAX {
            self.exhausted = true;
        } else {
            self.next = value + 1;
        }
        Ok(value)
    }
}

/// A 128-record sliding anti-replay window, independent of wall-clock time.
#[derive(Debug, Default)]
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    pub(crate) const WIDTH: u64 = u128::BITS as u64;

    pub(crate) fn accept(&mut self, sequence: u64) -> Result<(), CryptoError> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bitmap = 1;
            return Ok(());
        };

        if sequence > highest {
            let distance = sequence - highest;
            self.bitmap = if distance >= Self::WIDTH {
                0
            } else {
                self.bitmap << distance
            };
            self.bitmap |= 1;
            self.highest = Some(sequence);
            return Ok(());
        }

        let distance = highest - sequence;
        if distance >= Self::WIDTH {
            return Err(CryptoError::ReplayTooOld);
        }
        let mask = 1u128 << distance;
        if self.bitmap & mask != 0 {
            return Err(CryptoError::ReplayDetected);
        }
        self.bitmap |= mask;
        Ok(())
    }
}

fn record_aad(sequence: u64, application_aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut aad = Vec::with_capacity(RECORD_AAD_DOMAIN.len() + 8 + 4 + application_aad.len());
    aad.extend_from_slice(RECORD_AAD_DOMAIN);
    aad.extend_from_slice(&sequence.to_be_bytes());
    append_len_prefixed(&mut aad, application_aad)?;
    Ok(aad)
}

pub(crate) struct SecureChannel {
    transmit: Secret32,
    receive: Secret32,
    send_sequence: SendSequence,
    replay_window: ReplayWindow,
    contextual_replay_window: ReplayWindow,
}

impl fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureChannel")
            .field("send_sequence", &self.send_sequence)
            .field("replay_window", &self.replay_window)
            .field("contextual_replay_window", &self.contextual_replay_window)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl SecureChannel {
    pub(crate) const fn next_send_sequence(&self) -> Option<u64> {
        self.send_sequence.next_value()
    }

    pub(crate) fn seal<P: CryptoProvider>(
        &mut self,
        provider: &mut P,
        plaintext: &[u8],
        application_aad: &[u8],
    ) -> Result<SequencedCiphertext, CryptoError> {
        // Reserve first: a local encryption failure skips a sequence instead of risking two
        // different records with the same authenticated sequence.
        let sequence = self.send_sequence.reserve()?;
        let aad = record_aad(sequence, application_aad)?;
        let sealed = provider.seal(&self.transmit, plaintext, &aad)?;
        Ok(SequencedCiphertext { sequence, sealed })
    }

    pub(crate) fn open<P: CryptoProvider>(
        &mut self,
        provider: &P,
        record: &SequencedCiphertext,
        application_aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Self::open_with_replay_window(
            &self.receive,
            &mut self.replay_window,
            provider,
            record,
            application_aad,
        )
    }

    /// Authenticates and opens a record in the context-bound replay domain.
    ///
    /// Both domains share one sender record sequence. The provider allocates
    /// AES-GCM nonces independently through the same nonce generator used by
    /// `seal`; neither replay domain derives a nonce from the record sequence.
    /// Separate receiver windows prevent an authenticated outer record from
    /// aging nested evidence out of the ordinary domain.
    pub(crate) fn open_contextual<P: CryptoProvider>(
        &mut self,
        provider: &P,
        record: &SequencedCiphertext,
        application_aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Self::open_with_replay_window(
            &self.receive,
            &mut self.contextual_replay_window,
            provider,
            record,
            application_aad,
        )
    }

    fn open_with_replay_window<P: CryptoProvider>(
        receive: &Secret32,
        replay_window: &mut ReplayWindow,
        provider: &P,
        record: &SequencedCiphertext,
        application_aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let aad = record_aad(record.sequence, application_aad)?;
        // Authenticate before mutating replay state. A forged high sequence therefore cannot
        // advance the window and suppress legitimate records.
        let mut plaintext = provider.open(receive, &record.sealed, &aad)?;
        if let Err(error) = replay_window.accept(record.sequence) {
            plaintext.zeroize();
            return Err(error);
        }
        Ok(plaintext)
    }

    pub(crate) fn zeroize(&mut self) {
        self.transmit.zeroize();
        self.receive.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand_core::TryRng;

    /// Deterministic test-only generator. It is never available in production builds.
    #[derive(Debug)]
    struct TestRng {
        state: u64,
    }

    impl TestRng {
        fn seeded(seed: u64) -> Self {
            Self {
                state: seed ^ 0x9e37_79b9_7f4a_7c15,
            }
        }

        fn word(&mut self) -> u64 {
            // SplitMix64 is sufficient for deterministic, non-security test vectors.
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.state;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.word() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.word())
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in output.chunks_mut(8) {
                let bytes = self.word().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    fn provider(seed: u64) -> RustCryptoProvider<TestRng> {
        RustCryptoProvider::try_new(TestRng::seeded(seed))
            .unwrap_or_else(|error| panic!("test provider construction failed: {error}"))
    }

    #[test]
    fn reference_provider_is_explicitly_not_fips_validated() {
        let provider = provider(1);
        assert_eq!(
            provider.assurance(),
            CryptoAssurance::ReferenceOnlyNotFipsValidated
        );
    }

    #[test]
    fn sha_ids_and_labeled_hkdf_are_domain_separated() {
        let provider = provider(2);
        assert_eq!(provider.hash_id(b"same"), provider.hash_id(b"same"));
        assert_ne!(provider.hash_id(b"same"), provider.hash_id(b"different"));

        let first = provider
            .derive_secret(b"input secret", Some(b"salt"), b"payload", b"scope-a")
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));
        let different_input = provider
            .derive_secret(b"different secret", Some(b"salt"), b"payload", b"scope-a")
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));
        let different_label = provider
            .derive_secret(b"input secret", Some(b"salt"), b"metadata", b"scope-a")
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));
        let different_context = provider
            .derive_secret(b"input secret", Some(b"salt"), b"payload", b"scope-b")
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));

        assert_ne!(first.expose(), different_input.expose());
        assert_ne!(first.expose(), different_label.expose());
        assert_ne!(first.expose(), different_context.expose());
    }

    #[test]
    fn aes_gcm_rejects_tamper_wrong_aad_and_wrong_secret() {
        let mut provider = provider(3);
        let key = provider
            .derive_secret(b"key material", Some(b"salt"), b"test-aead", b"item-1")
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));
        let wrong_key = provider
            .derive_secret(
                b"different key material",
                Some(b"salt"),
                b"test-aead",
                b"item-1",
            )
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));
        let sealed = provider
            .seal(&key, b"mission payload", b"authenticated metadata")
            .unwrap_or_else(|error| panic!("encryption failed: {error}"));
        assert_eq!(
            provider
                .open(&key, &sealed, b"authenticated metadata")
                .unwrap_or_else(|error| panic!("decryption failed: {error}")),
            b"mission payload"
        );

        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 0x80;
        assert_eq!(
            provider.open(&key, &tampered, b"authenticated metadata"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            provider.open(&key, &sealed, b"wrong metadata"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            provider.open(&wrong_key, &sealed, b"authenticated metadata"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn generated_aead_nonces_are_unique() {
        let mut provider = provider(4);
        let key = provider
            .derive_secret(b"key material", None, b"nonce-test", b"")
            .unwrap_or_else(|error| panic!("KDF failed: {error}"));
        let first = provider
            .seal(&key, b"one", b"")
            .unwrap_or_else(|error| panic!("encryption failed: {error}"));
        let second = provider
            .seal(&key, b"two", b"")
            .unwrap_or_else(|error| panic!("encryption failed: {error}"));
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn hybrid_signatures_require_both_algorithms() {
        let mut provider = provider(5);
        let mut signing_key = provider
            .generate_signing_key()
            .unwrap_or_else(|error| panic!("key generation failed: {error}"));
        let verifying_key = provider
            .verifying_key(&signing_key)
            .unwrap_or_else(|error| panic!("public key export failed: {error}"));
        let signature = provider
            .sign(&signing_key, b"signed transcript")
            .unwrap_or_else(|error| panic!("signing failed: {error}"));
        assert_eq!(
            provider.verify(&verifying_key, b"signed transcript", &signature),
            Ok(())
        );

        let mut missing_classical = signature.clone();
        missing_classical.ecdsa_p256 = None;
        assert_eq!(
            provider.verify(&verifying_key, b"signed transcript", &missing_classical),
            Err(CryptoError::MissingClassicalSignature)
        );

        let mut missing_pq = signature.clone();
        missing_pq.ml_dsa_65 = None;
        assert_eq!(
            provider.verify(&verifying_key, b"signed transcript", &missing_pq),
            Err(CryptoError::MissingPostQuantumSignature)
        );

        let mut tampered = signature.clone();
        if let Some(classical) = tampered.ecdsa_p256.as_mut() {
            classical[0] ^= 1;
        }
        assert_eq!(
            provider.verify(&verifying_key, b"signed transcript", &tampered),
            Err(CryptoError::InvalidClassicalSignature)
        );

        signing_key.zeroize_key();
        assert!(signing_key.is_zeroized());
        assert_eq!(
            provider.sign(&signing_key, b"must not sign"),
            Err(CryptoError::KeyZeroized)
        );
    }

    struct CompletedHandshake {
        initiator_provider: RustCryptoProvider<TestRng>,
        responder_provider: RustCryptoProvider<TestRng>,
        initiator_session: SessionKeys,
        responder_session: SessionKeys,
    }

    fn complete_handshake(seed: u64) -> CompletedHandshake {
        complete_handshake_with_versions(seed, vec![SEMANTIC_PROTOCOL_V1])
    }

    fn complete_handshake_with_versions(
        seed: u64,
        supported_versions: Vec<u16>,
    ) -> CompletedHandshake {
        let mut initiator_provider = provider(seed);
        let mut responder_provider = provider(seed.wrapping_add(10_000));
        let initiator_key = initiator_provider
            .generate_signing_key()
            .unwrap_or_else(|error| panic!("initiator key generation failed: {error}"));
        let responder_key = responder_provider
            .generate_signing_key()
            .unwrap_or_else(|error| panic!("responder key generation failed: {error}"));
        let initiator_public = initiator_provider
            .verifying_key(&initiator_key)
            .unwrap_or_else(|error| panic!("initiator public key failed: {error}"));
        let responder_public = responder_provider
            .verifying_key(&responder_key)
            .unwrap_or_else(|error| panic!("responder public key failed: {error}"));

        let (initiator_state, client_hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            supported_versions,
            vec![HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &client_hello)
            .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        let (responder_state, server_hello) = prepared
            .seal_server_auth(
                &mut responder_provider,
                &responder_key,
                b"server credential and authority signature",
            )
            .unwrap_or_else(|error| panic!("server response failed: {error}"));
        let (pending, opened_server) = initiator_state
            .open_server_auth(&initiator_provider, &server_hello)
            .unwrap_or_else(|error| panic!("server auth open failed: {error}"));
        assert_eq!(
            opened_server.credential_context(),
            b"server credential and authority signature"
        );
        let authenticated = pending
            .authenticate_server(&initiator_provider, opened_server, &responder_public)
            .unwrap_or_else(|error| panic!("server auth failed: {error}"));
        let (awaiting_finished, client_finish) = authenticated
            .seal_client_auth(
                &mut initiator_provider,
                &initiator_key,
                b"client credential and authority signature",
            )
            .unwrap_or_else(|error| panic!("client finish failed: {error}"));
        let (responder_pending, opened_client) = responder_state
            .open_client_auth(&responder_provider, &client_finish)
            .unwrap_or_else(|error| panic!("client auth open failed: {error}"));
        assert_eq!(
            opened_client.credential_context(),
            b"client credential and authority signature"
        );
        let (server_finished, responder_session) = responder_pending
            .authenticate_client(&mut responder_provider, opened_client, &initiator_public)
            .unwrap_or_else(|error| panic!("client auth failed: {error}"));
        let initiator_session = awaiting_finished
            .finish(&initiator_provider, &server_finished)
            .unwrap_or_else(|error| panic!("server finished failed: {error}"));

        CompletedHandshake {
            initiator_provider,
            responder_provider,
            initiator_session,
            responder_session,
        }
    }

    #[test]
    fn hybrid_handshake_agrees_on_directional_keys_and_fresh_runs_differ() {
        let first = complete_handshake(6);
        assert_eq!(first.initiator_session.selected_version(), PROTOCOL_VERSION);
        assert_eq!(first.responder_session.selected_version(), PROTOCOL_VERSION);
        assert_eq!(
            first.initiator_session.transmit.expose(),
            first.responder_session.receive.expose()
        );
        assert_eq!(
            first.initiator_session.receive.expose(),
            first.responder_session.transmit.expose()
        );
        assert_ne!(
            first.initiator_session.transmit.expose(),
            first.initiator_session.receive.expose()
        );

        let second = complete_handshake(7);
        assert_ne!(
            first.initiator_session.transmit.expose(),
            second.initiator_session.transmit.expose()
        );
        assert_ne!(
            first.initiator_session.transcript_hash,
            second.initiator_session.transcript_hash
        );
    }

    #[test]
    fn selected_semantic_version_is_bound_into_fresh_record_keys() {
        let v1 = complete_handshake_with_versions(8_100, vec![SEMANTIC_PROTOCOL_V1]);
        let v2 = complete_handshake_with_versions(
            8_100,
            vec![SEMANTIC_PROTOCOL_V2, SEMANTIC_PROTOCOL_V1],
        );
        assert_eq!(
            v1.initiator_session.selected_version(),
            SEMANTIC_PROTOCOL_V1
        );
        assert_eq!(
            v2.initiator_session.selected_version(),
            SEMANTIC_PROTOCOL_V2
        );
        assert_ne!(
            v1.initiator_session.transmit.expose(),
            v2.initiator_session.transmit.expose()
        );

        let CompletedHandshake {
            mut initiator_provider,
            initiator_session,
            ..
        } = v2;
        let mut v2_channel = initiator_session.into_channel();
        let v2_record = v2_channel
            .seal(&mut initiator_provider, b"semantic-bound", b"test-aad")
            .unwrap();

        let CompletedHandshake {
            responder_provider,
            responder_session,
            ..
        } = v1;
        let mut v1_channel = responder_session.into_channel();
        assert_eq!(
            v1_channel.open(&responder_provider, &v2_record, b"test-aad"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn handshake_offers_require_bounded_canonical_nonempty_sets() {
        let mut initiator_provider = provider(7_001);
        let too_many_versions = (1..=MAX_OFFERED_VERSIONS as u16 + 1)
            .rev()
            .collect::<Vec<_>>();
        let too_many_suites = (1..=MAX_OFFERED_SUITES as u16 + 1)
            .rev()
            .collect::<Vec<_>>();

        assert!(matches!(
            InitiatorHandshake::start(&mut initiator_provider, Vec::new(), vec![HYBRID_SUITE_ID]),
            Err(CryptoError::InvalidVersionOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                too_many_versions,
                vec![HYBRID_SUITE_ID]
            ),
            Err(CryptoError::InvalidVersionOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![PROTOCOL_VERSION, PROTOCOL_VERSION],
                vec![HYBRID_SUITE_ID]
            ),
            Err(CryptoError::InvalidVersionOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![PROTOCOL_VERSION, PROTOCOL_VERSION + 1],
                vec![HYBRID_SUITE_ID]
            ),
            Err(CryptoError::InvalidVersionOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(&mut initiator_provider, vec![PROTOCOL_VERSION], Vec::new()),
            Err(CryptoError::InvalidSuiteOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![PROTOCOL_VERSION],
                too_many_suites
            ),
            Err(CryptoError::InvalidSuiteOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![PROTOCOL_VERSION],
                vec![HYBRID_SUITE_ID, HYBRID_SUITE_ID]
            ),
            Err(CryptoError::InvalidSuiteOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![PROTOCOL_VERSION],
                vec![HYBRID_SUITE_ID, HYBRID_SUITE_ID + 1]
            ),
            Err(CryptoError::InvalidSuiteOffer)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![SEMANTIC_PROTOCOL_V9 + 1],
                vec![HYBRID_SUITE_ID]
            ),
            Err(CryptoError::UnsupportedProtocolVersion)
        ));
        assert!(matches!(
            InitiatorHandshake::start(
                &mut initiator_provider,
                vec![PROTOCOL_VERSION],
                vec![HYBRID_SUITE_ID + 1]
            ),
            Err(CryptoError::UnsupportedSuite)
        ));
    }

    #[test]
    fn responder_selects_v2_and_falls_back_for_a_v1_only_peer() {
        let mut initiator_provider = provider(7_002);
        let mut responder_provider = provider(17_002);
        let (_initiator, hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![PROTOCOL_VERSION + 1, PROTOCOL_VERSION],
            vec![0x0202, HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));

        let prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &hello)
            .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        assert_eq!(prepared.public_hello.selected_version, SEMANTIC_PROTOCOL_V2);
        assert_eq!(prepared.public_hello.selected_suite, HYBRID_SUITE_ID);

        let mut unsupported_version = hello.clone();
        unsupported_version.supported_versions = vec![SEMANTIC_PROTOCOL_V9 + 1];
        assert!(matches!(
            ResponderHandshakePrepared::respond(&mut responder_provider, &unsupported_version),
            Err(CryptoError::UnsupportedProtocolVersion)
        ));

        let (_v1_initiator, v1_hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![SEMANTIC_PROTOCOL_V1],
            vec![HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("v1 client start failed: {error}"));
        let v1_prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &v1_hello)
            .unwrap_or_else(|error| panic!("v1 server preparation failed: {error}"));
        assert_eq!(
            v1_prepared.public_hello.selected_version,
            SEMANTIC_PROTOCOL_V1
        );

        let mut unsupported_suite = hello;
        unsupported_suite.offered_suites = vec![0x0202];
        assert!(matches!(
            ResponderHandshakePrepared::respond(&mut responder_provider, &unsupported_suite),
            Err(CryptoError::UnsupportedSuite)
        ));
    }

    #[test]
    fn semantic_v9_selects_v9_and_falls_back_to_v8_and_v7_peers() {
        assert_eq!(
            select_highest_common_version(
                SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
                SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
            ),
            Ok(SEMANTIC_PROTOCOL_V9)
        );
        assert_eq!(
            select_highest_common_version(
                SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
                &[SEMANTIC_PROTOCOL_V8, SEMANTIC_PROTOCOL_V7],
            ),
            Ok(SEMANTIC_PROTOCOL_V8)
        );
        assert_eq!(
            select_highest_common_version(
                SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
                &[
                    SEMANTIC_PROTOCOL_V7,
                    SEMANTIC_PROTOCOL_V6,
                    SEMANTIC_PROTOCOL_V5,
                    SEMANTIC_PROTOCOL_V4,
                    SEMANTIC_PROTOCOL_V3,
                    SEMANTIC_PROTOCOL_V2,
                    SEMANTIC_PROTOCOL_V1,
                ],
            ),
            Ok(SEMANTIC_PROTOCOL_V7)
        );
    }

    #[test]
    fn initiator_rejects_server_selections_that_were_not_offered() {
        let mut initiator_provider = provider(7_003);
        let mut responder_provider = provider(17_003);
        let responder_key = responder_provider
            .generate_signing_key()
            .unwrap_or_else(|error| panic!("key generation failed: {error}"));

        let (state, hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![PROTOCOL_VERSION],
            vec![HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &hello)
            .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        let (_server, mut response) = prepared
            .seal_server_auth(
                &mut responder_provider,
                &responder_key,
                b"server credential",
            )
            .unwrap_or_else(|error| panic!("server response failed: {error}"));
        response.selected_version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            state.open_server_auth(&initiator_provider, &response),
            Err(CryptoError::UnsupportedProtocolVersion)
        ));

        let (state, hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![PROTOCOL_VERSION],
            vec![HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &hello)
            .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        let (_server, mut response) = prepared
            .seal_server_auth(
                &mut responder_provider,
                &responder_key,
                b"server credential",
            )
            .unwrap_or_else(|error| panic!("server response failed: {error}"));
        response.selected_suite = 0x0202;
        assert!(matches!(
            state.open_server_auth(&initiator_provider, &response),
            Err(CryptoError::UnsupportedSuite)
        ));
    }

    #[test]
    fn transcript_binds_the_complete_version_offer_against_downgrade() {
        for (seed, stripped_versions) in [
            (
                7_004,
                vec![
                    SEMANTIC_PROTOCOL_V4,
                    SEMANTIC_PROTOCOL_V3,
                    SEMANTIC_PROTOCOL_V2,
                    SEMANTIC_PROTOCOL_V1,
                ],
            ),
            (7_005, vec![SEMANTIC_PROTOCOL_V2, SEMANTIC_PROTOCOL_V1]),
            (7_006, vec![SEMANTIC_PROTOCOL_V1]),
        ] {
            let mut initiator_provider = provider(seed);
            let mut responder_provider = provider(seed.wrapping_add(10_000));
            let responder_key = responder_provider
                .generate_signing_key()
                .unwrap_or_else(|error| panic!("key generation failed: {error}"));
            let (initiator_state, mut stripped_hello) = InitiatorHandshake::start(
                &mut initiator_provider,
                SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS.to_vec(),
                vec![HYBRID_SUITE_ID],
            )
            .unwrap_or_else(|error| panic!("client start failed: {error}"));
            assert_eq!(
                stripped_hello.supported_versions,
                vec![
                    SEMANTIC_PROTOCOL_V9,
                    SEMANTIC_PROTOCOL_V8,
                    SEMANTIC_PROTOCOL_V7,
                    SEMANTIC_PROTOCOL_V6,
                    SEMANTIC_PROTOCOL_V5,
                    SEMANTIC_PROTOCOL_V4,
                    SEMANTIC_PROTOCOL_V3,
                    SEMANTIC_PROTOCOL_V2,
                    SEMANTIC_PROTOCOL_V1
                ]
            );

            stripped_hello.supported_versions = stripped_versions;
            let prepared =
                ResponderHandshakePrepared::respond(&mut responder_provider, &stripped_hello)
                    .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
            let (_responder_state, server_hello) = prepared
                .seal_server_auth(
                    &mut responder_provider,
                    &responder_key,
                    b"server credential",
                )
                .unwrap_or_else(|error| panic!("server response failed: {error}"));
            let result = initiator_state.open_server_auth(&initiator_provider, &server_hello);
            assert!(matches!(result, Err(CryptoError::KeyConfirmationFailed)));
        }
    }

    #[test]
    fn transcript_binds_the_complete_suite_offer_against_downgrade() {
        let mut initiator_provider = provider(8);
        let mut responder_provider = provider(8_008);
        let responder_key = responder_provider
            .generate_signing_key()
            .unwrap_or_else(|error| panic!("key generation failed: {error}"));
        let (initiator_state, client_hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![PROTOCOL_VERSION],
            vec![0x0202, HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));

        // The attacker removes an offered future suite while leaving the mandatory hybrid suite.
        let mut stripped_hello = client_hello;
        stripped_hello.offered_suites.remove(0);
        let prepared =
            ResponderHandshakePrepared::respond(&mut responder_provider, &stripped_hello)
                .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        let (_responder_state, server_hello) = prepared
            .seal_server_auth(
                &mut responder_provider,
                &responder_key,
                b"server credential",
            )
            .unwrap_or_else(|error| panic!("server response failed: {error}"));
        let result = initiator_state.open_server_auth(&initiator_provider, &server_hello);
        assert!(matches!(result, Err(CryptoError::KeyConfirmationFailed)));
    }

    #[test]
    fn handshake_auth_is_encrypted_and_rejects_tampering() {
        let mut initiator_provider = provider(9);
        let mut responder_provider = provider(9_009);
        let responder_key = responder_provider
            .generate_signing_key()
            .unwrap_or_else(|error| panic!("key generation failed: {error}"));
        let server_context = b"stable server identity plus authority signature";

        let (state, hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![PROTOCOL_VERSION],
            vec![HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &hello)
            .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        let (_server_state, mut server_hello) = prepared
            .seal_server_auth(&mut responder_provider, &responder_key, server_context)
            .unwrap_or_else(|error| panic!("server response failed: {error}"));
        assert!(
            !server_hello
                .protected_auth
                .ciphertext
                .windows(server_context.len())
                .any(|window| window == server_context)
        );
        server_hello.protected_auth.ciphertext[0] ^= 1;
        let result = state.open_server_auth(&initiator_provider, &server_hello);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));

        let (state, hello) = InitiatorHandshake::start(
            &mut initiator_provider,
            vec![PROTOCOL_VERSION],
            vec![HYBRID_SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let prepared = ResponderHandshakePrepared::respond(&mut responder_provider, &hello)
            .unwrap_or_else(|error| panic!("server preparation failed: {error}"));
        let (_server_state, mut server_hello) = prepared
            .seal_server_auth(&mut responder_provider, &responder_key, server_context)
            .unwrap_or_else(|error| panic!("server response failed: {error}"));
        server_hello.confirmation.ciphertext[0] ^= 1;
        let result = state.open_server_auth(&initiator_provider, &server_hello);
        assert!(matches!(result, Err(CryptoError::KeyConfirmationFailed)));
    }

    #[test]
    fn secure_channel_authenticates_sequence_aad_and_rejects_replay() {
        let CompletedHandshake {
            mut initiator_provider,
            responder_provider,
            initiator_session,
            responder_session,
        } = complete_handshake(10);
        let mut sender = initiator_session.into_channel();
        let mut receiver = responder_session.into_channel();
        let record = sender
            .seal(
                &mut initiator_provider,
                b"store and forward payload",
                b"scope/topic/priority",
            )
            .unwrap_or_else(|error| panic!("record encryption failed: {error}"));

        // A failed authentication must not advance the replay window.
        assert_eq!(
            receiver.open(&responder_provider, &record, b"wrong aad"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            receiver
                .open(&responder_provider, &record, b"scope/topic/priority")
                .unwrap_or_else(|error| panic!("record decryption failed: {error}")),
            b"store and forward payload"
        );
        assert_eq!(
            receiver.open(&responder_provider, &record, b"scope/topic/priority"),
            Err(CryptoError::ReplayDetected)
        );
    }

    #[test]
    fn replay_window_accepts_reordering_but_rejects_duplicates_and_old_records() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.accept(200), Ok(()));
        assert_eq!(window.accept(199), Ok(()));
        assert_eq!(window.accept(199), Err(CryptoError::ReplayDetected));
        assert_eq!(window.accept(72), Err(CryptoError::ReplayTooOld));
        assert_eq!(window.accept(201), Ok(()));
    }
}
