//! Complete classical security profile selected by authenticated provisioning.
//!
//! This module is deliberately separate from the historical hybrid provider.
//! It contains no ML-DSA or ML-KEM types or calls. Profile `0x0002` is exact,
//! singleton policy: it is never offered alongside another suite and there is
//! no negotiation fallback. Its handshake is bound to an authenticated Iroh
//! QUIC exporter and ordinary application bytes stay in that carrier's AEAD.

use super::{
    AeadCiphertext, CryptoProvider, RustCryptoProvider, Secret32,
    profile::{
        ApplicationProtection, CLASSICAL_SECURITY_PROFILE_ID, CLASSICAL_SUITE_ID, SecurityProfile,
        SecurityProfileId, VerifiedSecurityProfile,
    },
};
use crate::blob::{BlobId, BlobRouteCommitment};
use crate::envelope::{
    ControlPrincipal, EnvelopeError, EnvelopeHeader, EnvelopeId, EnvelopeSealer, Revocation,
    ScopeEpoch, SealRequest, SealedEnvelope, VerifiedControl, VerifiedEnvelope,
};
use crate::model::{
    CausalStamp, DataClass, Dot, MAX_CAUSAL_CONTEXT_ENTRIES, NodeId, Priority, Scope, Topic,
    VersionVector,
};
use crate::provisioning::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProtectedProvisioningError, ProvisioningProtector,
    ProvisioningUnprotector, UnprotectedProvisioning, protect_provisioning_artifact,
    unprotect_provisioning_artifact,
};
use getrandom::SysRng;
use hkdf::Hkdf;
use p256::{
    FieldBytes, SecretKey as P256SecretKey,
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
        signature::{Signer as P256Signer, Verifier as P256Verifier},
    },
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use zeroize::Zeroize;

const PROTOCOL_VERSION: u16 = super::PROTOCOL_VERSION;
const SEMANTIC_VERSION: u16 = super::SEMANTIC_PROTOCOL_V1;

const BUNDLE_MAGIC: &[u8; 8] = b"ASTRPB04";
const BUNDLE_VERSION: u16 = 4;
const BUNDLE_CHECKSUM_DOMAIN: &[u8] = b"aster/classical/provisioning-check/v1";
const KDF_SALT: &[u8] = b"aster/classical-profile/v1";
const PROFILE_POLICY_DOMAIN: &[u8] = b"aster/classical/profile-policy/v1";
const MISSION_PRINCIPAL_LABEL: &[u8] = b"mission-principal";
const NODE_PRINCIPAL_LABEL: &[u8] = b"node-principal";
const POLICY_AUTHORITY_ID_DOMAIN: &[u8] = b"aster/policy-authority/v1";
const CREDENTIAL_SIGNATURE_DOMAIN: &[u8] = b"aster/classical/credential-signature/v1";
const LOCAL_ACCESS_COMMITMENT_DOMAIN: &[u8] = b"aster/classical/local-access-commitment/v1";
const ROUTE_GRANT_COMMITMENT_DOMAIN: &[u8] = b"aster/classical/route-grant-commitment/v1";
const MAX_GRANTS: usize = 256;
const MAX_ACCESS_EPOCHS: usize = 32;
const MAX_ACCESS_TOPICS: usize = 128;
const MAX_CREDENTIAL_LEN: usize = 16 * 1024;

const ROLE_RELAY: u32 = 1;
const ROLE_READER: u32 = 2;
const ROLE_CONTROL_AUTHORITY: u32 = 4;

const ENVELOPE_MAGIC: &[u8; 8] = b"ASTRENV2";
const ENVELOPE_FORMAT_VERSION: u16 = 2;
const PUBLIC_HEADER_LEN: usize = 44;
const SELECTOR_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const P256_PUBLIC_LEN: usize = 33;
const P256_SIGNATURE_LEN: usize = 64;
const MAX_ROUTE_CIPHERTEXT_LEN: usize = 256 * 1024;
const MAX_CORE_LEN: usize = 512 * 1024 * 1024;
const MAX_LOGICAL_KEY_LEN: usize = 64 * 1024;

const ITEM_ID_DOMAIN: &[u8] = b"aster/classical/item/v1";
const ITEM_SIGNATURE_DOMAIN: &[u8] = b"aster/classical/singleton/v1";
const ROUTE_KEY_LABEL: &[u8] = b"aster/classical/route-key/v1";
const CONTENT_KEY_LABEL: &[u8] = b"aster/classical/content-key/v1";
const CONTENT_NONCE_LABEL: &[u8] = b"aster/classical/content-nonce/v1";
const CONTENT_GROUP_DOMAIN: &[u8] = b"aster/classical/content-group/v1";
const CONTROL_MAGIC: &[u8; 8] = b"ASTRCA03";
const CONTROL_FORMAT: u16 = 3;
const CONTROL_SIGNATURE_DOMAIN: &[u8] = b"aster/classical/delegated-control/v1";
const SCOPE_EPOCH_LEGACY_FORMAT: u16 = 0;

const HANDSHAKE_MAGIC: &[u8; 8] = b"ASTRHS01";
const HANDSHAKE_FRAMING_VERSION: u16 = 1;
const HANDSHAKE_PROFILE_ID: u16 = CLASSICAL_SECURITY_PROFILE_ID;
const MAX_HANDSHAKE_FLIGHT_LEN: usize = 64 * 1024;
const MAX_CHANNEL_BINDING_LEN: usize = 1024;
const CHANNEL_BINDING_DOMAIN: &[u8] = b"aster/classical/iroh-exporter/v1";
const CLIENT_HELLO_DOMAIN: &[u8] = b"aster/classical/client-hello/v1";
const HANDSHAKE_TRANSCRIPT_DOMAIN: &[u8] = b"aster/classical/handshake-transcript/v1";
const SERVER_AUTH_DOMAIN: &[u8] = b"aster/classical/server-auth/v1";
const CLIENT_AUTH_DOMAIN: &[u8] = b"aster/classical/client-auth/v1";
const FINAL_TRANSCRIPT_DOMAIN: &[u8] = b"aster/classical/final-transcript/v1";
const MISSION_PROOF_KEY_LABEL: &[u8] = b"aster/classical/mission-proof-key/v1";
const MISSION_PROOF_AAD_DOMAIN: &[u8] = b"aster/classical/mission-proof-aad/v1";
const SERVER_AUTH_AAD_DOMAIN: &[u8] = b"aster/classical/server-auth-aad/v1";
const SERVER_CONFIRM_AAD_DOMAIN: &[u8] = b"aster/classical/server-confirm-aad/v1";
const CLIENT_AUTH_AAD_DOMAIN: &[u8] = b"aster/classical/client-auth-aad/v1";
const CLIENT_CONFIRM_AAD_DOMAIN: &[u8] = b"aster/classical/client-confirm-aad/v1";
const SERVER_FINISHED_AAD_DOMAIN: &[u8] = b"aster/classical/server-finished-aad/v1";
const HANDSHAKE_SCHEDULE_LABEL: &[u8] = b"aster/classical/handshake-schedule/v1";

#[cfg(test)]
mod primitive_audit {
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) static P256_SIGNATURES: AtomicUsize = AtomicUsize::new(0);
    pub(super) static P256_VERIFICATIONS: AtomicUsize = AtomicUsize::new(0);
    pub(super) static P256_AGREEMENTS: AtomicUsize = AtomicUsize::new(0);
    pub(super) static ML_DSA_OPERATIONS: AtomicUsize = AtomicUsize::new(0);
    pub(super) static ML_KEM_OPERATIONS: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn reset() {
        P256_SIGNATURES.store(0, Ordering::Relaxed);
        P256_VERIFICATIONS.store(0, Ordering::Relaxed);
        P256_AGREEMENTS.store(0, Ordering::Relaxed);
        ML_DSA_OPERATIONS.store(0, Ordering::Relaxed);
        ML_KEM_OPERATIONS.store(0, Ordering::Relaxed);
    }
}

/// Capability-reduced wrapper around the shared symmetric/P-256 implementation.
///
/// It intentionally exposes no ML-DSA or ML-KEM method, so the classical lane
/// cannot acquire a post-quantum operation through its provider field even
/// though the legacy provider remains compiled in the same crate.
struct ClassicalCryptoProvider {
    inner: RustCryptoProvider<SysRng>,
}

impl ClassicalCryptoProvider {
    fn try_new() -> Result<Self, super::CryptoError> {
        Ok(Self {
            inner: RustCryptoProvider::try_new(SysRng)?,
        })
    }

    fn fill_random(&mut self, output: &mut [u8]) -> Result<(), super::CryptoError> {
        self.inner.fill_random(output)
    }

    fn derive_secret(
        &self,
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        label: &[u8],
        context: &[u8],
    ) -> Result<Secret32, super::CryptoError> {
        self.inner
            .derive_secret(input_key_material, salt, label, context)
    }

    fn seal(
        &mut self,
        key: &Secret32,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<AeadCiphertext, super::CryptoError> {
        self.inner.seal(key, plaintext, associated_data)
    }

    fn open(
        &self,
        key: &Secret32,
        sealed: &AeadCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, super::CryptoError> {
        self.inner.open(key, sealed, associated_data)
    }

    fn generate_ecdh_keypair(&mut self) -> Result<(P256SecretKey, Vec<u8>), super::CryptoError> {
        self.inner.generate_ecdh_keypair()
    }

    fn ecdh_agree(
        &self,
        secret: &P256SecretKey,
        peer_public_key: &[u8],
    ) -> Result<Secret32, super::CryptoError> {
        #[cfg(test)]
        primitive_audit::P256_AGREEMENTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.ecdh_agree(secret, peer_public_key)
    }

    fn seal_with_nonce(
        &self,
        key: &Secret32,
        nonce: [u8; NONCE_LEN],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, super::CryptoError> {
        self.inner
            .seal_with_nonce(key, nonce, plaintext, associated_data)
    }

    fn open_parts(
        &self,
        key: &Secret32,
        nonce: [u8; NONCE_LEN],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, super::CryptoError> {
        self.inner
            .open_parts(key, nonce, ciphertext, associated_data)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum EnvelopeKind {
    Data = 1,
    Revocation = 2,
    ScopeEpoch = 3,
}

impl EnvelopeKind {
    fn decode(value: u8) -> Result<Self, EnvelopeError> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Revocation),
            3 => Ok(Self::ScopeEpoch),
            _ => Err(invalid_envelope()),
        }
    }
}

/// Bounded exporter bytes from an already-authenticated carrier (Iroh QUIC in
/// profile `0x0002`). The bytes are digested before they enter any transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedChannelBinding(Vec<u8>);

impl AuthenticatedChannelBinding {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, EnvelopeError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_CHANNEL_BINDING_LEN {
            return Err(EnvelopeError(
                "authenticated channel binding is empty or too large".into(),
            ));
        }
        Ok(Self(bytes))
    }

    fn digest(&self) -> [u8; 32] {
        hash_domain(CHANNEL_BINDING_DOMAIN, &self.0)
    }
}

impl fmt::Debug for AuthenticatedChannelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedChannelBinding")
            .field("length", &self.0.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AuthenticatedChannelBinding {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// High-level route/content access used by the classical provisioner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicalProvisioningAccess {
    scope: Scope,
    epochs: Vec<u64>,
    readable_topics: Vec<Topic>,
    route_access: bool,
}

impl ClassicalProvisioningAccess {
    pub fn relay(scope: Scope, epochs: Vec<u64>) -> Result<Self, EnvelopeError> {
        Self::new(scope, epochs, Vec::new(), true)
    }

    pub fn member(
        scope: Scope,
        epochs: Vec<u64>,
        readable_topics: Vec<Topic>,
    ) -> Result<Self, EnvelopeError> {
        if readable_topics.is_empty() {
            return Err(EnvelopeError(
                "a member access grant must contain at least one topic".into(),
            ));
        }
        Self::new(scope, epochs, readable_topics, true)
    }

    fn new(
        scope: Scope,
        mut epochs: Vec<u64>,
        mut readable_topics: Vec<Topic>,
        route_access: bool,
    ) -> Result<Self, EnvelopeError> {
        if epochs.is_empty()
            || epochs.len() > MAX_ACCESS_EPOCHS
            || readable_topics.len() > MAX_ACCESS_TOPICS
        {
            return Err(EnvelopeError("invalid provisioning access bounds".into()));
        }
        epochs.sort_unstable();
        readable_topics.sort();
        if epochs.windows(2).any(|pair| pair[0] == pair[1])
            || readable_topics.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(EnvelopeError("duplicate provisioning access".into()));
        }
        Ok(Self {
            scope,
            epochs,
            readable_topics,
            route_access,
        })
    }
}

struct RouteGrant {
    scope: Scope,
    epoch: u64,
    key: Secret32,
}

struct ContentGrant {
    scope: Scope,
    topic: Topic,
    epoch: u64,
    key: Secret32,
}

#[derive(Clone)]
struct ClassicalCredential {
    body: Vec<u8>,
    signature: [u8; P256_SIGNATURE_LEN],
    node_principal: NodeId,
    verifying_key: [u8; P256_PUBLIC_LEN],
    roles: u32,
    route_grant_commitments: Vec<[u8; 32]>,
}

#[derive(Clone, Copy)]
struct CredentialClaims {
    node_principal: NodeId,
    serial: u64,
    roles: u32,
    verifying_key: [u8; P256_PUBLIC_LEN],
    local_access_commitment: [u8; 32],
}

/// Canonical unprotected `ASTRPB04` provisioning representation.
/// Operational storage must use `to_protected_bytes`.
pub struct ClassicalProvisioningBundle {
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    policy_authority_verifying_key: [u8; P256_PUBLIC_LEN],
    identity_seed: Option<Secret32>,
    node_principal: NodeId,
    serial: u64,
    roles: u32,
    credential_signature: [u8; P256_SIGNATURE_LEN],
    control_route_key: Option<Secret32>,
    route_grants: Vec<RouteGrant>,
    content_grants: Vec<ContentGrant>,
}

impl fmt::Debug for ClassicalProvisioningBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalProvisioningBundle")
            .field("profile", &self.receipt.profile_id())
            .field("policy_generation", &self.receipt.policy_generation())
            .field("mission_principal", &self.receipt.mission_principal())
            .field("node_principal", &self.node_principal)
            .field("serial", &self.serial)
            .field("roles", &self.roles)
            .field("route_grants", &self.route_grants.len())
            .field("content_grants", &self.content_grants.len())
            .field("zeroized", &self.identity_seed.is_none())
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

impl ClassicalProvisioningBundle {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < BUNDLE_MAGIC.len() + 2 + 32
            || bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES
        {
            return Err(invalid_bundle());
        }
        let checksum_start = bytes.len().checked_sub(32).ok_or_else(invalid_bundle)?;
        if bytes[checksum_start..] != hash_domain(BUNDLE_CHECKSUM_DOMAIN, &bytes[..checksum_start])
        {
            return Err(invalid_bundle());
        }
        let mut reader = Reader::new(&bytes[..checksum_start]);
        if reader.take(8)? != BUNDLE_MAGIC
            || reader.u16()? != BUNDLE_VERSION
            || reader.u16()? != PROTOCOL_VERSION
            || reader.u16()? != CLASSICAL_SUITE_ID
            || reader.u16()? != SEMANTIC_VERSION
        {
            return Err(invalid_bundle());
        }
        let profile = reader.u16()?;
        let required = reader.u16()?;
        let generation = reader.u64()?;
        if profile != CLASSICAL_SECURITY_PROFILE_ID || required != profile || generation == 0 {
            return Err(invalid_bundle());
        }
        let mission_principal = reader.array::<32>()?;
        let policy_authority_id = reader.array::<32>()?;
        let policy_digest = reader.array::<32>()?;
        let policy_authority_verifying_key = reader.array::<P256_PUBLIC_LEN>()?;
        if P256VerifyingKey::from_sec1_bytes(&policy_authority_verifying_key).is_err()
            || derive_policy_authority_id(&mission_principal, &policy_authority_verifying_key)
                != policy_authority_id
            || derive_policy_digest(generation, mission_principal, policy_authority_id)
                != policy_digest
        {
            return Err(invalid_bundle());
        }
        let identity_seed = Secret32::new(reader.array::<32>()?);
        let node_principal = reader.array::<32>()?;
        let serial = reader.u64()?;
        let roles = reader.u32()?;
        if serial == 0
            || roles == 0
            || roles & !(ROLE_RELAY | ROLE_READER | ROLE_CONTROL_AUTHORITY) != 0
        {
            return Err(invalid_bundle());
        }
        let credential_signature = reader.array::<P256_SIGNATURE_LEN>()?;
        let control_route_key = Secret32::new(reader.array::<32>()?);
        let route_count = usize::from(reader.u16()?);
        if route_count > MAX_GRANTS {
            return Err(invalid_bundle());
        }
        let mut route_grants = Vec::with_capacity(route_count);
        let mut previous_route_name = None;
        for _ in 0..route_count {
            let scope = decode_scope(reader.u16_bytes(128)?)?;
            let epoch = reader.u64()?;
            let name = (scope.clone(), epoch);
            if previous_route_name
                .as_ref()
                .is_some_and(|previous| previous >= &name)
            {
                return Err(invalid_bundle());
            }
            previous_route_name = Some(name);
            route_grants.push(RouteGrant {
                scope,
                epoch,
                key: Secret32::new(reader.array::<32>()?),
            });
        }
        let content_count = usize::from(reader.u16()?);
        if content_count > MAX_GRANTS {
            return Err(invalid_bundle());
        }
        let mut content_grants = Vec::with_capacity(content_count);
        let mut previous_content_name = None;
        for _ in 0..content_count {
            let scope = decode_scope(reader.u16_bytes(128)?)?;
            let topic = decode_topic(reader.u16_bytes(128)?)?;
            let epoch = reader.u64()?;
            let name = (scope.clone(), topic.clone(), epoch);
            if previous_content_name
                .as_ref()
                .is_some_and(|previous| previous >= &name)
            {
                return Err(invalid_bundle());
            }
            previous_content_name = Some(name);
            content_grants.push(ContentGrant {
                scope,
                topic,
                epoch,
                key: Secret32::new(reader.array::<32>()?),
            });
        }
        reader.finish()?;
        if (roles & ROLE_RELAY != 0) != !route_grants.is_empty()
            || (roles & ROLE_READER != 0) != !content_grants.is_empty()
        {
            return Err(invalid_bundle());
        }
        let bundle = Self {
            receipt: VerifiedSecurityProfile::new_classical(
                generation,
                mission_principal,
                policy_authority_id,
            ),
            policy_digest,
            policy_authority_verifying_key,
            identity_seed: Some(identity_seed),
            node_principal,
            serial,
            roles,
            credential_signature,
            control_route_key: Some(control_route_key),
            route_grants,
            content_grants,
        };
        validate_bundle_credential(&bundle)?;
        Ok(bundle)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let identity_seed = self.identity_seed.as_ref().ok_or_else(zeroized_service)?;
        let control_route_key = self
            .control_route_key
            .as_ref()
            .ok_or_else(zeroized_service)?;
        if self.receipt.profile_id_u16() != CLASSICAL_SECURITY_PROFILE_ID
            || self.receipt.required_profile_id() != self.receipt.profile_id()
            || self.receipt.suite_id() != CLASSICAL_SUITE_ID
            || self.receipt.policy_generation() == 0
            || self.policy_digest
                != derive_policy_digest(
                    self.receipt.policy_generation(),
                    self.receipt.mission_principal(),
                    self.receipt.policy_authority_id(),
                )
            || derive_policy_authority_id(
                &self.receipt.mission_principal(),
                &self.policy_authority_verifying_key,
            ) != self.receipt.policy_authority_id()
            || self.route_grants.len() > MAX_GRANTS
            || self.content_grants.len() > MAX_GRANTS
            || !grants_are_strictly_canonical(&self.route_grants, &self.content_grants)
            || (self.roles & ROLE_RELAY != 0) != !self.route_grants.is_empty()
            || (self.roles & ROLE_READER != 0) != !self.content_grants.is_empty()
        {
            return Err(invalid_bundle());
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes.extend_from_slice(&CLASSICAL_SUITE_ID.to_be_bytes());
        bytes.extend_from_slice(&SEMANTIC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.receipt.profile_id_u16().to_be_bytes());
        bytes.extend_from_slice(&self.receipt.required_profile_id().as_u16().to_be_bytes());
        bytes.extend_from_slice(&self.receipt.policy_generation().to_be_bytes());
        bytes.extend_from_slice(&self.receipt.mission_principal());
        bytes.extend_from_slice(&self.receipt.policy_authority_id());
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.policy_authority_verifying_key);
        bytes.extend_from_slice(identity_seed.expose());
        bytes.extend_from_slice(&self.node_principal);
        bytes.extend_from_slice(&self.serial.to_be_bytes());
        bytes.extend_from_slice(&self.roles.to_be_bytes());
        bytes.extend_from_slice(&self.credential_signature);
        bytes.extend_from_slice(control_route_key.expose());
        bytes.extend_from_slice(
            &u16::try_from(self.route_grants.len())
                .map_err(|_| invalid_bundle())?
                .to_be_bytes(),
        );
        for grant in &self.route_grants {
            push_u16_bytes(&mut bytes, grant.scope.as_str().as_bytes())?;
            bytes.extend_from_slice(&grant.epoch.to_be_bytes());
            bytes.extend_from_slice(grant.key.expose());
        }
        bytes.extend_from_slice(
            &u16::try_from(self.content_grants.len())
                .map_err(|_| invalid_bundle())?
                .to_be_bytes(),
        );
        for grant in &self.content_grants {
            push_u16_bytes(&mut bytes, grant.scope.as_str().as_bytes())?;
            push_u16_bytes(&mut bytes, grant.topic.as_str().as_bytes())?;
            bytes.extend_from_slice(&grant.epoch.to_be_bytes());
            bytes.extend_from_slice(grant.key.expose());
        }
        let checksum = hash_domain(BUNDLE_CHECKSUM_DOMAIN, &bytes);
        bytes.extend_from_slice(&checksum);
        if bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
            bytes.zeroize();
            return Err(invalid_bundle());
        }
        Ok(bytes)
    }

    pub fn to_protected_bytes<P>(
        &self,
        protector: &mut P,
    ) -> Result<Vec<u8>, ProtectedProvisioningError>
    where
        P: ProvisioningProtector + ?Sized,
    {
        let plaintext = UnprotectedProvisioning::new(
            self.to_bytes()
                .map_err(|_| ProtectedProvisioningError::InvalidBundle)?,
        )?;
        protect_provisioning_artifact(&plaintext, protector).map_err(Into::into)
    }

    pub fn from_protected_bytes<P>(
        protected: &[u8],
        unprotector: &mut P,
    ) -> Result<Self, ProtectedProvisioningError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let plaintext = unprotect_provisioning_artifact(protected, unprotector)?;
        Self::from_bytes(plaintext.expose()).map_err(|_| ProtectedProvisioningError::InvalidBundle)
    }

    pub const fn claimed_profile_id(&self) -> SecurityProfileId {
        SecurityProfileId::ClassicalP256IrohQuicV1
    }

    pub const fn claimed_policy_generation(&self) -> u64 {
        self.receipt.policy_generation()
    }

    /// Authority-verified stable node principal. `from_bytes` performs this
    /// verification before constructing the bundle.
    pub const fn node_principal(&self) -> NodeId {
        self.node_principal
    }

    /// Exact authority-verified profile policy. `from_bytes` performs this
    /// verification before constructing the bundle.
    pub const fn verified_security_profile(&self) -> VerifiedSecurityProfile {
        self.receipt
    }

    pub fn zeroize(&mut self) {
        self.identity_seed = None;
        self.control_route_key = None;
        self.route_grants.clear();
        self.content_grants.clear();
        self.credential_signature.zeroize();
    }

    pub fn is_zeroized(&self) -> bool {
        self.identity_seed.is_none()
            && self.control_route_key.is_none()
            && self.route_grants.is_empty()
            && self.content_grants.is_empty()
    }
}

impl Drop for ClassicalProvisioningBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Provisioning authority for the exact classical profile.
pub struct ClassicalProvisioner {
    root: Option<Secret32>,
    provider: ClassicalCryptoProvider,
    policy_authority_signing_key: Option<P256SigningKey>,
    policy_authority_verifying_key: [u8; P256_PUBLIC_LEN],
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    issued_serials: BTreeSet<u64>,
}

impl fmt::Debug for ClassicalProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalProvisioner")
            .field("profile", &self.receipt.profile_id())
            .field("policy_generation", &self.receipt.policy_generation())
            .field("mission_principal", &self.receipt.mission_principal())
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

impl ClassicalProvisioner {
    pub fn from_seed(seed: [u8; 32], policy_generation: u64) -> Result<Self, EnvelopeError> {
        if seed.iter().all(|byte| *byte == 0) || policy_generation == 0 {
            return Err(EnvelopeError(
                "provisioning seed and policy generation must be nonzero".into(),
            ));
        }
        let root = Secret32::new(seed);
        let provider = ClassicalCryptoProvider::try_new().map_err(crypto_error)?;
        let authority_seed =
            derive_material::<32>(root.expose(), b"policy-authority-signing-seed", &[])?;
        let policy_authority_signing_key = derive_p256_signing_key(&authority_seed)?;
        let policy_authority_verifying_key: [u8; P256_PUBLIC_LEN] = policy_authority_signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_ref()
            .try_into()
            .map_err(|_| invalid_bundle())?;
        let mission_principal = derive_material::<32>(root.expose(), MISSION_PRINCIPAL_LABEL, &[])?;
        let policy_authority_id =
            derive_policy_authority_id(&mission_principal, &policy_authority_verifying_key);
        let receipt = VerifiedSecurityProfile::new_classical(
            policy_generation,
            mission_principal,
            policy_authority_id,
        );
        let policy_digest =
            derive_policy_digest(policy_generation, mission_principal, policy_authority_id);
        Ok(Self {
            root: Some(root),
            provider,
            policy_authority_signing_key: Some(policy_authority_signing_key),
            policy_authority_verifying_key,
            receipt,
            policy_digest,
            issued_serials: BTreeSet::new(),
        })
    }

    pub fn issue_node(
        &mut self,
        serial: u64,
        accesses: &[ClassicalProvisioningAccess],
    ) -> Result<ClassicalProvisioningBundle, EnvelopeError> {
        self.issue(serial, accesses, false)
    }

    pub fn issue_control_authority(
        &mut self,
        serial: u64,
        accesses: &[ClassicalProvisioningAccess],
    ) -> Result<ClassicalProvisioningBundle, EnvelopeError> {
        self.issue(serial, accesses, true)
    }

    pub const fn verified_security_profile(&self) -> VerifiedSecurityProfile {
        self.receipt
    }

    fn issue(
        &mut self,
        serial: u64,
        accesses: &[ClassicalProvisioningAccess],
        control_authority: bool,
    ) -> Result<ClassicalProvisioningBundle, EnvelopeError> {
        if serial == 0 || accesses.is_empty() || !self.issued_serials.insert(serial) {
            return Err(EnvelopeError(
                "invalid or duplicate node provisioning request".into(),
            ));
        }
        let root = self.root.as_ref().ok_or_else(zeroized_service)?;
        let authority_signing_key = self
            .policy_authority_signing_key
            .as_ref()
            .ok_or_else(zeroized_service)?;
        let mut identity_seed_bytes = [0u8; 32];
        self.provider
            .fill_random(&mut identity_seed_bytes)
            .map_err(crypto_error)?;
        let identity_seed = Secret32::new(identity_seed_bytes);
        let signing_key = derive_p256_signing_key(identity_seed.expose())?;
        let verifying_key: [u8; P256_PUBLIC_LEN] = signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_ref()
            .try_into()
            .map_err(|_| invalid_bundle())?;
        let node_principal =
            derive_material::<32>(root.expose(), NODE_PRINCIPAL_LABEL, &serial.to_be_bytes())?;

        let mut route_names = BTreeSet::new();
        let mut content_names = BTreeSet::new();
        let mut route_grants = Vec::new();
        let mut content_grants = Vec::new();
        for access in accesses {
            if access.route_access {
                for &epoch in &access.epochs {
                    if route_names.insert((access.scope.clone(), epoch)) {
                        let context = grant_context(&access.scope, None, epoch)?;
                        route_grants.push(RouteGrant {
                            scope: access.scope.clone(),
                            epoch,
                            key: Secret32::new(derive_material::<32>(
                                root.expose(),
                                b"scope-routing-epoch",
                                &context,
                            )?),
                        });
                    }
                }
            }
            for topic in &access.readable_topics {
                for &epoch in &access.epochs {
                    if content_names.insert((access.scope.clone(), topic.clone(), epoch)) {
                        let context = grant_context(&access.scope, Some(topic), epoch)?;
                        content_grants.push(ContentGrant {
                            scope: access.scope.clone(),
                            topic: topic.clone(),
                            epoch,
                            key: Secret32::new(derive_material::<32>(
                                root.expose(),
                                b"topic-content-epoch",
                                &context,
                            )?),
                        });
                    }
                }
            }
        }
        if route_grants.len() > MAX_GRANTS || content_grants.len() > MAX_GRANTS {
            return Err(EnvelopeError("too many provisioning grants".into()));
        }
        route_grants
            .sort_by(|left, right| (&left.scope, left.epoch).cmp(&(&right.scope, right.epoch)));
        content_grants.sort_by(|left, right| {
            (&left.scope, &left.topic, left.epoch).cmp(&(&right.scope, &right.topic, right.epoch))
        });
        let mut roles = 0;
        if !route_grants.is_empty() {
            roles |= ROLE_RELAY;
        }
        if !content_grants.is_empty() {
            roles |= ROLE_READER;
        }
        if control_authority {
            roles |= ROLE_CONTROL_AUTHORITY;
        }
        let control_route_key = Secret32::new(derive_material::<32>(
            root.expose(),
            b"mission-control-route",
            &self.receipt.mission_principal(),
        )?);
        let commitments = route_grant_commitments(self.receipt.mission_principal(), &route_grants)?;
        let local_access_commitment = local_access_commitment(
            self.receipt,
            self.policy_digest,
            node_principal,
            &control_route_key,
            &route_grants,
            &content_grants,
        )?;
        let credential_body = encode_credential_body(
            self.receipt,
            self.policy_digest,
            CredentialClaims {
                node_principal,
                serial,
                roles,
                verifying_key,
                local_access_commitment,
            },
            &commitments,
        )?;
        let credential_signature = sign_digest(
            authority_signing_key,
            &hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &credential_body),
        )?;
        Ok(ClassicalProvisioningBundle {
            receipt: self.receipt,
            policy_digest: self.policy_digest,
            policy_authority_verifying_key: self.policy_authority_verifying_key,
            identity_seed: Some(identity_seed),
            node_principal,
            serial,
            roles,
            credential_signature,
            control_route_key: Some(control_route_key),
            route_grants,
            content_grants,
        })
    }

    pub fn zeroize(&mut self) {
        self.root = None;
        self.policy_authority_signing_key = None;
    }
}

impl Drop for ClassicalProvisioner {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct OpenedBundle {
    provider: ClassicalCryptoProvider,
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    policy_authority_verifying_key: [u8; P256_PUBLIC_LEN],
    credential: ClassicalCredential,
    signing_key: P256SigningKey,
    control_route_key: Secret32,
    route_grants: Vec<RouteGrant>,
    content_grants: Vec<ContentGrant>,
}

fn open_bundle(mut bundle: ClassicalProvisioningBundle) -> Result<OpenedBundle, EnvelopeError> {
    let seed = bundle.identity_seed.as_ref().ok_or_else(zeroized_service)?;
    let provider = ClassicalCryptoProvider::try_new().map_err(crypto_error)?;
    let signing_key = derive_p256_signing_key(seed.expose())?;
    let verifying_key: [u8; P256_PUBLIC_LEN] = signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_ref()
        .try_into()
        .map_err(|_| invalid_bundle())?;
    let commitments =
        route_grant_commitments(bundle.receipt.mission_principal(), &bundle.route_grants)?;
    let local_access_commitment = local_access_commitment(
        bundle.receipt,
        bundle.policy_digest,
        bundle.node_principal,
        bundle
            .control_route_key
            .as_ref()
            .ok_or_else(zeroized_service)?,
        &bundle.route_grants,
        &bundle.content_grants,
    )?;
    let credential_body = encode_credential_body(
        bundle.receipt,
        bundle.policy_digest,
        CredentialClaims {
            node_principal: bundle.node_principal,
            serial: bundle.serial,
            roles: bundle.roles,
            verifying_key,
            local_access_commitment,
        },
        &commitments,
    )?;
    verify_digest(
        &bundle.policy_authority_verifying_key,
        &hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &credential_body),
        &bundle.credential_signature,
    )?;
    if bundle.receipt.profile_id() != SecurityProfileId::ClassicalP256IrohQuicV1
        || bundle.receipt.required_profile_id() != bundle.receipt.profile_id()
        || bundle.receipt.suite_id() != CLASSICAL_SUITE_ID
        || bundle.receipt.policy_generation() == 0
        || derive_policy_digest(
            bundle.receipt.policy_generation(),
            bundle.receipt.mission_principal(),
            bundle.receipt.policy_authority_id(),
        ) != bundle.policy_digest
        || derive_policy_authority_id(
            &bundle.receipt.mission_principal(),
            &bundle.policy_authority_verifying_key,
        ) != bundle.receipt.policy_authority_id()
    {
        return Err(authentication_failed());
    }
    let credential = ClassicalCredential {
        body: credential_body,
        signature: bundle.credential_signature,
        node_principal: bundle.node_principal,
        verifying_key,
        roles: bundle.roles,
        route_grant_commitments: commitments,
    };
    let control_route_key = bundle
        .control_route_key
        .take()
        .ok_or_else(zeroized_service)?;
    let route_grants = std::mem::take(&mut bundle.route_grants);
    let content_grants = std::mem::take(&mut bundle.content_grants);
    let opened = OpenedBundle {
        provider,
        receipt: bundle.receipt,
        policy_digest: bundle.policy_digest,
        policy_authority_verifying_key: bundle.policy_authority_verifying_key,
        credential,
        signing_key,
        control_route_key,
        route_grants,
        content_grants,
    };
    bundle.zeroize();
    Ok(opened)
}

struct ParsedEnvelope<'a> {
    kind: EnvelopeKind,
    selector: [u8; SELECTOR_LEN],
    public_header: &'a [u8],
    route_ciphertext: &'a [u8],
    content_ciphertext: &'a [u8],
}

struct DecodedDataRoute {
    credential: ClassicalCredential,
    item_id: [u8; 32],
    header: EnvelopeHeader,
    content_group: [u8; 32],
    content_nonce: [u8; NONCE_LEN],
    content_ciphertext_len: u64,
    content_ciphertext_hash: [u8; 32],
}

enum DecodedControl {
    Revocation {
        signer: NodeId,
        sequence: u64,
        previous: Option<EnvelopeId>,
        subject: NodeId,
        generation: u64,
    },
    ScopeEpoch {
        signer: NodeId,
        sequence: u64,
        previous: Option<EnvelopeId>,
        scope: Scope,
        epoch: u64,
    },
}

/// Source/control service for profile `0x0002`.
pub struct ClassicalEnvelopeSealer {
    provider: ClassicalCryptoProvider,
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    policy_authority_verifying_key: [u8; P256_PUBLIC_LEN],
    credential: ClassicalCredential,
    signing_key: Option<P256SigningKey>,
    control_route_key: Option<Secret32>,
    route_grants: Vec<RouteGrant>,
    content_grants: Vec<ContentGrant>,
    zeroized: bool,
}

impl fmt::Debug for ClassicalEnvelopeSealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalEnvelopeSealer")
            .field("identity", &self.credential.node_principal)
            .field("mission_principal", &self.receipt.mission_principal())
            .field("profile", &self.receipt.profile_id())
            .field("policy_generation", &self.receipt.policy_generation())
            .field("route_grants", &self.route_grants.len())
            .field("content_grants", &self.content_grants.len())
            .field("zeroized", &self.zeroized)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ClassicalEnvelopeSealer {
    pub fn open(bundle: ClassicalProvisioningBundle) -> Result<Self, EnvelopeError> {
        let opened = open_bundle(bundle)?;
        Ok(Self {
            provider: opened.provider,
            receipt: opened.receipt,
            policy_digest: opened.policy_digest,
            policy_authority_verifying_key: opened.policy_authority_verifying_key,
            credential: opened.credential,
            signing_key: Some(opened.signing_key),
            control_route_key: Some(opened.control_route_key),
            route_grants: opened.route_grants,
            content_grants: opened.content_grants,
            zeroized: false,
        })
    }

    pub const fn identity(&self) -> NodeId {
        self.credential.node_principal
    }

    pub const fn node_principal(&self) -> NodeId {
        self.identity()
    }

    pub const fn authority_id(&self) -> NodeId {
        self.receipt.mission_principal()
    }

    pub const fn mission_authority_id(&self) -> NodeId {
        self.authority_id()
    }

    pub const fn verified_security_profile(&self) -> VerifiedSecurityProfile {
        self.receipt
    }

    pub const fn application_protection(&self) -> ApplicationProtection {
        ApplicationProtection::AuthenticatedCarrierRequired
    }

    pub fn can_route_event(&self, scope: &Scope, epoch: u64) -> bool {
        self.route_grant(scope, epoch).is_some()
    }

    pub(crate) fn current_source_route_grant_commitment(
        &self,
        scope: &Scope,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        self.route_grant(scope, epoch)
            .and_then(|grant| route_grant_commitment(self.receipt.mission_principal(), grant).ok())
    }

    pub(crate) fn current_event_route_grant_commitment(
        &self,
        scope: &Scope,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        self.current_source_route_grant_commitment(scope, epoch)
    }

    pub(crate) fn inspect_event_route_with_lineage(
        &mut self,
        sealed: &[u8],
    ) -> Result<(VerifiedEnvelope, [u8; 32]), EnvelopeError> {
        let (verified, _, _) = self.inspect_data_internal(sealed)?;
        let commitment = self
            .current_event_route_grant_commitment(&verified.header.scope, verified.header.key_epoch)
            .ok_or_else(authentication_failed)?;
        Ok((verified, commitment))
    }

    pub fn can_open_event_content(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.content_grant(scope, topic, epoch).is_some()
    }

    pub fn is_route_only(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.route_grant(scope, epoch).is_some()
            && self.content_grant(scope, topic, epoch).is_none()
    }

    pub fn peer_can_route(
        &self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        scope: &Scope,
        epoch: u64,
    ) -> bool {
        <Self as EnvelopeSealer>::peer_can_route(self, peer, peer_route_commitments, scope, epoch)
    }

    pub fn seal_event(
        &mut self,
        header: &EnvelopeHeader,
        payload: &[u8],
    ) -> Result<SealedEnvelope, EnvelopeError> {
        if header.class != DataClass::Event {
            return Err(unsupported_profile("non-Event source object"));
        }
        self.seal_data(SealRequest { header, payload })
    }

    pub fn seal_revocation(
        &mut self,
        subject: NodeId,
        generation: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_revocation_chained(subject, generation, 1, None)
    }

    pub fn seal_revocation_chained(
        &mut self,
        subject: NodeId,
        generation: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if generation == 0 {
            return Err(EnvelopeError(
                "revocation generation must be nonzero".into(),
            ));
        }
        let mut body = self.control_prefix(EnvelopeKind::Revocation, sequence, previous)?;
        body.extend_from_slice(&subject);
        body.extend_from_slice(&generation.to_be_bytes());
        self.seal_control(EnvelopeKind::Revocation, body)
    }

    pub fn seal_scope_epoch(
        &mut self,
        scope: &Scope,
        epoch: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_scope_epoch_chained(scope, epoch, 1, None)
    }

    pub fn seal_scope_epoch_chained(
        &mut self,
        scope: &Scope,
        epoch: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if self.route_grant(scope, epoch).is_none() {
            return Err(EnvelopeError(
                "authority lacks the requested pre-provisioned routing epoch".into(),
            ));
        }
        let mut body = self.control_prefix(EnvelopeKind::ScopeEpoch, sequence, previous)?;
        push_u16_bytes(&mut body, scope.as_str().as_bytes())?;
        body.extend_from_slice(&epoch.to_be_bytes());
        body.extend_from_slice(&SCOPE_EPOCH_LEGACY_FORMAT.to_be_bytes());
        self.seal_control(EnvelopeKind::ScopeEpoch, body)
    }

    pub fn unsupported_batch(&self) -> Result<(), EnvelopeError> {
        Err(unsupported_profile("semantic-v2 batch"))
    }

    pub fn unsupported_bridge(&self) -> Result<(), EnvelopeError> {
        Err(unsupported_profile("bridge"))
    }

    pub fn unsupported_blob(&self) -> Result<(), EnvelopeError> {
        Err(unsupported_profile("blob"))
    }

    pub fn unsupported_rekey(&self) -> Result<(), EnvelopeError> {
        Err(unsupported_profile("recipient rekey"))
    }

    fn ensure_live(&self) -> Result<(), EnvelopeError> {
        if self.zeroized || self.signing_key.is_none() || self.control_route_key.is_none() {
            Err(zeroized_service())
        } else {
            Ok(())
        }
    }

    fn route_grant(&self, scope: &Scope, epoch: u64) -> Option<&RouteGrant> {
        self.route_grants
            .iter()
            .find(|grant| &grant.scope == scope && grant.epoch == epoch)
    }

    fn content_grant(&self, scope: &Scope, topic: &Topic, epoch: u64) -> Option<&ContentGrant> {
        self.content_grants
            .iter()
            .find(|grant| &grant.scope == scope && &grant.topic == topic && grant.epoch == epoch)
    }

    fn seal_data(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError> {
        self.ensure_live()?;
        if request.header.class != DataClass::Event {
            return Err(unsupported_profile(
                "non-Event or mutable source representation",
            ));
        }
        validate_header_for_seal(request.header, request.payload, &self.identity())?;
        let mut route_seed = *self
            .route_grant(&request.header.scope, request.header.key_epoch)
            .ok_or_else(|| EnvelopeError("no routing grant for Event scope epoch".into()))?
            .key
            .expose();
        let mut content_seed = *self
            .content_grant(
                &request.header.scope,
                &request.header.topic,
                request.header.key_epoch,
            )
            .ok_or_else(|| EnvelopeError("no content grant for Event topic epoch".into()))?
            .key
            .expose();
        let mut core = Vec::new();
        encode_header(&mut core, request.header)?;
        push_u64_bytes(&mut core, request.payload)?;
        if core.len() > MAX_CORE_LEN {
            core.zeroize();
            return Err(EnvelopeError("Event core is too large".into()));
        }
        let result = (|| {
            let item_id = hash_domain(ITEM_ID_DOMAIN, &core);
            let content_key = derive_item_secret(&content_seed, CONTENT_KEY_LABEL, &item_id)?;
            let nonce_material =
                derive_material::<32>(&content_seed, CONTENT_NONCE_LABEL, &item_id)?;
            let mut content_nonce = [0u8; NONCE_LEN];
            content_nonce.copy_from_slice(&nonce_material[..NONCE_LEN]);
            let content_ciphertext = self
                .provider
                .seal_with_nonce(
                    &content_key,
                    content_nonce,
                    &core,
                    &encode_content_aad(request.header.key_epoch, &item_id),
                )
                .map_err(crypto_error)?;
            let content_ciphertext_hash = hash_domain(
                b"aster/classical/content-ciphertext/v1",
                &content_ciphertext,
            );
            let mut route_plaintext = Vec::new();
            route_plaintext.push(EnvelopeKind::Data as u8);
            push_u32_bytes(&mut route_plaintext, &self.credential.body)?;
            route_plaintext.extend_from_slice(&self.credential.signature);
            route_plaintext.extend_from_slice(&item_id);
            encode_header(&mut route_plaintext, request.header)?;
            route_plaintext.extend_from_slice(&content_group_id(
                &request.header.scope,
                &request.header.topic,
            ));
            route_plaintext.extend_from_slice(&content_nonce);
            route_plaintext.extend_from_slice(
                &u64::try_from(content_ciphertext.len())
                    .map_err(|_| invalid_envelope())?
                    .to_be_bytes(),
            );
            route_plaintext.extend_from_slice(&content_ciphertext_hash);
            let signature = sign_digest(
                self.signing_key.as_ref().ok_or_else(zeroized_service)?,
                &hash_domain(ITEM_SIGNATURE_DOMAIN, &route_plaintext),
            )?;
            route_plaintext.extend_from_slice(&signature);

            let mut selector = [0u8; SELECTOR_LEN];
            self.provider
                .fill_random(&mut selector)
                .map_err(crypto_error)?;
            let route_key = derive_item_secret(&route_seed, ROUTE_KEY_LABEL, &selector)?;
            let public_header = encode_public_header(
                EnvelopeKind::Data,
                selector,
                route_plaintext.len().saturating_add(GCM_TAG_LEN),
                content_ciphertext.len(),
            )?;
            let route_ciphertext = self
                .provider
                .seal_with_nonce(
                    &route_key,
                    selector_nonce(&selector),
                    &route_plaintext,
                    &public_header,
                )
                .map_err(crypto_error)?;
            let mut sealed = Vec::with_capacity(
                public_header.len() + route_ciphertext.len() + content_ciphertext.len(),
            );
            sealed.extend_from_slice(&public_header);
            sealed.extend_from_slice(&route_ciphertext);
            sealed.extend_from_slice(&content_ciphertext);
            Ok(SealedEnvelope {
                id: item_id,
                bytes: sealed,
            })
        })();
        core.zeroize();
        route_seed.zeroize();
        content_seed.zeroize();
        result
    }

    fn inspect_data_internal<'a>(
        &'a self,
        sealed: &'a [u8],
    ) -> Result<(VerifiedEnvelope, ParsedEnvelope<'a>, DecodedDataRoute), EnvelopeError> {
        self.ensure_live()?;
        let parsed = parse_envelope(sealed)?;
        if parsed.kind != EnvelopeKind::Data {
            return Err(authentication_failed());
        }
        for grant in &self.route_grants {
            let Ok(route_key) =
                derive_item_secret(grant.key.expose(), ROUTE_KEY_LABEL, &parsed.selector)
            else {
                continue;
            };
            let Ok(mut plaintext) = self.provider.open_parts(
                &route_key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            ) else {
                continue;
            };
            let decoded = decode_data_route(
                &plaintext,
                self.receipt,
                self.policy_digest,
                &self.policy_authority_verifying_key,
            );
            plaintext.zeroize();
            let Ok(route) = decoded else {
                continue;
            };
            if route.header.class != DataClass::Event
                || grant.scope != route.header.scope
                || grant.epoch != route.header.key_epoch
                || route.header.stamp.dot.publisher != route.credential.node_principal
                || route.credential.roles & ROLE_RELAY == 0
                || route.content_group != content_group_id(&route.header.scope, &route.header.topic)
                || route.content_ciphertext_len != parsed.content_ciphertext.len() as u64
                || route.content_ciphertext_hash
                    != hash_domain(
                        b"aster/classical/content-ciphertext/v1",
                        parsed.content_ciphertext,
                    )
                || route
                    .credential
                    .route_grant_commitments
                    .binary_search(&route_grant_commitment(
                        self.receipt.mission_principal(),
                        grant,
                    )?)
                    .is_err()
            {
                continue;
            }
            return Ok((
                VerifiedEnvelope {
                    id: route.item_id,
                    header: route.header.clone(),
                },
                parsed,
                route,
            ));
        }
        Err(authentication_failed())
    }

    fn open_verified_content(
        &self,
        route: &DecodedDataRoute,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let grant = self
            .content_grant(
                &route.header.scope,
                &route.header.topic,
                route.header.key_epoch,
            )
            .ok_or_else(|| EnvelopeError("content is not granted to this node".into()))?;
        let content_key =
            derive_item_secret(grant.key.expose(), CONTENT_KEY_LABEL, &route.item_id)?;
        let nonce_material =
            derive_material::<32>(grant.key.expose(), CONTENT_NONCE_LABEL, &route.item_id)?;
        if route.content_nonce != nonce_material[..NONCE_LEN] {
            return Err(authentication_failed());
        }
        let mut core = self
            .provider
            .open_parts(
                &content_key,
                route.content_nonce,
                ciphertext,
                &encode_content_aad(route.header.key_epoch, &route.item_id),
            )
            .map_err(crypto_error)?;
        if hash_domain(ITEM_ID_DOMAIN, &core) != route.item_id {
            core.zeroize();
            return Err(authentication_failed());
        }
        let decoded = decode_core(&core);
        core.zeroize();
        let (header, payload) = decoded?;
        if header != route.header {
            return Err(authentication_failed());
        }
        Ok(payload)
    }

    fn control_prefix(
        &self,
        kind: EnvelopeKind,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.ensure_live()?;
        if self.credential.roles & ROLE_CONTROL_AUTHORITY == 0
            || sequence == 0
            || (sequence == 1) != previous.is_none()
        {
            return Err(EnvelopeError(
                "invalid delegated control publication".into(),
            ));
        }
        let mut body = Vec::new();
        body.push(kind as u8);
        body.extend_from_slice(CONTROL_MAGIC);
        body.extend_from_slice(&CONTROL_FORMAT.to_be_bytes());
        encode_profile_receipt(&mut body, self.receipt, self.policy_digest);
        push_u32_bytes(&mut body, &self.credential.body)?;
        body.extend_from_slice(&self.credential.signature);
        body.extend_from_slice(&sequence.to_be_bytes());
        match previous {
            Some(previous) => {
                body.push(1);
                body.extend_from_slice(&previous);
            }
            None => body.push(0),
        }
        Ok(body)
    }

    fn seal_control(
        &mut self,
        kind: EnvelopeKind,
        mut body: Vec<u8>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let signature = sign_digest(
            self.signing_key.as_ref().ok_or_else(zeroized_service)?,
            &hash_domain(CONTROL_SIGNATURE_DOMAIN, &body),
        )?;
        body.extend_from_slice(&signature);
        let mut selector = [0u8; SELECTOR_LEN];
        self.provider
            .fill_random(&mut selector)
            .map_err(crypto_error)?;
        let route_key = derive_item_secret(
            self.control_route_key
                .as_ref()
                .ok_or_else(zeroized_service)?
                .expose(),
            ROUTE_KEY_LABEL,
            &selector,
        )?;
        let public_header =
            encode_public_header(kind, selector, body.len().saturating_add(GCM_TAG_LEN), 0)?;
        let route_ciphertext = self
            .provider
            .seal_with_nonce(&route_key, selector_nonce(&selector), &body, &public_header)
            .map_err(crypto_error)?;
        let mut sealed = public_header;
        sealed.extend_from_slice(&route_ciphertext);
        Ok(sealed)
    }

    fn inspect_control_internal(&self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError> {
        self.ensure_live()?;
        let parsed = parse_envelope(sealed)?;
        if parsed.kind == EnvelopeKind::Data || !parsed.content_ciphertext.is_empty() {
            return Err(authentication_failed());
        }
        let route_key = derive_item_secret(
            self.control_route_key
                .as_ref()
                .ok_or_else(zeroized_service)?
                .expose(),
            ROUTE_KEY_LABEL,
            &parsed.selector,
        )?;
        let mut plaintext = self
            .provider
            .open_parts(
                &route_key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            )
            .map_err(crypto_error)?;
        let decoded = decode_control(
            &plaintext,
            parsed.kind,
            self.receipt,
            self.policy_digest,
            &self.policy_authority_verifying_key,
        );
        plaintext.zeroize();
        match decoded? {
            DecodedControl::Revocation {
                signer,
                sequence,
                previous,
                subject,
                generation,
            } => Ok(VerifiedControl::Revocation(Revocation {
                subject,
                authority: self.receipt.mission_principal(),
                signer,
                generation,
                control_sequence: sequence,
                previous_control: previous,
                sealed_notice: sealed.to_vec(),
                observed_at_ms: None,
            })),
            DecodedControl::ScopeEpoch {
                signer,
                sequence,
                previous,
                scope,
                epoch,
            } => Ok(VerifiedControl::ScopeEpoch(ScopeEpoch {
                authority: self.receipt.mission_principal(),
                signer,
                scope,
                epoch,
                control_sequence: sequence,
                previous_control: previous,
                sealed_notice: sealed.to_vec(),
            })),
        }
    }

    fn erase(&mut self) {
        self.signing_key = None;
        self.control_route_key = None;
        self.route_grants.clear();
        self.content_grants.clear();
        self.zeroized = true;
    }
}

impl Drop for ClassicalEnvelopeSealer {
    fn drop(&mut self) {
        self.erase();
    }
}

impl EnvelopeSealer for ClassicalEnvelopeSealer {
    fn seal(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError> {
        self.seal_data(request)
    }

    fn inspect(&mut self, sealed: &[u8]) -> Result<VerifiedEnvelope, EnvelopeError> {
        self.inspect_data_internal(sealed)
            .map(|(verified, _, _)| verified)
    }

    fn open_payload(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let (verified, parsed, route) = self.inspect_data_internal(sealed)?;
        if &verified != envelope {
            return Err(authentication_failed());
        }
        self.open_verified_content(&route, parsed.content_ciphertext)
    }

    fn open_payload_if_authorized(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EnvelopeError> {
        let (verified, parsed, route) = self.inspect_data_internal(sealed)?;
        if &verified != envelope {
            return Err(authentication_failed());
        }
        if self
            .content_grant(
                &route.header.scope,
                &route.header.topic,
                route.header.key_epoch,
            )
            .is_none()
        {
            return Ok(None);
        }
        self.open_verified_content(&route, parsed.content_ciphertext)
            .map(Some)
    }

    fn inspect_control(&mut self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError> {
        self.inspect_control_internal(sealed)
    }

    fn activate_control(
        &mut self,
        sealed: &[u8],
        _local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        self.inspect_control_internal(sealed).map(|_| ())
    }

    fn peer_can_route(
        &self,
        _peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        scope: &Scope,
        epoch: u64,
    ) -> bool {
        let Some(grant) = self.route_grant(scope, epoch) else {
            return false;
        };
        route_grant_commitment(self.receipt.mission_principal(), grant)
            .ok()
            .is_some_and(|commitment| peer_route_commitments.binary_search(&commitment).is_ok())
    }

    fn control_principal(&self) -> Option<ControlPrincipal> {
        (self.credential.roles & ROLE_CONTROL_AUTHORITY != 0).then_some(ControlPrincipal {
            authority: self.receipt.mission_principal(),
            signer: self.credential.node_principal,
        })
    }

    fn seal_revocation_control(
        &mut self,
        subject: NodeId,
        generation: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_revocation_chained(subject, generation, sequence, previous)
    }

    fn seal_scope_epoch_control(
        &mut self,
        scope: &Scope,
        epoch: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_scope_epoch_chained(scope, epoch, sequence, previous)
    }

    fn zeroize(&mut self) -> Result<(), EnvelopeError> {
        self.erase();
        Ok(())
    }
}

struct ClassicalSessionEndpoint {
    provider: ClassicalCryptoProvider,
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    policy_authority_verifying_key: [u8; P256_PUBLIC_LEN],
    credential: ClassicalCredential,
    signing_key: P256SigningKey,
    mission_proof_key: Secret32,
}

impl ClassicalSessionEndpoint {
    fn open(bundle: ClassicalProvisioningBundle) -> Result<Self, EnvelopeError> {
        let opened = open_bundle(bundle)?;
        Ok(Self {
            provider: opened.provider,
            receipt: opened.receipt,
            policy_digest: opened.policy_digest,
            policy_authority_verifying_key: opened.policy_authority_verifying_key,
            credential: opened.credential,
            signing_key: opened.signing_key,
            mission_proof_key: opened.control_route_key,
        })
    }

    fn decode_peer_credential(
        &self,
        body: Vec<u8>,
        signature: [u8; P256_SIGNATURE_LEN],
    ) -> Result<ClassicalCredential, EnvelopeError> {
        decode_credential(
            body,
            signature,
            self.receipt,
            self.policy_digest,
            &self.policy_authority_verifying_key,
        )
    }
}

#[derive(Clone)]
struct ClientPublic {
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    channel_binding_digest: [u8; 32],
    nonce: [u8; 32],
    p256_ephemeral_public: Vec<u8>,
}

#[derive(Clone)]
struct ServerPublic {
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    channel_binding_digest: [u8; 32],
    nonce: [u8; 32],
    p256_ephemeral_public: Vec<u8>,
}

struct HandshakeSchedule {
    server_auth: Secret32,
    server_confirmation: Secret32,
    client_auth: Secret32,
    client_confirmation: Secret32,
    server_finished: Secret32,
    session_master: Secret32,
}

/// Initiator state for the exact carrier-bound classical four-flight handshake.
pub struct ClassicalSessionInitiator {
    endpoint: ClassicalSessionEndpoint,
    binding_digest: [u8; 32],
    client_flight: Vec<u8>,
    ephemeral_secret: Option<P256SecretKey>,
}

impl fmt::Debug for ClassicalSessionInitiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalSessionInitiator")
            .field("identity", &self.endpoint.credential.node_principal)
            .field("profile", &self.endpoint.receipt.profile_id())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ClassicalSessionInitiator {
    pub fn start(
        bundle: ClassicalProvisioningBundle,
        channel_binding: AuthenticatedChannelBinding,
    ) -> Result<(Self, Vec<u8>), EnvelopeError> {
        let binding_digest = channel_binding.digest();
        drop(channel_binding);
        let mut endpoint = ClassicalSessionEndpoint::open(bundle)?;
        let (ephemeral_secret, p256_ephemeral_public) = endpoint
            .provider
            .generate_ecdh_keypair()
            .map_err(crypto_error)?;
        let mut nonce = [0u8; 32];
        endpoint
            .provider
            .fill_random(&mut nonce)
            .map_err(crypto_error)?;
        let public = ClientPublic {
            receipt: endpoint.receipt,
            policy_digest: endpoint.policy_digest,
            channel_binding_digest: binding_digest,
            nonce,
            p256_ephemeral_public,
        };
        let public_bytes = encode_client_public(&public)?;
        let hello_hash = hash_domain(CLIENT_HELLO_DOMAIN, &public_bytes);
        let mission_key = endpoint
            .provider
            .derive_secret(
                endpoint.mission_proof_key.expose(),
                Some(&endpoint.policy_digest),
                MISSION_PROOF_KEY_LABEL,
                &hello_hash,
            )
            .map_err(crypto_error)?;
        let mission_proof = endpoint
            .provider
            .seal(
                &mission_key,
                &[],
                &handshake_aad(MISSION_PROOF_AAD_DOMAIN, &hello_hash),
            )
            .map_err(crypto_error)?;
        let flight = encode_client_flight(&public_bytes, &mission_proof)?;
        Ok((
            Self {
                endpoint,
                binding_digest,
                client_flight: flight.clone(),
                ephemeral_secret: Some(ephemeral_secret),
            },
            flight,
        ))
    }

    pub fn receive_server(
        mut self,
        flight: &[u8],
    ) -> Result<(ClassicalSessionAwaitingFinished, Vec<u8>), EnvelopeError> {
        let (server, server_public_bytes, protected_auth, confirmation) =
            decode_server_flight(flight)?;
        validate_public_policy(
            server.receipt,
            server.policy_digest,
            server.channel_binding_digest,
            self.endpoint.receipt,
            self.endpoint.policy_digest,
            self.binding_digest,
        )?;
        let transcript = handshake_transcript(&self.client_flight, &server_public_bytes);
        let ephemeral_secret = self
            .ephemeral_secret
            .take()
            .ok_or_else(authentication_failed)?;
        let shared = audited_ecdh(
            &self.endpoint.provider,
            &ephemeral_secret,
            &server.p256_ephemeral_public,
        )?;
        let schedule = derive_handshake_schedule(
            &self.endpoint.provider,
            &shared,
            self.endpoint.receipt,
            self.endpoint.policy_digest,
            self.binding_digest,
            transcript,
        )?;
        let mut confirmed = self
            .endpoint
            .provider
            .open(
                &schedule.server_confirmation,
                &confirmation,
                &handshake_aad(SERVER_CONFIRM_AAD_DOMAIN, &transcript),
            )
            .map_err(crypto_error)?;
        if confirmed.as_slice() != transcript {
            confirmed.zeroize();
            return Err(authentication_failed());
        }
        confirmed.zeroize();
        let mut server_auth = self
            .endpoint
            .provider
            .open(
                &schedule.server_auth,
                &protected_auth,
                &handshake_aad(SERVER_AUTH_AAD_DOMAIN, &transcript),
            )
            .map_err(crypto_error)?;
        let decoded_auth = decode_handshake_auth(&server_auth)?;
        let peer = self.endpoint.decode_peer_credential(
            decoded_auth.credential_body,
            decoded_auth.credential_signature,
        )?;
        verify_digest(
            &peer.verifying_key,
            &handshake_auth_digest(
                SERVER_AUTH_DOMAIN,
                transcript,
                None,
                &peer.body,
                self.endpoint.receipt,
                self.endpoint.policy_digest,
                self.binding_digest,
            ),
            &decoded_auth.handshake_signature,
        )?;
        let server_auth_hash = hash_domain(SERVER_AUTH_DOMAIN, &server_auth);
        let client_digest = handshake_auth_digest(
            CLIENT_AUTH_DOMAIN,
            transcript,
            Some(server_auth_hash),
            &self.endpoint.credential.body,
            self.endpoint.receipt,
            self.endpoint.policy_digest,
            self.binding_digest,
        );
        let client_signature = sign_digest(&self.endpoint.signing_key, &client_digest)?;
        let mut client_auth = encode_handshake_auth(
            &self.endpoint.credential.body,
            &self.endpoint.credential.signature,
            &client_signature,
        )?;
        let client_auth_hash = hash_domain(CLIENT_AUTH_DOMAIN, &client_auth);
        let final_transcript = final_transcript(transcript, server_auth_hash, client_auth_hash);
        let protected_client_auth = self
            .endpoint
            .provider
            .seal(
                &schedule.client_auth,
                &client_auth,
                &handshake_aad(CLIENT_AUTH_AAD_DOMAIN, &transcript),
            )
            .map_err(crypto_error)?;
        let client_confirmation = self
            .endpoint
            .provider
            .seal(
                &schedule.client_confirmation,
                &final_transcript,
                &handshake_aad(CLIENT_CONFIRM_AAD_DOMAIN, &final_transcript),
            )
            .map_err(crypto_error)?;
        let client_flight =
            encode_client_auth_flight(&protected_client_auth, &client_confirmation)?;
        server_auth.zeroize();
        client_auth.zeroize();
        Ok((
            ClassicalSessionAwaitingFinished {
                endpoint: self.endpoint,
                peer_identity: peer.node_principal,
                peer_route_grant_commitments: peer.route_grant_commitments,
                schedule: Some(schedule),
                final_transcript,
                binding_digest: self.binding_digest,
            },
            client_flight,
        ))
    }
}

/// Initiator state after peer authentication but before flight four.
pub struct ClassicalSessionAwaitingFinished {
    endpoint: ClassicalSessionEndpoint,
    peer_identity: NodeId,
    peer_route_grant_commitments: Vec<[u8; 32]>,
    schedule: Option<HandshakeSchedule>,
    final_transcript: [u8; 32],
    binding_digest: [u8; 32],
}

impl ClassicalSessionAwaitingFinished {
    pub fn receive_finished(
        mut self,
        flight: &[u8],
    ) -> Result<ClassicalAuthenticatedSession, EnvelopeError> {
        let protected = decode_server_finished_flight(flight)?;
        let schedule = self.schedule.take().ok_or_else(authentication_failed)?;
        let mut finished = self
            .endpoint
            .provider
            .open(
                &schedule.server_finished,
                &protected,
                &handshake_aad(SERVER_FINISHED_AAD_DOMAIN, &self.final_transcript),
            )
            .map_err(crypto_error)?;
        if finished.as_slice() != self.final_transcript {
            finished.zeroize();
            return Err(authentication_failed());
        }
        finished.zeroize();
        authenticated_session(
            &self.endpoint.provider,
            self.peer_identity,
            self.peer_route_grant_commitments,
            self.endpoint.receipt,
            self.binding_digest,
            self.final_transcript,
            schedule.session_master,
        )
    }
}

/// Initial responder state for the exact classical profile.
pub struct ClassicalSessionResponder {
    endpoint: ClassicalSessionEndpoint,
    binding_digest: [u8; 32],
}

impl fmt::Debug for ClassicalSessionResponder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalSessionResponder")
            .field("identity", &self.endpoint.credential.node_principal)
            .field("profile", &self.endpoint.receipt.profile_id())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ClassicalSessionResponder {
    pub fn open(
        bundle: ClassicalProvisioningBundle,
        channel_binding: AuthenticatedChannelBinding,
    ) -> Result<Self, EnvelopeError> {
        let binding_digest = channel_binding.digest();
        drop(channel_binding);
        Ok(Self {
            endpoint: ClassicalSessionEndpoint::open(bundle)?,
            binding_digest,
        })
    }

    pub fn receive_client(
        mut self,
        flight: &[u8],
    ) -> Result<(ClassicalSessionResponderPending, Vec<u8>), EnvelopeError> {
        let (client, client_public_bytes, mission_proof) = decode_client_flight(flight)?;
        validate_public_policy(
            client.receipt,
            client.policy_digest,
            client.channel_binding_digest,
            self.endpoint.receipt,
            self.endpoint.policy_digest,
            self.binding_digest,
        )?;
        let hello_hash = hash_domain(CLIENT_HELLO_DOMAIN, &client_public_bytes);
        let mission_key = self
            .endpoint
            .provider
            .derive_secret(
                self.endpoint.mission_proof_key.expose(),
                Some(&self.endpoint.policy_digest),
                MISSION_PROOF_KEY_LABEL,
                &hello_hash,
            )
            .map_err(crypto_error)?;
        let mut mission_plaintext = self
            .endpoint
            .provider
            .open(
                &mission_key,
                &mission_proof,
                &handshake_aad(MISSION_PROOF_AAD_DOMAIN, &hello_hash),
            )
            .map_err(crypto_error)?;
        if !mission_plaintext.is_empty() {
            mission_plaintext.zeroize();
            return Err(authentication_failed());
        }

        let (ephemeral_secret, p256_ephemeral_public) = self
            .endpoint
            .provider
            .generate_ecdh_keypair()
            .map_err(crypto_error)?;
        let shared = audited_ecdh(
            &self.endpoint.provider,
            &ephemeral_secret,
            &client.p256_ephemeral_public,
        )?;
        let mut nonce = [0u8; 32];
        self.endpoint
            .provider
            .fill_random(&mut nonce)
            .map_err(crypto_error)?;
        let server = ServerPublic {
            receipt: self.endpoint.receipt,
            policy_digest: self.endpoint.policy_digest,
            channel_binding_digest: self.binding_digest,
            nonce,
            p256_ephemeral_public,
        };
        let server_public_bytes = encode_server_public(&server)?;
        let transcript = handshake_transcript(flight, &server_public_bytes);
        let schedule = derive_handshake_schedule(
            &self.endpoint.provider,
            &shared,
            self.endpoint.receipt,
            self.endpoint.policy_digest,
            self.binding_digest,
            transcript,
        )?;
        let server_digest = handshake_auth_digest(
            SERVER_AUTH_DOMAIN,
            transcript,
            None,
            &self.endpoint.credential.body,
            self.endpoint.receipt,
            self.endpoint.policy_digest,
            self.binding_digest,
        );
        let server_signature = sign_digest(&self.endpoint.signing_key, &server_digest)?;
        let mut server_auth = encode_handshake_auth(
            &self.endpoint.credential.body,
            &self.endpoint.credential.signature,
            &server_signature,
        )?;
        let server_auth_hash = hash_domain(SERVER_AUTH_DOMAIN, &server_auth);
        let protected_auth = self
            .endpoint
            .provider
            .seal(
                &schedule.server_auth,
                &server_auth,
                &handshake_aad(SERVER_AUTH_AAD_DOMAIN, &transcript),
            )
            .map_err(crypto_error)?;
        let confirmation = self
            .endpoint
            .provider
            .seal(
                &schedule.server_confirmation,
                &transcript,
                &handshake_aad(SERVER_CONFIRM_AAD_DOMAIN, &transcript),
            )
            .map_err(crypto_error)?;
        let server_flight =
            encode_server_flight(&server_public_bytes, &protected_auth, &confirmation)?;
        server_auth.zeroize();
        Ok((
            ClassicalSessionResponderPending {
                endpoint: self.endpoint,
                binding_digest: self.binding_digest,
                transcript,
                server_auth_hash,
                schedule: Some(schedule),
            },
            server_flight,
        ))
    }
}

/// Responder state waiting for flight three.
pub struct ClassicalSessionResponderPending {
    endpoint: ClassicalSessionEndpoint,
    binding_digest: [u8; 32],
    transcript: [u8; 32],
    server_auth_hash: [u8; 32],
    schedule: Option<HandshakeSchedule>,
}

impl ClassicalSessionResponderPending {
    pub fn receive_client_auth(
        mut self,
        flight: &[u8],
    ) -> Result<(ClassicalAuthenticatedSession, Vec<u8>), EnvelopeError> {
        let (protected_auth, confirmation) = decode_client_auth_flight(flight)?;
        let schedule = self.schedule.take().ok_or_else(authentication_failed)?;
        let mut client_auth = self
            .endpoint
            .provider
            .open(
                &schedule.client_auth,
                &protected_auth,
                &handshake_aad(CLIENT_AUTH_AAD_DOMAIN, &self.transcript),
            )
            .map_err(crypto_error)?;
        let decoded_auth = decode_handshake_auth(&client_auth)?;
        let peer = self.endpoint.decode_peer_credential(
            decoded_auth.credential_body,
            decoded_auth.credential_signature,
        )?;
        verify_digest(
            &peer.verifying_key,
            &handshake_auth_digest(
                CLIENT_AUTH_DOMAIN,
                self.transcript,
                Some(self.server_auth_hash),
                &peer.body,
                self.endpoint.receipt,
                self.endpoint.policy_digest,
                self.binding_digest,
            ),
            &decoded_auth.handshake_signature,
        )?;
        let client_auth_hash = hash_domain(CLIENT_AUTH_DOMAIN, &client_auth);
        let final_transcript =
            final_transcript(self.transcript, self.server_auth_hash, client_auth_hash);
        let mut confirmed = self
            .endpoint
            .provider
            .open(
                &schedule.client_confirmation,
                &confirmation,
                &handshake_aad(CLIENT_CONFIRM_AAD_DOMAIN, &final_transcript),
            )
            .map_err(crypto_error)?;
        if confirmed.as_slice() != final_transcript {
            confirmed.zeroize();
            return Err(authentication_failed());
        }
        confirmed.zeroize();
        let finished = self
            .endpoint
            .provider
            .seal(
                &schedule.server_finished,
                &final_transcript,
                &handshake_aad(SERVER_FINISHED_AAD_DOMAIN, &final_transcript),
            )
            .map_err(crypto_error)?;
        let finished_flight = encode_server_finished_flight(&finished)?;
        client_auth.zeroize();
        let session = authenticated_session(
            &self.endpoint.provider,
            peer.node_principal,
            peer.route_grant_commitments,
            self.endpoint.receipt,
            self.binding_digest,
            final_transcript,
            schedule.session_master,
        )?;
        Ok((session, finished_flight))
    }
}

/// Completed profile-`0x0002` adjacency authentication.
///
/// It intentionally has no Aster record keys. Ordinary bytes must remain in
/// the authenticated Iroh QUIC carrier whose exporter completed this session.
pub struct ClassicalAuthenticatedSession {
    peer_identity: NodeId,
    peer_route_grant_commitments: Vec<[u8; 32]>,
    receipt: VerifiedSecurityProfile,
    channel_binding_digest: [u8; 32],
    session_id: [u8; 32],
    live: bool,
}

impl fmt::Debug for ClassicalAuthenticatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicalAuthenticatedSession")
            .field("peer_identity", &self.peer_identity)
            .field("semantic_version", &SEMANTIC_VERSION)
            .field("profile", &self.receipt.profile_id())
            .field("policy_generation", &self.receipt.policy_generation())
            .field("application_protection", &self.application_protection())
            .finish()
    }
}

impl ClassicalAuthenticatedSession {
    pub const fn peer_identity(&self) -> NodeId {
        self.peer_identity
    }

    pub const fn protocol_version(&self) -> u16 {
        SEMANTIC_VERSION
    }

    pub const fn semantic_version(&self) -> u16 {
        SEMANTIC_VERSION
    }

    pub fn peer_route_grant_commitments(&self) -> &[[u8; 32]] {
        &self.peer_route_grant_commitments
    }

    pub const fn verified_security_profile(&self) -> VerifiedSecurityProfile {
        self.receipt
    }

    pub const fn application_protection(&self) -> ApplicationProtection {
        ApplicationProtection::AuthenticatedCarrierRequired
    }

    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub const fn channel_binding_digest(&self) -> [u8; 32] {
        self.channel_binding_digest
    }

    /// Profile `0x0002` forbids a second Aster record layer.
    pub fn seal_frame(&mut self, _plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Err(unsupported_profile(
            "Aster record framing; use the bound authenticated carrier",
        ))
    }

    /// Profile `0x0002` forbids a second Aster record layer.
    pub fn open_frame(&mut self, _frame: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Err(unsupported_profile(
            "Aster record framing; use the bound authenticated carrier",
        ))
    }

    pub fn zeroize(&mut self) {
        self.peer_route_grant_commitments.clear();
        self.channel_binding_digest.zeroize();
        self.session_id.zeroize();
        self.live = false;
    }

    pub const fn is_zeroized(&self) -> bool {
        !self.live
    }
}

impl Drop for ClassicalAuthenticatedSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn validate_bundle_credential(bundle: &ClassicalProvisioningBundle) -> Result<(), EnvelopeError> {
    let seed = bundle.identity_seed.as_ref().ok_or_else(zeroized_service)?;
    let signing_key = derive_p256_signing_key(seed.expose())?;
    let verifying_key: [u8; P256_PUBLIC_LEN] = signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_ref()
        .try_into()
        .map_err(|_| invalid_bundle())?;
    let commitments =
        route_grant_commitments(bundle.receipt.mission_principal(), &bundle.route_grants)?;
    let local_access_commitment = local_access_commitment(
        bundle.receipt,
        bundle.policy_digest,
        bundle.node_principal,
        bundle
            .control_route_key
            .as_ref()
            .ok_or_else(zeroized_service)?,
        &bundle.route_grants,
        &bundle.content_grants,
    )?;
    let body = encode_credential_body(
        bundle.receipt,
        bundle.policy_digest,
        CredentialClaims {
            node_principal: bundle.node_principal,
            serial: bundle.serial,
            roles: bundle.roles,
            verifying_key,
            local_access_commitment,
        },
        &commitments,
    )?;
    verify_digest(
        &bundle.policy_authority_verifying_key,
        &hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &body),
        &bundle.credential_signature,
    )
}

fn derive_policy_authority_id(
    mission_principal: &NodeId,
    verifying_key: &[u8; P256_PUBLIC_LEN],
) -> NodeId {
    let mut body = Vec::with_capacity(32 + P256_PUBLIC_LEN);
    body.extend_from_slice(mission_principal);
    body.extend_from_slice(verifying_key);
    hash_domain(POLICY_AUTHORITY_ID_DOMAIN, &body)
}

fn derive_policy_digest(
    generation: u64,
    mission_principal: NodeId,
    policy_authority_id: NodeId,
) -> [u8; 32] {
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&CLASSICAL_SUITE_ID.to_be_bytes());
    body.extend_from_slice(&SEMANTIC_VERSION.to_be_bytes());
    body.extend_from_slice(&CLASSICAL_SECURITY_PROFILE_ID.to_be_bytes());
    body.extend_from_slice(&CLASSICAL_SECURITY_PROFILE_ID.to_be_bytes());
    body.extend_from_slice(&generation.to_be_bytes());
    body.extend_from_slice(&mission_principal);
    body.extend_from_slice(&policy_authority_id);
    hash_domain(PROFILE_POLICY_DOMAIN, &body)
}

fn encode_profile_receipt(
    output: &mut Vec<u8>,
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
) {
    output.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    output.extend_from_slice(&receipt.suite_id().to_be_bytes());
    output.extend_from_slice(&SEMANTIC_VERSION.to_be_bytes());
    output.extend_from_slice(&receipt.profile_id_u16().to_be_bytes());
    output.extend_from_slice(&receipt.required_profile_id().as_u16().to_be_bytes());
    output.extend_from_slice(&receipt.policy_generation().to_be_bytes());
    output.extend_from_slice(&receipt.mission_principal());
    output.extend_from_slice(&receipt.policy_authority_id());
    output.extend_from_slice(&policy_digest);
}

fn decode_profile_receipt(
    reader: &mut Reader<'_>,
) -> Result<(VerifiedSecurityProfile, [u8; 32]), EnvelopeError> {
    if reader.u16()? != PROTOCOL_VERSION
        || reader.u16()? != CLASSICAL_SUITE_ID
        || reader.u16()? != SEMANTIC_VERSION
    {
        return Err(authentication_failed());
    }
    let selected = reader.u16()?;
    let required = reader.u16()?;
    let generation = reader.u64()?;
    let mission_principal = reader.array::<32>()?;
    let policy_authority_id = reader.array::<32>()?;
    let policy_digest = reader.array::<32>()?;
    if selected != CLASSICAL_SECURITY_PROFILE_ID
        || required != selected
        || generation == 0
        || derive_policy_digest(generation, mission_principal, policy_authority_id) != policy_digest
    {
        return Err(authentication_failed());
    }
    Ok((
        VerifiedSecurityProfile::new_classical(generation, mission_principal, policy_authority_id),
        policy_digest,
    ))
}

fn validate_public_policy(
    received: VerifiedSecurityProfile,
    received_digest: [u8; 32],
    received_binding: [u8; 32],
    expected: VerifiedSecurityProfile,
    expected_digest: [u8; 32],
    expected_binding: [u8; 32],
) -> Result<(), EnvelopeError> {
    if received != expected
        || received.profile_id() != received.required_profile_id()
        || received.profile_id() != SecurityProfileId::ClassicalP256IrohQuicV1
        || received.suite_id() != CLASSICAL_SUITE_ID
        || received.policy_generation() == 0
        || received_digest != expected_digest
        || received_binding != expected_binding
    {
        return Err(authentication_failed());
    }
    Ok(())
}

fn encode_credential_body(
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    claims: CredentialClaims,
    route_grant_commitments: &[[u8; 32]],
) -> Result<Vec<u8>, EnvelopeError> {
    if receipt.profile_id() != SecurityProfileId::ClassicalP256IrohQuicV1
        || receipt.required_profile_id() != receipt.profile_id()
        || receipt.suite_id() != CLASSICAL_SUITE_ID
        || receipt.policy_generation() == 0
        || claims.serial == 0
        || claims.roles == 0
        || claims.roles & !(ROLE_RELAY | ROLE_READER | ROLE_CONTROL_AUTHORITY) != 0
        || (claims.roles & ROLE_RELAY != 0) != !route_grant_commitments.is_empty()
        || route_grant_commitments.len() > MAX_GRANTS
        || route_grant_commitments
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || P256VerifyingKey::from_sec1_bytes(&claims.verifying_key).is_err()
        || derive_policy_digest(
            receipt.policy_generation(),
            receipt.mission_principal(),
            receipt.policy_authority_id(),
        ) != policy_digest
    {
        return Err(invalid_bundle());
    }
    let mut body = Vec::new();
    encode_profile_receipt(&mut body, receipt, policy_digest);
    body.extend_from_slice(&claims.node_principal);
    body.extend_from_slice(&claims.serial.to_be_bytes());
    body.extend_from_slice(&claims.roles.to_be_bytes());
    body.extend_from_slice(&claims.verifying_key);
    body.extend_from_slice(&claims.local_access_commitment);
    body.extend_from_slice(
        &u16::try_from(route_grant_commitments.len())
            .map_err(|_| invalid_bundle())?
            .to_be_bytes(),
    );
    for commitment in route_grant_commitments {
        body.extend_from_slice(commitment);
    }
    if body.len() > MAX_CREDENTIAL_LEN {
        return Err(invalid_bundle());
    }
    Ok(body)
}

fn decode_credential(
    body: Vec<u8>,
    signature: [u8; P256_SIGNATURE_LEN],
    expected_receipt: VerifiedSecurityProfile,
    expected_policy_digest: [u8; 32],
    authority_key: &[u8; P256_PUBLIC_LEN],
) -> Result<ClassicalCredential, EnvelopeError> {
    if body.len() > MAX_CREDENTIAL_LEN {
        return Err(authentication_failed());
    }
    verify_digest(
        authority_key,
        &hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &body),
        &signature,
    )?;
    let mut reader = Reader::new(&body);
    let (receipt, policy_digest) = decode_profile_receipt(&mut reader)?;
    if receipt != expected_receipt || policy_digest != expected_policy_digest {
        return Err(authentication_failed());
    }
    let node_principal = reader.array::<32>()?;
    let serial = reader.u64()?;
    let roles = reader.u32()?;
    let verifying_key = reader.array::<P256_PUBLIC_LEN>()?;
    let _local_access_commitment = reader.array::<32>()?;
    let count = usize::from(reader.u16()?);
    if serial == 0
        || roles == 0
        || roles & !(ROLE_RELAY | ROLE_READER | ROLE_CONTROL_AUTHORITY) != 0
        || count > MAX_GRANTS
        || (roles & ROLE_RELAY != 0) != (count != 0)
        || P256VerifyingKey::from_sec1_bytes(&verifying_key).is_err()
    {
        return Err(authentication_failed());
    }
    let mut route_grant_commitments = Vec::with_capacity(count);
    for _ in 0..count {
        route_grant_commitments.push(reader.array::<32>()?);
    }
    reader.finish()?;
    if route_grant_commitments
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(authentication_failed());
    }
    Ok(ClassicalCredential {
        body,
        signature,
        node_principal,
        verifying_key,
        roles,
        route_grant_commitments,
    })
}

fn grant_context(
    scope: &Scope,
    topic: Option<&Topic>,
    epoch: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut context = Vec::new();
    push_u16_bytes(&mut context, scope.as_str().as_bytes())?;
    match topic {
        Some(topic) => {
            context.push(1);
            push_u16_bytes(&mut context, topic.as_str().as_bytes())?;
        }
        None => context.push(0),
    }
    context.extend_from_slice(&epoch.to_be_bytes());
    Ok(context)
}

fn grants_are_strictly_canonical(
    route_grants: &[RouteGrant],
    content_grants: &[ContentGrant],
) -> bool {
    route_grants.len() <= MAX_GRANTS
        && content_grants.len() <= MAX_GRANTS
        && !route_grants
            .windows(2)
            .any(|pair| (&pair[0].scope, pair[0].epoch) >= (&pair[1].scope, pair[1].epoch))
        && !content_grants.windows(2).any(|pair| {
            (&pair[0].scope, &pair[0].topic, pair[0].epoch)
                >= (&pair[1].scope, &pair[1].topic, pair[1].epoch)
        })
}

/// Commits the authority-signed credential to every local decryption key and
/// its canonical grant name. The raw keys remain local to the provisioning
/// artifact; only this domain-separated digest travels in the credential.
fn local_access_commitment(
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    node_principal: NodeId,
    control_route_key: &Secret32,
    route_grants: &[RouteGrant],
    content_grants: &[ContentGrant],
) -> Result<[u8; 32], EnvelopeError> {
    if !grants_are_strictly_canonical(route_grants, content_grants) {
        return Err(invalid_bundle());
    }
    let mut body = Vec::new();
    let result = (|| {
        encode_profile_receipt(&mut body, receipt, policy_digest);
        body.extend_from_slice(&node_principal);
        body.extend_from_slice(control_route_key.expose());
        body.extend_from_slice(
            &u16::try_from(route_grants.len())
                .map_err(|_| invalid_bundle())?
                .to_be_bytes(),
        );
        for grant in route_grants {
            push_u16_bytes(&mut body, grant.scope.as_str().as_bytes())?;
            body.extend_from_slice(&grant.epoch.to_be_bytes());
            body.extend_from_slice(grant.key.expose());
        }
        body.extend_from_slice(
            &u16::try_from(content_grants.len())
                .map_err(|_| invalid_bundle())?
                .to_be_bytes(),
        );
        for grant in content_grants {
            push_u16_bytes(&mut body, grant.scope.as_str().as_bytes())?;
            push_u16_bytes(&mut body, grant.topic.as_str().as_bytes())?;
            body.extend_from_slice(&grant.epoch.to_be_bytes());
            body.extend_from_slice(grant.key.expose());
        }
        Ok(hash_domain(LOCAL_ACCESS_COMMITMENT_DOMAIN, &body))
    })();
    body.zeroize();
    result
}

fn route_grant_commitment(
    mission_principal: NodeId,
    grant: &RouteGrant,
) -> Result<[u8; 32], EnvelopeError> {
    let mut body = Vec::new();
    body.extend_from_slice(&mission_principal);
    push_u16_bytes(&mut body, grant.scope.as_str().as_bytes())?;
    body.extend_from_slice(&grant.epoch.to_be_bytes());
    body.extend_from_slice(grant.key.expose());
    Ok(hash_domain(ROUTE_GRANT_COMMITMENT_DOMAIN, &body))
}

fn route_grant_commitments(
    mission_principal: NodeId,
    grants: &[RouteGrant],
) -> Result<Vec<[u8; 32]>, EnvelopeError> {
    let mut commitments = grants
        .iter()
        .map(|grant| route_grant_commitment(mission_principal, grant))
        .collect::<Result<Vec<_>, _>>()?;
    commitments.sort_unstable();
    commitments.dedup();
    if commitments.len() != grants.len() {
        return Err(invalid_bundle());
    }
    Ok(commitments)
}

fn content_group_id(scope: &Scope, topic: &Topic) -> [u8; 32] {
    let mut body = Vec::new();
    body.extend_from_slice(&(scope.as_str().len() as u64).to_be_bytes());
    body.extend_from_slice(scope.as_str().as_bytes());
    body.extend_from_slice(&(topic.as_str().len() as u64).to_be_bytes());
    body.extend_from_slice(topic.as_str().as_bytes());
    hash_domain(CONTENT_GROUP_DOMAIN, &body)
}

fn encode_content_aad(epoch: u64, item_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    aad.extend_from_slice(&CLASSICAL_SUITE_ID.to_be_bytes());
    aad.extend_from_slice(&CLASSICAL_SECURITY_PROFILE_ID.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(item_id);
    aad
}

fn selector_nonce(selector: &[u8; SELECTOR_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&selector[..NONCE_LEN]);
    nonce
}

fn encode_public_header(
    kind: EnvelopeKind,
    selector: [u8; SELECTOR_LEN],
    route_ciphertext_len: usize,
    content_ciphertext_len: usize,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut header = Vec::with_capacity(PUBLIC_HEADER_LEN);
    header.extend_from_slice(ENVELOPE_MAGIC);
    header.extend_from_slice(&ENVELOPE_FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header.extend_from_slice(&CLASSICAL_SUITE_ID.to_be_bytes());
    header.push(kind as u8);
    header.push(0);
    header.extend_from_slice(&selector);
    header.extend_from_slice(
        &u32::try_from(route_ciphertext_len)
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    header.extend_from_slice(
        &u64::try_from(content_ciphertext_len)
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    if header.len() != PUBLIC_HEADER_LEN {
        return Err(invalid_envelope());
    }
    Ok(header)
}

fn parse_envelope(sealed: &[u8]) -> Result<ParsedEnvelope<'_>, EnvelopeError> {
    let mut reader = Reader::new(sealed);
    if reader.take(8)? != ENVELOPE_MAGIC
        || reader.u16()? != ENVELOPE_FORMAT_VERSION
        || reader.u16()? != PROTOCOL_VERSION
        || reader.u16()? != CLASSICAL_SUITE_ID
    {
        return Err(invalid_envelope());
    }
    let kind = EnvelopeKind::decode(reader.u8()?)?;
    if reader.u8()? != 0 {
        return Err(invalid_envelope());
    }
    let selector = reader.array::<SELECTOR_LEN>()?;
    let route_len = usize::try_from(reader.u32()?).map_err(|_| invalid_envelope())?;
    let content_len = usize::try_from(reader.u64()?).map_err(|_| invalid_envelope())?;
    if reader.position() != PUBLIC_HEADER_LEN
        || !(GCM_TAG_LEN..=MAX_ROUTE_CIPHERTEXT_LEN).contains(&route_len)
        || (kind == EnvelopeKind::Data && content_len < GCM_TAG_LEN)
        || (kind != EnvelopeKind::Data && content_len != 0)
        || content_len > MAX_CORE_LEN.saturating_add(GCM_TAG_LEN)
    {
        return Err(invalid_envelope());
    }
    let route_ciphertext = reader.take(route_len)?;
    let content_ciphertext = reader.take(content_len)?;
    reader.finish()?;
    Ok(ParsedEnvelope {
        kind,
        selector,
        public_header: &sealed[..PUBLIC_HEADER_LEN],
        route_ciphertext,
        content_ciphertext,
    })
}

fn decode_data_route(
    bytes: &[u8],
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    authority_key: &[u8; P256_PUBLIC_LEN],
) -> Result<DecodedDataRoute, EnvelopeError> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != EnvelopeKind::Data as u8 {
        return Err(authentication_failed());
    }
    let credential_body = reader.u32_bytes(MAX_CREDENTIAL_LEN)?.to_vec();
    let credential_signature = reader.array::<P256_SIGNATURE_LEN>()?;
    let credential = decode_credential(
        credential_body,
        credential_signature,
        receipt,
        policy_digest,
        authority_key,
    )?;
    let item_id = reader.array::<32>()?;
    let header = decode_header(&mut reader)?;
    let content_group = reader.array::<32>()?;
    let content_nonce = reader.array::<NONCE_LEN>()?;
    let content_ciphertext_len = reader.u64()?;
    let content_ciphertext_hash = reader.array::<32>()?;
    let signed_len = reader.position();
    let item_signature = reader.array::<P256_SIGNATURE_LEN>()?;
    reader.finish()?;
    verify_digest(
        &credential.verifying_key,
        &hash_domain(ITEM_SIGNATURE_DOMAIN, &bytes[..signed_len]),
        &item_signature,
    )?;
    Ok(DecodedDataRoute {
        credential,
        item_id,
        header,
        content_group,
        content_nonce,
        content_ciphertext_len,
        content_ciphertext_hash,
    })
}

fn decode_control(
    bytes: &[u8],
    expected_kind: EnvelopeKind,
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    authority_key: &[u8; P256_PUBLIC_LEN],
) -> Result<DecodedControl, EnvelopeError> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != expected_kind as u8
        || reader.take(8)? != CONTROL_MAGIC
        || reader.u16()? != CONTROL_FORMAT
    {
        return Err(authentication_failed());
    }
    let (encoded_receipt, encoded_digest) = decode_profile_receipt(&mut reader)?;
    if encoded_receipt != receipt || encoded_digest != policy_digest {
        return Err(authentication_failed());
    }
    let credential_body = reader.u32_bytes(MAX_CREDENTIAL_LEN)?.to_vec();
    let credential_signature = reader.array::<P256_SIGNATURE_LEN>()?;
    let credential = decode_credential(
        credential_body,
        credential_signature,
        receipt,
        policy_digest,
        authority_key,
    )?;
    if credential.roles & ROLE_CONTROL_AUTHORITY == 0 {
        return Err(authentication_failed());
    }
    let sequence = reader.u64()?;
    let previous = match reader.u8()? {
        0 => None,
        1 => Some(reader.array::<32>()?),
        _ => return Err(invalid_envelope()),
    };
    if sequence == 0 || (sequence == 1) != previous.is_none() {
        return Err(invalid_envelope());
    }
    let decoded = match expected_kind {
        EnvelopeKind::Revocation => {
            let subject = reader.array::<32>()?;
            let generation = reader.u64()?;
            if generation == 0 {
                return Err(invalid_envelope());
            }
            DecodedControl::Revocation {
                signer: credential.node_principal,
                sequence,
                previous,
                subject,
                generation,
            }
        }
        EnvelopeKind::ScopeEpoch => {
            let scope = decode_scope(reader.u16_bytes(128)?)?;
            let epoch = reader.u64()?;
            if reader.u16()? != SCOPE_EPOCH_LEGACY_FORMAT {
                return Err(unsupported_profile("recipient rekey control"));
            }
            DecodedControl::ScopeEpoch {
                signer: credential.node_principal,
                sequence,
                previous,
                scope,
                epoch,
            }
        }
        EnvelopeKind::Data => return Err(authentication_failed()),
    };
    let signed_len = reader.position();
    let signature = reader.array::<P256_SIGNATURE_LEN>()?;
    reader.finish()?;
    verify_digest(
        &credential.verifying_key,
        &hash_domain(CONTROL_SIGNATURE_DOMAIN, &bytes[..signed_len]),
        &signature,
    )?;
    Ok(decoded)
}

fn handshake_prefix(kind: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HANDSHAKE_MAGIC);
    bytes.extend_from_slice(&HANDSHAKE_FRAMING_VERSION.to_be_bytes());
    bytes.extend_from_slice(&HANDSHAKE_PROFILE_ID.to_be_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes
}

fn decode_handshake_prefix(
    reader: &mut Reader<'_>,
    expected_kind: u8,
) -> Result<(), EnvelopeError> {
    if reader.take(8)? != HANDSHAKE_MAGIC
        || reader.u16()? != HANDSHAKE_FRAMING_VERSION
        || reader.u16()? != HANDSHAKE_PROFILE_ID
        || reader.u8()? != expected_kind
        || reader.u8()? != 0
    {
        return Err(authentication_failed());
    }
    Ok(())
}

fn encode_client_public(public: &ClientPublic) -> Result<Vec<u8>, EnvelopeError> {
    if public.p256_ephemeral_public.len() != P256_PUBLIC_LEN
        || p256::PublicKey::from_sec1_bytes(&public.p256_ephemeral_public).is_err()
    {
        return Err(authentication_failed());
    }
    let mut bytes = handshake_prefix(1);
    encode_profile_receipt(&mut bytes, public.receipt, public.policy_digest);
    bytes.extend_from_slice(&public.channel_binding_digest);
    bytes.extend_from_slice(&public.nonce);
    push_u16_bytes(&mut bytes, &public.p256_ephemeral_public)?;
    Ok(bytes)
}

fn encode_server_public(public: &ServerPublic) -> Result<Vec<u8>, EnvelopeError> {
    if public.p256_ephemeral_public.len() != P256_PUBLIC_LEN
        || p256::PublicKey::from_sec1_bytes(&public.p256_ephemeral_public).is_err()
    {
        return Err(authentication_failed());
    }
    let mut bytes = handshake_prefix(2);
    encode_profile_receipt(&mut bytes, public.receipt, public.policy_digest);
    bytes.extend_from_slice(&public.channel_binding_digest);
    bytes.extend_from_slice(&public.nonce);
    push_u16_bytes(&mut bytes, &public.p256_ephemeral_public)?;
    Ok(bytes)
}

fn encode_aead(output: &mut Vec<u8>, sealed: &AeadCiphertext) -> Result<(), EnvelopeError> {
    output.extend_from_slice(&sealed.nonce);
    push_u32_bytes(output, &sealed.ciphertext)
}

fn decode_aead(reader: &mut Reader<'_>, maximum: usize) -> Result<AeadCiphertext, EnvelopeError> {
    let nonce = reader.array::<NONCE_LEN>()?;
    let ciphertext = reader.u32_bytes(maximum)?.to_vec();
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(authentication_failed());
    }
    Ok(AeadCiphertext { nonce, ciphertext })
}

fn encode_client_flight(
    public: &[u8],
    mission_proof: &AeadCiphertext,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut bytes = public.to_vec();
    encode_aead(&mut bytes, mission_proof)?;
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    Ok(bytes)
}

fn decode_client_flight(
    bytes: &[u8],
) -> Result<(ClientPublic, Vec<u8>, AeadCiphertext), EnvelopeError> {
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    decode_handshake_prefix(&mut reader, 1)?;
    let (receipt, policy_digest) = decode_profile_receipt(&mut reader)?;
    let channel_binding_digest = reader.array::<32>()?;
    let nonce = reader.array::<32>()?;
    let p256_ephemeral_public = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let public_end = reader.position();
    let mission_proof = decode_aead(&mut reader, 1024)?;
    reader.finish()?;
    let public = ClientPublic {
        receipt,
        policy_digest,
        channel_binding_digest,
        nonce,
        p256_ephemeral_public,
    };
    let canonical = encode_client_public(&public)?;
    if canonical != bytes[..public_end] {
        return Err(authentication_failed());
    }
    Ok((public, canonical, mission_proof))
}

fn encode_server_flight(
    public: &[u8],
    protected_auth: &AeadCiphertext,
    confirmation: &AeadCiphertext,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut bytes = public.to_vec();
    encode_aead(&mut bytes, protected_auth)?;
    encode_aead(&mut bytes, confirmation)?;
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    Ok(bytes)
}

fn decode_server_flight(
    bytes: &[u8],
) -> Result<(ServerPublic, Vec<u8>, AeadCiphertext, AeadCiphertext), EnvelopeError> {
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    decode_handshake_prefix(&mut reader, 2)?;
    let (receipt, policy_digest) = decode_profile_receipt(&mut reader)?;
    let channel_binding_digest = reader.array::<32>()?;
    let nonce = reader.array::<32>()?;
    let p256_ephemeral_public = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let public_end = reader.position();
    let protected_auth = decode_aead(&mut reader, MAX_CREDENTIAL_LEN + 512)?;
    let confirmation = decode_aead(&mut reader, 128)?;
    reader.finish()?;
    let public = ServerPublic {
        receipt,
        policy_digest,
        channel_binding_digest,
        nonce,
        p256_ephemeral_public,
    };
    let canonical = encode_server_public(&public)?;
    if canonical != bytes[..public_end] {
        return Err(authentication_failed());
    }
    Ok((public, canonical, protected_auth, confirmation))
}

fn encode_client_auth_flight(
    protected_auth: &AeadCiphertext,
    confirmation: &AeadCiphertext,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut bytes = handshake_prefix(3);
    encode_aead(&mut bytes, protected_auth)?;
    encode_aead(&mut bytes, confirmation)?;
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    Ok(bytes)
}

fn decode_client_auth_flight(
    bytes: &[u8],
) -> Result<(AeadCiphertext, AeadCiphertext), EnvelopeError> {
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    decode_handshake_prefix(&mut reader, 3)?;
    let protected_auth = decode_aead(&mut reader, MAX_CREDENTIAL_LEN + 512)?;
    let confirmation = decode_aead(&mut reader, 128)?;
    reader.finish()?;
    Ok((protected_auth, confirmation))
}

fn encode_server_finished_flight(finished: &AeadCiphertext) -> Result<Vec<u8>, EnvelopeError> {
    let mut bytes = handshake_prefix(4);
    encode_aead(&mut bytes, finished)?;
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    Ok(bytes)
}

fn decode_server_finished_flight(bytes: &[u8]) -> Result<AeadCiphertext, EnvelopeError> {
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    decode_handshake_prefix(&mut reader, 4)?;
    let finished = decode_aead(&mut reader, 128)?;
    reader.finish()?;
    Ok(finished)
}

fn encode_handshake_auth(
    credential_body: &[u8],
    credential_signature: &[u8; P256_SIGNATURE_LEN],
    handshake_signature: &[u8; P256_SIGNATURE_LEN],
) -> Result<Vec<u8>, EnvelopeError> {
    let mut bytes = Vec::new();
    push_u32_bytes(&mut bytes, credential_body)?;
    bytes.extend_from_slice(credential_signature);
    bytes.extend_from_slice(handshake_signature);
    Ok(bytes)
}

struct DecodedHandshakeAuth {
    credential_body: Vec<u8>,
    credential_signature: [u8; P256_SIGNATURE_LEN],
    handshake_signature: [u8; P256_SIGNATURE_LEN],
}

fn decode_handshake_auth(bytes: &[u8]) -> Result<DecodedHandshakeAuth, EnvelopeError> {
    let mut reader = Reader::new(bytes);
    let body = reader.u32_bytes(MAX_CREDENTIAL_LEN)?.to_vec();
    let credential_signature = reader.array::<P256_SIGNATURE_LEN>()?;
    let handshake_signature = reader.array::<P256_SIGNATURE_LEN>()?;
    reader.finish()?;
    Ok(DecodedHandshakeAuth {
        credential_body: body,
        credential_signature,
        handshake_signature,
    })
}

fn handshake_transcript(client_flight: &[u8], server_public: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(client_flight.len() as u64).to_be_bytes());
    bytes.extend_from_slice(client_flight);
    bytes.extend_from_slice(&(server_public.len() as u64).to_be_bytes());
    bytes.extend_from_slice(server_public);
    hash_domain(HANDSHAKE_TRANSCRIPT_DOMAIN, &bytes)
}

fn final_transcript(
    public_transcript: [u8; 32],
    server_auth_hash: [u8; 32],
    client_auth_hash: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&public_transcript);
    bytes.extend_from_slice(&server_auth_hash);
    bytes.extend_from_slice(&client_auth_hash);
    hash_domain(FINAL_TRANSCRIPT_DOMAIN, &bytes)
}

fn handshake_auth_digest(
    domain: &[u8],
    transcript: [u8; 32],
    preceding_auth_hash: Option<[u8; 32]>,
    credential_body: &[u8],
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    binding_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&transcript);
    match preceding_auth_hash {
        Some(hash) => {
            bytes.push(1);
            bytes.extend_from_slice(&hash);
        }
        None => bytes.push(0),
    }
    encode_profile_receipt(&mut bytes, receipt, policy_digest);
    bytes.extend_from_slice(&binding_digest);
    bytes.extend_from_slice(&hash_domain(
        b"aster/classical/credential-context/v1",
        credential_body,
    ));
    hash_domain(domain, &bytes)
}

fn handshake_aad(domain: &[u8], transcript: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(domain);
    aad.extend_from_slice(transcript);
    aad
}

fn derive_handshake_schedule(
    provider: &ClassicalCryptoProvider,
    shared: &Secret32,
    receipt: VerifiedSecurityProfile,
    policy_digest: [u8; 32],
    binding_digest: [u8; 32],
    transcript: [u8; 32],
) -> Result<HandshakeSchedule, EnvelopeError> {
    let mut context = Vec::new();
    encode_profile_receipt(&mut context, receipt, policy_digest);
    context.extend_from_slice(&binding_digest);
    context.extend_from_slice(&transcript);
    let master = provider
        .derive_secret(
            shared.expose(),
            Some(&transcript),
            HANDSHAKE_SCHEDULE_LABEL,
            &context,
        )
        .map_err(crypto_error)?;
    let derive = |label: &[u8]| {
        provider
            .derive_secret(master.expose(), Some(&policy_digest), label, &context)
            .map_err(crypto_error)
    };
    Ok(HandshakeSchedule {
        server_auth: derive(b"server-auth")?,
        server_confirmation: derive(b"server-confirmation")?,
        client_auth: derive(b"client-auth")?,
        client_confirmation: derive(b"client-confirmation")?,
        server_finished: derive(b"server-finished")?,
        session_master: derive(b"session-master")?,
    })
}

fn authenticated_session(
    provider: &ClassicalCryptoProvider,
    peer_identity: NodeId,
    peer_route_grant_commitments: Vec<[u8; 32]>,
    receipt: VerifiedSecurityProfile,
    binding_digest: [u8; 32],
    final_transcript: [u8; 32],
    session_master: Secret32,
) -> Result<ClassicalAuthenticatedSession, EnvelopeError> {
    let mut context = Vec::new();
    context.extend_from_slice(&final_transcript);
    context.extend_from_slice(&binding_digest);
    context.extend_from_slice(&receipt.profile_id_u16().to_be_bytes());
    context.extend_from_slice(&receipt.policy_generation().to_be_bytes());
    let session_receipt = provider
        .derive_secret(
            session_master.expose(),
            Some(&final_transcript),
            b"authenticated-carrier-session-id",
            &context,
        )
        .map_err(crypto_error)?;
    let session_id = hash_domain(
        b"aster/classical/authenticated-carrier-session/v1",
        session_receipt.expose(),
    );
    Ok(ClassicalAuthenticatedSession {
        peer_identity,
        peer_route_grant_commitments,
        receipt,
        channel_binding_digest: binding_digest,
        session_id,
        live: true,
    })
}

fn audited_ecdh(
    provider: &ClassicalCryptoProvider,
    secret: &P256SecretKey,
    peer_public: &[u8],
) -> Result<Secret32, EnvelopeError> {
    provider
        .ecdh_agree(secret, peer_public)
        .map_err(crypto_error)
}

fn derive_material<const N: usize>(
    input: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; N], EnvelopeError> {
    let mut info = Vec::new();
    info.extend_from_slice(&(label.len() as u64).to_be_bytes());
    info.extend_from_slice(label);
    info.extend_from_slice(&(context.len() as u64).to_be_bytes());
    info.extend_from_slice(context);
    let hkdf = Hkdf::<Sha256>::new(Some(KDF_SALT), input);
    let mut output = [0u8; N];
    hkdf.expand(&info, &mut output)
        .map_err(|_| EnvelopeError("classical profile key derivation failed".into()))?;
    Ok(output)
}

fn derive_item_secret(
    input: &[u8; 32],
    label: &[u8],
    context: &[u8],
) -> Result<Secret32, EnvelopeError> {
    Ok(Secret32::new(derive_material::<32>(input, label, context)?))
}

fn derive_p256_signing_key(seed: &[u8; 32]) -> Result<P256SigningKey, EnvelopeError> {
    for counter in 0u16..=255 {
        let mut candidate =
            derive_material::<32>(seed, b"ecdsa-p256-signing-scalar", &counter.to_be_bytes())?;
        let mut field = FieldBytes::default();
        field.as_mut_slice().copy_from_slice(&candidate);
        candidate.zeroize();
        let result = P256SigningKey::from_bytes(&field);
        field.as_mut_slice().zeroize();
        if let Ok(key) = result {
            return Ok(key);
        }
    }
    Err(EnvelopeError(
        "failed to derive a valid classical identity".into(),
    ))
}

fn sign_digest(
    key: &P256SigningKey,
    digest: &[u8; 32],
) -> Result<[u8; P256_SIGNATURE_LEN], EnvelopeError> {
    #[cfg(test)]
    primitive_audit::P256_SIGNATURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let signature: P256Signature = P256Signer::try_sign(key, digest)
        .map_err(|_| EnvelopeError("classical profile signature failed".into()))?;
    Ok(signature.to_bytes().into())
}

fn verify_digest(
    key: &[u8; P256_PUBLIC_LEN],
    digest: &[u8; 32],
    signature: &[u8; P256_SIGNATURE_LEN],
) -> Result<(), EnvelopeError> {
    #[cfg(test)]
    primitive_audit::P256_VERIFICATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let key = P256VerifyingKey::from_sec1_bytes(key).map_err(|_| authentication_failed())?;
    let signature = P256Signature::from_slice(signature).map_err(|_| authentication_failed())?;
    P256Verifier::verify(&key, digest, &signature).map_err(|_| authentication_failed())
}

fn hash_domain(domain: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((input.len() as u64).to_be_bytes());
    hasher.update(input);
    hasher.finalize().into()
}

fn encode_header(output: &mut Vec<u8>, header: &EnvelopeHeader) -> Result<(), EnvelopeError> {
    output.push(header.class as u8);
    output.push(header.priority as u8);
    push_u16_bytes(output, header.topic.as_str().as_bytes())?;
    push_u16_bytes(output, header.scope.as_str().as_bytes())?;
    output.extend_from_slice(&header.stamp.dot.publisher);
    output.extend_from_slice(&header.stamp.dot.counter.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(header.stamp.context.iter().len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    for (publisher, counter) in header.stamp.context.iter() {
        output.extend_from_slice(publisher);
        output.extend_from_slice(&counter.to_be_bytes());
    }
    push_optional_u64(output, header.event_sequence);
    push_u32_bytes(output, &header.logical_key)?;
    match header.blob_route {
        Some(route) => {
            output.push(1);
            output.extend_from_slice(route.blob_id().as_bytes());
            output.extend_from_slice(&route.chunk_count().to_be_bytes());
            output.extend_from_slice(route.root());
        }
        None => output.push(0),
    }
    push_optional_u64(output, header.ttl_ms);
    output.extend_from_slice(&header.content_len.to_be_bytes());
    output.push(u8::from(header.tombstone));
    output.extend_from_slice(&header.key_epoch.to_be_bytes());
    Ok(())
}

fn validate_header_for_seal(
    header: &EnvelopeHeader,
    payload: &[u8],
    identity: &NodeId,
) -> Result<(), EnvelopeError> {
    if header.class != DataClass::Event
        || header.blob_route.is_some()
        || &header.stamp.dot.publisher != identity
        || header.stamp.dot.counter == 0
        || header.content_len != payload.len() as u64
        || header.logical_key.len() > MAX_LOGICAL_KEY_LEN
        || (header.tombstone && !payload.is_empty())
        || header.event_sequence.is_none()
        || header.event_sequence == Some(0)
        || header.stamp.context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
        || header
            .stamp
            .context
            .iter()
            .any(|(_, counter)| *counter == 0)
        || header.stamp.context.counter(identity) >= header.stamp.dot.counter
    {
        return Err(EnvelopeError("invalid authenticated Event metadata".into()));
    }
    Ok(())
}

fn decode_core(bytes: &[u8]) -> Result<(EnvelopeHeader, Vec<u8>), EnvelopeError> {
    let mut reader = Reader::new(bytes);
    let header = decode_header(&mut reader)?;
    let payload_len = usize::try_from(reader.u64()?).map_err(|_| invalid_envelope())?;
    let payload = reader.take(payload_len)?.to_vec();
    reader.finish()?;
    if payload.len() as u64 != header.content_len {
        return Err(authentication_failed());
    }
    Ok((header, payload))
}

fn decode_header(reader: &mut Reader<'_>) -> Result<EnvelopeHeader, EnvelopeError> {
    let class = match reader.u8()? {
        0 => DataClass::State,
        1 => DataClass::Event,
        2 => DataClass::Record,
        3 => DataClass::Blob,
        _ => return Err(invalid_envelope()),
    };
    let priority = Priority::from_wire(reader.u8()?).ok_or_else(invalid_envelope)?;
    let topic = decode_topic(reader.u16_bytes(128)?)?;
    let scope = decode_scope(reader.u16_bytes(128)?)?;
    let publisher = reader.array::<32>()?;
    let counter = reader.u64()?;
    if counter == 0 {
        return Err(invalid_envelope());
    }
    let context_len = usize::try_from(reader.u32()?).map_err(|_| invalid_envelope())?;
    if context_len > MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(invalid_envelope());
    }
    let mut context = VersionVector::default();
    let mut previous = None;
    for _ in 0..context_len {
        let context_publisher = reader.array::<32>()?;
        let context_counter = reader.u64()?;
        if context_counter == 0 || previous.is_some_and(|value| value >= context_publisher) {
            return Err(invalid_envelope());
        }
        previous = Some(context_publisher);
        context.observe(Dot {
            publisher: context_publisher,
            counter: context_counter,
        });
    }
    let event_sequence = reader.optional_u64()?;
    let logical_key = reader.u32_bytes(MAX_LOGICAL_KEY_LEN)?.to_vec();
    let blob_route = match reader.u8()? {
        0 => None,
        1 => Some(BlobRouteCommitment::from_authenticated_header(
            BlobId::from_bytes(reader.array::<32>()?),
            reader.u64()?,
            reader.array::<32>()?,
        )),
        _ => return Err(invalid_envelope()),
    };
    let ttl_ms = reader.optional_u64()?;
    let content_len = reader.u64()?;
    let tombstone = reader.boolean()?;
    let key_epoch = reader.u64()?;
    if class != DataClass::Event
        || event_sequence.is_none()
        || event_sequence == Some(0)
        || blob_route.is_some()
        || (tombstone && content_len != 0)
        || context.counter(&publisher) >= counter
    {
        return Err(unsupported_profile(
            "non-Event or mutable source representation",
        ));
    }
    Ok(EnvelopeHeader {
        class,
        topic,
        scope,
        priority,
        stamp: CausalStamp {
            dot: Dot { publisher, counter },
            context,
        },
        event_sequence,
        logical_key,
        blob_route,
        ttl_ms,
        content_len,
        tombstone,
        key_epoch,
    })
}

fn decode_topic(bytes: &[u8]) -> Result<Topic, EnvelopeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_envelope())?;
    Topic::new(text.to_owned()).map_err(|_| invalid_envelope())
}

fn decode_scope(bytes: &[u8]) -> Result<Scope, EnvelopeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_envelope())?;
    Scope::new(text.to_owned()).map_err(|_| invalid_envelope())
}

fn push_u16_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn push_u32_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn push_u64_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn push_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self.offset.checked_add(len).ok_or_else(invalid_envelope)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(invalid_envelope)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        self.take(N)?.try_into().map_err(|_| invalid_envelope())
    }

    fn u8(&mut self) -> Result<u8, EnvelopeError> {
        self.take(1)?.first().copied().ok_or_else(invalid_envelope)
    }

    fn u16(&mut self) -> Result<u16, EnvelopeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, EnvelopeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, EnvelopeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn boolean(&mut self) -> Result<bool, EnvelopeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid_envelope()),
        }
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, EnvelopeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(invalid_envelope()),
        }
    }

    fn u16_bytes(&mut self, maximum: usize) -> Result<&'a [u8], EnvelopeError> {
        let len = usize::from(self.u16()?);
        if len > maximum {
            return Err(invalid_envelope());
        }
        self.take(len)
    }

    fn u32_bytes(&mut self, maximum: usize) -> Result<&'a [u8], EnvelopeError> {
        let len = usize::try_from(self.u32()?).map_err(|_| invalid_envelope())?;
        if len > maximum {
            return Err(invalid_envelope());
        }
        self.take(len)
    }

    fn finish(self) -> Result<(), EnvelopeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid_envelope())
        }
    }
}

fn invalid_bundle() -> EnvelopeError {
    EnvelopeError("invalid classical provisioning bundle".into())
}

fn invalid_envelope() -> EnvelopeError {
    EnvelopeError("invalid classical profile representation".into())
}

fn authentication_failed() -> EnvelopeError {
    EnvelopeError("classical profile authentication failed".into())
}

fn zeroized_service() -> EnvelopeError {
    EnvelopeError("classical profile key material has been zeroized".into())
}

fn unsupported_profile(feature: &str) -> EnvelopeError {
    EnvelopeError(format!(
        "{feature} is unsupported by security profile {}",
        SecurityProfile::CLASSICAL_P256_IROH_QUIC_V1.receipt_label()
    ))
}

fn crypto_error(error: super::CryptoError) -> EnvelopeError {
    EnvelopeError(format!(
        "classical profile cryptographic operation failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            ProvisioningAccess, ReferenceProvisioner, ReferenceSessionInitiator,
            ReferenceSessionResponder,
        },
        source_event::EventContentVerification,
    };
    use std::sync::atomic::Ordering;

    fn scope() -> Scope {
        Scope::new("test/classical-profile").expect("scope")
    }

    fn topic() -> Topic {
        Topic::new("events").expect("topic")
    }

    fn member() -> ClassicalProvisioningAccess {
        ClassicalProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("member")
    }

    fn relay() -> ClassicalProvisioningAccess {
        ClassicalProvisioningAccess::relay(scope(), vec![1]).expect("relay")
    }

    fn event_header(publisher: NodeId, payload: &[u8]) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Event,
            topic: topic(),
            scope: scope(),
            priority: Priority::Routine,
            stamp: CausalStamp {
                dot: Dot {
                    publisher,
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"event-1".to_vec(),
            blob_route: None,
            ttl_ms: None,
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        }
    }

    struct BundleAccessOffsets {
        control_key: usize,
        route_rows: Vec<(usize, usize)>,
        route_keys: Vec<usize>,
        content_rows: Vec<(usize, usize)>,
        content_keys: Vec<usize>,
    }

    fn bundle_access_offsets(bytes: &[u8]) -> BundleAccessOffsets {
        let checksum_start = bytes.len().checked_sub(32).expect("checksum");
        let mut reader = Reader::new(&bytes[..checksum_start]);
        // Fixed ASTRPB04 prefix through the authority credential signature.
        reader.take(297).expect("fixed bundle prefix");
        let control_key = reader.position();
        reader.take(32).expect("control route key");

        let route_count = usize::from(reader.u16().expect("route count"));
        let mut route_rows = Vec::with_capacity(route_count);
        let mut route_keys = Vec::with_capacity(route_count);
        for _ in 0..route_count {
            let start = reader.position();
            reader.u16_bytes(128).expect("route scope");
            reader.u64().expect("route epoch");
            route_keys.push(reader.position());
            reader.take(32).expect("route key");
            route_rows.push((start, reader.position()));
        }

        let content_count = usize::from(reader.u16().expect("content count"));
        let mut content_rows = Vec::with_capacity(content_count);
        let mut content_keys = Vec::with_capacity(content_count);
        for _ in 0..content_count {
            let start = reader.position();
            reader.u16_bytes(128).expect("content scope");
            reader.u16_bytes(128).expect("content topic");
            reader.u64().expect("content epoch");
            content_keys.push(reader.position());
            reader.take(32).expect("content key");
            content_rows.push((start, reader.position()));
        }
        reader.finish().expect("complete bundle body");
        BundleAccessOffsets {
            control_key,
            route_rows,
            route_keys,
            content_rows,
            content_keys,
        }
    }

    fn replace_bundle_checksum(bytes: &mut [u8]) {
        let checksum_start = bytes.len().checked_sub(32).expect("checksum");
        let checksum = hash_domain(BUNDLE_CHECKSUM_DOMAIN, &bytes[..checksum_start]);
        bytes[checksum_start..].copy_from_slice(&checksum);
    }

    fn swap_equal_rows(bytes: &mut [u8], rows: &[(usize, usize)]) {
        assert!(rows.len() >= 2, "two canonical rows required");
        let (first_start, first_end) = rows[0];
        let (second_start, second_end) = rows[1];
        assert_eq!(first_end - first_start, second_end - second_start);
        let first = bytes[first_start..first_end].to_vec();
        let second = bytes[second_start..second_end].to_vec();
        bytes[first_start..first_end].copy_from_slice(&second);
        bytes[second_start..second_end].copy_from_slice(&first);
    }

    #[test]
    fn ast_rpb04_authenticates_exact_policy_and_suite_independent_principals() {
        primitive_audit::reset();
        let seed = [0x41; 32];
        let mut provisioner = ClassicalProvisioner::from_seed(seed, 7).expect("provisioner");
        let bundle = provisioner.issue_node(9, &[member()]).expect("bundle");
        let expected_node = derive_material::<32>(&seed, NODE_PRINCIPAL_LABEL, &9u64.to_be_bytes())
            .expect("node principal");
        assert_eq!(bundle.node_principal(), expected_node);
        let receipt = bundle.verified_security_profile();
        assert_eq!(receipt.profile_id_u16(), CLASSICAL_SECURITY_PROFILE_ID);
        assert_eq!(receipt.required_profile_id(), receipt.profile_id());
        assert_eq!(receipt.policy_generation(), 7);
        assert_eq!(
            receipt.mission_principal(),
            provisioner.verified_security_profile().mission_principal()
        );
        assert_eq!(receipt.profile().maximum_semantic_version(), 1);
        assert_eq!(
            receipt.profile().receipt_label(),
            "classical-p256-iroh-quic-v1"
        );

        let encoded = bundle.to_bytes().expect("encode");
        assert_eq!(&encoded[..8], BUNDLE_MAGIC);
        assert!(
            encoded.len() < 4096,
            "classical credential must not carry PQ-sized fields"
        );
        let decoded = ClassicalProvisioningBundle::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded.node_principal(), expected_node);
        assert_eq!(decoded.to_bytes().expect("reencode"), encoded);

        let mut changed_generation = encoded.clone();
        // Magic + bundle/protocol/suite/semantic/profile/required.
        changed_generation[20..28].copy_from_slice(&8u64.to_be_bytes());
        let checksum_start = changed_generation.len() - 32;
        let checksum = hash_domain(
            BUNDLE_CHECKSUM_DOMAIN,
            &changed_generation[..checksum_start],
        );
        changed_generation[checksum_start..].copy_from_slice(&checksum);
        assert!(ClassicalProvisioningBundle::from_bytes(&changed_generation).is_err());

        assert_eq!(
            primitive_audit::ML_DSA_OPERATIONS.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            primitive_audit::ML_KEM_OPERATIONS.load(Ordering::Relaxed),
            0
        );
        assert!(primitive_audit::P256_SIGNATURES.load(Ordering::Relaxed) > 0);
        assert!(primitive_audit::P256_VERIFICATIONS.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn ast_rpb04_signed_local_access_commitment_rejects_key_substitution() {
        let mut provisioner = ClassicalProvisioner::from_seed([0x51; 32], 12).expect("authority");
        let access =
            ClassicalProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("access");
        let encoded = provisioner
            .issue_node(1, &[access])
            .expect("bundle")
            .to_bytes()
            .expect("encode");
        let offsets = bundle_access_offsets(&encoded);
        assert_eq!(offsets.route_keys.len(), 1);
        assert_eq!(offsets.content_keys.len(), 1);

        let mut changed_control_key = encoded.clone();
        changed_control_key[offsets.control_key] ^= 1;
        replace_bundle_checksum(&mut changed_control_key);
        assert!(ClassicalProvisioningBundle::from_bytes(&changed_control_key).is_err());

        let mut changed_content_key = encoded.clone();
        changed_content_key[offsets.content_keys[0]] ^= 1;
        replace_bundle_checksum(&mut changed_content_key);
        assert!(ClassicalProvisioningBundle::from_bytes(&changed_content_key).is_err());

        let mut changed_route_key = encoded;
        changed_route_key[offsets.route_keys[0]] ^= 1;
        replace_bundle_checksum(&mut changed_route_key);
        assert!(ClassicalProvisioningBundle::from_bytes(&changed_route_key).is_err());
    }

    #[test]
    fn ast_rpb04_rejects_noncanonical_grant_row_ordering() {
        let mut provisioner = ClassicalProvisioner::from_seed([0x52; 32], 13).expect("authority");
        let access = ClassicalProvisioningAccess::member(scope(), vec![1, 2], vec![topic()])
            .expect("access");
        let encoded = provisioner
            .issue_node(1, &[access])
            .expect("bundle")
            .to_bytes()
            .expect("encode");
        let offsets = bundle_access_offsets(&encoded);
        assert_eq!(offsets.route_rows.len(), 2);
        assert_eq!(offsets.content_rows.len(), 2);

        let mut reordered_routes = encoded.clone();
        swap_equal_rows(&mut reordered_routes, &offsets.route_rows);
        replace_bundle_checksum(&mut reordered_routes);
        assert!(ClassicalProvisioningBundle::from_bytes(&reordered_routes).is_err());

        let mut reordered_content = encoded;
        swap_equal_rows(&mut reordered_content, &offsets.content_rows);
        replace_bundle_checksum(&mut reordered_content);
        assert!(ClassicalProvisioningBundle::from_bytes(&reordered_content).is_err());
    }

    #[test]
    fn legacy_bundle_and_default_profile_remain_unchanged() {
        assert_eq!(
            SecurityProfile::default().id(),
            SecurityProfileId::HybridPqAsterRecordV1
        );
        assert_eq!(
            SecurityProfile::default().receipt_label(),
            "hybrid-pq-aster-record-v1"
        );
        let access = ProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x42; 32]).expect("hybrid");
        let bundle = provisioner.issue_node(1, &[access]).expect("bundle");
        let encoded = bundle.to_bytes().expect("encode");
        assert_eq!(&encoded[..8], b"ASTRPB03");
        let decoded =
            super::super::ProfileProvisioningBundle::from_bytes(&encoded).expect("facade parse");
        assert_eq!(
            decoded.profile(),
            SecurityProfile::HYBRID_PQ_ASTER_RECORD_V1
        );
        assert_eq!(decoded.to_bytes().expect("reencode"), encoded);
    }

    #[test]
    fn classical_event_and_chained_control_round_trip_and_unsupported_forms_fail() {
        let mut provisioner = ClassicalProvisioner::from_seed([0x43; 32], 11).expect("authority");
        let publisher_bundle = provisioner.issue_node(1, &[member()]).expect("publisher");
        let reader_bundle = provisioner.issue_node(2, &[member()]).expect("reader");
        let relay_bundle = provisioner.issue_node(3, &[relay()]).expect("relay");
        let authority_bundle = provisioner
            .issue_control_authority(4, &[member()])
            .expect("control authority");
        let mut publisher = ClassicalEnvelopeSealer::open(publisher_bundle).expect("open");
        let mut reader = ClassicalEnvelopeSealer::open(reader_bundle).expect("open");
        let mut relay = ClassicalEnvelopeSealer::open(relay_bundle).expect("open");
        let mut authority = ClassicalEnvelopeSealer::open(authority_bundle).expect("open");

        let payload = b"carrier-bound classical Event";
        let header = event_header(publisher.identity(), payload);
        let sealed = publisher.seal_event(&header, payload).expect("seal Event");
        let route = reader
            .verify_event_from(publisher.identity(), &sealed.bytes)
            .expect("route");
        assert!(reader.is_current_event_route_lineage(
            route.scope(),
            route.key_epoch(),
            route.route_lineage(),
        ));
        match reader
            .verify_event_content(route, &sealed.bytes)
            .expect("content")
        {
            EventContentVerification::ContentVerified {
                event,
                payload: opened,
            } => {
                assert_eq!(opened, payload);
                event
                    .verify_exact_payload(payload)
                    .expect("payload binding");
            }
            EventContentVerification::RouteOnly(_) => panic!("reader has content grant"),
        }
        let route_only = relay.verify_event(&sealed.bytes).expect("relay route");
        assert!(matches!(
            relay
                .verify_event_content(route_only, &sealed.bytes)
                .expect("route only"),
            EventContentVerification::RouteOnly(_)
        ));

        let revocation = authority
            .seal_revocation_chained(publisher.identity(), 2, 1, None)
            .expect("revocation");
        assert!(matches!(
            reader
                .inspect_control(&revocation)
                .expect("inspect revocation"),
            VerifiedControl::Revocation(Revocation { generation: 2, .. })
        ));
        let previous = [0x77; 32];
        let epoch = authority
            .seal_scope_epoch_chained(&scope(), 1, 2, Some(previous))
            .expect("epoch");
        assert!(matches!(
            reader.inspect_control(&epoch).expect("inspect epoch"),
            VerifiedControl::ScopeEpoch(ScopeEpoch {
                control_sequence: 2,
                previous_control: Some(value),
                ..
            }) if value == previous
        ));

        let mut wrong_class = header.clone();
        wrong_class.class = DataClass::State;
        wrong_class.event_sequence = None;
        assert!(
            publisher
                .seal(SealRequest {
                    header: &wrong_class,
                    payload
                })
                .is_err()
        );
        assert!(publisher.unsupported_batch().is_err());
        assert!(publisher.unsupported_bridge().is_err());
        assert!(publisher.unsupported_blob().is_err());
        assert!(publisher.unsupported_rekey().is_err());
    }

    #[test]
    fn four_flights_bind_exact_policy_and_iroh_exporter_without_pq_or_record_layer() {
        primitive_audit::reset();
        let mut provisioner = ClassicalProvisioner::from_seed([0x44; 32], 19).expect("authority");
        let initiator_bundle = provisioner.issue_node(1, &[member()]).expect("initiator");
        let initiator_identity = initiator_bundle.node_principal();
        let responder_bundle = provisioner.issue_node(2, &[member()]).expect("responder");
        let responder_identity = responder_bundle.node_principal();
        let exporter = b"iroh TLS exporter for exact QUIC connection".to_vec();
        let (initiator, flight1) = ClassicalSessionInitiator::start(
            initiator_bundle,
            AuthenticatedChannelBinding::new(exporter.clone()).expect("binding"),
        )
        .expect("start");
        let responder = ClassicalSessionResponder::open(
            responder_bundle,
            AuthenticatedChannelBinding::new(exporter).expect("binding"),
        )
        .expect("responder");
        let (pending, flight2) = responder.receive_client(&flight1).expect("flight 1");
        let (awaiting, flight3) = initiator.receive_server(&flight2).expect("flight 2");
        let (mut responder_session, flight4) =
            pending.receive_client_auth(&flight3).expect("flight 3");
        let mut initiator_session = awaiting.receive_finished(&flight4).expect("flight 4");
        assert_eq!(initiator_session.peer_identity(), responder_identity);
        assert_eq!(responder_session.peer_identity(), initiator_identity);
        assert_eq!(
            initiator_session.session_id(),
            responder_session.session_id()
        );
        assert_eq!(initiator_session.semantic_version(), 1);
        assert_eq!(
            initiator_session
                .verified_security_profile()
                .policy_generation(),
            19
        );
        assert_eq!(
            initiator_session.application_protection(),
            ApplicationProtection::AuthenticatedCarrierRequired
        );
        assert!(initiator_session.seal_frame(b"no double record").is_err());
        assert!(responder_session.open_frame(b"no double record").is_err());
        assert!(primitive_audit::P256_AGREEMENTS.load(Ordering::Relaxed) >= 2);
        assert_eq!(
            primitive_audit::ML_DSA_OPERATIONS.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            primitive_audit::ML_KEM_OPERATIONS.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn channel_binding_mismatch_and_hybrid_flight_fail_without_fallback() {
        let mut provisioner = ClassicalProvisioner::from_seed([0x45; 32], 3).expect("authority");
        let initiator_bundle = provisioner.issue_node(1, &[member()]).expect("initiator");
        let responder_bundle = provisioner.issue_node(2, &[member()]).expect("responder");
        let (_, flight1) = ClassicalSessionInitiator::start(
            initiator_bundle,
            AuthenticatedChannelBinding::new(b"exporter-a".to_vec()).expect("binding"),
        )
        .expect("start");
        let responder = ClassicalSessionResponder::open(
            responder_bundle,
            AuthenticatedChannelBinding::new(b"exporter-b".to_vec()).expect("binding"),
        )
        .expect("responder");
        assert!(responder.receive_client(&flight1).is_err());

        let hybrid_access =
            ProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("access");
        let mut hybrid_provisioner = ReferenceProvisioner::from_seed([0x46; 32]).expect("hybrid");
        let hybrid_bundle = hybrid_provisioner
            .issue_node(1, &[hybrid_access])
            .expect("bundle");
        let (_, hybrid_flight1) = ReferenceSessionInitiator::start(hybrid_bundle).expect("start");

        let classical_bundle = provisioner.issue_node(3, &[member()]).expect("classical");
        let classical_responder = ClassicalSessionResponder::open(
            classical_bundle,
            AuthenticatedChannelBinding::new(b"exporter-c".to_vec()).expect("binding"),
        )
        .expect("responder");
        assert!(classical_responder.receive_client(&hybrid_flight1).is_err());
    }

    #[test]
    fn classical_four_flights_are_materially_smaller_than_legacy_hybrid_flights() {
        let mut classical_provisioner =
            ClassicalProvisioner::from_seed([0x48; 32], 1).expect("classical authority");
        let classical_initiator = classical_provisioner
            .issue_node(1, &[member()])
            .expect("classical initiator");
        let classical_responder = classical_provisioner
            .issue_node(2, &[member()])
            .expect("classical responder");
        let binding = b"byte-accounting exporter".to_vec();
        let (classical_initiator, c1) = ClassicalSessionInitiator::start(
            classical_initiator,
            AuthenticatedChannelBinding::new(binding.clone()).expect("binding"),
        )
        .expect("classical start");
        let classical_responder = ClassicalSessionResponder::open(
            classical_responder,
            AuthenticatedChannelBinding::new(binding).expect("binding"),
        )
        .expect("classical responder");
        let (classical_pending, c2) = classical_responder
            .receive_client(&c1)
            .expect("classical flight 1");
        let (classical_awaiting, c3) = classical_initiator
            .receive_server(&c2)
            .expect("classical flight 2");
        let (_, c4) = classical_pending
            .receive_client_auth(&c3)
            .expect("classical flight 3");
        let _ = classical_awaiting
            .receive_finished(&c4)
            .expect("classical flight 4");

        let hybrid_access =
            ProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("access");
        let mut hybrid_provisioner =
            ReferenceProvisioner::from_seed([0x49; 32]).expect("hybrid authority");
        let hybrid_initiator = hybrid_provisioner
            .issue_node(1, std::slice::from_ref(&hybrid_access))
            .expect("hybrid initiator");
        let hybrid_responder = hybrid_provisioner
            .issue_node(2, &[hybrid_access])
            .expect("hybrid responder");
        let (hybrid_initiator, h1) =
            ReferenceSessionInitiator::start(hybrid_initiator).expect("hybrid start");
        let hybrid_responder =
            ReferenceSessionResponder::open(hybrid_responder).expect("hybrid responder");
        let (hybrid_pending, h2) = hybrid_responder
            .receive_client(&h1)
            .expect("hybrid flight 1");
        let (hybrid_awaiting, h3) = hybrid_initiator
            .receive_server(&h2)
            .expect("hybrid flight 2");
        let (_, h4) = hybrid_pending
            .receive_client_auth(&h3)
            .expect("hybrid flight 3");
        let _ = hybrid_awaiting
            .receive_finished(&h4)
            .expect("hybrid flight 4");

        let classical_lengths = [c1.len(), c2.len(), c3.len(), c4.len()];
        let hybrid_lengths = [h1.len(), h2.len(), h3.len(), h4.len()];
        let classical_total: usize = classical_lengths.iter().sum();
        let hybrid_total: usize = hybrid_lengths.iter().sum();
        assert_eq!(classical_lengths, [259, 712, 499, 78]);
        assert_eq!(classical_total, 1_548);
        // Semantic v9 adds another u16 version offer to the first hybrid flight.
        assert_eq!(hybrid_lengths, [1_325, 11_337, 10_142, 78]);
        assert_eq!(hybrid_total, 22_882);
        assert!(
            classical_total < hybrid_total,
            "classical flights {classical_lengths:?} total {classical_total} bytes; legacy hybrid flights {hybrid_lengths:?} total {hybrid_total} bytes"
        );
    }

    #[test]
    fn profile_bundle_facade_dispatches_only_exact_magic() {
        let mut provisioner = ClassicalProvisioner::from_seed([0x47; 32], 5).expect("authority");
        let bundle = provisioner.issue_node(1, &[member()]).expect("bundle");
        let bytes = bundle.to_bytes().expect("bytes");
        let parsed = super::super::ProfileProvisioningBundle::from_bytes(&bytes).expect("parse");
        assert_eq!(
            parsed.profile(),
            SecurityProfile::CLASSICAL_P256_IROH_QUIC_V1
        );
        assert_eq!(parsed.to_bytes().expect("bytes"), bytes);
        let mut unknown = bytes;
        unknown[..8].copy_from_slice(b"ASTRPB99");
        assert!(super::super::ProfileProvisioningBundle::from_bytes(&unknown).is_err());
    }
}
