//! Opaque provisioning and the high-level reference envelope service.
//!
//! The reference profile deliberately separates node identity, authority trust, scope-routing
//! grants, and topic-content grants. Applications never receive raw derived keys, nonces,
//! algorithm selection, or primitive operations. The RustCrypto implementation remains a
//! portable conformance aid and is not a FIPS 140-3 validated module.

use super::{
    AeadCiphertext, BatchCryptoProvider, BridgeCryptoProvider, BridgeEdgeEnrollment,
    BridgeEdgeEnrollmentClaims, ClientFinish, ClientHello, CryptoError, CryptoProvider,
    HybridSignature, HybridVerifyingKey, InitiatorHandshake, InitiatorHandshakeAwaitingFinished,
    MlKemDecapsulationKey, MlKemEncapsulationKey, MlKemKey, MlKemKeyExport, P256SecretKey,
    P256SigningKey, ResponderHandshake, ResponderHandshakePrepared, RustCryptoProvider,
    RustCryptoSigningKey, SealedBatchItem, SealedSourceBatch, Secret32, SecureChannel,
    SequencedCiphertext, ServerFinished, ServerHello, SessionKeys, ZeroizeKey, client_hello_hash,
};
use crate::batch;
use crate::blob::{
    BlobId, BlobPhysicalLineage, BlobRouteCommitment, BlobStore, BlobStoreConfig,
    ReferenceBlobService,
};
use crate::blob_custody::{
    AuthenticatedBlobCustodyContactV1, BlobCustodyClaimV1, BlobCustodyDirectionV1,
    blob_custody_lane_record_context,
};
use crate::blob_custody_v2::{
    ApplicationRecordContext, AuthenticatedBlobCustodyContactV2,
    AuthenticatedBlobCustodySendContextV2, BlobCustodyClaimV2,
};
use crate::bridge::{
    self, AuthorizationEnvelope, BridgeAuthorization, BridgeOuterKind, BridgeRoute,
};
use crate::custody::{
    CustodyClaims, CustodyExpectation, MAX_CUSTODY_WRAPPER_BYTES, MIN_CUSTODY_SEMANTIC_VERSION,
    VerifiedCustodyClaims, decode_claims, encode_claims,
};
#[cfg(feature = "sqlite-store")]
use crate::engine::{EngineError, Node, NodeConfig};
use crate::engine::{
    EnvelopeError, EnvelopeHeader, EnvelopeSealer, SealRequest, SealedEnvelope, VerifiedControl,
    VerifiedEnvelope,
};
use crate::model::{
    CausalStamp, DataClass, Dot, MAX_CAUSAL_CONTEXT_ENTRIES, NodeId, Priority, Scope, Topic,
    VersionVector,
};
#[cfg(test)]
use crate::provisioning::{MAX_PROTECTED_PROVISIONING_BYTES, ProvisioningProtectionError};
use crate::provisioning::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, ProtectedProvisioningError, ProvisioningProtector,
    ProvisioningUnprotector, UnprotectedProvisioning, protect_provisioning_artifact,
    unprotect_provisioning_artifact,
};
#[cfg(feature = "sqlite-store")]
use crate::store::SqliteStore;
use crate::store::{ControlPrincipal, Revocation, ScopeEpoch};
use crate::transfer_profile::{
    NegotiatedTransferProfiles, TransferLaneId, TransferProfileId, TransferProfileOfferV1,
    negotiate_transfer_profiles_for_semantic_version, transfer_profile_digest,
};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, array::Array},
};
use getrandom::SysRng;
use hkdf::Hkdf;
use ml_dsa::{MlDsa65, Seed as MlDsaSeed, SigningKey as MlDsaSigningKey};
use ml_kem::Seed as MlKemSeed;
use p256::{
    FieldBytes,
    ecdsa::{
        Signature as P256Signature, VerifyingKey as P256VerifyingKey,
        signature::{Signer as P256Signer, Verifier as P256Verifier},
    },
    elliptic_curve::sec1::ToSec1Point,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use zeroize::Zeroize;

const BUNDLE_MAGIC: &[u8; 8] = b"ASTRPB03";
const BUNDLE_VERSION: u16 = 3;
const BUNDLE_CHECKSUM_DOMAIN: &[u8] = b"aster/provisioning-check/v3";
const KDF_SALT: &[u8] = b"aster/reference-provisioning/v2";
const MAX_GRANTS: usize = 256;
const MAX_ACCESS_EPOCHS: usize = 32;
const MAX_ACCESS_TOPICS: usize = 128;

const ENVELOPE_MAGIC: &[u8; 8] = b"ASTRENV2";
const ENVELOPE_FORMAT_VERSION: u16 = 2;
const BATCH_ENVELOPE_MAGIC: &[u8; 8] = b"ASTRENV3";
const BATCH_PUBLIC_HEADER_LEN: usize = 44;
const PROTOCOL_VERSION: u16 = super::PROTOCOL_VERSION;
#[cfg(test)]
const SEMANTIC_PROTOCOL_V1: u16 = super::SEMANTIC_PROTOCOL_V1;
#[cfg(test)]
const SEMANTIC_PROTOCOL_V2: u16 = super::SEMANTIC_PROTOCOL_V2;
#[cfg(test)]
const SEMANTIC_PROTOCOL_V3: u16 = super::SEMANTIC_PROTOCOL_V3;
#[cfg(test)]
const SEMANTIC_PROTOCOL_V4: u16 = super::SEMANTIC_PROTOCOL_V4;
#[cfg(test)]
const SEMANTIC_PROTOCOL_V5: u16 = super::SEMANTIC_PROTOCOL_V5;
#[cfg(test)]
const SEMANTIC_PROTOCOL_V6: u16 = super::SEMANTIC_PROTOCOL_V6;
const SEMANTIC_PROTOCOL_V7: u16 = super::SEMANTIC_PROTOCOL_V7;
const SEMANTIC_PROTOCOL_V8: u16 = super::SEMANTIC_PROTOCOL_V8;
const SEMANTIC_PROTOCOL_V9: u16 = super::SEMANTIC_PROTOCOL_V9;
const TRANSFER_PROFILE_OFFER_FRAME_PREFIX: &[u8; 5] = b"ASM\x01\xd1";
const SUITE_ID: u16 = super::HYBRID_SUITE_ID;
const PUBLIC_HEADER_LEN: usize = 44;
const SELECTOR_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const P256_PUBLIC_LEN: usize = 33;
const P256_SIGNATURE_LEN: usize = 64;
const ML_DSA_PUBLIC_LEN: usize = 1952;
const ML_DSA_SIGNATURE_LEN: usize = 3309;
const ML_KEM_PUBLIC_LEN: usize = 1184;
const MAX_ROUTE_CIPHERTEXT_LEN: usize = 256 * 1024;
const MAX_LOGICAL_KEY_LEN: usize = 64 * 1024;
const MAX_CORE_LEN: usize = 512 * 1024 * 1024;
const MAX_REKEY_RECIPIENTS: usize = 128;
const MAX_REKEY_TOPICS_PER_RECIPIENT: usize = 128;
const MAX_REKEY_PACKAGE_CIPHERTEXT_LEN: usize = 64 * 1024;
const MAX_REKEY_REGISTRY_ENTRIES: usize = 1024;
const MAX_REKEY_REGISTRY_LEN: usize = 16 * 1024 * 1024;

const NODE_ID_DOMAIN: &[u8] = b"aster/node-credential/v1";
const AUTHORITY_ID_DOMAIN: &[u8] = b"aster/authority/v1";
const CREDENTIAL_SIGNATURE_DOMAIN: &[u8] = b"aster/credential-signature/v1";
const ROUTE_GRANT_COMMITMENT_DOMAIN: &[u8] = b"aster/route-grant-commitment/v1";
const ITEM_ID_DOMAIN: &[u8] = b"aster/item/v1";
const ITEM_SIGNATURE_DOMAIN: &[u8] = b"aster/singleton-batch/v1";
const BATCH_ID_DOMAIN: &[u8] = b"aster/singleton-batch-id/v1";
const ROUTE_KEY_LABEL: &[u8] = b"aster/route-key/v1";
const CONTENT_KEY_LABEL: &[u8] = b"aster/content-key/v1";
const CONTENT_NONCE_LABEL: &[u8] = b"aster/content-nonce/v1";
const BLOB_PEER_CONTENT_PROOF_LABEL: &[u8] = b"aster/blob-peer-content-proof/v1";
const CONTENT_GROUP_DOMAIN: &[u8] = b"aster/content-group/v1";
const CONTROL_AUTHENTICATION_MAGIC: &[u8; 8] = b"ASTRCA02";
const CONTROL_AUTHENTICATION_FORMAT: u16 = 2;
const CONTROL_SIGNATURE_DOMAIN: &[u8] = b"aster/delegated-control/v2";
const REKEY_CREDENTIAL_DOMAIN: &[u8] = b"aster/rekey-credential/v1";
const REKEY_GRANT_DOMAIN: &[u8] = b"aster/rekey-grant/v1";
const REKEY_PACKAGE_SET_DOMAIN: &[u8] = b"aster/rekey-package-set/v1";
const REKEY_PACKAGE_CONTEXT_DOMAIN: &[u8] = b"aster/rekey-package-context/v1";
const REKEY_PACKAGE_AAD_DOMAIN: &[u8] = b"aster/rekey-package-aad/v1";
const REKEY_PACKAGE_KEY_LABEL: &[u8] = b"scope-rekey-recipient-wrap";
const REKEY_REGISTRY_MAGIC: &[u8; 8] = b"ASTRRKR1";
const REKEY_REGISTRY_VERSION: u16 = 2;
const REKEY_REGISTRY_SIGNATURE_DOMAIN: &[u8] = b"aster/rekey-registry/v1";
const FORWARDING_MAGIC: &[u8; 8] = b"ASTRFWD1";
const FORWARDING_FORMAT_VERSION: u16 = 1;
const FORWARDING_KEY_LABEL: &[u8] = b"aster/forwarding-key/v1";
const FORWARDING_SIGNATURE_DOMAIN: &[u8] = b"aster/forwarding-signature/v1";
const FORWARDING_PUBLIC_HEADER_LEN: usize = 34;
const MAX_FORWARDING_CIPHERTEXT_LEN: usize = 64 * 1024;
const BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL: &[u8] = b"aster/bridge-authorization-route/v1";
const BRIDGE_WRAPPER_KEY_LABEL: &[u8] = b"aster/bridge-wrapper-key/v1";
const BRIDGE_EDGE_ENROLLMENT_MAGIC: &[u8; 8] = b"ASTRBE01";
const BRIDGE_EDGE_ENROLLMENT_VERSION: u16 = 1;
const BRIDGE_EDGE_ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"aster/bridge-edge-enrollment/v1";
const MAX_BRIDGE_EDGE_ENROLLMENT_BYTES: usize = 32 * 1024;
const MAX_BRIDGE_EDGE_ENROLLMENT_SCOPE_BYTES: usize = 4 * 1024;
const MAX_BRIDGE_EDGE_ENROLLMENT_CREDENTIAL_BYTES: usize = 16 * 1024;

const HANDSHAKE_MAGIC: &[u8; 8] = b"ASTRHS01";
// These identify the stable four-flight framing/profile. They are intentionally distinct from
// the semantic protocol-version and complete-suite values negotiated inside ClientHello and
// ServerHello, even though all current numeric values are one.
const HANDSHAKE_FRAMING_VERSION: u16 = 1;
const HANDSHAKE_PROFILE_ID: u16 = 0x0001;
const FRAME_MAGIC: &[u8; 8] = b"ASTRFR01";
const MISSION_PROOF_KEY_LABEL: &[u8] = b"aster/mission-proof-key/v1";
const MISSION_PROOF_NONCE_LABEL: &[u8] = b"aster/mission-proof-nonce/v1";
const MISSION_PROOF_AAD_DOMAIN: &[u8] = b"aster/mission-proof-aad/v1";
const MISSION_PROOF_TRANSCRIPT_DOMAIN: &[u8] = b"aster/mission-proof-transcript/v1";
const TRANSPORT_FRAME_AAD: &[u8] = b"aster/transport-frame/v1";
const CUSTODY_WRAPPER_AAD: &[u8] = b"aster/custody-wrapper/v3";
const MAX_HANDSHAKE_FLIGHT_LEN: usize = 64 * 1024;
const MAX_HANDSHAKE_OFFERS: usize = 16;
const MAX_TRANSPORT_FRAME_LEN: usize = 16 * 1024 * 1024;
/// Exact bytes added by the reference authenticated-session record around one plaintext frame.
pub const REFERENCE_SESSION_FRAME_OVERHEAD_BYTES: usize =
    FRAME_MAGIC.len() + 2 + 2 + 8 + NONCE_LEN + 4 + GCM_TAG_LEN;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
const SCOPE_EPOCH_LEGACY_FORMAT: u16 = 0;
const SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT: u16 = 1;
const SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT: u16 = 2;
const REKEY_CAPABILITY_GRANT_DOMAIN: &[u8] = b"aster/rekey-capability-grant/v1";

const ROLE_RELAY: u32 = 1;
const ROLE_READER: u32 = 2;
const ROLE_CONTROL_AUTHORITY: u32 = 4;

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

/// High-level access request used only by the reference provisioner.
///
/// A relay grant can decrypt protected routing metadata but not item content. A member grant
/// additionally permits content reads for the listed topics. Epochs are independent keys; listing
/// a future epoch pre-places it for later authority activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningAccess {
    scope: Scope,
    epochs: Vec<u64>,
    readable_topics: Vec<Topic>,
    route_access: bool,
}

impl ProvisioningAccess {
    /// Grants protected routing access without content-read access.
    pub fn relay(scope: Scope, epochs: Vec<u64>) -> Result<Self, EnvelopeError> {
        Self::new(scope, epochs, Vec::new(), true)
    }

    /// Grants protected routing access and content-read access for the listed topics.
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

    /// Grants only origin content access for bridge delivery. No route key or
    /// route-grant commitment is installed for this access request.
    pub fn content_only(
        scope: Scope,
        epochs: Vec<u64>,
        readable_topics: Vec<Topic>,
    ) -> Result<Self, EnvelopeError> {
        if readable_topics.is_empty() {
            return Err(EnvelopeError(
                "a content-only access grant must contain at least one topic".into(),
            ));
        }
        Self::new(scope, epochs, readable_topics, false)
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
        if epochs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EnvelopeError("duplicate provisioning epoch".into()));
        }
        readable_topics.sort();
        if readable_topics.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EnvelopeError("duplicate provisioning topic".into()));
        }
        Ok(Self {
            scope,
            epochs,
            readable_topics,
            route_access,
        })
    }
}

/// One recipient in an authority-managed in-field scope rekey.
///
/// Empty readable topics grant routing only. Topic names are canonicalized and the authority
/// provisioner resolves `node` to a previously issued, authority-signed credential; callers never
/// handle recipient public keys or key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRekeyRecipient {
    node: NodeId,
    readable_topics: Vec<Topic>,
    route_access: bool,
}

impl ScopeRekeyRecipient {
    /// Grants the recipient only the fresh scope routing key.
    pub fn route_only(node: NodeId) -> Self {
        Self {
            node,
            readable_topics: Vec::new(),
            route_access: true,
        }
    }

    /// Grants the recipient the fresh routing key and only the listed fresh topic keys.
    pub fn member(node: NodeId, mut readable_topics: Vec<Topic>) -> Result<Self, EnvelopeError> {
        if readable_topics.is_empty() || readable_topics.len() > MAX_REKEY_TOPICS_PER_RECIPIENT {
            return Err(EnvelopeError("invalid rekey recipient topic bounds".into()));
        }
        readable_topics.sort();
        if readable_topics.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EnvelopeError("duplicate rekey recipient topic".into()));
        }
        Ok(Self {
            node,
            readable_topics,
            route_access: true,
        })
    }

    /// Delegates only the fresh topic-content keys. The recipient receives no
    /// fresh scope route key and is excluded from dynamic route authorization.
    pub fn content_only(
        node: NodeId,
        mut readable_topics: Vec<Topic>,
    ) -> Result<Self, EnvelopeError> {
        if readable_topics.is_empty() || readable_topics.len() > MAX_REKEY_TOPICS_PER_RECIPIENT {
            return Err(EnvelopeError("invalid rekey recipient topic bounds".into()));
        }
        readable_topics.sort();
        if readable_topics.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EnvelopeError("duplicate rekey recipient topic".into()));
        }
        Ok(Self {
            node,
            readable_topics,
            route_access: false,
        })
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn readable_topics(&self) -> &[Topic] {
        &self.readable_topics
    }

    pub fn has_route_access(&self) -> bool {
        self.route_access
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RekeyCredential {
    body: Vec<u8>,
    signature: HybridSignature,
}

struct VerifiedRekeyRegistry {
    generation: u64,
    signed_credentials: BTreeMap<NodeId, RekeyCredential>,
    authenticated_credentials: BTreeMap<NodeId, Credential>,
}

#[derive(Clone)]
struct PlannedRekeyRecipient {
    request: ScopeRekeyRecipient,
    credential: Credential,
}

/// Opaque authority plan for a fresh capture-excluding scope epoch.
///
/// The visible inputs are a scope, a strictly newer epoch, recipient NodeIDs, and each
/// recipient's readable topics. Authority-signed recipient credentials are retained privately.
pub struct ScopeRekeyPlan {
    scope: Scope,
    epoch: u64,
    recipients: Vec<PlannedRekeyRecipient>,
}

impl fmt::Debug for ScopeRekeyPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopeRekeyPlan")
            .field("scope", &self.scope)
            .field("epoch", &self.epoch)
            .field(
                "recipients",
                &self
                    .recipients
                    .iter()
                    .map(|recipient| &recipient.request)
                    .collect::<Vec<_>>(),
            )
            .field("key_material", &"[NONE]")
            .finish()
    }
}

impl ScopeRekeyPlan {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn recipients(&self) -> impl ExactSizeIterator<Item = &ScopeRekeyRecipient> {
        self.recipients.iter().map(|recipient| &recipient.request)
    }

    fn wire_format(&self) -> u16 {
        if self
            .recipients
            .iter()
            .all(|recipient| recipient.request.route_access)
        {
            SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT
        } else {
            SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
        }
    }
}

fn build_scope_rekey_plan(
    scope: Scope,
    epoch: u64,
    mut recipients: Vec<ScopeRekeyRecipient>,
    mut credentials: BTreeMap<NodeId, Credential>,
) -> Result<ScopeRekeyPlan, EnvelopeError> {
    if epoch == 0 || recipients.is_empty() || recipients.len() > MAX_REKEY_RECIPIENTS {
        return Err(EnvelopeError("invalid scope rekey plan bounds".into()));
    }
    recipients.sort_by_key(|recipient| recipient.node);
    if recipients
        .windows(2)
        .any(|pair| pair[0].node == pair[1].node)
    {
        return Err(EnvelopeError("duplicate scope rekey recipient".into()));
    }
    let total_topic_grants = recipients.iter().try_fold(0usize, |total, recipient| {
        total
            .checked_add(recipient.readable_topics.len())
            .ok_or_else(|| EnvelopeError("scope rekey grant count overflow".into()))
    })?;
    if total_topic_grants > MAX_GRANTS {
        return Err(EnvelopeError("too many scope rekey topic grants".into()));
    }
    let mut planned = Vec::with_capacity(recipients.len());
    for request in recipients {
        let credential = credentials
            .remove(&request.node)
            .ok_or_else(|| EnvelopeError("unknown scope rekey recipient".into()))?;
        if credential.identity != request.node
            || (request.route_access && credential.roles & ROLE_RELAY == 0)
            || (!request.readable_topics.is_empty() && credential.roles & ROLE_READER == 0)
            || (!request.route_access && request.readable_topics.is_empty())
        {
            return Err(authentication_failed());
        }
        planned.push(PlannedRekeyRecipient {
            request,
            credential,
        });
    }
    Ok(ScopeRekeyPlan {
        scope,
        epoch,
        recipients: planned,
    })
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

/// Credential and grant package with a canonical unprotected inner representation.
///
/// Serialized `ASTRPB03` bytes contain identity and mission secrets. They must never be logged or
/// treated as protected storage. [`Self::from_bytes`] is retained for compatibility, tests, and
/// provisioning tooling; operational ingestion uses [`Self::from_protected_bytes`] with an
/// admitted provider. Bundle issuance remains separated into [`ReferenceProvisioner`].
pub struct ProvisioningBundle {
    mission: [u8; 32],
    authority_id: NodeId,
    authority_verifying_key: HybridVerifyingKey,
    identity_seed: Option<Secret32>,
    serial: u64,
    roles: u32,
    credential_signature: HybridSignature,
    control_route_key: Option<Secret32>,
    route_grants: Vec<RouteGrant>,
    content_grants: Vec<ContentGrant>,
}

impl fmt::Debug for ProvisioningBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisioningBundle")
            .field("mission", &self.mission)
            .field("authority", &self.authority_id)
            .field("serial", &self.serial)
            .field("roles", &self.roles)
            .field("route_grants", &self.route_grants.len())
            .field("content_grants", &self.content_grants.len())
            .field("zeroized", &self.identity_seed.is_none())
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

impl ProvisioningBundle {
    /// Parses the canonical unprotected inner bundle format and rejects truncation, trailing data,
    /// duplicate grants, invalid bounds, and checksum damage before any service is constructed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < BUNDLE_MAGIC.len() + 2 + 32
            || bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES
        {
            return Err(invalid_bundle());
        }
        let checksum_start = bytes.len().checked_sub(32).ok_or_else(invalid_bundle)?;
        let expected = hash_domain(BUNDLE_CHECKSUM_DOMAIN, &bytes[..checksum_start]);
        if bytes[checksum_start..] != expected {
            return Err(invalid_bundle());
        }
        let mut reader = Reader::new(&bytes[..checksum_start]);
        if reader.take(BUNDLE_MAGIC.len())? != BUNDLE_MAGIC || reader.u16()? != BUNDLE_VERSION {
            return Err(invalid_bundle());
        }
        let mission = reader.array::<32>()?;
        let authority_id = reader.array::<32>()?;
        let authority_verifying_key = decode_verifying_key(&mut reader)?;
        let identity_seed = Secret32::new(reader.array::<32>()?);
        let serial = reader.u64()?;
        let roles = reader.u32()?;
        if serial == 0
            || roles == 0
            || roles & !(ROLE_RELAY | ROLE_READER | ROLE_CONTROL_AUTHORITY) != 0
        {
            return Err(invalid_bundle());
        }
        let credential_signature = decode_signature(&mut reader)?;
        let control_route_key = match reader.u8()? {
            0 => None,
            1 => Some(Secret32::new(reader.array::<32>()?)),
            _ => return Err(invalid_bundle()),
        };
        let route_count = usize::from(reader.u16()?);
        if route_count > MAX_GRANTS {
            return Err(invalid_bundle());
        }
        let mut route_grants = Vec::with_capacity(route_count);
        let mut route_names = BTreeSet::new();
        for _ in 0..route_count {
            let scope = decode_scope(reader.u16_bytes(128)?)?;
            let epoch = reader.u64()?;
            if !route_names.insert((scope.clone(), epoch)) {
                return Err(invalid_bundle());
            }
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
        let mut content_names = BTreeSet::new();
        for _ in 0..content_count {
            let scope = decode_scope(reader.u16_bytes(128)?)?;
            let topic = decode_topic(reader.u16_bytes(128)?)?;
            let epoch = reader.u64()?;
            if !content_names.insert((scope.clone(), topic.clone(), epoch)) {
                return Err(invalid_bundle());
            }
            content_grants.push(ContentGrant {
                scope,
                topic,
                epoch,
                key: Secret32::new(reader.array::<32>()?),
            });
        }
        if (roles & ROLE_RELAY != 0) != (route_count != 0)
            || (roles & ROLE_READER != 0) != (content_count != 0)
        {
            return Err(invalid_bundle());
        }
        reader.finish()?;
        Ok(Self {
            mission,
            authority_id,
            authority_verifying_key,
            identity_seed: Some(identity_seed),
            serial,
            roles,
            credential_signature,
            control_route_key,
            route_grants,
            content_grants,
        })
    }

    /// Returns the canonical unprotected inner representation.
    ///
    /// Operational callers must immediately pass these secret bytes to an admitted
    /// [`ProvisioningProtector`] provider. Prefer [`Self::to_protected_bytes`] when possible.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let identity_seed = self.identity_seed.as_ref().ok_or_else(zeroized_service)?;
        let expected_len = self.encoded_len()?;
        let mut bytes = Vec::with_capacity(expected_len);
        let encoded = (|| -> Result<(), EnvelopeError> {
            bytes.extend_from_slice(BUNDLE_MAGIC);
            bytes.extend_from_slice(&BUNDLE_VERSION.to_be_bytes());
            bytes.extend_from_slice(&self.mission);
            bytes.extend_from_slice(&self.authority_id);
            encode_verifying_key(&mut bytes, &self.authority_verifying_key)?;
            bytes.extend_from_slice(identity_seed.expose());
            bytes.extend_from_slice(&self.serial.to_be_bytes());
            bytes.extend_from_slice(&self.roles.to_be_bytes());
            encode_signature(&mut bytes, &self.credential_signature)?;
            match &self.control_route_key {
                Some(key) => {
                    bytes.push(1);
                    bytes.extend_from_slice(key.expose());
                }
                None => bytes.push(0),
            }
            let route_count =
                u16::try_from(self.route_grants.len()).map_err(|_| invalid_bundle())?;
            bytes.extend_from_slice(&route_count.to_be_bytes());
            for grant in &self.route_grants {
                push_u16_bytes(&mut bytes, grant.scope.as_str().as_bytes())?;
                bytes.extend_from_slice(&grant.epoch.to_be_bytes());
                bytes.extend_from_slice(grant.key.expose());
            }
            let content_count =
                u16::try_from(self.content_grants.len()).map_err(|_| invalid_bundle())?;
            bytes.extend_from_slice(&content_count.to_be_bytes());
            for grant in &self.content_grants {
                push_u16_bytes(&mut bytes, grant.scope.as_str().as_bytes())?;
                push_u16_bytes(&mut bytes, grant.topic.as_str().as_bytes())?;
                bytes.extend_from_slice(&grant.epoch.to_be_bytes());
                bytes.extend_from_slice(grant.key.expose());
            }
            let checksum = hash_domain(BUNDLE_CHECKSUM_DOMAIN, &bytes);
            bytes.extend_from_slice(&checksum);
            if bytes.len() != expected_len {
                return Err(invalid_bundle());
            }
            Ok(())
        })();
        if let Err(error) = encoded {
            bytes.zeroize();
            return Err(error);
        }
        Ok(bytes)
    }

    fn encoded_len(&self) -> Result<usize, EnvelopeError> {
        fn add(total: &mut usize, amount: usize) -> Result<(), EnvelopeError> {
            *total = total.checked_add(amount).ok_or_else(invalid_bundle)?;
            Ok(())
        }

        self.identity_seed.as_ref().ok_or_else(zeroized_service)?;
        let classical = self
            .credential_signature
            .ecdsa_p256
            .as_deref()
            .ok_or_else(authentication_failed)?;
        let post_quantum = self
            .credential_signature
            .ml_dsa_65
            .as_deref()
            .ok_or_else(authentication_failed)?;
        if self.authority_verifying_key.p256_sec1.len() != P256_PUBLIC_LEN
            || self.authority_verifying_key.ml_dsa_65.len() != ML_DSA_PUBLIC_LEN
            || classical.len() != P256_SIGNATURE_LEN
            || post_quantum.len() != ML_DSA_SIGNATURE_LEN
            || self.serial == 0
            || self.roles == 0
            || self.roles & !(ROLE_RELAY | ROLE_READER | ROLE_CONTROL_AUTHORITY) != 0
            || self.route_grants.len() > MAX_GRANTS
            || self.content_grants.len() > MAX_GRANTS
            || (self.roles & ROLE_RELAY != 0) == self.route_grants.is_empty()
            || (self.roles & ROLE_READER != 0) == self.content_grants.is_empty()
        {
            return Err(invalid_bundle());
        }

        let mut total = BUNDLE_MAGIC.len();
        for fixed in [
            2,
            32,
            32,
            2 + P256_PUBLIC_LEN,
            4 + ML_DSA_PUBLIC_LEN,
            32,
            8,
            4,
            2 + P256_SIGNATURE_LEN,
            4 + ML_DSA_SIGNATURE_LEN,
            1,
            self.control_route_key.as_ref().map_or(0, |_| 32),
            2,
        ] {
            add(&mut total, fixed)?;
        }
        for grant in &self.route_grants {
            let scope_len = grant.scope.as_str().len();
            if scope_len > 128 {
                return Err(invalid_bundle());
            }
            add(&mut total, 2 + scope_len + 8 + 32)?;
        }
        add(&mut total, 2)?;
        for grant in &self.content_grants {
            let scope_len = grant.scope.as_str().len();
            let topic_len = grant.topic.as_str().len();
            if scope_len > 128 || topic_len > 128 {
                return Err(invalid_bundle());
            }
            add(&mut total, 2 + scope_len + 2 + topic_len + 8 + 32)?;
        }
        add(&mut total, 32)?;
        if total > MAX_UNPROTECTED_PROVISIONING_BYTES {
            return Err(invalid_bundle());
        }
        Ok(total)
    }

    /// Protects the canonical inner representation with a deployment-owned provider.
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

    /// Authenticates a provider-owned artifact and parses its canonical inner bundle.
    ///
    /// Provider rejection never falls back to interpreting `protected` as plaintext.
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

    /// Rapidly erases all secret fields held by this object.
    pub fn zeroize(&mut self) {
        self.identity_seed = None;
        self.control_route_key = None;
        self.route_grants.clear();
        self.content_grants.clear();
    }

    /// Reports whether secret fields have already been erased.
    pub fn is_zeroized(&self) -> bool {
        self.identity_seed.is_none()
    }
}

impl Drop for ProvisioningBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reference provisioning authority.
///
/// This deployment-side helper issues opaque packages and is not part of the application node
/// API. A caller must protect and separately escrow its seed. It exposes no algorithm choices or
/// derived key bytes.
pub struct ReferenceProvisioner {
    root: Option<Secret32>,
    provider: RustCryptoProvider<SysRng>,
    authority_signing_key: RustCryptoSigningKey,
    authority_verifying_key: HybridVerifyingKey,
    authority_id: NodeId,
    mission: [u8; 32],
    registry_generation: u64,
    issued_rekey_credentials: BTreeMap<NodeId, RekeyCredential>,
}

impl fmt::Debug for ReferenceProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceProvisioner")
            .field("mission", &self.mission)
            .field("authority", &self.authority_id)
            .field("secret_material", &"[REDACTED]")
            .finish()
    }
}

impl ReferenceProvisioner {
    /// Opens an issuing authority from a high-entropy mission provisioning seed.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, EnvelopeError> {
        if seed.iter().all(|byte| *byte == 0) {
            return Err(EnvelopeError(
                "provisioning seed must come from a cryptographic random source".into(),
            ));
        }
        let root = Secret32::new(seed);
        let provider = RustCryptoProvider::try_new(SysRng).map_err(reference_open_error)?;
        let authority_seed = Secret32::new(derive_material(
            root.expose(),
            b"authority-signing-seed",
            &[],
        )?);
        let authority_signing_key = derive_signing_key(authority_seed.expose())?;
        let authority_verifying_key = provider
            .verifying_key(&authority_signing_key)
            .map_err(reference_open_error)?;
        let mission = hash_domain(b"aster/mission/v1", root.expose());
        let authority_id = derive_authority_id(&mission, &authority_verifying_key);
        Ok(Self {
            root: Some(root),
            provider,
            authority_signing_key,
            authority_verifying_key,
            authority_id,
            mission,
            registry_generation: 0,
            issued_rekey_credentials: BTreeMap::new(),
        })
    }

    /// Issues a unique ordinary node identity with only the requested grants.
    pub fn issue_node(
        &mut self,
        serial: u64,
        accesses: &[ProvisioningAccess],
    ) -> Result<ProvisioningBundle, EnvelopeError> {
        self.issue(serial, accesses, false)
    }

    /// Issues an explicitly privileged authority node capable of creating control notices.
    pub fn issue_control_authority(
        &mut self,
        serial: u64,
        accesses: &[ProvisioningAccess],
    ) -> Result<ProvisioningBundle, EnvelopeError> {
        self.issue(serial, accesses, true)
    }

    /// Resolves high-level recipient choices to opaque authority-issued credentials.
    pub fn plan_scope_rekey(
        &self,
        scope: Scope,
        epoch: u64,
        recipients: Vec<ScopeRekeyRecipient>,
    ) -> Result<ScopeRekeyPlan, EnvelopeError> {
        self.root.as_ref().ok_or_else(zeroized_service)?;
        let credentials = authenticate_rekey_credentials(
            &self.issued_rekey_credentials,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        build_scope_rekey_plan(scope, epoch, recipients, credentials)
    }

    /// Returns locally issued public rekey-recipient identifiers in canonical registry order.
    ///
    /// These identifiers are not authentication evidence. Consumers must use the signed registry
    /// and planning path to authenticate recipients. This accessor exposes no credential body,
    /// signature, grant, secret, seed, or key.
    pub fn rekey_registry_recipient_nodes(&self) -> impl ExactSizeIterator<Item = NodeId> + '_ {
        self.issued_rekey_credentials.keys().copied()
    }

    /// Exports the bounded public recipient registry as one authority-signed canonical artifact.
    /// No identity seed, private key, route key, or content key is included.
    pub fn export_rekey_registry(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.root.as_ref().ok_or_else(zeroized_service)?;
        if self.issued_rekey_credentials.is_empty()
            || self.issued_rekey_credentials.len() > MAX_REKEY_REGISTRY_ENTRIES
            || self.registry_generation
                != u64::try_from(self.issued_rekey_credentials.len())
                    .map_err(|_| invalid_envelope())?
        {
            return Err(EnvelopeError("invalid rekey registry bounds".into()));
        }
        let mut encoded = Vec::new();
        encoded.extend_from_slice(REKEY_REGISTRY_MAGIC);
        encoded.extend_from_slice(&REKEY_REGISTRY_VERSION.to_be_bytes());
        encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        encoded.extend_from_slice(&SUITE_ID.to_be_bytes());
        encoded.extend_from_slice(&self.mission);
        encoded.extend_from_slice(&self.authority_id);
        encoded.extend_from_slice(&self.registry_generation.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(self.issued_rekey_credentials.len())
                .map_err(|_| invalid_envelope())?
                .to_be_bytes(),
        );
        for (node, credential) in &self.issued_rekey_credentials {
            encoded.extend_from_slice(node);
            push_u32_bytes(&mut encoded, &credential.body)?;
            encode_signature(&mut encoded, &credential.signature)?;
        }
        let digest = hash_domain(REKEY_REGISTRY_SIGNATURE_DOMAIN, &encoded);
        let signature = self
            .provider
            .sign(&self.authority_signing_key, &digest)
            .map_err(envelope_crypto_error)?;
        encode_signature(&mut encoded, &signature)?;
        if encoded.len() > MAX_REKEY_REGISTRY_LEN {
            return Err(EnvelopeError("rekey registry is too large".into()));
        }
        Ok(encoded)
    }

    /// Atomically imports a same-authority public registry after canonical and hybrid-signature
    /// verification. Registries are append-only: an initialized authority rejects rollback,
    /// same-generation replacement, and a later generation that omits or changes an entry.
    /// This is the explicit durable admin seam for authority restarts; the first import into a
    /// fresh instance establishes its trusted generation.
    pub fn import_rekey_registry(&mut self, encoded: &[u8]) -> Result<(), EnvelopeError> {
        self.import_rekey_registry_at_least(encoded, 0)
    }

    /// Imports a registry while enforcing an operator-persisted generation high-water mark.
    /// Callers that require rollback detection across process or storage replacement must retain
    /// the last accepted generation in independent durable state and pass it here on restart.
    pub fn import_rekey_registry_at_least(
        &mut self,
        encoded: &[u8],
        minimum_generation: u64,
    ) -> Result<(), EnvelopeError> {
        self.root.as_ref().ok_or_else(zeroized_service)?;
        let VerifiedRekeyRegistry {
            generation: imported_generation,
            signed_credentials: imported,
            ..
        } = verify_rekey_registry(
            encoded,
            minimum_generation,
            &self.mission,
            self.authority_id,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        if imported_generation < self.registry_generation
            || (imported_generation == self.registry_generation
                && imported != self.issued_rekey_credentials)
            || (imported_generation > self.registry_generation
                && !self
                    .issued_rekey_credentials
                    .iter()
                    .all(|(node, credential)| imported.get(node) == Some(credential)))
        {
            return Err(authentication_failed());
        }
        self.registry_generation = imported_generation;
        self.issued_rekey_credentials = imported;
        Ok(())
    }

    /// Returns the append-only registry generation for durable high-water tracking.
    pub fn rekey_registry_generation(&self) -> u64 {
        self.registry_generation
    }

    fn issue(
        &mut self,
        serial: u64,
        accesses: &[ProvisioningAccess],
        control_authority: bool,
    ) -> Result<ProvisioningBundle, EnvelopeError> {
        if serial == 0 || accesses.is_empty() {
            return Err(EnvelopeError("invalid node provisioning request".into()));
        }
        if self.issued_rekey_credentials.len() >= MAX_REKEY_REGISTRY_ENTRIES {
            return Err(EnvelopeError("rekey registry capacity exhausted".into()));
        }
        let root = self.root.as_ref().ok_or_else(zeroized_service)?;
        let mut identity_seed_bytes = [0u8; 32];
        self.provider
            .fill_random(&mut identity_seed_bytes)
            .map_err(reference_open_error)?;
        let identity_seed = Secret32::new(identity_seed_bytes);
        let (_, verifying_key, p256_ecdh_secret, p256_ecdh_public_key, kem_key, kem_public_key) =
            derive_identity(identity_seed.expose(), &self.provider)?;
        drop(p256_ecdh_secret);
        drop(kem_key);

        let mut route_names = BTreeSet::new();
        let mut content_names = BTreeSet::new();
        let mut route_grants = Vec::new();
        let mut content_grants = Vec::new();
        for access in accesses {
            if access.route_access {
                for &epoch in &access.epochs {
                    if !route_names.insert((access.scope.clone(), epoch)) {
                        continue;
                    }
                    if route_grants.len() >= MAX_GRANTS {
                        return Err(EnvelopeError("too many scope routing grants".into()));
                    }
                    let context = grant_context(&access.scope, None, epoch)?;
                    route_grants.push(RouteGrant {
                        scope: access.scope.clone(),
                        epoch,
                        key: Secret32::new(derive_material(
                            root.expose(),
                            b"scope-routing-epoch",
                            &context,
                        )?),
                    });
                }
            }
            for topic in &access.readable_topics {
                for &epoch in &access.epochs {
                    if !content_names.insert((access.scope.clone(), topic.clone(), epoch)) {
                        continue;
                    }
                    if content_grants.len() >= MAX_GRANTS {
                        return Err(EnvelopeError("too many content grants".into()));
                    }
                    let context = grant_context(&access.scope, Some(topic), epoch)?;
                    content_grants.push(ContentGrant {
                        scope: access.scope.clone(),
                        topic: topic.clone(),
                        epoch,
                        key: Secret32::new(derive_material(
                            root.expose(),
                            b"topic-content-epoch",
                            &context,
                        )?),
                    });
                }
            }
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
        let route_grant_commitments = route_grant_commitments(&self.mission, &route_grants)?;
        let credential_body = encode_credential_body(
            &self.mission,
            serial,
            roles,
            &verifying_key,
            &p256_ecdh_public_key,
            &kem_public_key,
            &route_grant_commitments,
        )?;
        let credential_digest = hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &credential_body);
        let credential_signature = self
            .provider
            .sign(&self.authority_signing_key, &credential_digest)
            .map_err(envelope_crypto_error)?;
        let control_route_key = Secret32::new(derive_material(
            root.expose(),
            b"mission-control-route",
            &self.mission,
        )?);
        let identity = hash_domain(NODE_ID_DOMAIN, &credential_body);
        if self.issued_rekey_credentials.contains_key(&identity) {
            return Err(EnvelopeError("duplicate provisioned identity".into()));
        }
        let next_registry_generation = self
            .registry_generation
            .checked_add(1)
            .ok_or_else(|| EnvelopeError("rekey registry generation exhausted".into()))?;
        self.issued_rekey_credentials.insert(
            identity,
            RekeyCredential {
                body: credential_body,
                signature: credential_signature.clone(),
            },
        );
        self.registry_generation = next_registry_generation;
        Ok(ProvisioningBundle {
            mission: self.mission,
            authority_id: self.authority_id,
            authority_verifying_key: self.authority_verifying_key.clone(),
            identity_seed: Some(identity_seed),
            serial,
            roles,
            credential_signature,
            control_route_key: Some(control_route_key),
            route_grants,
            content_grants,
        })
    }

    /// Erases the issuing root and authority signing capability.
    pub fn zeroize(&mut self) {
        self.root = None;
        self.authority_signing_key.zeroize_key();
    }
}

impl Drop for ReferenceProvisioner {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone)]
struct Credential {
    body: Vec<u8>,
    signature: HybridSignature,
    identity: NodeId,
    verifying_key: HybridVerifyingKey,
    p256_ecdh_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
    roles: u32,
    route_grant_commitments: Vec<[u8; 32]>,
}

/// Route-authenticated compact item awaiting its exact proof dependency.
pub(crate) struct PendingBatchItem {
    envelope_id: [u8; 32],
    item_id: [u8; 32],
    header: EnvelopeHeader,
    content_group: [u8; 32],
    content_nonce: [u8; NONCE_LEN],
    content_ciphertext_len: u64,
    authentication: batch::CompactAuthentication,
}

#[allow(dead_code)]
impl PendingBatchItem {
    pub(crate) fn envelope_id(&self) -> [u8; 32] {
        self.envelope_id
    }

    pub(crate) fn item_id(&self) -> [u8; 32] {
        self.item_id
    }

    pub(crate) fn proof_envelope_id(&self) -> [u8; 32] {
        self.authentication.proof_envelope_id
    }

    pub(crate) fn header(&self) -> &EnvelopeHeader {
        &self.header
    }
}

impl fmt::Debug for PendingBatchItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingBatchItem")
            .field("envelope_id", &self.envelope_id)
            .field("item_id", &self.item_id)
            .field("proof_envelope_id", &self.authentication.proof_envelope_id)
            .field("scope", &self.header.scope)
            .field("topic", &self.header.topic)
            .field("epoch", &self.header.key_epoch)
            .field("ciphertext_len", &self.content_ciphertext_len)
            .field("acceptance", &"[PENDING-PROOF]")
            .field("plaintext", &"[NONE]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Exact proof-envelope capability after route, credential, manifest, and both
/// hybrid signature families authenticate.
pub(crate) struct VerifiedBatchProof {
    proof_envelope_id: [u8; 32],
    batch_id: [u8; 32],
    manifest: batch::BatchManifest,
    publisher: NodeId,
    p256_verifying_key: Vec<u8>,
}

#[allow(dead_code)]
impl VerifiedBatchProof {
    pub(crate) fn proof_envelope_id(&self) -> [u8; 32] {
        self.proof_envelope_id
    }

    pub(crate) fn batch_id(&self) -> [u8; 32] {
        self.batch_id
    }

    pub(crate) fn manifest(&self) -> &batch::BatchManifest {
        &self.manifest
    }
}

impl fmt::Debug for VerifiedBatchProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBatchProof")
            .field("proof_envelope_id", &self.proof_envelope_id)
            .field("batch_id", &self.batch_id)
            .field("publisher", &self.publisher)
            .field("scope", &self.manifest.preamble.scope)
            .field("topic", &self.manifest.preamble.topic)
            .field("epoch", &self.manifest.preamble.key_epoch)
            .field("item_count", &self.manifest.preamble.item_count)
            .field("verification_key", &"[PROVIDER-OWNED]")
            .field("plaintext", &"[NONE]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Compact item capability after its exact proof, Merkle commitment, range,
/// ciphertext, header, and fixed-width P-256 signature all verify.
pub(crate) struct VerifiedBatchItem {
    envelope_id: [u8; 32],
    proof_envelope_id: [u8; 32],
    batch_id: [u8; 32],
    item_id: [u8; 32],
    header: EnvelopeHeader,
    content_nonce: [u8; NONCE_LEN],
    content_ciphertext_len: u64,
}

#[allow(dead_code)]
impl VerifiedBatchItem {
    pub(crate) fn envelope_id(&self) -> [u8; 32] {
        self.envelope_id
    }

    pub(crate) fn proof_envelope_id(&self) -> [u8; 32] {
        self.proof_envelope_id
    }

    pub(crate) fn batch_id(&self) -> [u8; 32] {
        self.batch_id
    }

    pub(crate) fn verified_envelope(&self) -> VerifiedEnvelope {
        VerifiedEnvelope {
            id: self.item_id,
            header: self.header.clone(),
        }
    }
}

impl fmt::Debug for VerifiedBatchItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBatchItem")
            .field("envelope_id", &self.envelope_id)
            .field("proof_envelope_id", &self.proof_envelope_id)
            .field("batch_id", &self.batch_id)
            .field("item_id", &self.item_id)
            .field("scope", &self.header.scope)
            .field("topic", &self.header.topic)
            .field("epoch", &self.header.key_epoch)
            .field("ciphertext_len", &self.content_ciphertext_len)
            .field("plaintext", &"[NONE]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Provider-authenticated, bridge-signed enrollment for one exact directed edge.
/// Credential bytes and route commitments remain inside this provider capability.
pub(crate) struct VerifiedBridgeEdgeEnrollment {
    claims: BridgeEdgeEnrollmentClaims,
    source_route_commitment: [u8; 32],
    target_route_commitment: [u8; 32],
    bridge_credential: Vec<u8>,
    authority_credential_signature: Vec<u8>,
}

impl fmt::Debug for VerifiedBridgeEdgeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBridgeEdgeEnrollment")
            .field("claims", &self.claims)
            .field("credential", &"[AUTHORITY-VERIFIED]")
            .field("route_grant_commitments", &"[PROVIDER-OWNED]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Provider-authenticated bridge authorization plus the public bridge verifying
/// key recovered from its exact authority-signed credential.
pub(crate) struct VerifiedBridgeAuthorization {
    envelope: AuthorizationEnvelope,
    bridge_verifying_key: Option<HybridVerifyingKey>,
    control_signer: NodeId,
}

#[allow(dead_code)]
impl VerifiedBridgeAuthorization {
    pub(crate) fn envelope(&self) -> &AuthorizationEnvelope {
        &self.envelope
    }

    pub(crate) fn control_signer(&self) -> NodeId {
        self.control_signer
    }
}

impl fmt::Debug for VerifiedBridgeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBridgeAuthorization")
            .field("envelope_id", &self.envelope.envelope_id)
            .field(
                "authorization_key",
                &self.envelope.authorization.authorization_key,
            )
            .field("generation", &self.envelope.authorization.generation)
            .field("enabled", &self.bridge_verifying_key.is_some())
            .field("credential", &"[AUTHORITY-VERIFIED]")
            .finish()
    }
}

/// Exact route plaintext returned only after source-envelope authentication.
///
/// The descriptor is intentionally opaque to bridge logic. Authenticated policy
/// metadata is copied out separately, and no route or content key is retained.
pub(crate) struct VerifiedBridgeSourceRoute {
    mission_id: [u8; 32],
    wrapper_envelope_id: Option<[u8; 32]>,
    origin_envelope_id: [u8; 32],
    source_item_id: [u8; 32],
    header: EnvelopeHeader,
    exact_route_descriptor: Vec<u8>,
    content_nonce: [u8; NONCE_LEN],
    content_ciphertext_len: u64,
}

#[allow(dead_code)]
impl VerifiedBridgeSourceRoute {
    pub(crate) fn mission_id(&self) -> [u8; 32] {
        self.mission_id
    }

    pub(crate) fn origin_envelope_id(&self) -> [u8; 32] {
        self.origin_envelope_id
    }

    pub(crate) fn source_item_id(&self) -> [u8; 32] {
        self.source_item_id
    }

    pub(crate) fn header(&self) -> &EnvelopeHeader {
        &self.header
    }

    pub(crate) fn content_ciphertext_len(&self) -> u64 {
        self.content_ciphertext_len
    }

    /// Copies only provider-verified opaque route bytes for target wrapping.
    pub(crate) fn copy_exact_route_descriptor(&self) -> Vec<u8> {
        self.exact_route_descriptor.clone()
    }
}

impl fmt::Debug for VerifiedBridgeSourceRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBridgeSourceRoute")
            .field("mission", &self.mission_id)
            .field("origin_envelope_id", &self.origin_envelope_id)
            .field("source_item_id", &self.source_item_id)
            .field("scope", &self.header.scope)
            .field("route_epoch", &self.header.key_epoch)
            .field("descriptor_len", &self.exact_route_descriptor.len())
            .field("content_ciphertext_len", &self.content_ciphertext_len)
            .field("wrapper_authenticated", &self.wrapper_envelope_id.is_some())
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Target-route-authenticated wrapper plaintext. The private constructor makes
/// this an unforgeable provider capability while accessors expose only bounded,
/// authenticated routing metadata needed for durable dependency staging.
pub(crate) struct VerifiedBridgeWrapper {
    wrapper_envelope_id: [u8; 32],
    route: BridgeRoute,
}

#[allow(dead_code)]
impl VerifiedBridgeWrapper {
    pub(crate) fn wrapper_envelope_id(&self) -> [u8; 32] {
        self.wrapper_envelope_id
    }

    pub(crate) fn route(&self) -> &BridgeRoute {
        &self.route
    }
}

impl fmt::Debug for VerifiedBridgeWrapper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBridgeWrapper")
            .field("wrapper_envelope_id", &self.wrapper_envelope_id)
            .field("bridge_route_id", &self.route.bridge_route_id)
            .field("origin_envelope_id", &self.route.origin_envelope_id)
            .field("source_item_id", &self.route.source_item_id)
            .field("origin_scope", &self.route.origin_scope)
            .field("current_scope", &self.route.current_scope)
            .field("hop_count", &self.route.hops.len())
            .field("key_material", &"[NONE]")
            .field("payload", &"[NONE]")
            .finish()
    }
}

impl Drop for VerifiedBridgeWrapper {
    fn drop(&mut self) {
        self.route.source_route_descriptor.zeroize();
    }
}

impl Drop for VerifiedBridgeSourceRoute {
    fn drop(&mut self) {
        self.exact_route_descriptor.zeroize();
    }
}

struct PreparedRekeyRecipient {
    request: ScopeRekeyRecipient,
    credential: Credential,
    credential_hash: [u8; 32],
    grant_salt: Secret32,
    grant_commitment: [u8; 32],
}

type DerivedIdentity = (
    RustCryptoSigningKey,
    HybridVerifyingKey,
    P256SecretKey,
    Vec<u8>,
    MlKemDecapsulationKey,
    Vec<u8>,
);

/// Concrete high-level reference implementation of [`EnvelopeSealer`].
pub struct ReferenceEnvelopeSealer {
    provider: RustCryptoProvider<SysRng>,
    mission: [u8; 32],
    authority_id: NodeId,
    authority_verifying_key: HybridVerifyingKey,
    credential: Credential,
    signing_key: RustCryptoSigningKey,
    p256_ecdh_secret: Option<P256SecretKey>,
    kem_decapsulation_key: Option<MlKemDecapsulationKey>,
    control_route_key: Option<Secret32>,
    route_grants: Vec<RouteGrant>,
    content_grants: Vec<ContentGrant>,
    rekey_route_authorizations: BTreeMap<(Scope, u64), Vec<NodeId>>,
    zeroized: bool,
}

impl fmt::Debug for ReferenceEnvelopeSealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceEnvelopeSealer")
            .field("identity", &self.credential.identity)
            .field("authority", &self.authority_id)
            .field("route_grants", &self.route_grants.len())
            .field("content_grants", &self.content_grants.len())
            .field("zeroized", &self.zeroized)
            .field("assurance", &self.provider.assurance())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ReferenceEnvelopeSealer {
    /// Opens the service, verifies the authority-issued credential, and consumes the bundle.
    pub fn open(mut bundle: ProvisioningBundle) -> Result<Self, EnvelopeError> {
        let seed = bundle.identity_seed.as_ref().ok_or_else(zeroized_service)?;
        let provider = RustCryptoProvider::try_new(SysRng).map_err(reference_open_error)?;
        let (
            signing_key,
            verifying_key,
            p256_ecdh_secret,
            p256_ecdh_public_key,
            kem_decapsulation_key,
            kem_public_key,
        ) = derive_identity(seed.expose(), &provider)?;
        let route_grant_commitments =
            route_grant_commitments(&bundle.mission, &bundle.route_grants)?;
        let credential_body = encode_credential_body(
            &bundle.mission,
            bundle.serial,
            bundle.roles,
            &verifying_key,
            &p256_ecdh_public_key,
            &kem_public_key,
            &route_grant_commitments,
        )?;
        let credential_digest = hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &credential_body);
        provider
            .verify(
                &bundle.authority_verifying_key,
                &credential_digest,
                &bundle.credential_signature,
            )
            .map_err(envelope_crypto_error)?;
        let derived_authority =
            derive_authority_id(&bundle.mission, &bundle.authority_verifying_key);
        if derived_authority != bundle.authority_id {
            return Err(authentication_failed());
        }
        let identity = hash_domain(NODE_ID_DOMAIN, &credential_body);
        let credential = Credential {
            body: credential_body,
            signature: bundle.credential_signature.clone(),
            identity,
            verifying_key,
            p256_ecdh_public_key,
            kem_public_key,
            roles: bundle.roles,
            route_grant_commitments,
        };
        let control_route_key = bundle.control_route_key.take();
        let route_grants = std::mem::take(&mut bundle.route_grants);
        let content_grants = std::mem::take(&mut bundle.content_grants);
        let mission = bundle.mission;
        let authority_id = bundle.authority_id;
        let authority_verifying_key = bundle.authority_verifying_key.clone();
        bundle.zeroize();
        Ok(Self {
            provider,
            mission,
            authority_id,
            authority_verifying_key,
            credential,
            signing_key,
            p256_ecdh_secret: Some(p256_ecdh_secret),
            kem_decapsulation_key: Some(kem_decapsulation_key),
            control_route_key,
            route_grants,
            content_grants,
            rekey_route_authorizations: BTreeMap::new(),
            zeroized: false,
        })
    }

    /// Stable unique identity authenticated by the provisioned authority credential.
    pub fn identity(&self) -> NodeId {
        self.credential.identity
    }

    /// Stable mission authority namespace authenticated by this provisioning bundle.
    ///
    /// This identifier is derived from the mission and authority verification key.
    /// It therefore remains stable across ordinary node credential rotation and is
    /// distinct from this node's [`Self::identity`].
    pub const fn authority_id(&self) -> NodeId {
        self.authority_id
    }

    /// Explicit alias for [`Self::authority_id`] at persistence boundaries.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.authority_id()
    }

    pub(crate) fn current_source_route_grant_commitment(
        &self,
        scope: &Scope,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        self.route_grant(scope, epoch)
            .and_then(|grant| route_grant_commitment(&self.mission, grant).ok())
    }

    pub(crate) fn seal_source_protocol_object(
        &self,
        signature_domain: &'static [u8],
        body: &[u8],
        maximum_body_len: usize,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.ensure_live()?;
        if body.len() > maximum_body_len {
            return Err(invalid_envelope());
        }
        let digest = hash_domain(signature_domain, body);
        let signature = self
            .provider
            .sign(&self.signing_key, &digest)
            .map_err(envelope_crypto_error)?;
        let mut encoded = Vec::new();
        push_u32_bytes(&mut encoded, &self.credential.body)?;
        encode_signature(&mut encoded, &self.credential.signature)?;
        push_u32_bytes(&mut encoded, body)?;
        encode_signature(&mut encoded, &signature)?;
        Ok(encoded)
    }

    pub(crate) fn verify_source_protocol_object(
        &self,
        signature_domain: &'static [u8],
        encoded: &[u8],
        maximum_body_len: usize,
    ) -> Result<(NodeId, Vec<u8>), EnvelopeError> {
        self.ensure_live()?;
        let mut reader = Reader::new(encoded);
        let credential_body = reader.u32_bytes(16 * 1024)?.to_vec();
        let credential_signature = decode_signature(&mut reader)?;
        let credential = decode_credential(
            credential_body,
            credential_signature,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        let body = reader.u32_bytes(maximum_body_len)?.to_vec();
        let signature = decode_signature(&mut reader)?;
        reader.finish()?;
        let digest = hash_domain(signature_domain, &body);
        self.provider
            .verify(&credential.verifying_key, &digest, &signature)
            .map_err(envelope_crypto_error)?;
        Ok((credential.identity, body))
    }

    pub(crate) fn blob_stream_content_grant_seed(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        if self.zeroized {
            return None;
        }
        self.content_grant(scope, topic, epoch)
            .map(|grant| *grant.key.expose())
    }

    pub(crate) fn current_event_route_grant_commitment(
        &self,
        scope: &Scope,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        self.current_source_route_grant_commitment(scope, epoch)
    }

    pub(crate) fn current_blob_physical_lineage(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
    ) -> Option<BlobPhysicalLineage> {
        self.content_grant(scope, topic, epoch).map(|grant| {
            BlobPhysicalLineage::from_content_grant(
                self.authority_id,
                scope,
                topic,
                epoch,
                grant.key.expose(),
            )
        })
    }

    pub(crate) fn blob_peer_content_proof_bytes(
        &self,
        claimant: NodeId,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        if self.zeroized {
            return None;
        }
        let grant = self.content_grant(scope, topic, epoch)?;
        let mut context =
            Vec::with_capacity(32 + 32 + 8 + scope.as_str().len() + 8 + topic.as_str().len() + 8);
        context.extend_from_slice(&self.authority_id);
        context.extend_from_slice(&claimant);
        context.extend_from_slice(&(scope.as_str().len() as u64).to_be_bytes());
        context.extend_from_slice(scope.as_str().as_bytes());
        context.extend_from_slice(&(topic.as_str().len() as u64).to_be_bytes());
        context.extend_from_slice(topic.as_str().as_bytes());
        context.extend_from_slice(&epoch.to_be_bytes());
        derive_material::<32>(grant.key.expose(), BLOB_PEER_CONTENT_PROOF_LABEL, &context).ok()
    }

    /// Tests whether an authenticated peer credential carries the exact
    /// authority-signed route grant for one scope and key epoch.
    ///
    /// The opaque commitments must come from a completed authenticated session,
    /// never from peer application data. This wrapper exposes only the existing
    /// provider authorization decision without revealing route-grant material.
    pub fn peer_can_route(
        &self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        scope: &Scope,
        epoch: u64,
    ) -> bool {
        <Self as EnvelopeSealer>::peer_can_route(self, peer, peer_route_commitments, scope, epoch)
    }

    /// Reports whether this node owns the exact route capability for an Event scope epoch.
    ///
    /// This exposes only a high-level authorization decision. Route key bytes and
    /// provider handles remain private.
    pub fn can_route_event(&self, scope: &Scope, epoch: u64) -> bool {
        self.route_grant(scope, epoch).is_some()
    }

    /// Reports whether this node can open Event content for an exact topic and scope epoch.
    ///
    /// This exposes only a high-level authorization decision. Content key bytes
    /// and provider handles remain private.
    pub fn can_open_event_content(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.content_grant(scope, topic, epoch).is_some()
    }

    /// Verifies an opaque authority-signed public registry and resolves only
    /// high-level recipient identities/topic grants into a private fresh-rekey
    /// plan. No issuing seed, private recipient key, or generated scope key
    /// crosses this boundary.
    pub(crate) fn plan_scope_rekey_from_registry(
        &self,
        encoded_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        epoch: u64,
        recipients: Vec<ScopeRekeyRecipient>,
    ) -> Result<(ScopeRekeyPlan, u64), EnvelopeError> {
        self.ensure_live()?;
        if self.credential.roles & ROLE_CONTROL_AUTHORITY == 0 {
            return Err(EnvelopeError("node is not a control authority".into()));
        }
        let VerifiedRekeyRegistry {
            generation,
            authenticated_credentials: credentials,
            ..
        } = verify_rekey_registry(
            encoded_registry,
            minimum_registry_generation,
            &self.mission,
            self.authority_id,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        let plan = build_scope_rekey_plan(scope, epoch, recipients, credentials)?;
        Ok((plan, generation))
    }

    /// Returns whether this node has routing-only access for an epoch but no content grant.
    pub fn is_route_only(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.route_grant(scope, epoch).is_some()
            && self.content_grant(scope, topic, epoch).is_none()
    }

    /// Returns whether this node has an explicit content grant without the
    /// corresponding routing grant or signed route commitment.
    pub fn is_content_only(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.route_grant(scope, epoch).is_none()
            && self.content_grant(scope, topic, epoch).is_some()
    }

    /// Reports only whether the exact content capability is present. Key
    /// material and grant handles remain provider-owned.
    pub(crate) fn has_content_grant(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.content_grant(scope, topic, epoch).is_some()
    }

    /// Opens a high-level durable Blob service only when this provider owns the
    /// requested content grant. Key bytes and cryptographic controls remain internal.
    pub fn blob_service(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        store_path: impl AsRef<Path>,
        config: BlobStoreConfig,
    ) -> Result<ReferenceBlobService, EnvelopeError> {
        self.ensure_live()?;
        let grant = self
            .content_grant(scope, topic, epoch)
            .ok_or_else(|| EnvelopeError("content is not granted to this node".into()))?;
        let mut service = ReferenceBlobService::open_with_config(
            store_path,
            *grant.key.expose(),
            scope,
            topic,
            epoch,
            config,
        )
        .map_err(|error| EnvelopeError(format!("Blob service open failed: {error}")))?;
        service
            .bind_mission_authority_id(self.mission_authority_id())
            .map_err(|error| EnvelopeError(format!("Blob service bind failed: {error}")))?;
        Ok(service)
    }

    pub fn blob_service_with_defaults(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        store_path: impl AsRef<Path>,
    ) -> Result<ReferenceBlobService, EnvelopeError> {
        self.blob_service(scope, topic, epoch, store_path, BlobStoreConfig::default())
    }

    /// Binds an arbitrary durable Blob adapter to this provider's exact
    /// scope/topic/epoch content grant without exporting key material.
    pub fn blob_service_with_store<S: BlobStore>(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        store: S,
    ) -> Result<ReferenceBlobService<S>, EnvelopeError> {
        self.ensure_live()?;
        let grant = self
            .content_grant(scope, topic, epoch)
            .ok_or_else(|| EnvelopeError("content is not granted to this node".into()))?;
        Ok(ReferenceBlobService::from_store(
            store,
            *grant.key.expose(),
            scope,
            topic,
            epoch,
            self.mission_authority_id(),
        ))
    }

    /// Creates an authority-signed revocation notice. Ordinary node credentials are rejected.
    pub fn seal_revocation(
        &mut self,
        subject: NodeId,
        generation: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_revocation_chained(subject, generation, 1, None)
    }

    fn seal_revocation_chained(
        &mut self,
        subject: NodeId,
        generation: u64,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
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

    /// Creates a legacy authority-signed activation of an independently pre-provisioned epoch.
    ///
    /// This explicit format-0 operation does not exclude a captured node that already holds the
    /// future epoch. New deployments should use the recipient-filtered rekey control API through
    /// the authority node.
    pub fn seal_scope_epoch(
        &mut self,
        scope: &Scope,
        epoch: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_scope_epoch_chained(scope, epoch, 1, None)
    }

    fn seal_scope_epoch_chained(
        &mut self,
        scope: &Scope,
        epoch: u64,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if self.route_grant(scope, epoch).is_none() {
            return Err(EnvelopeError(
                "authority node lacks the requested pre-provisioned routing epoch".into(),
            ));
        }
        let mut body = self.control_prefix(EnvelopeKind::ScopeEpoch, sequence, previous)?;
        push_u16_bytes(&mut body, scope.as_str().as_bytes())?;
        body.extend_from_slice(&epoch.to_be_bytes());
        body.extend_from_slice(&SCOPE_EPOCH_LEGACY_FORMAT.to_be_bytes());
        self.seal_control(EnvelopeKind::ScopeEpoch, body)
    }

    pub(crate) fn seal_scope_rekey_chained(
        &mut self,
        plan: &ScopeRekeyPlan,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if plan.epoch == 0
            || plan.recipients.is_empty()
            || plan.recipients.len() > MAX_REKEY_RECIPIENTS
            || plan
                .recipients
                .windows(2)
                .any(|pair| pair[0].request.node >= pair[1].request.node)
        {
            return Err(EnvelopeError("invalid scope rekey plan".into()));
        }
        let format = plan.wire_format();
        let mut prepared = Vec::with_capacity(plan.recipients.len());
        let mut unique_topics = BTreeSet::new();
        for planned in &plan.recipients {
            let credential = &planned.credential;
            if credential.identity != planned.request.node
                || (planned.request.route_access && credential.roles & ROLE_RELAY == 0)
                || (!planned.request.readable_topics.is_empty()
                    && credential.roles & ROLE_READER == 0)
                || (!planned.request.route_access && planned.request.readable_topics.is_empty())
                || planned.request.readable_topics.len() > MAX_REKEY_TOPICS_PER_RECIPIENT
                || planned
                    .request
                    .readable_topics
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(authentication_failed());
            }
            unique_topics.extend(planned.request.readable_topics.iter().cloned());
            if unique_topics.len() > MAX_GRANTS {
                return Err(EnvelopeError("too many fresh scope topic keys".into()));
            }
            let credential_hash = rekey_credential_hash(credential)?;
            let grant_salt = random_secret(&mut self.provider)?;
            let grant_commitment = rekey_grant_commitment(
                format,
                &plan.scope,
                plan.epoch,
                credential.identity,
                &credential_hash,
                &grant_salt,
                planned.request.route_access,
                &planned.request.readable_topics,
            )?;
            prepared.push(PreparedRekeyRecipient {
                request: planned.request.clone(),
                credential: credential.clone(),
                credential_hash,
                grant_salt,
                grant_commitment,
            });
        }
        let descriptors = prepared
            .iter()
            .map(|recipient| {
                (
                    recipient.request.node,
                    recipient.credential_hash,
                    recipient.grant_commitment,
                    recipient.request.route_access,
                )
            })
            .collect::<Vec<_>>();
        let package_set_hash = rekey_package_set_hash(format, &descriptors)?;
        let route_key = prepared
            .iter()
            .any(|recipient| recipient.request.route_access)
            .then(|| random_secret(&mut self.provider))
            .transpose()?;
        let mut content_keys = BTreeMap::new();
        for topic in unique_topics {
            content_keys.insert(topic, random_secret(&mut self.provider)?);
        }

        let mut packages = Vec::with_capacity(prepared.len());
        for recipient in &prepared {
            let (ephemeral_secret, p256_ephemeral_public) = self
                .provider
                .generate_ecdh_keypair()
                .map_err(envelope_crypto_error)?;
            let classical = self
                .provider
                .ecdh_agree(
                    &ephemeral_secret,
                    &recipient.credential.p256_ecdh_public_key,
                )
                .map_err(envelope_crypto_error)?;
            let (ml_kem_768_ciphertext, post_quantum) = self
                .provider
                .kem_encapsulate(&recipient.credential.kem_public_key)
                .map_err(envelope_crypto_error)?;
            let mut package = DecodedRekeyPackage {
                recipient: recipient.request.node,
                credential_hash: recipient.credential_hash,
                grant_commitment: recipient.grant_commitment,
                route_access: recipient.request.route_access,
                p256_ephemeral_public,
                ml_kem_768_ciphertext,
                sealed_grants: AeadCiphertext {
                    nonce: [0u8; NONCE_LEN],
                    ciphertext: Vec::new(),
                },
            };
            let context = rekey_package_context(
                format,
                &self.mission,
                self.authority_id,
                &plan.scope,
                plan.epoch,
                sequence,
                previous,
                &package_set_hash,
                &package,
            )?;
            let package_key = derive_rekey_package_key(
                &self.provider,
                &classical,
                &post_quantum,
                &package_set_hash,
                &context,
            )?;
            let aad = rekey_package_aad(&context)?;
            let mut plaintext = encode_rekey_grants(
                format,
                &self.mission,
                self.authority_id,
                &plan.scope,
                plan.epoch,
                sequence,
                previous,
                &package_set_hash,
                &package,
                &recipient.grant_salt,
                if recipient.request.route_access {
                    route_key.as_ref()
                } else {
                    None
                },
                &content_keys,
                &recipient.request.readable_topics,
            )?;
            let sealed = self.provider.seal(&package_key, &plaintext, &aad);
            plaintext.zeroize();
            package.sealed_grants = sealed.map_err(envelope_crypto_error)?;
            packages.push(package);
        }

        let mut body = self.control_prefix(EnvelopeKind::ScopeEpoch, sequence, previous)?;
        push_u16_bytes(&mut body, plan.scope.as_str().as_bytes())?;
        body.extend_from_slice(&plan.epoch.to_be_bytes());
        body.extend_from_slice(&format.to_be_bytes());
        body.extend_from_slice(&package_set_hash);
        body.extend_from_slice(
            &u16::try_from(packages.len())
                .map_err(|_| invalid_envelope())?
                .to_be_bytes(),
        );
        for package in &packages {
            encode_rekey_package(&mut body, format, package)?;
        }
        self.seal_control(EnvelopeKind::ScopeEpoch, body)
    }

    fn seal_forwarding_internal(
        &mut self,
        recipient: NodeId,
        exchange_id: u64,
        envelope_id: crate::store::EnvelopeId,
        custody_age_ms: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.ensure_live()?;
        let mut signed = Vec::new();
        signed.extend_from_slice(&self.mission);
        signed.extend_from_slice(&self.credential.identity);
        signed.extend_from_slice(&recipient);
        signed.extend_from_slice(&exchange_id.to_be_bytes());
        signed.extend_from_slice(&envelope_id);
        signed.extend_from_slice(&custody_age_ms.to_be_bytes());
        let digest = hash_domain(FORWARDING_SIGNATURE_DOMAIN, &signed);
        let signature = self
            .provider
            .sign(&self.signing_key, &digest)
            .map_err(envelope_crypto_error)?;

        let mut plaintext = Vec::new();
        push_u32_bytes(&mut plaintext, &self.credential.body)?;
        encode_signature(&mut plaintext, &self.credential.signature)?;
        plaintext.extend_from_slice(&recipient);
        plaintext.extend_from_slice(&exchange_id.to_be_bytes());
        plaintext.extend_from_slice(&envelope_id);
        plaintext.extend_from_slice(&custody_age_ms.to_be_bytes());
        encode_signature(&mut plaintext, &signature)?;
        if plaintext.len().saturating_add(GCM_TAG_LEN) > MAX_FORWARDING_CIPHERTEXT_LEN {
            plaintext.zeroize();
            return Err(EnvelopeError("forwarding metadata is too large".into()));
        }

        let mut selector = [0u8; SELECTOR_LEN];
        self.provider
            .fill_random(&mut selector)
            .map_err(envelope_crypto_error)?;
        let control_key = self
            .control_route_key
            .as_ref()
            .ok_or_else(authentication_failed)?;
        let route_key = derive_item_secret(control_key.expose(), FORWARDING_KEY_LABEL, &selector)?;
        let cipher_len = u32::try_from(plaintext.len().saturating_add(GCM_TAG_LEN))
            .map_err(|_| invalid_envelope())?;
        let mut public = Vec::with_capacity(FORWARDING_PUBLIC_HEADER_LEN);
        public.extend_from_slice(FORWARDING_MAGIC);
        public.extend_from_slice(&FORWARDING_FORMAT_VERSION.to_be_bytes());
        public.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        public.extend_from_slice(&SUITE_ID.to_be_bytes());
        public.extend_from_slice(&selector);
        public.extend_from_slice(&cipher_len.to_be_bytes());
        debug_assert_eq!(public.len(), FORWARDING_PUBLIC_HEADER_LEN);
        let ciphertext = self
            .provider
            .seal_with_nonce(&route_key, selector_nonce(&selector), &plaintext, &public)
            .map_err(envelope_crypto_error)?;
        plaintext.zeroize();
        public.extend_from_slice(&ciphertext);
        Ok(public)
    }

    fn inspect_forwarding_internal(
        &self,
        authenticated_sender: NodeId,
        recipient: NodeId,
        exchange_id: u64,
        envelope_id: crate::store::EnvelopeId,
        forwarding: &[u8],
    ) -> Result<u64, EnvelopeError> {
        self.ensure_live()?;
        let mut reader = Reader::new(forwarding);
        if reader.take(FORWARDING_MAGIC.len())? != FORWARDING_MAGIC
            || reader.u16()? != FORWARDING_FORMAT_VERSION
            || reader.u16()? != PROTOCOL_VERSION
            || reader.u16()? != SUITE_ID
        {
            return Err(authentication_failed());
        }
        let selector = reader.array::<SELECTOR_LEN>()?;
        let cipher_len = usize::try_from(reader.u32()?).map_err(|_| invalid_envelope())?;
        if reader.position() != FORWARDING_PUBLIC_HEADER_LEN
            || !(GCM_TAG_LEN..=MAX_FORWARDING_CIPHERTEXT_LEN).contains(&cipher_len)
        {
            return Err(authentication_failed());
        }
        let public = &forwarding[..FORWARDING_PUBLIC_HEADER_LEN];
        let ciphertext = reader.take(cipher_len)?;
        reader.finish()?;
        let control_key = self
            .control_route_key
            .as_ref()
            .ok_or_else(authentication_failed)?;
        let route_key = derive_item_secret(control_key.expose(), FORWARDING_KEY_LABEL, &selector)?;
        let mut plaintext = self
            .provider
            .open_parts(&route_key, selector_nonce(&selector), ciphertext, public)
            .map_err(envelope_crypto_error)?;
        let decoded = (|| {
            let mut inner = Reader::new(&plaintext);
            let credential_body = inner.u32_bytes(16 * 1024)?.to_vec();
            let credential_signature = decode_signature(&mut inner)?;
            let credential = decode_credential(
                credential_body,
                credential_signature,
                &self.mission,
                &self.authority_verifying_key,
                &self.provider,
            )?;
            let encoded_recipient = inner.array::<32>()?;
            let encoded_exchange = inner.u64()?;
            let encoded_envelope = inner.array::<32>()?;
            let custody_age_ms = inner.u64()?;
            let signature = decode_signature(&mut inner)?;
            inner.finish()?;
            if credential.identity != authenticated_sender
                || credential.roles & ROLE_RELAY == 0
                || encoded_recipient != recipient
                || encoded_exchange != exchange_id
                || encoded_envelope != envelope_id
            {
                return Err(authentication_failed());
            }
            let mut signed = Vec::new();
            signed.extend_from_slice(&self.mission);
            signed.extend_from_slice(&credential.identity);
            signed.extend_from_slice(&encoded_recipient);
            signed.extend_from_slice(&encoded_exchange.to_be_bytes());
            signed.extend_from_slice(&encoded_envelope);
            signed.extend_from_slice(&custody_age_ms.to_be_bytes());
            let digest = hash_domain(FORWARDING_SIGNATURE_DOMAIN, &signed);
            self.provider
                .verify(&credential.verifying_key, &digest, &signature)
                .map_err(envelope_crypto_error)?;
            Ok(custody_age_ms)
        })();
        plaintext.zeroize();
        decoded
    }

    fn ensure_live(&self) -> Result<(), EnvelopeError> {
        if self.zeroized {
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

    fn control_prefix(
        &self,
        kind: EnvelopeKind,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.ensure_live()?;
        if self.credential.roles & ROLE_CONTROL_AUTHORITY == 0 {
            return Err(EnvelopeError(
                "credential is not a control authority".into(),
            ));
        }
        let mut body = Vec::new();
        body.push(kind as u8);
        body.extend_from_slice(CONTROL_AUTHENTICATION_MAGIC);
        body.extend_from_slice(&CONTROL_AUTHENTICATION_FORMAT.to_be_bytes());
        body.extend_from_slice(&self.mission);
        body.extend_from_slice(&self.authority_id);
        push_u32_bytes(&mut body, &self.credential.body)?;
        encode_signature(&mut body, &self.credential.signature)?;
        if sequence == 0 || (sequence == 1) != previous.is_none() {
            return Err(EnvelopeError("invalid authority control chain link".into()));
        }
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
        mut unsigned_control: Vec<u8>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let digest = hash_domain(CONTROL_SIGNATURE_DOMAIN, &unsigned_control);
        let signature = self
            .provider
            .sign(&self.signing_key, &digest)
            .map_err(envelope_crypto_error)?;
        encode_signature(&mut unsigned_control, &signature)?;
        let mut selector = [0u8; SELECTOR_LEN];
        self.provider
            .fill_random(&mut selector)
            .map_err(envelope_crypto_error)?;
        let control_key = self
            .control_route_key
            .as_ref()
            .ok_or_else(authentication_failed)?;
        let route_key = derive_item_secret(control_key.expose(), ROUTE_KEY_LABEL, &selector)?;
        let prefix = encode_public_header(kind, selector, unsigned_control.len() + GCM_TAG_LEN, 0)?;
        let route_nonce = selector_nonce(&selector);
        let route_ciphertext = self
            .provider
            .seal_with_nonce(&route_key, route_nonce, &unsigned_control, &prefix)
            .map_err(envelope_crypto_error)?;
        unsigned_control.zeroize();
        let mut sealed = prefix;
        sealed.extend_from_slice(&route_ciphertext);
        Ok(sealed)
    }

    fn seal_data(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError> {
        self.ensure_live()?;
        validate_header_for_seal(request.header, request.payload, &self.credential.identity)?;
        let mut route_seed = *self
            .route_grant(&request.header.scope, request.header.key_epoch)
            .ok_or_else(|| EnvelopeError("no routing grant for scope epoch".into()))?
            .key
            .expose();
        let mut content_seed = *self
            .content_grant(
                &request.header.scope,
                &request.header.topic,
                request.header.key_epoch,
            )
            .ok_or_else(|| EnvelopeError("no content grant for topic epoch".into()))?
            .key
            .expose();

        let mut core = Vec::new();
        encode_header(&mut core, request.header)?;
        push_u64_bytes(&mut core, request.payload)?;
        if core.len() > MAX_CORE_LEN {
            core.zeroize();
            return Err(EnvelopeError("item core is too large".into()));
        }
        let item_id = hash_domain(ITEM_ID_DOMAIN, &core);
        let content_key = derive_item_secret(&content_seed, CONTENT_KEY_LABEL, &item_id)?;
        let content_nonce_full =
            derive_material::<32>(&content_seed, CONTENT_NONCE_LABEL, &item_id)?;
        content_seed.zeroize();
        let mut content_nonce = [0u8; NONCE_LEN];
        content_nonce.copy_from_slice(&content_nonce_full[..NONCE_LEN]);
        let content_aad = encode_content_aad(request.header.key_epoch, &item_id);
        let content_ciphertext = self
            .provider
            .seal_with_nonce(&content_key, content_nonce, &core, &content_aad)
            .map_err(envelope_crypto_error)?;
        core.zeroize();

        let batch_id = singleton_batch_id(&item_id, request.header)?;
        let signature_input = encode_singleton_manifest(&item_id, &batch_id, request.header)?;
        let signature_digest = hash_domain(ITEM_SIGNATURE_DOMAIN, &signature_input);
        let item_signature = self
            .provider
            .sign(&self.signing_key, &signature_digest)
            .map_err(envelope_crypto_error)?;
        let content_group = content_group_id(&request.header.scope, &request.header.topic);

        let mut route = Vec::new();
        route.push(EnvelopeKind::Data as u8);
        push_u32_bytes(&mut route, &self.credential.body)?;
        encode_signature(&mut route, &self.credential.signature)?;
        route.extend_from_slice(&item_id);
        encode_header(&mut route, request.header)?;
        route.extend_from_slice(&content_group);
        route.extend_from_slice(&content_nonce);
        route.extend_from_slice(&batch_id);
        let cipher_len = u64::try_from(content_ciphertext.len()).map_err(|_| invalid_envelope())?;
        route.extend_from_slice(&cipher_len.to_be_bytes());
        encode_signature(&mut route, &item_signature)?;
        if route.len() + GCM_TAG_LEN > MAX_ROUTE_CIPHERTEXT_LEN {
            route.zeroize();
            return Err(EnvelopeError(
                "protected route descriptor is too large".into(),
            ));
        }

        let mut selector = [0u8; SELECTOR_LEN];
        self.provider
            .fill_random(&mut selector)
            .map_err(envelope_crypto_error)?;
        let route_key = derive_item_secret(&route_seed, ROUTE_KEY_LABEL, &selector)?;
        route_seed.zeroize();
        let prefix = encode_public_header(
            EnvelopeKind::Data,
            selector,
            route.len() + GCM_TAG_LEN,
            content_ciphertext.len(),
        )?;
        let route_ciphertext = self
            .provider
            .seal_with_nonce(&route_key, selector_nonce(&selector), &route, &prefix)
            .map_err(envelope_crypto_error)?;
        route.zeroize();
        let final_len = prefix
            .len()
            .checked_add(route_ciphertext.len())
            .and_then(|value| value.checked_add(content_ciphertext.len()))
            .ok_or_else(invalid_envelope)?;
        let mut bytes = Vec::with_capacity(final_len);
        bytes.extend_from_slice(&prefix);
        bytes.extend_from_slice(&route_ciphertext);
        bytes.extend_from_slice(&content_ciphertext);
        Ok(SealedEnvelope { id: item_id, bytes })
    }

    fn inspect_data_internal<'a>(
        &self,
        sealed: &'a [u8],
    ) -> Result<(VerifiedEnvelope, ParsedEnvelope<'a>, DecodedDataRoute), EnvelopeError> {
        self.ensure_live()?;
        let parsed = parse_envelope(sealed)?;
        if parsed.kind != EnvelopeKind::Data {
            return Err(EnvelopeError("expected a data envelope".into()));
        }
        let route = self.open_data_route(&parsed)?;
        let verified = self.verify_decoded_data_route(&parsed, &route)?;
        Ok((verified, parsed, route))
    }

    pub(crate) fn inspect_source_route_with_lineage(
        &self,
        sealed: &[u8],
    ) -> Result<(VerifiedEnvelope, [u8; 32]), EnvelopeError> {
        self.ensure_live()?;
        let parsed = parse_envelope(sealed)?;
        if parsed.kind != EnvelopeKind::Data {
            return Err(EnvelopeError("expected a data envelope".into()));
        }
        let (route, mut exact_plaintext, lineage) =
            self.open_data_route_exact_with_lineage(&parsed)?;
        let verified = self.verify_decoded_data_route(&parsed, &route);
        exact_plaintext.zeroize();
        verified.map(|verified| (verified, lineage))
    }

    pub(crate) fn inspect_event_route_with_lineage(
        &self,
        sealed: &[u8],
    ) -> Result<(VerifiedEnvelope, [u8; 32]), EnvelopeError> {
        self.inspect_source_route_with_lineage(sealed)
    }

    fn verify_decoded_data_route(
        &self,
        parsed: &ParsedEnvelope<'_>,
        route: &DecodedDataRoute,
    ) -> Result<VerifiedEnvelope, EnvelopeError> {
        if route.header.stamp.dot.publisher != route.credential.identity
            || route.content_ciphertext_len
                != u64::try_from(parsed.content_ciphertext.len()).map_err(|_| invalid_envelope())?
            || route.content_group != content_group_id(&route.header.scope, &route.header.topic)
            || route.batch_id != singleton_batch_id(&route.item_id, &route.header)?
        {
            return Err(authentication_failed());
        }
        let manifest = encode_singleton_manifest(&route.item_id, &route.batch_id, &route.header)?;
        let digest = hash_domain(ITEM_SIGNATURE_DOMAIN, &manifest);
        self.provider
            .verify(
                &route.credential.verifying_key,
                &digest,
                &route.item_signature,
            )
            .map_err(envelope_crypto_error)?;
        Ok(VerifiedEnvelope {
            id: route.item_id,
            header: route.header.clone(),
        })
    }

    fn open_data_route(
        &self,
        parsed: &ParsedEnvelope<'_>,
    ) -> Result<DecodedDataRoute, EnvelopeError> {
        let (route, mut exact_plaintext) = self.open_data_route_exact(parsed)?;
        exact_plaintext.zeroize();
        Ok(route)
    }

    fn open_data_route_exact(
        &self,
        parsed: &ParsedEnvelope<'_>,
    ) -> Result<(DecodedDataRoute, Vec<u8>), EnvelopeError> {
        self.open_data_route_exact_with_lineage(parsed)
            .map(|(route, plaintext, _)| (route, plaintext))
    }

    fn open_data_route_exact_with_lineage(
        &self,
        parsed: &ParsedEnvelope<'_>,
    ) -> Result<(DecodedDataRoute, Vec<u8>, [u8; 32]), EnvelopeError> {
        for grant in &self.route_grants {
            let route_key =
                derive_item_secret(grant.key.expose(), ROUTE_KEY_LABEL, &parsed.selector)?;
            let plaintext = self.provider.open_parts(
                &route_key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            );
            let Ok(mut plaintext) = plaintext else {
                continue;
            };
            let decoded = decode_data_route(
                &plaintext,
                &self.mission,
                self.authority_id,
                &self.authority_verifying_key,
                &self.provider,
            );
            if let Ok(route) = decoded
                && route.header.scope == grant.scope
                && route.header.key_epoch == grant.epoch
            {
                let lineage = route_grant_commitment(&self.mission, grant);
                match lineage {
                    Ok(lineage) => return Ok((route, plaintext, lineage)),
                    Err(error) => {
                        plaintext.zeroize();
                        return Err(error);
                    }
                }
            }
            plaintext.zeroize();
        }
        Err(authentication_failed())
    }

    fn inspect_control_internal(&self, sealed: &[u8]) -> Result<DecodedControl, EnvelopeError> {
        self.ensure_live()?;
        let parsed = parse_envelope(sealed)?;
        if parsed.kind == EnvelopeKind::Data || !parsed.content_ciphertext.is_empty() {
            return Err(EnvelopeError("expected a control envelope".into()));
        }
        let control_seed = self
            .control_route_key
            .as_ref()
            .ok_or_else(authentication_failed)?;
        let route_key =
            derive_item_secret(control_seed.expose(), ROUTE_KEY_LABEL, &parsed.selector)?;
        let mut plaintext = self
            .provider
            .open_parts(
                &route_key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            )
            .map_err(envelope_crypto_error)?;
        let decoded = decode_control(
            &plaintext,
            parsed.kind,
            &self.mission,
            self.authority_id,
            &self.authority_verifying_key,
            &self.provider,
        );
        plaintext.zeroize();
        decoded
    }

    fn verified_control_from_decoded(
        &self,
        decoded: DecodedControl,
        sealed: &[u8],
    ) -> Result<(VerifiedControl, Option<Vec<NodeId>>), EnvelopeError> {
        match decoded {
            DecodedControl::Revocation {
                signer,
                sequence,
                previous,
                subject,
                generation,
            } => Ok((
                VerifiedControl::Revocation(Revocation {
                    subject,
                    authority: self.authority_id,
                    signer,
                    generation,
                    control_sequence: sequence,
                    previous_control: previous,
                    sealed_notice: sealed.to_vec(),
                    observed_at_ms: None,
                }),
                None,
            )),
            DecodedControl::ScopeEpoch {
                signer,
                sequence,
                previous,
                scope,
                epoch,
                keying,
            } => {
                let scope_rekey_recipient_nodes = match &keying {
                    ScopeEpochKeying::LegacyPreprovisioned => {
                        if self.route_grant(&scope, epoch).is_none() {
                            return Err(EnvelopeError(
                                "scope epoch was not independently pre-provisioned".into(),
                            ));
                        }
                        None
                    }
                    ScopeEpochKeying::RecipientPackages { packages, .. } => {
                        Some(packages.iter().map(|package| package.recipient).collect())
                    }
                };
                Ok((
                    VerifiedControl::ScopeEpoch(ScopeEpoch {
                        authority: self.authority_id,
                        signer,
                        scope,
                        epoch,
                        control_sequence: sequence,
                        previous_control: previous,
                        sealed_notice: sealed.to_vec(),
                    }),
                    scope_rekey_recipient_nodes,
                ))
            }
        }
    }

    pub(crate) fn inspect_control_with_scope_rekey_recipient_nodes(
        &self,
        sealed: &[u8],
    ) -> Result<(VerifiedControl, Option<Vec<NodeId>>), EnvelopeError> {
        let decoded = self.inspect_control_internal(sealed)?;
        self.verified_control_from_decoded(decoded, sealed)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_rekey_package(
        &self,
        format: u16,
        scope: &Scope,
        epoch: u64,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
        package_set_hash: &[u8; 32],
        package: &DecodedRekeyPackage,
    ) -> Result<DecodedRekeyGrants, EnvelopeError> {
        if package.recipient != self.credential.identity
            || package.credential_hash != rekey_credential_hash(&self.credential)?
        {
            return Err(authentication_failed());
        }
        let ecdh_secret = self
            .p256_ecdh_secret
            .as_ref()
            .ok_or_else(zeroized_service)?;
        let kem_key = self
            .kem_decapsulation_key
            .as_ref()
            .ok_or_else(zeroized_service)?;
        let classical = self
            .provider
            .ecdh_agree(ecdh_secret, &package.p256_ephemeral_public)
            .map_err(envelope_crypto_error)?;
        let post_quantum = self
            .provider
            .kem_decapsulate(kem_key, &package.ml_kem_768_ciphertext)
            .map_err(envelope_crypto_error)?;
        let context = rekey_package_context(
            format,
            &self.mission,
            self.authority_id,
            scope,
            epoch,
            sequence,
            previous,
            package_set_hash,
            package,
        )?;
        let package_key = derive_rekey_package_key(
            &self.provider,
            &classical,
            &post_quantum,
            package_set_hash,
            &context,
        )?;
        let aad = rekey_package_aad(&context)?;
        let mut plaintext = self
            .provider
            .open(&package_key, &package.sealed_grants, &aad)
            .map_err(envelope_crypto_error)?;
        let decoded = decode_rekey_grants(
            &plaintext,
            format,
            &self.mission,
            self.authority_id,
            scope,
            epoch,
            sequence,
            previous,
            package_set_hash,
            package,
        );
        plaintext.zeroize();
        decoded
    }

    fn activate_scope_epoch_control(
        &mut self,
        sealed: &[u8],
        local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        let DecodedControl::ScopeEpoch {
            signer: _,
            sequence,
            previous,
            scope,
            epoch,
            keying,
        } = self.inspect_control_internal(sealed)?
        else {
            return Ok(());
        };
        let ScopeEpochKeying::RecipientPackages {
            format,
            package_set_hash,
            packages,
        } = keying
        else {
            return Ok(());
        };
        let authorized_recipients = packages
            .iter()
            .filter(|package| package.route_access)
            .map(|package| package.recipient)
            .collect::<Vec<_>>();
        let replacement = if local_revoked {
            None
        } else {
            packages
                .iter()
                .find(|package| package.recipient == self.credential.identity)
                .map(|package| {
                    self.open_rekey_package(
                        format,
                        &scope,
                        epoch,
                        sequence,
                        previous,
                        &package_set_hash,
                        package,
                    )
                })
                .transpose()?
        };

        // Mutate only after the complete matching package has authenticated and decoded. Removing
        // an old pre-placed grant for nonrecipients is what makes capture exclusion effective.
        self.route_grants
            .retain(|grant| grant.scope != scope || grant.epoch != epoch);
        self.content_grants
            .retain(|grant| grant.scope != scope || grant.epoch != epoch);
        if let Some(replacement) = replacement {
            if let Some(route_key) = replacement.route_key {
                self.route_grants.push(RouteGrant {
                    scope: scope.clone(),
                    epoch,
                    key: route_key,
                });
            }
            for (topic, key) in replacement.content_keys {
                self.content_grants.push(ContentGrant {
                    scope: scope.clone(),
                    topic,
                    epoch,
                    key,
                });
            }
            self.route_grants
                .sort_by(|left, right| (&left.scope, left.epoch).cmp(&(&right.scope, right.epoch)));
            self.content_grants.sort_by(|left, right| {
                (&left.scope, &left.topic, left.epoch).cmp(&(
                    &right.scope,
                    &right.topic,
                    right.epoch,
                ))
            });
        }
        self.rekey_route_authorizations
            .insert((scope, epoch), authorized_recipients);
        Ok(())
    }

    fn erase(&mut self) {
        if self.zeroized {
            return;
        }
        self.signing_key.zeroize_key();
        self.control_route_key = None;
        self.p256_ecdh_secret = None;
        self.kem_decapsulation_key = None;
        self.route_grants.clear();
        self.content_grants.clear();
        self.rekey_route_authorizations.clear();
        self.credential.body.zeroize();
        self.credential.kem_public_key.zeroize();
        self.zeroized = true;
    }
}

#[allow(dead_code)]
impl ReferenceEnvelopeSealer {
    fn verify_bridge_edge_enrollment_internal(
        &self,
        bytes: &[u8],
    ) -> Result<VerifiedBridgeEdgeEnrollment, EnvelopeError> {
        self.ensure_live()?;
        if bytes.len() > MAX_BRIDGE_EDGE_ENROLLMENT_BYTES
            || self.credential.roles & ROLE_CONTROL_AUTHORITY == 0
        {
            return Err(authentication_failed());
        }
        let mut reader = Reader::new(bytes);
        if reader.take(BRIDGE_EDGE_ENROLLMENT_MAGIC.len())? != BRIDGE_EDGE_ENROLLMENT_MAGIC
            || reader.u16()? != BRIDGE_EDGE_ENROLLMENT_VERSION
            || reader.u16()? != PROTOCOL_VERSION
            || reader.u16()? != SUITE_ID
        {
            return Err(authentication_failed());
        }
        let mission_id = reader.array::<32>()?;
        let authority_id = reader.array::<32>()?;
        let bridge_node_id = reader.array::<32>()?;
        let source_scope = decode_scope(reader.u16_bytes(MAX_BRIDGE_EDGE_ENROLLMENT_SCOPE_BYTES)?)?;
        let source_route_epoch = reader.u64()?;
        let source_route_commitment = reader.array::<32>()?;
        let target_scope = decode_scope(reader.u16_bytes(MAX_BRIDGE_EDGE_ENROLLMENT_SCOPE_BYTES)?)?;
        let target_route_epoch = reader.u64()?;
        let target_route_commitment = reader.array::<32>()?;
        let bridge_credential = reader
            .u32_bytes(MAX_BRIDGE_EDGE_ENROLLMENT_CREDENTIAL_BYTES)?
            .to_vec();
        let authority_credential_signature = reader.take(bridge::HYBRID_SIGNATURE_BYTES)?.to_vec();
        let signed_end = reader.position();
        let bridge_signature_bytes = reader.take(bridge::HYBRID_SIGNATURE_BYTES)?;
        reader.finish()?;
        if mission_id != self.mission
            || authority_id != self.authority_id
            || source_scope == target_scope
            || source_route_epoch == 0
            || target_route_epoch == 0
        {
            return Err(authentication_failed());
        }
        let canonical = encode_bridge_edge_enrollment_body(
            &mission_id,
            &authority_id,
            &bridge_node_id,
            &source_scope,
            source_route_epoch,
            &source_route_commitment,
            &target_scope,
            target_route_epoch,
            &target_route_commitment,
            &bridge_credential,
            &authority_credential_signature,
        )?;
        if canonical.as_slice() != &bytes[..signed_end] {
            return Err(authentication_failed());
        }
        let credential_signature = decode_exact_hybrid_signature(&authority_credential_signature)?;
        let credential = decode_credential(
            bridge_credential.clone(),
            credential_signature,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        if credential.identity != bridge_node_id
            || credential.roles & ROLE_RELAY == 0
            || credential
                .route_grant_commitments
                .binary_search(&source_route_commitment)
                .is_err()
            || credential
                .route_grant_commitments
                .binary_search(&target_route_commitment)
                .is_err()
        {
            return Err(authentication_failed());
        }
        let bridge_signature = decode_exact_hybrid_signature(bridge_signature_bytes)?;
        let digest = hash_domain(
            BRIDGE_EDGE_ENROLLMENT_SIGNATURE_DOMAIN,
            &bytes[..signed_end],
        );
        self.provider
            .verify(&credential.verifying_key, &digest, &bridge_signature)
            .map_err(envelope_crypto_error)?;
        self.require_local_bridge_route_commitment(
            &source_scope,
            source_route_epoch,
            &source_route_commitment,
        )?;
        self.require_local_bridge_route_commitment(
            &target_scope,
            target_route_epoch,
            &target_route_commitment,
        )?;
        Ok(VerifiedBridgeEdgeEnrollment {
            claims: BridgeEdgeEnrollmentClaims {
                mission_id,
                bridge_node_id,
                source_scope,
                source_route_epoch,
                target_scope,
                target_route_epoch,
            },
            source_route_commitment,
            target_route_commitment,
            bridge_credential,
            authority_credential_signature,
        })
    }

    fn verify_bridge_authorization_internal(
        &self,
        authorization: &BridgeAuthorization,
    ) -> Result<(Option<HybridVerifyingKey>, NodeId), EnvelopeError> {
        self.ensure_live()?;
        authorization
            .validate()
            .map_err(bridge_authentication_error)?;
        if authorization.mission_id != self.mission
            || authorization.authority_id != self.authority_id
        {
            return Err(authentication_failed());
        }

        let control_authentication = bridge::decode_delegated_control_authentication(
            &authorization.authority_control_signature,
        )
        .map_err(bridge_authentication_error)?;
        let authority_credential_signature =
            decode_exact_hybrid_signature(&control_authentication.authority_credential_signature)?;
        let control_credential = decode_credential(
            control_authentication.credential_body.clone(),
            authority_credential_signature,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        if control_credential.roles & ROLE_CONTROL_AUTHORITY == 0 {
            return Err(authentication_failed());
        }
        let control_signature =
            decode_exact_hybrid_signature(&control_authentication.control_signature)?;
        let control_digest = authorization
            .control_signature_digest(
                &control_authentication.credential_body,
                &control_authentication.authority_credential_signature,
            )
            .map_err(bridge_authentication_error)?;
        self.provider
            .verify(
                &control_credential.verifying_key,
                &control_digest,
                &control_signature,
            )
            .map_err(envelope_crypto_error)?;

        let Some(enabled) = &authorization.enabled else {
            return Ok((None, control_credential.identity));
        };
        let credential_signature =
            decode_exact_hybrid_signature(&enabled.authority_credential_signature)?;
        let credential = decode_credential(
            enabled.bridge_credential.clone(),
            credential_signature,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        if credential.identity != authorization.bridge_node_id
            || credential.roles & ROLE_RELAY == 0
            || credential
                .route_grant_commitments
                .binary_search(&enabled.source_route_commitment)
                .is_err()
            || credential
                .route_grant_commitments
                .binary_search(&enabled.target_route_commitment)
                .is_err()
        {
            return Err(authentication_failed());
        }
        self.verify_local_bridge_route_commitment(
            &authorization.source_scope,
            enabled.source_route_epoch,
            &enabled.source_route_commitment,
        )?;
        self.verify_local_bridge_route_commitment(
            &authorization.target_scope,
            enabled.target_route_epoch,
            &enabled.target_route_commitment,
        )?;
        Ok((Some(credential.verifying_key), control_credential.identity))
    }

    fn verify_local_bridge_route_commitment(
        &self,
        scope: &Scope,
        epoch: u64,
        expected: &[u8; 32],
    ) -> Result<(), EnvelopeError> {
        if let Some(grant) = self.route_grant(scope, epoch)
            && route_grant_commitment(&self.mission, grant)? != *expected
        {
            return Err(authentication_failed());
        }
        Ok(())
    }

    fn require_local_bridge_route_commitment(
        &self,
        scope: &Scope,
        epoch: u64,
        expected: &[u8; 32],
    ) -> Result<(), EnvelopeError> {
        let grant = self
            .route_grant(scope, epoch)
            .ok_or_else(authentication_failed)?;
        if route_grant_commitment(&self.mission, grant)? != *expected {
            return Err(authentication_failed());
        }
        Ok(())
    }

    fn build_verified_bridge_source(
        &self,
        source_envelope: &[u8],
        parsed: &ParsedEnvelope<'_>,
        route: DecodedDataRoute,
        mut exact_route_descriptor: Vec<u8>,
        wrapper_envelope_id: Option<[u8; 32]>,
    ) -> Result<VerifiedBridgeSourceRoute, EnvelopeError> {
        let result = (|| {
            if exact_route_descriptor.is_empty()
                || exact_route_descriptor.len() > bridge::MAX_SOURCE_DESCRIPTOR_BYTES
            {
                return Err(authentication_failed());
            }
            let verified = self.verify_decoded_data_route(parsed, &route)?;
            Ok(VerifiedBridgeSourceRoute {
                mission_id: self.mission,
                wrapper_envelope_id,
                origin_envelope_id: bridge::exact_object_id(source_envelope),
                source_item_id: verified.id,
                header: verified.header,
                exact_route_descriptor: std::mem::take(&mut exact_route_descriptor),
                content_nonce: route.content_nonce,
                content_ciphertext_len: route.content_ciphertext_len,
            })
        })();
        exact_route_descriptor.zeroize();
        result
    }

    fn source_matches_bridge_route(
        route: &BridgeRoute,
        source: &VerifiedBridgeSourceRoute,
    ) -> Result<(), EnvelopeError> {
        if route.mission_id != source.mission_id
            || route.origin_envelope_id != source.origin_envelope_id
            || route.source_item_id != source.source_item_id
            || route.origin_scope != source.header.scope
            || route.origin_route_epoch != source.header.key_epoch
            || route.source_route_descriptor != source.exact_route_descriptor
        {
            return Err(authentication_failed());
        }
        Ok(())
    }

    fn verify_copied_bridge_source(
        &self,
        source_envelope: &[u8],
        exact_route_descriptor: &[u8],
        wrapper_envelope_id: Option<[u8; 32]>,
    ) -> Result<VerifiedBridgeSourceRoute, EnvelopeError> {
        if exact_route_descriptor.is_empty()
            || exact_route_descriptor.len() > bridge::MAX_SOURCE_DESCRIPTOR_BYTES
        {
            return Err(authentication_failed());
        }
        let parsed = parse_envelope(source_envelope)?;
        if parsed.kind != EnvelopeKind::Data {
            return Err(authentication_failed());
        }
        let route = decode_data_route(
            exact_route_descriptor,
            &self.mission,
            self.authority_id,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        self.build_verified_bridge_source(
            source_envelope,
            &parsed,
            route,
            exact_route_descriptor.to_vec(),
            wrapper_envelope_id,
        )
    }

    fn open_verified_content(
        &self,
        item_id: &[u8; 32],
        header: &EnvelopeHeader,
        content_nonce: [u8; NONCE_LEN],
        content_ciphertext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let content_seed = self
            .content_grant(&header.scope, &header.topic, header.key_epoch)
            .ok_or_else(|| EnvelopeError("content is not granted to this node".into()))?;
        let content_key =
            derive_item_secret(content_seed.key.expose(), CONTENT_KEY_LABEL, item_id)?;
        let expected_nonce_full =
            derive_material::<32>(content_seed.key.expose(), CONTENT_NONCE_LABEL, item_id)?;
        if content_nonce != expected_nonce_full[..NONCE_LEN] {
            return Err(authentication_failed());
        }
        let aad = encode_content_aad(header.key_epoch, item_id);
        let mut core = self
            .provider
            .open_parts(&content_key, content_nonce, content_ciphertext, &aad)
            .map_err(envelope_crypto_error)?;
        if hash_domain(ITEM_ID_DOMAIN, &core) != *item_id {
            core.zeroize();
            return Err(authentication_failed());
        }
        let decoded = decode_core(&core);
        core.zeroize();
        let (decoded_header, payload) = decoded?;
        if &decoded_header != header {
            return Err(authentication_failed());
        }
        Ok(payload)
    }

    fn prepare_batch_item(
        &self,
        request: &SealRequest<'_>,
        item_index: u16,
    ) -> Result<PreparedBatchItem, EnvelopeError> {
        validate_header_for_seal(request.header, request.payload, &self.credential.identity)?;
        let content_seed = self
            .content_grant(
                &request.header.scope,
                &request.header.topic,
                request.header.key_epoch,
            )
            .ok_or_else(|| EnvelopeError("no content grant for batch topic epoch".into()))?;
        let mut core = Vec::new();
        encode_header(&mut core, request.header)?;
        push_u64_bytes(&mut core, request.payload)?;
        if core.len() > MAX_CORE_LEN {
            core.zeroize();
            return Err(EnvelopeError("batch item core is too large".into()));
        }
        let result = (|| {
            let item_id = hash_domain(ITEM_ID_DOMAIN, &core);
            let content_key =
                derive_item_secret(content_seed.key.expose(), CONTENT_KEY_LABEL, &item_id)?;
            let mut nonce_material =
                derive_material::<32>(content_seed.key.expose(), CONTENT_NONCE_LABEL, &item_id)?;
            let mut content_nonce = [0u8; NONCE_LEN];
            content_nonce.copy_from_slice(&nonce_material[..NONCE_LEN]);
            nonce_material.zeroize();
            let content_ciphertext = self
                .provider
                .seal_with_nonce(
                    &content_key,
                    content_nonce,
                    &core,
                    &encode_content_aad(request.header.key_epoch, &item_id),
                )
                .map_err(envelope_crypto_error)?;
            let mut canonical_header = Vec::new();
            encode_header(&mut canonical_header, request.header)?;
            let leaf = batch::BatchLeaf::from_ciphertext(
                item_index,
                item_id,
                canonical_header,
                content_group_id(&request.header.scope, &request.header.topic),
                content_nonce,
                &content_ciphertext,
            )
            .map_err(batch_construction_error)?;
            Ok(PreparedBatchItem {
                item_id,
                header: request.header.clone(),
                content_nonce,
                content_ciphertext,
                leaf,
            })
        })();
        core.zeroize();
        result
    }

    fn seal_batch_envelope(
        &mut self,
        object_kind: u8,
        scope: &Scope,
        route_epoch: u64,
        route_plaintext: &[u8],
        content_ciphertext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let mut selector = [0u8; SELECTOR_LEN];
        self.provider
            .fill_random(&mut selector)
            .map_err(envelope_crypto_error)?;
        let route_grant = self
            .route_grant(scope, route_epoch)
            .ok_or_else(|| EnvelopeError("no routing grant for batch scope epoch".into()))?;
        let route_key = derive_item_secret(route_grant.key.expose(), ROUTE_KEY_LABEL, &selector)?;
        let public_header = encode_batch_public_header(
            object_kind,
            selector,
            route_plaintext.len().saturating_add(GCM_TAG_LEN),
            content_ciphertext.len(),
        )?;
        let route_ciphertext = self
            .provider
            .seal_with_nonce(
                &route_key,
                selector_nonce(&selector),
                route_plaintext,
                &public_header,
            )
            .map_err(envelope_crypto_error)?;
        let capacity = public_header
            .len()
            .checked_add(route_ciphertext.len())
            .and_then(|value| value.checked_add(content_ciphertext.len()))
            .ok_or_else(invalid_envelope)?;
        let mut sealed = Vec::with_capacity(capacity);
        sealed.extend_from_slice(&public_header);
        sealed.extend_from_slice(&route_ciphertext);
        sealed.extend_from_slice(content_ciphertext);
        Ok(sealed)
    }

    fn open_batch_route_for_any_local_grant<'a>(
        &'a self,
        parsed: &ParsedBatchEnvelope<'_>,
    ) -> Result<(&'a RouteGrant, Vec<u8>), EnvelopeError> {
        for route_grant in &self.route_grants {
            let Ok(route_key) =
                derive_item_secret(route_grant.key.expose(), ROUTE_KEY_LABEL, &parsed.selector)
            else {
                continue;
            };
            let Ok(plaintext) = self.provider.open_parts(
                &route_key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            ) else {
                continue;
            };
            return Ok((route_grant, plaintext));
        }
        Err(authentication_failed())
    }

    fn sign_batch_item_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<[u8; batch::ITEM_SIGNATURE_BYTES], EnvelopeError> {
        let signing_key = self
            .signing_key
            .p256
            .as_ref()
            .ok_or_else(zeroized_service)?;
        let signature: P256Signature = P256Signer::try_sign(signing_key, digest)
            .map_err(|_| EnvelopeError("P-256 batch item signing failed".into()))?;
        Ok(signature.to_bytes().into())
    }

    fn verify_batch_item_digest(
        &self,
        p256_verifying_key: &[u8],
        digest: &[u8; 32],
        signature: &[u8; batch::ITEM_SIGNATURE_BYTES],
    ) -> Result<(), EnvelopeError> {
        let verifying_key = P256VerifyingKey::from_sec1_bytes(p256_verifying_key)
            .map_err(|_| authentication_failed())?;
        let signature =
            P256Signature::from_slice(signature).map_err(|_| authentication_failed())?;
        P256Verifier::verify(&verifying_key, digest, &signature)
            .map_err(|_| authentication_failed())
    }
}

impl BatchCryptoProvider for ReferenceEnvelopeSealer {
    type Error = EnvelopeError;
    type PendingItem = PendingBatchItem;
    type VerifiedProof = VerifiedBatchProof;
    type VerifiedItem = VerifiedBatchItem;

    fn seal_source_batch(
        &mut self,
        requests: &[SealRequest<'_>],
    ) -> Result<SealedSourceBatch, Self::Error> {
        self.ensure_live()?;
        let item_count = u16::try_from(requests.len()).map_err(|_| invalid_envelope())?;
        if !(batch::MIN_BATCH_ITEMS..=batch::MAX_BATCH_ITEMS).contains(&item_count) {
            return Err(EnvelopeError("invalid source batch size".into()));
        }
        let first = requests.first().ok_or_else(invalid_envelope)?;
        if self
            .route_grant(&first.header.scope, first.header.key_epoch)
            .is_none()
        {
            return Err(EnvelopeError(
                "no routing grant for batch scope epoch".into(),
            ));
        }
        let first_counter = first.header.stamp.dot.counter;
        let first_event_sequence = if first.header.class == DataClass::Event {
            first
                .header
                .event_sequence
                .ok_or_else(|| EnvelopeError("event batch lacks an event sequence".into()))?
        } else {
            0
        };
        let mut prepared = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            let index_u16 = u16::try_from(index).map_err(|_| invalid_envelope())?;
            let index_u64 = u64::try_from(index).map_err(|_| invalid_envelope())?;
            let expected_counter = first_counter
                .checked_add(index_u64)
                .ok_or_else(invalid_envelope)?;
            let expected_event_sequence = if first.header.class == DataClass::Event {
                Some(
                    first_event_sequence
                        .checked_add(index_u64)
                        .ok_or_else(invalid_envelope)?,
                )
            } else {
                None
            };
            if request.header.class != first.header.class
                || request.header.topic != first.header.topic
                || request.header.scope != first.header.scope
                || request.header.key_epoch != first.header.key_epoch
                || request.header.stamp.dot.publisher != self.credential.identity
                || request.header.stamp.dot.counter != expected_counter
                || request.header.event_sequence != expected_event_sequence
            {
                return Err(EnvelopeError(
                    "source batch crosses a mandatory manifest boundary".into(),
                ));
            }
            prepared.push(self.prepare_batch_item(request, index_u16)?);
        }

        let authority_signature = encode_exact_hybrid_signature(&self.credential.signature)?;
        let credential_id = batch::credential_id(&self.credential.body, &authority_signature)
            .map_err(batch_construction_error)?;
        let preamble = batch::BatchPreamble {
            data_class: first.header.class as u8,
            credential_id,
            publisher: self.credential.identity,
            topic: first.header.topic.as_str().to_owned(),
            scope: first.header.scope.as_str().to_owned(),
            key_epoch: first.header.key_epoch,
            first_causal_counter: first_counter,
            first_event_sequence,
            item_count,
        };
        let leaves = prepared
            .iter()
            .map(|item| item.leaf.clone())
            .collect::<Vec<_>>();
        let tree =
            batch::BatchMerkleTree::build(&preamble, &leaves).map_err(batch_construction_error)?;
        let manifest = batch::BatchManifest {
            preamble,
            merkle_root: tree.root,
        };
        let batch_id = manifest.batch_id().map_err(batch_construction_error)?;
        let source_signature = self
            .provider
            .sign(
                &self.signing_key,
                &manifest
                    .signature_digest()
                    .map_err(batch_construction_error)?,
            )
            .map_err(envelope_crypto_error)?;
        let proof_route = batch::BatchProofRoute {
            credential_body: self.credential.body.clone(),
            authority_signature,
            manifest: manifest.clone(),
            source_signature: encode_exact_hybrid_signature(&source_signature)?,
        };
        let mut proof_plaintext = proof_route.encode().map_err(batch_construction_error)?;
        let proof_result = self.seal_batch_envelope(
            batch::OBJECT_KIND_BATCH_PROOF,
            &first.header.scope,
            first.header.key_epoch,
            &proof_plaintext,
            &[],
        );
        proof_plaintext.zeroize();
        let proof_bytes = proof_result?;
        let proof_envelope_id = batch::proof_envelope_id(&proof_bytes);

        let mut sealed_items = Vec::with_capacity(prepared.len());
        for item in prepared {
            let mut authentication = batch::CompactAuthentication {
                proof_envelope_id,
                batch_id,
                item_index: item.leaf.item_index,
                siblings: tree
                    .path(item.leaf.item_index)
                    .map_err(batch_construction_error)?
                    .to_vec(),
                item_signature: [0u8; batch::ITEM_SIGNATURE_BYTES],
            };
            let leaf_hash = item.leaf.leaf_hash().map_err(batch_construction_error)?;
            let signature_digest = authentication
                .signature_digest(leaf_hash)
                .map_err(batch_construction_error)?;
            authentication.item_signature = self.sign_batch_item_digest(&signature_digest)?;
            let route = DecodedCompactBatchRoute {
                item_id: item.item_id,
                header: item.header.clone(),
                content_group: item.leaf.content_group,
                content_nonce: item.content_nonce,
                content_ciphertext_len: item.leaf.content_ciphertext_length,
                authentication,
            };
            let mut route_plaintext = encode_compact_batch_route(&route)?;
            let sealed_result = self.seal_batch_envelope(
                EnvelopeKind::Data as u8,
                &item.header.scope,
                item.header.key_epoch,
                &route_plaintext,
                &item.content_ciphertext,
            );
            route_plaintext.zeroize();
            let bytes = sealed_result?;
            sealed_items.push(SealedBatchItem {
                item_id: item.item_id,
                envelope_id: batch::proof_envelope_id(&bytes),
                bytes,
            });
        }
        Ok(SealedSourceBatch {
            batch_id,
            proof_envelope_id,
            proof_bytes,
            items: sealed_items,
        })
    }

    fn open_batch_proof(
        &self,
        sealed: &[u8],
        selected_semantic_version: u16,
    ) -> Result<Self::VerifiedProof, Self::Error> {
        self.ensure_live()?;
        let parsed = parse_batch_envelope(sealed, selected_semantic_version)?;
        if parsed.object_kind != batch::OBJECT_KIND_BATCH_PROOF {
            return Err(authentication_failed());
        }
        let (route_grant, mut plaintext) = self.open_batch_route_for_any_local_grant(&parsed)?;
        let decoded = batch::BatchProofRoute::decode(&plaintext)
            .map_err(batch_authentication_error)
            .and_then(|route| {
                if route.encode().map_err(batch_authentication_error)? != plaintext {
                    return Err(authentication_failed());
                }
                Ok(route)
            });
        plaintext.zeroize();
        let route = decoded?;
        if route.manifest.preamble.scope != route_grant.scope.as_str()
            || route.manifest.preamble.key_epoch != route_grant.epoch
        {
            return Err(authentication_failed());
        }
        let authority_signature = decode_exact_hybrid_signature(&route.authority_signature)?;
        let credential = decode_credential(
            route.credential_body.clone(),
            authority_signature,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        let route_commitment = route_grant_commitment(&self.mission, route_grant)?;
        if credential.identity != route.manifest.preamble.publisher
            || credential.roles & ROLE_RELAY == 0
            || credential
                .route_grant_commitments
                .binary_search(&route_commitment)
                .is_err()
        {
            return Err(authentication_failed());
        }
        let source_signature = decode_exact_hybrid_signature(&route.source_signature)?;
        self.provider
            .verify(
                &credential.verifying_key,
                &route
                    .manifest
                    .signature_digest()
                    .map_err(batch_authentication_error)?,
                &source_signature,
            )
            .map_err(envelope_crypto_error)?;
        let batch_id = route
            .manifest
            .batch_id()
            .map_err(batch_authentication_error)?;
        Ok(VerifiedBatchProof {
            proof_envelope_id: batch::proof_envelope_id(sealed),
            batch_id,
            manifest: route.manifest,
            publisher: credential.identity,
            p256_verifying_key: credential.verifying_key.p256_sec1,
        })
    }

    fn open_compact_batch_item(
        &self,
        sealed: &[u8],
        selected_semantic_version: u16,
    ) -> Result<Self::PendingItem, Self::Error> {
        self.ensure_live()?;
        let parsed = parse_batch_envelope(sealed, selected_semantic_version)?;
        if parsed.object_kind != EnvelopeKind::Data as u8 {
            return Err(authentication_failed());
        }
        let (route_grant, mut plaintext) = self.open_batch_route_for_any_local_grant(&parsed)?;
        let decoded = decode_compact_batch_route(&plaintext);
        plaintext.zeroize();
        let route = decoded?;
        if route.header.scope != route_grant.scope
            || route.header.key_epoch != route_grant.epoch
            || route.content_group != content_group_id(&route.header.scope, &route.header.topic)
            || route.content_ciphertext_len
                != u64::try_from(parsed.content_ciphertext.len())
                    .map_err(|_| authentication_failed())?
        {
            return Err(authentication_failed());
        }
        Ok(PendingBatchItem {
            envelope_id: batch::proof_envelope_id(sealed),
            item_id: route.item_id,
            header: route.header,
            content_group: route.content_group,
            content_nonce: route.content_nonce,
            content_ciphertext_len: route.content_ciphertext_len,
            authentication: route.authentication,
        })
    }

    fn pending_batch_proof_id(&self, pending: &Self::PendingItem) -> [u8; 32] {
        pending.authentication.proof_envelope_id
    }

    fn verify_compact_batch_item(
        &self,
        pending: &Self::PendingItem,
        proof: Option<&Self::VerifiedProof>,
        sealed: &[u8],
    ) -> Result<Self::VerifiedItem, Self::Error> {
        self.ensure_live()?;
        let proof = proof.ok_or_else(authentication_failed)?;
        if pending.envelope_id != batch::proof_envelope_id(sealed)
            || pending.authentication.proof_envelope_id != proof.proof_envelope_id
            || pending.authentication.batch_id != proof.batch_id
        {
            return Err(authentication_failed());
        }
        let parsed = parse_batch_envelope(sealed, batch::SEMANTIC_PROTOCOL_VERSION)?;
        if parsed.object_kind != EnvelopeKind::Data as u8
            || pending.content_ciphertext_len
                != u64::try_from(parsed.content_ciphertext.len())
                    .map_err(|_| authentication_failed())?
        {
            return Err(authentication_failed());
        }
        let route = DecodedCompactBatchRoute {
            item_id: pending.item_id,
            header: pending.header.clone(),
            content_group: pending.content_group,
            content_nonce: pending.content_nonce,
            content_ciphertext_len: pending.content_ciphertext_len,
            authentication: pending.authentication.clone(),
        };
        validate_compact_manifest_binding(&route, &proof.manifest)?;
        if route.header.stamp.dot.publisher != proof.publisher {
            return Err(authentication_failed());
        }
        let mut canonical_header = Vec::new();
        encode_header(&mut canonical_header, &route.header)?;
        let leaf = batch::BatchLeaf::from_ciphertext(
            route.authentication.item_index,
            route.item_id,
            canonical_header,
            route.content_group,
            route.content_nonce,
            parsed.content_ciphertext,
        )
        .map_err(batch_authentication_error)?;
        let signature_digest = batch::verify_compact_commitment(
            &proof.manifest,
            proof.proof_envelope_id,
            &leaf,
            parsed.content_ciphertext,
            &route.authentication,
        )
        .map_err(batch_authentication_error)?;
        self.verify_batch_item_digest(
            &proof.p256_verifying_key,
            &signature_digest,
            &route.authentication.item_signature,
        )?;
        Ok(VerifiedBatchItem {
            envelope_id: pending.envelope_id,
            proof_envelope_id: proof.proof_envelope_id,
            batch_id: proof.batch_id,
            item_id: pending.item_id,
            header: pending.header.clone(),
            content_nonce: pending.content_nonce,
            content_ciphertext_len: pending.content_ciphertext_len,
        })
    }

    fn open_compact_batch_payload(
        &self,
        verified: &Self::VerifiedItem,
        sealed: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.ensure_live()?;
        if verified.envelope_id != batch::proof_envelope_id(sealed) {
            return Err(authentication_failed());
        }
        let parsed = parse_batch_envelope(sealed, batch::SEMANTIC_PROTOCOL_VERSION)?;
        if parsed.object_kind != EnvelopeKind::Data as u8
            || verified.content_ciphertext_len
                != u64::try_from(parsed.content_ciphertext.len())
                    .map_err(|_| authentication_failed())?
        {
            return Err(authentication_failed());
        }
        self.open_verified_content(
            &verified.item_id,
            &verified.header,
            verified.content_nonce,
            parsed.content_ciphertext,
        )
        .map_err(|_| authentication_failed())
    }
}

impl BridgeCryptoProvider for ReferenceEnvelopeSealer {
    type Error = EnvelopeError;
    type EdgeEnrollment = BridgeEdgeEnrollment;
    type VerifiedEdgeEnrollment = VerifiedBridgeEdgeEnrollment;
    type VerifiedAuthorization = VerifiedBridgeAuthorization;
    type VerifiedSourceRoute = VerifiedBridgeSourceRoute;
    type VerifiedWrapper = VerifiedBridgeWrapper;

    fn bridge_mission_id(&self) -> [u8; 32] {
        self.mission
    }

    fn create_bridge_edge_enrollment(
        &self,
        source_scope: &Scope,
        source_route_epoch: u64,
        target_scope: &Scope,
        target_route_epoch: u64,
    ) -> Result<Self::EdgeEnrollment, Self::Error> {
        self.ensure_live()?;
        if self.credential.roles & ROLE_RELAY == 0
            || source_scope == target_scope
            || source_route_epoch == 0
            || target_route_epoch == 0
        {
            return Err(authentication_failed());
        }
        let source_grant = self
            .route_grant(source_scope, source_route_epoch)
            .ok_or_else(authentication_failed)?;
        let target_grant = self
            .route_grant(target_scope, target_route_epoch)
            .ok_or_else(authentication_failed)?;
        let source_route_commitment = route_grant_commitment(&self.mission, source_grant)?;
        let target_route_commitment = route_grant_commitment(&self.mission, target_grant)?;
        if self
            .credential
            .route_grant_commitments
            .binary_search(&source_route_commitment)
            .is_err()
            || self
                .credential
                .route_grant_commitments
                .binary_search(&target_route_commitment)
                .is_err()
        {
            return Err(authentication_failed());
        }
        let authority_credential_signature =
            encode_exact_hybrid_signature(&self.credential.signature)?;
        let mut bytes = encode_bridge_edge_enrollment_body(
            &self.mission,
            &self.authority_id,
            &self.credential.identity,
            source_scope,
            source_route_epoch,
            &source_route_commitment,
            target_scope,
            target_route_epoch,
            &target_route_commitment,
            &self.credential.body,
            &authority_credential_signature,
        )?;
        let digest = hash_domain(BRIDGE_EDGE_ENROLLMENT_SIGNATURE_DOMAIN, &bytes);
        let signature = self
            .provider
            .sign(&self.signing_key, &digest)
            .map_err(envelope_crypto_error)?;
        bytes.extend_from_slice(&encode_exact_hybrid_signature(&signature)?);
        if bytes.len() > MAX_BRIDGE_EDGE_ENROLLMENT_BYTES {
            bytes.zeroize();
            return Err(authentication_failed());
        }
        Ok(BridgeEdgeEnrollment { bytes })
    }

    fn open_bridge_edge_enrollment(
        &self,
        enrollment: &Self::EdgeEnrollment,
    ) -> Result<Self::VerifiedEdgeEnrollment, Self::Error> {
        self.verify_bridge_edge_enrollment_internal(&enrollment.bytes)
    }

    fn bridge_edge_enrollment_claims(
        enrollment: &Self::VerifiedEdgeEnrollment,
    ) -> BridgeEdgeEnrollmentClaims {
        enrollment.claims.clone()
    }

    fn bind_bridge_edge_enrollment(
        &self,
        enrollment: &Self::VerifiedEdgeEnrollment,
        authorization: &mut BridgeAuthorization,
    ) -> Result<(), Self::Error> {
        self.ensure_live()?;
        let enabled = authorization
            .enabled
            .as_mut()
            .ok_or_else(authentication_failed)?;
        if authorization.mission_id != enrollment.claims.mission_id
            || authorization.authority_id != self.authority_id
            || authorization.bridge_node_id != enrollment.claims.bridge_node_id
            || authorization.source_scope != enrollment.claims.source_scope
            || authorization.target_scope != enrollment.claims.target_scope
            || enabled.source_route_epoch != enrollment.claims.source_route_epoch
            || enabled.target_route_epoch != enrollment.claims.target_route_epoch
        {
            return Err(authentication_failed());
        }
        enabled.source_route_commitment = enrollment.source_route_commitment;
        enabled.target_route_commitment = enrollment.target_route_commitment;
        enabled.bridge_credential = enrollment.bridge_credential.clone();
        enabled.authority_credential_signature = enrollment.authority_credential_signature.clone();
        Ok(())
    }

    fn bind_own_bridge_credential(
        &self,
        authorization: &mut BridgeAuthorization,
    ) -> Result<(), Self::Error> {
        self.ensure_live()?;
        if self.credential.roles & ROLE_RELAY == 0
            || authorization.mission_id != self.mission
            || authorization.authority_id != self.authority_id
            || authorization.bridge_node_id != self.credential.identity
        {
            return Err(authentication_failed());
        }
        let enabled = authorization
            .enabled
            .as_mut()
            .ok_or_else(authentication_failed)?;
        enabled.bridge_credential = self.credential.body.clone();
        enabled.authority_credential_signature =
            encode_exact_hybrid_signature(&self.credential.signature)?;
        Ok(())
    }

    fn seal_bridge_authorization(
        &mut self,
        mut authorization: BridgeAuthorization,
    ) -> Result<Vec<u8>, Self::Error> {
        self.ensure_live()?;
        if self.credential.roles & ROLE_CONTROL_AUTHORITY == 0
            || authorization.mission_id != self.mission
            || authorization.authority_id != self.authority_id
        {
            return Err(authentication_failed());
        }
        if let Some(enabled) = &authorization.enabled {
            self.require_local_bridge_route_commitment(
                &authorization.source_scope,
                enabled.source_route_epoch,
                &enabled.source_route_commitment,
            )?;
            self.require_local_bridge_route_commitment(
                &authorization.target_scope,
                enabled.target_route_epoch,
                &enabled.target_route_commitment,
            )?;
        }
        let authority_credential_signature =
            encode_exact_hybrid_signature(&self.credential.signature)?;
        let digest = authorization
            .control_signature_digest(&self.credential.body, &authority_credential_signature)
            .map_err(bridge_authentication_error)?;
        let signature = self
            .provider
            .sign(&self.signing_key, &digest)
            .map_err(envelope_crypto_error)?;
        authorization.authority_control_signature =
            bridge::encode_delegated_control_authentication(
                &self.credential.body,
                &authority_credential_signature,
                &encode_exact_hybrid_signature(&signature)?,
            )
            .map_err(bridge_authentication_error)?;
        self.verify_bridge_authorization_internal(&authorization)?;

        let mut plaintext = authorization
            .encode()
            .map_err(bridge_authentication_error)?;
        let sealed_parts = (|| {
            let mut selector = [0u8; SELECTOR_LEN];
            self.provider
                .fill_random(&mut selector)
                .map_err(envelope_crypto_error)?;
            let control_route_key = self
                .control_route_key
                .as_ref()
                .ok_or_else(authentication_failed)?;
            let key = derive_item_secret(
                control_route_key.expose(),
                BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
                &selector,
            )?;
            let header = bridge::encode_public_header(
                bridge::AUTHORIZATION_MAGIC,
                selector,
                plaintext.len().saturating_add(GCM_TAG_LEN),
            )
            .map_err(bridge_authentication_error)?;
            let ciphertext = self
                .provider
                .seal_with_nonce(&key, selector_nonce(&selector), &plaintext, &header)
                .map_err(envelope_crypto_error)?;
            Ok::<_, EnvelopeError>((header, ciphertext))
        })();
        plaintext.zeroize();
        let (header, ciphertext) = sealed_parts?;
        let mut sealed = Vec::with_capacity(header.len().saturating_add(ciphertext.len()));
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(&ciphertext);
        if sealed.len() > bridge::MAX_AUTHORIZATION_TOTAL_BYTES {
            sealed.zeroize();
            return Err(authentication_failed());
        }
        Ok(sealed)
    }

    fn open_bridge_authorization(
        &self,
        sealed: &[u8],
    ) -> Result<Self::VerifiedAuthorization, Self::Error> {
        self.ensure_live()?;
        let parsed = parse_bridge_object(sealed, bridge::AUTHORIZATION_MAGIC)?;
        let control_route_key = self
            .control_route_key
            .as_ref()
            .ok_or_else(authentication_failed)?;
        let key = derive_item_secret(
            control_route_key.expose(),
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            &parsed.selector,
        )?;
        let mut plaintext = self
            .provider
            .open_parts(
                &key,
                selector_nonce(&parsed.selector),
                parsed.ciphertext,
                parsed.header,
            )
            .map_err(envelope_crypto_error)?;
        let decoded = BridgeAuthorization::decode(&plaintext).map_err(bridge_authentication_error);
        plaintext.zeroize();
        let authorization = decoded?;
        let (bridge_verifying_key, control_signer) =
            self.verify_bridge_authorization_internal(&authorization)?;
        Ok(VerifiedBridgeAuthorization {
            envelope: AuthorizationEnvelope {
                envelope_id: bridge::exact_object_id(sealed),
                authorization,
            },
            bridge_verifying_key,
            control_signer,
        })
    }

    fn open_source_route_for_bridge(
        &self,
        source_envelope: &[u8],
    ) -> Result<Self::VerifiedSourceRoute, Self::Error> {
        self.ensure_live()?;
        let parsed = parse_envelope(source_envelope)?;
        if parsed.kind != EnvelopeKind::Data {
            return Err(authentication_failed());
        }
        let (route, exact_route_descriptor) = self.open_data_route_exact(&parsed)?;
        self.build_verified_bridge_source(
            source_envelope,
            &parsed,
            route,
            exact_route_descriptor,
            None,
        )
    }

    fn verify_copied_source_route_for_bridge(
        &self,
        source_envelope: &[u8],
        exact_route_descriptor: &[u8],
    ) -> Result<Self::VerifiedSourceRoute, Self::Error> {
        self.ensure_live()?;
        self.verify_copied_bridge_source(source_envelope, exact_route_descriptor, None)
    }

    fn sign_bridge_hop(&self, route: &mut BridgeRoute, index: usize) -> Result<(), Self::Error> {
        self.ensure_live()?;
        let hop = route.hops.get(index).ok_or_else(authentication_failed)?;
        if index.saturating_add(1) != route.hops.len()
            || route.mission_id != self.mission
            || self.credential.roles & ROLE_RELAY == 0
            || hop.bridge_node_id != self.credential.identity
            || self
                .route_grant(&hop.from_scope, hop.from_route_epoch)
                .is_none()
            || self
                .route_grant(&hop.to_scope, hop.to_route_epoch)
                .is_none()
        {
            return Err(authentication_failed());
        }
        let digest = route
            .hop_signature_digest(index)
            .map_err(bridge_authentication_error)?;
        let signature = self
            .provider
            .sign(&self.signing_key, &digest)
            .map_err(envelope_crypto_error)?;
        let mut candidate = route.clone();
        candidate.hops[index].bridge_hybrid_signature = encode_exact_hybrid_signature(&signature)?;
        candidate.bridge_route_id = candidate
            .compute_route_id()
            .map_err(bridge_authentication_error)?;
        candidate
            .validate_structure()
            .map_err(bridge_authentication_error)?;
        *route = candidate;
        Ok(())
    }

    fn verify_bridge_hop(
        &self,
        route: &BridgeRoute,
        index: usize,
        authorization: &Self::VerifiedAuthorization,
    ) -> Result<(), Self::Error> {
        self.ensure_live()?;
        route
            .validate_structure()
            .map_err(bridge_authentication_error)?;
        let hop = route.hops.get(index).ok_or_else(authentication_failed)?;
        let record = &authorization.envelope;
        let control = &record.authorization;
        let enabled = control.enabled.as_ref().ok_or_else(authentication_failed)?;
        let verifying_key = authorization
            .bridge_verifying_key
            .as_ref()
            .ok_or_else(authentication_failed)?;
        if route.mission_id != self.mission
            || control.mission_id != route.mission_id
            || record.envelope_id != hop.authorization_envelope_id
            || control.bridge_node_id != hop.bridge_node_id
            || control.source_scope != hop.from_scope
            || control.target_scope != hop.to_scope
            || enabled.source_route_epoch != hop.from_route_epoch
            || enabled.target_route_epoch != hop.to_route_epoch
            || usize::from(enabled.max_total_hops) < route.hops.len()
        {
            return Err(authentication_failed());
        }
        let digest = route
            .hop_signature_digest(index)
            .map_err(bridge_authentication_error)?;
        let signature = decode_exact_hybrid_signature(&hop.bridge_hybrid_signature)?;
        self.provider
            .verify(verifying_key, &digest, &signature)
            .map_err(envelope_crypto_error)
    }

    fn seal_bridge_wrapper(
        &mut self,
        route: &BridgeRoute,
        source: &Self::VerifiedSourceRoute,
        target_scope: &Scope,
        target_route_epoch: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        self.ensure_live()?;
        Self::source_matches_bridge_route(route, source)?;
        let last_index = route
            .hops
            .len()
            .checked_sub(1)
            .ok_or_else(authentication_failed)?;
        let last_hop = &route.hops[last_index];
        if route.mission_id != self.mission
            || &route.current_scope != target_scope
            || route.current_route_epoch != target_route_epoch
            || last_hop.bridge_node_id != self.credential.identity
        {
            return Err(authentication_failed());
        }
        let digest = route
            .hop_signature_digest(last_index)
            .map_err(bridge_authentication_error)?;
        let last_signature = decode_exact_hybrid_signature(&last_hop.bridge_hybrid_signature)?;
        self.provider
            .verify(&self.credential.verifying_key, &digest, &last_signature)
            .map_err(envelope_crypto_error)?;

        let mut plaintext = route.encode().map_err(bridge_authentication_error)?;
        let sealed_parts = (|| {
            let mut selector = [0u8; SELECTOR_LEN];
            self.provider
                .fill_random(&mut selector)
                .map_err(envelope_crypto_error)?;
            let key = {
                let route_grant = self
                    .route_grant(target_scope, target_route_epoch)
                    .ok_or_else(authentication_failed)?;
                derive_item_secret(
                    route_grant.key.expose(),
                    BRIDGE_WRAPPER_KEY_LABEL,
                    &selector,
                )?
            };
            let header = bridge::encode_public_header(
                bridge::WRAPPER_MAGIC,
                selector,
                plaintext.len().saturating_add(GCM_TAG_LEN),
            )
            .map_err(bridge_authentication_error)?;
            let ciphertext = self
                .provider
                .seal_with_nonce(&key, selector_nonce(&selector), &plaintext, &header)
                .map_err(envelope_crypto_error)?;
            Ok::<_, EnvelopeError>((header, ciphertext))
        })();
        plaintext.zeroize();
        let (header, ciphertext) = sealed_parts?;
        let mut sealed = Vec::with_capacity(header.len().saturating_add(ciphertext.len()));
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open_bridge_wrapper(
        &self,
        sealed: &[u8],
        target_scope: &Scope,
        target_route_epoch: u64,
    ) -> Result<Self::VerifiedWrapper, Self::Error> {
        self.ensure_live()?;
        let parsed = parse_bridge_object(sealed, bridge::WRAPPER_MAGIC)?;
        let route_grant = self
            .route_grant(target_scope, target_route_epoch)
            .ok_or_else(authentication_failed)?;
        let key = derive_item_secret(
            route_grant.key.expose(),
            BRIDGE_WRAPPER_KEY_LABEL,
            &parsed.selector,
        )?;
        let mut plaintext = self
            .provider
            .open_parts(
                &key,
                selector_nonce(&parsed.selector),
                parsed.ciphertext,
                parsed.header,
            )
            .map_err(envelope_crypto_error)?;
        let decoded = BridgeRoute::decode(&plaintext).map_err(bridge_authentication_error);
        plaintext.zeroize();
        let route = decoded?;
        if route.mission_id != self.mission
            || &route.current_scope != target_scope
            || route.current_route_epoch != target_route_epoch
        {
            return Err(authentication_failed());
        }
        Ok(VerifiedBridgeWrapper {
            wrapper_envelope_id: bridge::exact_object_id(sealed),
            route,
        })
    }

    fn open_bridge_wrapper_for_any_local_route(
        &self,
        sealed: &[u8],
    ) -> Result<Self::VerifiedWrapper, Self::Error> {
        self.ensure_live()?;
        let parsed = parse_bridge_object(sealed, bridge::WRAPPER_MAGIC)
            .map_err(|_| authentication_failed())?;
        for route_grant in &self.route_grants {
            let Ok(key) = derive_item_secret(
                route_grant.key.expose(),
                BRIDGE_WRAPPER_KEY_LABEL,
                &parsed.selector,
            ) else {
                continue;
            };
            let Ok(mut plaintext) = self.provider.open_parts(
                &key,
                selector_nonce(&parsed.selector),
                parsed.ciphertext,
                parsed.header,
            ) else {
                continue;
            };
            let decoded = BridgeRoute::decode(&plaintext).map_err(bridge_authentication_error);
            plaintext.zeroize();
            let Ok(route) = decoded else {
                continue;
            };
            if route.mission_id == self.mission
                && route.current_scope == route_grant.scope
                && route.current_route_epoch == route_grant.epoch
            {
                return Ok(VerifiedBridgeWrapper {
                    wrapper_envelope_id: bridge::exact_object_id(sealed),
                    route,
                });
            }
        }
        Err(authentication_failed())
    }

    fn verify_bridge_wrapper_source(
        &self,
        wrapper: &Self::VerifiedWrapper,
        source_envelope: &[u8],
    ) -> Result<Self::VerifiedSourceRoute, Self::Error> {
        self.ensure_live()?;
        let source = self.verify_copied_bridge_source(
            source_envelope,
            &wrapper.route.source_route_descriptor,
            Some(wrapper.wrapper_envelope_id),
        )?;
        Self::source_matches_bridge_route(&wrapper.route, &source)?;
        Ok(source)
    }

    fn open_bridged_payload(
        &self,
        source: &Self::VerifiedSourceRoute,
        source_envelope: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.ensure_live()?;
        if source.wrapper_envelope_id.is_none()
            || source.mission_id != self.mission
            || source.origin_envelope_id != bridge::exact_object_id(source_envelope)
        {
            return Err(authentication_failed());
        }
        let parsed = parse_envelope(source_envelope)?;
        if parsed.kind != EnvelopeKind::Data
            || source.content_ciphertext_len
                != u64::try_from(parsed.content_ciphertext.len()).map_err(|_| invalid_envelope())?
        {
            return Err(authentication_failed());
        }
        self.open_verified_content(
            &source.source_item_id,
            &source.header,
            source.content_nonce,
            parsed.content_ciphertext,
        )
        .map_err(|_| authentication_failed())
    }
}

impl Drop for ReferenceEnvelopeSealer {
    fn drop(&mut self) {
        self.erase();
    }
}

impl EnvelopeSealer for ReferenceEnvelopeSealer {
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
        self.open_verified_content(
            &verified.id,
            &verified.header,
            route.content_nonce,
            parsed.content_ciphertext,
        )
    }

    fn open_compact_batch_payload_with_proof(
        &mut self,
        compact: &[u8],
        proof: &[u8],
    ) -> Result<(VerifiedEnvelope, Vec<u8>), EnvelopeError> {
        let proof = <Self as BatchCryptoProvider>::open_batch_proof(
            self,
            proof,
            batch::SEMANTIC_PROTOCOL_VERSION,
        )?;
        let pending = <Self as BatchCryptoProvider>::open_compact_batch_item(
            self,
            compact,
            batch::SEMANTIC_PROTOCOL_VERSION,
        )?;
        if <Self as BatchCryptoProvider>::pending_batch_proof_id(self, &pending)
            != proof.proof_envelope_id()
        {
            return Err(authentication_failed());
        }
        let verified = <Self as BatchCryptoProvider>::verify_compact_batch_item(
            self,
            &pending,
            Some(&proof),
            compact,
        )?;
        let envelope = verified.verified_envelope();
        let payload = if envelope.header.tombstone {
            Vec::new()
        } else {
            <Self as BatchCryptoProvider>::open_compact_batch_payload(self, &verified, compact)?
        };
        Ok((envelope, payload))
    }

    fn open_payload_if_authorized(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EnvelopeError> {
        let (verified, _, _) = self.inspect_data_internal(sealed)?;
        if &verified != envelope {
            return Err(authentication_failed());
        }
        if self
            .content_grant(
                &verified.header.scope,
                &verified.header.topic,
                verified.header.key_epoch,
            )
            .is_none()
        {
            return Ok(None);
        }
        self.open_payload(envelope, sealed).map(Some)
    }

    fn inspect_control(&mut self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError> {
        self.inspect_control_with_scope_rekey_recipient_nodes(sealed)
            .map(|(control, _)| control)
    }

    fn seal_forwarding(
        &mut self,
        recipient: NodeId,
        exchange_id: u64,
        envelope_id: crate::store::EnvelopeId,
        custody_age_ms: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_forwarding_internal(recipient, exchange_id, envelope_id, custody_age_ms)
    }

    fn inspect_forwarding(
        &mut self,
        authenticated_sender: NodeId,
        recipient: NodeId,
        exchange_id: u64,
        envelope_id: crate::store::EnvelopeId,
        forwarding: &[u8],
    ) -> Result<u64, EnvelopeError> {
        self.inspect_forwarding_internal(
            authenticated_sender,
            recipient,
            exchange_id,
            envelope_id,
            forwarding,
        )
    }

    fn peer_can_route(
        &self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        scope: &Scope,
        epoch: u64,
    ) -> bool {
        if let Some(recipients) = self.rekey_route_authorizations.get(&(scope.clone(), epoch)) {
            return recipients.binary_search(&peer).is_ok();
        }
        let Some(grant) = self.route_grant(scope, epoch) else {
            return false;
        };
        route_grant_commitment(&self.mission, grant)
            .ok()
            .is_some_and(|commitment| peer_route_commitments.binary_search(&commitment).is_ok())
    }

    fn control_principal(&self) -> Option<ControlPrincipal> {
        (self.credential.roles & ROLE_CONTROL_AUTHORITY != 0).then_some(ControlPrincipal {
            authority: self.authority_id,
            signer: self.credential.identity,
        })
    }

    fn seal_revocation_control(
        &mut self,
        subject: NodeId,
        generation: u64,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_revocation_chained(subject, generation, sequence, previous)
    }

    fn seal_scope_epoch_control(
        &mut self,
        scope: &Scope,
        epoch: u64,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_scope_epoch_chained(scope, epoch, sequence, previous)
    }

    fn activate_control(
        &mut self,
        sealed: &[u8],
        local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        self.activate_scope_epoch_control(sealed, local_revoked)
    }

    fn zeroize(&mut self) -> Result<(), EnvelopeError> {
        self.erase();
        Ok(())
    }
}

struct SessionEndpoint {
    provider: RustCryptoProvider<SysRng>,
    mission: [u8; 32],
    authority_id: NodeId,
    authority_verifying_key: HybridVerifyingKey,
    credential: Credential,
    signing_key: RustCryptoSigningKey,
    mission_proof_key: Secret32,
}

impl SessionEndpoint {
    fn open(mut bundle: ProvisioningBundle) -> Result<Self, EnvelopeError> {
        let seed = bundle.identity_seed.as_ref().ok_or_else(zeroized_service)?;
        let provider = RustCryptoProvider::try_new(SysRng).map_err(reference_open_error)?;
        let (
            signing_key,
            verifying_key,
            p256_ecdh_secret,
            p256_ecdh_public_key,
            kem_key,
            kem_public_key,
        ) = derive_identity(seed.expose(), &provider)?;
        drop(p256_ecdh_secret);
        drop(kem_key);
        let route_grant_commitments =
            route_grant_commitments(&bundle.mission, &bundle.route_grants)?;
        let body = encode_credential_body(
            &bundle.mission,
            bundle.serial,
            bundle.roles,
            &verifying_key,
            &p256_ecdh_public_key,
            &kem_public_key,
            &route_grant_commitments,
        )?;
        let digest = hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &body);
        provider
            .verify(
                &bundle.authority_verifying_key,
                &digest,
                &bundle.credential_signature,
            )
            .map_err(envelope_crypto_error)?;
        if derive_authority_id(&bundle.mission, &bundle.authority_verifying_key)
            != bundle.authority_id
        {
            return Err(authentication_failed());
        }
        let credential = Credential {
            identity: hash_domain(NODE_ID_DOMAIN, &body),
            body,
            signature: bundle.credential_signature.clone(),
            verifying_key,
            p256_ecdh_public_key,
            kem_public_key,
            roles: bundle.roles,
            route_grant_commitments,
        };
        let mission = bundle.mission;
        let authority_id = bundle.authority_id;
        let authority_verifying_key = bundle.authority_verifying_key.clone();
        let mission_proof_key = bundle
            .control_route_key
            .take()
            .ok_or_else(authentication_failed)?;
        bundle.zeroize();
        Ok(Self {
            provider,
            mission,
            authority_id,
            authority_verifying_key,
            credential,
            signing_key,
            mission_proof_key,
        })
    }

    fn decode_peer_credential(
        &self,
        body: Vec<u8>,
        signature: HybridSignature,
    ) -> Result<Credential, EnvelopeError> {
        let peer = decode_credential(
            body,
            signature,
            &self.mission,
            &self.authority_verifying_key,
            &self.provider,
        )?;
        if derive_authority_id(&self.mission, &self.authority_verifying_key) != self.authority_id
            || peer.roles & ROLE_RELAY == 0
        {
            return Err(authentication_failed());
        }
        Ok(peer)
    }
}

#[cfg(test)]
pub(crate) struct SessionPrivacyCanaries {
    pub(crate) mission: [u8; 32],
    pub(crate) credential: Vec<u8>,
    pub(crate) credential_body: Vec<u8>,
    pub(crate) identity: NodeId,
    pub(crate) route_grant_commitments: Vec<[u8; 32]>,
}

#[cfg(test)]
pub(crate) fn session_privacy_canaries(
    bundle: &ProvisioningBundle,
) -> Result<SessionPrivacyCanaries, EnvelopeError> {
    let encoded = bundle.to_bytes()?;
    let endpoint = SessionEndpoint::open(ProvisioningBundle::from_bytes(&encoded)?)?;
    let mut credential = Vec::new();
    encode_flight_credential(&mut credential, &endpoint.credential)?;
    Ok(SessionPrivacyCanaries {
        mission: endpoint.mission,
        credential,
        credential_body: endpoint.credential.body,
        identity: endpoint.credential.identity,
        route_grant_commitments: endpoint.credential.route_grant_commitments,
    })
}

/// Initiator state for the four-flight, mutually authenticated reference session.
///
/// Construction returns the first opaque byte flight. The state is consumed at every transition,
/// so application frames cannot be sent before the server-finished flight authenticates.
pub struct ReferenceSessionInitiator {
    endpoint: SessionEndpoint,
    handshake: Option<InitiatorHandshake<RustCryptoProvider<SysRng>>>,
    mission_proof_commitment: [u8; 32],
}

impl fmt::Debug for ReferenceSessionInitiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceSessionInitiator")
            .field("identity", &self.endpoint.credential.identity)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ReferenceSessionInitiator {
    /// Starts a session and returns `(state, ClientHello bytes)`.
    pub fn start(bundle: ProvisioningBundle) -> Result<(Self, Vec<u8>), EnvelopeError> {
        Self::start_with_semantic_versions(
            bundle,
            super::SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS.to_vec(),
        )
    }

    /// Starts a session for an adapter that fully implements semantic versions
    /// only through `semantic_ceiling`.
    ///
    /// This declares implementation capability; it is not an application
    /// protocol preference or an in-session downgrade mechanism.
    pub fn start_with_semantic_ceiling(
        bundle: ProvisioningBundle,
        semantic_ceiling: u16,
    ) -> Result<(Self, Vec<u8>), EnvelopeError> {
        if semantic_ceiling == 0 || semantic_ceiling > super::SEMANTIC_PROTOCOL_V9 {
            return Err(invalid_envelope());
        }
        Self::start_with_semantic_versions(bundle, (1..=semantic_ceiling).rev().collect())
    }

    /// Compatibility-only constructor for downstream authenticated transport
    /// tests representing an older implementation. This symbol is absent
    /// unless the non-default `test-utils` feature is selected.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn start_with_semantic_versions_for_test(
        bundle: ProvisioningBundle,
        supported_versions: Vec<u16>,
    ) -> Result<(Self, Vec<u8>), EnvelopeError> {
        Self::start_with_semantic_versions(bundle, supported_versions)
    }

    /// Test/compatibility entry point for representing an older implementation.
    /// Production callers do not choose session semantics.
    pub(crate) fn start_with_semantic_versions(
        bundle: ProvisioningBundle,
        supported_versions: Vec<u16>,
    ) -> Result<(Self, Vec<u8>), EnvelopeError> {
        let mut endpoint = SessionEndpoint::open(bundle)?;
        let (handshake, hello) =
            InitiatorHandshake::start(&mut endpoint.provider, supported_versions, vec![SUITE_ID])
                .map_err(handshake_error)?;
        let mission_proof = create_mission_proof(&endpoint, &hello)?;
        let mission_proof_commitment = mission_proof_commitment(&mission_proof)?;
        let flight = encode_client_flight(&hello, &mission_proof)?;
        Ok((
            Self {
                endpoint,
                handshake: Some(handshake),
                mission_proof_commitment,
            },
            flight,
        ))
    }

    /// Verifies `ServerHello+ServerAuth` and returns `(pending state, ClientAuth bytes)`.
    pub fn receive_server(
        self,
        flight: &[u8],
    ) -> Result<(ReferenceSessionAwaitingFinished, Vec<u8>), EnvelopeError> {
        self.receive_server_retryable(flight)
            .map_err(|(_, error)| error)
    }

    // Returning the owned state inline avoids an attacker-triggered heap
    // allocation on every rejected flight while preserving exact secrets.
    #[allow(clippy::result_large_err)]
    pub(crate) fn receive_server_retryable(
        mut self,
        flight: &[u8],
    ) -> Result<(ReferenceSessionAwaitingFinished, Vec<u8>), (Self, EnvelopeError)> {
        let hello = match decode_server_flight(flight) {
            Ok(hello) => hello,
            Err(error) => return Err((self, error)),
        };
        let Some(handshake) = self.handshake.as_ref() else {
            return Err((self, authentication_failed()));
        };
        let (pending, opened) =
            match handshake.open_server_auth_borrowed(&self.endpoint.provider, &hello) {
                Ok(opened) => opened,
                Err(error) => return Err((self, handshake_error(error))),
            };
        let (proof_commitment, credential_body, credential_signature) =
            match decode_server_auth_context(opened.credential_context()) {
                Ok(context) => context,
                Err(error) => return Err((self, error)),
            };
        if proof_commitment != self.mission_proof_commitment {
            return Err((self, authentication_failed()));
        }
        let peer = match self
            .endpoint
            .decode_peer_credential(credential_body, credential_signature)
        {
            Ok(peer) => peer,
            Err(error) => return Err((self, error)),
        };
        let authenticated =
            match pending.authenticate_server(&self.endpoint.provider, opened, &peer.verifying_key)
            {
                Ok(authenticated) => authenticated,
                Err(error) => return Err((self, handshake_error(error))),
            };
        let credential_context = match encode_client_auth_context(&self.endpoint.credential) {
            Ok(context) => context,
            Err(error) => return Err((self, error)),
        };
        let (handshake, finish) = match authenticated.seal_client_auth(
            &mut self.endpoint.provider,
            &self.endpoint.signing_key,
            &credential_context,
        ) {
            Ok(result) => result,
            Err(error) => return Err((self, handshake_error(error))),
        };
        let client_flight = match encode_client_auth_flight(&finish) {
            Ok(flight) => flight,
            Err(error) => return Err((self, error)),
        };
        let endpoint = self.endpoint;
        Ok((
            ReferenceSessionAwaitingFinished {
                provider: endpoint.provider,
                peer_identity: peer.identity,
                peer_route_grant_commitments: peer.route_grant_commitments,
                handshake: Some(handshake),
            },
            client_flight,
        ))
    }
}

/// Initiator state which has authenticated the responder but has not received final key
/// confirmation. It deliberately has no transport-frame methods.
pub struct ReferenceSessionAwaitingFinished {
    provider: RustCryptoProvider<SysRng>,
    peer_identity: NodeId,
    peer_route_grant_commitments: Vec<[u8; 32]>,
    handshake: Option<InitiatorHandshakeAwaitingFinished>,
}

impl ReferenceSessionAwaitingFinished {
    /// Authenticates `ServerFinished`; only success yields an application-capable session.
    pub fn receive_finished(
        self,
        flight: &[u8],
    ) -> Result<ReferenceAuthenticatedSession, EnvelopeError> {
        self.receive_finished_retryable(flight)
            .map_err(|(_, error)| error)
    }

    // See `receive_server_retryable`; this is a bounded cold error path.
    #[allow(clippy::result_large_err)]
    pub(crate) fn receive_finished_retryable(
        mut self,
        flight: &[u8],
    ) -> Result<ReferenceAuthenticatedSession, (Self, EnvelopeError)> {
        let finished = match decode_server_finished_flight(flight) {
            Ok(finished) => finished,
            Err(error) => return Err((self, error)),
        };
        let Some(handshake) = self.handshake.as_ref() else {
            return Err((self, authentication_failed()));
        };
        if let Err(error) = handshake.verify_finished(&self.provider, &finished) {
            return Err((self, handshake_error(error)));
        }
        let Some(handshake) = self.handshake.take() else {
            return Err((self, authentication_failed()));
        };
        let keys = handshake.into_session_keys();
        let protocol_version = keys.selected_version();
        let session_id = keys.transcript_hash;
        Ok(ReferenceAuthenticatedSession {
            provider: self.provider,
            peer_identity: self.peer_identity,
            peer_route_grant_commitments: self.peer_route_grant_commitments,
            semantic_version: protocol_version,
            session_id,
            role: SessionRole::Initiator,
            channel: keys.into_channel(),
            transfer_profiles: TransferProfileNegotiationState::default(),
        })
    }
}

/// Initial responder state for the four-flight authenticated session.
pub struct ReferenceSessionResponder {
    endpoint: SessionEndpoint,
    supported_versions: Vec<u16>,
}

impl fmt::Debug for ReferenceSessionResponder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceSessionResponder")
            .field("identity", &self.endpoint.credential.identity)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ReferenceSessionResponder {
    /// Opens a responder from an opaque provisioning package.
    pub fn open(bundle: ProvisioningBundle) -> Result<Self, EnvelopeError> {
        Self::open_with_semantic_versions(
            bundle,
            super::SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS.to_vec(),
        )
    }

    /// Opens a responder for an adapter that fully implements semantic
    /// versions only through `semantic_ceiling`.
    ///
    /// See [`ReferenceSessionInitiator::start_with_semantic_ceiling`].
    pub fn open_with_semantic_ceiling(
        bundle: ProvisioningBundle,
        semantic_ceiling: u16,
    ) -> Result<Self, EnvelopeError> {
        if semantic_ceiling == 0 || semantic_ceiling > super::SEMANTIC_PROTOCOL_V9 {
            return Err(invalid_envelope());
        }
        Self::open_with_semantic_versions(bundle, (1..=semantic_ceiling).rev().collect())
    }

    pub(crate) fn open_with_semantic_versions(
        bundle: ProvisioningBundle,
        supported_versions: Vec<u16>,
    ) -> Result<Self, EnvelopeError> {
        super::validate_version_offer(&supported_versions).map_err(handshake_error)?;
        Ok(Self {
            endpoint: SessionEndpoint::open(bundle)?,
            supported_versions,
        })
    }

    /// Verifies `ClientHello` and returns `(pending state, ServerHello+ServerAuth bytes)`.
    pub fn receive_client(
        self,
        flight: &[u8],
    ) -> Result<(ReferenceSessionResponderPending, Vec<u8>), EnvelopeError> {
        self.receive_client_retryable(flight)
            .map_err(|(_, error)| error)
    }

    // See `receive_server_retryable`; this is a bounded cold error path.
    #[allow(clippy::result_large_err)]
    pub(crate) fn receive_client_retryable(
        mut self,
        flight: &[u8],
    ) -> Result<(ReferenceSessionResponderPending, Vec<u8>), (Self, EnvelopeError)> {
        let (hello, mission_proof) = match decode_client_flight(flight) {
            Ok(decoded) => decoded,
            Err(error) => return Err((self, error)),
        };
        if let Err(error) = verify_mission_proof(&self.endpoint, &hello, &mission_proof) {
            return Err((self, error));
        }
        if let Err(error) = validate_kem_public_key(&hello.ml_kem_768_encapsulation_key) {
            return Err((self, error));
        }
        let proof_commitment = match mission_proof_commitment(&mission_proof) {
            Ok(commitment) => commitment,
            Err(error) => return Err((self, error)),
        };
        let credential_context =
            match encode_server_auth_context(proof_commitment, &self.endpoint.credential) {
                Ok(context) => context,
                Err(error) => return Err((self, error)),
            };
        // Mission proof verification deliberately precedes P-256 agreement and ML-KEM
        // encapsulation so unauthenticated probes cannot trigger the expensive response.
        let prepared = match ResponderHandshakePrepared::respond_with_supported_versions(
            &mut self.endpoint.provider,
            &hello,
            &self.supported_versions,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return Err((self, handshake_error(error))),
        };
        let (handshake, server_hello) = match prepared.seal_server_auth(
            &mut self.endpoint.provider,
            &self.endpoint.signing_key,
            &credential_context,
        ) {
            Ok(result) => result,
            Err(error) => return Err((self, handshake_error(error))),
        };
        let server_flight = match encode_server_flight(&server_hello) {
            Ok(flight) => flight,
            Err(error) => return Err((self, error)),
        };
        Ok((
            ReferenceSessionResponderPending {
                endpoint: self.endpoint,
                handshake: Some(handshake),
            },
            server_flight,
        ))
    }
}

/// Responder state waiting for the third handshake flight.
pub struct ReferenceSessionResponderPending {
    endpoint: SessionEndpoint,
    handshake: Option<ResponderHandshake>,
}

impl ReferenceSessionResponderPending {
    /// Verifies `ClientAuth` and returns `(authenticated session, ServerFinished bytes)`.
    pub fn receive_client_auth(
        self,
        flight: &[u8],
    ) -> Result<(ReferenceAuthenticatedSession, Vec<u8>), EnvelopeError> {
        self.receive_client_auth_retryable(flight)
            .map_err(|(_, error)| error)
    }

    // See `receive_server_retryable`; this is a bounded cold error path.
    #[allow(clippy::result_large_err)]
    pub(crate) fn receive_client_auth_retryable(
        mut self,
        flight: &[u8],
    ) -> Result<(ReferenceAuthenticatedSession, Vec<u8>), (Self, EnvelopeError)> {
        let finish = match decode_client_auth_flight(flight) {
            Ok(finish) => finish,
            Err(error) => return Err((self, error)),
        };
        let Some(handshake) = self.handshake.as_ref() else {
            return Err((self, authentication_failed()));
        };
        let (final_transcript_hash, opened) =
            match handshake.inspect_client_auth(&self.endpoint.provider, &finish) {
                Ok(inspected) => inspected,
                Err(error) => return Err((self, handshake_error(error))),
            };
        let (credential_body, credential_signature) =
            match decode_client_auth_context(opened.credential_context()) {
                Ok(context) => context,
                Err(error) => return Err((self, error)),
            };
        let peer = match self
            .endpoint
            .decode_peer_credential(credential_body, credential_signature)
        {
            Ok(peer) => peer,
            Err(error) => return Err((self, error)),
        };
        if let Err(error) =
            handshake.verify_client_auth(&self.endpoint.provider, &opened, &peer.verifying_key)
        {
            return Err((self, handshake_error(error)));
        }
        let finished = match handshake
            .seal_server_finished(&mut self.endpoint.provider, &final_transcript_hash)
        {
            Ok(finished) => finished,
            Err(error) => return Err((self, handshake_error(error))),
        };
        let finished_flight = match encode_server_finished_flight(&finished) {
            Ok(flight) => flight,
            Err(error) => return Err((self, error)),
        };
        let Some(handshake) = self.handshake.take() else {
            return Err((self, authentication_failed()));
        };
        let keys = handshake.into_session_keys(final_transcript_hash);
        let protocol_version = keys.selected_version();
        let session_id = keys.transcript_hash;
        let peer_identity = peer.identity;
        let peer_route_grant_commitments = peer.route_grant_commitments;
        let endpoint = self.endpoint;
        Ok((
            ReferenceAuthenticatedSession {
                provider: endpoint.provider,
                peer_identity,
                peer_route_grant_commitments,
                semantic_version: protocol_version,
                session_id,
                role: SessionRole::Responder,
                channel: keys.into_channel(),
                transfer_profiles: TransferProfileNegotiationState::default(),
            },
            finished_flight,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Debug, Default)]
struct TransferProfileNegotiationState {
    local_offer: Option<TransferProfileOfferV1>,
    authenticated_peer_offer: Option<TransferProfileOfferV1>,
    authenticated: Option<AuthenticatedTransferProfiles>,
}

#[derive(Debug)]
struct AuthenticatedTransferProfiles {
    negotiated: NegotiatedTransferProfiles,
    digest: [u8; 32],
}

/// Completed mutually authenticated adjacency with ordered, encrypted, replay-protected frames.
pub struct ReferenceAuthenticatedSession {
    provider: RustCryptoProvider<SysRng>,
    peer_identity: NodeId,
    peer_route_grant_commitments: Vec<[u8; 32]>,
    semantic_version: u16,
    session_id: [u8; 32],
    role: SessionRole,
    channel: SecureChannel,
    transfer_profiles: TransferProfileNegotiationState,
}

/// Deterministic v9 authenticated sessions for corpus generation and fuzzing.
/// This constructor is absent from ordinary production builds.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_reference_v9_session_pair() -> (
    ReferenceAuthenticatedSession,
    ReferenceAuthenticatedSession,
    [u8; 32],
) {
    fn provider(prefix: [u8; 4]) -> RustCryptoProvider<SysRng> {
        RustCryptoProvider {
            rng: SysRng,
            nonce_prefix: prefix,
            nonce_counter: 1,
            nonce_start: 1,
            nonce_exhausted: false,
        }
    }
    fn profiles() -> (TransferProfileNegotiationState, [u8; 32]) {
        let offer = TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V9)
            .expect("fixed v9 fuzz offer");
        let negotiated =
            negotiate_transfer_profiles_for_semantic_version(SEMANTIC_PROTOCOL_V9, &offer, &offer)
                .expect("fixed v9 fuzz negotiation");
        let digest = transfer_profile_digest(&offer, &offer, &negotiated);
        (
            TransferProfileNegotiationState {
                local_offer: Some(offer.clone()),
                authenticated_peer_offer: Some(offer),
                authenticated: Some(AuthenticatedTransferProfiles { negotiated, digest }),
            },
            digest,
        )
    }
    let session_id = [0x31; 32];
    let (initiator_profiles, digest) = profiles();
    let (responder_profiles, responder_digest) = profiles();
    debug_assert_eq!(digest, responder_digest);
    let initiator_keys = SessionKeys {
        transmit: Secret32::new([0x41; 32]),
        receive: Secret32::new([0x42; 32]),
        transcript_hash: session_id,
        selected_version: SEMANTIC_PROTOCOL_V9,
        selected_suite: super::HYBRID_SUITE_ID,
    };
    let responder_keys = SessionKeys {
        transmit: Secret32::new([0x42; 32]),
        receive: Secret32::new([0x41; 32]),
        transcript_hash: session_id,
        selected_version: SEMANTIC_PROTOCOL_V9,
        selected_suite: super::HYBRID_SUITE_ID,
    };
    (
        ReferenceAuthenticatedSession {
            provider: provider([0x51; 4]),
            peer_identity: [0x61; 32],
            peer_route_grant_commitments: Vec::new(),
            semantic_version: SEMANTIC_PROTOCOL_V9,
            session_id,
            role: SessionRole::Initiator,
            channel: initiator_keys.into_channel(),
            transfer_profiles: initiator_profiles,
        },
        ReferenceAuthenticatedSession {
            provider: provider([0x52; 4]),
            peer_identity: [0x62; 32],
            peer_route_grant_commitments: Vec::new(),
            semantic_version: SEMANTIC_PROTOCOL_V9,
            session_id,
            role: SessionRole::Responder,
            channel: responder_keys.into_channel(),
            transfer_profiles: responder_profiles,
        },
        digest,
    )
}

impl fmt::Debug for ReferenceAuthenticatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceAuthenticatedSession")
            .field("peer_identity", &self.peer_identity)
            .field("semantic_version", &self.semantic_version)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl ReferenceAuthenticatedSession {
    /// Identity authenticated by the authority credential and both signature families.
    pub fn peer_identity(&self) -> NodeId {
        self.peer_identity
    }

    /// Highest mutually supported semantic protocol version authenticated by this session.
    pub fn protocol_version(&self) -> u16 {
        self.semantic_version
    }

    /// Highest mutually supported semantic version authenticated by this session.
    ///
    /// This is peer/session status. Applications cannot select it.
    pub fn semantic_version(&self) -> u16 {
        self.semantic_version
    }

    /// Non-secret identifier for this completed authenticated session.
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Mints one non-clone outbound Blob custody context from the completed
    /// semantic/profile negotiation and this endpoint's authenticated role.
    pub fn mint_blob_custody_send_context(
        &self,
        direction: BlobCustodyDirectionV1,
        exchange_id: u64,
        finalization_charge_ms: u64,
    ) -> Result<crate::AuthenticatedBlobCustodySendContextV1, EnvelopeError> {
        let expected_direction = match self.role {
            SessionRole::Initiator => BlobCustodyDirectionV1::ToSessionResponder,
            SessionRole::Responder => BlobCustodyDirectionV1::ToSessionInitiator,
        };
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V8
            || direction != expected_direction
            || finalization_charge_ms == 0
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobRangesStreamV1)
        {
            return Err(blob_custody_contact_unavailable());
        }
        Ok(
            crate::AuthenticatedBlobCustodySendContextV1::from_authenticated_session(
                self.session_id,
                exchange_id,
                direction,
                finalization_charge_ms,
            ),
        )
    }

    /// Returns the authenticated semantic-v9 Blob record context for the next
    /// outbound contextual record. The linear send authority is tied to that
    /// exact sequence and cannot be cloned.
    pub fn mint_blob_custody_send_context_v2(
        &self,
        direction: BlobCustodyDirectionV1,
        exchange_id: u64,
        attempt_nonce: [u8; 32],
        finalization_charge_ms: u64,
    ) -> Result<AuthenticatedBlobCustodySendContextV2, EnvelopeError> {
        let expected_direction = match self.role {
            SessionRole::Initiator => BlobCustodyDirectionV1::ToSessionResponder,
            SessionRole::Responder => BlobCustodyDirectionV1::ToSessionInitiator,
        };
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V9
            || direction != expected_direction
            || finalization_charge_ms == 0
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobStreamV1)
        {
            return Err(blob_custody_contact_unavailable());
        }
        let sequence = self
            .channel
            .next_send_sequence()
            .ok_or_else(blob_custody_contact_unavailable)?;
        let context = ApplicationRecordContext::new_v9_blob(
            profiles.digest,
            direction,
            attempt_nonce,
            sequence,
        )
        .map_err(|_| blob_custody_contact_unavailable())?;
        Ok(
            AuthenticatedBlobCustodySendContextV2::from_authenticated_record(
                self.session_id,
                exchange_id,
                context,
                finalization_charge_ms,
            ),
        )
    }

    fn v9_blob_record_context(
        &self,
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        attempt_nonce: [u8; 32],
        record_sequence: u64,
    ) -> Result<ApplicationRecordContext, EnvelopeError> {
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V9
            || transfer_profile_digest != profiles.digest
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobStreamV1)
        {
            return Err(blob_custody_contact_unavailable());
        }
        ApplicationRecordContext::new_v9_blob(
            profiles.digest,
            direction,
            attempt_nonce,
            record_sequence,
        )
        .map_err(|_| blob_custody_contact_unavailable())
    }

    /// Seals one bounded record in the v9/profile-5 attempt and sequence domain.
    pub fn seal_v9_blob_application_frame(
        &mut self,
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        attempt_nonce: [u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let sequence = self
            .channel
            .next_send_sequence()
            .ok_or_else(blob_custody_contact_unavailable)?;
        let context = self.v9_blob_record_context(
            transfer_profile_digest,
            direction,
            attempt_nonce,
            sequence,
        )?;
        self.seal_frame_with_context(plaintext, &context.aad())
    }

    /// Opens one bounded record only in its exact v9/profile-5 attempt and
    /// authenticated record-sequence domain.
    pub fn open_v9_blob_application_frame(
        &mut self,
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        attempt_nonce: [u8; 32],
        frame: &[u8],
    ) -> Result<(Vec<u8>, u64), EnvelopeError> {
        let record = decode_transport_frame(frame)?;
        let context = self.v9_blob_record_context(
            transfer_profile_digest,
            direction,
            attempt_nonce,
            record.sequence,
        )?;
        let aad = transport_frame_context_aad(&context.aad())?;
        let plaintext = self
            .channel
            .open_contextual(&self.provider, &record, &aad)
            .map_err(handshake_error)?;
        Ok((plaintext, record.sequence))
    }

    /// Seals one exact v2 custody claim at the sequence captured by its
    /// authenticated send authority.
    pub fn seal_blob_custody_frame_v2(
        &mut self,
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        attempt_nonce: [u8; 32],
        claim: &BlobCustodyClaimV2,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if claim.session_transcript() != self.session_id || claim.direction() != direction {
            return Err(blob_custody_contact_unavailable());
        }
        self.seal_v9_blob_application_frame(
            transfer_profile_digest,
            direction,
            attempt_nonce,
            &claim.encode(),
        )
    }

    /// Opens one exact v2 claim and returns its non-clone authenticated contact.
    pub fn open_blob_custody_frame_v2(
        &mut self,
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        attempt_nonce: [u8; 32],
        frame: &[u8],
    ) -> Result<(BlobCustodyClaimV2, AuthenticatedBlobCustodyContactV2), EnvelopeError> {
        let record = decode_transport_frame(frame)?;
        let context = self.v9_blob_record_context(
            transfer_profile_digest,
            direction,
            attempt_nonce,
            record.sequence,
        )?;
        let aad = transport_frame_context_aad(&context.aad())?;
        let plaintext = self
            .channel
            .open_contextual(&self.provider, &record, &aad)
            .map_err(handshake_error)?;
        let claim = BlobCustodyClaimV2::decode(&plaintext)
            .map_err(|_| blob_custody_contact_unavailable())?;
        if claim.session_transcript() != self.session_id || claim.direction() != direction {
            return Err(blob_custody_contact_unavailable());
        }
        let contact = AuthenticatedBlobCustodyContactV2::from_opened_record(
            self.session_id,
            context,
            claim.digest(),
        );
        Ok((claim, contact))
    }

    /// Opaque, authority-signed route-grant commitments from the peer credential.
    ///
    /// These bytes were authenticated by the completed handshake. They are safe
    /// to use only as input to provider authorization such as
    /// [`ReferenceEnvelopeSealer::peer_can_route`]; they confer no key access and
    /// must not be interpreted or accepted from application frames.
    pub fn peer_route_grant_commitments(&self) -> &[[u8; 32]] {
        &self.peer_route_grant_commitments
    }

    /// Encrypts and authenticates one transport-neutral replication frame.
    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        if plaintext.len() > MAX_TRANSPORT_FRAME_LEN {
            return Err(EnvelopeError("transport frame is too large".into()));
        }
        let record = self
            .channel
            .seal(&mut self.provider, plaintext, TRANSPORT_FRAME_AAD)
            .map_err(handshake_error)?;
        encode_transport_frame(&record)
    }

    /// Authenticates, decrypts, and replay-checks one transport-neutral replication frame.
    pub fn open_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let record = decode_transport_frame(frame)?;
        self.channel
            .open(&self.provider, &record, TRANSPORT_FRAME_AAD)
            .map_err(handshake_error)
    }

    /// Encrypts and authenticates one replication frame in a caller-supplied
    /// subdomain of the established transport record domain.
    ///
    /// The context is authenticated but not carried in the frame. Both peers
    /// must independently supply identical canonical bytes.
    pub fn seal_frame_with_context(
        &mut self,
        plaintext: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if plaintext.len() > MAX_TRANSPORT_FRAME_LEN {
            return Err(EnvelopeError("transport frame is too large".into()));
        }
        let aad = transport_frame_context_aad(context)?;
        let record = self
            .channel
            .seal(&mut self.provider, plaintext, &aad)
            .map_err(handshake_error)?;
        encode_transport_frame(&record)
    }

    /// Authenticates and opens a frame only in the exact caller-supplied
    /// transport-record subdomain used by its sender.
    pub fn open_frame_with_context(
        &mut self,
        frame: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let record = decode_transport_frame(frame)?;
        let aad = transport_frame_context_aad(context)?;
        self.channel
            .open_contextual(&self.provider, &record, &aad)
            .map_err(handshake_error)
    }

    /// Seals this endpoint's canonical transfer-profile offer and records it
    /// as the local half of the one authenticated negotiation for this session.
    pub fn seal_transfer_profile_offer(
        &mut self,
        offer: &TransferProfileOfferV1,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if self.semantic_version < SEMANTIC_PROTOCOL_V7
            || self.transfer_profiles.local_offer.is_some()
        {
            return Err(transfer_profile_negotiation_failed());
        }
        let body = offer
            .encode()
            .map_err(|_| transfer_profile_negotiation_failed())?;
        let authenticated = self.profile_binding_after(
            Some(offer),
            self.transfer_profiles.authenticated_peer_offer.as_ref(),
        )?;
        let mut plaintext =
            Vec::with_capacity(TRANSFER_PROFILE_OFFER_FRAME_PREFIX.len() + body.len());
        plaintext.extend_from_slice(TRANSFER_PROFILE_OFFER_FRAME_PREFIX);
        plaintext.extend_from_slice(&body);
        let frame = self.seal_frame(&plaintext)?;
        self.transfer_profiles.local_offer = Some(offer.clone());
        self.transfer_profiles.authenticated = authenticated;
        Ok(frame)
    }

    /// Opens, decodes, and records the peer's exact protected transfer-profile
    /// offer. Only this path can install peer negotiation state.
    pub fn open_transfer_profile_offer(
        &mut self,
        frame: &[u8],
    ) -> Result<TransferProfileOfferV1, EnvelopeError> {
        if self.semantic_version < SEMANTIC_PROTOCOL_V7
            || self.transfer_profiles.authenticated_peer_offer.is_some()
        {
            return Err(transfer_profile_negotiation_failed());
        }
        let plaintext = self.open_frame(frame)?;
        let body = plaintext
            .strip_prefix(TRANSFER_PROFILE_OFFER_FRAME_PREFIX)
            .ok_or_else(transfer_profile_negotiation_failed)?;
        let offer = TransferProfileOfferV1::decode(body)
            .map_err(|_| transfer_profile_negotiation_failed())?;
        let authenticated =
            self.profile_binding_after(self.transfer_profiles.local_offer.as_ref(), Some(&offer))?;
        self.transfer_profiles.authenticated_peer_offer = Some(offer.clone());
        self.transfer_profiles.authenticated = authenticated;
        Ok(offer)
    }

    /// Selected profile from the authenticated, completed offer exchange.
    pub fn negotiated_transfer_profile(&self, lane: TransferLaneId) -> Option<TransferProfileId> {
        self.transfer_profiles
            .authenticated
            .as_ref()
            .and_then(|profiles| profiles.negotiated.profile(lane))
    }

    fn profile_binding_after(
        &self,
        local: Option<&TransferProfileOfferV1>,
        peer: Option<&TransferProfileOfferV1>,
    ) -> Result<Option<AuthenticatedTransferProfiles>, EnvelopeError> {
        let (Some(local), Some(peer)) = (local, peer) else {
            return Ok(None);
        };
        let (initiator, responder) = match self.role {
            SessionRole::Initiator => (local, peer),
            SessionRole::Responder => (peer, local),
        };
        let negotiated = negotiate_transfer_profiles_for_semantic_version(
            self.semantic_version,
            initiator,
            responder,
        )
        .map_err(|_| transfer_profile_negotiation_failed())?;
        let digest = transfer_profile_digest(initiator, responder, &negotiated);
        Ok(Some(AuthenticatedTransferProfiles { negotiated, digest }))
    }

    /// Protects a complete v8 Blob source-bearing frame in the authenticated
    /// profile-4 context. Durable frames end in the canonical absent field;
    /// finite frames end in the exact canonical claim supplied here.
    pub fn seal_blob_source_frame(
        &mut self,
        direction: BlobCustodyDirectionV1,
        claim: Option<&BlobCustodyClaimV1>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let expected_direction = match self.role {
            SessionRole::Initiator => BlobCustodyDirectionV1::ToSessionResponder,
            SessionRole::Responder => BlobCustodyDirectionV1::ToSessionInitiator,
        };
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V8
            || direction != expected_direction
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobRangesStreamV1)
        {
            return Err(blob_custody_contact_unavailable());
        }
        match claim {
            None if plaintext.last() == Some(&0) => {}
            Some(claim) => {
                let encoded = claim.encode();
                let tail_len = 1 + 2 + encoded.len();
                let Some(tail) = plaintext.get(plaintext.len().saturating_sub(tail_len)..) else {
                    return Err(blob_custody_contact_unavailable());
                };
                if claim.session_transcript() != self.session_id
                    || claim.direction() != direction
                    || tail[0] != 1
                    || tail[1..3] != (encoded.len() as u16).to_be_bytes()
                    || tail[3..] != encoded
                {
                    return Err(blob_custody_contact_unavailable());
                }
            }
            None => return Err(blob_custody_contact_unavailable()),
        }
        let context = blob_custody_lane_record_context(profiles.digest, direction);
        self.seal_frame_with_context(plaintext, &context)
    }

    /// Opens one complete v8 Blob source-bearing frame under profile 4.
    /// Finite frames return the one-use contact authority for their exact
    /// embedded claim; durable frames return no custody authority.
    pub fn open_blob_source_frame(
        &mut self,
        direction: BlobCustodyDirectionV1,
        frame: &[u8],
    ) -> Result<crate::OpenedBlobSourceFrameV1, EnvelopeError> {
        let expected_direction = match self.role {
            SessionRole::Initiator => BlobCustodyDirectionV1::ToSessionInitiator,
            SessionRole::Responder => BlobCustodyDirectionV1::ToSessionResponder,
        };
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V8
            || direction != expected_direction
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobRangesStreamV1)
        {
            return Err(blob_custody_contact_unavailable());
        }
        let record = decode_transport_frame(frame)?;
        let record_sequence = record.sequence;
        let context = blob_custody_lane_record_context(profiles.digest, direction);
        let aad = transport_frame_context_aad(&context)?;
        let plaintext = self
            .channel
            .open_contextual(&self.provider, &record, &aad)
            .map_err(handshake_error)?;
        let tail_len = 1 + 2 + crate::BLOB_CUSTODY_CLAIM_V1_BYTES;
        let tail = plaintext.get(plaintext.len().saturating_sub(tail_len)..);
        if !tail.is_some_and(|tail| {
            tail[0] == 1 && tail[1..3] == (crate::BLOB_CUSTODY_CLAIM_V1_BYTES as u16).to_be_bytes()
        }) {
            return if plaintext.last() == Some(&0) {
                Ok((plaintext, None))
            } else {
                Err(blob_custody_contact_unavailable())
            };
        }
        let tail = tail.expect("checked finite Blob source tail");
        let claim = BlobCustodyClaimV1::decode(&tail[3..])
            .map_err(|_| blob_custody_contact_unavailable())?;
        if claim.session_transcript() != self.session_id || claim.direction() != direction {
            return Err(blob_custody_contact_unavailable());
        }
        let authority = AuthenticatedBlobCustodyContactV1::from_opened_record(
            self.session_id,
            profiles.digest,
            direction,
            record_sequence,
            claim.digest(),
        );
        Ok((plaintext, Some((claim, authority))))
    }

    /// Protects one frame in the fixed semantic-v8 Blob lane/profile-4 domain.
    ///
    /// This allocates no finite Blob lifecycle behavior; it only ensures that a
    /// later receiver capability can be tied to the authenticated profile/lane
    /// record rather than caller-selected claim fields.
    pub fn seal_blob_custody_frame(
        &mut self,
        direction: BlobCustodyDirectionV1,
        claim: &BlobCustodyClaimV1,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let expected_direction = match self.role {
            SessionRole::Initiator => BlobCustodyDirectionV1::ToSessionResponder,
            SessionRole::Responder => BlobCustodyDirectionV1::ToSessionInitiator,
        };
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V8
            || direction != expected_direction
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobRangesStreamV1)
            || claim.session_transcript() != self.session_id
            || claim.direction() != direction
        {
            return Err(blob_custody_contact_unavailable());
        }
        let context = blob_custody_lane_record_context(profiles.digest, direction);
        self.seal_frame_with_context(&claim.encode(), &context)
    }

    /// Authenticates, replay-checks, and canonically decodes one fixed
    /// semantic-v8 Blob/profile-4 claim record with its opaque contact authority.
    ///
    /// The returned capability is bound to this completed session transcript,
    /// exact negotiated-profile digest, Blob profile/direction AAD, and accepted
    /// record sequence and exact 208-byte claim digest. Raw application values
    /// cannot construct it.
    pub fn open_blob_custody_frame(
        &mut self,
        direction: BlobCustodyDirectionV1,
        frame: &[u8],
    ) -> Result<(BlobCustodyClaimV1, AuthenticatedBlobCustodyContactV1), EnvelopeError> {
        let expected_direction = match self.role {
            SessionRole::Initiator => BlobCustodyDirectionV1::ToSessionInitiator,
            SessionRole::Responder => BlobCustodyDirectionV1::ToSessionResponder,
        };
        let profiles = self
            .transfer_profiles
            .authenticated
            .as_ref()
            .ok_or_else(blob_custody_contact_unavailable)?;
        if self.semantic_version != SEMANTIC_PROTOCOL_V8
            || direction != expected_direction
            || profiles.negotiated.profile(TransferLaneId::Blob)
                != Some(TransferProfileId::BlobRangesStreamV1)
        {
            return Err(blob_custody_contact_unavailable());
        }
        let record = decode_transport_frame(frame)?;
        let record_sequence = record.sequence;
        let context = blob_custody_lane_record_context(profiles.digest, direction);
        let aad = transport_frame_context_aad(&context)?;
        let plaintext = self
            .channel
            .open_contextual(&self.provider, &record, &aad)
            .map_err(handshake_error)?;
        let claim = BlobCustodyClaimV1::decode(&plaintext)
            .map_err(|_| blob_custody_contact_unavailable())?;
        if claim.session_transcript() != self.session_id || claim.direction() != direction {
            return Err(blob_custody_contact_unavailable());
        }
        let authority = AuthenticatedBlobCustodyContactV1::from_opened_record(
            self.session_id,
            profiles.digest,
            direction,
            record_sequence,
            claim.digest(),
        );
        Ok((claim, authority))
    }

    /// Encrypts and authenticates one fixed, transfer-bound semantic-v3 custody claim.
    ///
    /// Stable source bytes and range payloads remain in the ordinary peer-neutral
    /// transfer path.  Only the bounded claim is placed in this distinct session
    /// record domain.
    pub fn seal_custody_wrapper(
        &mut self,
        claims: &CustodyClaims,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if self.semantic_version < MIN_CUSTODY_SEMANTIC_VERSION {
            return Err(custody_version_unavailable());
        }
        let mut plaintext =
            encode_claims(*claims, self.session_id).map_err(|_| custody_authentication_failed())?;
        let record = self
            .channel
            .seal(&mut self.provider, &plaintext, CUSTODY_WRAPPER_AAD);
        plaintext.zeroize();
        let wrapper = encode_transport_frame(&record.map_err(custody_channel_error)?)?;
        if wrapper.len() > MAX_CUSTODY_WRAPPER_BYTES {
            return Err(custody_authentication_failed());
        }
        Ok(wrapper)
    }

    /// Authenticates, replay-checks, and context-checks one semantic-v3 custody claim.
    ///
    /// `expected` must be built from the live exchange and freshly verified
    /// stable source header, so TTL and priority cannot be relabelled by a relay.
    pub fn open_custody_wrapper(
        &mut self,
        wrapper: &[u8],
        expected: CustodyExpectation,
    ) -> Result<VerifiedCustodyClaims, EnvelopeError> {
        if self.semantic_version < MIN_CUSTODY_SEMANTIC_VERSION {
            return Err(custody_version_unavailable());
        }
        if wrapper.is_empty() || wrapper.len() > MAX_CUSTODY_WRAPPER_BYTES {
            return Err(custody_authentication_failed());
        }
        let record =
            decode_transport_frame(wrapper).map_err(|_| custody_authentication_failed())?;
        let mut plaintext = self
            .channel
            .open(&self.provider, &record, CUSTODY_WRAPPER_AAD)
            .map_err(custody_channel_error)?;
        let decoded = decode_claims(&plaintext, self.session_id).and_then(|claims| {
            claims
                .verify_expected(expected)
                .map(|()| VerifiedCustodyClaims::from_authenticated(claims))
        });
        plaintext.zeroize();
        decoded.map_err(|_| custody_authentication_failed())
    }

    /// Rapidly erases directional traffic keys.
    pub fn zeroize(&mut self) {
        self.channel.zeroize();
    }
}

impl Drop for ReferenceAuthenticatedSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Ready-to-use node type backed by SQLite and the reference envelope service.
#[cfg(feature = "sqlite-store")]
pub type ReferenceNode = Node<SqliteStore, ReferenceEnvelopeSealer>;

/// Opens a node without allowing an identity/key mismatch at the call site.
#[cfg(feature = "sqlite-store")]
pub fn open_reference_node(
    path: impl AsRef<Path>,
    bundle: ProvisioningBundle,
    config: NodeConfig,
) -> Result<ReferenceNode, EngineError> {
    let sealer = ReferenceEnvelopeSealer::open(bundle).map_err(EngineError::Envelope)?;
    let identity = sealer.identity();
    let mut node = Node::open(path, identity, sealer, config)?;
    node.reauthenticate_application_batch_state()?;
    Ok(node)
}

fn handshake_error(error: CryptoError) -> EnvelopeError {
    match error {
        CryptoError::RandomnessUnavailable => reference_open_error(error),
        CryptoError::ReplayDetected | CryptoError::ReplayTooOld => {
            EnvelopeError("transport frame replay rejected".into())
        }
        CryptoError::SequenceExhausted => {
            EnvelopeError("transport frame sequence exhausted".into())
        }
        _ => authentication_failed(),
    }
}

fn custody_channel_error(error: CryptoError) -> EnvelopeError {
    match error {
        CryptoError::ReplayDetected | CryptoError::ReplayTooOld => {
            EnvelopeError("custody wrapper replay rejected".into())
        }
        CryptoError::SequenceExhausted => {
            EnvelopeError("custody wrapper sequence exhausted".into())
        }
        CryptoError::RandomnessUnavailable => reference_open_error(error),
        _ => custody_authentication_failed(),
    }
}

fn custody_authentication_failed() -> EnvelopeError {
    EnvelopeError("custody wrapper authentication failed".into())
}

fn custody_version_unavailable() -> EnvelopeError {
    EnvelopeError("semantic protocol v3 custody is unavailable".into())
}

fn blob_custody_contact_unavailable() -> EnvelopeError {
    EnvelopeError("authenticated Blob contact context is unavailable".into())
}

fn transfer_profile_negotiation_failed() -> EnvelopeError {
    EnvelopeError("authenticated transfer-profile negotiation failed".into())
}

fn handshake_prefix(kind: u8) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(HANDSHAKE_MAGIC);
    output.extend_from_slice(&HANDSHAKE_FRAMING_VERSION.to_be_bytes());
    output.extend_from_slice(&HANDSHAKE_PROFILE_ID.to_be_bytes());
    output.push(kind);
    output.push(0);
    output
}

fn handshake_reader<'a>(bytes: &'a [u8], expected_kind: u8) -> Result<Reader<'a>, EnvelopeError> {
    if bytes.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(HANDSHAKE_MAGIC.len())? != HANDSHAKE_MAGIC
        || reader.u16()? != HANDSHAKE_FRAMING_VERSION
        || reader.u16()? != HANDSHAKE_PROFILE_ID
        || reader.u8()? != expected_kind
        || reader.u8()? != 0
    {
        return Err(authentication_failed());
    }
    Ok(reader)
}

fn encode_flight_credential(
    output: &mut Vec<u8>,
    credential: &Credential,
) -> Result<(), EnvelopeError> {
    push_u32_bytes(output, &credential.body)?;
    encode_signature(output, &credential.signature)
}

fn decode_flight_credential(
    reader: &mut Reader<'_>,
) -> Result<(Vec<u8>, HybridSignature), EnvelopeError> {
    let body = reader.u32_bytes(16 * 1024)?.to_vec();
    let signature = decode_signature(reader)?;
    Ok((body, signature))
}

fn encode_client_auth_context(credential: &Credential) -> Result<Vec<u8>, EnvelopeError> {
    let mut output = Vec::new();
    encode_flight_credential(&mut output, credential)?;
    Ok(output)
}

fn decode_client_auth_context(bytes: &[u8]) -> Result<(Vec<u8>, HybridSignature), EnvelopeError> {
    let mut reader = Reader::new(bytes);
    let credential = decode_flight_credential(&mut reader)?;
    reader.finish()?;
    Ok(credential)
}

fn encode_server_auth_context(
    mission_proof_commitment: [u8; 32],
    credential: &Credential,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut output = Vec::new();
    output.extend_from_slice(&mission_proof_commitment);
    encode_flight_credential(&mut output, credential)?;
    Ok(output)
}

fn decode_server_auth_context(
    bytes: &[u8],
) -> Result<([u8; 32], Vec<u8>, HybridSignature), EnvelopeError> {
    let mut reader = Reader::new(bytes);
    let mission_proof_commitment = reader.array::<32>()?;
    let (credential, signature) = decode_flight_credential(&mut reader)?;
    reader.finish()?;
    Ok((mission_proof_commitment, credential, signature))
}

fn mission_proof_aad(hello_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MISSION_PROOF_AAD_DOMAIN.len() + hello_hash.len());
    aad.extend_from_slice(MISSION_PROOF_AAD_DOMAIN);
    aad.extend_from_slice(hello_hash);
    aad
}

fn create_mission_proof(
    endpoint: &SessionEndpoint,
    hello: &ClientHello,
) -> Result<AeadCiphertext, EnvelopeError> {
    let hello_hash = client_hello_hash(&endpoint.provider, hello).map_err(handshake_error)?;
    let mut key = derive_material::<32>(
        endpoint.mission_proof_key.expose(),
        MISSION_PROOF_KEY_LABEL,
        &hello_hash,
    )?;
    let mut nonce = derive_material::<NONCE_LEN>(
        endpoint.mission_proof_key.expose(),
        MISSION_PROOF_NONCE_LABEL,
        &hello_hash,
    )?;
    let mut key_array = Array(key);
    let cipher = Aes256Gcm::new(&key_array);
    key_array.as_mut_slice().zeroize();
    key.zeroize();
    let nonce_array = Array(nonce);
    let aad = mission_proof_aad(&hello_hash);
    let mut ciphertext = Vec::new();
    let result = cipher
        .encrypt_in_place(&nonce_array, &aad, &mut ciphertext)
        .map_err(|_| authentication_failed());
    nonce.zeroize();
    result?;
    Ok(AeadCiphertext {
        nonce: nonce_array.into(),
        ciphertext,
    })
}

fn verify_mission_proof(
    endpoint: &SessionEndpoint,
    hello: &ClientHello,
    proof: &AeadCiphertext,
) -> Result<(), EnvelopeError> {
    if proof.ciphertext.len() != GCM_TAG_LEN {
        return Err(authentication_failed());
    }
    let hello_hash = client_hello_hash(&endpoint.provider, hello).map_err(handshake_error)?;
    let mut key = derive_material::<32>(
        endpoint.mission_proof_key.expose(),
        MISSION_PROOF_KEY_LABEL,
        &hello_hash,
    )?;
    let mut expected_nonce = derive_material::<NONCE_LEN>(
        endpoint.mission_proof_key.expose(),
        MISSION_PROOF_NONCE_LABEL,
        &hello_hash,
    )?;
    if proof.nonce != expected_nonce {
        key.zeroize();
        expected_nonce.zeroize();
        return Err(authentication_failed());
    }
    let mut key_array = Array(key);
    let cipher = Aes256Gcm::new(&key_array);
    key_array.as_mut_slice().zeroize();
    key.zeroize();
    let nonce_array = Array(expected_nonce);
    let aad = mission_proof_aad(&hello_hash);
    let mut plaintext = proof.ciphertext.clone();
    let result = cipher
        .decrypt_in_place(&nonce_array, &aad, &mut plaintext)
        .map_err(|_| authentication_failed());
    expected_nonce.zeroize();
    if result.is_err() || !plaintext.is_empty() {
        plaintext.zeroize();
        return Err(authentication_failed());
    }
    plaintext.zeroize();
    Ok(())
}

fn mission_proof_commitment(proof: &AeadCiphertext) -> Result<[u8; 32], EnvelopeError> {
    let mut encoded = Vec::with_capacity(NONCE_LEN + 4 + proof.ciphertext.len());
    encode_aead(&mut encoded, proof)?;
    Ok(hash_domain(MISSION_PROOF_TRANSCRIPT_DOMAIN, &encoded))
}

fn encode_client_flight(
    hello: &ClientHello,
    mission_proof: &AeadCiphertext,
) -> Result<Vec<u8>, EnvelopeError> {
    super::validate_client_hello(hello).map_err(handshake_error)?;
    let mut output = handshake_prefix(1);
    let version_count =
        u16::try_from(hello.supported_versions.len()).map_err(|_| invalid_envelope())?;
    output.extend_from_slice(&version_count.to_be_bytes());
    for version in &hello.supported_versions {
        output.extend_from_slice(&version.to_be_bytes());
    }
    let suite_count = u16::try_from(hello.offered_suites.len()).map_err(|_| invalid_envelope())?;
    output.extend_from_slice(&suite_count.to_be_bytes());
    for suite in &hello.offered_suites {
        output.extend_from_slice(&suite.to_be_bytes());
    }
    output.extend_from_slice(&hello.initiator_nonce);
    push_u16_bytes(&mut output, &hello.p256_ephemeral_public)?;
    push_u32_bytes(&mut output, &hello.ml_kem_768_encapsulation_key)?;
    encode_aead(&mut output, mission_proof)?;
    if output.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(invalid_envelope());
    }
    Ok(output)
}

fn decode_client_flight(bytes: &[u8]) -> Result<(ClientHello, AeadCiphertext), EnvelopeError> {
    let mut reader = handshake_reader(bytes, 1)?;
    let version_count = usize::from(reader.u16()?);
    if !(1..=MAX_HANDSHAKE_OFFERS).contains(&version_count) {
        return Err(authentication_failed());
    }
    let mut supported_versions = Vec::with_capacity(version_count);
    for _ in 0..version_count {
        supported_versions.push(reader.u16()?);
    }
    let suite_count = usize::from(reader.u16()?);
    if !(1..=MAX_HANDSHAKE_OFFERS).contains(&suite_count) {
        return Err(authentication_failed());
    }
    let mut offered_suites = Vec::with_capacity(suite_count);
    for _ in 0..suite_count {
        offered_suites.push(reader.u16()?);
    }
    let initiator_nonce = reader.array::<32>()?;
    let p256_ephemeral_public = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let ml_kem_768_encapsulation_key = reader.u32_bytes(ML_KEM_PUBLIC_LEN)?.to_vec();
    let mission_proof = decode_aead(&mut reader, GCM_TAG_LEN)?;
    reader.finish()?;
    if p256_ephemeral_public.len() != P256_PUBLIC_LEN
        || ml_kem_768_encapsulation_key.len() != ML_KEM_PUBLIC_LEN
        || mission_proof.ciphertext.len() != GCM_TAG_LEN
    {
        return Err(authentication_failed());
    }
    let hello = ClientHello {
        supported_versions,
        offered_suites,
        initiator_nonce,
        p256_ephemeral_public,
        ml_kem_768_encapsulation_key,
    };
    super::validate_client_hello(&hello).map_err(handshake_error)?;
    Ok((hello, mission_proof))
}

fn encode_aead(output: &mut Vec<u8>, sealed: &AeadCiphertext) -> Result<(), EnvelopeError> {
    output.extend_from_slice(&sealed.nonce);
    push_u32_bytes(output, &sealed.ciphertext)
}

fn encode_rekey_package(
    output: &mut Vec<u8>,
    format: u16,
    package: &DecodedRekeyPackage,
) -> Result<(), EnvelopeError> {
    if !matches!(
        format,
        SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
    ) || (format == SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT && !package.route_access)
        || package.p256_ephemeral_public.len() != P256_PUBLIC_LEN
        || package.ml_kem_768_ciphertext.len() != ML_KEM_CIPHERTEXT_LEN
        || !(GCM_TAG_LEN + 1..=MAX_REKEY_PACKAGE_CIPHERTEXT_LEN)
            .contains(&package.sealed_grants.ciphertext.len())
    {
        return Err(invalid_envelope());
    }
    output.extend_from_slice(&package.recipient);
    output.extend_from_slice(&package.credential_hash);
    output.extend_from_slice(&package.grant_commitment);
    if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
        output.push(u8::from(package.route_access));
    }
    push_u16_bytes(output, &package.p256_ephemeral_public)?;
    push_u32_bytes(output, &package.ml_kem_768_ciphertext)?;
    encode_aead(output, &package.sealed_grants)
}

fn decode_aead(reader: &mut Reader<'_>, maximum: usize) -> Result<AeadCiphertext, EnvelopeError> {
    let nonce = reader.array::<NONCE_LEN>()?;
    let ciphertext = reader.u32_bytes(maximum)?.to_vec();
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(authentication_failed());
    }
    Ok(AeadCiphertext { nonce, ciphertext })
}

fn encode_server_flight(hello: &ServerHello) -> Result<Vec<u8>, EnvelopeError> {
    let mut output = handshake_prefix(2);
    output.extend_from_slice(&hello.selected_version.to_be_bytes());
    output.extend_from_slice(&hello.selected_suite.to_be_bytes());
    output.extend_from_slice(&hello.responder_nonce);
    push_u16_bytes(&mut output, &hello.p256_ephemeral_public)?;
    push_u32_bytes(&mut output, &hello.ml_kem_768_ciphertext)?;
    encode_aead(&mut output, &hello.protected_auth)?;
    encode_aead(&mut output, &hello.confirmation)?;
    if output.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(invalid_envelope());
    }
    Ok(output)
}

fn decode_server_flight(bytes: &[u8]) -> Result<ServerHello, EnvelopeError> {
    let mut reader = handshake_reader(bytes, 2)?;
    let selected_version = reader.u16()?;
    let selected_suite = reader.u16()?;
    let responder_nonce = reader.array::<32>()?;
    let p256_ephemeral_public = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let ml_kem_768_ciphertext = reader.u32_bytes(ML_KEM_CIPHERTEXT_LEN)?.to_vec();
    let protected_auth = decode_aead(&mut reader, MAX_HANDSHAKE_FLIGHT_LEN)?;
    let confirmation = decode_aead(&mut reader, GCM_TAG_LEN)?;
    reader.finish()?;
    if p256_ephemeral_public.len() != P256_PUBLIC_LEN
        || ml_kem_768_ciphertext.len() != ML_KEM_CIPHERTEXT_LEN
        || protected_auth.ciphertext.len() <= GCM_TAG_LEN
        || confirmation.ciphertext.len() != GCM_TAG_LEN
    {
        return Err(authentication_failed());
    }
    Ok(ServerHello {
        selected_version,
        selected_suite,
        responder_nonce,
        p256_ephemeral_public,
        ml_kem_768_ciphertext,
        protected_auth,
        confirmation,
    })
}

fn encode_client_auth_flight(finish: &ClientFinish) -> Result<Vec<u8>, EnvelopeError> {
    let mut output = handshake_prefix(3);
    encode_aead(&mut output, &finish.protected_auth)?;
    encode_aead(&mut output, &finish.confirmation)?;
    if output.len() > MAX_HANDSHAKE_FLIGHT_LEN {
        return Err(invalid_envelope());
    }
    Ok(output)
}

fn decode_client_auth_flight(bytes: &[u8]) -> Result<ClientFinish, EnvelopeError> {
    let mut reader = handshake_reader(bytes, 3)?;
    let protected_auth = decode_aead(&mut reader, MAX_HANDSHAKE_FLIGHT_LEN)?;
    let confirmation = decode_aead(&mut reader, GCM_TAG_LEN)?;
    reader.finish()?;
    if protected_auth.ciphertext.len() <= GCM_TAG_LEN
        || confirmation.ciphertext.len() != GCM_TAG_LEN
    {
        return Err(authentication_failed());
    }
    Ok(ClientFinish {
        protected_auth,
        confirmation,
    })
}

fn encode_record_body(
    output: &mut Vec<u8>,
    record: &SequencedCiphertext,
) -> Result<(), EnvelopeError> {
    output.extend_from_slice(&record.sequence.to_be_bytes());
    encode_aead(output, &record.sealed)
}

fn decode_record_body(
    reader: &mut Reader<'_>,
    maximum: usize,
) -> Result<SequencedCiphertext, EnvelopeError> {
    let sequence = reader.u64()?;
    let sealed = decode_aead(reader, maximum)?;
    Ok(SequencedCiphertext { sequence, sealed })
}

fn encode_server_finished_flight(finished: &ServerFinished) -> Result<Vec<u8>, EnvelopeError> {
    let mut output = handshake_prefix(4);
    encode_aead(&mut output, &finished.protected_finished)?;
    Ok(output)
}

fn decode_server_finished_flight(bytes: &[u8]) -> Result<ServerFinished, EnvelopeError> {
    let mut reader = handshake_reader(bytes, 4)?;
    let protected_finished = decode_aead(&mut reader, 32 + GCM_TAG_LEN)?;
    reader.finish()?;
    if protected_finished.ciphertext.len() != 32 + GCM_TAG_LEN {
        return Err(authentication_failed());
    }
    Ok(ServerFinished { protected_finished })
}

fn transport_frame_context_aad(context: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let context_len = u32::try_from(context.len())
        .map_err(|_| EnvelopeError("transport frame context is too large".into()))?;
    let mut aad = Vec::with_capacity(TRANSPORT_FRAME_AAD.len() + 4 + context.len());
    aad.extend_from_slice(TRANSPORT_FRAME_AAD);
    aad.extend_from_slice(&context_len.to_be_bytes());
    aad.extend_from_slice(context);
    Ok(aad)
}

fn encode_transport_frame(record: &SequencedCiphertext) -> Result<Vec<u8>, EnvelopeError> {
    let mut output = Vec::new();
    output.extend_from_slice(FRAME_MAGIC);
    output.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    output.extend_from_slice(&SUITE_ID.to_be_bytes());
    encode_record_body(&mut output, record)?;
    Ok(output)
}

fn decode_transport_frame(bytes: &[u8]) -> Result<SequencedCiphertext, EnvelopeError> {
    if bytes.len() > MAX_TRANSPORT_FRAME_LEN + 128 {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(FRAME_MAGIC.len())? != FRAME_MAGIC
        || reader.u16()? != PROTOCOL_VERSION
        || reader.u16()? != SUITE_ID
    {
        return Err(authentication_failed());
    }
    let record = decode_record_body(&mut reader, MAX_TRANSPORT_FRAME_LEN + GCM_TAG_LEN)?;
    reader.finish()?;
    Ok(record)
}

struct ParsedEnvelope<'a> {
    kind: EnvelopeKind,
    selector: [u8; SELECTOR_LEN],
    public_header: &'a [u8],
    route_ciphertext: &'a [u8],
    content_ciphertext: &'a [u8],
}

struct ParsedBatchEnvelope<'a> {
    object_kind: u8,
    selector: [u8; SELECTOR_LEN],
    public_header: &'a [u8],
    route_ciphertext: &'a [u8],
    content_ciphertext: &'a [u8],
}

struct ParsedBridgeObject<'a> {
    selector: [u8; SELECTOR_LEN],
    header: &'a [u8],
    ciphertext: &'a [u8],
}

struct DecodedDataRoute {
    credential: Credential,
    item_id: [u8; 32],
    header: EnvelopeHeader,
    content_group: [u8; 32],
    content_nonce: [u8; NONCE_LEN],
    batch_id: [u8; 32],
    content_ciphertext_len: u64,
    item_signature: HybridSignature,
}

struct DecodedCompactBatchRoute {
    item_id: [u8; 32],
    header: EnvelopeHeader,
    content_group: [u8; 32],
    content_nonce: [u8; NONCE_LEN],
    content_ciphertext_len: u64,
    authentication: batch::CompactAuthentication,
}

struct PreparedBatchItem {
    item_id: [u8; 32],
    header: EnvelopeHeader,
    content_nonce: [u8; NONCE_LEN],
    content_ciphertext: Vec<u8>,
    leaf: batch::BatchLeaf,
}

enum DecodedControl {
    Revocation {
        signer: NodeId,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
        subject: NodeId,
        generation: u64,
    },
    ScopeEpoch {
        signer: NodeId,
        sequence: u64,
        previous: Option<crate::store::EnvelopeId>,
        scope: Scope,
        epoch: u64,
        keying: ScopeEpochKeying,
    },
}

struct DecodedRekeyPackage {
    recipient: NodeId,
    credential_hash: [u8; 32],
    grant_commitment: [u8; 32],
    route_access: bool,
    p256_ephemeral_public: Vec<u8>,
    ml_kem_768_ciphertext: Vec<u8>,
    sealed_grants: AeadCiphertext,
}

struct DecodedRekeyGrants {
    route_key: Option<Secret32>,
    content_keys: Vec<(Topic, Secret32)>,
}

enum ScopeEpochKeying {
    LegacyPreprovisioned,
    RecipientPackages {
        format: u16,
        package_set_hash: [u8; 32],
        packages: Vec<DecodedRekeyPackage>,
    },
}

fn invalid_bundle() -> EnvelopeError {
    EnvelopeError("invalid provisioning bundle".into())
}

fn invalid_envelope() -> EnvelopeError {
    EnvelopeError("invalid canonical envelope encoding".into())
}

fn authentication_failed() -> EnvelopeError {
    EnvelopeError("envelope authentication failed".into())
}

fn batch_construction_error(error: batch::BatchError) -> EnvelopeError {
    EnvelopeError(format!("batch construction failed: {error}"))
}

fn batch_authentication_error(_: batch::BatchError) -> EnvelopeError {
    authentication_failed()
}

fn zeroized_service() -> EnvelopeError {
    EnvelopeError("cryptographic service is zeroized".into())
}

fn envelope_crypto_error(_error: CryptoError) -> EnvelopeError {
    authentication_failed()
}

fn bridge_authentication_error(_error: bridge::BridgeCodecError) -> EnvelopeError {
    authentication_failed()
}

fn reference_open_error(error: CryptoError) -> EnvelopeError {
    match error {
        CryptoError::RandomnessUnavailable => {
            EnvelopeError("operating-system cryptographic randomness is unavailable".into())
        }
        _ => EnvelopeError("failed to initialize reference cryptographic service".into()),
    }
}

fn hash_domain(domain: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((input.len() as u64).to_be_bytes());
    hash.update(input);
    let digest = hash.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn derive_material<const N: usize>(
    root: &[u8; 32],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; N], EnvelopeError> {
    let label_len = u16::try_from(label.len()).map_err(|_| invalid_envelope())?;
    let context_len = u32::try_from(context.len()).map_err(|_| invalid_envelope())?;
    let mut info = Vec::with_capacity(2 + label.len() + 4 + context.len());
    info.extend_from_slice(&label_len.to_be_bytes());
    info.extend_from_slice(label);
    info.extend_from_slice(&context_len.to_be_bytes());
    info.extend_from_slice(context);
    let hkdf = Hkdf::<Sha256>::new(Some(KDF_SALT), root);
    let mut output = [0u8; N];
    hkdf.expand(&info, &mut output)
        .map_err(|_| EnvelopeError("failed to derive provisioned key material".into()))?;
    Ok(output)
}

fn derive_item_secret(
    root: &[u8; 32],
    label: &[u8],
    context: &[u8],
) -> Result<Secret32, EnvelopeError> {
    Ok(Secret32::new(derive_material(root, label, context)?))
}

fn random_secret(provider: &mut RustCryptoProvider<SysRng>) -> Result<Secret32, EnvelopeError> {
    let mut bytes = [0u8; 32];
    provider
        .fill_random(&mut bytes)
        .map_err(reference_open_error)?;
    let secret = Secret32::new(bytes);
    bytes.zeroize();
    Ok(secret)
}

fn rekey_credential_hash(credential: &Credential) -> Result<[u8; 32], EnvelopeError> {
    let mut encoded = Vec::new();
    encode_flight_credential(&mut encoded, credential)?;
    Ok(hash_domain(REKEY_CREDENTIAL_DOMAIN, &encoded))
}

#[allow(clippy::too_many_arguments)]
fn rekey_grant_commitment(
    format: u16,
    scope: &Scope,
    epoch: u64,
    recipient: NodeId,
    credential_hash: &[u8; 32],
    grant_salt: &Secret32,
    route_access: bool,
    readable_topics: &[Topic],
) -> Result<[u8; 32], EnvelopeError> {
    if !matches!(
        format,
        SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
    ) || (format == SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT && !route_access)
        || (!route_access && readable_topics.is_empty())
        || readable_topics.len() > MAX_REKEY_TOPICS_PER_RECIPIENT
        || readable_topics.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid_envelope());
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    encoded.extend_from_slice(&SUITE_ID.to_be_bytes());
    if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
        encoded.extend_from_slice(&format.to_be_bytes());
        encoded.push(u8::from(route_access));
    }
    push_u16_bytes(&mut encoded, scope.as_str().as_bytes())?;
    encoded.extend_from_slice(&epoch.to_be_bytes());
    encoded.extend_from_slice(&recipient);
    encoded.extend_from_slice(credential_hash);
    encoded.extend_from_slice(grant_salt.expose());
    encoded.extend_from_slice(
        &u16::try_from(readable_topics.len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    for topic in readable_topics {
        push_u16_bytes(&mut encoded, topic.as_str().as_bytes())?;
    }
    let domain = if format == SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT {
        REKEY_GRANT_DOMAIN
    } else {
        REKEY_CAPABILITY_GRANT_DOMAIN
    };
    let commitment = hash_domain(domain, &encoded);
    encoded.zeroize();
    Ok(commitment)
}

fn rekey_package_set_hash(
    format: u16,
    descriptors: &[(NodeId, [u8; 32], [u8; 32], bool)],
) -> Result<[u8; 32], EnvelopeError> {
    if !matches!(
        format,
        SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
    ) || descriptors.is_empty()
        || descriptors.len() > MAX_REKEY_RECIPIENTS
        || descriptors.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || (format == SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT
            && descriptors.iter().any(|descriptor| !descriptor.3))
    {
        return Err(invalid_envelope());
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    encoded.extend_from_slice(&SUITE_ID.to_be_bytes());
    encoded.extend_from_slice(&format.to_be_bytes());
    encoded.extend_from_slice(
        &u16::try_from(descriptors.len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    for (recipient, credential_hash, grant_commitment, route_access) in descriptors {
        encoded.extend_from_slice(recipient);
        encoded.extend_from_slice(credential_hash);
        encoded.extend_from_slice(grant_commitment);
        if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
            encoded.push(u8::from(*route_access));
        }
    }
    Ok(hash_domain(REKEY_PACKAGE_SET_DOMAIN, &encoded))
}

fn append_control_link(
    output: &mut Vec<u8>,
    sequence: u64,
    previous: Option<crate::store::EnvelopeId>,
) {
    output.extend_from_slice(&sequence.to_be_bytes());
    match previous {
        Some(previous) => {
            output.push(1);
            output.extend_from_slice(&previous);
        }
        None => output.push(0),
    }
}

#[allow(clippy::too_many_arguments)]
fn rekey_package_context(
    format: u16,
    mission: &[u8; 32],
    authority: NodeId,
    scope: &Scope,
    epoch: u64,
    sequence: u64,
    previous: Option<crate::store::EnvelopeId>,
    package_set_hash: &[u8; 32],
    package: &DecodedRekeyPackage,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut context = Vec::new();
    context.extend_from_slice(REKEY_PACKAGE_CONTEXT_DOMAIN);
    context.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    context.extend_from_slice(&SUITE_ID.to_be_bytes());
    if !matches!(
        format,
        SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
    ) {
        return Err(invalid_envelope());
    }
    context.extend_from_slice(&format.to_be_bytes());
    context.extend_from_slice(mission);
    context.extend_from_slice(&authority);
    push_u16_bytes(&mut context, scope.as_str().as_bytes())?;
    context.extend_from_slice(&epoch.to_be_bytes());
    append_control_link(&mut context, sequence, previous);
    context.extend_from_slice(package_set_hash);
    context.extend_from_slice(&package.recipient);
    context.extend_from_slice(&package.credential_hash);
    context.extend_from_slice(&package.grant_commitment);
    if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
        context.push(u8::from(package.route_access));
    } else if !package.route_access {
        return Err(invalid_envelope());
    }
    push_u16_bytes(&mut context, &package.p256_ephemeral_public)?;
    push_u32_bytes(&mut context, &package.ml_kem_768_ciphertext)?;
    Ok(context)
}

fn rekey_package_aad(context: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let mut aad = Vec::new();
    aad.extend_from_slice(REKEY_PACKAGE_AAD_DOMAIN);
    push_u32_bytes(&mut aad, context)?;
    Ok(aad)
}

fn derive_rekey_package_key(
    provider: &RustCryptoProvider<SysRng>,
    classical: &Secret32,
    post_quantum: &Secret32,
    package_set_hash: &[u8; 32],
    context: &[u8],
) -> Result<Secret32, EnvelopeError> {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(classical.expose());
    combined.extend_from_slice(post_quantum.expose());
    let result = provider
        .derive_secret(
            &combined,
            Some(package_set_hash),
            REKEY_PACKAGE_KEY_LABEL,
            context,
        )
        .map_err(envelope_crypto_error);
    combined.zeroize();
    result
}

#[allow(clippy::too_many_arguments)]
fn encode_rekey_grants(
    format: u16,
    mission: &[u8; 32],
    authority: NodeId,
    scope: &Scope,
    epoch: u64,
    sequence: u64,
    previous: Option<crate::store::EnvelopeId>,
    package_set_hash: &[u8; 32],
    package: &DecodedRekeyPackage,
    grant_salt: &Secret32,
    route_key: Option<&Secret32>,
    content_keys: &BTreeMap<Topic, Secret32>,
    readable_topics: &[Topic],
) -> Result<Vec<u8>, EnvelopeError> {
    if !matches!(
        format,
        SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
    ) || (format == SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT && !package.route_access)
        || package.route_access != route_key.is_some()
        || (!package.route_access && readable_topics.is_empty())
    {
        return Err(invalid_envelope());
    }
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&format.to_be_bytes());
    plaintext.extend_from_slice(mission);
    plaintext.extend_from_slice(&authority);
    push_u16_bytes(&mut plaintext, scope.as_str().as_bytes())?;
    plaintext.extend_from_slice(&epoch.to_be_bytes());
    append_control_link(&mut plaintext, sequence, previous);
    plaintext.extend_from_slice(package_set_hash);
    plaintext.extend_from_slice(&package.recipient);
    plaintext.extend_from_slice(&package.credential_hash);
    plaintext.extend_from_slice(&package.grant_commitment);
    plaintext.extend_from_slice(grant_salt.expose());
    if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
        plaintext.push(u8::from(package.route_access));
    }
    if let Some(route_key) = route_key {
        plaintext.extend_from_slice(route_key.expose());
    }
    plaintext.extend_from_slice(
        &u16::try_from(readable_topics.len())
            .map_err(|_| invalid_envelope())?
            .to_be_bytes(),
    );
    for topic in readable_topics {
        push_u16_bytes(&mut plaintext, topic.as_str().as_bytes())?;
        plaintext.extend_from_slice(
            content_keys
                .get(topic)
                .ok_or_else(invalid_envelope)?
                .expose(),
        );
    }
    if plaintext.len().saturating_add(GCM_TAG_LEN) > MAX_REKEY_PACKAGE_CIPHERTEXT_LEN {
        plaintext.zeroize();
        return Err(EnvelopeError(
            "scope rekey recipient package is too large".into(),
        ));
    }
    Ok(plaintext)
}

#[allow(clippy::too_many_arguments)]
fn decode_rekey_grants(
    plaintext: &[u8],
    expected_format: u16,
    mission: &[u8; 32],
    authority: NodeId,
    scope: &Scope,
    epoch: u64,
    sequence: u64,
    previous: Option<crate::store::EnvelopeId>,
    package_set_hash: &[u8; 32],
    package: &DecodedRekeyPackage,
) -> Result<DecodedRekeyGrants, EnvelopeError> {
    let mut reader = Reader::new(plaintext);
    let format = reader.u16()?;
    let encoded_mission = reader.array::<32>()?;
    let encoded_authority = reader.array::<32>()?;
    let encoded_scope = decode_scope(reader.u16_bytes(128)?)?;
    let encoded_epoch = reader.u64()?;
    let encoded_sequence = reader.u64()?;
    if format != expected_format
        || !matches!(
            format,
            SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT
        )
        || encoded_mission != *mission
        || encoded_authority != authority
        || &encoded_scope != scope
        || encoded_epoch != epoch
        || encoded_sequence != sequence
    {
        return Err(authentication_failed());
    }
    let encoded_previous = match reader.u8()? {
        0 => None,
        1 => Some(reader.array::<32>()?),
        _ => return Err(authentication_failed()),
    };
    if encoded_previous != previous
        || reader.array::<32>()? != *package_set_hash
        || reader.array::<32>()? != package.recipient
        || reader.array::<32>()? != package.credential_hash
        || reader.array::<32>()? != package.grant_commitment
    {
        return Err(authentication_failed());
    }
    let grant_salt = Secret32::new(reader.array::<32>()?);
    let route_access = if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
        match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(authentication_failed()),
        }
    } else {
        true
    };
    if route_access != package.route_access {
        return Err(authentication_failed());
    }
    let route_key = route_access
        .then(|| reader.array::<32>())
        .transpose()?
        .map(Secret32::new);
    let topic_count = usize::from(reader.u16()?);
    if topic_count > MAX_REKEY_TOPICS_PER_RECIPIENT {
        return Err(authentication_failed());
    }
    let mut content_keys = Vec::with_capacity(topic_count);
    for _ in 0..topic_count {
        let topic = decode_topic(reader.u16_bytes(128)?)?;
        let key = Secret32::new(reader.array::<32>()?);
        if content_keys
            .last()
            .is_some_and(|(previous, _)| previous >= &topic)
        {
            return Err(authentication_failed());
        }
        content_keys.push((topic, key));
    }
    reader.finish()?;
    let topics = content_keys
        .iter()
        .map(|(topic, _)| topic.clone())
        .collect::<Vec<_>>();
    if rekey_grant_commitment(
        format,
        scope,
        epoch,
        package.recipient,
        &package.credential_hash,
        &grant_salt,
        route_access,
        &topics,
    )? != package.grant_commitment
    {
        return Err(authentication_failed());
    }
    Ok(DecodedRekeyGrants {
        route_key,
        content_keys,
    })
}

fn derive_signing_key(seed: &[u8; 32]) -> Result<RustCryptoSigningKey, EnvelopeError> {
    let p256 = derive_p256_signing_key(seed)?;
    let mut ml_seed_bytes = derive_material::<32>(seed, b"ml-dsa-65-signing-seed", &[])?;
    let mut ml_seed = MlDsaSeed::default();
    ml_seed.as_mut_slice().copy_from_slice(&ml_seed_bytes);
    ml_seed_bytes.zeroize();
    let ml_dsa = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_seed);
    ml_seed.as_mut_slice().zeroize();
    Ok(RustCryptoSigningKey {
        p256: Some(p256),
        ml_dsa: Some(ml_dsa),
    })
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
        "failed to derive a valid provisioned identity".into(),
    ))
}

fn derive_p256_ecdh_secret(seed: &[u8; 32]) -> Result<P256SecretKey, EnvelopeError> {
    for counter in 0u16..=255 {
        let mut candidate =
            derive_material::<32>(seed, b"p256-static-ecdh-scalar", &counter.to_be_bytes())?;
        let mut field = FieldBytes::default();
        field.as_mut_slice().copy_from_slice(&candidate);
        candidate.zeroize();
        let result = P256SecretKey::from_bytes(&field);
        field.as_mut_slice().zeroize();
        if let Ok(key) = result {
            return Ok(key);
        }
    }
    Err(EnvelopeError(
        "failed to derive a valid provisioned key-agreement identity".into(),
    ))
}

fn derive_identity(
    seed: &[u8; 32],
    provider: &RustCryptoProvider<SysRng>,
) -> Result<DerivedIdentity, EnvelopeError> {
    let signing_key = derive_signing_key(seed)?;
    let verifying_key = provider
        .verifying_key(&signing_key)
        .map_err(reference_open_error)?;
    let p256_ecdh_secret = derive_p256_ecdh_secret(seed)?;
    let p256_ecdh_public = p256_ecdh_secret
        .public_key()
        .to_sec1_point(true)
        .as_ref()
        .to_vec();
    let mut kem_seed_bytes = derive_material::<64>(seed, b"ml-kem-768-seed", &[])?;
    let mut kem_seed = MlKemSeed::default();
    kem_seed.as_mut_slice().copy_from_slice(&kem_seed_bytes);
    kem_seed_bytes.zeroize();
    let kem_decapsulation_key = MlKemDecapsulationKey::from_seed(kem_seed);
    let kem_public_key = kem_decapsulation_key
        .encapsulation_key()
        .to_bytes()
        .as_slice()
        .to_vec();
    Ok((
        signing_key,
        verifying_key,
        p256_ecdh_secret,
        p256_ecdh_public,
        kem_decapsulation_key,
        kem_public_key,
    ))
}

fn derive_authority_id(mission: &[u8; 32], key: &HybridVerifyingKey) -> NodeId {
    let mut body = Vec::new();
    body.extend_from_slice(mission);
    body.extend_from_slice(&key.p256_sec1);
    body.extend_from_slice(&key.ml_dsa_65);
    hash_domain(AUTHORITY_ID_DOMAIN, &body)
}

fn encode_credential_body(
    mission: &[u8; 32],
    serial: u64,
    roles: u32,
    verifying_key: &HybridVerifyingKey,
    p256_ecdh_public_key: &[u8],
    kem_public_key: &[u8],
    route_grant_commitments: &[[u8; 32]],
) -> Result<Vec<u8>, EnvelopeError> {
    let has_route_role = roles & ROLE_RELAY != 0;
    if serial == 0
        || roles == 0
        || p256_ecdh_public_key.len() != P256_PUBLIC_LEN
        || kem_public_key.len() != ML_KEM_PUBLIC_LEN
        || has_route_role == route_grant_commitments.is_empty()
        || route_grant_commitments.len() > MAX_GRANTS
        || route_grant_commitments
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid_bundle());
    }
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&SUITE_ID.to_be_bytes());
    body.extend_from_slice(mission);
    body.extend_from_slice(&serial.to_be_bytes());
    body.extend_from_slice(&roles.to_be_bytes());
    encode_verifying_key(&mut body, verifying_key)?;
    push_u16_bytes(&mut body, p256_ecdh_public_key)?;
    push_u32_bytes(&mut body, kem_public_key)?;
    body.extend_from_slice(
        &u16::try_from(route_grant_commitments.len())
            .map_err(|_| invalid_bundle())?
            .to_be_bytes(),
    );
    for commitment in route_grant_commitments {
        body.extend_from_slice(commitment);
    }
    Ok(body)
}

fn decode_credential(
    body: Vec<u8>,
    signature: HybridSignature,
    expected_mission: &[u8; 32],
    authority_key: &HybridVerifyingKey,
    provider: &RustCryptoProvider<SysRng>,
) -> Result<Credential, EnvelopeError> {
    let digest = hash_domain(CREDENTIAL_SIGNATURE_DOMAIN, &body);
    provider
        .verify(authority_key, &digest, &signature)
        .map_err(envelope_crypto_error)?;
    let mut reader = Reader::new(&body);
    if reader.u16()? != PROTOCOL_VERSION || reader.u16()? != SUITE_ID {
        return Err(authentication_failed());
    }
    if reader.array::<32>()? != *expected_mission {
        return Err(authentication_failed());
    }
    let serial = reader.u64()?;
    let roles = reader.u32()?;
    if serial == 0
        || roles == 0
        || roles & !(ROLE_RELAY | ROLE_READER | ROLE_CONTROL_AUTHORITY) != 0
    {
        return Err(authentication_failed());
    }
    let verifying_key = decode_verifying_key(&mut reader)?;
    let p256_ecdh_public_key = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let kem_public_key = reader.u32_bytes(ML_KEM_PUBLIC_LEN)?.to_vec();
    let commitment_count = usize::from(reader.u16()?);
    if commitment_count > MAX_GRANTS || (roles & ROLE_RELAY != 0) != (commitment_count != 0) {
        return Err(authentication_failed());
    }
    let mut route_grant_commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        route_grant_commitments.push(reader.array::<32>()?);
    }
    if route_grant_commitments
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(authentication_failed());
    }
    reader.finish()?;
    if p256_ecdh_public_key.len() != P256_PUBLIC_LEN
        || p256::PublicKey::from_sec1_bytes(&p256_ecdh_public_key).is_err()
    {
        return Err(authentication_failed());
    }
    validate_kem_public_key(&kem_public_key)?;
    let identity = hash_domain(NODE_ID_DOMAIN, &body);
    Ok(Credential {
        body,
        signature,
        identity,
        verifying_key,
        p256_ecdh_public_key,
        kem_public_key,
        roles,
        route_grant_commitments,
    })
}

fn authenticate_rekey_credentials(
    credentials: &BTreeMap<NodeId, RekeyCredential>,
    expected_mission: &[u8; 32],
    authority_key: &HybridVerifyingKey,
    provider: &RustCryptoProvider<SysRng>,
) -> Result<BTreeMap<NodeId, Credential>, EnvelopeError> {
    let mut authenticated = BTreeMap::new();
    for (node, signed) in credentials {
        let credential = decode_credential(
            signed.body.clone(),
            signed.signature.clone(),
            expected_mission,
            authority_key,
            provider,
        )?;
        if credential.identity != *node
            || credential.roles & (ROLE_RELAY | ROLE_READER) == 0
            || authenticated.insert(*node, credential).is_some()
        {
            return Err(authentication_failed());
        }
    }
    Ok(authenticated)
}

fn verify_rekey_registry(
    encoded: &[u8],
    minimum_generation: u64,
    expected_mission: &[u8; 32],
    expected_authority: NodeId,
    authority_key: &HybridVerifyingKey,
    provider: &RustCryptoProvider<SysRng>,
) -> Result<VerifiedRekeyRegistry, EnvelopeError> {
    if encoded.len() > MAX_REKEY_REGISTRY_LEN {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(encoded);
    if reader.take(REKEY_REGISTRY_MAGIC.len())? != REKEY_REGISTRY_MAGIC
        || reader.u16()? != REKEY_REGISTRY_VERSION
        || reader.u16()? != PROTOCOL_VERSION
        || reader.u16()? != SUITE_ID
        || reader.array::<32>()? != *expected_mission
        || reader.array::<32>()? != expected_authority
    {
        return Err(authentication_failed());
    }
    let generation = reader.u64()?;
    let count = usize::from(reader.u16()?);
    if generation < minimum_generation
        || count == 0
        || count > MAX_REKEY_REGISTRY_ENTRIES
        || generation != u64::try_from(count).map_err(|_| authentication_failed())?
    {
        return Err(authentication_failed());
    }
    let mut credentials = BTreeMap::new();
    let mut authenticated_credentials = BTreeMap::new();
    let mut previous_node = None;
    for _ in 0..count {
        let node = reader.array::<32>()?;
        if previous_node.is_some_and(|previous| previous >= node) {
            return Err(authentication_failed());
        }
        previous_node = Some(node);
        let body = reader.u32_bytes(16 * 1024)?.to_vec();
        let signature = decode_signature(&mut reader)?;
        let credential = decode_credential(
            body.clone(),
            signature.clone(),
            expected_mission,
            authority_key,
            provider,
        )?;
        if credential.identity != node || credential.roles & (ROLE_RELAY | ROLE_READER) == 0 {
            return Err(authentication_failed());
        }
        if credentials
            .insert(node, RekeyCredential { body, signature })
            .is_some()
            || authenticated_credentials.insert(node, credential).is_some()
        {
            return Err(authentication_failed());
        }
    }
    let signed_end = reader.position();
    let signature = decode_signature(&mut reader)?;
    reader.finish()?;
    let digest = hash_domain(REKEY_REGISTRY_SIGNATURE_DOMAIN, &encoded[..signed_end]);
    provider
        .verify(authority_key, &digest, &signature)
        .map_err(envelope_crypto_error)?;
    Ok(VerifiedRekeyRegistry {
        generation,
        signed_credentials: credentials,
        authenticated_credentials,
    })
}

fn route_grant_commitments(
    mission: &[u8; 32],
    grants: &[RouteGrant],
) -> Result<Vec<[u8; 32]>, EnvelopeError> {
    let mut commitments = grants
        .iter()
        .map(|grant| route_grant_commitment(mission, grant))
        .collect::<Result<Vec<_>, _>>()?;
    commitments.sort_unstable();
    commitments.dedup();
    if commitments.len() > MAX_GRANTS {
        return Err(invalid_bundle());
    }
    Ok(commitments)
}

fn route_grant_commitment(
    mission: &[u8; 32],
    grant: &RouteGrant,
) -> Result<[u8; 32], EnvelopeError> {
    let mut material = Vec::new();
    material.extend_from_slice(mission);
    push_u16_bytes(&mut material, grant.scope.as_str().as_bytes())?;
    material.extend_from_slice(&grant.epoch.to_be_bytes());
    material.extend_from_slice(grant.key.expose());
    Ok(hash_domain(ROUTE_GRANT_COMMITMENT_DOMAIN, &material))
}

fn validate_kem_public_key(key: &[u8]) -> Result<(), EnvelopeError> {
    if key.len() != ML_KEM_PUBLIC_LEN {
        return Err(authentication_failed());
    }
    let encoded =
        MlKemKey::<MlKemEncapsulationKey>::try_from(key).map_err(|_| authentication_failed())?;
    MlKemEncapsulationKey::new(&encoded)
        .map(|_| ())
        .map_err(|_| authentication_failed())
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

fn content_group_id(scope: &Scope, topic: &Topic) -> [u8; 32] {
    let mut body = Vec::new();
    body.extend_from_slice(scope.as_str().as_bytes());
    body.push(0);
    body.extend_from_slice(topic.as_str().as_bytes());
    hash_domain(CONTENT_GROUP_DOMAIN, &body)
}

fn singleton_batch_id(
    item_id: &[u8; 32],
    header: &EnvelopeHeader,
) -> Result<[u8; 32], EnvelopeError> {
    let manifest = encode_singleton_manifest(item_id, &[0u8; 32], header)?;
    Ok(hash_domain(BATCH_ID_DOMAIN, &manifest))
}

fn encode_singleton_manifest(
    item_id: &[u8; 32],
    batch_id: &[u8; 32],
    header: &EnvelopeHeader,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut manifest = Vec::new();
    manifest.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    manifest.extend_from_slice(&SUITE_ID.to_be_bytes());
    manifest.extend_from_slice(item_id);
    manifest.extend_from_slice(batch_id);
    let mut encoded_header = Vec::new();
    encode_header(&mut encoded_header, header)?;
    push_u32_bytes(&mut manifest, &encoded_header)?;
    Ok(manifest)
}

fn encode_batch_public_header(
    object_kind: u8,
    selector: [u8; SELECTOR_LEN],
    route_ciphertext_len: usize,
    content_ciphertext_len: usize,
) -> Result<Vec<u8>, EnvelopeError> {
    let is_compact = object_kind == EnvelopeKind::Data as u8;
    let is_proof = object_kind == batch::OBJECT_KIND_BATCH_PROOF;
    if (!is_compact && !is_proof)
        || !(GCM_TAG_LEN..=MAX_ROUTE_CIPHERTEXT_LEN).contains(&route_ciphertext_len)
        || (is_compact && content_ciphertext_len < GCM_TAG_LEN)
        || (is_proof && content_ciphertext_len != 0)
        || content_ciphertext_len > MAX_CORE_LEN.saturating_add(GCM_TAG_LEN)
    {
        return Err(invalid_envelope());
    }
    let route_len = u32::try_from(route_ciphertext_len).map_err(|_| invalid_envelope())?;
    let content_len = u64::try_from(content_ciphertext_len).map_err(|_| invalid_envelope())?;
    let mut header = Vec::with_capacity(BATCH_PUBLIC_HEADER_LEN);
    header.extend_from_slice(BATCH_ENVELOPE_MAGIC);
    header.extend_from_slice(&batch::ENVELOPE_FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&batch::SEMANTIC_PROTOCOL_VERSION.to_be_bytes());
    header.extend_from_slice(&batch::CRYPTO_SUITE.to_be_bytes());
    header.push(object_kind);
    header.push(0);
    header.extend_from_slice(&selector);
    header.extend_from_slice(&route_len.to_be_bytes());
    header.extend_from_slice(&content_len.to_be_bytes());
    if header.len() != BATCH_PUBLIC_HEADER_LEN {
        return Err(invalid_envelope());
    }
    Ok(header)
}

fn parse_batch_envelope(
    sealed: &[u8],
    selected_semantic_version: u16,
) -> Result<ParsedBatchEnvelope<'_>, EnvelopeError> {
    if !matches!(
        selected_semantic_version,
        batch::SEMANTIC_PROTOCOL_VERSION
            | MIN_CUSTODY_SEMANTIC_VERSION
            | super::SEMANTIC_PROTOCOL_V4
            | super::SEMANTIC_PROTOCOL_V5
            | super::SEMANTIC_PROTOCOL_V6
            | super::SEMANTIC_PROTOCOL_V7
            | super::SEMANTIC_PROTOCOL_V8
            | super::SEMANTIC_PROTOCOL_V9
    ) {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(sealed);
    if reader.take(BATCH_ENVELOPE_MAGIC.len())? != BATCH_ENVELOPE_MAGIC
        || reader.u16()? != batch::ENVELOPE_FORMAT_VERSION
        || reader.u16()? != batch::SEMANTIC_PROTOCOL_VERSION
        || reader.u16()? != batch::CRYPTO_SUITE
    {
        return Err(authentication_failed());
    }
    let object_kind = reader.u8()?;
    if !matches!(object_kind, 1 | batch::OBJECT_KIND_BATCH_PROOF) || reader.u8()? != 0 {
        return Err(authentication_failed());
    }
    let selector = reader.array::<SELECTOR_LEN>()?;
    let route_len = usize::try_from(reader.u32()?).map_err(|_| authentication_failed())?;
    let content_len = usize::try_from(reader.u64()?).map_err(|_| authentication_failed())?;
    if reader.position() != BATCH_PUBLIC_HEADER_LEN
        || !(GCM_TAG_LEN..=MAX_ROUTE_CIPHERTEXT_LEN).contains(&route_len)
        || (object_kind == EnvelopeKind::Data as u8 && content_len < GCM_TAG_LEN)
        || (object_kind == batch::OBJECT_KIND_BATCH_PROOF && content_len != 0)
        || content_len > MAX_CORE_LEN.saturating_add(GCM_TAG_LEN)
    {
        return Err(authentication_failed());
    }
    let route_ciphertext = reader.take(route_len)?;
    let content_ciphertext = reader.take(content_len)?;
    reader.finish()?;
    Ok(ParsedBatchEnvelope {
        object_kind,
        selector,
        public_header: &sealed[..BATCH_PUBLIC_HEADER_LEN],
        route_ciphertext,
        content_ciphertext,
    })
}

fn encode_compact_batch_route(route: &DecodedCompactBatchRoute) -> Result<Vec<u8>, EnvelopeError> {
    let mut encoded = Vec::new();
    encoded.push(EnvelopeKind::Data as u8);
    encoded.extend_from_slice(&route.item_id);
    encode_header(&mut encoded, &route.header)?;
    encoded.extend_from_slice(&route.content_group);
    encoded.extend_from_slice(&route.content_nonce);
    encoded.extend_from_slice(&route.content_ciphertext_len.to_be_bytes());
    encoded.extend_from_slice(
        &route
            .authentication
            .encode()
            .map_err(batch_construction_error)?,
    );
    Ok(encoded)
}

fn decode_compact_batch_route(bytes: &[u8]) -> Result<DecodedCompactBatchRoute, EnvelopeError> {
    let mut reader = Reader::new(bytes);
    if reader.u8()? != EnvelopeKind::Data as u8 {
        return Err(authentication_failed());
    }
    let item_id = reader.array::<32>()?;
    let header = decode_header(&mut reader)?;
    let content_group = reader.array::<32>()?;
    let content_nonce = reader.array::<NONCE_LEN>()?;
    let content_ciphertext_len = reader.u64()?;
    let remaining = bytes
        .len()
        .checked_sub(reader.position())
        .ok_or_else(authentication_failed)?;
    let authentication = batch::CompactAuthentication::decode(reader.take(remaining)?)
        .map_err(batch_authentication_error)?;
    reader.finish()?;
    let route = DecodedCompactBatchRoute {
        item_id,
        header,
        content_group,
        content_nonce,
        content_ciphertext_len,
        authentication,
    };
    if encode_compact_batch_route(&route)? != bytes {
        return Err(authentication_failed());
    }
    Ok(route)
}

fn validate_compact_manifest_binding(
    route: &DecodedCompactBatchRoute,
    manifest: &batch::BatchManifest,
) -> Result<(), EnvelopeError> {
    let preamble = &manifest.preamble;
    let index = u64::from(route.authentication.item_index);
    let expected_counter = preamble
        .first_causal_counter
        .checked_add(index)
        .ok_or_else(authentication_failed)?;
    let expected_event_sequence = if route.header.class == DataClass::Event {
        Some(
            preamble
                .first_event_sequence
                .checked_add(index)
                .ok_or_else(authentication_failed)?,
        )
    } else {
        None
    };
    if route.authentication.item_index >= preamble.item_count
        || preamble.publisher != route.header.stamp.dot.publisher
        || preamble.data_class != route.header.class as u8
        || preamble.topic != route.header.topic.as_str()
        || preamble.scope != route.header.scope.as_str()
        || preamble.key_epoch != route.header.key_epoch
        || expected_counter != route.header.stamp.dot.counter
        || expected_event_sequence != route.header.event_sequence
        || route.content_group != content_group_id(&route.header.scope, &route.header.topic)
    {
        return Err(authentication_failed());
    }
    Ok(())
}

fn encode_public_header(
    kind: EnvelopeKind,
    selector: [u8; SELECTOR_LEN],
    route_ciphertext_len: usize,
    content_ciphertext_len: usize,
) -> Result<Vec<u8>, EnvelopeError> {
    let route_len = u32::try_from(route_ciphertext_len).map_err(|_| invalid_envelope())?;
    let content_len = u64::try_from(content_ciphertext_len).map_err(|_| invalid_envelope())?;
    let mut header = Vec::with_capacity(PUBLIC_HEADER_LEN);
    header.extend_from_slice(ENVELOPE_MAGIC);
    header.extend_from_slice(&ENVELOPE_FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header.extend_from_slice(&SUITE_ID.to_be_bytes());
    header.push(kind as u8);
    header.push(0);
    header.extend_from_slice(&selector);
    header.extend_from_slice(&route_len.to_be_bytes());
    header.extend_from_slice(&content_len.to_be_bytes());
    if header.len() != PUBLIC_HEADER_LEN {
        return Err(invalid_envelope());
    }
    Ok(header)
}

fn parse_envelope(sealed: &[u8]) -> Result<ParsedEnvelope<'_>, EnvelopeError> {
    let mut reader = Reader::new(sealed);
    if reader.take(ENVELOPE_MAGIC.len())? != ENVELOPE_MAGIC
        || reader.u16()? != ENVELOPE_FORMAT_VERSION
        || reader.u16()? != PROTOCOL_VERSION
        || reader.u16()? != SUITE_ID
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

fn parse_bridge_object<'a>(
    sealed: &'a [u8],
    expected_magic: &[u8; 8],
) -> Result<ParsedBridgeObject<'a>, EnvelopeError> {
    let header_bytes = sealed
        .get(..bridge::BRIDGE_PUBLIC_HEADER_BYTES)
        .ok_or_else(authentication_failed)?;
    let header = bridge::decode_public_header(header_bytes).map_err(bridge_authentication_error)?;
    let expected_kind = if expected_magic == bridge::AUTHORIZATION_MAGIC {
        BridgeOuterKind::Authorization
    } else if expected_magic == bridge::WRAPPER_MAGIC {
        BridgeOuterKind::Wrapper
    } else {
        return Err(authentication_failed());
    };
    if header.kind != expected_kind
        || header.total_length().map_err(bridge_authentication_error)? != sealed.len()
    {
        return Err(authentication_failed());
    }
    let ciphertext = &sealed[bridge::BRIDGE_PUBLIC_HEADER_BYTES..];
    if ciphertext.len() != header.protected_length {
        return Err(authentication_failed());
    }
    Ok(ParsedBridgeObject {
        selector: header.selector,
        header: header_bytes,
        ciphertext,
    })
}

fn decode_data_route(
    bytes: &[u8],
    mission: &[u8; 32],
    authority_id: NodeId,
    authority_key: &HybridVerifyingKey,
    provider: &RustCryptoProvider<SysRng>,
) -> Result<DecodedDataRoute, EnvelopeError> {
    let mut reader = Reader::new(bytes);
    if EnvelopeKind::decode(reader.u8()?)? != EnvelopeKind::Data {
        return Err(authentication_failed());
    }
    let credential_body = reader.u32_bytes(16 * 1024)?.to_vec();
    let credential_signature = decode_signature(&mut reader)?;
    let credential = decode_credential(
        credential_body,
        credential_signature,
        mission,
        authority_key,
        provider,
    )?;
    if derive_authority_id(mission, authority_key) != authority_id {
        return Err(authentication_failed());
    }
    let item_id = reader.array::<32>()?;
    let header = decode_header(&mut reader)?;
    let content_group = reader.array::<32>()?;
    let content_nonce = reader.array::<NONCE_LEN>()?;
    let batch_id = reader.array::<32>()?;
    let content_ciphertext_len = reader.u64()?;
    let item_signature = decode_signature(&mut reader)?;
    reader.finish()?;
    Ok(DecodedDataRoute {
        credential,
        item_id,
        header,
        content_group,
        content_nonce,
        batch_id,
        content_ciphertext_len,
        item_signature,
    })
}

fn decode_control(
    bytes: &[u8],
    expected_kind: EnvelopeKind,
    mission: &[u8; 32],
    authority_id: NodeId,
    authority_key: &HybridVerifyingKey,
    provider: &RustCryptoProvider<SysRng>,
) -> Result<DecodedControl, EnvelopeError> {
    let mut reader = Reader::new(bytes);
    if EnvelopeKind::decode(reader.u8()?)? != expected_kind
        || reader.take(CONTROL_AUTHENTICATION_MAGIC.len())? != CONTROL_AUTHENTICATION_MAGIC
        || reader.u16()? != CONTROL_AUTHENTICATION_FORMAT
        || reader.array::<32>()? != *mission
        || reader.array::<32>()? != authority_id
    {
        return Err(authentication_failed());
    }
    let credential_body = reader.u32_bytes(16 * 1024)?.to_vec();
    let credential_signature = decode_signature(&mut reader)?;
    let credential = decode_credential(
        credential_body,
        credential_signature,
        mission,
        authority_key,
        provider,
    )?;
    if credential.roles & ROLE_CONTROL_AUTHORITY == 0
        || derive_authority_id(mission, authority_key) != authority_id
    {
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
    let body = match expected_kind {
        EnvelopeKind::Revocation => {
            let subject = reader.array::<32>()?;
            let generation = reader.u64()?;
            if generation == 0 {
                return Err(invalid_envelope());
            }
            DecodedControl::Revocation {
                signer: credential.identity,
                sequence,
                previous,
                subject,
                generation,
            }
        }
        EnvelopeKind::ScopeEpoch => {
            let scope = decode_scope(reader.u16_bytes(128)?)?;
            let epoch = reader.u64()?;
            let format = reader.u16()?;
            let keying = match format {
                SCOPE_EPOCH_LEGACY_FORMAT => ScopeEpochKeying::LegacyPreprovisioned,
                SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT | SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT => {
                    if epoch == 0 {
                        return Err(invalid_envelope());
                    }
                    let package_set_hash = reader.array::<32>()?;
                    let package_count = usize::from(reader.u16()?);
                    if package_count == 0 || package_count > MAX_REKEY_RECIPIENTS {
                        return Err(invalid_envelope());
                    }
                    let mut packages = Vec::with_capacity(package_count);
                    for _ in 0..package_count {
                        let package = decode_rekey_package(&mut reader, format)?;
                        if packages
                            .last()
                            .is_some_and(|previous: &DecodedRekeyPackage| {
                                previous.recipient >= package.recipient
                            })
                        {
                            return Err(invalid_envelope());
                        }
                        packages.push(package);
                    }
                    let descriptors = packages
                        .iter()
                        .map(|package| {
                            (
                                package.recipient,
                                package.credential_hash,
                                package.grant_commitment,
                                package.route_access,
                            )
                        })
                        .collect::<Vec<_>>();
                    if rekey_package_set_hash(format, &descriptors)? != package_set_hash {
                        return Err(authentication_failed());
                    }
                    ScopeEpochKeying::RecipientPackages {
                        format,
                        package_set_hash,
                        packages,
                    }
                }
                _ => return Err(invalid_envelope()),
            };
            DecodedControl::ScopeEpoch {
                signer: credential.identity,
                sequence,
                previous,
                scope,
                epoch,
                keying,
            }
        }
        EnvelopeKind::Data => return Err(invalid_envelope()),
    };
    let signed_end = reader.position();
    let signature = decode_signature(&mut reader)?;
    reader.finish()?;
    let digest = hash_domain(CONTROL_SIGNATURE_DOMAIN, &bytes[..signed_end]);
    provider
        .verify(&credential.verifying_key, &digest, &signature)
        .map_err(envelope_crypto_error)?;
    Ok(body)
}

fn decode_rekey_package(
    reader: &mut Reader<'_>,
    format: u16,
) -> Result<DecodedRekeyPackage, EnvelopeError> {
    let recipient = reader.array::<32>()?;
    let credential_hash = reader.array::<32>()?;
    let grant_commitment = reader.array::<32>()?;
    let route_access = if format == SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT {
        match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(invalid_envelope()),
        }
    } else if format == SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT {
        true
    } else {
        return Err(invalid_envelope());
    };
    let p256_ephemeral_public = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let ml_kem_768_ciphertext = reader.u32_bytes(ML_KEM_CIPHERTEXT_LEN)?.to_vec();
    let sealed_grants = decode_aead(reader, MAX_REKEY_PACKAGE_CIPHERTEXT_LEN)?;
    if p256_ephemeral_public.len() != P256_PUBLIC_LEN
        || p256::PublicKey::from_sec1_bytes(&p256_ephemeral_public).is_err()
        || ml_kem_768_ciphertext.len() != ML_KEM_CIPHERTEXT_LEN
        || sealed_grants.ciphertext.len() <= GCM_TAG_LEN
    {
        return Err(invalid_envelope());
    }
    Ok(DecodedRekeyPackage {
        recipient,
        credential_hash,
        grant_commitment,
        route_access,
        p256_ephemeral_public,
        ml_kem_768_ciphertext,
        sealed_grants,
    })
}

fn encode_content_aad(epoch: u64, item_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(item_id);
    aad
}

fn selector_nonce(selector: &[u8; SELECTOR_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&selector[..NONCE_LEN]);
    nonce
}

fn encode_verifying_key(
    output: &mut Vec<u8>,
    key: &HybridVerifyingKey,
) -> Result<(), EnvelopeError> {
    if key.p256_sec1.len() != P256_PUBLIC_LEN || key.ml_dsa_65.len() != ML_DSA_PUBLIC_LEN {
        return Err(invalid_bundle());
    }
    push_u16_bytes(output, &key.p256_sec1)?;
    push_u32_bytes(output, &key.ml_dsa_65)?;
    Ok(())
}

fn decode_verifying_key(reader: &mut Reader<'_>) -> Result<HybridVerifyingKey, EnvelopeError> {
    let p256 = reader.u16_bytes(P256_PUBLIC_LEN)?.to_vec();
    let ml_dsa = reader.u32_bytes(ML_DSA_PUBLIC_LEN)?.to_vec();
    if p256.len() != P256_PUBLIC_LEN || ml_dsa.len() != ML_DSA_PUBLIC_LEN {
        return Err(invalid_envelope());
    }
    Ok(HybridVerifyingKey {
        p256_sec1: p256,
        ml_dsa_65: ml_dsa,
    })
}

fn encode_signature(
    output: &mut Vec<u8>,
    signature: &HybridSignature,
) -> Result<(), EnvelopeError> {
    let classical = signature
        .ecdsa_p256
        .as_deref()
        .ok_or_else(authentication_failed)?;
    let post_quantum = signature
        .ml_dsa_65
        .as_deref()
        .ok_or_else(authentication_failed)?;
    if classical.len() != P256_SIGNATURE_LEN || post_quantum.len() != ML_DSA_SIGNATURE_LEN {
        return Err(authentication_failed());
    }
    push_u16_bytes(output, classical)?;
    push_u32_bytes(output, post_quantum)?;
    Ok(())
}

fn encode_exact_hybrid_signature(signature: &HybridSignature) -> Result<Vec<u8>, EnvelopeError> {
    let mut encoded = Vec::with_capacity(bridge::HYBRID_SIGNATURE_BYTES);
    encode_signature(&mut encoded, signature)?;
    if encoded.len() != bridge::HYBRID_SIGNATURE_BYTES {
        encoded.zeroize();
        return Err(authentication_failed());
    }
    Ok(encoded)
}

fn decode_signature(reader: &mut Reader<'_>) -> Result<HybridSignature, EnvelopeError> {
    let classical = reader.u16_bytes(P256_SIGNATURE_LEN)?.to_vec();
    let post_quantum = reader.u32_bytes(ML_DSA_SIGNATURE_LEN)?.to_vec();
    if classical.len() != P256_SIGNATURE_LEN || post_quantum.len() != ML_DSA_SIGNATURE_LEN {
        return Err(invalid_envelope());
    }
    Ok(HybridSignature {
        ecdsa_p256: Some(classical),
        ml_dsa_65: Some(post_quantum),
    })
}

fn decode_exact_hybrid_signature(bytes: &[u8]) -> Result<HybridSignature, EnvelopeError> {
    if bytes.len() != bridge::HYBRID_SIGNATURE_BYTES {
        return Err(authentication_failed());
    }
    let mut reader = Reader::new(bytes);
    let signature = decode_signature(&mut reader)?;
    reader.finish()?;
    Ok(signature)
}

#[allow(clippy::too_many_arguments)]
fn encode_bridge_edge_enrollment_body(
    mission_id: &[u8; 32],
    authority_id: &NodeId,
    bridge_node_id: &NodeId,
    source_scope: &Scope,
    source_route_epoch: u64,
    source_route_commitment: &[u8; 32],
    target_scope: &Scope,
    target_route_epoch: u64,
    target_route_commitment: &[u8; 32],
    bridge_credential: &[u8],
    authority_credential_signature: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if source_scope == target_scope
        || source_route_epoch == 0
        || target_route_epoch == 0
        || source_scope.as_str().len() > MAX_BRIDGE_EDGE_ENROLLMENT_SCOPE_BYTES
        || target_scope.as_str().len() > MAX_BRIDGE_EDGE_ENROLLMENT_SCOPE_BYTES
        || bridge_credential.is_empty()
        || bridge_credential.len() > MAX_BRIDGE_EDGE_ENROLLMENT_CREDENTIAL_BYTES
        || authority_credential_signature.len() != bridge::HYBRID_SIGNATURE_BYTES
    {
        return Err(authentication_failed());
    }
    let mut output = Vec::new();
    output.extend_from_slice(BRIDGE_EDGE_ENROLLMENT_MAGIC);
    output.extend_from_slice(&BRIDGE_EDGE_ENROLLMENT_VERSION.to_be_bytes());
    output.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    output.extend_from_slice(&SUITE_ID.to_be_bytes());
    output.extend_from_slice(mission_id);
    output.extend_from_slice(authority_id);
    output.extend_from_slice(bridge_node_id);
    push_u16_bytes(&mut output, source_scope.as_str().as_bytes())?;
    output.extend_from_slice(&source_route_epoch.to_be_bytes());
    output.extend_from_slice(source_route_commitment);
    push_u16_bytes(&mut output, target_scope.as_str().as_bytes())?;
    output.extend_from_slice(&target_route_epoch.to_be_bytes());
    output.extend_from_slice(target_route_commitment);
    push_u32_bytes(&mut output, bridge_credential)?;
    output.extend_from_slice(authority_credential_signature);
    if output.len().saturating_add(bridge::HYBRID_SIGNATURE_BYTES)
        > MAX_BRIDGE_EDGE_ENROLLMENT_BYTES
    {
        output.zeroize();
        return Err(authentication_failed());
    }
    Ok(output)
}

fn push_u16_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    let len = u16::try_from(value.len()).map_err(|_| invalid_envelope())?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_u32_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    let len = u32::try_from(value.len()).map_err(|_| invalid_envelope())?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_u64_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    let len = u64::try_from(value.len()).map_err(|_| invalid_envelope())?;
    output.extend_from_slice(&len.to_be_bytes());
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

fn encode_header(output: &mut Vec<u8>, header: &EnvelopeHeader) -> Result<(), EnvelopeError> {
    output.push(header.class as u8);
    output.push(header.priority as u8);
    push_u16_bytes(output, header.topic.as_str().as_bytes())?;
    push_u16_bytes(output, header.scope.as_str().as_bytes())?;
    output.extend_from_slice(&header.stamp.dot.publisher);
    output.extend_from_slice(&header.stamp.dot.counter.to_be_bytes());
    let context_len =
        u32::try_from(header.stamp.context.iter().len()).map_err(|_| invalid_envelope())?;
    output.extend_from_slice(&context_len.to_be_bytes());
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
    let blob_route_valid = match (header.class, header.blob_route) {
        (DataClass::Blob, Some(route)) => {
            header.logical_key.as_slice() == route.blob_id().as_bytes()
        }
        (DataClass::Blob, None) => false,
        (_, None) => true,
        (_, Some(_)) => false,
    };
    if &header.stamp.dot.publisher != identity
        || header.stamp.dot.counter == 0
        || header.content_len != payload.len() as u64
        || header.logical_key.len() > MAX_LOGICAL_KEY_LEN
        || (header.tombstone && !payload.is_empty())
        || (header.tombstone && header.class == DataClass::Blob)
        || (header.class == DataClass::Event) != header.event_sequence.is_some()
        || header.event_sequence == Some(0)
        || header.stamp.context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
        || header
            .stamp
            .context
            .iter()
            .any(|(_, counter)| *counter == 0)
        || header.stamp.context.counter(identity) >= header.stamp.dot.counter
        || !blob_route_valid
    {
        return Err(EnvelopeError("invalid authenticated item metadata".into()));
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
    let blob_route_valid = match (class, blob_route) {
        (DataClass::Blob, Some(route)) => logical_key.as_slice() == route.blob_id().as_bytes(),
        (DataClass::Blob, None) => false,
        (_, None) => true,
        (_, Some(_)) => false,
    };
    if (class == DataClass::Event) != event_sequence.is_some()
        || event_sequence == Some(0)
        || (tombstone && class == DataClass::Blob)
        || (tombstone && content_len != 0)
        || context.counter(&publisher) >= counter
        || !blob_route_valid
    {
        return Err(invalid_envelope());
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

#[cfg(all(test, feature = "sqlite-store"))]
mod tests {
    use super::*;
    use crate::engine::EnvelopeSealer;
    use crate::store::{RecordStore, StoreConfig};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_PROTECTION_PREFIX: &[u8] = b"test-protected-provisioning:";

    #[derive(Default)]
    struct TestProvisioningProtection {
        protect_calls: usize,
        unprotect_calls: usize,
        failure: Option<ProvisioningProtectionError>,
    }

    impl ProvisioningProtector for TestProvisioningProtection {
        fn protect(
            &mut self,
            plaintext: &UnprotectedProvisioning,
        ) -> Result<Vec<u8>, ProvisioningProtectionError> {
            self.protect_calls += 1;
            if let Some(error) = self.failure {
                return Err(error);
            }
            let mut protected =
                Vec::with_capacity(TEST_PROTECTION_PREFIX.len().saturating_add(plaintext.len()));
            protected.extend_from_slice(TEST_PROTECTION_PREFIX);
            protected.extend_from_slice(plaintext.expose());
            Ok(protected)
        }
    }

    impl ProvisioningUnprotector for TestProvisioningProtection {
        fn unprotect(
            &mut self,
            protected: &[u8],
            max_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.unprotect_calls += 1;
            if let Some(error) = self.failure {
                return Err(error);
            }
            let plaintext = protected
                .strip_prefix(TEST_PROTECTION_PREFIX)
                .ok_or(ProvisioningProtectionError::Rejected)?;
            if plaintext.len() > max_plaintext_len {
                return Err(ProvisioningProtectionError::TooLarge);
            }
            UnprotectedProvisioning::new(plaintext.to_vec())
        }
    }

    fn scope(value: &str) -> Scope {
        Scope::new(value).unwrap_or_else(|error| panic!("test scope failed: {error}"))
    }

    fn topic(value: &str) -> Topic {
        Topic::new(value).unwrap_or_else(|error| panic!("test topic failed: {error}"))
    }

    fn member_access(epochs: Vec<u64>) -> ProvisioningAccess {
        ProvisioningAccess::member(scope("alpha"), epochs, vec![topic("ops")])
            .unwrap_or_else(|error| panic!("test access failed: {error}"))
    }

    fn relay_access(epochs: Vec<u64>) -> ProvisioningAccess {
        ProvisioningAccess::relay(scope("alpha"), epochs)
            .unwrap_or_else(|error| panic!("test access failed: {error}"))
    }

    fn bundle_identity(bundle: &ProvisioningBundle) -> NodeId {
        session_privacy_canaries(bundle)
            .unwrap_or_else(|error| panic!("bundle identity failed: {error}"))
            .identity
    }

    fn complete_sessions_with_versions(
        initiator_bundle: ProvisioningBundle,
        responder_bundle: ProvisioningBundle,
        versions: Vec<u16>,
    ) -> (ReferenceAuthenticatedSession, ReferenceAuthenticatedSession) {
        let (initiator, flight_one) =
            ReferenceSessionInitiator::start_with_semantic_versions(initiator_bundle, versions)
                .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let responder = ReferenceSessionResponder::open(responder_bundle)
            .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (responder_pending, flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let (initiator_pending, flight_three) = initiator
            .receive_server(&flight_two)
            .unwrap_or_else(|error| panic!("server flight failed: {error}"));
        let (responder_session, flight_four) = responder_pending
            .receive_client_auth(&flight_three)
            .unwrap_or_else(|error| panic!("client auth failed: {error}"));
        let initiator_session = initiator_pending
            .receive_finished(&flight_four)
            .unwrap_or_else(|error| panic!("server finished failed: {error}"));
        (initiator_session, responder_session)
    }

    fn memory_reference_node(bundle: ProvisioningBundle) -> ReferenceNode {
        let sealer = ReferenceEnvelopeSealer::open(bundle)
            .unwrap_or_else(|error| panic!("reference sealer open failed: {error}"));
        let identity = sealer.identity();
        let store = SqliteStore::open_in_memory(StoreConfig::default())
            .unwrap_or_else(|error| panic!("memory store open failed: {error}"));
        Node::with_store(identity, store, sealer, NodeConfig::default())
    }

    fn unique_store_path(label: &str) -> std::path::PathBuf {
        let unique = format!(
            "aster-{label}-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|error| panic!("system time failed: {error}"))
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    fn remove_store_files(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack.len() >= needle.len()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn open_test_control_plaintext(
        service: &ReferenceEnvelopeSealer,
        sealed: &[u8],
    ) -> (EnvelopeKind, [u8; SELECTOR_LEN], Vec<u8>) {
        let parsed = parse_envelope(sealed)
            .unwrap_or_else(|error| panic!("control test parse failed: {error}"));
        let root = service
            .control_route_key
            .as_ref()
            .unwrap_or_else(|| panic!("control test route key missing"));
        let key = derive_item_secret(root.expose(), ROUTE_KEY_LABEL, &parsed.selector)
            .unwrap_or_else(|error| panic!("control test key failed: {error}"));
        let plaintext = service
            .provider
            .open_parts(
                &key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            )
            .unwrap_or_else(|error| panic!("control test open failed: {error}"));
        (parsed.kind, parsed.selector, plaintext)
    }

    fn seal_test_control_plaintext(
        service: &ReferenceEnvelopeSealer,
        kind: EnvelopeKind,
        selector: [u8; SELECTOR_LEN],
        mut plaintext: Vec<u8>,
    ) -> Vec<u8> {
        let root = service
            .control_route_key
            .as_ref()
            .unwrap_or_else(|| panic!("control test route key missing"));
        let key = derive_item_secret(root.expose(), ROUTE_KEY_LABEL, &selector)
            .unwrap_or_else(|error| panic!("control test key failed: {error}"));
        let header = encode_public_header(
            kind,
            selector,
            plaintext.len().saturating_add(GCM_TAG_LEN),
            0,
        )
        .unwrap_or_else(|error| panic!("control test header failed: {error}"));
        let ciphertext = service
            .provider
            .seal_with_nonce(&key, selector_nonce(&selector), &plaintext, &header)
            .unwrap_or_else(|error| panic!("control test seal failed: {error}"));
        plaintext.zeroize();
        [header, ciphertext].concat()
    }

    fn registry_node_offsets(encoded: &[u8]) -> Vec<usize> {
        let mut reader = Reader::new(encoded);
        reader
            .take(REKEY_REGISTRY_MAGIC.len())
            .unwrap_or_else(|error| panic!("registry magic failed: {error}"));
        for _ in 0..3 {
            reader
                .u16()
                .unwrap_or_else(|error| panic!("registry version failed: {error}"));
        }
        reader
            .array::<32>()
            .unwrap_or_else(|error| panic!("registry mission failed: {error}"));
        reader
            .array::<32>()
            .unwrap_or_else(|error| panic!("registry authority failed: {error}"));
        reader
            .u64()
            .unwrap_or_else(|error| panic!("registry generation failed: {error}"));
        let count = usize::from(
            reader
                .u16()
                .unwrap_or_else(|error| panic!("registry count failed: {error}")),
        );
        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            offsets.push(reader.position());
            reader
                .array::<32>()
                .unwrap_or_else(|error| panic!("registry node failed: {error}"));
            reader
                .u32_bytes(16 * 1024)
                .unwrap_or_else(|error| panic!("registry credential failed: {error}"));
            decode_signature(&mut reader)
                .unwrap_or_else(|error| panic!("registry credential signature failed: {error}"));
        }
        offsets
    }

    fn assert_private_canaries_absent(flight: &[u8], canaries: &SessionPrivacyCanaries) {
        assert!(!contains_bytes(flight, &canaries.mission));
        assert!(!contains_bytes(flight, &canaries.credential));
        assert!(!contains_bytes(flight, &canaries.credential_body));
        assert!(!contains_bytes(flight, &canaries.identity));
        for commitment in &canaries.route_grant_commitments {
            assert!(!contains_bytes(flight, commitment));
        }
    }

    fn header(identity: NodeId, epoch: u64) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::State,
            topic: topic("ops"),
            scope: scope("alpha"),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: identity,
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: None,
            logical_key: b"unit-7".to_vec(),
            blob_route: None,
            ttl_ms: Some(30_000),
            content_len: 7,
            tombstone: false,
            key_epoch: epoch,
        }
    }

    fn service(bundle: ProvisioningBundle) -> ReferenceEnvelopeSealer {
        ReferenceEnvelopeSealer::open(bundle)
            .unwrap_or_else(|error| panic!("test service open failed: {error}"))
    }

    struct BridgeProviderServices {
        authority: ReferenceEnvelopeSealer,
        second_authority: ReferenceEnvelopeSealer,
        bridge_node: ReferenceEnvelopeSealer,
        publisher: ReferenceEnvelopeSealer,
        target: ReferenceEnvelopeSealer,
        target_without_origin_content: ReferenceEnvelopeSealer,
        authority_bundle: Vec<u8>,
        bridge_bundle: Vec<u8>,
        target_bundle: Vec<u8>,
    }

    fn bridge_relay_access(value: &str, epoch: u64) -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(value), vec![epoch])
            .unwrap_or_else(|error| panic!("bridge relay access failed: {error}"))
    }

    fn bridge_provider_services(seed: u8) -> BridgeProviderServices {
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32])
            .unwrap_or_else(|error| panic!("bridge provisioner failed: {error}"));
        let bridge_accesses = [
            bridge_relay_access("alpha", 7),
            bridge_relay_access("bravo", 9),
        ];
        let authority_bundle = provisioner
            .issue_control_authority(1, &bridge_accesses)
            .unwrap_or_else(|error| panic!("bridge authority issue failed: {error}"));
        let bridge_bundle = provisioner
            .issue_node(2, &bridge_accesses)
            .unwrap_or_else(|error| panic!("bridge node issue failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(
                3,
                &[
                    ProvisioningAccess::member(scope("alpha"), vec![7], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("bridge publisher access failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("bridge publisher issue failed: {error}"));
        let target_bundle = provisioner
            .issue_node(
                4,
                &[
                    ProvisioningAccess::member(scope("bravo"), vec![9], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("bridge target access failed: {error}")),
                    ProvisioningAccess::content_only(scope("alpha"), vec![7], vec![topic("ops")])
                        .unwrap_or_else(|error| {
                            panic!("bridge target content-only access failed: {error}")
                        }),
                ],
            )
            .unwrap_or_else(|error| panic!("bridge target issue failed: {error}"));
        let target_without_origin_content_bundle = provisioner
            .issue_node(
                5,
                &[
                    ProvisioningAccess::member(scope("bravo"), vec![9], vec![topic("ops")])
                        .unwrap_or_else(|error| {
                            panic!("bridge limited target access failed: {error}")
                        }),
                ],
            )
            .unwrap_or_else(|error| panic!("bridge limited target issue failed: {error}"));
        let second_authority_bundle = provisioner
            .issue_control_authority(6, &bridge_accesses)
            .unwrap_or_else(|error| panic!("second bridge authority issue failed: {error}"));
        let authority_bytes = authority_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("bridge authority persist failed: {error}"));
        let bridge_bytes = bridge_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("bridge node persist failed: {error}"));
        let target_bytes = target_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("bridge target persist failed: {error}"));
        BridgeProviderServices {
            authority: service(authority_bundle),
            second_authority: service(second_authority_bundle),
            bridge_node: service(bridge_bundle),
            publisher: service(publisher_bundle),
            target: service(target_bundle),
            target_without_origin_content: service(target_without_origin_content_bundle),
            authority_bundle: authority_bytes,
            bridge_bundle: bridge_bytes,
            target_bundle: target_bytes,
        }
    }

    struct BatchProviderServices {
        publisher: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        relay: ReferenceEnvelopeSealer,
        wrong_content: ReferenceEnvelopeSealer,
        content_only: ReferenceEnvelopeSealer,
        publisher_bundle: Vec<u8>,
        reader_bundle: Vec<u8>,
        relay_bundle: Vec<u8>,
    }

    fn batch_provider_services(seed: u8) -> BatchProviderServices {
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32])
            .unwrap_or_else(|error| panic!("batch provisioner failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(1, &[member_access(vec![7])])
            .unwrap_or_else(|error| panic!("batch publisher issue failed: {error}"));
        let reader_bundle = provisioner
            .issue_node(2, &[member_access(vec![7])])
            .unwrap_or_else(|error| panic!("batch reader issue failed: {error}"));
        let relay_bundle = provisioner
            .issue_node(3, &[relay_access(vec![7])])
            .unwrap_or_else(|error| panic!("batch relay issue failed: {error}"));
        let wrong_content_bundle = provisioner
            .issue_node(
                4,
                &[
                    ProvisioningAccess::member(scope("alpha"), vec![7], vec![topic("intel")])
                        .unwrap_or_else(|error| {
                            panic!("batch wrong-content access failed: {error}")
                        }),
                ],
            )
            .unwrap_or_else(|error| panic!("batch wrong-content issue failed: {error}"));
        let content_only_bundle = provisioner
            .issue_node(
                5,
                &[
                    ProvisioningAccess::content_only(scope("alpha"), vec![7], vec![topic("ops")])
                        .unwrap_or_else(|error| {
                            panic!("batch content-only access failed: {error}")
                        }),
                ],
            )
            .unwrap_or_else(|error| panic!("batch content-only issue failed: {error}"));
        let publisher_bytes = publisher_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("batch publisher persist failed: {error}"));
        let reader_bytes = reader_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("batch reader persist failed: {error}"));
        let relay_bytes = relay_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("batch relay persist failed: {error}"));
        BatchProviderServices {
            publisher: service(publisher_bundle),
            reader: service(reader_bundle),
            relay: service(relay_bundle),
            wrong_content: service(wrong_content_bundle),
            content_only: service(content_only_bundle),
            publisher_bundle: publisher_bytes,
            reader_bundle: reader_bytes,
            relay_bundle: relay_bytes,
        }
    }

    fn seal_batch_fixture(
        publisher: &mut ReferenceEnvelopeSealer,
        first_counter: u64,
        payloads: &[&[u8]],
    ) -> SealedSourceBatch {
        let headers = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                let mut metadata = header(publisher.identity(), 7);
                metadata.stamp.dot.counter = first_counter
                    .checked_add(
                        u64::try_from(index)
                            .unwrap_or_else(|error| panic!("batch index failed: {error}")),
                    )
                    .unwrap_or_else(|| panic!("batch fixture counter overflow"));
                metadata.logical_key = format!("batch-{first_counter}-{index}").into_bytes();
                metadata.content_len = payload.len() as u64;
                metadata
            })
            .collect::<Vec<_>>();
        let requests = headers
            .iter()
            .zip(payloads)
            .map(|(header, payload)| SealRequest { header, payload })
            .collect::<Vec<_>>();
        publisher
            .seal_source_batch(&requests)
            .unwrap_or_else(|error| panic!("batch fixture seal failed: {error}"))
    }

    fn try_seal_batch_headers(
        publisher: &mut ReferenceEnvelopeSealer,
        headers: &[EnvelopeHeader],
        payloads: &[&[u8]],
    ) -> Result<SealedSourceBatch, EnvelopeError> {
        assert_eq!(headers.len(), payloads.len());
        let requests = headers
            .iter()
            .zip(payloads)
            .map(|(header, payload)| SealRequest { header, payload })
            .collect::<Vec<_>>();
        publisher.seal_source_batch(&requests)
    }

    fn batch_overhead_service(
        seed: u8,
        credential_groups: u16,
    ) -> (ReferenceEnvelopeSealer, Scope, Topic) {
        let target_scope = scope(&"s".repeat(batch::MAX_SCOPE_BYTES));
        let target_topic = topic(&"t".repeat(batch::MAX_TOPIC_BYTES));
        let accesses = match credential_groups {
            batch::MIN_CREDENTIAL_GROUPS => vec![
                ProvisioningAccess::member(
                    target_scope.clone(),
                    vec![7],
                    vec![target_topic.clone()],
                )
                .unwrap_or_else(|error| panic!("minimum batch access failed: {error}")),
            ],
            batch::MAX_CREDENTIAL_GROUPS => {
                let epochs = (1..=32).collect::<Vec<_>>();
                (0..8)
                    .map(|index| {
                        let granted_scope = if index == 0 {
                            target_scope.clone()
                        } else {
                            let prefix = format!("g{index}-");
                            scope(&format!(
                                "{prefix}{}",
                                "s".repeat(batch::MAX_SCOPE_BYTES - prefix.len())
                            ))
                        };
                        ProvisioningAccess::member(
                            granted_scope,
                            epochs.clone(),
                            vec![target_topic.clone()],
                        )
                        .unwrap_or_else(|error| panic!("maximum batch access failed: {error}"))
                    })
                    .collect()
            }
            value => panic!("unsupported credential group fixture {value}"),
        };
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32])
            .unwrap_or_else(|error| panic!("overhead provisioner failed: {error}"));
        let bundle = provisioner
            .issue_node(1, &accesses)
            .unwrap_or_else(|error| panic!("overhead publisher issue failed: {error}"));
        (service(bundle), target_scope, target_topic)
    }

    fn open_test_batch_route(service: &ReferenceEnvelopeSealer, sealed: &[u8]) -> Vec<u8> {
        let parsed = parse_batch_envelope(sealed, batch::SEMANTIC_PROTOCOL_VERSION)
            .unwrap_or_else(|error| panic!("batch test parse failed: {error}"));
        service
            .open_batch_route_for_any_local_grant(&parsed)
            .map(|(_, plaintext)| plaintext)
            .unwrap_or_else(|error| panic!("batch test route open failed: {error}"))
    }

    fn reseal_test_batch_route(
        service: &mut ReferenceEnvelopeSealer,
        original: &[u8],
        mut route_plaintext: Vec<u8>,
    ) -> Vec<u8> {
        let parsed = parse_batch_envelope(original, batch::SEMANTIC_PROTOCOL_VERSION)
            .unwrap_or_else(|error| panic!("batch test original parse failed: {error}"));
        let content_ciphertext = parsed.content_ciphertext.to_vec();
        let result = service.seal_batch_envelope(
            parsed.object_kind,
            &scope("alpha"),
            7,
            &route_plaintext,
            &content_ciphertext,
        );
        route_plaintext.zeroize();
        result.unwrap_or_else(|error| panic!("batch test reseal failed: {error}"))
    }

    fn bridge_authorization_fixture(
        authority: &ReferenceEnvelopeSealer,
        bridge_node: &ReferenceEnvelopeSealer,
    ) -> BridgeAuthorization {
        let source_scope = scope("alpha");
        let target_scope = scope("bravo");
        let source_grant = bridge_node
            .route_grant(&source_scope, 7)
            .unwrap_or_else(|| panic!("source route grant missing"));
        let target_grant = bridge_node
            .route_grant(&target_scope, 9)
            .unwrap_or_else(|| panic!("target route grant missing"));
        let mut authorization = BridgeAuthorization {
            mission_id: authority.mission,
            authority_id: authority.authority_id,
            control_sequence: 1,
            previous_control_id: None,
            authorization_key: bridge::bridge_authorization_key(
                &authority.mission,
                &bridge_node.identity(),
                &source_scope,
                &target_scope,
            )
            .unwrap_or_else(|error| panic!("authorization key failed: {error}")),
            generation: 1,
            bridge_node_id: bridge_node.identity(),
            source_scope,
            target_scope,
            enabled: Some(crate::bridge::EnabledAuthorization {
                source_route_epoch: 7,
                target_route_epoch: 9,
                source_route_commitment: route_grant_commitment(&bridge_node.mission, source_grant)
                    .unwrap_or_else(|error| panic!("source commitment failed: {error}")),
                target_route_commitment: route_grant_commitment(&bridge_node.mission, target_grant)
                    .unwrap_or_else(|error| panic!("target commitment failed: {error}")),
                allowed_priority_mask: 0b1111,
                max_total_hops: 8,
                topics: vec![topic("ops")],
                bridge_credential: Vec::new(),
                authority_credential_signature: Vec::new(),
            }),
            authority_control_signature: Vec::new(),
        };
        bridge_node
            .bind_own_bridge_credential(&mut authorization)
            .unwrap_or_else(|error| panic!("bridge credential binding failed: {error}"));
        authorization
    }

    fn bridge_source_fixture(
        publisher: &mut ReferenceEnvelopeSealer,
        bridge_node: &ReferenceEnvelopeSealer,
    ) -> (SealedEnvelope, VerifiedBridgeSourceRoute) {
        let source_header = header(publisher.identity(), 7);
        let source = publisher
            .seal(SealRequest {
                header: &source_header,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("bridge source seal failed: {error}"));
        let verified = bridge_node
            .open_source_route_for_bridge(&source.bytes)
            .unwrap_or_else(|error| panic!("bridge source route open failed: {error}"));
        (source, verified)
    }

    fn one_hop_bridge_route(
        bridge_node: &ReferenceEnvelopeSealer,
        authorization: &VerifiedBridgeAuthorization,
        source: &VerifiedBridgeSourceRoute,
    ) -> BridgeRoute {
        let source_header = source.header();
        let mut route = BridgeRoute {
            mission_id: source.mission_id(),
            origin_envelope_id: source.origin_envelope_id(),
            source_item_id: source.source_item_id(),
            origin_scope: source_header.scope.clone(),
            origin_route_epoch: source_header.key_epoch,
            current_scope: scope("bravo"),
            current_route_epoch: 9,
            source_route_descriptor: source.copy_exact_route_descriptor(),
            hops: vec![crate::bridge::BridgeHop {
                authorization_envelope_id: authorization.envelope().envelope_id,
                bridge_node_id: bridge_node.identity(),
                from_scope: scope("alpha"),
                from_route_epoch: 7,
                to_scope: scope("bravo"),
                to_route_epoch: 9,
                cumulative_custody_age_ms: 25,
                age_continuity_unknown: false,
                previous_hop_digest: [0u8; 32],
                bridge_hybrid_signature: Vec::new(),
            }],
            bridge_route_id: [0u8; 32],
        };
        bridge_node
            .sign_bridge_hop(&mut route, 0)
            .unwrap_or_else(|error| panic!("bridge hop signing failed: {error}"));
        route
    }

    fn seal_test_bridge_object(
        service: &mut ReferenceEnvelopeSealer,
        magic: &[u8; 8],
        label: &[u8],
        mut root: [u8; 32],
        mut plaintext: Vec<u8>,
    ) -> Vec<u8> {
        let mut selector = [0u8; SELECTOR_LEN];
        service
            .provider
            .fill_random(&mut selector)
            .unwrap_or_else(|error| panic!("bridge test selector failed: {error}"));
        let key = derive_item_secret(&root, label, &selector)
            .unwrap_or_else(|error| panic!("bridge test key failed: {error}"));
        root.zeroize();
        let header = bridge::encode_public_header(
            magic,
            selector,
            plaintext.len().saturating_add(GCM_TAG_LEN),
        )
        .unwrap_or_else(|error| panic!("bridge test header failed: {error}"));
        let ciphertext = service
            .provider
            .seal_with_nonce(&key, selector_nonce(&selector), &plaintext, &header)
            .unwrap_or_else(|error| panic!("bridge test seal failed: {error}"));
        plaintext.zeroize();
        let mut sealed = Vec::with_capacity(header.len().saturating_add(ciphertext.len()));
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    fn resign_bridge_authorization_for_test(
        authority: &ReferenceEnvelopeSealer,
        authorization: &mut BridgeAuthorization,
    ) {
        let credential_signature = encode_exact_hybrid_signature(&authority.credential.signature)
            .unwrap_or_else(|error| panic!("bridge test credential signature failed: {error}"));
        let digest = authorization
            .control_signature_digest(&authority.credential.body, &credential_signature)
            .unwrap_or_else(|error| panic!("bridge test control digest failed: {error}"));
        let signature = authority
            .provider
            .sign(&authority.signing_key, &digest)
            .unwrap_or_else(|error| panic!("bridge test control signing failed: {error}"));
        let signature = encode_exact_hybrid_signature(&signature)
            .unwrap_or_else(|error| panic!("bridge test signature encoding failed: {error}"));
        authorization.authority_control_signature =
            bridge::encode_delegated_control_authentication(
                &authority.credential.body,
                &credential_signature,
                &signature,
            )
            .unwrap_or_else(|error| panic!("bridge test authentication failed: {error}"));
    }

    #[test]
    fn distinct_authority_credentials_interoperate_and_item_id_is_semantic() {
        let mut provisioner = ReferenceProvisioner::from_seed([7u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(1, &[member_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let persisted = publisher_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("bundle serialization failed: {error}"));
        let restored = ProvisioningBundle::from_bytes(&persisted)
            .unwrap_or_else(|error| panic!("bundle parse failed: {error}"));
        assert_eq!(
            restored
                .to_bytes()
                .unwrap_or_else(|error| panic!("bundle reserialization failed: {error}")),
            persisted
        );
        let reader_bundle = provisioner
            .issue_node(2, &[member_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("reader issue failed: {error}"));
        let relay_bundle = provisioner
            .issue_node(3, &[relay_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("relay issue failed: {error}"));

        let mut publisher = service(restored);
        let mut reopened_publisher = service(
            ProvisioningBundle::from_bytes(&persisted)
                .unwrap_or_else(|error| panic!("reopened bundle parse failed: {error}")),
        );
        let mut reader = service(reader_bundle);
        let mut relay = service(relay_bundle);
        assert_eq!(publisher.identity(), reopened_publisher.identity());
        assert_ne!(publisher.identity(), reader.identity());
        assert!(relay.is_route_only(&scope("alpha"), &topic("ops"), 0));
        assert!(relay.can_route_event(&scope("alpha"), 0));
        assert!(!relay.can_open_event_content(&scope("alpha"), &topic("ops"), 0));
        assert!(publisher.can_route_event(&scope("alpha"), 0));
        assert!(publisher.can_open_event_content(&scope("alpha"), &topic("ops"), 0));

        let metadata = header(publisher.identity(), 0);
        let first = publisher
            .seal(SealRequest {
                header: &metadata,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("first seal failed: {error}"));
        let second = publisher
            .seal(SealRequest {
                header: &metadata,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("second seal failed: {error}"));
        assert_eq!(first.id, second.id);
        assert_ne!(first.bytes, second.bytes);

        let verified = reader
            .inspect(&first.bytes)
            .unwrap_or_else(|error| panic!("reader inspect failed: {error}"));
        assert_eq!(verified.id, first.id);
        let reopened_verified = reopened_publisher
            .inspect(&first.bytes)
            .unwrap_or_else(|error| panic!("reopened inspect failed: {error}"));
        assert_eq!(
            reopened_publisher
                .open_payload(&reopened_verified, &first.bytes)
                .unwrap_or_else(|error| panic!("reopened open failed: {error}")),
            b"payload"
        );
        assert_eq!(
            reader
                .open_payload(&verified, &first.bytes)
                .unwrap_or_else(|error| panic!("reader open failed: {error}")),
            b"payload"
        );
        let relay_verified = relay
            .inspect(&first.bytes)
            .unwrap_or_else(|error| panic!("relay inspect failed: {error}"));
        assert!(relay.open_payload(&relay_verified, &first.bytes).is_err());
    }

    #[test]
    fn source_sealing_rejects_zero_and_oversized_causal_contexts() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x3b; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let mut publisher = service(publisher_bundle);
        let identity = publisher.identity();

        let mut zero = header(identity, 0);
        zero.stamp.context.observe(Dot {
            publisher: [0x81; 32],
            counter: 0,
        });
        assert!(
            publisher
                .seal(SealRequest {
                    header: &zero,
                    payload: b"payload",
                })
                .is_err(),
            "sealing must reject rather than normalize a zero predecessor"
        );

        let mut oversized = header(identity, 0);
        for index in 0..=MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut predecessor = [0u8; 32];
            predecessor[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            if predecessor == identity {
                predecessor[31] = 1;
            }
            oversized.stamp.context.observe(Dot {
                publisher: predecessor,
                counter: 1,
            });
        }
        assert_eq!(
            oversized.stamp.context.len(),
            MAX_CAUSAL_CONTEXT_ENTRIES + 1
        );
        assert!(
            publisher
                .seal(SealRequest {
                    header: &oversized,
                    payload: b"payload",
                })
                .is_err(),
            "sealing must reject rather than truncate an oversized context"
        );
    }

    #[test]
    fn authenticated_maximal_remote_context_cannot_poison_local_publication() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x3a; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let receiver_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("receiver issue failed: {error}"));
        let mut publisher = service(publisher_bundle);
        let publisher_id = publisher.identity();
        let mut receiver = memory_reference_node(receiver_bundle);
        let receiver_id = receiver.identity();

        let mut fabricated = VersionVector::default();
        let mut first_claim = None;
        for index in 0..MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut claimed_publisher = [0xa5; 32];
            claimed_publisher[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            assert_ne!(claimed_publisher, publisher_id);
            assert_ne!(claimed_publisher, receiver_id);
            first_claim.get_or_insert(claimed_publisher);
            fabricated.observe(Dot {
                publisher: claimed_publisher,
                counter: 7,
            });
        }
        assert_eq!(fabricated.len(), MAX_CAUSAL_CONTEXT_ENTRIES);

        let mut metadata = header(publisher_id, 0);
        metadata.stamp.context = fabricated;
        let authenticated = publisher
            .seal(SealRequest {
                header: &metadata,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("maximal context seal failed: {error}"));
        receiver
            .ingest(&authenticated.bytes)
            .unwrap_or_else(|error| panic!("authenticated maximal context ingest failed: {error}"));

        let local = receiver
            .publish(crate::engine::PublishRequest {
                class: DataClass::State,
                topic: topic("ops"),
                scope: scope("alpha"),
                priority: Priority::Routine,
                ttl_ms: None,
                logical_key: b"receiver-status".to_vec(),
                payload: b"ready".to_vec(),
                tombstone: false,
            })
            .unwrap_or_else(|error| panic!("later local publication was poisoned: {error}"));

        assert!(local.stamp.context.observes(metadata.stamp.dot));
        assert!(!local.stamp.context.observes(Dot {
            publisher: first_claim.expect("fabricated context has an entry"),
            counter: 7,
        }));
        assert!(local.stamp.context.len() <= MAX_CAUSAL_CONTEXT_ENTRIES);
    }

    #[test]
    fn content_only_bundle_has_no_origin_route_grant_or_commitment() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x66; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(1, &[member_access(vec![7])])
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let target_bundle = provisioner
            .issue_node(
                2,
                &[
                    ProvisioningAccess::content_only(scope("alpha"), vec![7], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("content-only access failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("content-only issue failed: {error}"));
        assert!(target_bundle.route_grants.is_empty());
        assert_eq!(target_bundle.content_grants.len(), 1);
        assert_eq!(target_bundle.roles, ROLE_READER);
        let persisted = target_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("content-only persist failed: {error}"));
        let restored = ProvisioningBundle::from_bytes(&persisted)
            .unwrap_or_else(|error| panic!("content-only parse failed: {error}"));
        assert!(restored.route_grants.is_empty());
        assert_eq!(restored.content_grants.len(), 1);

        let mut publisher = service(publisher_bundle);
        let mut target = service(restored);
        assert!(target.credential.route_grant_commitments.is_empty());
        assert_eq!(target.credential.roles & ROLE_RELAY, 0);
        assert_ne!(target.credential.roles & ROLE_READER, 0);
        assert!(target.is_content_only(&scope("alpha"), &topic("ops"), 7));
        assert!(!target.can_route_event(&scope("alpha"), 7));
        assert!(target.can_open_event_content(&scope("alpha"), &topic("ops"), 7));
        let source_header = header(publisher.identity(), 7);
        let source = publisher
            .seal(SealRequest {
                header: &source_header,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("content-only source seal failed: {error}"));
        assert!(target.inspect(&source.bytes).is_err());
        assert!(format!("{target:?}").contains("key_material: \"[REDACTED]\""));

        EnvelopeSealer::zeroize(&mut target)
            .unwrap_or_else(|error| panic!("content-only zeroize failed: {error}"));
        assert!(target.route_grants.is_empty());
        assert!(target.content_grants.is_empty());
        assert!(target.inspect(&source.bytes).is_err());
    }

    #[test]
    fn blob_route_commitment_is_strict_and_source_authenticated_for_relays() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x67; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let reader_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("reader issue failed: {error}"));
        let relay_bundle = provisioner
            .issue_node(3, &[relay_access(vec![0])])
            .unwrap_or_else(|error| panic!("relay issue failed: {error}"));
        let mut publisher = service(publisher_bundle);
        let mut reader = service(reader_bundle);
        let mut relay = service(relay_bundle);
        let blob_id = BlobId::from_bytes([0x68; 32]);
        let commitment = BlobRouteCommitment::from_authenticated_header(blob_id, 3, [0x69; 32]);
        let payload = b"encrypted manifest";
        let mut metadata = header(publisher.identity(), 0);
        metadata.class = DataClass::Blob;
        metadata.logical_key = blob_id.as_bytes().to_vec();
        metadata.blob_route = Some(commitment);
        metadata.content_len = payload.len() as u64;

        let sealed = publisher
            .seal(SealRequest {
                header: &metadata,
                payload,
            })
            .unwrap_or_else(|error| panic!("Blob seal failed: {error}"));
        let relayed = relay
            .inspect(&sealed.bytes)
            .unwrap_or_else(|error| panic!("relay inspect failed: {error}"));
        assert_eq!(relayed.header.blob_route, Some(commitment));
        assert_eq!(
            relay
                .open_payload_if_authorized(&relayed, &sealed.bytes)
                .unwrap_or_else(|error| panic!("relay authorization failed: {error}")),
            None
        );
        let readable = reader
            .inspect(&sealed.bytes)
            .unwrap_or_else(|error| panic!("reader inspect failed: {error}"));
        assert_eq!(
            reader
                .open_payload_if_authorized(&readable, &sealed.bytes)
                .unwrap_or_else(|error| panic!("reader open failed: {error}")),
            Some(payload.to_vec())
        );

        let mut missing = metadata.clone();
        missing.blob_route = None;
        assert!(
            publisher
                .seal(SealRequest {
                    header: &missing,
                    payload,
                })
                .is_err()
        );
        let mut wrong_class = metadata.clone();
        wrong_class.class = DataClass::State;
        assert!(
            publisher
                .seal(SealRequest {
                    header: &wrong_class,
                    payload,
                })
                .is_err()
        );
        let mut wrong_key = metadata.clone();
        wrong_key.logical_key = [0x6a; 32].to_vec();
        assert!(
            publisher
                .seal(SealRequest {
                    header: &wrong_key,
                    payload,
                })
                .is_err()
        );

        // A relay knows the shared routing key, so prove the source signature—not merely the
        // routing-layer AEAD—rejects its authenticated rewrite of protected metadata.
        let parsed =
            parse_envelope(&sealed.bytes).unwrap_or_else(|error| panic!("parse failed: {error}"));
        let mut decoded = relay
            .open_data_route(&parsed)
            .unwrap_or_else(|error| panic!("route open failed: {error}"));
        decoded.header.priority = Priority::Routine;
        let mut rewritten_route = Vec::new();
        rewritten_route.push(EnvelopeKind::Data as u8);
        push_u32_bytes(&mut rewritten_route, &decoded.credential.body)
            .unwrap_or_else(|error| panic!("credential encode failed: {error}"));
        encode_signature(&mut rewritten_route, &decoded.credential.signature)
            .unwrap_or_else(|error| panic!("credential signature encode failed: {error}"));
        rewritten_route.extend_from_slice(&decoded.item_id);
        encode_header(&mut rewritten_route, &decoded.header)
            .unwrap_or_else(|error| panic!("header encode failed: {error}"));
        rewritten_route.extend_from_slice(&decoded.content_group);
        rewritten_route.extend_from_slice(&decoded.content_nonce);
        rewritten_route.extend_from_slice(&decoded.batch_id);
        rewritten_route.extend_from_slice(&decoded.content_ciphertext_len.to_be_bytes());
        encode_signature(&mut rewritten_route, &decoded.item_signature)
            .unwrap_or_else(|error| panic!("item signature encode failed: {error}"));
        let route_key = derive_item_secret(
            relay
                .route_grant(&decoded.header.scope, decoded.header.key_epoch)
                .unwrap_or_else(|| panic!("relay route grant missing"))
                .key
                .expose(),
            ROUTE_KEY_LABEL,
            &parsed.selector,
        )
        .unwrap_or_else(|error| panic!("route key failed: {error}"));
        let rewritten_ciphertext = relay
            .provider
            .seal_with_nonce(
                &route_key,
                selector_nonce(&parsed.selector),
                &rewritten_route,
                parsed.public_header,
            )
            .unwrap_or_else(|error| panic!("route rewrite failed: {error}"));
        assert_eq!(rewritten_ciphertext.len(), parsed.route_ciphertext.len());
        let mut rewritten = Vec::new();
        rewritten.extend_from_slice(parsed.public_header);
        rewritten.extend_from_slice(&rewritten_ciphertext);
        rewritten.extend_from_slice(parsed.content_ciphertext);
        assert!(relay.inspect(&rewritten).is_err());
    }

    #[test]
    fn wrong_authority_downgrade_tamper_and_missing_signature_are_rejected() {
        let mut provisioner = ReferenceProvisioner::from_seed([8u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let mut publisher = service(
            provisioner
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("publisher issue failed: {error}")),
        );
        let mut reader = service(
            provisioner
                .issue_node(2, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("reader issue failed: {error}")),
        );
        let metadata = header(publisher.identity(), 0);
        let sealed = publisher
            .seal(SealRequest {
                header: &metadata,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("seal failed: {error}"));

        let mut other_provisioner = ReferenceProvisioner::from_seed([9u8; 32])
            .unwrap_or_else(|error| panic!("other provisioner failed: {error}"));
        let mut outsider = service(
            other_provisioner
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("outsider issue failed: {error}")),
        );
        assert!(outsider.inspect(&sealed.bytes).is_err());

        let mut downgrade = sealed.bytes.clone();
        downgrade[12..14].copy_from_slice(&2u16.to_be_bytes());
        assert!(reader.inspect(&downgrade).is_err());

        let mut route_tamper = sealed.bytes.clone();
        route_tamper[PUBLIC_HEADER_LEN] ^= 1;
        assert!(reader.inspect(&route_tamper).is_err());

        let mut content_tamper = sealed.bytes.clone();
        let last = content_tamper
            .len()
            .checked_sub(1)
            .unwrap_or_else(|| panic!("sealed test envelope was empty"));
        content_tamper[last] ^= 1;
        let tampered_verified = reader
            .inspect(&content_tamper)
            .unwrap_or_else(|error| panic!("route should remain inspectable: {error}"));
        assert!(
            reader
                .open_payload(&tampered_verified, &content_tamper)
                .is_err()
        );

        let parsed =
            parse_envelope(&sealed.bytes).unwrap_or_else(|error| panic!("parse failed: {error}"));
        let route_seed = publisher
            .route_grant(&scope("alpha"), 0)
            .unwrap_or_else(|| panic!("test route grant absent"));
        let route_key =
            derive_item_secret(route_seed.key.expose(), ROUTE_KEY_LABEL, &parsed.selector)
                .unwrap_or_else(|error| panic!("route KDF failed: {error}"));
        let mut route = publisher
            .provider
            .open_parts(
                &route_key,
                selector_nonce(&parsed.selector),
                parsed.route_ciphertext,
                parsed.public_header,
            )
            .unwrap_or_else(|error| panic!("route open failed: {error}"));
        let item_signature_bytes = 2 + P256_SIGNATURE_LEN + 4 + ML_DSA_SIGNATURE_LEN;
        let signature_start = route
            .len()
            .checked_sub(item_signature_bytes)
            .unwrap_or_else(|| panic!("test route signature absent"));
        route[signature_start..signature_start + 2].copy_from_slice(&0u16.to_be_bytes());
        let forged_route = publisher
            .provider
            .seal_with_nonce(
                &route_key,
                selector_nonce(&parsed.selector),
                &route,
                parsed.public_header,
            )
            .unwrap_or_else(|error| panic!("test route reseal failed: {error}"));
        let mut missing_signature = sealed.bytes.clone();
        let route_end = PUBLIC_HEADER_LEN + parsed.route_ciphertext.len();
        missing_signature[PUBLIC_HEADER_LEN..route_end].copy_from_slice(&forged_route);
        assert!(reader.inspect(&missing_signature).is_err());
        route.zeroize();

        let mut trailing = sealed.bytes.clone();
        trailing.push(0);
        assert!(reader.inspect(&trailing).is_err());
        assert!(reader.inspect(&sealed.bytes[..PUBLIC_HEADER_LEN]).is_err());
    }

    #[test]
    fn only_authority_controls_verify_and_preprovisioned_epoch_changes_keys() {
        let mut provisioner = ReferenceProvisioner::from_seed([10u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let mut authority = service(
            provisioner
                .issue_control_authority(1, &[member_access(vec![0, 1])])
                .unwrap_or_else(|error| panic!("authority issue failed: {error}")),
        );
        let mut member = service(
            provisioner
                .issue_node(2, &[member_access(vec![0, 1])])
                .unwrap_or_else(|error| panic!("member issue failed: {error}")),
        );
        let mut current_only = service(
            provisioner
                .issue_node(3, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("current issue failed: {error}")),
        );
        assert!(member.seal_revocation([3u8; 32], 1).is_err());

        let revocation = authority
            .seal_revocation(current_only.identity(), 1)
            .unwrap_or_else(|error| panic!("revocation seal failed: {error}"));
        assert!(matches!(
            member
                .inspect_control(&revocation)
                .unwrap_or_else(|error| panic!("revocation inspect failed: {error}")),
            VerifiedControl::Revocation(_)
        ));

        let rekey = authority
            .seal_scope_epoch(&scope("alpha"), 1)
            .unwrap_or_else(|error| panic!("rekey seal failed: {error}"));
        assert!(matches!(
            member
                .inspect_control(&rekey)
                .unwrap_or_else(|error| panic!("rekey inspect failed: {error}")),
            VerifiedControl::ScopeEpoch(ScopeEpoch { epoch: 1, .. })
        ));
        assert!(current_only.inspect_control(&rekey).is_err());

        let epoch_one_header = header(authority.identity(), 1);
        let epoch_one = authority
            .seal(SealRequest {
                header: &epoch_one_header,
                payload: b"payload",
            })
            .unwrap_or_else(|error| panic!("epoch-one seal failed: {error}"));
        let verified = member
            .inspect(&epoch_one.bytes)
            .unwrap_or_else(|error| panic!("epoch-one inspect failed: {error}"));
        assert_eq!(
            member
                .open_payload(&verified, &epoch_one.bytes)
                .unwrap_or_else(|error| panic!("epoch-one open failed: {error}")),
            b"payload"
        );
        assert!(current_only.inspect(&epoch_one.bytes).is_err());

        let mut tampered = rekey;
        let index = PUBLIC_HEADER_LEN;
        tampered[index] ^= 1;
        assert!(member.inspect_control(&tampered).is_err());
    }

    #[test]
    fn delegated_controls_bind_distinct_authority_credentials_and_reject_legacy_or_substitution() {
        let provisioning_seed = [0x2a; 32];
        let mut provisioner = ReferenceProvisioner::from_seed(provisioning_seed)
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let first_bundle = provisioner
            .issue_control_authority(1, &[member_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("first authority issue failed: {error}"));
        let first_bundle_bytes = first_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("first authority serialization failed: {error}"));
        let second_bundle = provisioner
            .issue_control_authority(2, &[member_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("second authority issue failed: {error}"));
        let ordinary_bundle = provisioner
            .issue_node(3, &[member_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("ordinary issue failed: {error}"));
        let member_bundle = provisioner
            .issue_node(4, &[member_access(vec![0, 1])])
            .unwrap_or_else(|error| panic!("member issue failed: {error}"));

        let mut authority_seed =
            derive_material::<32>(&provisioning_seed, b"authority-signing-seed", &[])
                .unwrap_or_else(|error| panic!("authority seed derivation failed: {error}"));
        assert!(!contains_bytes(&first_bundle_bytes, &authority_seed));
        authority_seed.zeroize();

        let mut first = service(
            ProvisioningBundle::from_bytes(&first_bundle_bytes)
                .unwrap_or_else(|error| panic!("first authority restore failed: {error}")),
        );
        let mut second = service(second_bundle);
        let ordinary = service(ordinary_bundle);
        let mut member = service(member_bundle);
        let first_public = first
            .provider
            .verifying_key(&first.signing_key)
            .unwrap_or_else(|error| panic!("first identity public key failed: {error}"));
        let second_public = second
            .provider
            .verifying_key(&second.signing_key)
            .unwrap_or_else(|error| panic!("second identity public key failed: {error}"));
        assert_ne!(first_public, first.authority_verifying_key);
        assert_ne!(second_public, second.authority_verifying_key);
        assert_ne!(first_public, second_public);

        let first_control = first
            .seal_revocation([0x41; 32], 1)
            .unwrap_or_else(|error| panic!("first delegated control failed: {error}"));
        let second_control = second
            .seal_revocation([0x42; 32], 1)
            .unwrap_or_else(|error| panic!("second delegated control failed: {error}"));
        assert!(matches!(
            first
                .inspect_control_internal(&first_control)
                .unwrap_or_else(|error| panic!("first delegated inspect failed: {error}")),
            DecodedControl::Revocation { signer, .. } if signer == first.identity()
        ));
        assert!(matches!(
            second
                .inspect_control_internal(&second_control)
                .unwrap_or_else(|error| panic!("second delegated inspect failed: {error}")),
            DecodedControl::Revocation { signer, .. } if signer == second.identity()
        ));
        member
            .inspect_control(&first_control)
            .unwrap_or_else(|error| panic!("member rejected first authority: {error}"));
        member
            .inspect_control(&second_control)
            .unwrap_or_else(|error| panic!("member rejected second authority: {error}"));

        let (kind, selector, first_plaintext) = open_test_control_plaintext(&first, &first_control);
        let mut reader = Reader::new(&first_plaintext);
        reader
            .u8()
            .unwrap_or_else(|error| panic!("kind failed: {error}"));
        reader
            .take(CONTROL_AUTHENTICATION_MAGIC.len())
            .unwrap_or_else(|error| panic!("control magic failed: {error}"));
        reader
            .u16()
            .unwrap_or_else(|error| panic!("control format failed: {error}"));
        reader
            .array::<32>()
            .unwrap_or_else(|error| panic!("mission failed: {error}"));
        reader
            .array::<32>()
            .unwrap_or_else(|error| panic!("authority failed: {error}"));
        let credential_start = reader.position();
        reader
            .u32_bytes(16 * 1024)
            .unwrap_or_else(|error| panic!("credential failed: {error}"));
        decode_signature(&mut reader)
            .unwrap_or_else(|error| panic!("credential signature failed: {error}"));
        let credential_end = reader.position();

        let mut credential_substitution = first_plaintext[..credential_start].to_vec();
        push_u32_bytes(&mut credential_substitution, &second.credential.body)
            .unwrap_or_else(|error| panic!("replacement credential failed: {error}"));
        encode_signature(&mut credential_substitution, &second.credential.signature)
            .unwrap_or_else(|error| panic!("replacement credential signature failed: {error}"));
        credential_substitution.extend_from_slice(&first_plaintext[credential_end..]);
        let credential_substitution =
            seal_test_control_plaintext(&first, kind, selector, credential_substitution);
        assert!(member.inspect_control(&credential_substitution).is_err());

        let signature_len = 2 + P256_SIGNATURE_LEN + 4 + ML_DSA_SIGNATURE_LEN;
        let (_, _, second_plaintext) = open_test_control_plaintext(&second, &second_control);
        let mut signature_substitution = first_plaintext.clone();
        let first_signature_start = signature_substitution.len() - signature_len;
        let second_signature_start = second_plaintext.len() - signature_len;
        signature_substitution[first_signature_start..]
            .copy_from_slice(&second_plaintext[second_signature_start..]);
        let signature_substitution =
            seal_test_control_plaintext(&first, kind, selector, signature_substitution);
        assert!(member.inspect_control(&signature_substitution).is_err());

        let mut ordinary_forgery = first_plaintext[..credential_start].to_vec();
        push_u32_bytes(&mut ordinary_forgery, &ordinary.credential.body)
            .unwrap_or_else(|error| panic!("ordinary credential failed: {error}"));
        encode_signature(&mut ordinary_forgery, &ordinary.credential.signature)
            .unwrap_or_else(|error| panic!("ordinary credential signature failed: {error}"));
        ordinary_forgery.extend_from_slice(
            &first_plaintext[credential_end..first_plaintext.len() - signature_len],
        );
        let digest = hash_domain(CONTROL_SIGNATURE_DOMAIN, &ordinary_forgery);
        let forged_signature = ordinary
            .provider
            .sign(&ordinary.signing_key, &digest)
            .unwrap_or_else(|error| panic!("ordinary control signing failed: {error}"));
        encode_signature(&mut ordinary_forgery, &forged_signature)
            .unwrap_or_else(|error| panic!("ordinary signature encoding failed: {error}"));
        let ordinary_forgery =
            seal_test_control_plaintext(&first, kind, selector, ordinary_forgery);
        assert!(member.inspect_control(&ordinary_forgery).is_err());

        let mut legacy = Vec::new();
        legacy.push(EnvelopeKind::Revocation as u8);
        legacy.extend_from_slice(&first.mission);
        legacy.extend_from_slice(&first.authority_id);
        legacy.extend_from_slice(&1u64.to_be_bytes());
        legacy.push(0);
        legacy.extend_from_slice(&[0x43; 32]);
        legacy.extend_from_slice(&1u64.to_be_bytes());
        let legacy_digest = hash_domain(b"aster/authority-control/v1", &legacy);
        let legacy_signature = provisioner
            .provider
            .sign(&provisioner.authority_signing_key, &legacy_digest)
            .unwrap_or_else(|error| panic!("legacy root signing failed: {error}"));
        encode_signature(&mut legacy, &legacy_signature)
            .unwrap_or_else(|error| panic!("legacy signature encoding failed: {error}"));
        let legacy = seal_test_control_plaintext(&first, kind, selector, legacy);
        assert!(member.inspect_control(&legacy).is_err());
    }

    #[test]
    fn fresh_scope_rekey_excludes_capture_and_enforces_recipient_topics() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x61; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let epochs = vec![0, 1];
        let route_bundle = provisioner
            .issue_node(1, &[relay_access(epochs.clone())])
            .unwrap_or_else(|error| panic!("route issue failed: {error}"));
        let ops_bundle = provisioner
            .issue_node(2, &[member_access(epochs.clone())])
            .unwrap_or_else(|error| panic!("ops issue failed: {error}"));
        let intel_access =
            ProvisioningAccess::member(scope("alpha"), epochs.clone(), vec![topic("intel")])
                .unwrap_or_else(|error| panic!("intel access failed: {error}"));
        let intel_bundle = provisioner
            .issue_node(3, std::slice::from_ref(&intel_access))
            .unwrap_or_else(|error| panic!("intel issue failed: {error}"));
        let captured_access =
            ProvisioningAccess::member(scope("alpha"), epochs, vec![topic("intel"), topic("ops")])
                .unwrap_or_else(|error| panic!("captured access failed: {error}"));
        let captured_bundle = provisioner
            .issue_node(4, std::slice::from_ref(&captured_access))
            .unwrap_or_else(|error| panic!("captured issue failed: {error}"));
        let authority_bundle = provisioner
            .issue_control_authority(5, &[captured_access])
            .unwrap_or_else(|error| panic!("authority issue failed: {error}"));

        let route_id = bundle_identity(&route_bundle);
        let ops_id = bundle_identity(&ops_bundle);
        let intel_id = bundle_identity(&intel_bundle);
        let captured_id = bundle_identity(&captured_bundle);
        let authority_id = bundle_identity(&authority_bundle);
        let plan = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                1,
                vec![
                    ScopeRekeyRecipient::route_only(route_id),
                    ScopeRekeyRecipient::member(ops_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("ops plan failed: {error}")),
                    ScopeRekeyRecipient::member(intel_id, vec![topic("intel")])
                        .unwrap_or_else(|error| panic!("intel plan failed: {error}")),
                    ScopeRekeyRecipient::member(authority_id, vec![topic("intel"), topic("ops")])
                        .unwrap_or_else(|error| panic!("authority plan failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("rekey plan failed: {error}"));

        let mut authority_node = memory_reference_node(authority_bundle);
        let receipt = authority_node
            .publish_scope_rekey(&plan)
            .unwrap_or_else(|error| panic!("rekey publish failed: {error}"));
        assert_eq!(receipt.sequence, 1);
        let (mut authority_store, mut authority) = authority_node.into_parts();
        let control = authority_store
            .applied_controls()
            .unwrap_or_else(|error| panic!("controls failed: {error}"))
            .first()
            .unwrap_or_else(|| panic!("rekey control missing"))
            .sealed
            .clone();
        let DecodedControl::ScopeEpoch {
            keying: ScopeEpochKeying::RecipientPackages { format, .. },
            ..
        } = authority
            .inspect_control_internal(&control)
            .unwrap_or_else(|error| panic!("fresh control decode failed: {error}"))
        else {
            panic!("fresh control did not contain recipient packages");
        };
        assert_eq!(format, SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT);
        let mut fresh_route_key = *authority
            .route_grant(&scope("alpha"), 1)
            .unwrap_or_else(|| panic!("authority fresh route grant missing"))
            .key
            .expose();
        let mut fresh_ops_key = *authority
            .content_grant(&scope("alpha"), &topic("ops"), 1)
            .unwrap_or_else(|| panic!("authority fresh ops grant missing"))
            .key
            .expose();
        assert!(!contains_bytes(&control, &fresh_route_key));
        assert!(!contains_bytes(&control, &fresh_ops_key));
        assert!(!contains_bytes(&control, &captured_id));
        fresh_route_key.zeroize();
        fresh_ops_key.zeroize();

        let mut route_node = memory_reference_node(route_bundle);
        route_node
            .ingest_control(&control)
            .unwrap_or_else(|error| panic!("route control ingest failed: {error}"));
        let (_, mut route) = route_node.into_parts();
        let mut ops_node = memory_reference_node(ops_bundle);
        ops_node
            .ingest_control(&control)
            .unwrap_or_else(|error| panic!("ops control ingest failed: {error}"));
        let (_, mut ops) = ops_node.into_parts();
        let mut intel_node = memory_reference_node(intel_bundle);
        intel_node
            .ingest_control(&control)
            .unwrap_or_else(|error| panic!("intel control ingest failed: {error}"));
        let (_, mut intel) = intel_node.into_parts();
        let mut captured_node = memory_reference_node(captured_bundle);
        captured_node
            .ingest_control(&control)
            .unwrap_or_else(|error| panic!("captured control ingest failed: {error}"));
        let (_, mut captured) = captured_node.into_parts();

        assert!(route.is_route_only(&scope("alpha"), &topic("ops"), 1));
        assert!(
            ops.content_grant(&scope("alpha"), &topic("ops"), 1)
                .is_some()
        );
        assert!(
            ops.content_grant(&scope("alpha"), &topic("intel"), 1)
                .is_none()
        );
        assert!(
            intel
                .content_grant(&scope("alpha"), &topic("intel"), 1)
                .is_some()
        );
        assert!(
            intel
                .content_grant(&scope("alpha"), &topic("ops"), 1)
                .is_none()
        );
        assert!(captured.route_grant(&scope("alpha"), 1).is_none());
        assert!(
            captured
                .content_grant(&scope("alpha"), &topic("ops"), 1)
                .is_none()
        );
        assert!(authority.peer_can_route(
            route_id,
            &route.credential.route_grant_commitments,
            &scope("alpha"),
            1,
        ));
        assert!(!authority.peer_can_route(
            captured_id,
            &captured.credential.route_grant_commitments,
            &scope("alpha"),
            1,
        ));

        let mut metadata = header(authority.identity(), 1);
        metadata.content_len = b"fresh ops payload".len() as u64;
        let ops_envelope = authority
            .seal(SealRequest {
                header: &metadata,
                payload: b"fresh ops payload",
            })
            .unwrap_or_else(|error| panic!("ops seal failed: {error}"));
        let verified = route
            .inspect(&ops_envelope.bytes)
            .unwrap_or_else(|error| panic!("route inspect failed: {error}"));
        assert!(route.open_payload(&verified, &ops_envelope.bytes).is_err());
        let verified = ops
            .inspect(&ops_envelope.bytes)
            .unwrap_or_else(|error| panic!("ops inspect failed: {error}"));
        assert_eq!(
            ops.open_payload(&verified, &ops_envelope.bytes)
                .unwrap_or_else(|error| panic!("ops open failed: {error}")),
            b"fresh ops payload"
        );
        assert!(intel.open_payload(&verified, &ops_envelope.bytes).is_err());
        assert!(captured.inspect(&ops_envelope.bytes).is_err());

        let mut intel_metadata = header(authority.identity(), 1);
        intel_metadata.topic = topic("intel");
        intel_metadata.content_len = b"fresh intel payload".len() as u64;
        let intel_envelope = authority
            .seal(SealRequest {
                header: &intel_metadata,
                payload: b"fresh intel payload",
            })
            .unwrap_or_else(|error| panic!("intel seal failed: {error}"));
        let verified = intel
            .inspect(&intel_envelope.bytes)
            .unwrap_or_else(|error| panic!("intel inspect failed: {error}"));
        assert_eq!(
            intel
                .open_payload(&verified, &intel_envelope.bytes)
                .unwrap_or_else(|error| panic!("intel open failed: {error}")),
            b"fresh intel payload"
        );
        assert!(ops.open_payload(&verified, &intel_envelope.bytes).is_err());
    }

    #[test]
    fn authority_bundle_builds_fresh_plan_from_signed_public_registry() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x68; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let member_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("member issue failed: {error}"));
        let captured_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("captured issue failed: {error}"));
        let authority_bundle = provisioner
            .issue_control_authority(3, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("authority issue failed: {error}"));
        let member_id = bundle_identity(&member_bundle);
        let captured_id = bundle_identity(&captured_bundle);
        let authority_id = bundle_identity(&authority_bundle);
        let registry = provisioner
            .export_rekey_registry()
            .unwrap_or_else(|error| panic!("registry export failed: {error}"));

        let mut authority = memory_reference_node(authority_bundle);
        let (receipt, generation) = authority
            .publish_scope_rekey_from_registry(
                &registry,
                3,
                scope("alpha"),
                1,
                vec![
                    ScopeRekeyRecipient::member(authority_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("authority recipient failed: {error}")),
                    ScopeRekeyRecipient::member(member_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("member recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("registry rekey failed: {error}"));
        assert_eq!(generation, 3);
        assert_eq!(receipt.sequence, 1);
        let (mut authority_store, _) = authority.into_parts();
        let control = authority_store
            .applied_controls()
            .unwrap_or_else(|error| panic!("authority controls failed: {error}"))[0]
            .sealed
            .clone();

        let mut member = memory_reference_node(member_bundle);
        member
            .ingest_control(&control)
            .unwrap_or_else(|error| panic!("member control ingest failed: {error}"));
        let (_, member_sealer) = member.into_parts();
        assert!(
            member_sealer
                .content_grant(&scope("alpha"), &topic("ops"), 1)
                .is_some()
        );

        let mut captured = memory_reference_node(captured_bundle);
        captured
            .ingest_control(&control)
            .unwrap_or_else(|error| panic!("captured control ingest failed: {error}"));
        let (_, captured_sealer) = captured.into_parts();
        assert!(captured_sealer.route_grant(&scope("alpha"), 1).is_none());
        assert!(
            captured_sealer
                .content_grant(&scope("alpha"), &topic("ops"), 1)
                .is_none()
        );
        assert_ne!(captured_id, member_id);
    }

    #[test]
    fn fresh_rekey_grant_commitment_is_salted() {
        let scope = scope("alpha");
        let recipient = [0x71; 32];
        let credential_hash = [0x72; 32];
        let topics = vec![topic("intel"), topic("ops")];
        let first_salt = Secret32::new([0x73; 32]);
        let second_salt = Secret32::new([0x74; 32]);

        let first = rekey_grant_commitment(
            SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT,
            &scope,
            7,
            recipient,
            &credential_hash,
            &first_salt,
            true,
            &topics,
        )
        .unwrap_or_else(|error| panic!("first commitment failed: {error}"));
        let second = rekey_grant_commitment(
            SCOPE_EPOCH_RECIPIENT_PACKAGES_FORMAT,
            &scope,
            7,
            recipient,
            &credential_hash,
            &second_salt,
            true,
            &topics,
        )
        .unwrap_or_else(|error| panic!("second commitment failed: {error}"));

        assert_ne!(first, second);
    }

    #[test]
    fn rekey_registry_export_import_survives_authority_restart() {
        let seed = [0x62; 32];
        let mut provisioner = ReferenceProvisioner::from_seed(seed)
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let recipient = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("recipient issue failed: {error}"));
        let recipient_id = bundle_identity(&recipient);
        assert_eq!(
            provisioner
                .rekey_registry_recipient_nodes()
                .collect::<Vec<_>>(),
            vec![recipient_id]
        );
        let identity_seed = *recipient
            .identity_seed
            .as_ref()
            .unwrap_or_else(|| panic!("recipient identity seed missing"))
            .expose();
        let control_route_key = *recipient
            .control_route_key
            .as_ref()
            .unwrap_or_else(|| panic!("recipient control route key missing"))
            .expose();
        let registry = provisioner
            .export_rekey_registry()
            .unwrap_or_else(|error| panic!("registry export failed: {error}"));
        assert_eq!(provisioner.rekey_registry_generation(), 1);
        assert!(!contains_bytes(&registry, &seed));
        assert!(!contains_bytes(&registry, &identity_seed));
        assert!(!contains_bytes(&registry, &control_route_key));
        drop(provisioner);

        let mut restarted = ReferenceProvisioner::from_seed(seed)
            .unwrap_or_else(|error| panic!("restart failed: {error}"));
        assert!(
            restarted
                .import_rekey_registry_at_least(&registry, 2)
                .is_err()
        );
        assert_eq!(restarted.rekey_registry_generation(), 0);
        restarted
            .import_rekey_registry_at_least(&registry, 1)
            .unwrap_or_else(|error| panic!("registry import failed: {error}"));
        assert_eq!(restarted.rekey_registry_generation(), 1);
        assert_eq!(
            restarted
                .rekey_registry_recipient_nodes()
                .collect::<Vec<_>>(),
            vec![recipient_id]
        );
        let plan = restarted
            .plan_scope_rekey(
                scope("alpha"),
                1,
                vec![
                    ScopeRekeyRecipient::member(recipient_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("recipient plan failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("restart plan failed: {error}"));
        assert_eq!(plan.recipients().len(), 1);

        let mut damaged = registry.clone();
        let last = damaged
            .last_mut()
            .unwrap_or_else(|| panic!("registry was empty"));
        *last ^= 1;
        assert!(restarted.import_rekey_registry(&damaged).is_err());
        assert_eq!(restarted.rekey_registry_generation(), 1);
        assert!(
            restarted
                .plan_scope_rekey(
                    scope("alpha"),
                    2,
                    vec![ScopeRekeyRecipient::route_only(recipient_id)],
                )
                .is_ok()
        );

        let second = restarted
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("second recipient issue failed: {error}"));
        let second_id = bundle_identity(&second);
        assert_eq!(restarted.rekey_registry_generation(), 2);
        let mut expected_recipients = vec![recipient_id, second_id];
        expected_recipients.sort_unstable();
        assert_eq!(
            restarted
                .rekey_registry_recipient_nodes()
                .collect::<Vec<_>>(),
            expected_recipients
        );
        assert!(restarted.import_rekey_registry(&registry).is_err());
        assert!(
            restarted
                .plan_scope_rekey(
                    scope("alpha"),
                    3,
                    vec![ScopeRekeyRecipient::route_only(second_id)],
                )
                .is_ok()
        );
    }

    #[test]
    fn rekey_registry_rejects_replacement_noncanonical_and_wrong_authority() {
        let seed = [0x65; 32];
        let mut authority = ReferenceProvisioner::from_seed(seed)
            .unwrap_or_else(|error| panic!("authority failed: {error}"));
        authority
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("first issue failed: {error}"));
        authority
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("second issue failed: {error}"));
        let canonical = authority
            .export_rekey_registry()
            .unwrap_or_else(|error| panic!("canonical export failed: {error}"));
        let offsets = registry_node_offsets(&canonical);
        assert_eq!(offsets.len(), 2);

        let mut duplicate = canonical.clone();
        duplicate.copy_within(offsets[0]..offsets[0] + 32, offsets[1]);
        let mut fresh = ReferenceProvisioner::from_seed(seed)
            .unwrap_or_else(|error| panic!("duplicate verifier failed: {error}"));
        assert!(fresh.import_rekey_registry(&duplicate).is_err());

        let mut unsorted = canonical.clone();
        for index in 0..32 {
            unsorted.swap(offsets[0] + index, offsets[1] + index);
        }
        assert!(fresh.import_rekey_registry(&unsorted).is_err());

        let mut wrong_authority = ReferenceProvisioner::from_seed([0x66; 32])
            .unwrap_or_else(|error| panic!("wrong authority failed: {error}"));
        wrong_authority
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("wrong authority issue failed: {error}"));
        let wrong_registry = wrong_authority
            .export_rekey_registry()
            .unwrap_or_else(|error| panic!("wrong authority export failed: {error}"));
        assert!(fresh.import_rekey_registry(&wrong_registry).is_err());

        fresh
            .import_rekey_registry(&canonical)
            .unwrap_or_else(|error| panic!("canonical import failed: {error}"));
        let mut replacement = ReferenceProvisioner::from_seed(seed)
            .unwrap_or_else(|error| panic!("replacement authority failed: {error}"));
        replacement
            .issue_node(91, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("replacement first issue failed: {error}"));
        replacement
            .issue_node(92, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("replacement second issue failed: {error}"));
        let replacement_registry = replacement
            .export_rekey_registry()
            .unwrap_or_else(|error| panic!("replacement export failed: {error}"));
        assert!(fresh.import_rekey_registry(&replacement_registry).is_err());
        assert_eq!(fresh.rekey_registry_generation(), 2);
    }

    #[test]
    fn out_of_order_rekey_activates_after_commit_and_replays_on_reopen() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x63; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let member_bundle = provisioner
            .issue_node(1, &[member_access(vec![0, 1, 2])])
            .unwrap_or_else(|error| panic!("member issue failed: {error}"));
        let member_id = bundle_identity(&member_bundle);
        let member_bytes = member_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("member serialize failed: {error}"));
        let authority_bundle = provisioner
            .issue_control_authority(2, &[member_access(vec![0, 1, 2])])
            .unwrap_or_else(|error| panic!("authority issue failed: {error}"));
        let plan_one = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                1,
                vec![
                    ScopeRekeyRecipient::member(member_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("epoch-one recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("epoch-one plan failed: {error}"));
        let plan_two = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                2,
                vec![
                    ScopeRekeyRecipient::member(member_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("epoch-two recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("epoch-two plan failed: {error}"));
        let mut authority = service(authority_bundle);
        let control_one = authority
            .seal_scope_rekey_chained(&plan_one, 1, None)
            .unwrap_or_else(|error| panic!("epoch-one control failed: {error}"));
        let control_one_id: [u8; 32] = Sha256::digest(&control_one).into();
        let control_two = authority
            .seal_scope_rekey_chained(&plan_two, 2, Some(control_one_id))
            .unwrap_or_else(|error| panic!("epoch-two control failed: {error}"));

        let original = service(
            ProvisioningBundle::from_bytes(&member_bytes)
                .unwrap_or_else(|error| panic!("member parse failed: {error}")),
        );
        let old_epoch_two = *original
            .route_grant(&scope("alpha"), 2)
            .unwrap_or_else(|| panic!("old epoch-two route grant missing"))
            .key
            .expose();
        drop(original);

        let path = unique_store_path("rekey-reopen");
        let mut node = open_reference_node(
            &path,
            ProvisioningBundle::from_bytes(&member_bytes)
                .unwrap_or_else(|error| panic!("member parse failed: {error}")),
            NodeConfig::default(),
        )
        .unwrap_or_else(|error| panic!("member node open failed: {error}"));
        assert!(matches!(
            node.ingest_control(&control_two)
                .unwrap_or_else(|error| panic!("pending ingest failed: {error}")),
            crate::store::ControlOutcome::Pending { .. }
        ));
        let (store, pending_service) = node.into_parts();
        assert_eq!(
            pending_service
                .route_grant(&scope("alpha"), 2)
                .unwrap_or_else(|| panic!("pending epoch-two route grant missing"))
                .key
                .expose(),
            &old_epoch_two
        );
        let mut node = Node::with_store(member_id, store, pending_service, NodeConfig::default());
        let outcome = node
            .ingest_control(&control_one)
            .unwrap_or_else(|error| panic!("chain-closing ingest failed: {error}"));
        assert!(matches!(
            outcome,
            crate::store::ControlOutcome::Applied { ref activated, .. } if activated.len() == 2
        ));
        let (mut store, active_service) = node.into_parts();
        assert_eq!(
            store
                .scope_epoch(&scope("alpha"))
                .unwrap_or_else(|error| panic!("scope epoch failed: {error}")),
            2
        );
        let fresh_epoch_two = *active_service
            .route_grant(&scope("alpha"), 2)
            .unwrap_or_else(|| panic!("fresh epoch-two route grant missing"))
            .key
            .expose();
        assert_ne!(fresh_epoch_two, old_epoch_two);
        drop(store);
        drop(active_service);

        let reopened = open_reference_node(
            &path,
            ProvisioningBundle::from_bytes(&member_bytes)
                .unwrap_or_else(|error| panic!("member reopen parse failed: {error}")),
            NodeConfig::default(),
        )
        .unwrap_or_else(|error| panic!("member reopen failed: {error}"));
        let (mut reopened_store, reopened_service) = reopened.into_parts();
        assert_eq!(
            reopened_store
                .scope_epoch(&scope("alpha"))
                .unwrap_or_else(|error| panic!("reopened epoch failed: {error}")),
            2
        );
        assert_eq!(
            reopened_service
                .route_grant(&scope("alpha"), 2)
                .unwrap_or_else(|| panic!("replayed epoch-two route grant missing"))
                .key
                .expose(),
            &fresh_epoch_two
        );
        drop(reopened_store);
        drop(reopened_service);
        remove_store_files(&path);
    }

    #[test]
    fn rejected_rekey_tamper_fork_rollback_and_revocation_do_not_install_keys() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x64; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let recipient_bundle = provisioner
            .issue_node(1, &[member_access(vec![0, 1, 2, 3])])
            .unwrap_or_else(|error| panic!("recipient issue failed: {error}"));
        let recipient_id = bundle_identity(&recipient_bundle);
        let recipient_bytes = recipient_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("recipient serialize failed: {error}"));
        let other_bundle = provisioner
            .issue_node(2, &[member_access(vec![0, 1, 2, 3])])
            .unwrap_or_else(|error| panic!("other issue failed: {error}"));
        let other_id = bundle_identity(&other_bundle);
        let authority_bundle = provisioner
            .issue_control_authority(3, &[member_access(vec![0, 1, 2, 3])])
            .unwrap_or_else(|error| panic!("authority issue failed: {error}"));
        let authority_bytes = authority_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("authority serialize failed: {error}"));

        assert!(
            provisioner
                .plan_scope_rekey(
                    scope("alpha"),
                    1,
                    vec![
                        ScopeRekeyRecipient::route_only(recipient_id),
                        ScopeRekeyRecipient::route_only(recipient_id),
                    ],
                )
                .is_err()
        );
        assert!(
            provisioner
                .plan_scope_rekey(
                    scope("alpha"),
                    1,
                    vec![ScopeRekeyRecipient::route_only([0xee; 32])],
                )
                .is_err()
        );
        let plan_one = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                1,
                vec![
                    ScopeRekeyRecipient::member(recipient_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("plan-one recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("plan one failed: {error}"));
        let plan_two = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                2,
                vec![
                    ScopeRekeyRecipient::member(recipient_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("plan-two recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("plan two failed: {error}"));
        let plan_other = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                3,
                vec![
                    ScopeRekeyRecipient::member(other_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("other recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("other plan failed: {error}"));

        let mut authority = service(authority_bundle);
        let control_one = authority
            .seal_scope_rekey_chained(&plan_one, 1, None)
            .unwrap_or_else(|error| panic!("control one failed: {error}"));
        let control_one_id: [u8; 32] = Sha256::digest(&control_one).into();
        let rollback = authority
            .seal_scope_rekey_chained(&plan_one, 2, Some(control_one_id))
            .unwrap_or_else(|error| panic!("rollback fixture failed: {error}"));
        let control_two = authority
            .seal_scope_rekey_chained(&plan_two, 2, Some(control_one_id))
            .unwrap_or_else(|error| panic!("control two failed: {error}"));
        let fork_two = authority
            .seal_scope_rekey_chained(&plan_two, 2, Some(control_one_id))
            .unwrap_or_else(|error| panic!("fork fixture failed: {error}"));
        let control_two_id: [u8; 32] = Sha256::digest(&control_two).into();
        let wrong_recipient = authority
            .seal_scope_rekey_chained(&plan_other, 3, Some(control_two_id))
            .unwrap_or_else(|error| panic!("wrong-recipient control failed: {error}"));

        let mut node = memory_reference_node(
            ProvisioningBundle::from_bytes(&recipient_bytes)
                .unwrap_or_else(|error| panic!("recipient parse failed: {error}")),
        );
        node.ingest_control(&control_one)
            .unwrap_or_else(|error| panic!("control one ingest failed: {error}"));
        let (store, service_after_one) = node.into_parts();
        let accepted_one = *service_after_one
            .route_grant(&scope("alpha"), 1)
            .unwrap_or_else(|| panic!("accepted epoch-one key missing"))
            .key
            .expose();
        let old_two = *service_after_one
            .route_grant(&scope("alpha"), 2)
            .unwrap_or_else(|| panic!("old epoch-two key missing"))
            .key
            .expose();
        let mut node = Node::with_store(
            recipient_id,
            store,
            service_after_one,
            NodeConfig::default(),
        );

        let mut tampered = control_two.clone();
        let last = tampered
            .last_mut()
            .unwrap_or_else(|| panic!("control two was empty"));
        *last ^= 1;
        assert!(node.ingest_control(&tampered).is_err());
        assert!(node.ingest_control(&rollback).is_err());
        let (store, service_after_rejections) = node.into_parts();
        assert_eq!(
            service_after_rejections
                .route_grant(&scope("alpha"), 1)
                .unwrap_or_else(|| panic!("epoch-one key disappeared"))
                .key
                .expose(),
            &accepted_one
        );
        assert_eq!(
            service_after_rejections
                .route_grant(&scope("alpha"), 2)
                .unwrap_or_else(|| panic!("old epoch-two key disappeared"))
                .key
                .expose(),
            &old_two
        );
        let mut node = Node::with_store(
            recipient_id,
            store,
            service_after_rejections,
            NodeConfig::default(),
        );
        node.ingest_control(&control_two)
            .unwrap_or_else(|error| panic!("control two ingest failed: {error}"));
        let (store, service_after_two) = node.into_parts();
        let accepted_two = *service_after_two
            .route_grant(&scope("alpha"), 2)
            .unwrap_or_else(|| panic!("accepted epoch-two key missing"))
            .key
            .expose();
        assert_ne!(accepted_two, old_two);
        let mut node = Node::with_store(
            recipient_id,
            store,
            service_after_two,
            NodeConfig::default(),
        );
        assert!(node.ingest_control(&fork_two).is_err());
        node.ingest_control(&wrong_recipient)
            .unwrap_or_else(|error| panic!("wrong-recipient ingest failed: {error}"));
        let (_, service_after_wrong_recipient) = node.into_parts();
        assert_eq!(
            service_after_wrong_recipient
                .route_grant(&scope("alpha"), 2)
                .unwrap_or_else(|| panic!("accepted epoch-two key changed"))
                .key
                .expose(),
            &accepted_two
        );
        assert!(
            service_after_wrong_recipient
                .route_grant(&scope("alpha"), 3)
                .is_none()
        );

        let mut authority = service(
            ProvisioningBundle::from_bytes(&authority_bytes)
                .unwrap_or_else(|error| panic!("authority parse failed: {error}")),
        );
        let revocation = authority
            .seal_revocation_chained(recipient_id, 1, 1, None)
            .unwrap_or_else(|error| panic!("revocation failed: {error}"));
        let revocation_id: [u8; 32] = Sha256::digest(&revocation).into();
        let rekey_after_revocation = authority
            .seal_scope_rekey_chained(&plan_one, 2, Some(revocation_id))
            .unwrap_or_else(|error| panic!("post-revocation rekey failed: {error}"));
        let mut revoked_node = memory_reference_node(
            ProvisioningBundle::from_bytes(&recipient_bytes)
                .unwrap_or_else(|error| panic!("revoked recipient parse failed: {error}")),
        );
        revoked_node
            .ingest_control(&revocation)
            .unwrap_or_else(|error| panic!("revocation ingest failed: {error}"));
        revoked_node
            .ingest_control(&rekey_after_revocation)
            .unwrap_or_else(|error| panic!("post-revocation ingest failed: {error}"));
        let (_, revoked_service) = revoked_node.into_parts();
        assert!(revoked_service.route_grant(&scope("alpha"), 1).is_none());

        let mut authority_node = memory_reference_node(
            ProvisioningBundle::from_bytes(&authority_bytes)
                .unwrap_or_else(|error| panic!("authority node parse failed: {error}")),
        );
        authority_node
            .publish_revocation(recipient_id, 1)
            .unwrap_or_else(|error| panic!("authority revocation publish failed: {error}"));
        assert!(authority_node.publish_scope_rekey(&plan_one).is_err());
    }

    #[test]
    fn forwarding_age_is_protected_and_bound_to_live_adjacency() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x31; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let sender_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("sender issue failed: {error}"));
        let receiver_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("receiver issue failed: {error}"));
        let other_bundle = provisioner
            .issue_node(3, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("other issue failed: {error}"));
        let mut sender = service(sender_bundle);
        let mut receiver = service(receiver_bundle);
        let mut other = service(other_bundle);
        let envelope_id = [0x91; 32];
        let forwarding = sender
            .seal_forwarding(receiver.identity(), 44, envelope_id, 12_345)
            .unwrap_or_else(|error| panic!("forwarding seal failed: {error}"));
        assert_eq!(
            receiver
                .inspect_forwarding(
                    sender.identity(),
                    receiver.identity(),
                    44,
                    envelope_id,
                    &forwarding,
                )
                .unwrap_or_else(|error| panic!("forwarding inspect failed: {error}")),
            12_345
        );
        assert!(
            receiver
                .inspect_forwarding(
                    other.identity(),
                    receiver.identity(),
                    44,
                    envelope_id,
                    &forwarding,
                )
                .is_err()
        );
        assert!(
            receiver
                .inspect_forwarding(
                    sender.identity(),
                    receiver.identity(),
                    45,
                    envelope_id,
                    &forwarding,
                )
                .is_err()
        );
        let relayed = receiver
            .seal_forwarding(other.identity(), 45, envelope_id, 12_400)
            .unwrap_or_else(|error| panic!("relay forwarding seal failed: {error}"));
        assert_eq!(
            other
                .inspect_forwarding(
                    receiver.identity(),
                    other.identity(),
                    45,
                    envelope_id,
                    &relayed,
                )
                .unwrap_or_else(|error| panic!("relay forwarding inspect failed: {error}")),
            12_400
        );
        assert!(
            other
                .inspect_forwarding(
                    receiver.identity(),
                    other.identity(),
                    45,
                    envelope_id,
                    &forwarding,
                )
                .is_err()
        );
        let mut tampered = forwarding;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            receiver
                .inspect_forwarding(
                    sender.identity(),
                    receiver.identity(),
                    44,
                    envelope_id,
                    &tampered,
                )
                .is_err()
        );
    }

    #[test]
    fn peer_route_commitments_are_opaque_signed_scope_authorization() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x32; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let first = service(
            provisioner
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("first issue failed: {error}")),
        );
        let second = service(
            provisioner
                .issue_node(2, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("second issue failed: {error}")),
        );
        let other_access = ProvisioningAccess::member(scope("bravo"), vec![0], vec![topic("ops")])
            .unwrap_or_else(|error| panic!("other access failed: {error}"));
        let other = service(
            provisioner
                .issue_node(3, &[other_access])
                .unwrap_or_else(|error| panic!("other issue failed: {error}")),
        );
        assert!(first.peer_can_route(
            second.credential.identity,
            &second.credential.route_grant_commitments,
            &scope("alpha"),
            0,
        ));
        assert!(!first.peer_can_route(
            other.credential.identity,
            &other.credential.route_grant_commitments,
            &scope("alpha"),
            0,
        ));
        let encoded = &second.credential.body;
        assert!(
            !encoded
                .windows(scope("alpha").as_str().len())
                .any(|window| window == scope("alpha").as_str().as_bytes())
        );
    }

    #[test]
    fn authority_controls_authenticate_sequence_and_previous_hash() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x33; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let mut authority = service(
            provisioner
                .issue_control_authority(1, &[member_access(vec![0, 1])])
                .unwrap_or_else(|error| panic!("authority issue failed: {error}")),
        );
        let mut member = service(
            provisioner
                .issue_node(2, &[member_access(vec![0, 1])])
                .unwrap_or_else(|error| panic!("member issue failed: {error}")),
        );
        let first = authority
            .seal_revocation_control([0x44; 32], 1, 1, None)
            .unwrap_or_else(|error| panic!("first control failed: {error}"));
        let first_id: [u8; 32] = Sha256::digest(&first).into();
        let second = authority
            .seal_scope_epoch_control(&scope("alpha"), 1, 2, Some(first_id))
            .unwrap_or_else(|error| panic!("second control failed: {error}"));
        assert!(matches!(
            member
                .inspect_control(&second)
                .unwrap_or_else(|error| panic!("second inspect failed: {error}")),
            VerifiedControl::ScopeEpoch(ScopeEpoch {
                control_sequence: 2,
                previous_control: Some(value),
                ..
            }) if value == first_id
        ));
        assert!(
            authority
                .seal_scope_epoch_control(&scope("alpha"), 1, 2, None)
                .is_err()
        );
    }

    #[test]
    fn bundle_and_service_zeroization_are_explicit_and_reference_service_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ReferenceEnvelopeSealer>();

        let mut provisioner = ReferenceProvisioner::from_seed([11u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let mut bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("bundle issue failed: {error}"));
        let mut damaged = bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("bundle serialize failed: {error}"));
        damaged[10] ^= 1;
        assert!(ProvisioningBundle::from_bytes(&damaged).is_err());
        bundle.zeroize();
        assert!(bundle.is_zeroized());
        assert!(bundle.to_bytes().is_err());

        let mut service = service(
            provisioner
                .issue_node(2, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("service issue failed: {error}")),
        );
        service
            .zeroize()
            .unwrap_or_else(|error| panic!("service zeroize failed: {error}"));
        let metadata = header(service.identity(), 0);
        assert!(
            service
                .seal(SealRequest {
                    header: &metadata,
                    payload: b"payload",
                })
                .is_err()
        );
    }

    #[test]
    fn protected_bundle_boundary_round_trips_and_never_falls_back_to_plaintext() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x91; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("bundle issue failed: {error}"));
        let expected_identity = bundle_identity(&bundle);
        let raw = bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("bundle serialize failed: {error}"));

        let mut protection = TestProvisioningProtection::default();
        let mut protected = bundle
            .to_protected_bytes(&mut protection)
            .unwrap_or_else(|error| panic!("bundle protect failed: {error}"));
        assert_eq!(protection.protect_calls, 1);
        assert!(ProvisioningBundle::from_bytes(&protected).is_err());

        let restored = ProvisioningBundle::from_protected_bytes(&protected, &mut protection)
            .unwrap_or_else(|error| panic!("bundle unprotect failed: {error}"));
        assert_eq!(bundle_identity(&restored), expected_identity);
        assert_eq!(protection.unprotect_calls, 1);

        let mut rejecting = TestProvisioningProtection {
            failure: Some(ProvisioningProtectionError::Rejected),
            ..TestProvisioningProtection::default()
        };
        let error = ProvisioningBundle::from_protected_bytes(&raw, &mut rejecting)
            .expect_err("provider rejection must not fall back to plaintext");
        assert_eq!(
            error,
            ProtectedProvisioningError::Protection(ProvisioningProtectionError::Rejected)
        );
        assert_eq!(rejecting.unprotect_calls, 0);
        protected.zeroize();
    }

    #[test]
    fn protected_bundle_boundary_checks_outer_bounds_and_inner_canonical_integrity() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x92; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("bundle issue failed: {error}"));
        let mut protection = TestProvisioningProtection::default();
        let mut protected = bundle
            .to_protected_bytes(&mut protection)
            .unwrap_or_else(|error| panic!("bundle protect failed: {error}"));

        protected[TEST_PROTECTION_PREFIX.len() + 10] ^= 1;
        let error = ProvisioningBundle::from_protected_bytes(&protected, &mut protection)
            .expect_err("tampered inner bundle must fail checksum validation");
        assert_eq!(error, ProtectedProvisioningError::InvalidBundle);

        let calls = protection.unprotect_calls;
        let oversized = vec![0; MAX_PROTECTED_PROVISIONING_BYTES + 1];
        let error = ProvisioningBundle::from_protected_bytes(&oversized, &mut protection)
            .expect_err("oversized outer artifact must fail before provider use");
        assert_eq!(
            error,
            ProtectedProvisioningError::Protection(ProvisioningProtectionError::TooLarge)
        );
        assert_eq!(protection.unprotect_calls, calls);

        let mut zeroized = bundle;
        zeroized.zeroize();
        let calls = protection.protect_calls;
        assert!(zeroized.to_protected_bytes(&mut protection).is_err());
        assert_eq!(protection.protect_calls, calls);
        protected.zeroize();
    }

    #[test]
    fn maximum_v3_bundle_matches_the_public_plaintext_bound() {
        fn maximum_name(prefix: char, index: usize) -> String {
            let value = format!("{prefix}{index:03}{}", "x".repeat(124));
            assert_eq!(value.len(), 128);
            value
        }

        let mut provisioner = ReferenceProvisioner::from_seed([0x95; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let mut bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("bundle issue failed: {error}"));
        bundle.control_route_key = Some(Secret32::new([0x41; 32]));
        bundle.route_grants = (0..MAX_GRANTS)
            .map(|index| RouteGrant {
                scope: scope(&maximum_name('s', index)),
                epoch: 1,
                key: Secret32::new([0x42; 32]),
            })
            .collect();
        let maximum_scope = scope(&maximum_name('c', 0));
        bundle.content_grants = (0..MAX_GRANTS)
            .map(|index| ContentGrant {
                scope: maximum_scope.clone(),
                topic: topic(&maximum_name('t', index)),
                epoch: 1,
                key: Secret32::new([0x43; 32]),
            })
            .collect();

        let encoded = UnprotectedProvisioning::new(
            bundle
                .to_bytes()
                .unwrap_or_else(|error| panic!("maximum bundle encode failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("maximum bundle ownership failed: {error}"));
        assert_eq!(encoded.len(), MAX_UNPROTECTED_PROVISIONING_BYTES);
        ProvisioningBundle::from_bytes(encoded.expose())
            .unwrap_or_else(|error| panic!("maximum bundle parse failed: {error}"));
    }

    #[test]
    fn handshake_flights_keep_stable_profile_and_negotiate_semantic_v2() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x31; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("responder issue failed: {error}"));

        let mut endpoint = SessionEndpoint::open(initiator_bundle)
            .unwrap_or_else(|error| panic!("initiator endpoint failed: {error}"));
        let (_handshake, hello) = InitiatorHandshake::start(
            &mut endpoint.provider,
            vec![PROTOCOL_VERSION + 1, PROTOCOL_VERSION],
            vec![0x0202, SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let mission_proof = create_mission_proof(&endpoint, &hello)
            .unwrap_or_else(|error| panic!("mission proof failed: {error}"));
        let flight_one = encode_client_flight(&hello, &mission_proof)
            .unwrap_or_else(|error| panic!("client flight encoding failed: {error}"));

        assert_eq!(&flight_one[..8], HANDSHAKE_MAGIC);
        assert_eq!(
            u16::from_be_bytes(
                flight_one[8..10]
                    .try_into()
                    .unwrap_or_else(|_| panic!("framing version bytes"))
            ),
            HANDSHAKE_FRAMING_VERSION
        );
        assert_eq!(
            u16::from_be_bytes(
                flight_one[10..12]
                    .try_into()
                    .unwrap_or_else(|_| panic!("profile bytes"))
            ),
            HANDSHAKE_PROFILE_ID
        );
        assert_eq!(&flight_one[12..14], &[1, 0]);
        assert_eq!(&flight_one[14..16], &2u16.to_be_bytes());
        assert_eq!(
            &flight_one[16..20],
            &[PROTOCOL_VERSION + 1, PROTOCOL_VERSION]
                .into_iter()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(&flight_one[20..22], &2u16.to_be_bytes());
        assert_eq!(
            &flight_one[22..26],
            &[0x0202u16, SUITE_ID]
                .into_iter()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>()
        );
        let (decoded, decoded_proof) = decode_client_flight(&flight_one)
            .unwrap_or_else(|error| panic!("client flight decoding failed: {error}"));
        assert_eq!(decoded, hello);
        assert_eq!(decoded_proof, mission_proof);
        let mut reordered_versions = flight_one.clone();
        reordered_versions[16..18].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        reordered_versions[18..20].copy_from_slice(&(PROTOCOL_VERSION + 1).to_be_bytes());
        assert!(decode_client_flight(&reordered_versions).is_err());

        let responder = ReferenceSessionResponder::open(responder_bundle)
            .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (_pending, flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("future-compatible client flight failed: {error}"));
        assert_eq!(&flight_two[..14], &handshake_prefix(2));
        assert_eq!(&flight_two[14..16], &SEMANTIC_PROTOCOL_V2.to_be_bytes());
        assert_eq!(&flight_two[16..18], &SUITE_ID.to_be_bytes());
        let selected = decode_server_flight(&flight_two)
            .unwrap_or_else(|error| panic!("server flight decoding failed: {error}"));
        assert_eq!(selected.selected_version, SEMANTIC_PROTOCOL_V2);
        assert_eq!(selected.selected_suite, SUITE_ID);
        assert_eq!(
            encode_server_flight(&selected)
                .unwrap_or_else(|error| panic!("server flight re-encoding failed: {error}")),
            flight_two
        );
    }

    #[test]
    fn reference_handshake_falls_back_for_a_v1_only_peer() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x39; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("responder issue failed: {error}"));
        let (_initiator, first_flight) = ReferenceSessionInitiator::start_with_semantic_versions(
            initiator_bundle,
            vec![SEMANTIC_PROTOCOL_V1],
        )
        .unwrap_or_else(|error| panic!("v1 initiator start failed: {error}"));
        let (hello, _) = decode_client_flight(&first_flight)
            .unwrap_or_else(|error| panic!("v1 client flight failed: {error}"));
        assert_eq!(hello.supported_versions, vec![SEMANTIC_PROTOCOL_V1]);

        let responder = ReferenceSessionResponder::open(responder_bundle)
            .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (_pending, second_flight) = responder
            .receive_client(&first_flight)
            .unwrap_or_else(|error| panic!("v1 client flight rejected: {error}"));
        let selected = decode_server_flight(&second_flight)
            .unwrap_or_else(|error| panic!("v1 server flight failed: {error}"));
        assert_eq!(selected.selected_version, SEMANTIC_PROTOCOL_V1);
    }

    #[test]
    fn reference_handshake_selects_v4_for_a_v4_only_offer() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x3a; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("responder issue failed: {error}"));
        let (initiator, responder) = complete_sessions_with_versions(
            initiator_bundle,
            responder_bundle,
            vec![
                SEMANTIC_PROTOCOL_V4,
                SEMANTIC_PROTOCOL_V3,
                SEMANTIC_PROTOCOL_V2,
                SEMANTIC_PROTOCOL_V1,
            ],
        );
        assert_eq!(initiator.semantic_version(), SEMANTIC_PROTOCOL_V4);
        assert_eq!(responder.semantic_version(), SEMANTIC_PROTOCOL_V4);
    }

    #[test]
    fn semantic_registry_negotiates_each_supported_version_and_rejects_neighbors() {
        for version in [
            SEMANTIC_PROTOCOL_V1,
            SEMANTIC_PROTOCOL_V2,
            SEMANTIC_PROTOCOL_V3,
            SEMANTIC_PROTOCOL_V4,
            SEMANTIC_PROTOCOL_V5,
            SEMANTIC_PROTOCOL_V6,
            SEMANTIC_PROTOCOL_V7,
            SEMANTIC_PROTOCOL_V8,
            SEMANTIC_PROTOCOL_V9,
        ] {
            let mut provisioner = ReferenceProvisioner::from_seed([0x40 + version as u8; 32])
                .unwrap_or_else(|error| panic!("v{version} provisioner failed: {error}"));
            let initiator_bundle = provisioner
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("v{version} initiator issue failed: {error}"));
            let responder_bundle = provisioner
                .issue_node(2, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("v{version} responder issue failed: {error}"));
            let (initiator, responder) =
                complete_sessions_with_versions(initiator_bundle, responder_bundle, vec![version]);
            assert_eq!(initiator.semantic_version(), version);
            assert_eq!(responder.semantic_version(), version);
        }

        for unsupported in [0, SEMANTIC_PROTOCOL_V9 + 1] {
            let mut provisioner = ReferenceProvisioner::from_seed([0x50 + unsupported as u8; 32])
                .unwrap_or_else(|error| panic!("v{unsupported} provisioner failed: {error}"));
            let initiator_bundle = provisioner
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("v{unsupported} initiator issue failed: {error}"));
            assert!(
                ReferenceSessionInitiator::start_with_semantic_versions(
                    initiator_bundle,
                    vec![unsupported],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn mission_proof_rejects_version_and_suite_offer_stripping() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x32; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bytes = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("responder fixture failed: {error}"));
        let mut endpoint = SessionEndpoint::open(initiator_bundle)
            .unwrap_or_else(|error| panic!("initiator endpoint failed: {error}"));
        let (_handshake, hello) = InitiatorHandshake::start(
            &mut endpoint.provider,
            vec![PROTOCOL_VERSION + 1, PROTOCOL_VERSION],
            vec![0x0202, SUITE_ID],
        )
        .unwrap_or_else(|error| panic!("client start failed: {error}"));
        let mission_proof = create_mission_proof(&endpoint, &hello)
            .unwrap_or_else(|error| panic!("mission proof failed: {error}"));

        let mut stripped_version = hello.clone();
        stripped_version.supported_versions.remove(0);
        let stripped_version = encode_client_flight(&stripped_version, &mission_proof)
            .unwrap_or_else(|error| panic!("stripped version encoding failed: {error}"));
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        assert!(responder.receive_client(&stripped_version).is_err());

        let mut stripped_suite = hello;
        stripped_suite.offered_suites.remove(0);
        let stripped_suite = encode_client_flight(&stripped_suite, &mission_proof)
            .unwrap_or_else(|error| panic!("stripped suite encoding failed: {error}"));
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        assert!(responder.receive_client(&stripped_suite).is_err());
    }

    #[test]
    fn mission_proof_rejects_stripping_v9_from_the_default_offer() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x74; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("responder issue failed: {error}"));
        let (_initiator, first_flight) = ReferenceSessionInitiator::start(initiator_bundle)
            .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let (mut hello, mission_proof) = decode_client_flight(&first_flight)
            .unwrap_or_else(|error| panic!("client flight decode failed: {error}"));
        assert_eq!(
            hello.supported_versions,
            vec![
                SEMANTIC_PROTOCOL_V9,
                SEMANTIC_PROTOCOL_V8,
                SEMANTIC_PROTOCOL_V7,
                SEMANTIC_PROTOCOL_V6,
                SEMANTIC_PROTOCOL_V5,
                SEMANTIC_PROTOCOL_V4,
                SEMANTIC_PROTOCOL_V3,
                SEMANTIC_PROTOCOL_V2,
                SEMANTIC_PROTOCOL_V1,
            ]
        );
        hello.supported_versions.remove(0);
        assert_eq!(
            hello.supported_versions,
            vec![
                SEMANTIC_PROTOCOL_V8,
                SEMANTIC_PROTOCOL_V7,
                SEMANTIC_PROTOCOL_V6,
                SEMANTIC_PROTOCOL_V5,
                SEMANTIC_PROTOCOL_V4,
                SEMANTIC_PROTOCOL_V3,
                SEMANTIC_PROTOCOL_V2,
                SEMANTIC_PROTOCOL_V1,
            ]
        );
        let stripped = encode_client_flight(&hello, &mission_proof)
            .unwrap_or_else(|error| panic!("stripped flight encoding failed: {error}"));
        let responder = ReferenceSessionResponder::open(responder_bundle)
            .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        assert!(responder.receive_client(&stripped).is_err());
    }

    #[test]
    fn public_four_flight_session_authenticates_peers_and_rejects_frame_replay() {
        let mut provisioner = ReferenceProvisioner::from_seed([12u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("responder issue failed: {error}"));

        let (initiator, flight_one) = ReferenceSessionInitiator::start(initiator_bundle)
            .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let (default_hello, _) = decode_client_flight(&flight_one)
            .unwrap_or_else(|error| panic!("default client flight failed: {error}"));
        assert_eq!(
            default_hello.supported_versions,
            vec![
                SEMANTIC_PROTOCOL_V9,
                SEMANTIC_PROTOCOL_V8,
                SEMANTIC_PROTOCOL_V7,
                SEMANTIC_PROTOCOL_V6,
                SEMANTIC_PROTOCOL_V5,
                SEMANTIC_PROTOCOL_V4,
                SEMANTIC_PROTOCOL_V3,
                SEMANTIC_PROTOCOL_V2,
                SEMANTIC_PROTOCOL_V1,
            ]
        );
        let initiator_id = initiator.endpoint.credential.identity;
        let responder = ReferenceSessionResponder::open(responder_bundle)
            .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let responder_id = responder.endpoint.credential.identity;
        let (responder_pending, flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let (initiator_pending, flight_three) = initiator
            .receive_server(&flight_two)
            .unwrap_or_else(|error| panic!("server flight failed: {error}"));
        let (mut responder_session, flight_four) = responder_pending
            .receive_client_auth(&flight_three)
            .unwrap_or_else(|error| panic!("client auth failed: {error}"));
        let mut initiator_session = initiator_pending
            .receive_finished(&flight_four)
            .unwrap_or_else(|error| panic!("server finished failed: {error}"));
        assert_eq!(initiator_session.peer_identity(), responder_id);
        assert_eq!(responder_session.peer_identity(), initiator_id);
        assert_eq!(initiator_session.semantic_version(), SEMANTIC_PROTOCOL_V9);
        assert_eq!(responder_session.semantic_version(), SEMANTIC_PROTOCOL_V9);

        let frame = initiator_session
            .seal_frame(b"opaque replication frame")
            .unwrap_or_else(|error| panic!("frame seal failed: {error}"));
        assert_eq!(
            frame.len(),
            b"opaque replication frame".len() + REFERENCE_SESSION_FRAME_OVERHEAD_BYTES
        );
        assert_eq!(
            responder_session
                .open_frame(&frame)
                .unwrap_or_else(|error| panic!("frame open failed: {error}")),
            b"opaque replication frame"
        );
        assert!(responder_session.open_frame(&frame).is_err());

        let reverse = responder_session
            .seal_frame(b"receipt")
            .unwrap_or_else(|error| panic!("reverse seal failed: {error}"));
        assert_eq!(
            initiator_session
                .open_frame(&reverse)
                .unwrap_or_else(|error| panic!("reverse open failed: {error}")),
            b"receipt"
        );
        let mut tampered = reverse;
        let last = tampered
            .len()
            .checked_sub(1)
            .unwrap_or_else(|| panic!("test frame was empty"));
        tampered[last] ^= 1;
        assert!(initiator_session.open_frame(&tampered).is_err());
    }

    #[test]
    fn v3_custody_wrapper_is_nested_replay_safe_and_context_bound() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x73; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bytes = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("initiator fixture failed: {error}"));
        let responder_bytes = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("responder fixture failed: {error}"));
        let pair = || {
            complete_sessions_with_versions(
                ProvisioningBundle::from_bytes(&initiator_bytes)
                    .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
                ProvisioningBundle::from_bytes(&responder_bytes)
                    .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
                vec![
                    SEMANTIC_PROTOCOL_V3,
                    SEMANTIC_PROTOCOL_V2,
                    SEMANTIC_PROTOCOL_V1,
                ],
            )
        };
        let (mut sender, mut receiver) = pair();
        let (_other_sender, mut other_receiver) = pair();
        let transfer = crate::custody::CustodyTransferClaims::new(
            crate::custody::CustodyTransferId::from_exact_hash([0x51; 32]),
            4_096,
            Some(10_000),
            Priority::Immediate,
        )
        .unwrap_or_else(|error| panic!("transfer claims failed: {error}"));
        let claims = CustodyClaims::new(
            transfer,
            900,
            17,
            crate::custody::CustodyHop::new(
                2_000,
                crate::custody::CustodySample {
                    clock_id: [0x61; 16],
                    tick_ms: 5_000,
                },
                25,
            )
            .unwrap_or_else(|error| panic!("hop failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("custody claims failed: {error}"));
        let expected = CustodyExpectation::new(transfer, 900);

        // The selected node nests the small custody record in an ordinary
        // mission frame.  This creates inner sequence n followed by outer n+1;
        // opening n+1 before n must remain valid exactly once.
        let inner = sender
            .seal_custody_wrapper(&claims)
            .unwrap_or_else(|error| panic!("custody seal failed: {error}"));
        assert_eq!(inner.len(), 202);
        assert!(inner.len() <= MAX_CUSTODY_WRAPPER_BYTES);
        assert!(
            receiver
                .open_custody_wrapper(&vec![0; MAX_CUSTODY_WRAPPER_BYTES + 1], expected)
                .is_err()
        );
        let outer = sender
            .seal_frame(&inner)
            .unwrap_or_else(|error| panic!("outer seal failed: {error}"));
        let opened_inner = receiver
            .open_frame(&outer)
            .unwrap_or_else(|error| panic!("outer open failed: {error}"));
        assert_eq!(opened_inner, inner);
        let verified = receiver
            .open_custody_wrapper(&opened_inner, expected)
            .unwrap_or_else(|error| panic!("custody open failed: {error}"));
        assert_eq!(verified.transfer_id(), transfer.transfer_id());
        assert_eq!(verified.exact_len(), transfer.exact_len());
        assert_eq!(verified.forwarding_age_ms(), 2_025);
        assert!(receiver.open_custody_wrapper(&inner, expected).is_err());

        let later = sender
            .seal_frame(b"later ordinary traffic")
            .unwrap_or_else(|error| panic!("later seal failed: {error}"));
        assert_eq!(
            receiver
                .open_frame(&later)
                .unwrap_or_else(|error| panic!("later open failed: {error}")),
            b"later ordinary traffic"
        );

        let authentic_after_tamper = sender
            .seal_custody_wrapper(&claims)
            .unwrap_or_else(|error| panic!("second custody seal failed: {error}"));
        let mut tampered = authentic_after_tamper.clone();
        *tampered
            .last_mut()
            .unwrap_or_else(|| panic!("custody wrapper was empty")) ^= 1;
        assert!(receiver.open_custody_wrapper(&tampered, expected).is_err());
        assert_eq!(
            receiver
                .open_custody_wrapper(&authentic_after_tamper, expected)
                .unwrap_or_else(|error| panic!("authentic retry failed: {error}"))
                .forwarding_age_ms(),
            2_025
        );

        let cross_session = sender
            .seal_custody_wrapper(&claims)
            .unwrap_or_else(|error| panic!("cross-session fixture failed: {error}"));
        assert!(
            other_receiver
                .open_custody_wrapper(&cross_session, expected)
                .is_err()
        );
        assert_eq!(
            receiver
                .open_custody_wrapper(&cross_session, expected)
                .unwrap_or_else(|error| panic!("original session rejected claim: {error}"))
                .forwarding_age_ms(),
            2_025
        );

        let wrong_source = crate::custody::CustodyTransferClaims::new(
            transfer.transfer_id(),
            transfer.exact_len(),
            Some(9_999),
            transfer.source_priority(),
        )
        .unwrap_or_else(|error| panic!("wrong source fixture failed: {error}"));
        let wrong_context = sender
            .seal_custody_wrapper(&claims)
            .unwrap_or_else(|error| panic!("context fixture failed: {error}"));
        assert!(
            receiver
                .open_custody_wrapper(
                    &wrong_context,
                    CustodyExpectation::new(wrong_source, expected.exchange_id()),
                )
                .is_err()
        );
    }

    #[test]
    fn v8_blob_custody_requires_the_authenticated_negotiated_blob_profile() {
        // Mutations caught: accepting a caller-supplied transfer-profile
        // digest, treating a Legacy-selected Blob lane as profile 4, or
        // deriving negotiation state from an unauthenticated offer.
        let mut provisioner = ReferenceProvisioner::from_seed([0x84; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bytes = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("initiator fixture failed: {error}"));
        let responder_bytes = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("responder fixture failed: {error}"));
        let pair = || {
            complete_sessions_with_versions(
                ProvisioningBundle::from_bytes(&initiator_bytes)
                    .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
                ProvisioningBundle::from_bytes(&responder_bytes)
                    .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
                vec![SEMANTIC_PROTOCOL_V8],
            )
        };

        let authenticate_offers =
            |initiator: &mut ReferenceAuthenticatedSession,
             responder: &mut ReferenceAuthenticatedSession,
             initiator_offer: &crate::TransferProfileOfferV1,
             responder_offer: &crate::TransferProfileOfferV1| {
                let request = initiator
                    .seal_transfer_profile_offer(initiator_offer)
                    .unwrap_or_else(|error| panic!("offer request seal failed: {error}"));
                assert_eq!(
                    responder
                        .open_transfer_profile_offer(&request)
                        .unwrap_or_else(|error| panic!("offer request open failed: {error}")),
                    *initiator_offer
                );
                let response = responder
                    .seal_transfer_profile_offer(responder_offer)
                    .unwrap_or_else(|error| panic!("offer response seal failed: {error}"));
                assert_eq!(
                    initiator
                        .open_transfer_profile_offer(&response)
                        .unwrap_or_else(|error| panic!("offer response open failed: {error}")),
                    *responder_offer
                );
            };

        let current = crate::TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V8)
            .expect("semantic-v8 offer");
        let legacy = crate::TransferProfileOfferV1::legacy_only();
        let direction = crate::BlobCustodyDirectionV1::ToSessionResponder;
        let mut literal = literal_blob_custody_claim();

        let (mut legacy_sender, mut legacy_receiver) = pair();
        let request = legacy_sender
            .seal_transfer_profile_offer(&current)
            .expect("stream offer request");
        assert_eq!(
            legacy_receiver
                .open_transfer_profile_offer(&request)
                .expect("authenticated stream offer"),
            current
        );
        assert!(
            legacy_receiver
                .seal_transfer_profile_offer(&legacy)
                .is_err(),
            "a legacy-only Blob offer must fail before any profile-4 record can be minted"
        );

        let (mut sender, mut receiver) = pair();
        authenticate_offers(&mut sender, &mut receiver, &current, &current);
        literal[14..46].copy_from_slice(&sender.session_id);
        literal[54] = direction as u8;
        let claim = crate::BlobCustodyClaimV1::decode(&literal).expect("session-bound claim");
        let substituted_context = blob_custody_lane_record_context([0xa5; 32], direction);
        let substituted = sender
            .seal_frame_with_context(&claim.encode(), &substituted_context)
            .expect("caller-selected digest frame");
        assert!(
            receiver
                .open_blob_custody_frame(direction, &substituted)
                .is_err(),
            "a caller-selected profile digest must not mint Blob authority"
        );
        let negotiated = negotiate_transfer_profiles_for_semantic_version(
            SEMANTIC_PROTOCOL_V8,
            &current,
            &current,
        )
        .expect("BlobRangesStreamV1-selected semantic-v8 profiles");
        let digest = transfer_profile_digest(&current, &current, &negotiated);
        let mut substituted_profile = blob_custody_lane_record_context(digest, direction);
        let profile_offset = substituted_profile.len() - 3;
        substituted_profile[profile_offset..profile_offset + 2]
            .copy_from_slice(&(TransferProfileId::LegacyV6 as u16).to_be_bytes());
        let substituted = sender
            .seal_frame_with_context(&claim.encode(), &substituted_profile)
            .expect("caller-selected profile frame");
        assert!(
            receiver
                .open_blob_custody_frame(direction, &substituted)
                .is_err(),
            "a caller-selected profile ID must not mint Blob authority"
        );
        let frame = sender
            .seal_blob_custody_frame(direction, &claim)
            .unwrap_or_else(|error| panic!("Blob custody seal failed: {error}"));
        let (opened, authority) = receiver
            .open_blob_custody_frame(direction, &frame)
            .unwrap_or_else(|error| panic!("Blob custody open failed: {error}"));
        assert_eq!(opened, claim);
        assert_eq!(authority.claim_digest(), claim.digest());
        assert!(
            receiver.open_blob_custody_frame(direction, &frame).is_err(),
            "one protected claim record must mint authority at most once"
        );
        assert_eq!(
            sender.negotiated_transfer_profile(crate::TransferLaneId::Blob),
            Some(crate::TransferProfileId::BlobRangesStreamV1)
        );

        // Mutation caught: protecting only an adjacent claim record, accepting
        // a claim that differs from the complete authenticated source frame,
        // or replaying that frame could mint reusable runtime authority.
        let mut source_plaintext = b"canonical source-bearing prefix".to_vec();
        source_plaintext.extend_from_slice(&[1, 0, 208]);
        source_plaintext.extend_from_slice(&claim.encode());
        let (mut source_sender, mut source_receiver) = pair();
        authenticate_offers(&mut source_sender, &mut source_receiver, &current, &current);
        let mut source_claim_bytes = claim.encode();
        source_claim_bytes[14..46].copy_from_slice(&source_sender.session_id);
        let source_claim = crate::BlobCustodyClaimV1::decode(&source_claim_bytes)
            .expect("source-frame session claim");
        source_plaintext.truncate(b"canonical source-bearing prefix".len());
        source_plaintext.extend_from_slice(&[1, 0, 208]);
        source_plaintext.extend_from_slice(&source_claim.encode());
        let source_frame = source_sender
            .seal_blob_source_frame(direction, Some(&source_claim), &source_plaintext)
            .expect("protect complete Blob source frame");
        let (opened_source, opened_finite) = source_receiver
            .open_blob_source_frame(direction, &source_frame)
            .expect("open complete Blob source frame");
        let (opened_claim, source_authority) =
            opened_finite.expect("finite source authority is present");
        assert_eq!(opened_source, source_plaintext);
        assert_eq!(opened_claim, source_claim);
        assert_eq!(source_authority.claim_digest(), source_claim.digest());
        assert!(
            source_receiver
                .open_blob_source_frame(direction, &source_frame)
                .is_err(),
            "the complete source record must remain replay-checked"
        );
        let mut mismatched_plaintext = source_plaintext.clone();
        *mismatched_plaintext.last_mut().expect("claim tail") ^= 1;
        assert!(
            source_sender
                .seal_blob_source_frame(direction, Some(&source_claim), &mismatched_plaintext,)
                .is_err(),
            "the protected source tail must equal the supplied canonical claim"
        );

        // Mutation caught: letting Store authorization accept caller-selected
        // session, profile, exchange, direction, or finalization fields would
        // mint a claim without exact authenticated outbound contact context.
        let outbound = source_sender
            .mint_blob_custody_send_context(direction, 73, 41)
            .expect("mint exact outbound Blob custody context");
        assert_eq!(outbound.semantic_version(), SEMANTIC_PROTOCOL_V8);
        assert_eq!(
            outbound.profile_id(),
            TransferProfileId::BlobRangesStreamV1 as u16
        );
        assert_eq!(outbound.session_transcript(), source_sender.session_id());
        assert_eq!(outbound.exchange_id(), 73);
        assert_eq!(outbound.direction(), direction);
        assert_eq!(outbound.finalization_charge_ms(), 41);
        assert!(
            source_sender
                .mint_blob_custody_send_context(
                    crate::BlobCustodyDirectionV1::ToSessionInitiator,
                    73,
                    41,
                )
                .is_err(),
            "the authenticated sender role fixes the outbound direction"
        );
    }

    #[test]
    fn blob_custody_v2_requires_v9_profile_five_attempt_context() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x85; 32]).unwrap();
        let initiator = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap();
        let responder = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap();
        let (mut sender, mut receiver) =
            complete_sessions_with_versions(initiator, responder, vec![SEMANTIC_PROTOCOL_V9]);
        let offer =
            crate::TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V9).unwrap();
        let request = sender.seal_transfer_profile_offer(&offer).unwrap();
        receiver.open_transfer_profile_offer(&request).unwrap();
        let response = receiver.seal_transfer_profile_offer(&offer).unwrap();
        sender.open_transfer_profile_offer(&response).unwrap();
        let negotiated =
            negotiate_transfer_profiles_for_semantic_version(SEMANTIC_PROTOCOL_V9, &offer, &offer)
                .unwrap();
        let digest = transfer_profile_digest(&offer, &offer, &negotiated);
        let direction = BlobCustodyDirectionV1::ToSessionResponder;
        let nonce = [0x91; 32];
        let outbound = sender
            .mint_blob_custody_send_context_v2(direction, 73, nonce, 41)
            .expect("mint v2 send capability");
        assert_eq!(outbound.session_transcript(), sender.session_id());
        assert_eq!(outbound.context().semantic_version(), 9);
        assert_eq!(outbound.context().profile(), 5);
        assert_eq!(outbound.context().lane(), 4);
        assert_eq!(outbound.context().attempt_nonce(), nonce);
        assert_eq!(outbound.context().transfer_profile_digest(), digest);

        let mut bytes = literal_blob_custody_claim_v2();
        bytes[14..46].copy_from_slice(&sender.session_id);
        bytes[54] = direction as u8;
        let claim = crate::BlobCustodyClaimV2::decode(&bytes).unwrap();
        let frame = sender
            .seal_blob_custody_frame_v2(digest, direction, nonce, &claim)
            .expect("seal v2 claim");

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(
            receiver
                .open_blob_custody_frame_v2(wrong_digest, direction, nonce, &frame,)
                .is_err()
        );
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert!(
            receiver
                .open_blob_custody_frame_v2(digest, direction, wrong_nonce, &frame,)
                .is_err()
        );
        let (opened, contact) = receiver
            .open_blob_custody_frame_v2(digest, direction, nonce, &frame)
            .expect("open exact v2 claim");
        assert_eq!(opened, claim);
        assert_eq!(contact.claim_digest(), claim.digest());
        assert_eq!(contact.context().attempt_nonce(), nonce);
        assert!(
            receiver
                .open_blob_custody_frame_v2(digest, direction, nonce, &frame,)
                .is_err()
        );
    }

    fn literal_blob_custody_claim_v2() -> [u8; crate::BLOB_CUSTODY_CLAIM_V2_BYTES] {
        const HEX: &str = "41535452424c30390002000900051111111111111111111111111111111111111111111111111111111111111111000000000000000001222222222222222222222222222222222222222222222222222222222222222200000000000000013333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000100000000000000005555555555555555555555555555555500000000000000000000000000000000";
        let mut output = [0u8; crate::BLOB_CUSTODY_CLAIM_V2_BYTES];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&HEX[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    fn literal_blob_custody_claim() -> [u8; crate::BLOB_CUSTODY_CLAIM_V1_BYTES] {
        const HEX: &str = "41535452424c30380001000800041111111111111111111111111111111111111111111111111111111111111111000000000000000001222222222222222222222222222222222222222222222222222222222222222200000000000000013333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000100000000000000005555555555555555555555555555555500000000000000000000000000000000";
        let mut output = [0u8; crate::BLOB_CUSTODY_CLAIM_V1_BYTES];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&HEX[index * 2..index * 2 + 2], 16)
                .expect("literal hexadecimal byte");
        }
        output
    }

    #[test]
    fn v1_v2_keep_durable_frames_and_refuse_finite_custody_wrappers() {
        for version in [SEMANTIC_PROTOCOL_V1, SEMANTIC_PROTOCOL_V2] {
            let mut provisioner = ReferenceProvisioner::from_seed([version as u8; 32])
                .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
            let initiator_bundle = provisioner
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
            let responder_bundle = provisioner
                .issue_node(2, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("responder issue failed: {error}"));
            let (mut sender, mut receiver) =
                complete_sessions_with_versions(initiator_bundle, responder_bundle, vec![version]);
            assert_eq!(sender.semantic_version(), version);
            assert_eq!(receiver.semantic_version(), version);
            let durable = sender
                .seal_frame(b"durable source bytes")
                .unwrap_or_else(|error| panic!("v{version} durable seal failed: {error}"));
            assert_eq!(
                receiver
                    .open_frame(&durable)
                    .unwrap_or_else(|error| panic!("v{version} durable open failed: {error}")),
                b"durable source bytes"
            );
            let transfer = crate::custody::CustodyTransferClaims::new(
                crate::custody::CustodyTransferId::from_exact_hash([version as u8; 32]),
                128,
                Some(1_000),
                Priority::Flash,
            )
            .unwrap_or_else(|error| panic!("transfer fixture failed: {error}"));
            let finite = CustodyClaims::new(
                transfer,
                1,
                1,
                crate::custody::CustodyHop::new(
                    0,
                    crate::custody::CustodySample {
                        clock_id: [version as u8; 16],
                        tick_ms: 1,
                    },
                    0,
                )
                .unwrap_or_else(|error| panic!("finite hop failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("finite claims failed: {error}"));
            assert!(sender.seal_custody_wrapper(&finite).is_err());
        }
    }

    #[test]
    fn public_session_flights_hide_identity_and_require_anonymous_mission_proof() {
        let mut provisioner = ReferenceProvisioner::from_seed([13u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bytes = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("initiator fixture failed: {error}"));
        let responder_bytes = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("responder fixture failed: {error}"));
        let initiator_canaries = session_privacy_canaries(
            &ProvisioningBundle::from_bytes(&initiator_bytes)
                .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("initiator canaries failed: {error}"));
        let responder_canaries = session_privacy_canaries(
            &ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder canaries failed: {error}"));

        let (initiator, flight_one) = ReferenceSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bytes)
                .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        assert_private_canaries_absent(&flight_one, &initiator_canaries);
        assert_private_canaries_absent(&flight_one, &responder_canaries);

        let mut damaged_proof = flight_one.clone();
        let proof_byte = damaged_proof
            .last_mut()
            .unwrap_or_else(|| panic!("client flight was empty"));
        *proof_byte ^= 1;
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        assert!(responder.receive_client(&damaged_proof).is_err());

        let mut outsider = ReferenceProvisioner::from_seed([0x91; 32])
            .unwrap_or_else(|error| panic!("outsider provisioner failed: {error}"));
        let outsider = ReferenceSessionResponder::open(
            outsider
                .issue_node(1, &[member_access(vec![0])])
                .unwrap_or_else(|error| panic!("outsider issue failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("outsider open failed: {error}"));
        assert!(outsider.receive_client(&flight_one).is_err());

        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (responder_pending, flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let replay_responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("replay responder open failed: {error}"));
        let (_unused, replay_flight_two) = replay_responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("replayed client flight failed: {error}"));
        assert_ne!(flight_two, replay_flight_two);
        assert_private_canaries_absent(&flight_two, &initiator_canaries);
        assert_private_canaries_absent(&flight_two, &responder_canaries);
        assert_private_canaries_absent(&replay_flight_two, &responder_canaries);

        let (initiator_pending, flight_three) = initiator
            .receive_server(&flight_two)
            .unwrap_or_else(|error| panic!("server flight failed: {error}"));
        assert_private_canaries_absent(&flight_three, &initiator_canaries);
        assert_private_canaries_absent(&flight_three, &responder_canaries);
        let (_responder_session, flight_four) = responder_pending
            .receive_client_auth(&flight_three)
            .unwrap_or_else(|error| panic!("client auth failed: {error}"));
        assert_private_canaries_absent(&flight_four, &initiator_canaries);
        assert_private_canaries_absent(&flight_four, &responder_canaries);
        initiator_pending
            .receive_finished(&flight_four)
            .unwrap_or_else(|error| panic!("server finished failed: {error}"));

        let mut missing_key = provisioner
            .issue_node(3, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("missing-key issue failed: {error}"));
        missing_key.control_route_key = None;
        assert!(ReferenceSessionInitiator::start(missing_key).is_err());
        let mut missing_key = provisioner
            .issue_node(4, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("missing-key issue failed: {error}"));
        missing_key.control_route_key = None;
        assert!(ReferenceSessionResponder::open(missing_key).is_err());
    }

    #[test]
    fn public_session_rejects_downgrade_and_protected_auth_tamper() {
        let mut provisioner = ReferenceProvisioner::from_seed([14u8; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bytes = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("initiator fixture failed: {error}"));
        let responder_bytes = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .and_then(|bundle| bundle.to_bytes())
            .unwrap_or_else(|error| panic!("responder fixture failed: {error}"));

        let (initiator, mut flight_one) = ReferenceSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bytes)
                .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        flight_one[10..12].copy_from_slice(&2u16.to_be_bytes());
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        assert!(responder.receive_client(&flight_one).is_err());
        drop(initiator);

        let (initiator, flight_one) = ReferenceSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bytes)
                .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (_pending, mut flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let mut server_hello = decode_server_flight(&flight_two)
            .unwrap_or_else(|error| panic!("server flight decode failed: {error}"));
        server_hello.protected_auth.ciphertext[0] ^= 1;
        flight_two = encode_server_flight(&server_hello)
            .unwrap_or_else(|error| panic!("server flight encode failed: {error}"));
        assert!(initiator.receive_server(&flight_two).is_err());

        let (initiator, flight_one) = ReferenceSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bytes)
                .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (responder_pending, flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let (initiator_pending, flight_three) = initiator
            .receive_server(&flight_two)
            .unwrap_or_else(|error| panic!("server flight failed: {error}"));
        let mut client_finish = decode_client_auth_flight(&flight_three)
            .unwrap_or_else(|error| panic!("client auth decode failed: {error}"));
        client_finish.protected_auth.ciphertext[0] ^= 1;
        let damaged_flight_three = encode_client_auth_flight(&client_finish)
            .unwrap_or_else(|error| panic!("client auth encode failed: {error}"));
        assert!(
            responder_pending
                .receive_client_auth(&damaged_flight_three)
                .is_err()
        );
        drop(initiator_pending);

        let (initiator, flight_one) = ReferenceSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bytes)
                .unwrap_or_else(|error| panic!("initiator parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let responder = ReferenceSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes)
                .unwrap_or_else(|error| panic!("responder parse failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (responder_pending, flight_two) = responder
            .receive_client(&flight_one)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let (initiator_pending, flight_three) = initiator
            .receive_server(&flight_two)
            .unwrap_or_else(|error| panic!("server flight failed: {error}"));
        let (_responder_session, mut flight_four) = responder_pending
            .receive_client_auth(&flight_three)
            .unwrap_or_else(|error| panic!("client auth failed: {error}"));
        let last = flight_four
            .len()
            .checked_sub(1)
            .unwrap_or_else(|| panic!("server finished was empty"));
        flight_four[last] ^= 1;
        assert!(initiator_pending.receive_finished(&flight_four).is_err());
    }

    #[test]
    fn batch_provider_round_trip_requires_exact_proof_version_and_grants() {
        let mut services = batch_provider_services(0xd1);
        let payloads: [&[u8]; 3] = [b"red", b"green", b"blue"];
        let sealed = seal_batch_fixture(&mut services.publisher, 10, &payloads);
        assert_eq!(&sealed.proof_bytes[..8], BATCH_ENVELOPE_MAGIC);
        assert_eq!(sealed.proof_bytes[14], batch::OBJECT_KIND_BATCH_PROOF);
        assert_eq!(
            sealed.proof_envelope_id,
            batch::proof_envelope_id(&sealed.proof_bytes)
        );
        assert_eq!(sealed.items.len(), payloads.len());
        for item in &sealed.items {
            assert_eq!(&item.bytes[..8], BATCH_ENVELOPE_MAGIC);
            assert_eq!(item.bytes[14], EnvelopeKind::Data as u8);
            assert_eq!(item.envelope_id, batch::proof_envelope_id(&item.bytes));
        }
        assert!(!format!("{sealed:?}").contains("green"));
        assert!(format!("{sealed:?}").contains("plaintext: \"[NONE]\""));

        let v4_reader_proof = services
            .reader
            .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V4)
            .unwrap_or_else(|error| panic!("v4 reader proof open failed: {error}"));
        let v4_pending = services
            .reader
            .open_compact_batch_item(&sealed.items[1].bytes, SEMANTIC_PROTOCOL_V4)
            .unwrap_or_else(|error| panic!("v4 reader compact open failed: {error}"));
        assert_eq!(
            v4_reader_proof.proof_envelope_id(),
            sealed.proof_envelope_id
        );
        assert_eq!(
            services.reader.pending_batch_proof_id(&v4_pending),
            sealed.proof_envelope_id
        );

        let reader_proof = services
            .reader
            .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("reader proof open failed: {error}"));
        assert_eq!(reader_proof.proof_envelope_id(), sealed.proof_envelope_id);
        assert_eq!(reader_proof.batch_id(), sealed.batch_id);
        let pending = services
            .reader
            .open_compact_batch_item(&sealed.items[1].bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("reader compact open failed: {error}"));
        assert_eq!(
            services.reader.pending_batch_proof_id(&pending),
            sealed.proof_envelope_id
        );
        assert!(
            services
                .reader
                .verify_compact_batch_item(&pending, None, &sealed.items[1].bytes)
                .is_err()
        );
        let verified = services
            .reader
            .verify_compact_batch_item(&pending, Some(&reader_proof), &sealed.items[1].bytes)
            .unwrap_or_else(|error| panic!("reader compact verify failed: {error}"));
        assert_eq!(verified.verified_envelope().id, sealed.items[1].item_id);
        assert_eq!(
            services
                .reader
                .open_compact_batch_payload(&verified, &sealed.items[1].bytes)
                .unwrap_or_else(|error| panic!("reader batch payload failed: {error}")),
            b"green"
        );
        assert!(!format!("{reader_proof:?}").contains("green"));
        assert!(!format!("{pending:?}").contains("green"));
        assert!(!format!("{verified:?}").contains("green"));
        assert!(format!("{reader_proof:?}").contains("key_material: \"[NONE]\""));
        assert!(format!("{pending:?}").contains("acceptance: \"[PENDING-PROOF]\""));

        let relay_proof = services
            .relay
            .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("relay proof open failed: {error}"));
        let relay_pending = services
            .relay
            .open_compact_batch_item(&sealed.items[1].bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("relay compact open failed: {error}"));
        let relay_verified = services
            .relay
            .verify_compact_batch_item(&relay_pending, Some(&relay_proof), &sealed.items[1].bytes)
            .unwrap_or_else(|error| panic!("relay compact verify failed: {error}"));
        assert!(
            services
                .relay
                .open_compact_batch_payload(&relay_verified, &sealed.items[1].bytes)
                .is_err()
        );
        assert!(
            !services
                .relay
                .has_content_grant(&scope("alpha"), &topic("ops"), 7)
        );

        let wrong_content_proof = services
            .wrong_content
            .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-content proof open failed: {error}"));
        let wrong_content_pending = services
            .wrong_content
            .open_compact_batch_item(&sealed.items[0].bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-content compact open failed: {error}"));
        let wrong_content_verified = services
            .wrong_content
            .verify_compact_batch_item(
                &wrong_content_pending,
                Some(&wrong_content_proof),
                &sealed.items[0].bytes,
            )
            .unwrap_or_else(|error| panic!("wrong-content verify failed: {error}"));
        assert!(
            services
                .wrong_content
                .open_compact_batch_payload(&wrong_content_verified, &sealed.items[0].bytes)
                .is_err()
        );
        assert!(
            services
                .content_only
                .has_content_grant(&scope("alpha"), &topic("ops"), 7)
        );
        assert!(
            services
                .content_only
                .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        assert!(
            services
                .content_only
                .open_compact_batch_item(&sealed.items[0].bytes, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );

        assert!(
            services
                .reader
                .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V1)
                .is_err()
        );
        assert!(
            services
                .reader
                .open_compact_batch_item(&sealed.items[0].bytes, SEMANTIC_PROTOCOL_V1)
                .is_err()
        );
        assert!(services.reader.inspect(&sealed.items[0].bytes).is_err());
        let raw_kind_three = open_test_batch_route(&services.publisher, &sealed.proof_bytes);
        assert!(
            services
                .reader
                .open_batch_proof(&raw_kind_three, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        let mut invented_magic = sealed.proof_bytes.clone();
        invented_magic[..8].copy_from_slice(b"ASTBPRF1");
        assert!(
            services
                .reader
                .open_batch_proof(&invented_magic, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );

        // Re-encrypting the same authenticated proof route creates a valid alternate
        // EnvelopeID for the same BatchID. Compact items name the exact proof encoding,
        // so neither direct proof substitution nor rewriting only the compact reference
        // may authenticate.
        let alternate_proof_route = open_test_batch_route(&services.publisher, &sealed.proof_bytes);
        let alternate_proof_bytes = reseal_test_batch_route(
            &mut services.publisher,
            &sealed.proof_bytes,
            alternate_proof_route,
        );
        let alternate_proof = services
            .reader
            .open_batch_proof(&alternate_proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("alternate proof open failed: {error}"));
        assert_eq!(alternate_proof.batch_id(), sealed.batch_id);
        assert_ne!(
            alternate_proof.proof_envelope_id(),
            sealed.proof_envelope_id
        );
        assert!(
            services
                .reader
                .verify_compact_batch_item(
                    &pending,
                    Some(&alternate_proof),
                    &sealed.items[1].bytes,
                )
                .is_err()
        );

        let mut rebound_route = decode_compact_batch_route(&open_test_batch_route(
            &services.publisher,
            &sealed.items[1].bytes,
        ))
        .unwrap_or_else(|error| panic!("rebound compact decode failed: {error}"));
        rebound_route.authentication.proof_envelope_id = alternate_proof.proof_envelope_id();
        let rebound_item = reseal_test_batch_route(
            &mut services.publisher,
            &sealed.items[1].bytes,
            encode_compact_batch_route(&rebound_route)
                .unwrap_or_else(|error| panic!("rebound compact encode failed: {error}")),
        );
        let rebound_pending = services
            .reader
            .open_compact_batch_item(&rebound_item, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("rebound compact open failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(&rebound_pending, Some(&alternate_proof), &rebound_item,)
                .is_err()
        );

        let second = seal_batch_fixture(&mut services.publisher, 20, &[b"other", b"proof"]);
        let wrong_proof = services
            .reader
            .open_batch_proof(&second.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong proof open failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(&pending, Some(&wrong_proof), &sealed.items[1].bytes,)
                .is_err()
        );
        let outsider = batch_provider_services(0xd2).reader;
        assert!(
            outsider
                .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        assert!(
            outsider
                .open_compact_batch_item(&sealed.items[0].bytes, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );

        let restarted_reader = service(
            ProvisioningBundle::from_bytes(&services.reader_bundle)
                .unwrap_or_else(|error| panic!("reader restart parse failed: {error}")),
        );
        let restarted_proof = restarted_reader
            .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("reader restart proof failed: {error}"));
        let restarted_pending = restarted_reader
            .open_compact_batch_item(&sealed.items[2].bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("reader restart compact failed: {error}"));
        let restarted_verified = restarted_reader
            .verify_compact_batch_item(
                &restarted_pending,
                Some(&restarted_proof),
                &sealed.items[2].bytes,
            )
            .unwrap_or_else(|error| panic!("reader restart verify failed: {error}"));
        assert_eq!(
            restarted_reader
                .open_compact_batch_payload(&restarted_verified, &sealed.items[2].bytes)
                .unwrap_or_else(|error| panic!("reader restart payload failed: {error}")),
            b"blue"
        );
        let restarted_relay = service(
            ProvisioningBundle::from_bytes(&services.relay_bundle)
                .unwrap_or_else(|error| panic!("relay restart parse failed: {error}")),
        );
        assert!(
            restarted_relay
                .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
                .is_ok()
        );
        let mut restarted_publisher = service(
            ProvisioningBundle::from_bytes(&services.publisher_bundle)
                .unwrap_or_else(|error| panic!("publisher restart parse failed: {error}")),
        );
        let restarted_source_batch =
            seal_batch_fixture(&mut restarted_publisher, 40, &[b"restart", b"source"]);
        assert!(
            restarted_reader
                .open_batch_proof(&restarted_source_batch.proof_bytes, SEMANTIC_PROTOCOL_V2,)
                .is_ok()
        );

        EnvelopeSealer::zeroize(&mut services.reader)
            .unwrap_or_else(|error| panic!("batch reader zeroize failed: {error}"));
        assert!(services.reader.route_grants.is_empty());
        assert!(services.reader.content_grants.is_empty());
        assert!(
            services
                .reader
                .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        assert!(
            services
                .reader
                .open_compact_batch_payload(&verified, &sealed.items[1].bytes)
                .is_err()
        );
        EnvelopeSealer::zeroize(&mut services.publisher)
            .unwrap_or_else(|error| panic!("batch publisher zeroize failed: {error}"));
        assert!(services.publisher.seal_source_batch(&[]).is_err());
    }

    #[test]
    fn batch_provider_enforces_atomic_source_boundaries_and_event_ranges() {
        let mut services = batch_provider_services(0xd4);
        let payloads: [&[u8]; 2] = [b"first", b"second"];
        let mut headers = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                let mut value = header(services.publisher.identity(), 7);
                value.stamp.dot.counter = 50 + index as u64;
                value.logical_key = format!("boundary-{index}").into_bytes();
                value.content_len = payload.len() as u64;
                value
            })
            .collect::<Vec<_>>();

        let one = [headers[0].clone()];
        assert!(
            try_seal_batch_headers(&mut services.publisher, &one, &payloads[..1])
                .unwrap_err()
                .0
                .contains("invalid source batch size")
        );

        let sixty_five_payloads = vec![b"x".as_slice(); 65];
        let sixty_five_headers = (0..65)
            .map(|index| {
                let mut value = header(services.publisher.identity(), 7);
                value.stamp.dot.counter = 100 + index as u64;
                value.logical_key = format!("maximum-{index}").into_bytes();
                value.content_len = 1;
                value
            })
            .collect::<Vec<_>>();
        assert!(
            try_seal_batch_headers(
                &mut services.publisher,
                &sixty_five_headers,
                &sixty_five_payloads,
            )
            .unwrap_err()
            .0
            .contains("invalid source batch size")
        );

        fn change_class(value: &mut EnvelopeHeader) {
            value.class = DataClass::Record;
        }
        fn change_topic(value: &mut EnvelopeHeader) {
            value.topic = topic("intel");
        }
        fn change_scope(value: &mut EnvelopeHeader) {
            value.scope = scope("bravo");
        }
        fn change_epoch(value: &mut EnvelopeHeader) {
            value.key_epoch = 8;
        }
        fn change_publisher(value: &mut EnvelopeHeader) {
            value.stamp.dot.publisher = [0x55; 32];
        }
        fn skip_counter(value: &mut EnvelopeHeader) {
            value.stamp.dot.counter += 1;
        }
        fn add_non_event_sequence(value: &mut EnvelopeHeader) {
            value.event_sequence = Some(1);
        }

        let baseline = headers.clone();
        for mutate in [
            change_class,
            change_topic,
            change_scope,
            change_epoch,
            change_publisher,
            skip_counter,
            add_non_event_sequence,
        ] {
            headers.clone_from(&baseline);
            mutate(&mut headers[1]);
            let error =
                try_seal_batch_headers(&mut services.publisher, &headers, &payloads).unwrap_err();
            assert!(
                error.0.contains("mandatory manifest boundary"),
                "unexpected boundary error: {error}"
            );
        }

        headers.clone_from(&baseline);
        headers[0].stamp.dot.counter = 0;
        headers[1].stamp.dot.counter = 1;
        assert!(try_seal_batch_headers(&mut services.publisher, &headers, &payloads).is_err());
        headers.clone_from(&baseline);
        headers[0].stamp.dot.counter = u64::MAX;
        assert!(try_seal_batch_headers(&mut services.publisher, &headers, &payloads).is_err());

        headers.clone_from(&baseline);
        for (index, value) in headers.iter_mut().enumerate() {
            value.class = DataClass::Event;
            value.event_sequence = Some(900 + index as u64);
        }
        let event_batch = try_seal_batch_headers(&mut services.publisher, &headers, &payloads)
            .unwrap_or_else(|error| panic!("valid Event batch failed: {error}"));
        let event_proof = services
            .reader
            .open_batch_proof(&event_batch.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("Event proof failed: {error}"));
        assert_eq!(event_proof.manifest().preamble.first_event_sequence, 900);
        let event_pending = services
            .reader
            .open_compact_batch_item(&event_batch.items[1].bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("Event compact open failed: {error}"));
        let event_verified = services
            .reader
            .verify_compact_batch_item(
                &event_pending,
                Some(&event_proof),
                &event_batch.items[1].bytes,
            )
            .unwrap_or_else(|error| panic!("Event compact verify failed: {error}"));
        assert_eq!(
            event_verified.verified_envelope().header.event_sequence,
            Some(901)
        );

        headers[1].event_sequence = Some(902);
        assert!(try_seal_batch_headers(&mut services.publisher, &headers, &payloads).is_err());
        headers[1].event_sequence = Some(901);
        headers[0].event_sequence = None;
        assert!(try_seal_batch_headers(&mut services.publisher, &headers, &payloads).is_err());
        headers[0].event_sequence = Some(u64::MAX);
        assert!(try_seal_batch_headers(&mut services.publisher, &headers, &payloads).is_err());
    }

    #[test]
    fn batch_provider_actual_serializations_meet_normative_overhead_gates() {
        for (fixture_index, credential_groups) in
            [batch::MIN_CREDENTIAL_GROUPS, batch::MAX_CREDENTIAL_GROUPS]
                .into_iter()
                .enumerate()
        {
            let (mut publisher, target_scope, target_topic) =
                batch_overhead_service(0xe0 + fixture_index as u8, credential_groups);
            let payload_storage = (0..batch::MAX_BATCH_ITEMS)
                .map(|index| vec![index as u8])
                .collect::<Vec<_>>();
            let payloads = payload_storage
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let headers = payloads
                .iter()
                .enumerate()
                .map(|(index, payload)| EnvelopeHeader {
                    class: DataClass::State,
                    topic: target_topic.clone(),
                    scope: target_scope.clone(),
                    priority: Priority::Routine,
                    stamp: CausalStamp {
                        dot: Dot {
                            publisher: publisher.identity(),
                            counter: index as u64 + 1,
                        },
                        context: VersionVector::default(),
                    },
                    event_sequence: None,
                    logical_key: format!("overhead-{index}").into_bytes(),
                    blob_route: None,
                    ttl_ms: None,
                    content_len: payload.len() as u64,
                    tombstone: false,
                    key_epoch: 7,
                })
                .collect::<Vec<_>>();
            let sealed = try_seal_batch_headers(&mut publisher, &headers, &payloads)
                .unwrap_or_else(|error| panic!("overhead batch seal failed: {error}"));

            let mut proof_plaintext = open_test_batch_route(&publisher, &sealed.proof_bytes);
            let proof_route = batch::BatchProofRoute::decode(&proof_plaintext)
                .unwrap_or_else(|error| panic!("overhead proof decode failed: {error}"));
            assert_eq!(
                batch::credential_group_count(proof_route.credential_body.len())
                    .unwrap_or_else(|error| panic!("credential group count failed: {error}")),
                credential_groups
            );
            assert_eq!(
                proof_route.authority_signature.len(),
                batch::HYBRID_SIGNATURE_BYTES
            );
            assert_eq!(
                proof_route.source_signature.len(),
                batch::HYBRID_SIGNATURE_BYTES
            );
            let authority_signature =
                decode_exact_hybrid_signature(&proof_route.authority_signature)
                    .unwrap_or_else(|error| panic!("authority signature decode failed: {error}"));
            let credential = decode_credential(
                proof_route.credential_body.clone(),
                authority_signature,
                &publisher.mission,
                &publisher.authority_verifying_key,
                &publisher.provider,
            )
            .unwrap_or_else(|error| panic!("overhead credential failed: {error}"));
            assert_eq!(credential.verifying_key.ml_dsa_65.len(), ML_DSA_PUBLIC_LEN);
            let source_signature = decode_exact_hybrid_signature(&proof_route.source_signature)
                .unwrap_or_else(|error| panic!("source signature decode failed: {error}"));
            assert_eq!(
                source_signature.ml_dsa_65.as_ref().map(Vec::len),
                Some(batch::ML_DSA_65_SIGNATURE_BYTES)
            );
            proof_plaintext.zeroize();

            let expected_item_auth = batch::expected_compact_auth_len(batch::MAX_BATCH_ITEMS)
                .unwrap_or_else(|error| panic!("compact overhead failed: {error}"));
            let mut compact_authentication_bytes = 0usize;
            for item in &sealed.items {
                let mut route_plaintext = open_test_batch_route(&publisher, &item.bytes);
                let route = decode_compact_batch_route(&route_plaintext)
                    .unwrap_or_else(|error| panic!("compact overhead decode failed: {error}"));
                let authentication = route
                    .authentication
                    .encode()
                    .unwrap_or_else(|error| panic!("compact overhead encode failed: {error}"));
                assert_eq!(authentication.len(), expected_item_auth);
                assert_eq!(
                    route.authentication.item_signature.len(),
                    batch::ITEM_SIGNATURE_BYTES
                );
                compact_authentication_bytes = compact_authentication_bytes
                    .checked_add(authentication.len())
                    .unwrap_or_else(|| panic!("compact authentication byte count overflow"));
                route_plaintext.zeroize();
            }

            let actual_batch_authentication = sealed
                .proof_bytes
                .len()
                .checked_add(compact_authentication_bytes)
                .unwrap_or_else(|| panic!("batch authentication byte count overflow"));
            let expected_batch_authentication = batch::expected_batch_auth_len(
                credential_groups,
                batch::MAX_TOPIC_BYTES,
                batch::MAX_SCOPE_BYTES,
                batch::MAX_BATCH_ITEMS,
            )
            .unwrap_or_else(|error| panic!("batch overhead formula failed: {error}"));
            assert_eq!(
                sealed.proof_bytes.len(),
                batch::expected_proof_envelope_len(
                    credential_groups,
                    batch::MAX_TOPIC_BYTES,
                    batch::MAX_SCOPE_BYTES,
                )
                .unwrap_or_else(|error| panic!("proof overhead formula failed: {error}"))
            );
            assert_eq!(actual_batch_authentication, expected_batch_authentication);

            let transfer_seconds = actual_batch_authentication as f64 * 8.0 / 3_000.0;
            assert!(transfer_seconds <= 120.0);
            assert!(transfer_seconds / f64::from(batch::MAX_BATCH_ITEMS) <= 2.0);
            let singleton_authentication = batch::singleton_auth_len(credential_groups)
                .unwrap_or_else(|error| panic!("singleton overhead formula failed: {error}"))
                * usize::from(batch::MAX_BATCH_ITEMS);
            assert!(singleton_authentication as f64 / actual_batch_authentication as f64 >= 20.0);
            assert_eq!(
                actual_batch_authentication,
                if credential_groups == batch::MIN_CREDENTIAL_GROUPS {
                    31_254
                } else {
                    39_414
                }
            );
        }
    }

    #[test]
    fn batch_provider_rejects_proof_leaf_path_header_ciphertext_and_signature_tamper() {
        let mut services = batch_provider_services(0xd3);
        let sealed = seal_batch_fixture(&mut services.publisher, 30, &[b"one", b"two", b"three"]);
        let proof = services
            .reader
            .open_batch_proof(&sealed.proof_bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("baseline proof open failed: {error}"));

        for (name, mutate) in [
            ("magic", 0usize),
            ("envelope format", 9),
            ("semantic version", 11),
            ("suite", 13),
            ("object kind", 14),
            ("reserved", 15),
            ("route selector", 16),
        ] {
            let mut damaged = sealed.proof_bytes.clone();
            damaged[mutate] ^= 0x80;
            assert!(
                services
                    .reader
                    .open_batch_proof(&damaged, SEMANTIC_PROTOCOL_V2)
                    .is_err(),
                "damaged public-header {name} was accepted"
            );
        }
        let mut wrong_route_length = sealed.proof_bytes.clone();
        wrong_route_length[32..36].fill(0);
        assert!(
            services
                .reader
                .open_batch_proof(&wrong_route_length, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        let mut nonzero_proof_content = sealed.proof_bytes.clone();
        nonzero_proof_content[43] = 1;
        assert!(
            services
                .reader
                .open_batch_proof(&nonzero_proof_content, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        let mut trailing_proof = sealed.proof_bytes.clone();
        trailing_proof.push(0);
        assert!(
            services
                .reader
                .open_batch_proof(&trailing_proof, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        assert!(
            services
                .reader
                .open_batch_proof(
                    &sealed.proof_bytes[..sealed.proof_bytes.len() - 1],
                    SEMANTIC_PROTOCOL_V2,
                )
                .is_err()
        );

        let proof_plaintext = open_test_batch_route(&services.publisher, &sealed.proof_bytes);
        let decoded_proof_route = batch::BatchProofRoute::decode(&proof_plaintext)
            .unwrap_or_else(|error| panic!("proof discriminator fixture failed: {error}"));
        let manifest_offset =
            5 + decoded_proof_route.credential_body.len() + batch::HYBRID_SIGNATURE_BYTES;
        for (offset, name) in [
            (0usize, "batch format"),
            (2, "envelope format"),
            (4, "semantic protocol"),
            (6, "complete suite"),
            (8, "hash algorithm"),
            (10, "tree algorithm"),
            (12, "batch signature algorithm"),
            (14, "item signature algorithm"),
        ] {
            let mut damaged_route = proof_plaintext.clone();
            damaged_route[manifest_offset + offset + 1] ^= 0x80;
            let damaged = reseal_test_batch_route(
                &mut services.publisher,
                &sealed.proof_bytes,
                damaged_route,
            );
            assert!(
                services
                    .reader
                    .open_batch_proof(&damaged, SEMANTIC_PROTOCOL_V2)
                    .is_err(),
                "damaged manifest {name} was accepted"
            );
        }
        let mut source_signature_route = batch::BatchProofRoute::decode(&proof_plaintext)
            .unwrap_or_else(|error| panic!("source-signature route decode failed: {error}"));
        *source_signature_route
            .source_signature
            .last_mut()
            .unwrap_or_else(|| panic!("source signature was empty")) ^= 1;
        let bad_source_signature = reseal_test_batch_route(
            &mut services.publisher,
            &sealed.proof_bytes,
            source_signature_route
                .encode()
                .unwrap_or_else(|error| panic!("source-signature route encode failed: {error}")),
        );
        assert!(
            services
                .reader
                .open_batch_proof(&bad_source_signature, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );

        let mut authority_signature_route = batch::BatchProofRoute::decode(&proof_plaintext)
            .unwrap_or_else(|error| panic!("authority-signature route decode failed: {error}"));
        authority_signature_route.authority_signature[2] ^= 1;
        authority_signature_route.manifest.preamble.credential_id = batch::credential_id(
            &authority_signature_route.credential_body,
            &authority_signature_route.authority_signature,
        )
        .unwrap_or_else(|error| panic!("tampered credential id failed: {error}"));
        let resigned_manifest = services
            .publisher
            .provider
            .sign(
                &services.publisher.signing_key,
                &authority_signature_route
                    .manifest
                    .signature_digest()
                    .unwrap_or_else(|error| panic!("tampered manifest digest failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("tampered manifest signing failed: {error}"));
        authority_signature_route.source_signature =
            encode_exact_hybrid_signature(&resigned_manifest)
                .unwrap_or_else(|error| panic!("tampered manifest signature failed: {error}"));
        let bad_authority_signature = reseal_test_batch_route(
            &mut services.publisher,
            &sealed.proof_bytes,
            authority_signature_route
                .encode()
                .unwrap_or_else(|error| panic!("authority-signature route encode failed: {error}")),
        );
        assert!(
            services
                .reader
                .open_batch_proof(&bad_authority_signature, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );

        let mut credential_mismatch = proof_plaintext;
        credential_mismatch[5] ^= 1;
        let credential_mismatch = reseal_test_batch_route(
            &mut services.publisher,
            &sealed.proof_bytes,
            credential_mismatch,
        );
        assert!(
            services
                .reader
                .open_batch_proof(&credential_mismatch, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
        let mut proof_aead_tamper = sealed.proof_bytes.clone();
        *proof_aead_tamper
            .last_mut()
            .unwrap_or_else(|| panic!("proof envelope was empty")) ^= 1;
        assert!(
            services
                .reader
                .open_batch_proof(&proof_aead_tamper, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );

        let item = &sealed.items[0];
        let compact_plaintext = open_test_batch_route(&services.publisher, &item.bytes);
        let baseline_route = decode_compact_batch_route(&compact_plaintext)
            .unwrap_or_else(|error| panic!("compact route decode failed: {error}"));

        let mut wrong_index = DecodedCompactBatchRoute {
            item_id: baseline_route.item_id,
            header: baseline_route.header.clone(),
            content_group: baseline_route.content_group,
            content_nonce: baseline_route.content_nonce,
            content_ciphertext_len: baseline_route.content_ciphertext_len,
            authentication: baseline_route.authentication.clone(),
        };
        wrong_index.authentication.item_index = 1;
        let wrong_index = reseal_test_batch_route(
            &mut services.publisher,
            &item.bytes,
            encode_compact_batch_route(&wrong_index)
                .unwrap_or_else(|error| panic!("wrong-index route encode failed: {error}")),
        );
        let wrong_index_pending = services
            .reader
            .open_compact_batch_item(&wrong_index, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-index pending failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(&wrong_index_pending, Some(&proof), &wrong_index)
                .is_err()
        );

        let mut wrong_path = DecodedCompactBatchRoute {
            item_id: baseline_route.item_id,
            header: baseline_route.header.clone(),
            content_group: baseline_route.content_group,
            content_nonce: baseline_route.content_nonce,
            content_ciphertext_len: baseline_route.content_ciphertext_len,
            authentication: baseline_route.authentication.clone(),
        };
        wrong_path.authentication.siblings[0][0] ^= 1;
        let wrong_path = reseal_test_batch_route(
            &mut services.publisher,
            &item.bytes,
            encode_compact_batch_route(&wrong_path)
                .unwrap_or_else(|error| panic!("wrong-path route encode failed: {error}")),
        );
        let wrong_path_pending = services
            .reader
            .open_compact_batch_item(&wrong_path, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-path pending failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(&wrong_path_pending, Some(&proof), &wrong_path)
                .is_err()
        );

        let mut wrong_leaf = DecodedCompactBatchRoute {
            item_id: baseline_route.item_id,
            header: baseline_route.header.clone(),
            content_group: baseline_route.content_group,
            content_nonce: baseline_route.content_nonce,
            content_ciphertext_len: baseline_route.content_ciphertext_len,
            authentication: baseline_route.authentication.clone(),
        };
        wrong_leaf.item_id[0] ^= 1;
        let wrong_leaf = reseal_test_batch_route(
            &mut services.publisher,
            &item.bytes,
            encode_compact_batch_route(&wrong_leaf)
                .unwrap_or_else(|error| panic!("wrong-leaf route encode failed: {error}")),
        );
        let wrong_leaf_pending = services
            .reader
            .open_compact_batch_item(&wrong_leaf, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-leaf pending failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(&wrong_leaf_pending, Some(&proof), &wrong_leaf)
                .is_err()
        );

        let mut wrong_header = DecodedCompactBatchRoute {
            item_id: baseline_route.item_id,
            header: baseline_route.header.clone(),
            content_group: baseline_route.content_group,
            content_nonce: baseline_route.content_nonce,
            content_ciphertext_len: baseline_route.content_ciphertext_len,
            authentication: baseline_route.authentication.clone(),
        };
        wrong_header.header.logical_key.push(0x55);
        let wrong_header = reseal_test_batch_route(
            &mut services.publisher,
            &item.bytes,
            encode_compact_batch_route(&wrong_header)
                .unwrap_or_else(|error| panic!("wrong-header route encode failed: {error}")),
        );
        let wrong_header_pending = services
            .reader
            .open_compact_batch_item(&wrong_header, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-header pending failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(&wrong_header_pending, Some(&proof), &wrong_header)
                .is_err()
        );

        let mut wrong_signature = DecodedCompactBatchRoute {
            item_id: baseline_route.item_id,
            header: baseline_route.header.clone(),
            content_group: baseline_route.content_group,
            content_nonce: baseline_route.content_nonce,
            content_ciphertext_len: baseline_route.content_ciphertext_len,
            authentication: baseline_route.authentication.clone(),
        };
        wrong_signature.authentication.item_signature[0] ^= 1;
        let wrong_signature = reseal_test_batch_route(
            &mut services.publisher,
            &item.bytes,
            encode_compact_batch_route(&wrong_signature)
                .unwrap_or_else(|error| panic!("wrong-signature route encode failed: {error}")),
        );
        let wrong_signature_pending = services
            .reader
            .open_compact_batch_item(&wrong_signature, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-signature pending failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(
                    &wrong_signature_pending,
                    Some(&proof),
                    &wrong_signature,
                )
                .is_err()
        );

        let parsed_item = parse_batch_envelope(&item.bytes, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("item parse failed: {error}"));
        let content_offset = BATCH_PUBLIC_HEADER_LEN + parsed_item.route_ciphertext.len();
        let mut wrong_ciphertext = item.bytes.clone();
        wrong_ciphertext[content_offset] ^= 1;
        let wrong_ciphertext_pending = services
            .reader
            .open_compact_batch_item(&wrong_ciphertext, SEMANTIC_PROTOCOL_V2)
            .unwrap_or_else(|error| panic!("wrong-ciphertext pending failed: {error}"));
        assert!(
            services
                .reader
                .verify_compact_batch_item(
                    &wrong_ciphertext_pending,
                    Some(&proof),
                    &wrong_ciphertext,
                )
                .is_err()
        );
        let mut route_aead_tamper = item.bytes.clone();
        route_aead_tamper[BATCH_PUBLIC_HEADER_LEN] ^= 1;
        assert!(
            services
                .reader
                .open_compact_batch_item(&route_aead_tamper, SEMANTIC_PROTOCOL_V2)
                .is_err()
        );
    }

    #[test]
    fn bridge_authorization_provider_fails_closed_on_identity_signature_and_aead_damage() {
        let mut services = bridge_provider_services(0xa1);
        let base = bridge_authorization_fixture(&services.authority, &services.bridge_node);

        let mut wrong_mission = base.clone();
        wrong_mission.mission_id[0] ^= 1;
        assert!(
            services
                .authority
                .seal_bridge_authorization(wrong_mission)
                .is_err()
        );
        let mut wrong_scope = base.clone();
        wrong_scope.source_scope = scope("charlie");
        wrong_scope.authorization_key = bridge::bridge_authorization_key(
            &wrong_scope.mission_id,
            &wrong_scope.bridge_node_id,
            &wrong_scope.source_scope,
            &wrong_scope.target_scope,
        )
        .unwrap_or_else(|error| panic!("wrong-scope key failed: {error}"));
        assert!(
            services
                .authority
                .seal_bridge_authorization(wrong_scope)
                .is_err()
        );
        let mut wrong_epoch = base.clone();
        wrong_epoch
            .enabled
            .as_mut()
            .unwrap_or_else(|| panic!("enabled authorization missing"))
            .source_route_epoch = 8;
        assert!(
            services
                .authority
                .seal_bridge_authorization(wrong_epoch)
                .is_err()
        );
        let mut wrong_commitment = base.clone();
        wrong_commitment
            .enabled
            .as_mut()
            .unwrap_or_else(|| panic!("enabled authorization missing"))
            .target_route_commitment[0] ^= 1;
        assert!(
            services
                .authority
                .seal_bridge_authorization(wrong_commitment)
                .is_err()
        );
        let mut wrong_public_identity = base.clone();
        wrong_public_identity.authorization_key[0] ^= 1;
        assert!(
            services
                .authority
                .seal_bridge_authorization(wrong_public_identity)
                .is_err()
        );

        let sealed = services
            .authority
            .seal_bridge_authorization(base)
            .unwrap_or_else(|error| panic!("valid authorization seal failed: {error}"));
        let verified = services
            .target
            .open_bridge_authorization(&sealed)
            .unwrap_or_else(|error| panic!("valid authorization open failed: {error}"));
        assert_eq!(verified.control_signer(), services.authority.identity());
        let mut control_root = *services
            .authority
            .control_route_key
            .as_ref()
            .unwrap_or_else(|| panic!("control route key missing"))
            .expose();

        let second_sealed = services
            .second_authority
            .seal_bridge_authorization(verified.envelope().authorization.clone())
            .unwrap_or_else(|error| panic!("second authority seal failed: {error}"));
        let second_verified = services
            .target
            .open_bridge_authorization(&second_sealed)
            .unwrap_or_else(|error| panic!("second authority open failed: {error}"));
        assert_eq!(
            second_verified.control_signer(),
            services.second_authority.identity()
        );

        let first_authentication = bridge::decode_delegated_control_authentication(
            &verified
                .envelope()
                .authorization
                .authority_control_signature,
        )
        .unwrap_or_else(|error| panic!("first control authentication failed: {error}"));
        let second_authentication = bridge::decode_delegated_control_authentication(
            &second_verified
                .envelope()
                .authorization
                .authority_control_signature,
        )
        .unwrap_or_else(|error| panic!("second control authentication failed: {error}"));
        let mut substituted_control_credential = verified.envelope().authorization.clone();
        substituted_control_credential.authority_control_signature =
            bridge::encode_delegated_control_authentication(
                &second_authentication.credential_body,
                &second_authentication.authority_credential_signature,
                &first_authentication.control_signature,
            )
            .unwrap_or_else(|error| panic!("substituted authentication failed: {error}"));
        let substituted_control_credential = seal_test_bridge_object(
            &mut services.authority,
            bridge::AUTHORIZATION_MAGIC,
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            control_root,
            substituted_control_credential
                .encode()
                .unwrap_or_else(|error| panic!("substituted authorization encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&substituted_control_credential)
                .is_err()
        );

        let mut ordinary_control = verified.envelope().authorization.clone();
        resign_bridge_authorization_for_test(&services.bridge_node, &mut ordinary_control);
        let ordinary_control = seal_test_bridge_object(
            &mut services.authority,
            bridge::AUTHORIZATION_MAGIC,
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            control_root,
            ordinary_control
                .encode()
                .unwrap_or_else(|error| panic!("ordinary authorization encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&ordinary_control)
                .is_err()
        );

        let mut legacy_control = verified.envelope().authorization.clone();
        legacy_control.authority_control_signature = first_authentication.control_signature;
        let legacy_control = seal_test_bridge_object(
            &mut services.authority,
            bridge::AUTHORIZATION_MAGIC,
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            control_root,
            legacy_control
                .encode()
                .unwrap_or_else(|error| panic!("legacy authorization encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&legacy_control)
                .is_err()
        );

        let mut bad_control_signature = verified.envelope().authorization.clone();
        *bad_control_signature
            .authority_control_signature
            .last_mut()
            .unwrap_or_else(|| panic!("control signature missing")) ^= 1;
        let bad_control = seal_test_bridge_object(
            &mut services.authority,
            bridge::AUTHORIZATION_MAGIC,
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            control_root,
            bad_control_signature
                .encode()
                .unwrap_or_else(|error| panic!("bad control encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&bad_control)
                .is_err()
        );

        let mut bad_credential_signature = verified.envelope().authorization.clone();
        *bad_credential_signature
            .enabled
            .as_mut()
            .unwrap_or_else(|| panic!("enabled authorization missing"))
            .authority_credential_signature
            .last_mut()
            .unwrap_or_else(|| panic!("credential signature missing")) ^= 1;
        resign_bridge_authorization_for_test(&services.authority, &mut bad_credential_signature);
        let bad_credential = seal_test_bridge_object(
            &mut services.authority,
            bridge::AUTHORIZATION_MAGIC,
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            control_root,
            bad_credential_signature
                .encode()
                .unwrap_or_else(|error| panic!("bad credential encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&bad_credential)
                .is_err()
        );

        let mut wrong_body_kind = verified
            .envelope()
            .authorization
            .encode()
            .unwrap_or_else(|error| panic!("authorization encode failed: {error}"));
        wrong_body_kind[0] ^= 1;
        let wrong_kind = seal_test_bridge_object(
            &mut services.authority,
            bridge::AUTHORIZATION_MAGIC,
            BRIDGE_AUTHORIZATION_ROUTE_KEY_LABEL,
            control_root,
            wrong_body_kind,
        );
        control_root.zeroize();
        assert!(
            services
                .target
                .open_bridge_authorization(&wrong_kind)
                .is_err()
        );

        for offset in [0usize, 9, 11, 13, 14] {
            let mut damaged = sealed.clone();
            damaged[offset] ^= 1;
            assert!(
                services.target.open_bridge_authorization(&damaged).is_err(),
                "authorization header byte {offset} was accepted"
            );
        }
        let mut wrong_length = sealed.clone();
        wrong_length[30..34].copy_from_slice(&15u32.to_be_bytes());
        assert!(
            services
                .target
                .open_bridge_authorization(&wrong_length)
                .is_err()
        );
        let mut oversized = sealed[..bridge::BRIDGE_PUBLIC_HEADER_BYTES].to_vec();
        oversized[30..34].copy_from_slice(
            &u32::try_from(
                bridge::MAX_AUTHORIZATION_TOTAL_BYTES - bridge::BRIDGE_PUBLIC_HEADER_BYTES + 1,
            )
            .unwrap_or_else(|error| panic!("oversized length conversion failed: {error}"))
            .to_be_bytes(),
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&oversized)
                .is_err()
        );
        let mut wrong_tag = sealed.clone();
        *wrong_tag
            .last_mut()
            .unwrap_or_else(|| panic!("sealed authorization empty")) ^= 1;
        assert!(
            services
                .target
                .open_bridge_authorization(&wrong_tag)
                .is_err()
        );
        let mut trailing = sealed.clone();
        trailing.push(0);
        assert!(
            services
                .target
                .open_bridge_authorization(&trailing)
                .is_err()
        );
        assert!(
            services
                .target
                .open_bridge_authorization(&sealed[..sealed.len() - 1])
                .is_err()
        );

        let outsider = bridge_provider_services(0xa2).target;
        assert!(outsider.open_bridge_authorization(&sealed).is_err());
    }

    #[test]
    fn opaque_bridge_edge_enrollment_binds_exact_edge_and_rejects_tamper_and_wrong_mission() {
        let services = bridge_provider_services(0xb0);
        let enrollment = services
            .bridge_node
            .create_bridge_edge_enrollment(&scope("alpha"), 7, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("enrollment creation failed: {error}"));
        assert!(!format!("{enrollment:?}").contains("ASTRBE01"));
        let verified = services
            .authority
            .open_bridge_edge_enrollment(&enrollment)
            .unwrap_or_else(|error| panic!("enrollment verification failed: {error}"));
        let claims = ReferenceEnvelopeSealer::bridge_edge_enrollment_claims(&verified);
        assert_eq!(claims.bridge_node_id, services.bridge_node.identity());
        assert_eq!(claims.source_scope, scope("alpha"));
        assert_eq!(claims.source_route_epoch, 7);
        assert_eq!(claims.target_scope, scope("bravo"));
        assert_eq!(claims.target_route_epoch, 9);
        assert!(
            services
                .target
                .open_bridge_edge_enrollment(&enrollment)
                .is_err(),
            "ordinary node accepted an authority-only enrollment"
        );

        let mut damaged = services
            .bridge_node
            .create_bridge_edge_enrollment(&scope("alpha"), 7, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("damaged enrollment setup failed: {error}"));
        let middle = damaged.bytes.len() / 2;
        damaged.bytes[middle] ^= 1;
        assert!(
            services
                .authority
                .open_bridge_edge_enrollment(&damaged)
                .is_err()
        );

        let outsider = bridge_provider_services(0xb2).authority;
        assert!(outsider.open_bridge_edge_enrollment(&enrollment).is_err());
    }

    #[test]
    fn bridge_provider_round_trip_is_restart_stateless_and_zeroizes() {
        let mut services = bridge_provider_services(0xb1);
        let authorization =
            bridge_authorization_fixture(&services.authority, &services.bridge_node);
        let sealed_authorization = services
            .authority
            .seal_bridge_authorization(authorization)
            .unwrap_or_else(|error| panic!("authorization seal failed: {error}"));
        let bridge_authorization = services
            .bridge_node
            .open_bridge_authorization(&sealed_authorization)
            .unwrap_or_else(|error| panic!("bridge authorization open failed: {error}"));
        let target_authorization = services
            .target
            .open_bridge_authorization(&sealed_authorization)
            .unwrap_or_else(|error| panic!("target authorization open failed: {error}"));
        let (source_envelope, verified_source) =
            bridge_source_fixture(&mut services.publisher, &services.bridge_node);
        let stable_source_bytes = source_envelope.bytes.clone();
        let route_only_verified = services
            .bridge_node
            .inspect(&source_envelope.bytes)
            .unwrap_or_else(|error| panic!("route-only bridge inspect failed: {error}"));
        assert!(
            services
                .bridge_node
                .open_payload(&route_only_verified, &source_envelope.bytes)
                .is_err()
        );
        let route = one_hop_bridge_route(
            &services.bridge_node,
            &bridge_authorization,
            &verified_source,
        );
        services
            .target
            .verify_bridge_hop(&route, 0, &target_authorization)
            .unwrap_or_else(|error| panic!("target hop verification failed: {error}"));
        let wrapper = services
            .bridge_node
            .seal_bridge_wrapper(&route, &verified_source, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("bridge wrapper seal failed: {error}"));

        // The target has no source-scope route grant. It authenticates the copied
        // format-2 descriptor without opening the original route ciphertext.
        assert!(services.target.inspect(&source_envelope.bytes).is_err());
        let opened_wrapper = services
            .target
            .open_bridge_wrapper_for_any_local_route(&wrapper)
            .unwrap_or_else(|error| panic!("target wrapper open failed: {error}"));
        assert_eq!(opened_wrapper.route(), &route);
        let opened_source = services
            .target
            .verify_bridge_wrapper_source(&opened_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("target source verification failed: {error}"));
        assert!(
            services
                .target
                .is_content_only(&scope("alpha"), &topic("ops"), 7)
        );
        assert_eq!(
            services
                .target
                .open_bridged_payload(&opened_source, &source_envelope.bytes)
                .unwrap_or_else(|error| panic!("bridged payload open failed: {error}")),
            b"payload"
        );
        assert!(
            services
                .bridge_node
                .open_bridged_payload(&verified_source, &source_envelope.bytes)
                .is_err()
        );
        let limited_wrapper = services
            .target_without_origin_content
            .open_bridge_wrapper(&wrapper, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("limited target wrapper open failed: {error}"));
        let limited_source = services
            .target_without_origin_content
            .verify_bridge_wrapper_source(&limited_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("limited target source verify failed: {error}"));
        assert!(
            services
                .target_without_origin_content
                .open_bridged_payload(&limited_source, &source_envelope.bytes)
                .is_err()
        );
        assert_eq!(opened_source.source_item_id(), source_envelope.id);
        assert_eq!(
            opened_source.content_ciphertext_len(),
            u64::try_from(
                parse_envelope(&source_envelope.bytes)
                    .unwrap_or_else(|error| panic!("source parse failed: {error}"))
                    .content_ciphertext
                    .len()
            )
            .unwrap_or_else(|error| panic!("source length conversion failed: {error}"))
        );
        assert_eq!(source_envelope.bytes, stable_source_bytes);
        assert!(format!("{opened_source:?}").contains("key_material: \"[NONE]\""));
        assert!(format!("{opened_wrapper:?}").contains("payload: \"[NONE]\""));
        assert!(!format!("{target_authorization:?}").contains("bridge_credential"));

        let restarted_target = service(
            ProvisioningBundle::from_bytes(&services.target_bundle)
                .unwrap_or_else(|error| panic!("target restart parse failed: {error}")),
        );
        let restarted_authorization = restarted_target
            .open_bridge_authorization(&sealed_authorization)
            .unwrap_or_else(|error| panic!("target restart authorization failed: {error}"));
        let restarted_wrapper = restarted_target
            .open_bridge_wrapper_for_any_local_route(&wrapper)
            .unwrap_or_else(|error| panic!("target restart wrapper failed: {error}"));
        restarted_target
            .verify_bridge_hop(restarted_wrapper.route(), 0, &restarted_authorization)
            .unwrap_or_else(|error| panic!("target restart hop verification failed: {error}"));
        assert_eq!(restarted_wrapper.route(), &route);
        let restarted_source = restarted_target
            .verify_bridge_wrapper_source(&restarted_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("target restart source failed: {error}"));
        assert_eq!(
            restarted_target
                .open_bridged_payload(&restarted_source, &source_envelope.bytes)
                .unwrap_or_else(|error| panic!("target restart payload failed: {error}")),
            b"payload"
        );

        let restarted_bridge = service(
            ProvisioningBundle::from_bytes(&services.bridge_bundle)
                .unwrap_or_else(|error| panic!("bridge restart parse failed: {error}")),
        );
        let restarted_source = restarted_bridge
            .open_source_route_for_bridge(&source_envelope.bytes)
            .unwrap_or_else(|error| panic!("bridge restart source failed: {error}"));
        assert_eq!(
            restarted_source.copy_exact_route_descriptor(),
            route.source_route_descriptor
        );
        let restarted_authority = service(
            ProvisioningBundle::from_bytes(&services.authority_bundle)
                .unwrap_or_else(|error| panic!("authority restart parse failed: {error}")),
        );
        restarted_authority
            .open_bridge_authorization(&sealed_authorization)
            .unwrap_or_else(|error| panic!("authority restart authorization failed: {error}"));

        EnvelopeSealer::zeroize(&mut services.target)
            .unwrap_or_else(|error| panic!("target zeroize failed: {error}"));
        EnvelopeSealer::zeroize(&mut services.bridge_node)
            .unwrap_or_else(|error| panic!("bridge zeroize failed: {error}"));
        EnvelopeSealer::zeroize(&mut services.authority)
            .unwrap_or_else(|error| panic!("authority zeroize failed: {error}"));
        assert!(services.target.zeroized);
        assert!(services.target.route_grants.is_empty());
        assert!(services.target.control_route_key.is_none());
        assert!(
            services
                .target
                .open_bridge_authorization(&sealed_authorization)
                .is_err()
        );
        assert!(
            services
                .target
                .open_bridge_wrapper(&wrapper, &scope("bravo"), 9)
                .is_err()
        );
        assert!(
            services
                .bridge_node
                .open_source_route_for_bridge(&source_envelope.bytes)
                .is_err()
        );
        let mut unsigned_after_zeroize = route;
        unsigned_after_zeroize.hops[0]
            .bridge_hybrid_signature
            .clear();
        assert!(
            services
                .bridge_node
                .sign_bridge_hop(&mut unsigned_after_zeroize, 0)
                .is_err()
        );
        let disabled = bridge_authorization_fixture(&restarted_authority, &restarted_bridge);
        assert!(
            services
                .authority
                .seal_bridge_authorization(disabled)
                .is_err()
        );
    }

    #[test]
    fn fresh_content_only_capsule_opens_only_the_exact_bridged_source() {
        let mut provisioner = ReferenceProvisioner::from_seed([0xb2; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let authority_bundle = provisioner
            .issue_control_authority(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("authority issue failed: {error}"));
        let publisher_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("publisher issue failed: {error}"));
        let bridge_bundle = provisioner
            .issue_node(3, &[relay_access(vec![0]), bridge_relay_access("bravo", 9)])
            .unwrap_or_else(|error| panic!("bridge issue failed: {error}"));
        let target_bundle = provisioner
            .issue_node(
                4,
                &[
                    ProvisioningAccess::member(scope("bravo"), vec![9], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("target route access failed: {error}")),
                    ProvisioningAccess::content_only(scope("alpha"), vec![0], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("target content access failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("target issue failed: {error}"));
        let limited_target_bundle = provisioner
            .issue_node(
                5,
                &[
                    ProvisioningAccess::member(scope("bravo"), vec![9], vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("limited target access failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("limited target issue failed: {error}"));

        let authority_id = bundle_identity(&authority_bundle);
        let publisher_id = bundle_identity(&publisher_bundle);
        let bridge_id = bundle_identity(&bridge_bundle);
        let target_id = bundle_identity(&target_bundle);
        let target_bundle_bytes = target_bundle
            .to_bytes()
            .unwrap_or_else(|error| panic!("target persist failed: {error}"));
        let plan = provisioner
            .plan_scope_rekey(
                scope("alpha"),
                1,
                vec![
                    ScopeRekeyRecipient::member(authority_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("authority recipient failed: {error}")),
                    ScopeRekeyRecipient::member(publisher_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("publisher recipient failed: {error}")),
                    ScopeRekeyRecipient::route_only(bridge_id),
                    ScopeRekeyRecipient::content_only(target_id, vec![topic("ops")])
                        .unwrap_or_else(|error| panic!("target recipient failed: {error}")),
                ],
            )
            .unwrap_or_else(|error| panic!("fresh rekey plan failed: {error}"));
        assert_eq!(plan.wire_format(), SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT);

        let mut authority = service(authority_bundle);
        let mut publisher = service(publisher_bundle);
        let mut bridge_node = service(bridge_bundle);
        let mut target = service(target_bundle);
        let mut limited_target = service(limited_target_bundle);
        assert!(target.is_content_only(&scope("alpha"), &topic("ops"), 0));
        assert!(target.route_grant(&scope("alpha"), 0).is_none());
        let target_bravo_commitment = route_grant_commitment(
            &target.mission,
            target
                .route_grant(&scope("bravo"), 9)
                .unwrap_or_else(|| panic!("target bravo route grant missing")),
        )
        .unwrap_or_else(|error| panic!("target bravo commitment failed: {error}"));
        assert_eq!(
            target.credential.route_grant_commitments,
            vec![target_bravo_commitment]
        );

        let control = authority
            .seal_scope_rekey_chained(&plan, 1, None)
            .unwrap_or_else(|error| panic!("fresh rekey seal failed: {error}"));
        let DecodedControl::ScopeEpoch {
            signer: _,
            sequence,
            previous,
            scope: rekey_scope,
            epoch: rekey_epoch,
            keying:
                ScopeEpochKeying::RecipientPackages {
                    format,
                    package_set_hash,
                    packages,
                },
        } = target
            .inspect_control_internal(&control)
            .unwrap_or_else(|error| panic!("fresh rekey inspect failed: {error}"))
        else {
            panic!("fresh rekey did not contain recipient capsules");
        };
        assert_eq!(format, SCOPE_EPOCH_RECIPIENT_CAPSULES_FORMAT);
        let mut target_package = packages
            .into_iter()
            .find(|package| package.recipient == target_id)
            .unwrap_or_else(|| panic!("target capsule missing"));
        assert!(!target_package.route_access);
        let decoded_target_grants = target
            .open_rekey_package(
                format,
                &rekey_scope,
                rekey_epoch,
                sequence,
                previous,
                &package_set_hash,
                &target_package,
            )
            .unwrap_or_else(|error| panic!("target capsule open failed: {error}"));
        assert!(decoded_target_grants.route_key.is_none());
        assert_eq!(decoded_target_grants.content_keys.len(), 1);
        drop(decoded_target_grants);
        target_package.route_access = true;
        assert!(
            target
                .open_rekey_package(
                    format,
                    &rekey_scope,
                    rekey_epoch,
                    sequence,
                    previous,
                    &package_set_hash,
                    &target_package,
                )
                .is_err()
        );

        for service in [
            &mut authority,
            &mut publisher,
            &mut bridge_node,
            &mut target,
            &mut limited_target,
        ] {
            service
                .activate_scope_epoch_control(&control, false)
                .unwrap_or_else(|error| panic!("fresh rekey activation failed: {error}"));
        }
        assert!(target.is_content_only(&scope("alpha"), &topic("ops"), 1));
        assert!(target.route_grant(&scope("alpha"), 1).is_none());
        assert!(bridge_node.is_route_only(&scope("alpha"), &topic("ops"), 1));
        assert!(!authority.peer_can_route(
            target_id,
            &target.credential.route_grant_commitments,
            &scope("alpha"),
            1,
        ));
        assert!(authority.peer_can_route(
            bridge_id,
            &bridge_node.credential.route_grant_commitments,
            &scope("alpha"),
            1,
        ));
        let mut fresh_route_key = *authority
            .route_grant(&scope("alpha"), 1)
            .unwrap_or_else(|| panic!("fresh authority route key missing"))
            .key
            .expose();
        let mut fresh_target_content_key = *target
            .content_grant(&scope("alpha"), &topic("ops"), 1)
            .unwrap_or_else(|| panic!("fresh target content key missing"))
            .key
            .expose();
        assert!(!contains_bytes(&control, &fresh_route_key));
        assert!(!contains_bytes(&control, &fresh_target_content_key));
        fresh_route_key.zeroize();
        fresh_target_content_key.zeroize();

        let mut source_header = header(publisher.identity(), 1);
        source_header.content_len = b"fresh bridge payload".len() as u64;
        let source_envelope = publisher
            .seal(SealRequest {
                header: &source_header,
                payload: b"fresh bridge payload",
            })
            .unwrap_or_else(|error| panic!("fresh source seal failed: {error}"));
        let bridge_source = bridge_node
            .open_source_route_for_bridge(&source_envelope.bytes)
            .unwrap_or_else(|error| panic!("fresh source route open failed: {error}"));
        let mut route = BridgeRoute {
            mission_id: bridge_source.mission_id(),
            origin_envelope_id: bridge_source.origin_envelope_id(),
            source_item_id: bridge_source.source_item_id(),
            origin_scope: scope("alpha"),
            origin_route_epoch: 1,
            current_scope: scope("bravo"),
            current_route_epoch: 9,
            source_route_descriptor: bridge_source.copy_exact_route_descriptor(),
            hops: vec![crate::bridge::BridgeHop {
                authorization_envelope_id: [0x5a; 32],
                bridge_node_id: bridge_node.identity(),
                from_scope: scope("alpha"),
                from_route_epoch: 1,
                to_scope: scope("bravo"),
                to_route_epoch: 9,
                cumulative_custody_age_ms: 25,
                age_continuity_unknown: false,
                previous_hop_digest: [0u8; 32],
                bridge_hybrid_signature: Vec::new(),
            }],
            bridge_route_id: [0u8; 32],
        };
        bridge_node
            .sign_bridge_hop(&mut route, 0)
            .unwrap_or_else(|error| panic!("fresh bridge hop signing failed: {error}"));
        let wrapper = bridge_node
            .seal_bridge_wrapper(&route, &bridge_source, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("fresh wrapper seal failed: {error}"));

        // Wrapper authentication is complete while the exact source object is
        // still pending; the sealed wrapper can be persisted and reopened later.
        let pending_wrapper = target
            .open_bridge_wrapper_for_any_local_route(&wrapper)
            .unwrap_or_else(|error| panic!("fresh pending wrapper failed: {error}"));
        assert_eq!(pending_wrapper.route(), &route);
        assert!(target.inspect(&source_envelope.bytes).is_err());
        let target_source = target
            .verify_bridge_wrapper_source(&pending_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("fresh source binding failed: {error}"));
        assert_eq!(
            target
                .open_bridged_payload(&target_source, &source_envelope.bytes)
                .unwrap_or_else(|error| panic!("fresh bridged payload failed: {error}")),
            b"fresh bridge payload"
        );
        assert!(!format!("{pending_wrapper:?}").contains("fresh bridge payload"));
        assert!(!format!("{target_source:?}").contains("fresh bridge payload"));

        let route_only_wrapper = bridge_node
            .open_bridge_wrapper_for_any_local_route(&wrapper)
            .unwrap_or_else(|error| panic!("route-only wrapper failed: {error}"));
        let route_only_source = bridge_node
            .verify_bridge_wrapper_source(&route_only_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("route-only source binding failed: {error}"));
        assert!(
            bridge_node
                .open_bridged_payload(&route_only_source, &source_envelope.bytes)
                .is_err()
        );
        let limited_wrapper = limited_target
            .open_bridge_wrapper_for_any_local_route(&wrapper)
            .unwrap_or_else(|error| panic!("limited wrapper failed: {error}"));
        let limited_source = limited_target
            .verify_bridge_wrapper_source(&limited_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("limited source binding failed: {error}"));
        assert!(
            limited_target
                .open_bridged_payload(&limited_source, &source_envelope.bytes)
                .is_err()
        );

        let mut wrong_topic = target
            .verify_bridge_wrapper_source(&pending_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("wrong-topic token failed: {error}"));
        wrong_topic.header.topic = topic("intel");
        assert!(
            target
                .open_bridged_payload(&wrong_topic, &source_envelope.bytes)
                .is_err()
        );
        let mut wrong_epoch = target
            .verify_bridge_wrapper_source(&pending_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("wrong-epoch token failed: {error}"));
        wrong_epoch.header.key_epoch = 2;
        assert!(
            target
                .open_bridged_payload(&wrong_epoch, &source_envelope.bytes)
                .is_err()
        );
        let mut wrong_origin = target
            .verify_bridge_wrapper_source(&pending_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("wrong-origin token failed: {error}"));
        wrong_origin.header.scope = scope("charlie");
        assert!(
            target
                .open_bridged_payload(&wrong_origin, &source_envelope.bytes)
                .is_err()
        );
        let mut damaged_source = source_envelope.bytes.clone();
        *damaged_source
            .last_mut()
            .unwrap_or_else(|| panic!("fresh source was empty")) ^= 1;
        assert!(
            target
                .verify_bridge_wrapper_source(&pending_wrapper, &damaged_source)
                .is_err()
        );
        assert!(
            target
                .open_bridged_payload(&target_source, &damaged_source)
                .is_err()
        );
        let mut damaged_wrapper = wrapper.clone();
        *damaged_wrapper
            .last_mut()
            .unwrap_or_else(|| panic!("fresh wrapper was empty")) ^= 1;
        assert!(
            target
                .open_bridge_wrapper_for_any_local_route(&damaged_wrapper)
                .is_err()
        );
        let mut damaged_control = control.clone();
        damaged_control[PUBLIC_HEADER_LEN] ^= 1;
        let mut control_tamper_target = service(
            ProvisioningBundle::from_bytes(&target_bundle_bytes)
                .unwrap_or_else(|error| panic!("tamper target parse failed: {error}")),
        );
        assert!(
            control_tamper_target
                .activate_scope_epoch_control(&damaged_control, false)
                .is_err()
        );
        assert!(
            control_tamper_target
                .content_grant(&scope("alpha"), &topic("ops"), 1)
                .is_none()
        );

        let mut restarted_target = service(
            ProvisioningBundle::from_bytes(&target_bundle_bytes)
                .unwrap_or_else(|error| panic!("restart target parse failed: {error}")),
        );
        restarted_target
            .activate_scope_epoch_control(&control, false)
            .unwrap_or_else(|error| panic!("restart rekey activation failed: {error}"));
        let restarted_wrapper = restarted_target
            .open_bridge_wrapper_for_any_local_route(&wrapper)
            .unwrap_or_else(|error| panic!("restart wrapper failed: {error}"));
        let restarted_source = restarted_target
            .verify_bridge_wrapper_source(&restarted_wrapper, &source_envelope.bytes)
            .unwrap_or_else(|error| panic!("restart source binding failed: {error}"));
        assert_eq!(
            restarted_target
                .open_bridged_payload(&restarted_source, &source_envelope.bytes)
                .unwrap_or_else(|error| panic!("restart bridged payload failed: {error}")),
            b"fresh bridge payload"
        );

        EnvelopeSealer::zeroize(&mut target)
            .unwrap_or_else(|error| panic!("fresh target zeroize failed: {error}"));
        assert!(target.route_grants.is_empty());
        assert!(target.content_grants.is_empty());
        assert!(
            target
                .open_bridge_wrapper_for_any_local_route(&wrapper)
                .is_err()
        );
        assert!(
            target
                .open_bridged_payload(&target_source, &source_envelope.bytes)
                .is_err()
        );
    }

    #[test]
    fn bridge_wrapper_and_hop_provider_reject_wrong_bounds_keys_and_source_binding() {
        let mut services = bridge_provider_services(0xc1);
        let authorization =
            bridge_authorization_fixture(&services.authority, &services.bridge_node);
        let sealed_authorization = services
            .authority
            .seal_bridge_authorization(authorization)
            .unwrap_or_else(|error| panic!("authorization seal failed: {error}"));
        let bridge_authorization = services
            .bridge_node
            .open_bridge_authorization(&sealed_authorization)
            .unwrap_or_else(|error| panic!("bridge authorization open failed: {error}"));
        let target_authorization = services
            .target
            .open_bridge_authorization(&sealed_authorization)
            .unwrap_or_else(|error| panic!("target authorization open failed: {error}"));
        let (source_envelope, verified_source) =
            bridge_source_fixture(&mut services.publisher, &services.bridge_node);
        let route = one_hop_bridge_route(
            &services.bridge_node,
            &bridge_authorization,
            &verified_source,
        );
        let wrapper = services
            .bridge_node
            .seal_bridge_wrapper(&route, &verified_source, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("wrapper seal failed: {error}"));

        assert!(
            services
                .bridge_node
                .open_bridge_wrapper(&wrapper, &scope("alpha"), 7)
                .is_err()
        );
        assert!(
            services
                .target
                .open_bridge_wrapper(&wrapper, &scope("bravo"), 8)
                .is_err()
        );
        let outsider = bridge_provider_services(0xc2).target;
        assert!(
            outsider
                .open_bridge_wrapper(&wrapper, &scope("bravo"), 9)
                .is_err()
        );
        assert!(
            outsider
                .open_bridge_wrapper_for_any_local_route(&wrapper)
                .is_err()
        );

        for offset in [0usize, 9, 11, 13, 14] {
            let mut damaged = wrapper.clone();
            damaged[offset] ^= 1;
            assert!(
                services
                    .target
                    .open_bridge_wrapper(&damaged, &scope("bravo"), 9)
                    .is_err(),
                "wrapper header byte {offset} was accepted"
            );
            assert!(
                services
                    .target
                    .open_bridge_wrapper_for_any_local_route(&damaged)
                    .is_err(),
                "wrapper header byte {offset} was accepted by local selection"
            );
        }
        let mut oversized = wrapper[..bridge::BRIDGE_PUBLIC_HEADER_BYTES].to_vec();
        oversized[30..34].copy_from_slice(
            &u32::try_from(bridge::MAX_WRAPPER_PROTECTED_BYTES + 1)
                .unwrap_or_else(|error| panic!("oversized length conversion failed: {error}"))
                .to_be_bytes(),
        );
        assert!(
            services
                .target
                .open_bridge_wrapper(&oversized, &scope("bravo"), 9)
                .is_err()
        );
        let mut wrong_tag = wrapper.clone();
        *wrong_tag
            .last_mut()
            .unwrap_or_else(|| panic!("wrapper was empty")) ^= 1;
        assert!(
            services
                .target
                .open_bridge_wrapper(&wrong_tag, &scope("bravo"), 9)
                .is_err()
        );
        let mut trailing = wrapper.clone();
        trailing.push(0);
        assert!(
            services
                .target
                .open_bridge_wrapper(&trailing, &scope("bravo"), 9)
                .is_err()
        );
        assert!(
            services
                .target
                .open_bridge_wrapper(&wrapper[..wrapper.len() - 1], &scope("bravo"), 9,)
                .is_err()
        );

        let mut bad_hop = route.clone();
        *bad_hop.hops[0]
            .bridge_hybrid_signature
            .last_mut()
            .unwrap_or_else(|| panic!("hop signature missing")) ^= 1;
        bad_hop.bridge_route_id = bad_hop
            .compute_route_id()
            .unwrap_or_else(|error| panic!("bad hop route id failed: {error}"));
        bad_hop
            .validate_structure()
            .unwrap_or_else(|error| panic!("bad hop structural validation failed: {error}"));
        assert!(
            services
                .target
                .verify_bridge_hop(&bad_hop, 0, &target_authorization)
                .is_err()
        );
        assert!(
            services
                .bridge_node
                .seal_bridge_wrapper(&bad_hop, &verified_source, &scope("bravo"), 9)
                .is_err()
        );

        let mut wrong_authorization = route.clone();
        wrong_authorization.hops[0].authorization_envelope_id[0] ^= 1;
        wrong_authorization.hops[0].bridge_hybrid_signature.clear();
        services
            .bridge_node
            .sign_bridge_hop(&mut wrong_authorization, 0)
            .unwrap_or_else(|error| panic!("wrong authorization route signing failed: {error}"));
        assert!(
            services
                .target
                .verify_bridge_hop(&wrong_authorization, 0, &target_authorization)
                .is_err()
        );

        let mut wrong_mission = route.clone();
        wrong_mission.mission_id[0] ^= 1;
        wrong_mission.bridge_route_id = wrong_mission
            .compute_route_id()
            .unwrap_or_else(|error| panic!("wrong mission route id failed: {error}"));
        assert!(
            services
                .bridge_node
                .seal_bridge_wrapper(&wrong_mission, &verified_source, &scope("bravo"), 9)
                .is_err()
        );
        let mut wrong_descriptor = route.clone();
        wrong_descriptor.source_route_descriptor[0] ^= 1;
        wrong_descriptor.bridge_route_id = wrong_descriptor
            .compute_route_id()
            .unwrap_or_else(|error| panic!("wrong descriptor route id failed: {error}"));
        assert!(
            services
                .bridge_node
                .seal_bridge_wrapper(&wrong_descriptor, &verified_source, &scope("bravo"), 9)
                .is_err()
        );

        // Even after a target-route AEAD succeeds, local selection accepts only
        // the scope and epoch named by the grant that authenticated it.
        let mut mismatched_target = route.clone();
        mismatched_target.current_route_epoch = 8;
        mismatched_target.hops[0].to_route_epoch = 8;
        mismatched_target.bridge_route_id = mismatched_target
            .compute_route_id()
            .unwrap_or_else(|error| panic!("mismatched target route id failed: {error}"));
        let target_root = *services
            .bridge_node
            .route_grant(&scope("bravo"), 9)
            .unwrap_or_else(|| panic!("target route grant missing"))
            .key
            .expose();
        let mismatched_wrapper = seal_test_bridge_object(
            &mut services.bridge_node,
            bridge::WRAPPER_MAGIC,
            BRIDGE_WRAPPER_KEY_LABEL,
            target_root,
            mismatched_target
                .encode()
                .unwrap_or_else(|error| panic!("mismatched target encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_wrapper_for_any_local_route(&mismatched_wrapper)
                .is_err()
        );

        let mut wrapped_wrong_mission = route.clone();
        wrapped_wrong_mission.mission_id[0] ^= 1;
        wrapped_wrong_mission.bridge_route_id = wrapped_wrong_mission
            .compute_route_id()
            .unwrap_or_else(|error| panic!("wrapped wrong mission route id failed: {error}"));
        let target_root = *services
            .bridge_node
            .route_grant(&scope("bravo"), 9)
            .unwrap_or_else(|| panic!("target route grant missing"))
            .key
            .expose();
        let wrong_mission_wrapper = seal_test_bridge_object(
            &mut services.bridge_node,
            bridge::WRAPPER_MAGIC,
            BRIDGE_WRAPPER_KEY_LABEL,
            target_root,
            wrapped_wrong_mission
                .encode()
                .unwrap_or_else(|error| panic!("wrapped wrong mission encode failed: {error}")),
        );
        assert!(
            services
                .target
                .open_bridge_wrapper_for_any_local_route(&wrong_mission_wrapper)
                .is_err()
        );

        let mut damaged_source = source_envelope.bytes.clone();
        *damaged_source
            .last_mut()
            .unwrap_or_else(|| panic!("source envelope was empty")) ^= 1;
        let pending_wrapper = services
            .target
            .open_bridge_wrapper(&wrapper, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("pending wrapper open failed: {error}"));
        assert!(
            services
                .target
                .verify_bridge_wrapper_source(&pending_wrapper, &damaged_source)
                .is_err()
        );

        let mut forged_descriptor_route = route.clone();
        *forged_descriptor_route
            .source_route_descriptor
            .last_mut()
            .unwrap_or_else(|| panic!("source descriptor was empty")) ^= 1;
        forged_descriptor_route.hops[0]
            .bridge_hybrid_signature
            .clear();
        services
            .bridge_node
            .sign_bridge_hop(&mut forged_descriptor_route, 0)
            .unwrap_or_else(|error| panic!("forged descriptor route signing failed: {error}"));
        let mut target_root = *services
            .bridge_node
            .route_grant(&scope("bravo"), 9)
            .unwrap_or_else(|| panic!("target route grant missing"))
            .key
            .expose();
        let forged_wrapper = seal_test_bridge_object(
            &mut services.bridge_node,
            bridge::WRAPPER_MAGIC,
            BRIDGE_WRAPPER_KEY_LABEL,
            target_root,
            forged_descriptor_route
                .encode()
                .unwrap_or_else(|error| panic!("forged descriptor route encode failed: {error}")),
        );
        target_root.zeroize();
        let forged_pending = services
            .target
            .open_bridge_wrapper(&forged_wrapper, &scope("bravo"), 9)
            .unwrap_or_else(|error| panic!("forged pending wrapper open failed: {error}"));
        assert!(
            services
                .target
                .verify_bridge_wrapper_source(&forged_pending, &source_envelope.bytes)
                .is_err()
        );
    }

    #[test]
    fn on_path_rewrite_of_an_offered_v9_selection_to_v5_fails_authentication() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x8e; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let initiator_bundle = provisioner
            .issue_node(1, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("initiator issue failed: {error}"));
        let responder_bundle = provisioner
            .issue_node(2, &[member_access(vec![0])])
            .unwrap_or_else(|error| panic!("responder issue failed: {error}"));

        let (initiator, first_flight) = ReferenceSessionInitiator::start(initiator_bundle)
            .unwrap_or_else(|error| panic!("initiator start failed: {error}"));
        let (hello, _) = decode_client_flight(&first_flight)
            .unwrap_or_else(|error| panic!("client flight decode failed: {error}"));
        assert_eq!(
            hello.supported_versions,
            vec![
                SEMANTIC_PROTOCOL_V9,
                SEMANTIC_PROTOCOL_V8,
                SEMANTIC_PROTOCOL_V7,
                SEMANTIC_PROTOCOL_V6,
                SEMANTIC_PROTOCOL_V5,
                SEMANTIC_PROTOCOL_V4,
                SEMANTIC_PROTOCOL_V3,
                SEMANTIC_PROTOCOL_V2,
                SEMANTIC_PROTOCOL_V1,
            ]
        );
        let responder = ReferenceSessionResponder::open(responder_bundle)
            .unwrap_or_else(|error| panic!("responder open failed: {error}"));
        let (_pending, second_flight) = responder
            .receive_client(&first_flight)
            .unwrap_or_else(|error| panic!("client flight failed: {error}"));
        let mut server_hello = decode_server_flight(&second_flight)
            .unwrap_or_else(|error| panic!("server flight decode failed: {error}"));
        assert_eq!(server_hello.selected_version, SEMANTIC_PROTOCOL_V9);

        // Version 5 was genuinely offered, so membership checks alone would
        // accept it. The rewrite must still fail because selection is bound
        // into the transcript, key schedule, confirmation, and server auth.
        server_hello.selected_version = SEMANTIC_PROTOCOL_V5;
        let rewritten = encode_server_flight(&server_hello)
            .unwrap_or_else(|error| panic!("rewritten server flight encode failed: {error}"));
        assert!(initiator.receive_server(&rewritten).is_err());
    }
}
